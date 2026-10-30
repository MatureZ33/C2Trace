from __future__ import annotations

"""Synchronous Executor-facing wrapper around the official async MCP client."""

import asyncio
from concurrent.futures import Future
from dataclasses import dataclass
from datetime import timedelta
import os
from pathlib import Path
from queue import Empty, Queue
import sys
from threading import Event, Thread
from typing import Any, Literal, TextIO

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from c2trace.execution import (
    McpToolReceipt,
    ResponseAuthorization,
    ToolResult,
    canonical_arguments,
    tool_catalog_hash,
)


class McpTransportError(RuntimeError):
    pass


@dataclass(slots=True)
class _Request:
    operation: Literal["list_tools", "call_tool", "close"]
    future: Future[Any]
    tool: str = ""
    arguments: dict[str, Any] | None = None
    authorization: ResponseAuthorization | None = None


class StdioMcpToolClient:
    """One MCP server process and session per C2Trace case."""

    def __init__(
        self,
        *,
        case_id: str,
        response_enabled: bool,
        public_key_b64: str,
        timeout_seconds: float = 60.0,
        cwd: str | Path | None = None,
        errlog: TextIO | None = None,
    ) -> None:
        self.case_id = str(case_id)
        self.response_enabled = bool(response_enabled)
        self.public_key_b64 = str(public_key_b64)
        self.timeout_seconds = max(1.0, float(timeout_seconds))
        self.cwd = str(Path(cwd or Path.cwd()).resolve())
        self._errlog = errlog or sys.stderr
        self._requests: Queue[_Request] = Queue()
        self._ready = Event()
        self._startup_error: BaseException | None = None
        self._closed = False
        self._thread = Thread(target=self._thread_main, name=f"c2trace-mcp-{self.case_id}", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=self.timeout_seconds):
            raise McpTransportError("timed out starting C2Trace MCP server")
        if self._startup_error is not None:
            raise McpTransportError(f"unable to start C2Trace MCP server: {self._startup_error}")
        tools = self.list_tools()
        self.catalog = tools
        self.catalog_hash = tool_catalog_hash(tools)

    def _thread_main(self) -> None:
        try:
            asyncio.run(self._session_main())
        except BaseException as exc:
            self._startup_error = exc
            self._ready.set()
            while True:
                try:
                    request = self._requests.get_nowait()
                except Empty:
                    break
                if not request.future.done():
                    request.future.set_exception(exc)

    async def _session_main(self) -> None:
        env = dict(os.environ)
        env.update({
            "C2TRACE_MCP_MODE": "response_enabled" if self.response_enabled else "read_only",
            "C2TRACE_MCP_CASE_ID": self.case_id,
            "C2TRACE_MCP_PUBLIC_KEY": self.public_key_b64,
        })
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "c2trace.mcp.server"],
            env=env,
            cwd=self.cwd,
            encoding="utf-8",
            encoding_error_handler="replace",
        )
        async with stdio_client(parameters, errlog=self._errlog) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                self._ready.set()
                while True:
                    request = await asyncio.to_thread(self._requests.get)
                    if request.operation == "close":
                        request.future.set_result(None)
                        return
                    try:
                        if request.operation == "list_tools":
                            result = await session.list_tools()
                            request.future.set_result([
                                tool.model_dump(by_alias=True, exclude_none=True)
                                for tool in result.tools
                            ])
                        else:
                            meta: dict[str, Any] | None = None
                            if request.authorization is not None:
                                meta = {"c2trace": {"authorization": request.authorization.to_wire()}}
                            result = await session.call_tool(
                                request.tool,
                                arguments=request.arguments,
                                read_timeout_seconds=timedelta(seconds=self.timeout_seconds),
                                meta=meta,
                            )
                            request.future.set_result(result)
                    except BaseException as exc:
                        request.future.set_exception(exc)

    def _submit(self, request: _Request) -> Any:
        if self._closed:
            raise McpTransportError("C2Trace MCP client is closed")
        if self._startup_error is not None:
            raise McpTransportError(f"C2Trace MCP session failed: {self._startup_error}")
        if not self._thread.is_alive():
            raise McpTransportError("C2Trace MCP session terminated")
        self._requests.put(request)
        try:
            return request.future.result(timeout=self.timeout_seconds + 5.0)
        except Exception as exc:
            raise McpTransportError(str(exc)) from exc

    def list_tools(self) -> list[dict[str, Any]]:
        future: Future[Any] = Future()
        result = self._submit(_Request("list_tools", future))
        if not isinstance(result, list):
            raise McpTransportError("MCP list_tools returned an invalid catalog")
        return [dict(item) for item in result if isinstance(item, dict)]

    @staticmethod
    def _structured_payload(result: Any) -> dict[str, Any]:
        structured = getattr(result, "structuredContent", None)
        if isinstance(structured, dict):
            if isinstance(structured.get("result"), dict):
                return dict(structured["result"])
            return dict(structured)
        for block in list(getattr(result, "content", []) or []):
            text = getattr(block, "text", None)
            if not isinstance(text, str):
                continue
            import json
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
        raise McpTransportError("MCP tool returned no structured receipt")

    def run(
        self,
        tool: str,
        params: dict[str, Any] | None = None,
        *,
        authorization: ResponseAuthorization | None = None,
    ) -> ToolResult:
        arguments = canonical_arguments(params)
        future: Future[Any] = Future()
        try:
            result = self._submit(_Request(
                "call_tool",
                future,
                tool=str(tool),
                arguments=arguments,
                authorization=authorization,
            ))
            receipt = McpToolReceipt.from_dict(self._structured_payload(result))
            if receipt.tool != str(tool):
                raise McpTransportError("MCP receipt tool does not match the request")
            return receipt.to_tool_result()
        except McpTransportError as exc:
            return ToolResult(False, error=str(exc), error_type="infrastructure_invalid")
        except (TypeError, ValueError) as exc:
            return ToolResult(False, error=str(exc), error_type="infrastructure_invalid")

    def close(self) -> None:
        if self._closed:
            return
        if not self._thread.is_alive():
            self._closed = True
            return
        future: Future[Any] = Future()
        self._requests.put(_Request("close", future))
        try:
            future.result(timeout=10.0)
        finally:
            self._closed = True
            self._thread.join(timeout=10.0)
        if self._thread.is_alive():
            raise McpTransportError("timed out cleaning up C2Trace MCP subprocess")

    def __enter__(self) -> "StdioMcpToolClient":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()
