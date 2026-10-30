from __future__ import annotations

"""Independent stdio MCP server for deterministic Windows tools."""

import os
import time
from typing import Any, Mapping
from uuid import uuid4

from mcp.server.fastmcp import Context, FastMCP

from c2trace.agents.target_identity import revalidate_target_before_response
from c2trace.authorization import ResponseAuthorizationVerifier
from c2trace.execution import (
    McpToolReceipt,
    canonical_arguments,
    canonical_sha256,
    effective_arguments,
)
from c2trace.tools import RESPONSE_TOOLS
from c2trace.tools.system import WindowsToolBackend


TOOL_VERSION = "1.0"
SERVER_MODE = str(os.environ.get("C2TRACE_MCP_MODE") or "read_only").strip().lower()
CASE_ID = str(os.environ.get("C2TRACE_MCP_CASE_ID") or "").strip()
PUBLIC_KEY = str(os.environ.get("C2TRACE_MCP_PUBLIC_KEY") or "").strip()

if SERVER_MODE not in {"read_only", "response_enabled"}:
    raise RuntimeError(f"invalid C2TRACE_MCP_MODE: {SERVER_MODE}")
if not CASE_ID:
    raise RuntimeError("C2TRACE_MCP_CASE_ID is required")
if SERVER_MODE == "response_enabled" and not PUBLIC_KEY:
    raise RuntimeError("C2TRACE_MCP_PUBLIC_KEY is required in response_enabled mode")


backend = WindowsToolBackend(execute_response=SERVER_MODE == "response_enabled")
verifier = ResponseAuthorizationVerifier(PUBLIC_KEY) if PUBLIC_KEY else None
mcp = FastMCP(
    "C2Trace Windows MCP Server",
    instructions=(
        "Deterministic Windows investigation, response, and verification tools. "
        "This server does not plan cases and cannot modify CaseFile."
    ),
    log_level="WARNING",
)


def _request_meta(ctx: Context) -> dict[str, Any]:
    meta = ctx.request_context.meta
    if meta is None:
        return {}
    dumped = meta.model_dump(by_alias=True, exclude_none=True)
    return dict(dumped.get("c2trace") or {}) if isinstance(dumped.get("c2trace"), Mapping) else {}


def _receipt(
    *,
    request_id: str,
    tool: str,
    params: dict[str, Any],
    success: bool,
    data: Any,
    error: str | None,
    error_type: str,
    elapsed_ms: float,
    authorization_receipt: dict[str, Any] | None = None,
    target_revalidation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return McpToolReceipt(
        request_id=request_id,
        tool=tool,
        tool_version=TOOL_VERSION,
        success=success,
        data=data,
        error=error,
        error_type=error_type,
        elapsed_ms=elapsed_ms,
        actual_args_summary=effective_arguments(params),
        actual_args_sha256=canonical_sha256(effective_arguments(params)),
        authorization_receipt=authorization_receipt,
        target_revalidation=target_revalidation,
    ).to_dict()


def _invoke(tool: str, params: dict[str, Any], ctx: Context) -> dict[str, Any]:
    started = time.perf_counter()
    request_id = str(ctx.request_id or uuid4())
    authorization_receipt: dict[str, Any] | None = None
    target_revalidation: dict[str, Any] | None = None
    try:
        if tool in RESPONSE_TOOLS and SERVER_MODE == "read_only":
            return _receipt(
                request_id=request_id,
                tool=tool,
                params=params,
                success=False,
                data=None,
                error="response tools are disabled while the MCP server is read-only",
                error_type="response_disabled",
                elapsed_ms=(time.perf_counter() - started) * 1000,
            )
        if tool in RESPONSE_TOOLS and SERVER_MODE == "response_enabled":
            if verifier is None:  # pragma: no cover - guarded at module load
                raise PermissionError("response authorization verifier is unavailable")
            meta = _request_meta(ctx)
            wire = meta.get("authorization")
            if not isinstance(wire, Mapping):
                raise PermissionError("response tool requires Auditor authorization")
            claims = wire.get("claims") if isinstance(wire.get("claims"), Mapping) else {}
            verification = verifier.verify(
                wire,
                case_id=CASE_ID,
                call_id=str(claims.get("call_id") or ""),
                node_id=str(claims.get("strategy_node_id") or ""),
                tool=tool,
                arguments_sha256=canonical_sha256(effective_arguments(params)),
            )
            authorization_receipt = verification.receipt(consumed=False)
            if not verification.valid:
                raise PermissionError(verification.reason)
            target_lock = verification.claims.get("target_lock")
            if not isinstance(target_lock, Mapping):
                raise PermissionError("authorization contains no target lock")
            try:
                target_revalidation = revalidate_target_before_response(
                    backend,
                    tool=tool,
                    arguments=params,
                    target_lock=target_lock,
                )
            except PermissionError as exc:
                return _receipt(
                    request_id=request_id,
                    tool=tool,
                    params=params,
                    success=False,
                    data=None,
                    error=str(exc),
                    error_type="target_drift",
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                    authorization_receipt=authorization_receipt,
                    target_revalidation={"checked": True, "passed": False, "reason": str(exc)},
                )
            verifier.consume(verification)
            authorization_receipt = verification.receipt(consumed=True)
            with backend.mcp_authorized_response(tool=tool, params=params):
                raw = backend.run(tool, params)
        else:
            raw = backend.run(tool, params)
        return _receipt(
            request_id=request_id,
            tool=tool,
            params=params,
            success=raw.success,
            data=raw.data,
            error=raw.error,
            error_type=raw.error_type or ("" if raw.success else "tool_error"),
            elapsed_ms=(time.perf_counter() - started) * 1000,
            authorization_receipt=authorization_receipt,
            target_revalidation=target_revalidation,
        )
    except PermissionError as exc:
        return _receipt(
            request_id=request_id,
            tool=tool,
            params=params,
            success=False,
            data=None,
            error=str(exc),
            error_type="authorization_denied",
            elapsed_ms=(time.perf_counter() - started) * 1000,
            authorization_receipt=authorization_receipt,
            target_revalidation=target_revalidation,
        )
    except Exception as exc:  # fail closed at the process boundary
        return _receipt(
            request_id=request_id,
            tool=tool,
            params=params,
            success=False,
            data=None,
            error=str(exc),
            error_type="tool_error",
            elapsed_ms=(time.perf_counter() - started) * 1000,
            authorization_receipt=authorization_receipt,
            target_revalidation=target_revalidation,
        )


READ_META = {"c2trace": {"tool_version": TOOL_VERSION, "response": False}}
RESPONSE_META = {"c2trace": {"tool_version": TOOL_VERSION, "response": True}}


@mcp.tool(description="List active TCP connections or an exact inbound listener.", meta=READ_META, structured_output=True)
def check_network(
    remote_ip: str = "",
    remote_port: str | int = "",
    target_ip: str = "",
    target_port: str | int = "",
    local_port: str | int = "",
    network_mode: str = "outbound_active_flow",
    local_ip: str = "",
    ctx: Context = None,
) -> dict[str, Any]:
    return _invoke("check_network", {
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "target_ip": target_ip,
        "target_port": target_port,
        "local_port": local_port,
        "network_mode": network_mode,
        "local_ip": local_ip,
    }, ctx)


@mcp.tool(description="Inspect one Windows process by PID or exact name.", meta=READ_META, structured_output=True)
def check_process(pid: int = 0, process_name: str = "", ctx: Context = None) -> dict[str, Any]:
    return _invoke("check_process", {"pid": pid, "process_name": process_name}, ctx)


@mcp.tool(description="Collect a bounded process-parent chain.", meta=READ_META, structured_output=True)
def check_process_tree(pid: int = 0, process_name: str = "", ctx: Context = None) -> dict[str, Any]:
    return _invoke("check_process_tree", {"pid": pid, "process_name": process_name}, ctx)


@mcp.tool(description="Read metadata and SHA-256 for one exact file path.", meta=READ_META, structured_output=True)
def check_file_metadata(file_path: str = "", ctx: Context = None) -> dict[str, Any]:
    return _invoke("check_file_metadata", {"file_path": file_path}, ctx)


@mcp.tool(description="Scan bounded fixed roots for recently modified files.", meta=READ_META, structured_output=True)
def check_recent_files(
    since_utc: str,
    until_utc: str,
    root_aliases: list[str] | None = None,
    max_depth: int = 0,
    max_results: int = 128,
    max_file_size: int = 4194304,
    ctx: Context = None,
) -> dict[str, Any]:
    return _invoke("check_recent_files", {
        "since_utc": since_utc,
        "until_utc": until_utc,
        "root_aliases": root_aliases,
        "max_depth": max_depth,
        "max_results": max_results,
        "max_file_size": max_file_size,
    }, ctx)


@mcp.tool(description="Inspect registry, scheduled-task, and service persistence.", meta=READ_META, structured_output=True)
def check_persistence_all(process_path: str = "", ctx: Context = None) -> dict[str, Any]:
    return _invoke("check_persistence_all", {"process_path": process_path}, ctx)


@mcp.tool(description="Search bounded PowerShell history lines.", meta=READ_META, structured_output=True)
def check_powershell_history(pattern: str = "", max_lines: int = 80, ctx: Context = None) -> dict[str, Any]:
    return _invoke("check_powershell_history", {"pattern": pattern, "max_lines": max_lines}, ctx)


@mcp.tool(description="Inspect the Windows DNS client cache.", meta=READ_META, structured_output=True)
def check_dns_cache(domain_filter: str = "", ctx: Context = None) -> dict[str, Any]:
    return _invoke("check_dns_cache", {"domain_filter": domain_filter}, ctx)


@mcp.tool(description="Verify exact post-response network, process, file, and persistence state.", meta=READ_META, structured_output=True)
def verify_cleanup(
    remote_ip: str = "",
    remote_port: str | int = "",
    local_port: str | int = "",
    file_path: str = "",
    pid: int = 0,
    process_name: str = "",
    response_actions: list[dict[str, Any]] | None = None,
    ctx: Context = None,
) -> dict[str, Any]:
    return _invoke("verify_cleanup", {
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "local_port": local_port,
        "file_path": file_path,
        "pid": pid,
        "process_name": process_name,
        "response_actions": response_actions,
    }, ctx)


@mcp.tool(description="Terminate the exact Auditor-authorized process.", meta=RESPONSE_META, structured_output=True)
def kill_process(process_name: str = "", pid: int = 0, expected_path: str = "", ctx: Context = None) -> dict[str, Any]:
    return _invoke("kill_process", {"process_name": process_name, "pid": pid, "expected_path": expected_path}, ctx)


@mcp.tool(description="Remove the exact Auditor-authorized file.", meta=RESPONSE_META, structured_output=True)
def remove_file(file_path: str, ctx: Context = None) -> dict[str, Any]:
    return _invoke("remove_file", {"file_path": file_path}, ctx)


@mcp.tool(description="Remove the exact Auditor-authorized registry value.", meta=RESPONSE_META, structured_output=True)
def remove_registry(reg_path: str, value_name: str, expected_value: str = "", ctx: Context = None) -> dict[str, Any]:
    return _invoke("remove_registry", {"reg_path": reg_path, "value_name": value_name, "expected_value": expected_value}, ctx)


@mcp.tool(description="Remove the exact Auditor-authorized scheduled task.", meta=RESPONSE_META, structured_output=True)
def remove_scheduled_task(task_name: str, task_path: str = "", ctx: Context = None) -> dict[str, Any]:
    return _invoke("remove_scheduled_task", {"task_name": task_name, "task_path": task_path}, ctx)


@mcp.tool(description="Remove the exact Auditor-authorized Windows service.", meta=RESPONSE_META, structured_output=True)
def remove_service(service_name: str, ctx: Context = None) -> dict[str, Any]:
    return _invoke("remove_service", {"service_name": service_name}, ctx)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
