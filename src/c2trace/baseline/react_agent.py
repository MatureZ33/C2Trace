"""Public-task ReAct tools for the independent baseline.

Only low-level Windows observation semantics are shared with the treatment.
This module contains no CaseFile, strategy, target identity, answer file, or
private investigation-policy dependency.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict
from typing import Any

from c2trace.execution import ToolResult
from c2trace.tools.system import WindowsToolBackend
from c2trace.baseline.safety_mediator import SafetyMediator


RESPONSE_TOOLS = frozenset({
    "kill_process", "remove_file", "remove_registry",
    "remove_scheduled_task", "remove_service",
})
READ_ONLY_TOOLS = frozenset({
    "check_network", "check_process", "check_process_tree",
    "check_file_metadata", "check_recent_files", "check_persistence_all",
    "check_powershell_history", "check_dns_cache", "check_post_state",
})


class ResponseSandbox:
    """Target-agnostic response boundary for the baseline."""

    def __init__(self, backend: WindowsToolBackend, mediator: SafetyMediator | None = None) -> None:
        self.backend = backend
        self.mediator = mediator or SafetyMediator()
        self.decisions: list[dict[str, Any]] = []

    def call(self, tool_name: str, arguments: dict[str, Any], *, decision: Any = None) -> ToolResult:
        decision = decision or self.mediator.review(tool_name, arguments)
        self.decisions.append(decision.to_dict())
        if not decision.allowed:
            return ToolResult(False, error=f"response sandbox blocked {tool_name}: {decision.reason}")
        method = getattr(self.backend, tool_name)
        # This is the low-level capability required by the shared Windows
        # backend. The baseline has no target identity or audit binding.
        with self.backend.mcp_authorized_response(tool=tool_name, params=dict(arguments)):
            return method(**arguments)


class ToolCallRecorder:
    """Record raw observations and response attempts without target binding."""

    def __init__(self, backend: WindowsToolBackend, max_calls: int = 50, mediator: SafetyMediator | None = None) -> None:
        self.backend = backend
        self.calls: list[dict[str, Any]] = []
        self.max_calls = int(max_calls)
        self.sandbox = ResponseSandbox(backend, mediator)
        self.mediator = self.sandbox.mediator
        self.proposed_actions: list[dict[str, Any]] = []
        self.blocked_actions: list[dict[str, Any]] = []

    def call(self, tool_name: str, **kwargs: Any) -> ToolResult:
        if len(self.calls) >= self.max_calls:
            result = ToolResult(False, error=f"tool call budget exhausted ({len(self.calls)}/{self.max_calls})")
            self.calls.append(self._record(tool_name, kwargs, result, "budget_blocked"))
            return result
        started = time.perf_counter()
        decision_payload: dict[str, Any] | None = None
        try:
            if tool_name in RESPONSE_TOOLS:
                self.proposed_actions.append({"tool": tool_name, "arguments": dict(kwargs)})
                decision = self.mediator.review(tool_name, kwargs)
                decision_payload = decision.to_dict()
                if not decision.allowed:
                    self.blocked_actions.append({"tool": tool_name, "arguments": dict(kwargs), "decision": decision.to_dict()})
                    result = ToolResult(False, error=f"response sandbox blocked {tool_name}: {decision.reason}")
                    self.calls.append(self._record(tool_name, kwargs, result, "safety_blocked", decision.to_dict()))
                    return result
                result = self.sandbox.call(tool_name, dict(kwargs), decision=decision)
                classification = "response"
            elif tool_name == "check_post_state":
                result = self.backend.verify_cleanup(**kwargs)
                classification = "verification"
            elif tool_name in READ_ONLY_TOOLS:
                result = getattr(self.backend, tool_name)(**kwargs)
                classification = "investigation"
            else:
                result = ToolResult(False, error=f"unsupported public tool: {tool_name}")
                classification = "unsupported"
        except Exception as exc:
            result = ToolResult(False, error=f"backend exception: {exc}")
            classification = "exception"
        self.calls.append(self._record(tool_name, kwargs, result, classification, decision=decision_payload, elapsed_ms=(time.perf_counter() - started) * 1000))
        return result

    @staticmethod
    def _record(tool: str, arguments: dict[str, Any], result: ToolResult, classification: str, decision: dict[str, Any] | None = None, elapsed_ms: float = 0.0) -> dict[str, Any]:
        return {
            "tool": tool,
            "arguments": dict(arguments),
            "success": result.success,
            "data": result.data,
            "error": result.error,
            "elapsed_ms": result.elapsed_ms or elapsed_ms,
            "timestamp": time.time(),
            "classification": classification,
            "safety_decision": decision,
        }


def result_to_str(result: ToolResult) -> str:
    return json.dumps(asdict(result), ensure_ascii=False, default=str)


def build_tools(recorder: ToolCallRecorder):
    """Build the public tool API. Names and descriptions are neutral."""
    from langchain_core.tools import tool

    @tool
    def check_network(remote_ip: str = "", remote_port: str = "", target_ip: str = "", target_port: str = "", local_port: str = "", network_mode: str = "outbound_active_flow", local_ip: str = "") -> str:
        """Inspect matching TCP connections or listeners."""
        return result_to_str(recorder.call("check_network", remote_ip=remote_ip, remote_port=remote_port, target_ip=target_ip, target_port=target_port, local_port=local_port, network_mode=network_mode, local_ip=local_ip))

    @tool
    def check_process(pid: int = 0, process_name: str = "") -> str:
        """Inspect process identity and executable metadata."""
        return result_to_str(recorder.call("check_process", pid=pid, process_name=process_name))

    @tool
    def check_process_tree(pid: int = 0, process_name: str = "") -> str:
        """Inspect the parent process chain."""
        return result_to_str(recorder.call("check_process_tree", pid=pid, process_name=process_name))

    @tool
    def check_file_metadata(file_path: str = "") -> str:
        """Inspect existence, hash, signature, and timestamps for a file."""
        return result_to_str(recorder.call("check_file_metadata", file_path=file_path))

    @tool
    def check_recent_files(since_utc: str = "", until_utc: str = "", root_aliases: list | None = None, max_depth: int = 4, max_results: int = 64, max_file_size: int = 4194304) -> str:
        """Inspect bounded metadata for recent files in safe roots."""
        return result_to_str(recorder.call("check_recent_files", since_utc=since_utc, until_utc=until_utc, root_aliases=root_aliases or None, max_depth=max_depth, max_results=max_results, max_file_size=max_file_size))

    @tool
    def check_persistence_all(process_path: str = "") -> str:
        """Inspect non-system persistence entries."""
        return result_to_str(recorder.call("check_persistence_all", process_path=process_path))

    @tool
    def check_powershell_history(pattern: str = "", max_lines: int = 80) -> str:
        """Inspect matching PowerShell history lines."""
        return result_to_str(recorder.call("check_powershell_history", pattern=pattern, max_lines=max_lines))

    @tool
    def check_dns_cache(domain_filter: str = "") -> str:
        """Inspect DNS cache entries."""
        return result_to_str(recorder.call("check_dns_cache", domain_filter=domain_filter))

    @tool
    def check_post_state(remote_ip: str = "", remote_port: str = "", file_path: str = "", pid: int = 0, process_name: str = "", local_port: str = "") -> str:
        """Inspect current state after requested response actions."""
        return result_to_str(recorder.call("check_post_state", remote_ip=remote_ip, remote_port=remote_port, file_path=file_path, pid=pid, process_name=process_name, local_port=local_port))

    @tool
    def kill_process(process_name: str = "", pid: int = 0, expected_path: str = "") -> str:
        """Terminate one matching process."""
        return result_to_str(recorder.call("kill_process", process_name=process_name, pid=pid, expected_path=expected_path))

    @tool
    def remove_file(file_path: str) -> str:
        """Remove one file inside the experiment file root."""
        return result_to_str(recorder.call("remove_file", file_path=file_path))

    @tool
    def remove_registry(reg_path: str, value_name: str, expected_value: str = "") -> str:
        """Remove one non-system registry value."""
        return result_to_str(recorder.call("remove_registry", reg_path=reg_path, value_name=value_name, expected_value=expected_value))

    @tool
    def remove_scheduled_task(task_name: str, task_path: str = "") -> str:
        """Remove one non-system scheduled task."""
        return result_to_str(recorder.call("remove_scheduled_task", task_name=task_name, task_path=task_path))

    @tool
    def remove_service(service_name: str) -> str:
        """Remove one non-system service."""
        return result_to_str(recorder.call("remove_service", service_name=service_name))

    return [check_network, check_process, check_process_tree, check_file_metadata, check_recent_files, check_persistence_all, check_powershell_history, check_dns_cache, check_post_state, kill_process, remove_file, remove_registry, remove_scheduled_task, remove_service]


__all__ = ["READ_ONLY_TOOLS", "RESPONSE_TOOLS", "ResponseSandbox", "ToolCallRecorder", "build_tools"]
