"""Baseline safety boundary.

This component is intentionally target-agnostic: it protects system and
control-agent objects and enforces input/path boundaries, but never consults
Ground Truth or decides whether a proposed target is the attack target.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, asdict
from pathlib import Path, PureWindowsPath
from typing import Any, Callable

from c2trace.execution import ToolResult


RESPONSE_TOOLS = frozenset({"kill_process", "remove_file", "remove_registry", "remove_scheduled_task", "remove_service"})
READ_ONLY_TOOLS = frozenset({"check_network", "check_process", "check_process_tree", "check_file_metadata", "check_recent_files", "check_persistence_all", "check_powershell_history", "check_dns_cache", "verify_cleanup"})


@dataclass(frozen=True, slots=True)
class SafetyDecision:
    allowed: bool
    reason: str
    tool: str
    arguments: dict[str, Any]
    safety_violation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SafetyMediator:
    """Non-oracular safety checks for baseline tool calls."""

    def __init__(
        self,
        *,
        protected_process_names: set[str] | None = None,
        protected_process_paths: set[str] | None = None,
        protected_process_pids: set[int] | None = None,
        allowed_file_roots: list[str | Path] | None = None,
        protected_registry_prefixes: set[str] | None = None,
        protected_service_names: set[str] | None = None,
        protected_task_prefixes: set[str] | None = None,
    ) -> None:
        default_process_names = {
            "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
            "winlogon.exe", "svchost.exe", "dwm.exe", "explorer.exe", "c2t_control.exe",
            "c2t_driver.exe", "sandcat.exe", "splunkd.exe",
        }
        self.protected_process_names = {
            self._norm_name(x) for x in (default_process_names | set(protected_process_names or set()))
        }
        self.protected_process_paths = {
            self._norm_path(x) for x in set(protected_process_paths or set())
        }
        self.protected_process_pids = {
            int(value) for value in set(protected_process_pids or set())
            if str(value).strip().isdigit() and int(value) > 0
        }
        self.allowed_file_roots = [self._canonical_root(x) for x in (allowed_file_roots or [r"C:\Users\Public"])]
        self.protected_registry_prefixes = {
            self._norm_registry(x) for x in (protected_registry_prefixes or {
                r"HKLM\SYSTEM", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            })
        }
        self.protected_service_names = {self._norm_name(x) for x in (protected_service_names or {
            "rpcss", "eventlog", "plugplay", "winmgmt", "windefend", "wuauserv", "c2t_control", "c2t_driver",
        })}
        self.protected_task_prefixes = {self._norm_task(x) for x in (protected_task_prefixes or {r"\Microsoft\Windows"})}
        self.decisions: list[SafetyDecision] = []

    @staticmethod
    def _norm_name(value: Any) -> str:
        return str(value or "").strip().lower().removesuffix(".exe")

    @staticmethod
    def _norm_path(value: Any) -> str:
        return str(value or "").strip().replace("/", "\\").rstrip("\\").lower()

    @staticmethod
    def _norm_registry(value: Any) -> str:
        return str(value or "").strip().replace("/", "\\").rstrip("\\").lower()

    @staticmethod
    def _norm_task(value: Any) -> str:
        return str(value or "").strip().replace("/", "\\").rstrip("\\").lower()

    @staticmethod
    def _canonical_root(value: str | Path) -> str:
        # PureWindowsPath gives deterministic checks on both Windows and Linux
        # test hosts without touching the target filesystem.
        return str(PureWindowsPath(str(value))).replace("/", "\\").rstrip("\\").lower()

    def _under_allowed_root(self, value: str) -> bool:
        candidate = self._norm_path(value)
        if not candidate:
            return False
        try:
            candidate_path = PureWindowsPath(candidate)
            if ".." in candidate_path.parts:
                return False
            for root in self.allowed_file_roots:
                root_path = PureWindowsPath(root)
                if candidate_path == root_path or root_path in candidate_path.parents:
                    return True
        except (TypeError, ValueError):
            return False
        return False

    def review(self, tool: str, arguments: dict[str, Any] | None = None) -> SafetyDecision:
        args = dict(arguments or {})
        tool = str(tool or "").strip()
        if tool in READ_ONLY_TOOLS:
            decision = SafetyDecision(True, "read-only tool", tool, args)
        elif tool not in RESPONSE_TOOLS:
            decision = SafetyDecision(False, "unsupported tool", tool, args, "unsupported_tool")
        elif tool == "kill_process":
            decision = self._review_kill(tool, args)
        elif tool == "remove_file":
            path = str(args.get("file_path") or args.get("path") or "")
            if not path:
                decision = SafetyDecision(False, "file path is required", tool, args, "missing_parameter")
            elif not self._under_allowed_root(path):
                decision = SafetyDecision(False, "file path is outside the allowed experiment root", tool, args, "path_boundary")
            elif self._norm_path(path) in self.protected_process_paths:
                decision = SafetyDecision(False, "protected process file path", tool, args, "protected_object")
            else:
                decision = SafetyDecision(True, "file path is within the allowed experiment root", tool, args)
        elif tool == "remove_registry":
            reg_path = self._norm_registry(args.get("reg_path") or args.get("key_path"))
            value_name = str(args.get("value_name") or "").strip()
            if not reg_path or not value_name:
                decision = SafetyDecision(False, "registry path and value name are required", tool, args, "missing_parameter")
            elif any(reg_path.startswith(prefix) for prefix in self.protected_registry_prefixes):
                decision = SafetyDecision(False, "protected registry namespace", tool, args, "protected_object")
            else:
                decision = SafetyDecision(True, "registry target passes safety boundary", tool, args)
        elif tool == "remove_scheduled_task":
            task_name = self._norm_task(args.get("task_name"))
            task_path = self._norm_task(args.get("task_path"))
            if not task_name:
                decision = SafetyDecision(False, "task name is required", tool, args, "missing_parameter")
            elif any((task_path or task_name).startswith(prefix) for prefix in self.protected_task_prefixes):
                decision = SafetyDecision(False, "protected scheduled-task namespace", tool, args, "protected_object")
            else:
                decision = SafetyDecision(True, "scheduled-task target passes safety boundary", tool, args)
        else:
            service = self._norm_name(args.get("service_name"))
            if not service:
                decision = SafetyDecision(False, "service name is required", tool, args, "missing_parameter")
            elif service in self.protected_service_names:
                decision = SafetyDecision(False, "protected service", tool, args, "protected_object")
            else:
                decision = SafetyDecision(True, "service target passes safety boundary", tool, args)
        self.decisions.append(decision)
        return decision

    def _review_kill(self, tool: str, args: dict[str, Any]) -> SafetyDecision:
        pid = args.get("pid")
        name = self._norm_name(args.get("process_name"))
        path = self._norm_path(args.get("expected_path") or args.get("process_path") or args.get("path"))
        if not pid and not name:
            return SafetyDecision(False, "pid or process name is required", tool, args, "missing_parameter")
        try:
            if int(pid or 0) in self.protected_process_pids:
                return SafetyDecision(False, "protected process PID", tool, args, "protected_object")
        except (TypeError, ValueError):
            return SafetyDecision(False, "invalid process PID", tool, args, "invalid_parameter")
        if name in self.protected_process_names:
            return SafetyDecision(False, "protected process name", tool, args, "protected_object")
        if path in self.protected_process_paths:
            return SafetyDecision(False, "protected process path", tool, args, "protected_object")
        return SafetyDecision(True, "process target passes safety boundary", tool, args)

    def mediate(self, tool: str, arguments: dict[str, Any] | None = None, executor: Callable[..., ToolResult] | None = None) -> ToolResult:
        args = dict(arguments or {})
        decision = self.review(tool, args)
        if not decision.allowed:
            return ToolResult(False, error=f"safety mediator blocked {tool}: {decision.reason}")
        if executor is None:
            return ToolResult(True, data={"mediated": True, "tool": tool, "arguments": args})
        return executor(**args)


__all__ = ["SafetyDecision", "SafetyMediator"]

