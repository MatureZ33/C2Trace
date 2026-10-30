from __future__ import annotations

"""Concrete Windows adapters for the Bench v4 live boundary.

The public contracts in :mod:`live_safety` stay dependency-injected.  This
module is the only place that turns those contracts into local Windows and
CALDERA observations.  It performs no work at import time.
"""

import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
from typing import Any, Mapping, Sequence

from c2trace.bench_v4.windows_admin import BenchWindowsAdmin


class WindowsAdapterError(RuntimeError):
    """A privileged/read-only Windows adapter returned an invalid result."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tool_data(result: Any, label: str) -> dict[str, Any]:
    if getattr(result, "success", False) is not True:
        raise WindowsAdapterError(
            f"{label} failed: {getattr(result, 'error', None) or 'unknown error'}"
        )
    value = getattr(result, "data", None)
    if not isinstance(value, Mapping):
        raise WindowsAdapterError(f"{label} returned malformed data")
    return dict(value)


class WindowsLivePreflightDependencies:
    """Read-only observations required by ``run_live_preflight``."""

    def __init__(
        self,
        *,
        project_root: str | Path,
        caldera_client: Any,
        active_vm_snapshot_id: str,
        model_name: str,
        api_key_present: bool,
        runner: BenchWindowsAdmin | None = None,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.client = caldera_client
        self.active_vm_snapshot_id = str(active_vm_snapshot_id or "").strip()
        self.model_name = str(model_name or "").strip()
        self.api_key_present = bool(api_key_present)
        self.runner = runner or BenchWindowsAdmin(execute_response=False)

    def is_admin(self) -> bool:
        if os.name != "nt":
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False

    def inspect_file(self, path: str) -> Mapping[str, Any]:
        target = Path(path)
        if not target.is_file():
            return {"exists": False, "is_file": False, "path": str(target)}
        resolved = target.resolve()
        return {
            "exists": True,
            "is_file": True,
            "path": str(resolved),
            "sha256": _sha256(resolved),
            "size": resolved.stat().st_size,
        }

    def inspect_directory(self, path: str) -> Mapping[str, Any]:
        target = Path(path)
        exists = target.is_dir()
        return {
            "exists": exists,
            "is_directory": exists,
            "writable": exists and os.access(target, os.W_OK),
            "path": str(target.resolve()) if exists else str(target),
        }

    def tcp_reachable(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, int(port)), timeout=2.0):
                return True
        except OSError:
            return False

    def _host_adapter(self, action: str, *arguments: str) -> dict[str, Any]:
        script = self.project_root / "scripts" / "c2trace_bench_v4_host_adapter.ps1"
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script),
                "-Action",
                action,
                *arguments,
            ],
            cwd=str(self.project_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if completed.returncode != 0:
            raise WindowsAdapterError(
                f"host adapter {action} failed: {(completed.stderr or completed.stdout)[-1600:]}"
            )
        try:
            value = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise WindowsAdapterError(f"host adapter {action} returned invalid JSON") from exc
        if not isinstance(value, Mapping):
            raise WindowsAdapterError(f"host adapter {action} returned a non-object")
        return dict(value)

    def inspect_interface(self, name: str) -> Mapping[str, Any]:
        if not name or any(character in name for character in "*?[]"):
            return {"exists": False, "up": False, "capture_capable": False, "name": name}
        value = self._host_adapter("inspect_interface", "-Name", name)
        # Npcap presence is checked separately by the preflight contract.  An
        # exact, enabled Windows adapter is therefore capture-capable here.
        value["capture_capable"] = value.get("exists") is True and value.get("up") is True
        return value

    def model_configuration(self) -> Mapping[str, Any]:
        return {"model": self.model_name, "api_key_present": self.api_key_present}

    def current_vm_snapshot_id(self) -> str:
        return self.active_vm_snapshot_id

    def caldera_agents(self) -> Sequence[Mapping[str, Any]]:
        return self.client.agents()

    def caldera_operations(self) -> Sequence[Mapping[str, Any]]:
        return self.client.operations()

    def inspect_process(self, pid: int) -> Mapping[str, Any]:
        data = _tool_data(self.runner.run("check_process", {"pid": int(pid)}), "check_process")
        rows = data.get("processes")
        matches = [dict(row) for row in rows or [] if isinstance(row, Mapping)]
        if not matches:
            return {"running": False, "pid": int(pid)}
        if len(matches) != 1 or int(matches[0].get("pid") or 0) != int(pid):
            raise WindowsAdapterError("process observation is ambiguous")
        return {"running": True, **matches[0]}

    def now_utc(self) -> datetime:
        return datetime.now(timezone.utc)


class PowerShellCleanupTransport:
    """Exact-selector transport used by the two-phase cleanup backend."""

    def __init__(
        self,
        *,
        project_root: str | Path,
        runner: BenchWindowsAdmin | None = None,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.runner = runner or BenchWindowsAdmin(execute_response=False)
        self.script = self.project_root / "scripts" / "c2trace_bench_v4_host_adapter.ps1"

    def _invoke(self, action: str, *arguments: str) -> dict[str, Any]:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(self.script),
                "-Action",
                action,
                *arguments,
            ],
            cwd=str(self.project_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if completed.returncode != 0:
            raise WindowsAdapterError(
                f"cleanup transport {action} failed: {(completed.stderr or completed.stdout)[-1600:]}"
            )
        try:
            value = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise WindowsAdapterError(f"cleanup transport {action} returned invalid JSON") from exc
        if not isinstance(value, Mapping):
            raise WindowsAdapterError(f"cleanup transport {action} returned a non-object")
        return dict(value)

    def inspect_process(self, pid: int) -> Mapping[str, Any]:
        data = _tool_data(self.runner.run("check_process", {"pid": int(pid)}), "check_process")
        rows = [dict(row) for row in data.get("processes") or [] if isinstance(row, Mapping)]
        if not rows:
            return {"present": False, "pid": int(pid)}
        if len(rows) != 1 or int(rows[0].get("pid") or 0) != int(pid):
            raise WindowsAdapterError("cleanup process observation is ambiguous")
        return {"present": True, **rows[0]}

    def inspect_file(self, path: str) -> Mapping[str, Any]:
        data = _tool_data(
            self.runner.run("check_file_metadata", {"file_path": path}),
            "check_file_metadata",
        )
        row = data.get("file") if isinstance(data.get("file"), Mapping) else {}
        return {"present": row.get("exists") is True, **dict(row)}

    def inspect_directory(self, path: str) -> Mapping[str, Any]:
        return self._invoke("inspect_directory", "-Path", path)

    def inspect_registry(
        self, hive: str, key_path: str, value_name: str | None
    ) -> Mapping[str, Any]:
        arguments = ["-Hive", hive, "-KeyPath", key_path]
        if value_name is not None:
            arguments.extend(["-ValueName", value_name])
        return self._invoke("inspect_registry", *arguments)

    def stop_process(self, pid: int) -> Mapping[str, Any]:
        return self._invoke("stop_process", "-ProcessId", str(int(pid)))

    def remove_file(self, path: str) -> Mapping[str, Any]:
        return self._invoke("remove_file", "-Path", path)

    def remove_directory(self, path: str) -> Mapping[str, Any]:
        return self._invoke("remove_directory", "-Path", path)

    def remove_registry(
        self, hive: str, key_path: str, value_name: str | None
    ) -> Mapping[str, Any]:
        arguments = ["-Hive", hive, "-KeyPath", key_path]
        if value_name is not None:
            arguments.extend(["-ValueName", value_name])
        return self._invoke("remove_registry", *arguments)


__all__ = [
    "PowerShellCleanupTransport",
    "WindowsAdapterError",
    "WindowsLivePreflightDependencies",
]
