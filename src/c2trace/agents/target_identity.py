from __future__ import annotations

"""Auditor-owned target identity policy and MCP-side TOCTOU recheck."""

import ntpath
import re
from typing import Any, Mapping

from c2trace.models import CaseFile, StrategyNode
from c2trace.target_safety import TargetSafetyGuard
from c2trace.time_identity import compare_creation_times


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _path(value: Any) -> str:
    text = str(value or "").strip().strip('"')
    return ntpath.normcase(ntpath.normpath(text.replace("/", "\\"))) if text else ""


def _sha256(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if _SHA256_RE.fullmatch(text) else ""


def _pid(value: Any) -> int:
    try:
        result = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return result if result > 0 else 0


class TargetIdentityValidator:
    """The deterministic safety kernel owned and invoked by AuditorAgent."""

    def __init__(
        self,
        guard: TargetSafetyGuard | None = None,
        *,
        observer: Any | None = None,
        protected_processes: list[dict[str, Any]] | None = None,
        reviewed_target: dict[str, Any] | None = None,
        run_id: str = "",
        expected_target: dict[str, Any] | None = None,
        target_lock_schema_version: str = "",
    ) -> None:
        if guard is not None and observer is not None:
            raise ValueError("provide a legacy guard or an Executor observer, not both")
        self._observer = observer
        self._active_case: CaseFile | None = None
        self._active_node: StrategyNode | None = None
        if guard is None:
            if observer is None:
                raise ValueError("TargetIdentityValidator requires an Executor observer")
            # TargetSafetyGuard is retained only as the implementation-compatible
            # kernel for old artifacts/tests.  Production constructs and owns
            # this validator through AuditorAgent.
            guard = TargetSafetyGuard(
                tool_runner=self,
                protected_processes=protected_processes,
                reviewed_target=reviewed_target,
                run_id=run_id,
                expected_target=expected_target,
                target_lock_schema_version=target_lock_schema_version,
            )
        self._guard = guard

    @property
    def guard(self) -> TargetSafetyGuard:
        """Compatibility access for diagnostics; not a separate workflow role."""

        return self._guard

    def run(self, tool: str, params: dict[str, Any] | None = None) -> Any:
        """Compatibility adapter that delegates every observation to Executor."""

        if self._observer is None or self._active_case is None or self._active_node is None:
            raise RuntimeError("target observation requested outside Auditor lock acquisition")
        return self._observer.observe_target(
            self._active_case,
            self._active_node,
            tool,
            dict(params or {}),
        )

    def validate_case_input(self, case: CaseFile) -> None:
        self._guard.validate_case_input(case)

    def lock_response(
        self,
        case: CaseFile,
        node: StrategyNode,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        self._active_case = case
        self._active_node = node
        try:
            lock = self._guard.prepare_response(case, node, arguments)
        finally:
            self._active_case = None
            self._active_node = None
        case.add_timeline(
            "auditor_target_identity_validated",
            "Auditor validated and locked the exact response target",
            "auditor",
            refs=[node.node_id],
            details={
                "lock_id": str(lock.get("lock_id") or ""),
                "schema_version": str(lock.get("schema_version") or ""),
            },
        )
        return lock


def _persistence_matches(category: str, item: Mapping[str, Any], arguments: Mapping[str, Any]) -> bool:
    if category == "registry_run_keys":
        return (
            _path(item.get("path")) == _path(arguments.get("reg_path"))
            and str(item.get("name") or "").strip().casefold()
            == str(arguments.get("value_name") or "").strip().casefold()
            and (
                not arguments.get("expected_value")
                or str(item.get("value") or "") == str(arguments.get("expected_value") or "")
            )
        )
    if category == "scheduled_tasks":
        return (
            str(item.get("name") or "").strip().casefold()
            == str(arguments.get("task_name") or "").strip().casefold()
            and (
                not arguments.get("task_path")
                or _path(item.get("path")) == _path(arguments.get("task_path"))
            )
        )
    return (
        str(item.get("name") or "").strip().casefold()
        == str(arguments.get("service_name") or "").strip().casefold()
    )


def revalidate_target_before_response(
    backend: Any,
    *,
    tool: str,
    arguments: Mapping[str, Any],
    target_lock: Mapping[str, Any],
) -> dict[str, Any]:
    """Recheck the signed Auditor lock immediately before a side effect.

    The function returns a receipt on success and raises ``PermissionError``
    on any ambiguity or drift.  It intentionally performs no mutation.
    """
    lock_process = target_lock.get("process") if isinstance(target_lock.get("process"), Mapping) else {}
    lock_file = target_lock.get("file") if isinstance(target_lock.get("file"), Mapping) else {}
    receipt: dict[str, Any] = {
        "checked": True,
        "tool": tool,
        "lock_id": str(target_lock.get("lock_id") or ""),
        "comparisons": {},
    }

    if tool == "kill_process":
        expected_pid = _pid(lock_process.get("pid"))
        req_pid = _pid(arguments.get("pid"))
        secondary_pid = int(target_lock.get("secondary_pid") or 0)
        if req_pid != expected_pid and req_pid != secondary_pid:
            raise PermissionError("TOCTOU recheck rejected kill_process PID mismatch")
        # For sibling C2 processes, validate the sibling PID is live.
        if req_pid == secondary_pid and req_pid != expected_pid:
            result = backend.run("check_process", {"pid": req_pid})
            rows = result.data.get("processes", []) if result.success and isinstance(result.data, dict) else []
            matches = [
                item for item in rows
                if isinstance(item, Mapping) and _pid(item.get("pid") or item.get("process_id")) == req_pid
            ]
            if len(matches) != 1:
                raise PermissionError("TOCTOU recheck requires exactly one sibling process")
            receipt["comparisons"] = {
                "pid": {"expected": req_pid, "observed": req_pid, "matches": True, "sibling": True},
            }
            return receipt
        result = backend.run("check_process", {"pid": expected_pid})
        rows = result.data.get("processes", []) if result.success and isinstance(result.data, dict) else []
        matches = [
            item for item in rows
            if isinstance(item, Mapping) and _pid(item.get("pid") or item.get("process_id")) == expected_pid
        ]
        if len(matches) != 1:
            raise PermissionError("TOCTOU recheck requires exactly one locked process")
        observed = matches[0]
        observed_path = _path(observed.get("path") or observed.get("process_path") or observed.get("executable_path"))
        expected_path = _path(lock_process.get("canonical_path") or lock_process.get("path"))
        time_comparison = compare_creation_times(
            observed.get("creation_time_utc") or observed.get("creation_date"),
            lock_process.get("creation_time_utc"),
        )
        receipt["comparisons"] = {
            "pid": {"expected": expected_pid, "observed": expected_pid, "matches": True},
            "path": {"expected": expected_path, "observed": observed_path, "matches": observed_path == expected_path},
            "creation_time_utc": time_comparison.to_dict(),
        }
        if observed_path != expected_path or not time_comparison.matches:
            raise PermissionError("TOCTOU recheck detected locked process identity drift")
        file_result = backend.run("check_file_metadata", {"file_path": str(lock_process.get("path") or "")})
        file_info = file_result.data.get("file") if file_result.success and isinstance(file_result.data, dict) else None
        observed_hash = _sha256(file_info.get("sha256")) if isinstance(file_info, Mapping) else ""
        expected_hash = _sha256(lock_process.get("sha256"))
        receipt["comparisons"]["sha256"] = {
            "expected": expected_hash,
            "observed": observed_hash,
            "matches": bool(expected_hash and observed_hash == expected_hash),
        }
        if not expected_hash or observed_hash != expected_hash:
            raise PermissionError("TOCTOU recheck detected locked process hash drift")
        receipt["passed"] = True
        return receipt

    if tool == "remove_file":
        expected_path = _path(lock_file.get("canonical_path") or lock_file.get("path"))
        if _path(arguments.get("file_path")) != expected_path:
            raise PermissionError("TOCTOU recheck rejected remove_file path mismatch")
        result = backend.run("check_file_metadata", {"file_path": str(arguments.get("file_path") or "")})
        file_info = result.data.get("file") if result.success and isinstance(result.data, dict) else None
        if not isinstance(file_info, Mapping) or file_info.get("exists") is not True:
            raise PermissionError("TOCTOU recheck found no locked file")
        observed_path = _path(file_info.get("path"))
        observed_hash = _sha256(file_info.get("sha256"))
        expected_hash = _sha256(lock_file.get("sha256"))
        receipt["comparisons"] = {
            "path": {"expected": expected_path, "observed": observed_path, "matches": observed_path == expected_path},
            "sha256": {"expected": expected_hash, "observed": observed_hash, "matches": observed_hash == expected_hash},
        }
        if observed_path != expected_path or not expected_hash or observed_hash != expected_hash:
            raise PermissionError("TOCTOU recheck detected locked file identity drift")
        receipt["passed"] = True
        return receipt

    category = {
        "remove_registry": "registry_run_keys",
        "remove_scheduled_task": "scheduled_tasks",
        "remove_service": "services",
    }.get(tool)
    if category is None:
        raise PermissionError(f"TOCTOU recheck does not support response tool {tool}")
    locked_targets = [
        item for item in target_lock.get("persistence_targets", [])
        if isinstance(item, Mapping) and item.get("category") == category
    ]
    if not any(_persistence_matches(category, item, arguments) for item in locked_targets):
        raise PermissionError("TOCTOU recheck target is absent from the signed persistence lock")
    result = backend.run("check_persistence_all", {})
    live_items = result.data.get(category, []) if result.success and isinstance(result.data, dict) else []
    if not isinstance(live_items, list) or not any(
        isinstance(item, Mapping) and _persistence_matches(category, item, arguments)
        for item in live_items
    ):
        raise PermissionError("TOCTOU recheck detected persistence target drift")
    receipt["comparisons"] = {"persistence_target": {"category": category, "matches": True}}
    receipt["passed"] = True
    return receipt
