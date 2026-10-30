from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ntpath
import re
from typing import Any, Mapping, Protocol, Sequence

from c2trace.bench_v4.live_safety import CleanupBackendError, PowerShellCleanupBackend

from .models import content_hash


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,80}$")
ROOT_ID = "CTID-WEBSHELL-001"


class ReferenceResponseError(RuntimeError):
    pass


class ReferenceResponseTransport(Protocol):
    def inspect_process(self, pid: int) -> Mapping[str, Any]: ...

    def inspect_file(self, path: str) -> Mapping[str, Any]: ...

    def inspect_directory(self, path: str) -> Mapping[str, Any]: ...

    def inspect_registry(
        self, hive: str, key_path: str, value_name: str | None
    ) -> Mapping[str, Any]: ...

    def stop_process(self, pid: int) -> Mapping[str, Any]: ...

    def remove_file(self, path: str) -> Mapping[str, Any]: ...

    def remove_directory(self, path: str) -> Mapping[str, Any]: ...

    def remove_registry(
        self, hive: str, key_path: str, value_name: str | None
    ) -> Mapping[str, Any]: ...


def _normalise_path(value: Any) -> str:
    text = str(value or "").strip().strip('"')
    return ntpath.normcase(ntpath.normpath(text)) if text else ""


def _target_identity(target: Mapping[str, Any]) -> dict[str, Any]:
    pid = int(target.get("pid") or target.get("process_id") or 0)
    path = str(target.get("path") or target.get("canonical_path") or "").strip()
    creation = str(
        target.get("creation_time_utc") or target.get("creation_time") or ""
    ).strip()
    digest = str(target.get("sha256") or "").strip().casefold()
    if pid <= 0 or not ntpath.isabs(path) or not creation or not SHA256_RE.fullmatch(digest):
        raise ReferenceResponseError("reference target lacks exact PID/time/path/SHA-256 identity")
    return {
        "pid": pid,
        "path": path,
        "canonical_path": _normalise_path(path),
        "creation_time_utc": creation,
        "sha256": digest,
    }


def build_reference_response_plan(
    *,
    root_id: str,
    run_id: str,
    target: Mapping[str, Any],
    protected_processes: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if root_id != ROOT_ID:
        raise ReferenceResponseError(f"reference response is restricted to {ROOT_ID}")
    if not RUN_ID_RE.fullmatch(run_id):
        raise ReferenceResponseError("reference response RunId is not path-safe")
    identity = _target_identity(target)
    expected_path = _normalise_path(fr"C:\Users\Public\c2t_{run_id}.exe")
    if identity["canonical_path"] != expected_path:
        raise ReferenceResponseError("reference target path is outside the frozen RunId contract")

    for raw in protected_processes:
        if not isinstance(raw, Mapping):
            raise ReferenceResponseError("protected process entry is malformed")
        protected_pid = int(raw.get("pid") or raw.get("process_id") or 0)
        protected_path = _normalise_path(raw.get("path") or raw.get("canonical_path"))
        if protected_pid == identity["pid"] or (
            protected_path and protected_path == identity["canonical_path"]
        ):
            raise ReferenceResponseError("reference target collides with a protected process")

    actions = (
        {
            "action_id": "reference.stop_webshell_process",
            "tool": "stop_process",
            "target": {"path": identity["path"]},
            "expected": {
                "pid": identity["pid"],
                "creation_time_utc": identity["creation_time_utc"],
                "canonical_path": identity["canonical_path"],
                "sha256": identity["sha256"],
            },
        },
        {
            "action_id": "reference.remove_webshell_file",
            "tool": "remove_file",
            "target": {"path": identity["path"]},
            "expected": {
                "canonical_path": identity["canonical_path"],
                "sha256": identity["sha256"],
            },
        },
    )
    material = {
        "root_id": root_id,
        "run_id": run_id,
        "target": identity,
        "actions": actions,
        "protected_processes": [dict(row) for row in protected_processes],
    }
    return {
        "schema_version": "c2trace.benchmark.v1.reference_response_plan",
        **material,
        "plan_sha256": content_hash(material),
        "allowlisted_tools": ["stop_process", "remove_file"],
        "c2trace_used": False,
        "llm_used": False,
    }


def execute_reference_response(
    plan: Mapping[str, Any],
    transport: ReferenceResponseTransport,
) -> dict[str, Any]:
    if plan.get("schema_version") != "c2trace.benchmark.v1.reference_response_plan":
        raise ReferenceResponseError("unsupported reference response plan")
    if plan.get("root_id") != ROOT_ID:
        raise ReferenceResponseError("reference response plan has the wrong root")
    material = {
        "root_id": plan.get("root_id"),
        "run_id": plan.get("run_id"),
        "target": plan.get("target"),
        "actions": plan.get("actions"),
        "protected_processes": plan.get("protected_processes"),
    }
    if plan.get("plan_sha256") != content_hash(material):
        raise ReferenceResponseError("reference response plan content hash is invalid")
    if plan.get("allowlisted_tools") != ["stop_process", "remove_file"]:
        raise ReferenceResponseError("reference response tool allowlist drifted")
    if plan.get("c2trace_used") is not False or plan.get("llm_used") is not False:
        raise ReferenceResponseError("reference response must be independent of C2Trace and LLMs")
    actions = tuple(dict(row) for row in plan.get("actions") or [] if isinstance(row, Mapping))
    if len(actions) != 2 or [row.get("tool") for row in actions] != [
        "stop_process",
        "remove_file",
    ]:
        raise ReferenceResponseError("reference response plan must contain the exact two actions")
    target = _target_identity(plan.get("target") if isinstance(plan.get("target"), Mapping) else {})
    run_id = str(plan.get("run_id") or "")
    try:
        backend = PowerShellCleanupBackend(
            transport=transport,
            actions=actions,
            run_id=run_id,
            allowed_roots=[r"C:\Users\Public"],
            expected_file_hashes={target["path"]: target["sha256"]},
        )
    except CleanupBackendError as exc:
        raise ReferenceResponseError(f"reference response plan is unsafe: {exc}") from exc

    started = datetime.now(timezone.utc).isoformat()
    before: list[dict[str, Any]] = []
    for action in actions:
        try:
            observed = dict(backend.inspect(action))
        except CleanupBackendError as exc:
            raise ReferenceResponseError(
                f"reference prevalidation failed for {action['action_id']}: {exc}"
            ) from exc
        if observed.get("present") is not True:
            raise ReferenceResponseError(
                f"reference target is absent before {action['action_id']}; no real state change"
            )
        before.append(observed)

    results: list[dict[str, Any]] = []
    for action, prestate in zip(actions, before, strict=True):
        try:
            result = dict(backend.execute(action))
            poststate = dict(backend.inspect(action))
        except CleanupBackendError as exc:
            raise ReferenceResponseError(
                f"reference execution failed for {action['action_id']}: {exc}"
            ) from exc
        if poststate.get("present") is not False:
            raise ReferenceResponseError(f"{action['action_id']} did not make its target absent")
        results.append(
            {
                "action_id": action["action_id"],
                "tool": action["tool"],
                "request_sha256": content_hash(action),
                "prestate": prestate,
                "result": result,
                "poststate": poststate,
                "state_changed": True,
            }
        )
    completed = datetime.now(timezone.utc).isoformat()
    receipt_material = {
        "root_id": ROOT_ID,
        "run_id": run_id,
        "plan_sha256": str(plan.get("plan_sha256") or ""),
        "started_at_utc": started,
        "completed_at_utc": completed,
        "actions": results,
    }
    return {
        "schema_version": "c2trace.benchmark.v1.reference_response_receipt",
        **receipt_material,
        "receipt_sha256": content_hash(receipt_material),
        "all_actions_prevalidated": True,
        "actual_state_changed": all(row["state_changed"] for row in results),
        "c2trace_used": False,
        "llm_used": False,
        "secret_material_persisted": False,
    }


__all__ = [
    "ReferenceResponseError",
    "ReferenceResponseTransport",
    "build_reference_response_plan",
    "execute_reference_response",
]
