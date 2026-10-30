from __future__ import annotations

"""Fail-closed, post-scoring cleanup for Bench v4.

Cleanup is intentionally a separate two-phase transaction: every action is
rendered and read-only validated first; only then may any mutation occur.
This prevents a partially validated manifest from deleting host state.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import ntpath
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from c2trace.time_identity import creation_times_match as _shared_creation_times_match

from .runtime import BenchV4RuntimeError, RuntimeCase, RuntimeValues, render_runtime_value


class CleanupSafetyError(BenchV4RuntimeError):
    """Cleanup could not be proven safe and no further actions are allowed."""


class CleanupBackend(Protocol):
    def inspect(self, action: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def execute(self, action: Mapping[str, Any]) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class PreparedCleanup:
    case_id: str
    run_id: str
    score_path: str
    score_sha256: str
    actions: tuple[dict[str, Any], ...]


def _normalise_path(value: Any) -> str:
    text = str(value or "").strip().strip('"')
    return ntpath.normcase(ntpath.normpath(text)) if text else ""


def _normalise_time(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text[:-1] + "+00:00" if text.endswith("z") else text


# Windows Win32_Process.CreationDate can jitter by tens of milliseconds between
# two reads of the same process.  Compare the frozen vs. observed creation stamp
# with a small tolerance instead of an exact string match; fall back to the
# normalized-string compare when either value cannot be parsed as a datetime.
_CREATION_TIME_TOLERANCE_SECONDS = 2.0


def _creation_times_match(left: Any, right: Any) -> bool:
    return _shared_creation_times_match(left, right)


def _score_lock(path: str | Path) -> tuple[str, str]:
    target = Path(path).resolve()
    try:
        raw = target.read_bytes()
        payload = json.loads(raw.decode("utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CleanupSafetyError(f"scoring artifact is unavailable or invalid: {exc}") from exc
    if not isinstance(payload, dict) or not payload:
        raise CleanupSafetyError("cleanup requires a non-empty JSON scoring artifact")
    return str(target), hashlib.sha256(raw).hexdigest()


def _artifact_map(
    target_lock: Mapping[str, Any],
    frozen_artifacts: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    file_row = target_lock.get("file")
    if isinstance(file_row, Mapping):
        path = _normalise_path(file_row.get("path") or file_row.get("canonical_path"))
        if path:
            result[path] = dict(file_row)
    for row in frozen_artifacts:
        if not isinstance(row, Mapping):
            continue
        path = _normalise_path(row.get("path") or row.get("canonical_path"))
        if path:
            result[path] = dict(row)
    return result


def _protected_match(
    pid: int,
    creation_time: str,
    path: str,
    protected: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    wanted_path = _normalise_path(path)
    wanted_time = _normalise_time(creation_time)
    for row in protected:
        if int(row.get("pid") or 0) != pid:
            continue
        observed_time = _normalise_time(
            row.get("creation_time_utc") or row.get("creation_time")
        )
        observed_path = _normalise_path(
            row.get("canonical_path") or row.get("path")
        )
        if observed_time == wanted_time or observed_path == wanted_path:
            return dict(row)
    return None


def prepare_cleanup(
    runtime: RuntimeCase,
    values: RuntimeValues,
    *,
    target_lock: Mapping[str, Any],
    protected_processes: Sequence[Mapping[str, Any]],
    score_artifact: str | Path,
    frozen_artifacts: Sequence[Mapping[str, Any]] = (),
) -> PreparedCleanup:
    plan = runtime.cleanup_plan
    if plan.get("fail_closed") is not True:
        raise CleanupSafetyError("cleanup plan must be fail_closed")
    if str(target_lock.get("schema_version") or "") not in {
        "c2trace.response_target_lock.v1",
        "c2trace.response_target_lock.v2",
    }:
        raise CleanupSafetyError("cleanup requires a validated response target lock")
    if str(target_lock.get("case_id") or "") != runtime.case_id:
        raise CleanupSafetyError("target lock case_id differs from cleanup case")
    if str(target_lock.get("run_id") or "") != values.run_id:
        raise CleanupSafetyError("target lock run_id differs from cleanup run")
    score_path, score_sha256 = _score_lock(score_artifact)
    artifacts = _artifact_map(target_lock, frozen_artifacts)
    replacements = {
        "run_id": values.run_id,
        "victim_ip": values.victim_ip,
        "kali_ip": values.kali_ip,
        "webshell_port": values.webshell_port or "",
        "c2trace.appdata": values.appdata,
        **values.facts,
    }
    prepared: list[dict[str, Any]] = []
    seen: set[str] = set()
    supported_tools = {
        "stop_process",
        "remove_file",
        "remove_directory",
        "remove_registry",
        "remove_scheduled_task",
        "remove_service",
    }
    for raw in plan.get("actions", []):
        if not isinstance(raw, Mapping):
            raise CleanupSafetyError("cleanup action is malformed")
        target_role = str(raw.get("target_role") or "primary")
        if target_role == "secondary":
            process = target_lock.get("secondary_process") if isinstance(target_lock.get("secondary_process"), Mapping) else {}
        else:
            process = target_lock.get("process") if isinstance(target_lock.get("process"), Mapping) else {}
        action_id = str(raw.get("action_id") or "")
        if not action_id or action_id in seen:
            raise CleanupSafetyError("cleanup action IDs must be non-empty and unique")
        seen.add(action_id)
        if raw.get("phase") != "after_scoring":
            raise CleanupSafetyError(f"cleanup action {action_id} is not post-scoring")
        target = render_runtime_value(raw.get("target_template") or {}, replacements)
        if not isinstance(target, Mapping):
            raise CleanupSafetyError(f"cleanup action {action_id} target is invalid")
        checks = [str(value) for value in raw.get("identity_validation", [])]
        resolved = {
            "action_id": action_id,
            "tool": str(raw.get("tool") or ""),
            "target": dict(target),
            "identity_validation": checks,
            "required": raw.get("required") is True,
            "source_step_ids": list(raw.get("source_step_ids") or []),
            "expected": {},
        }
        if resolved["tool"] not in supported_tools:
            raise CleanupSafetyError(
                f"cleanup action {action_id} uses an unsupported fail-closed tool: "
                f"{resolved['tool']}"
            )
        path = _normalise_path(target.get("path"))
        if "run_id" in checks:
            identity_text = " ".join(str(value) for value in target.values()).lower()
            target_name = str(values.facts.get("c2trace.target_name") or "").lower()
            if values.run_id.lower() not in identity_text and (
                not target_name or target_name not in identity_text
            ):
                raise CleanupSafetyError(
                    f"cleanup action {action_id} is not bound to this run ID"
                )
        if "path" in checks:
            if not path or path in {"\\", "."}:
                raise CleanupSafetyError(f"cleanup action {action_id} lacks an exact path")
            resolved["expected"]["canonical_path"] = path
        if "pid" in checks:
            pid = int(process.get("pid") or 0)
            if pid <= 0:
                raise CleanupSafetyError(f"cleanup action {action_id} lacks a locked PID")
            resolved["expected"]["pid"] = pid
        if "creation_time" in checks:
            creation = str(
                process.get("creation_time_utc")
                or process.get("creation_time")
                or ""
            )
            if not creation:
                raise CleanupSafetyError(
                    f"cleanup action {action_id} lacks a locked creation time"
                )
            resolved["expected"]["creation_time_utc"] = creation
        if "sha256" in checks:
            artifact = artifacts.get(path)
            digest = str((artifact or {}).get("sha256") or "").lower()
            if len(digest) != 64:
                raise CleanupSafetyError(
                    f"cleanup action {action_id} lacks a frozen SHA-256"
                )
            resolved["expected"]["sha256"] = digest
        if "registry_value" in checks:
            if not target.get("hive") or not target.get("key_path"):
                raise CleanupSafetyError(
                    f"cleanup action {action_id} lacks an exact registry target"
                )
        if "task_action" in checks and not target.get("task_name"):
            raise CleanupSafetyError(f"cleanup action {action_id} lacks a task name")
        if "service_binary" in checks and not target.get("service_name"):
            raise CleanupSafetyError(f"cleanup action {action_id} lacks a service name")
        if resolved["tool"] == "stop_process":
            target_type = str(runtime.target.get("target_type") or "")
            if target_type in ("carbanak_cscript_https_rat_outbound", "emotet_dll_http_outbound", "plugx_http_outbound"):
                resolved["expected"]["command_line_hosted"] = True
            protected = _protected_match(
                int(resolved["expected"].get("pid") or 0),
                str(resolved["expected"].get("creation_time_utc") or ""),
                str(target.get("path") or ""),
                protected_processes,
            )
            if protected is not None:
                raise CleanupSafetyError(
                    f"cleanup action {action_id} resolves to a protected control process"
                )
        prepared.append(resolved)
    return PreparedCleanup(
        case_id=runtime.case_id,
        run_id=values.run_id,
        score_path=score_path,
        score_sha256=score_sha256,
        actions=tuple(prepared),
    )


def _validate_observation(action: Mapping[str, Any], observed: Mapping[str, Any]) -> None:
    action_id = str(action["action_id"])
    if not isinstance(observed.get("present"), bool):
        raise CleanupSafetyError(f"cleanup inspection {action_id} lacks a present boolean")
    if observed["present"] is False:
        return
    expected = action.get("expected") if isinstance(action.get("expected"), Mapping) else {}
    if expected.get("command_line_hosted") is True:
        observed_cmd = str(observed.get("command_line") or "")
        if str(expected.get("canonical_path") or "").casefold() not in observed_cmd.casefold():
            raise CleanupSafetyError(f"cleanup inspection {action_id} command line does not contain payload path")
    elif "canonical_path" in expected:
        actual_path = _normalise_path(observed.get("path") or observed.get("canonical_path"))
        if actual_path != str(expected["canonical_path"]):
            raise CleanupSafetyError(f"cleanup inspection {action_id} path drifted")
    if "pid" in expected and int(observed.get("pid") or 0) != int(expected["pid"]):
        raise CleanupSafetyError(f"cleanup inspection {action_id} PID drifted")
    if "creation_time_utc" in expected and not _creation_times_match(
        observed.get("creation_time_utc") or observed.get("creation_time"),
        expected["creation_time_utc"],
    ):
        raise CleanupSafetyError(f"cleanup inspection {action_id} creation time drifted")
    if "sha256" in expected and str(observed.get("sha256") or "").lower() != str(
        expected["sha256"]
    ).lower():
        raise CleanupSafetyError(f"cleanup inspection {action_id} SHA-256 drifted")
    for key in ("registry_value", "task_action", "service_binary"):
        if key in action.get("identity_validation", []):
            wanted = action["target"].get(key)
            actual = observed.get(key)
            if wanted is not None and str(actual) != str(wanted):
                raise CleanupSafetyError(f"cleanup inspection {action_id} {key} drifted")
    target = action.get("target") if isinstance(action.get("target"), Mapping) else {}
    tool = str(action.get("tool") or "")
    if tool == "remove_registry":
        for key in ("hive", "key_path", "value_name"):
            wanted = target.get(key)
            if wanted is not None and str(observed.get(key) or "").casefold() != str(
                wanted
            ).casefold():
                raise CleanupSafetyError(
                    f"cleanup inspection {action_id} registry {key} drifted"
                )
    elif tool == "remove_scheduled_task":
        for key in ("task_name", "task_path"):
            wanted = target.get(key)
            if wanted is not None and str(observed.get(key) or "").casefold() != str(
                wanted
            ).casefold():
                raise CleanupSafetyError(
                    f"cleanup inspection {action_id} scheduled-task {key} drifted"
                )
    elif tool == "remove_service":
        wanted = target.get("service_name")
        if wanted is not None and str(observed.get("service_name") or "").casefold() != str(
            wanted
        ).casefold():
            raise CleanupSafetyError(
                f"cleanup inspection {action_id} service name drifted"
            )


def execute_cleanup(prepared: PreparedCleanup, backend: CleanupBackend) -> dict[str, Any]:
    """Validate every action, then mutate; any drift blocks the whole plan."""

    inspections: list[dict[str, Any]] = []
    for action in prepared.actions:
        try:
            observed = backend.inspect(action)
        except Exception as exc:  # pragma: no cover - adapter-specific failure
            raise CleanupSafetyError(
                f"cleanup inspection {action['action_id']} failed: {exc}"
            ) from exc
        if not isinstance(observed, Mapping):
            raise CleanupSafetyError(
                f"cleanup inspection {action['action_id']} returned malformed data"
            )
        _validate_observation(action, observed)
        inspections.append(dict(observed))

    results: list[dict[str, Any]] = []
    for action, before in zip(prepared.actions, inspections, strict=True):
        if before.get("present") is False:
            results.append(
                {"action_id": action["action_id"], "status": "already_absent"}
            )
            continue
        # Re-check at the last possible moment.  The first pass proves the
        # complete plan is valid; this second pass closes the validation/use
        # window for PID reuse and artifact replacement.
        current = backend.inspect(action)
        if not isinstance(current, Mapping):
            raise CleanupSafetyError(
                f"cleanup inspection {action['action_id']} returned malformed data"
            )
        _validate_observation(action, current)
        if current.get("present") is False:
            results.append(
                {"action_id": action["action_id"], "status": "already_absent"}
            )
            continue
        try:
            result = backend.execute(action)
        except Exception as exc:  # pragma: no cover - adapter-specific failure
            raise CleanupSafetyError(
                f"cleanup action {action['action_id']} failed; manual review required: {exc}"
            ) from exc
        if not isinstance(result, Mapping) or result.get("success") is not True:
            raise CleanupSafetyError(
                f"cleanup action {action['action_id']} did not confirm success; "
                "manual review required"
            )
        after = backend.inspect(action)
        if not isinstance(after, Mapping) or after.get("present") is not False:
            raise CleanupSafetyError(
                f"cleanup action {action['action_id']} left the target present; "
                "manual review required"
            )
        results.append(
            {"action_id": action["action_id"], "status": "removed", "result": dict(result)}
        )
    return {
        "schema_version": "c2trace.bench.cleanup_receipt.v4",
        "case_id": prepared.case_id,
        "run_id": prepared.run_id,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "score_path": prepared.score_path,
        "score_sha256": prepared.score_sha256,
        "all_actions_prevalidated": True,
        "actions": results,
        "manual_review_required": False,
    }
