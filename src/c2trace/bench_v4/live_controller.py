from __future__ import annotations

"""Complete, evidence-bound live transaction for one Bench v4 trial.

The batch entry point owns Suricata lifetime and Resume policy.  This module
owns exactly one already-preflighted trial from baseline through post-score
cleanup.  Ground Truth is kept out of the C2Trace execution window and is
materialized only after the dry-run and execute passes have completed.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import ntpath
from pathlib import Path
import time
from typing import Any, Callable, Mapping, Sequence

from c2trace.bench_v3.caldera_client import agent_is_recent, agent_paw, agent_pid
from c2trace.bench_v4.windows_admin import BenchWindowsAdmin

from .cleanup import execute_cleanup, prepare_cleanup
from .controller_support import (
    PersistentJournal,
    build_operational_metrics,
    build_scoring_casefile,
    dry_run_gate,
    read_json,
    response_tools_from_ground_truth,
    run_c2trace,
    selected_source,
    synthetic_failure_casefile,
    utc_now,
    write_json_atomic,
)
from .evidence import EvidenceCaptureError, PlanDrivenEvidenceCollector
from .live_safety import (
    PayloadWriteAuthorization,
    PowerShellCleanupBackend,
    guarded_caldera_write,
)
from .runtime import (
    BenchV4RuntimeError,
    CalderaBootstrapPhaseResult,
    CalderaPhaseResult,
    CalderaScenarioPhaseResult,
    CalderaTargetCandidate,
    RuntimeCase,
    RuntimeValues,
    resolve_caldera_target_phase,
    run_caldera_bootstrap_phase,
    run_caldera_scenario_phase,
)
from .scorer import score_case, write_score_outputs
from .transaction import (
    build_protected_processes_v2,
    build_protected_manifest_safe,
    build_cleanup_ground_truth,
    evaluate_baseline_clean,
    evaluate_post_response,
    materialize_ground_truth,
    snapshot_unchanged,
)
from .windows_adapter import PowerShellCleanupTransport
from c2trace.baseline.neutral_records import project_for_scoring


class LiveControllerError(BenchV4RuntimeError):
    """A live trial could not preserve the evaluation transaction."""


_WEBSHELL_SCENARIO_ABILITY_IDS = {
    "dc934e5a-3184-5b6f-8535-a78cc2adfac5",
    "87bd9d84-f8b7-5810-9a53-ce0a9cdb589d",
}


def response_authorization_receipt(
    action_result: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Return the public MCP authorization receipt from an action result."""

    direct = action_result.get("authorization_receipt")
    if isinstance(direct, Mapping) and direct:
        return direct
    transport = action_result.get("transport_receipt")
    if not isinstance(transport, Mapping):
        return {}
    nested = transport.get("authorization_receipt")
    return nested if isinstance(nested, Mapping) else {}


def validate_webshell_scenario_semantics(
    runtime: RuntimeCase, event_logs: Sequence[Mapping[str, Any]]
) -> None:
    """Reject HTTP-200 WebShell responses that contain application errors."""

    if runtime.case_id != "MEP-WINDOWS-WEBSHELL-01":
        return
    by_ability: dict[str, list[Mapping[str, Any]]] = {
        ability_id: [] for ability_id in _WEBSHELL_SCENARIO_ABILITY_IDS
    }
    for event in event_logs:
        metadata = (
            event.get("ability_metadata")
            if isinstance(event.get("ability_metadata"), Mapping)
            else {}
        )
        ability_id = str(metadata.get("ability_id") or "")
        if ability_id in by_ability:
            by_ability[ability_id].append(event)
    for ability_id, matches in by_ability.items():
        if len(matches) != 1:
            raise LiveControllerError(
                f"WebShell Scenario semantic evidence for {ability_id} is absent or ambiguous"
            )
        output = (
            matches[0].get("output")
            if isinstance(matches[0].get("output"), Mapping)
            else {}
        )
        stdout = str(output.get("stdout") or "").strip()
        try:
            response = json.loads(stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            raise LiveControllerError(
                f"WebShell Scenario response for {ability_id} is not valid JSON"
            ) from exc
        if not isinstance(response, Mapping):
            raise LiveControllerError(
                f"WebShell Scenario response for {ability_id} is not an object"
            )
        error = str(response.get("Error") or "").strip()
        error_string = str(response.get("ErrorString") or "").strip()
        if error or error_string:
            raise LiveControllerError(
                f"WebShell Scenario returned an application error for {ability_id}: "
                f"{error or error_string}"
            )


@dataclass(frozen=True, slots=True)
class TrialExecutionConfig:
    project_root: Path
    result_root: Path
    eve_path: Path
    python: Path
    caldera_server: str
    operation_timeout: float = 360.0
    poll_seconds: float = 3.0
    evidence_timeout: float = 45.0
    # Baseline agents have an independent response contract.  They still use
    # the shared evidence transaction and post-state collector, but their
    # response attempt must not be rejected by C2Trace's target-lock/dry-run
    # gate.  Cleanup remains controller-owned and happens only after scoring.
    baseline_mode: bool = False


def _normalise_path(value: Any) -> str:
    text = str(value or "").strip().strip('"')
    return ntpath.normcase(ntpath.normpath(text)) if text else ""


def _tool_data(result: Any, label: str) -> dict[str, Any]:
    if getattr(result, "success", False) is not True:
        raise LiveControllerError(
            f"{label} failed: {getattr(result, 'error', None) or 'unknown error'}"
        )
    value = getattr(result, "data", None)
    if not isinstance(value, Mapping):
        raise LiveControllerError(f"{label} returned malformed data")
    return dict(value)


def _single_process(
    runner: BenchWindowsAdmin,
    pid: int,
    expected_path: str,
    *,
    match_command_line: bool = False,
) -> dict[str, Any]:
    data = _tool_data(runner.run("check_process", {"pid": int(pid)}), "check_process")
    rows = [
        dict(row)
        for row in data.get("processes") or []
        if isinstance(row, Mapping) and int(row.get("pid") or 0) == int(pid)
    ]
    if len(rows) != 1:
        raise LiveControllerError(f"target PID {pid} is absent or ambiguous")
    path = str(rows[0].get("path") or "")
    command_line = str(rows[0].get("command_line") or "")
    if match_command_line:
        if _normalise_path(expected_path).casefold() not in command_line.casefold():
            raise LiveControllerError(
                "target process command line does not contain the expected payload path"
            )
    elif _normalise_path(path) != _normalise_path(expected_path):
        raise LiveControllerError("target process path differs from the frozen runtime path")
    created = str(
        rows[0].get("creation_time_utc")
        or rows[0].get("creation_time")
        or rows[0].get("creation_date")
        or ""
    )
    if not created:
        raise LiveControllerError("target process lacks a creation-time identity")
    return {**rows[0], "path": path, "creation_time_utc": created}


def _single_file(runner: BenchWindowsAdmin, path: str) -> dict[str, Any]:
    data = _tool_data(
        runner.run("check_file_metadata", {"file_path": path}),
        "check_file_metadata",
    )
    row = data.get("file") if isinstance(data.get("file"), Mapping) else {}
    digest = str(row.get("sha256") or "").strip().lower()
    if (
        row.get("exists") is not True
        or _normalise_path(row.get("path")) != _normalise_path(path)
        or len(digest) != 64
    ):
        raise LiveControllerError("target executable path/hash could not be frozen")
    return {**dict(row), "sha256": digest}


def _network_rows(
    runner: BenchWindowsAdmin,
    runtime: RuntimeCase,
    values: RuntimeValues,
) -> list[dict[str, Any]]:
    target = runtime.target
    if target["network_mode"] == "inbound_listener":
        params = {
            "network_mode": "inbound_listener",
            "local_ip": values.victim_ip,
            "local_port": int(values.webshell_port or 0),
        }
    else:
        params = {
            "remote_ip": values.kali_ip,
            "remote_port": int(target["contact"]["listener_port"]),
        }
    data = _tool_data(runner.run("check_network", params), "check_network")
    return [dict(row) for row in data.get("connections") or [] if isinstance(row, Mapping)]


def freeze_target_identity(
    runner: BenchWindowsAdmin,
    runtime: RuntimeCase,
    values: RuntimeValues,
    raw_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Freeze one process/file/five-tuple target without guessing by name."""

    raw = dict(raw_identity or {})
    requested_pid = int(raw.get("pid") or raw.get("process_id") or 0)
    candidates: list[dict[str, Any]] = []
    for attempt in range(15):
        candidates = []
        for row in _network_rows(runner, runtime, values):
            pid = int(row.get("pid") or row.get("owning_process") or 0)
            if requested_pid and pid != requested_pid:
                continue
            state = str(row.get("state") or "").casefold()
            if runtime.target["network_mode"] == "inbound_listener":
                if int(row.get("local_port") or 0) != int(values.webshell_port or 0):
                    continue
                if state not in {"listen", "listening"}: continue
            else:
                if str(row.get("remote_address") or "") != values.kali_ip:
                    continue
                if int(row.get("remote_port") or 0) != int(runtime.target["contact"]["listener_port"]):
                    continue
                if state != "established":
                    continue
            if pid > 0:
                candidates.append(row)
        if len(candidates) == 1:
            break
        time.sleep(2)
    if len(candidates) != 1:
        raise LiveControllerError(f"target requires one exact live network owner; found {len(candidates)}")
    connection = candidates[0]
    pid = int(connection.get("pid") or connection.get("owning_process") or 0)
    target_type = str(runtime.target.get("target_type") or "")
    match_cmd = target_type in ("carbanak_cscript_https_rat_outbound", "emotet_dll_http_outbound", "plugx_http_outbound")
    process = _single_process(
        runner, pid, values.target_path, match_command_line=match_cmd,
    )
    file_info = _single_file(runner, values.target_path)
    result = {
        **raw,
        "pid": pid,
        "path": values.target_path,
        "canonical_path": _normalise_path(values.target_path),
        "creation_time_utc": process["creation_time_utc"],
        "sha256": file_info["sha256"],
        "executable_path": process.get("path") or "",
        "executable_sha256": "",
        "command_line": process.get("command_line") or "",
        "local_address": str(connection.get("local_address") or values.victim_ip),
        "local_port": int(connection.get("local_port") or 0),
        "remote_address": str(connection.get("remote_address") or values.kali_ip),
        "remote_port": int(connection.get("remote_port") or 0),
        "network": dict(connection),
        "host": str(raw.get("host") or raw.get("hostname") or "WIN10"),
    }
    executable_path = str(result.get("executable_path") or "")
    if executable_path and _normalise_path(executable_path) != _normalise_path(values.target_path):
        try:
            exec_file_info = _single_file(runner, executable_path)
            result["executable_sha256"] = exec_file_info.get("sha256", "")
        except LiveControllerError:
            pass
    else:
        result["executable_sha256"] = result.get("sha256", "")
    secondary_pid = int(raw.get("secondary_pid") or 0)
    if secondary_pid > 0:
        try:
            secondary_process = _single_process(runner, secondary_pid, values.target_path)
            result["secondary_creation_time_utc"] = secondary_process["creation_time_utc"]
        except LiveControllerError:
            pass
    return result


def control_identity_from_preflight(receipt: Mapping[str, Any]) -> dict[str, Any]:
    row = receipt.get("control_agent")
    if not isinstance(row, Mapping):
        raise LiveControllerError("live preflight has no protected control identity")
    return {
        **dict(row),
        "creation_time_utc": str(row.get("process_creation_time_utc") or ""),
        "sha256": str(row.get("file_sha256") or "").lower(),
    }


def refresh_control_identity(
    client: Any,
    runner: BenchWindowsAdmin,
    expected: Mapping[str, Any],
) -> dict[str, Any] | None:
    matches = [
        dict(row)
        for row in client.agents()
        if isinstance(row, Mapping)
        and agent_paw(row) == str(expected.get("paw") or "")
        and agent_pid(row) == int(expected.get("pid") or 0)
        and agent_is_recent(row, now=datetime.now(timezone.utc))
    ]
    if len(matches) != 1:
        return None
    try:
        process = _single_process(
            runner, int(expected.get("pid") or 0), str(expected.get("path") or "")
        )
        file_info = _single_file(runner, str(expected.get("path") or ""))
    except LiveControllerError:
        return None
    return {
        **matches[0],
        "paw": agent_paw(matches[0]),
        "pid": agent_pid(matches[0]),
        "path": str(expected.get("path") or ""),
        "creation_time_utc": process["creation_time_utc"],
        "sha256": file_info["sha256"],
    }


def _agent_identity(raw: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(raw, Mapping):
        return None
    return {
        **dict(raw),
        "paw": agent_paw(raw),
        "pid": agent_pid(raw),
        "path": str(raw.get("path") or raw.get("exe_name") or raw.get("location") or ""),
        "creation_time_utc": str(raw.get("creation_time_utc") or raw.get("created") or ""),
        "sha256": str(raw.get("sha256") or ""),
    }


def refresh_driver_identity(client: Any, expected: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(expected, Mapping):
        return None
    matches = [
        dict(row)
        for row in client.agents()
        if isinstance(row, Mapping)
        and agent_paw(row) == agent_paw(expected)
        and agent_pid(row) == agent_pid(expected)
        and agent_is_recent(row, now=datetime.now(timezone.utc))
    ]
    return _agent_identity(matches[0]) if len(matches) == 1 else None


def _capture_with_wait(
    collector: PlanDrivenEvidenceCollector,
    stage: str,
    *,
    timeout: float,
    poll_seconds: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return collector.capture_stage(stage)
        except EvidenceCaptureError as exc:
            last_error = exc
            time.sleep(min(max(poll_seconds, 0.1), 5.0))
    raise LiveControllerError(
        f"evidence stage {stage} did not become complete: {last_error}"
    )


def _trace_observations(evidence: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for capture in evidence.get("captures") or []:
        if not isinstance(capture, Mapping) or not isinstance(capture.get("result"), Mapping):
            continue
        rows = capture["result"].get("trace_observations")
        if isinstance(rows, Mapping):
            for key, value in rows.items():
                if isinstance(value, Mapping):
                    result[str(key)] = dict(value)
    return result


def _frozen_artifacts(evidence: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for observation in _trace_observations(evidence).values():
        data = observation.get("data") if isinstance(observation.get("data"), Mapping) else {}
        candidates: list[Mapping[str, Any]] = []
        if isinstance(data.get("file"), Mapping):
            candidates.append(data["file"])
        if isinstance(data.get("files"), list):
            candidates.extend(row for row in data["files"] if isinstance(row, Mapping))
        rows.extend(dict(row) for row in candidates if row.get("exists") is True)
    return rows


def _registry_expectations(
    actions: Sequence[Mapping[str, Any]], evidence: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    observations = _trace_observations(evidence)
    registry_rows: list[dict[str, Any]] = []
    for observation in observations.values():
        data = observation.get("data") if isinstance(observation.get("data"), Mapping) else {}
        for field in ("registry_values", "registry_run_keys"):
            values = data.get(field)
            if isinstance(values, list):
                registry_rows.extend(dict(row) for row in values if isinstance(row, Mapping))
    result: dict[str, dict[str, Any]] = {}
    for action in actions:
        if action.get("tool") != "remove_registry":
            continue
        target = action.get("target") if isinstance(action.get("target"), Mapping) else {}
        hive = str(target.get("hive") or "").upper()
        key = str(target.get("key_path") or "").strip("\\")
        name = target.get("value_name")
        matches = [
            row
            for row in registry_rows
            if str(row.get("hive") or "").upper() == hive
            and str(row.get("key_path") or row.get("path") or "").strip("\\").casefold()
            == key.casefold()
            and (name is None or str(row.get("value_name") or row.get("name") or "") == str(name))
        ]
        if name is not None:
            if len(matches) != 1:
                raise LiveControllerError(
                    f"cleanup registry value {action.get('action_id')} is absent or ambiguous"
                )
            result[str(action["action_id"])] = {
                "hive": hive,
                "key_path": key,
                "value_name": str(name),
                "value_data": matches[0].get("value_data", matches[0].get("value")),
            }
        else:
            values = {
                str(row.get("value_name") or row.get("name") or ""): row.get(
                    "value_data", row.get("value")
                )
                for row in matches
                if str(row.get("value_name") or row.get("name") or "")
            }
            if not values:
                raise LiveControllerError(
                    f"cleanup registry tree {action.get('action_id')} has no frozen values"
                )
            result[str(action["action_id"])] = {
                "hive": hive,
                "key_path": key,
                "value_name": None,
                "values": values,
            }
    return result


def _cleanup_lock(
    cleanup_ground_truth: Mapping[str, Any], dry_case: Mapping[str, Any] | None
) -> dict[str, Any]:
    """Build the post-score cleanup lock from cleanup-only Ground Truth.

    This helper is intentionally separate from the safe protected-process
    manifest passed to C2Trace.  It must only be called after C2Trace execution
    and deterministic scoring have completed.
    """

    expected = cleanup_ground_truth.get("expected_target")
    if not isinstance(expected, Mapping):
        raise LiveControllerError("cleanup has no frozen expected target")
    secondary_pid = int(expected.get("secondary_pid") or 0)
    secondary_process = None
    if secondary_pid > 0:
        secondary_process = {
            "pid": secondary_pid,
            "creation_time_utc": expected.get("secondary_creation_time_utc"),
            "path": expected.get("path"),
            "canonical_path": _normalise_path(expected.get("path")),
            "sha256": expected.get("sha256"),
        }
    if isinstance(dry_case, Mapping) and isinstance(dry_case.get("response_target_lock"), Mapping):
        lock = dict(dry_case["response_target_lock"])
    else:
        lock = {
            "schema_version": "c2trace.response_target_lock.v2",
            "case_id": cleanup_ground_truth.get("case_id"),
            "run_id": cleanup_ground_truth.get("run_id"),
            "target_paw": expected.get("paw"),
            "group": expected.get("group"),
            "host": expected.get("host"),
            "contact": expected.get("contact"),
            "process": {
                "pid": expected.get("pid"),
                "creation_time_utc": expected.get("creation_time_utc"),
                "path": expected.get("path"),
                "canonical_path": _normalise_path(expected.get("path")),
                "sha256": expected.get("sha256"),
            },
            "file": {
                "path": expected.get("payload_path"),
                "canonical_path": _normalise_path(expected.get("payload_path")),
                "sha256": expected.get("payload_sha256"),
            },
            "network": dict(expected.get("network_identity") or {}),
            "source": dict(expected.get("source_binding") or {}),
        }
    if secondary_process is not None:
        lock["secondary_process"] = secondary_process
    return lock


def _write_bootstrap_phase_artifacts(
    root: Path, phase: CalderaBootstrapPhaseResult
) -> None:
    values: dict[str, Any] = {
        "caldera_install_receipt.json": phase.install_receipt,
        "caldera_runtime_source.json": phase.runtime_source,
        "caldera_bootstrap_operation.json": phase.bootstrap_operation,
        "caldera_bootstrap_links.json": {"links": list(phase.bootstrap_links)},
        "caldera_bootstrap_report.json": phase.bootstrap_report,
        "caldera_bootstrap_event_logs.json": {"events": list(phase.bootstrap_event_logs)},
    }
    for name, value in values.items():
        write_json_atomic(root / name, value)


def _write_scenario_phase_artifacts(
    root: Path, phase: CalderaScenarioPhaseResult
) -> None:
    values: dict[str, Any] = {
        "caldera_target_identity_raw.json": phase.target_identity,
        "caldera_scenario_operation.json": phase.scenario_operation,
        "caldera_scenario_links.json": {"links": list(phase.scenario_links)},
        "caldera_scenario_report.json": phase.scenario_report,
        "caldera_scenario_event_logs.json": {"events": list(phase.scenario_event_logs)},
    }
    for name, value in values.items():
        write_json_atomic(root / name, value)


def _write_failed_operation_artifacts(
    root: Path, artifacts: Mapping[str, Any]
) -> None:
    """Persist every available read-only snapshot without masking the failure."""

    role = str(artifacts.get("role") or "").strip().casefold()
    if role not in {"bootstrap", "scenario"}:
        raise LiveControllerError("failed Operation artifacts have an invalid role")
    values: list[tuple[str, Any]] = []
    operation = artifacts.get("operation")
    if isinstance(operation, Mapping):
        values.append((f"caldera_{role}_operation.json", dict(operation)))
    links = artifacts.get("links")
    if isinstance(links, (list, tuple)):
        values.append(
            (
                f"caldera_{role}_links.json",
                {
                    "links": [
                        dict(row) if isinstance(row, Mapping) else row for row in links
                    ]
                },
            )
        )
    report = artifacts.get("report")
    if isinstance(report, Mapping):
        values.append((f"caldera_{role}_report.json", dict(report)))
    event_logs = artifacts.get("event_logs")
    if isinstance(event_logs, (list, tuple)):
        values.append(
            (
                f"caldera_{role}_event_logs.json",
                {
                    "events": [
                        dict(row) if isinstance(row, Mapping) else row
                        for row in event_logs
                    ]
                },
            )
        )
    capture_errors = artifacts.get("capture_errors")
    if isinstance(capture_errors, Mapping) and capture_errors:
        values.append(
            (
                f"caldera_{role}_artifact_capture_errors.json",
                {
                    "operation_id": str(artifacts.get("operation_id") or ""),
                    "errors": dict(capture_errors),
                },
            )
        )
    for name, value in values:
        try:
            write_json_atomic(root / name, value)
        except Exception:
            # A failure to persist one artifact must not prevent attempts to
            # persist the others or replace the authoritative CALDERA error.
            continue


def _target_identity_key(identity: Mapping[str, Any]) -> tuple[Any, ...]:
    network = identity.get("network") if isinstance(identity.get("network"), Mapping) else {}
    return (
        agent_paw(identity),
        int(identity.get("pid") or identity.get("process_id") or 0),
        _normalise_path(identity.get("path")),
        str(identity.get("creation_time_utc") or ""),
        str(identity.get("sha256") or "").casefold(),
        str(identity.get("local_address") or network.get("local_address") or ""),
        int(identity.get("local_port") or network.get("local_port") or 0),
        str(identity.get("remote_address") or network.get("remote_address") or ""),
        int(identity.get("remote_port") or network.get("remote_port") or 0),
    )


def _run_split_caldera_transaction(
    *,
    client: Any,
    runtime: RuntimeCase,
    values: RuntimeValues,
    payload_authorization: PayloadWriteAuthorization,
    config: TrialExecutionConfig,
    runner: BenchWindowsAdmin,
    trial_root: Path,
    journal: PersistentJournal,
    bootstrap_phase_runner: Callable[..., CalderaBootstrapPhaseResult],
    target_phase_resolver: Callable[..., CalderaTargetCandidate],
    scenario_phase_runner: Callable[..., CalderaScenarioPhaseResult],
    target_freezer: Callable[..., dict[str, Any]],
    checkpoint_hook: Callable[[str, Mapping[str, Any]], None] | None = None,
) -> tuple[CalderaPhaseResult, dict[str, Any]]:
    """Run Bootstrap, freeze the host target, and only then create Scenario."""

    def event_sink(stage: str, details: Mapping[str, Any]) -> None:
        journal.append(stage, details=details)

    def failure_artifact_sink(artifacts: Mapping[str, Any]) -> None:
        _write_failed_operation_artifacts(trial_root, artifacts)

    bootstrap = guarded_caldera_write(
        payload_authorization,
        case_id=runtime.case_id,
        caldera_server=config.caldera_server,
        writer=bootstrap_phase_runner,
        args=(client, runtime, values),
        kwargs={
            "operation_timeout": config.operation_timeout,
            "poll_seconds": config.poll_seconds,
            "event_sink": event_sink,
            "failure_artifact_sink": failure_artifact_sink,
        },
    )
    _write_bootstrap_phase_artifacts(trial_root, bootstrap)
    journal.append(
        "bundle_installed",
        details={
            "deployment_manifest_sha256": bootstrap.deployment_manifest_sha256,
            "runtime_source_id": bootstrap.runtime_source_id,
        },
    )
    journal.append(
        "bootstrap_complete",
        details={"operation_id": bootstrap.bootstrap_operation.get("id")},
    )

    candidate = target_phase_resolver(
        client,
        runtime,
        values,
        bootstrap,
        timeout_seconds=config.operation_timeout,
        poll_seconds=config.poll_seconds,
    )
    write_json_atomic(
        trial_root / "caldera_target_candidate.json",
        {
            "case_id": candidate.case_id,
            "run_id": candidate.run_id,
            "deployment_manifest_sha256": candidate.deployment_manifest_sha256,
            "runtime_source_id": candidate.runtime_source_id,
            "scenario_paw": candidate.scenario_paw,
            "raw_identity": candidate.raw_identity,
        },
    )
    frozen_before_scenario = target_freezer(
        runner,
        runtime,
        values,
        candidate.raw_identity,
    )
    write_json_atomic(
        trial_root / "target_identity.pre_scenario.json", frozen_before_scenario
    )
    journal.append(
        "target_frozen",
        details={
            "paw": agent_paw(frozen_before_scenario),
            "pid": frozen_before_scenario.get("pid"),
            "sha256": frozen_before_scenario.get("sha256"),
        },
    )
    if checkpoint_hook is not None:
        checkpoint_hook(
            "bootstrap",
            {
                "trial_root": str(trial_root),
                "bootstrap_operation_id": bootstrap.bootstrap_operation.get("id"),
                "bootstrap_operation": str(trial_root / "caldera_bootstrap_operation.json"),
                "bootstrap_links": str(trial_root / "caldera_bootstrap_links.json"),
                "target_pid": frozen_before_scenario.get("pid"),
                "target_path": frozen_before_scenario.get("path"),
                "target_creation_time_utc": frozen_before_scenario.get("creation_time_utc"),
                "target_sha256": frozen_before_scenario.get("sha256"),
                "listener_port": values.webshell_port,
                "target_identity": str(trial_root / "target_identity.pre_scenario.json"),
            },
        )

    scenario = guarded_caldera_write(
        payload_authorization,
        case_id=runtime.case_id,
        caldera_server=config.caldera_server,
        writer=scenario_phase_runner,
        args=(
            client,
            runtime,
            values,
            bootstrap,
            candidate,
            frozen_before_scenario,
        ),
        kwargs={
            "operation_timeout": config.operation_timeout,
            "poll_seconds": config.poll_seconds,
            "event_sink": event_sink,
            "failure_artifact_sink": failure_artifact_sink,
        },
    )
    _write_scenario_phase_artifacts(trial_root, scenario)
    validate_webshell_scenario_semantics(runtime, scenario.scenario_event_logs)
    journal.append(
        "scenario_complete",
        details={"operation_id": scenario.scenario_operation.get("id")},
    )

    frozen_after_scenario = target_freezer(
        runner,
        runtime,
        values,
        scenario.target_identity,
    )
    if _target_identity_key(frozen_before_scenario) != _target_identity_key(
        frozen_after_scenario
    ):
        raise LiveControllerError("frozen target identity drifted during Scenario")
    write_json_atomic(trial_root / "target_identity.json", frozen_after_scenario)

    phase = CalderaPhaseResult(
        install_receipt=bootstrap.install_receipt,
        runtime_source=bootstrap.runtime_source,
        control_agent=bootstrap.control_agent,
        driver_agent=bootstrap.driver_agent,
        target_identity=frozen_after_scenario,
        bootstrap_operation=bootstrap.bootstrap_operation,
        bootstrap_links=bootstrap.bootstrap_links,
        bootstrap_report=bootstrap.bootstrap_report,
        bootstrap_event_logs=bootstrap.bootstrap_event_logs,
        scenario_operation=scenario.scenario_operation,
        scenario_links=scenario.scenario_links,
        scenario_report=scenario.scenario_report,
        scenario_event_logs=scenario.scenario_event_logs,
    )
    journal.append("reports_exported")
    return phase, frozen_after_scenario


def run_live_trial(
    *,
    client: Any,
    runtime: RuntimeCase,
    values: RuntimeValues,
    preflight_receipt: Mapping[str, Any],
    payload_authorization: PayloadWriteAuthorization,
    config: TrialExecutionConfig,
    runner: BenchWindowsAdmin | None = None,
    cleanup_transport: PowerShellCleanupTransport | None = None,
    bootstrap_phase_runner: Callable[..., CalderaBootstrapPhaseResult] = (
        run_caldera_bootstrap_phase
    ),
    target_phase_resolver: Callable[..., CalderaTargetCandidate] = (
        resolve_caldera_target_phase
    ),
    scenario_phase_runner: Callable[..., CalderaScenarioPhaseResult] = (
        run_caldera_scenario_phase
    ),
    target_freezer: Callable[..., dict[str, Any]] = freeze_target_identity,
    c2trace_runner: Callable[..., Any] = run_c2trace,
    checkpoint_hook: Callable[[str, Mapping[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Execute one pre-registered trial and always score before normal cleanup."""

    trial_started_clock = time.perf_counter()
    trial_root = config.result_root.resolve()
    if trial_root.exists():
        existing_result = trial_root / "trial_result.json"
        if existing_result.is_file():
            raise LiveControllerError("refusing to overwrite a completed trial")
    trial_root.mkdir(parents=True, exist_ok=True)
    journal = PersistentJournal(trial_root / "state.jsonl")
    journal.append("preregistered", details={"case_id": runtime.case_id, "run_id": values.run_id})
    runner = runner or BenchWindowsAdmin(execute_response=False)
    cleanup_transport = cleanup_transport or PowerShellCleanupTransport(
        project_root=config.project_root, runner=runner
    )
    control_identity = control_identity_from_preflight(preflight_receipt)
    source_not_before = ""
    phase: CalderaPhaseResult | None = None
    target_identity: dict[str, Any] | None = None
    before: dict[str, Any] | None = None
    protected_manifest: dict[str, Any] | None = None
    dry_case: dict[str, Any] | None = None
    dry_metadata: dict[str, Any] = {}
    execute_metadata: dict[str, Any] = {}
    cleanup_completed = False
    caldera_write_attempted = False
    try:
        journal.append("preflight_complete")
        baseline_collector = PlanDrivenEvidenceCollector(
            runtime=runtime,
            values=values,
            probe=runner,
        )
        baseline = baseline_collector.capture_stage("baseline")
        write_json_atomic(trial_root / "evidence" / "baseline.json", baseline)
        baseline_gate = evaluate_baseline_clean(runtime, baseline)
        write_json_atomic(trial_root / "baseline_gate.json", baseline_gate)
        if baseline_gate.get("clean") is not True:
            raise LiveControllerError(f"case residue exists at baseline: {baseline_gate}")
        journal.append("baseline_captured")

        write_json_atomic(
            trial_root / "payload_write_authorization.json",
            {
                "case_id": payload_authorization.case_id,
                "caldera_server": payload_authorization.caldera_server,
                "required": payload_authorization.required,
                "verified": payload_authorization.verified,
                "deployment_manifest_sha256": payload_authorization.deployment_manifest_sha256,
                "payload_name": payload_authorization.payload_name,
                "payload_sha256": payload_authorization.payload_sha256,
                "receipt_sha256": payload_authorization.receipt_sha256,
            },
        )
        journal.append("bundle_verified")
        source_not_before = utc_now()
        journal.append(
            "caldera_write_intent",
            status="intent",
            details={
                "case_id": runtime.case_id,
                "run_id": values.run_id,
                "payload_gate_verified": payload_authorization.verified,
            },
        )

        caldera_write_attempted = True
        phase, target_identity = _run_split_caldera_transaction(
            client=client,
            runtime=runtime,
            values=values,
            payload_authorization=payload_authorization,
            config=config,
            runner=runner,
            trial_root=trial_root,
            journal=journal,
            bootstrap_phase_runner=bootstrap_phase_runner,
            target_phase_resolver=target_phase_resolver,
            scenario_phase_runner=scenario_phase_runner,
            target_freezer=target_freezer,
            checkpoint_hook=checkpoint_hook,
        )

        collector = PlanDrivenEvidenceCollector(
            runtime=runtime,
            values=values,
            probe=runner,
            target_identity=target_identity,
            suricata_eve=config.eve_path,
            source_not_before_utc=source_not_before,
        )
        before = _capture_with_wait(
            collector,
            "before_response",
            timeout=config.evidence_timeout,
            poll_seconds=config.poll_seconds,
        )
        write_json_atomic(trial_root / "evidence" / "before_response.json", before)
        journal.append("before_response_captured")
        event, artifact = selected_source(before)
        write_json_atomic(trial_root / "suricata_event.json", event)
        write_json_atomic(trial_root / "suricata_artifact.json", artifact)
        journal.append(
            "source_event_frozen",
            details={"flow_id": event.get("flow_id"), "event_sha256": artifact.get("event_sha256")},
        )
        if checkpoint_hook is not None:
            target_base = (
                values.target_path[:-4]
                if values.target_path.casefold().endswith(".exe")
                else values.target_path
            )
            checkpoint_hook(
                "scenario_detection",
                {
                    "trial_root": str(trial_root),
                    "scenario_operation_id": phase.scenario_operation.get("id"),
                    "scenario_operation": str(trial_root / "caldera_scenario_operation.json"),
                    "scenario_links": str(trial_root / "caldera_scenario_links.json"),
                    "flow_id": event.get("flow_id"),
                    "event_sha256": artifact.get("event_sha256"),
                    "suricata_event": str(trial_root / "suricata_event.json"),
                    "suricata_artifact": str(trial_root / "suricata_artifact.json"),
                    "groups_output": f"{target_base}.groups.txt",
                    "tasklist_output": f"{target_base}.tasks.txt",
                    "target_pid": target_identity.get("pid"),
                    "target_path": values.target_path,
                    "target_creation_time_utc": target_identity.get("creation_time_utc"),
                    "target_sha256": target_identity.get("sha256"),
                    "listener_port": values.webshell_port,
                },
            )

        protected_manifest = build_protected_processes_v2(
            runtime,
            values,
            control_identity=control_identity,
            target_identity=target_identity,
            before_response_evidence=before,
            source_event=event,
            source_artifact=artifact,
            source_not_before_utc=source_not_before,
        )
        safe_manifest = build_protected_manifest_safe(protected_manifest)
        protected_safe_path = write_json_atomic(
            trial_root / "protected_processes.safe.json", safe_manifest
        )
        from c2trace.tools import RESPONSE_TOOLS as _ALL_RESPONSE_TOOLS
        response_tools = sorted(_ALL_RESPONSE_TOOLS)

        dry_dir = trial_root / "c2trace_dryrun"
        dry_process = c2trace_runner(
            project_root=config.project_root,
            python=config.python,
            case_id=runtime.case_id,
            victim_ip=values.victim_ip,
            eve_path=config.eve_path,
            event=event,
            artifact=artifact,
            output_dir=dry_dir,
            log_path=trial_root / "c2trace_dryrun_stdout_stderr.txt",
            protected_manifest=protected_safe_path,
            response_tools=response_tools,
            reviewed_casefile=None,
            execute=False,
        )
        if config.baseline_mode:
            dry_path = dry_dir / "run_record.json"
            if dry_path.is_file():
                dry_case = read_json(dry_path)
            else:
                dry_case = {
                    "schema_version": "c2trace.public_react_run.v1",
                    "case_id": runtime.case_id,
                    "alert": {},
                    "tool_calls": [],
                    "model_output": {"observations": [], "actions": []},
                    "executed_actions": [],
                    "errors": [{"type": "missing_run_record", "message": "baseline dry-run produced no run_record.json"}],
                    "operational_metrics": {},
                }
                dry_path = write_json_atomic(dry_dir / "baseline_failure_record.json", dry_case)
        else:
            dry_path = dry_dir / "casefile.json"
            if dry_path.is_file():
                dry_case = read_json(dry_path)
            else:
                dry_case = synthetic_failure_casefile(
                    case_id=runtime.case_id,
                    stage="dry_run",
                    exit_code=int(getattr(dry_process, "returncode", -1)),
                    reason="C2Trace dry-run produced no CaseFile",
                )
                dry_path = write_json_atomic(dry_dir / "benchmark_failure_casefile.json", dry_case)
        dry_metadata_path = dry_dir / "run_metadata.json"
        if dry_metadata_path.is_file():
            dry_metadata = read_json(dry_metadata_path)
        journal.append("dryrun_complete", details={"exit_code": getattr(dry_process, "returncode", -1)})

        after_dry = collector.capture_stage("after_dryrun")
        write_json_atomic(trial_root / "evidence" / "after_dryrun.json", after_dry)
        unchanged = snapshot_unchanged(before, after_dry)
        write_json_atomic(trial_root / "after_dryrun_gate.json", unchanged)
        if unchanged.get("unchanged") is not True:
            raise LiveControllerError("C2Trace dry-run changed frozen host state")
        if config.baseline_mode:
            baseline_errors: list[str] = []
            if str(dry_case.get("case_id") or "") != runtime.case_id:
                baseline_errors.append("baseline dry-run record case_id differs from the frozen case")
            if str(dry_case.get("schema_version") or "") != "c2trace.public_react_run.v1":
                baseline_errors.append("baseline dry-run record schema is missing or invalid")
            if dry_case.get("errors"):
                baseline_errors.append("baseline dry-run reported runtime errors")
            gate = {
                "schema_version": "c2trace.bench.baseline_gate.v1",
                "mode": "independent_response_contract",
                "passed": not baseline_errors,
                "errors": baseline_errors,
                "target_binding_required": False,
                "private_answer_inputs_used": False,
            }
        else:
            gate = dry_run_gate(
                dry_case,
                expected_case_id=runtime.case_id,
                expected_run_id=values.run_id,
                expected_target=None,  # Round3: do not validate target correctness in system path
                protected_processes=safe_manifest["processes"],
            )
        if int(getattr(dry_process, "returncode", -1)) != 0:
            gate["passed"] = False
            gate["errors"].append(
                f"C2Trace dry-run exited with code {getattr(dry_process, 'returncode', -1)}"
            )
        write_json_atomic(trial_root / "dry_run_gate.json", gate)
        journal.append(
            "target_gate_passed",
            status="completed" if gate["passed"] else "failed",
            details={"errors": gate["errors"]},
        )
        if checkpoint_hook is not None and gate["passed"]:
            checkpoint_hook(
                "dry_run",
                {
                    "trial_root": str(trial_root),
                    "run_record": str(dry_path),
                    "run_metadata": str(dry_dir / "run_metadata.json"),
                    "dry_run_gate": str(trial_root / "dry_run_gate.json"),
                    "after_dryrun_gate": str(trial_root / "after_dryrun_gate.json"),
                    "host_unchanged": unchanged.get("unchanged") is True,
                    "suricata_event": str(trial_root / "suricata_event.json"),
                    "target_pid": target_identity.get("pid"),
                    "target_path": values.target_path,
                    "target_sha256": target_identity.get("sha256"),
                    "listener_port": values.webshell_port,
                    "target_binding_used": False if config.baseline_mode else isinstance(dry_case.get("response_target_lock"), Mapping),
                },
            )

        execute_case: dict[str, Any] | None = None
        execute_process: Any | None = None
        if gate["passed"]:
            execute_dir = trial_root / "c2trace_execute"
            execute_process = c2trace_runner(
                project_root=config.project_root,
                python=config.python,
                case_id=runtime.case_id,
                victim_ip=values.victim_ip,
                eve_path=config.eve_path,
                event=event,
                artifact=artifact,
                output_dir=execute_dir,
                log_path=trial_root / "c2trace_execute_stdout_stderr.txt",
                protected_manifest=protected_safe_path,
                response_tools=response_tools,
                reviewed_casefile=dry_path,
                execute=True,
            )
            if config.baseline_mode:
                execute_path = execute_dir / "run_record.json"
                if execute_path.is_file():
                    execute_case = read_json(execute_path)
                else:
                    execute_case = {
                        "schema_version": "c2trace.public_react_run.v1",
                        "case_id": runtime.case_id,
                        "alert": dry_case.get("alert", {}),
                        "tool_calls": [],
                        "model_output": {"observations": [], "actions": []},
                        "executed_actions": [],
                        "errors": [{"type": "missing_run_record", "message": "baseline execute produced no run_record.json"}],
                        "operational_metrics": {},
                    }
                    write_json_atomic(execute_dir / "baseline_failure_record.json", execute_case)
            else:
                execute_path = execute_dir / "casefile.json"
                if execute_path.is_file():
                    execute_case = read_json(execute_path)
                else:
                    execute_case = synthetic_failure_casefile(
                        case_id=runtime.case_id,
                        stage="execute",
                        exit_code=int(getattr(execute_process, "returncode", -1)),
                        reason="C2Trace execute produced no CaseFile",
                        investigation_source=dry_case,
                    )
                    write_json_atomic(
                        execute_dir / "benchmark_failure_casefile.json", execute_case
                    )
            execute_metadata_path = execute_dir / "run_metadata.json"
            if execute_metadata_path.is_file():
                execute_metadata = read_json(execute_metadata_path)
        journal.append(
            "execute_complete",
            status="completed" if execute_case is not None else "not_executed",
            details={"exit_code": getattr(execute_process, "returncode", None)},
        )

        after_execute = collector.capture_stage("after_execute")
        write_json_atomic(trial_root / "evidence" / "after_execute.json", after_execute)
        observed_control = refresh_control_identity(client, runner, control_identity)
        expected_driver = _agent_identity(phase.driver_agent)
        observed_driver = refresh_driver_identity(client, phase.driver_agent)
        post = evaluate_post_response(
            runtime,
            after_execute,
            protected_manifest=safe_manifest,
            observed_control=observed_control,
            expected_driver=expected_driver,
            observed_driver=observed_driver,
        )
        write_json_atomic(trial_root / "post_response_validation.json", post)
        journal.append("after_execute_captured", details={"passed": post.get("passed")})
        if checkpoint_hook is not None and gate["passed"]:
            response_actions = []
            execute_rows = (
                (execute_case or {}).get("tool_calls", [])
                if config.baseline_mode
                else (execute_case or {}).get("action_results", [])
            )
            for row in execute_rows:
                if not isinstance(row, Mapping) or str(row.get("tool") or "") not in {
                    "kill_process",
                    "remove_file",
                }:
                    continue
                authorization = response_authorization_receipt(row)
                response_actions.append(
                    {
                        "tool": str(row.get("tool") or ""),
                        "success": row.get("success") is True,
                        "authorization_receipt_present": bool(authorization),
                        "authorization_valid": authorization.get("valid") is True,
                        "nonce_consumed": authorization.get("nonce_consumed") is True,
                    }
                )
            checkpoint_hook(
                "execute_verify",
                {
                    "trial_root": str(trial_root),
                    "execute_record": str(trial_root / "c2trace_execute" / ("run_record.json" if config.baseline_mode else "casefile.json")),
                    "execute_run_metadata": str(trial_root / "c2trace_execute" / "run_metadata.json"),
                    "post_response_validation": str(trial_root / "post_response_validation.json"),
                    "passed": post.get("passed") is True,
                    "target_pid": target_identity.get("pid"),
                    "target_path": values.target_path,
                    "target_sha256": target_identity.get("sha256"),
                    "listener_port": values.webshell_port,
                    "response_actions": response_actions,
                    "authorization_receipts": "not applicable to the independent baseline" if config.baseline_mode else "embedded in execute CaseFile action_results",
                    "target_process_absent": post.get("target_process_absent"),
                    "target_network_absent": post.get("target_network_absent"),
                    "target_file_absent": post.get("target_file_absent"),
                    "control_agent_alive": post.get("control_sandcat_alive"),
                    "driver_agent_alive": post.get("driver_agent_alive"),
                },
            )

        if config.baseline_mode:
            _, scoring_case = project_for_scoring(dry_case, response_record=execute_case)
        else:
            scoring_case = build_scoring_casefile(dry_case, execute_case)
        runtime_metrics = build_operational_metrics(
            dry_metadata=dry_metadata,
            execute_metadata=execute_metadata,
            end_to_end_duration_ms=(time.perf_counter() - trial_started_clock) * 1000,
        )
        operational_metrics = {
            **runtime_metrics,
            "wrong_target": post["wrong_target"],
            "target_network_absent": post["target_network_absent"],
            "target_process_absent": post["target_process_absent"],
            "target_file_absent": post["target_file_absent"],
            "target_persistence_absent": post["target_persistence_absent"],
            "control_agent_alive": post["control_sandcat_alive"],
            "driver_agent_alive": post["driver_agent_alive"],
        }
        scoring_case["operational_metrics"] = operational_metrics
        scoring_case["operational_metrics_provenance"] = {
            "schema_version": "c2trace.bench.operational_metrics_provenance.v4",
            "measurement_window": "trial_entry_through_post_response_capture",
            "dry_run_metadata": {
                "path": str(dry_dir / "run_metadata.json"),
                "available": bool(dry_metadata),
            },
            "execute_metadata": {
                "path": str(trial_root / "c2trace_execute" / "run_metadata.json"),
                "available": bool(execute_metadata),
            },
            "missing_measurements_are_null": True,
        }
        write_json_atomic(
            trial_root / "operational_metrics.json",
            {
                "schema_version": "c2trace.bench.operational_metrics.v4",
                "case_id": runtime.case_id,
                "run_id": values.run_id,
                "captured_at": utc_now(),
                "metrics": operational_metrics,
                "provenance": scoring_case["operational_metrics_provenance"],
            },
        )
        baseline_record_ok = (
            isinstance(execute_case, Mapping)
            and str(execute_case.get("schema_version") or "") == "c2trace.public_react_run.v1"
            and not execute_case.get("errors")
        )
        response_ok = bool(
            execute_case
            and int(getattr(execute_process, "returncode", -1)) == 0
            and (baseline_record_ok if config.baseline_mode else str(execute_case.get("final_status") or "") == "completed")
            and post.get("passed") is True
        )
        trial_class = "evaluation_valid_pass" if response_ok else "evaluation_valid_fail"
        scoring_case["trial_class"] = trial_class
        scoring_path = write_json_atomic(
            trial_root / ("scoring_projection.json" if config.baseline_mode else "scoring_casefile.json"),
            scoring_case,
        )
        if config.baseline_mode:
            evaluation_record, _ = project_for_scoring(
                dry_case,
                response_record=execute_case,
                operational_metrics=operational_metrics,
            )
            evaluation_record.write_json(trial_root / "evaluation_record.json")

        # Keep evaluation truth out of the C2Trace execution window.  The
        # controller materializes it only after both dry-run and execute have
        # returned, immediately before deterministic scoring.
        ground_truth = materialize_ground_truth(
            runtime,
            values,
            bootstrap_operation=phase.bootstrap_operation,
            bootstrap_links=phase.bootstrap_links,
            scenario_operation=phase.scenario_operation,
            scenario_links=phase.scenario_links,
            target_identity=target_identity,
            before_response_evidence=before,
            source_event=event,
            source_artifact=artifact,
        )
        ground_truth_path = write_json_atomic(trial_root / "ground_truth.json", ground_truth)
        score = score_case(ground_truth, scoring_case)
        score["trial_class"] = trial_class
        write_score_outputs(score, trial_root / "score.json", trial_root / "score.md")
        journal.append("scored", details={"trial_class": trial_class})

        # Preserve the complete, target-bearing manifest only after C2Trace
        # execution and scoring have finished.  It is a forensic/controller
        # artifact, never a C2Trace input.
        write_json_atomic(
            trial_root / "protected_processes.v2.json", protected_manifest
        )

        # The cleanup-only truth file is created after C2Trace and scoring.
        # It is never passed to run_case.py or any C2Trace agent.
        cleanup_gt = build_cleanup_ground_truth(protected_manifest)
        cleanup_gt_path = write_json_atomic(
            trial_root / "cleanup_ground_truth.json", cleanup_gt
        )
        # A baseline's target proposal must not determine controller cleanup:
        # otherwise a wrong proposal becomes an infrastructure failure and the
        # baseline's response miss is excluded from scoring.  The controller
        # uses cleanup-only truth after scoring to restore the host for the
        # next trial; that truth never enters the baseline agent.
        cleanup_lock = _cleanup_lock(
            cleanup_gt,
            None if config.baseline_mode else dry_case,
        )
        prepared = prepare_cleanup(
            runtime,
            values,
            target_lock=cleanup_lock,
            protected_processes=safe_manifest["processes"],
            score_artifact=trial_root / "score.json",
            frozen_artifacts=_frozen_artifacts(before),
        )
        expected_hashes = {
            _normalise_path(cleanup_gt["expected_target"]["path"]): str(
                cleanup_gt["expected_target"]["sha256"]
            ).lower()
        }
        registry_expectations = _registry_expectations(prepared.actions, before)
        roots = [r"C:\Users\Public"]
        if values.appdata:
            roots.append(values.appdata)
        backend = PowerShellCleanupBackend(
            transport=cleanup_transport,
            actions=prepared.actions,
            run_id=values.run_id,
            allowed_roots=roots,
            expected_file_hashes=expected_hashes,
            registry_expectations=registry_expectations,
        )
        cleanup_receipt = execute_cleanup(prepared, backend)
        write_json_atomic(trial_root / "external_cleanup.json", cleanup_receipt)
        cleanup_completed = True
        journal.append("cleanup_complete")
        result = {
            "schema_version": "c2trace.bench.trial_result.v4",
            "case_id": runtime.case_id,
            "run_id": values.run_id,
            "trial_class": trial_class,
            "infrastructure_valid": True,
            "score_path": str(trial_root / "score.json"),
            "ground_truth_path": str(ground_truth_path),
            "protected_safe_path": str(protected_safe_path),
            "cleanup_ground_truth_path": str(cleanup_gt_path),
            "scoring_casefile_path": str(scoring_path),
            "cleanup_completed": True,
            "execution_contract": "baseline" if config.baseline_mode else "c2trace",
            "completed_at": utc_now(),
        }
        write_json_atomic(trial_root / "trial_result.json", result)
        journal.append("complete", details={"trial_class": trial_class})
        return result
    except Exception as exc:
        journal.append(
            "trial_failed",
            status="infrastructure_invalid",
            details={"error_type": type(exc).__name__, "error": str(exc)},
        )
        invalid = {
            "schema_version": "c2trace.bench.trial_result.v4",
            "case_id": runtime.case_id,
            "run_id": values.run_id,
            "trial_class": "infrastructure_invalid",
            "infrastructure_valid": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "cleanup_completed": cleanup_completed,
            "manual_reconciliation_required": caldera_write_attempted
            and not cleanup_completed,
            "failed_at": utc_now(),
        }
        write_json_atomic(trial_root / "infrastructure_invalid.json", invalid)
        # A post-side-effect failure is intentionally not auto-replayed and is
        # not silently cleaned with an incomplete selector set.  Resume will
        # detect the write intent and require manual reconciliation.
        raise LiveControllerError(str(exc)) from exc


__all__ = [
    "LiveControllerError",
    "TrialExecutionConfig",
    "control_identity_from_preflight",
    "freeze_target_identity",
    "refresh_control_identity",
    "run_live_trial",
]

