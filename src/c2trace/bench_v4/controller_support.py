from __future__ import annotations

"""Side-effect boundary helpers for the Bench v4 controller.

The controller keeps these operations explicit so tests can replace them and
so a Resume never has to infer whether an external mutation occurred.  This
module does not contact CALDERA or start a process at import time.
"""

from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import subprocess
from typing import Any, Iterable, Mapping, Sequence

from c2trace.time_identity import compare_creation_times


class ControllerSupportError(RuntimeError):
    """A controller-side invariant failed and the trial must stop."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: str | Path) -> dict[str, Any]:
    target = Path(path)
    try:
        value = json.loads(target.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ControllerSupportError(f"unable to read JSON {target}: {exc}") from exc
    if not isinstance(value, dict):
        raise ControllerSupportError(f"JSON root must be an object: {target}")
    return value


def write_json_atomic(path: str | Path, value: Mapping[str, Any]) -> Path:
    target = Path(path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    data = (json.dumps(dict(value), ensure_ascii=False, indent=2) + "\n").encode(
        "utf-8"
    )
    try:
        with temporary.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return target


class PersistentJournal:
    """Append-only JSONL journal flushed before returning to its caller."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        stage: str,
        *,
        status: str = "completed",
        details: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        record = {
            "schema_version": "c2trace.bench.state_event.v4",
            "timestamp": utc_now(),
            "stage": str(stage),
            "status": str(status),
            "details": dict(details or {}),
        }
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return record

    def events(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        rows: list[dict[str, Any]] = []
        for number, raw in enumerate(
            self.path.read_text(encoding="utf-8-sig").splitlines(), 1
        ):
            if not raw.strip():
                continue
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ControllerSupportError(
                    f"journal contains invalid JSON at line {number}: {self.path}"
                ) from exc
            if not isinstance(value, dict):
                raise ControllerSupportError(
                    f"journal line {number} is not an object: {self.path}"
                )
            rows.append(value)
        return rows


def run_logged(
    command: Sequence[str | Path],
    *,
    log_path: str | Path,
    cwd: str | Path,
    check: bool = True,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    argv = [str(item) for item in command]
    completed = subprocess.run(
        argv,
        cwd=str(Path(cwd).resolve()),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=timeout,
    )
    target = Path(log_path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    # list2cmdline is diagnostic only. The process was started with argv and
    # never through a shell.
    target.write_text(
        "COMMAND\n"
        + subprocess.list2cmdline(argv)
        + "\n\nSTDOUT\n"
        + (completed.stdout or "")
        + "\n\nSTDERR\n"
        + (completed.stderr or "")
        + f"\n\nEXIT_CODE\n{completed.returncode}\n",
        encoding="utf-8",
    )
    if check and completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "")[-1800:]
        raise ControllerSupportError(
            f"command failed with exit {completed.returncode}: {argv[0]}\n{detail}"
        )
    return completed


def tcp_reachable(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def start_suricata(
    *,
    project_root: Path,
    bench_root: Path,
    interface: str,
    kali_ip: str,
    log_dir: Path,
    log_path: Path,
    suricata_exe: str,
    suricata_config: str,
    required_sids: Sequence[int] = (9204001, 9204002, 9204005),
    rule_label: str = "v4",
) -> Path:
    canonical = bench_root / "suricata" / "c2trace_bench_v4.rules"
    try:
        rules = canonical.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise ControllerSupportError(
            f"unable to read {rule_label} Suricata rules: {exc}"
        ) from exc
    normalized_sids = tuple(int(sid) for sid in required_sids)
    if not normalized_sids or any(sid <= 0 for sid in normalized_sids):
        raise ControllerSupportError("required Suricata SIDs must be positive integers")
    for sid in normalized_sids:
        if f"sid:{sid};" not in rules:
            raise ControllerSupportError(
                f"{rule_label} Suricata rule SID {sid} is missing"
            )
    if kali_ip not in rules:
        raise ControllerSupportError(
            f"the frozen {rule_label} Suricata rules do not match the configured Kali IP"
        )
    runtime_rule = log_dir / "c2trace_bench_v4.runtime.rules"
    runtime_rule.parent.mkdir(parents=True, exist_ok=True)
    runtime_rule.write_text(rules, encoding="utf-8")
    run_logged(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            project_root / "scripts" / "start_suricata_s002.ps1",
            "-SuricataExe",
            suricata_exe,
            "-ConfigPath",
            suricata_config,
            "-Interface",
            interface,
            "-RulePath",
            runtime_rule,
            "-LogDir",
            log_dir,
        ],
        log_path=log_path,
        cwd=project_root,
    )
    return log_dir / "eve.json"


def stop_suricata(
    *,
    project_root: Path,
    log_dir: Path,
    log_path: Path,
    suricata_exe: str,
) -> subprocess.CompletedProcess[str]:
    return run_logged(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            project_root / "scripts" / "stop_suricata_s002.ps1",
            "-LogDir",
            log_dir,
            "-SuricataExe",
            suricata_exe,
        ],
        log_path=log_path,
        cwd=project_root,
        check=False,
    )


def selected_source(capture: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    captures = capture.get("captures")
    if not isinstance(captures, list):
        raise ControllerSupportError("evidence capture has no captures array")
    rows = [
        row
        for row in captures
        if isinstance(row, Mapping) and row.get("collector") == "suricata"
    ]
    if len(rows) != 1:
        raise ControllerSupportError(
            f"expected one frozen Suricata capture, found {len(rows)}"
        )
    result = rows[0].get("result")
    if not isinstance(result, Mapping):
        raise ControllerSupportError("frozen Suricata result is malformed")
    event = result.get("source_event") or result.get("selected_event")
    artifact = result.get("source_artifact") or result.get("selected_artifact")
    if not isinstance(event, Mapping) or not isinstance(artifact, Mapping):
        raise ControllerSupportError(
            "frozen Suricata result lacks an exact event/artifact pair"
        )
    if not event.get("flow_id") or not artifact.get("event_sha256"):
        raise ControllerSupportError("frozen Suricata identity lacks flow/hash")
    if not (artifact.get("line_number") or artifact.get("record_index")):
        raise ControllerSupportError(
            "frozen Suricata identity lacks a physical source location"
        )
    return dict(event), dict(artifact)


def run_c2trace(
    *,
    project_root: Path,
    python: Path,
    case_id: str,
    victim_ip: str,
    eve_path: Path,
    event: Mapping[str, Any],
    artifact: Mapping[str, Any],
    output_dir: Path,
    log_path: Path,
    protected_manifest: Path,
    response_tools: Sequence[str],
    reviewed_casefile: Path | None = None,
    execute: bool = False,
) -> subprocess.CompletedProcess[str]:
    alert = event.get("alert") if isinstance(event.get("alert"), Mapping) else {}
    sid = str(alert.get("signature_id") or event.get("signature_id") or "")
    if not sid:
        raise ControllerSupportError("source event has no Suricata signature ID")
    command: list[str | Path] = [
        python,
        project_root / "run_case.py",
        "--suricata-eve",
        eve_path,
        "--case-id",
        case_id,
        "--victim-ip",
        victim_ip,
        "--signature-id",
        sid,
        "--flow-id",
        str(event.get("flow_id") or ""),
        "--event-sha256",
        str(artifact.get("event_sha256") or ""),
        "--output",
        output_dir,
        "--protected-processes",
        protected_manifest,
        "--response-tools",
        *sorted(set(str(item) for item in response_tools)),
    ]
    if str(os.environ.get("C2TRACE_REQUIRE_AUDITOR_LLM") or "").strip().lower() in {
        "1",
        "true",
        "yes",
    }:
        command.append("--require-auditor-llm")
    if artifact.get("line_number"):
        command.extend(["--eve-line", str(artifact["line_number"])])
    elif artifact.get("record_index"):
        command.extend(["--eve-record-index", str(artifact["record_index"])])
    else:  # defensive duplicate of selected_source's gate
        raise ControllerSupportError("source artifact has no physical selector")
    if reviewed_casefile is not None:
        command.extend(
            [
                "--reviewed-target-from",
                reviewed_casefile,
                "--strategy-tree-from",
                reviewed_casefile,
            ]
        )
    if execute:
        if reviewed_casefile is None:
            raise ControllerSupportError(
                "guarded execute requires a reviewed dry-run CaseFile"
            )
        command.append("--execute-response")
    return run_logged(
        command,
        log_path=log_path,
        cwd=project_root,
        check=False,
    )


def build_operational_metrics(
    *,
    dry_metadata: Mapping[str, Any],
    execute_metadata: Mapping[str, Any] | None,
    end_to_end_duration_ms: float,
) -> dict[str, Any]:
    """Build aggregation-ready metrics from C2Trace's persisted metadata.

    Missing measurements remain ``None``.  Values are never inferred from a
    CaseFile action count because that would under-count investigation and LLM
    work.  A present but malformed measurement fails closed instead of being
    silently coerced.
    """

    metadata_rows = [dry_metadata] if dry_metadata else []
    if isinstance(execute_metadata, Mapping) and execute_metadata:
        metadata_rows.append(execute_metadata)
    llm_rows = [
        row.get("llm_usage") if isinstance(row.get("llm_usage"), Mapping) else {}
        for row in metadata_rows
    ]
    tool_rows = [
        row.get("tool_usage") if isinstance(row.get("tool_usage"), Mapping) else {}
        for row in metadata_rows
    ]

    def number(value: Any, label: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ControllerSupportError(f"{label} must be a non-negative number")
        result = float(value)
        if not math.isfinite(result) or result < 0:
            raise ControllerSupportError(f"{label} must be a non-negative number")
        return result

    def numeric_sum(rows: Iterable[Mapping[str, Any]], key: str) -> float | None:
        values = [
            number(row[key], f"run_metadata.{key}")
            for row in rows
            if key in row
        ]
        return round(sum(values), 3) if values else None

    phase_totals: dict[str, float | None] = {}
    for phase in ("investigate", "response", "verify"):
        values = [
            number(
                row["phase_elapsed_ms"][phase],
                f"run_metadata.tool_usage.phase_elapsed_ms.{phase}",
            )
            for row in tool_rows
            if isinstance(row.get("phase_elapsed_ms"), Mapping)
            and phase in row["phase_elapsed_ms"]
        ]
        phase_totals[phase] = round(sum(values), 3) if values else None

    def integer_sum(rows: Iterable[Mapping[str, Any]], key: str) -> int | None:
        value = numeric_sum(rows, key)
        if value is None:
            return None
        if not float(value).is_integer():
            raise ControllerSupportError(f"run_metadata.{key} must be an integer")
        return int(value)

    return {
        "end_to_end_duration_ms": round(
            number(end_to_end_duration_ms, "end_to_end_duration_ms"), 3
        ),
        "investigation_duration_ms": phase_totals["investigate"],
        "response_duration_ms": phase_totals["response"],
        "verification_duration_ms": phase_totals["verify"],
        "case_duration_ms": numeric_sum(metadata_rows, "duration_ms"),
        "llm_calls": integer_sum(llm_rows, "call_count"),
        "tool_calls": integer_sum(tool_rows, "call_count"),
        "prompt_tokens": integer_sum(llm_rows, "prompt_tokens"),
        "completion_tokens": integer_sum(llm_rows, "completion_tokens"),
        "total_tokens": integer_sum(llm_rows, "total_tokens"),
    }


def synthetic_failure_casefile(
    *,
    case_id: str,
    stage: str,
    exit_code: int,
    reason: str,
    investigation_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    source = investigation_source if isinstance(investigation_source, Mapping) else {}
    now = utc_now()
    return {
        "case_id": case_id,
        "case_name": f"Bench v4 synthetic {stage} failure record",
        "source_alert": dict(source.get("source_alert") or {})
        if isinstance(source.get("source_alert"), Mapping)
        else {},
        "source_events": list(source.get("source_events") or [])
        if isinstance(source.get("source_events"), list)
        else [],
        "source_artifacts": list(source.get("source_artifacts") or [])
        if isinstance(source.get("source_artifacts"), list)
        else [],
        "response_target_lock": source.get("response_target_lock"),
        "strategy_tree": source.get("strategy_tree"),
        "findings": list(source.get("findings") or [])
        if isinstance(source.get("findings"), list)
        else [],
        "action_results": [],
        "audit_decisions": list(source.get("audit_decisions") or [])
        if isinstance(source.get("audit_decisions"), list)
        else [],
        "evidence_links": list(source.get("evidence_links") or [])
        if isinstance(source.get("evidence_links"), list)
        else [],
        "timeline": [],
        "final_report": None,
        "final_status": "c2trace_system_failure",
        "errors": [
            {
                "error_type": "c2trace_system_failure",
                "message": reason,
                "details": {"stage": stage, "exit_code": int(exit_code)},
                "created_at": now,
            }
        ],
        "created_at": now,
        "updated_at": now,
        "synthetic_benchmark_failure_record": True,
    }


def build_scoring_casefile(
    dry_case: Mapping[str, Any], execute_case: Mapping[str, Any] | None
) -> dict[str, Any]:
    """Freeze investigation at dry-run and response results at execute time."""

    result = dict(execute_case) if isinstance(execute_case, Mapping) else dict(dry_case)
    for field, default in (
        ("source_alert", {}),
        ("source_events", []),
        ("source_artifacts", []),
        ("response_target_lock", None),
        ("strategy_tree", None),
        ("findings", []),
        ("evidence_links", []),
    ):
        value = dry_case.get(field, default)
        # Round-trip JSON gives a small, deterministic deep copy without
        # preserving arbitrary Python objects in a CaseFile.
        result[field] = json.loads(json.dumps(value, ensure_ascii=False, default=str))
    if isinstance(execute_case, Mapping):
        raw_actions = execute_case.get("action_results")
        result["action_results"] = (
            json.loads(json.dumps(raw_actions, ensure_ascii=False, default=str))
            if isinstance(raw_actions, list)
            else []
        )
        result["benchmark_scoring_sources"] = {
            "investigation": "dry_run",
            "response": "execute",
        }
    else:
        result["action_results"] = []
        result["benchmark_scoring_sources"] = {
            "investigation": "dry_run",
            "response": "not_executed",
        }
    return result


def dry_run_gate(
    casefile: Mapping[str, Any],
    *,
    expected_case_id: str,
    expected_run_id: str,
    expected_target: Mapping[str, Any] | None = None,
    protected_processes: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    errors: list[str] = []
    creation_time_comparison: dict[str, Any] | None = None
    if str(casefile.get("final_status") or "") != "completed_dry_run":
        errors.append(
            f"dry-run final_status={casefile.get('final_status') or '<missing>'}"
        )
    if str(casefile.get("case_id") or "") != expected_case_id:
        errors.append("dry-run CaseFile case_id differs from the frozen case")
    if not isinstance(casefile.get("strategy_tree"), Mapping):
        errors.append("dry-run produced no replayable StrategyTree")
    errors.extend(_recent_file_baseline_errors(casefile))
    lock = casefile.get("response_target_lock")
    if not isinstance(lock, Mapping):
        errors.append("dry-run produced no response target lock")
    else:
        if lock.get("schema_version") != "c2trace.response_target_lock.v2":
            errors.append("dry-run target lock is not v2")
        if str(lock.get("case_id") or "") != expected_case_id:
            errors.append("dry-run target lock case_id drifted")
        if str(lock.get("run_id") or "") != expected_run_id:
            errors.append("dry-run target lock run_id drifted")
        if isinstance(expected_target, Mapping):
            process = lock.get("process") if isinstance(lock.get("process"), Mapping) else {}
            file_info = lock.get("file") if isinstance(lock.get("file"), Mapping) else {}
            network = lock.get("network") if isinstance(lock.get("network"), Mapping) else {}
            source = lock.get("source") if isinstance(lock.get("source"), Mapping) else {}
            identity_checks = {
                "target_paw": (lock.get("target_paw"), expected_target.get("paw")),
                "group": (lock.get("group"), expected_target.get("group")),
                "host": (lock.get("host"), expected_target.get("host")),
                "contact": (lock.get("contact"), expected_target.get("contact")),
                "pid": (process.get("pid"), expected_target.get("pid")),
                "process_path": (
                    process.get("path"),
                    expected_target.get("executable_path") or expected_target.get("path"),
                ),
                "process_sha256": (
                    process.get("sha256"),
                    expected_target.get("executable_sha256") or expected_target.get("sha256"),
                ),
                "file_path": (file_info.get("path"), expected_target.get("payload_path")),
                "file_sha256": (
                    file_info.get("sha256"),
                    expected_target.get("payload_sha256"),
                ),
                "network_mode": (lock.get("network_mode"), expected_target.get("network_mode")),
            }
            expected_network = (
                expected_target.get("network_identity")
                if isinstance(expected_target.get("network_identity"), Mapping)
                else {}
            )
            identity_checks.update(
                {
                    "network.protocol": (network.get("protocol"), expected_network.get("protocol")),
                    "network.local_address": (
                        network.get("local_address"),
                        expected_network.get("local_ip"),
                    ),
                    "network.local_port": (network.get("local_port"), expected_network.get("local_port")),
                    "network.remote_address": (
                        network.get("remote_address"),
                        expected_network.get("remote_ip"),
                    ),
                    "network.remote_port": (
                        network.get("remote_port"),
                        expected_network.get("remote_port"),
                    ),
                }
            )
            binding = (
                expected_target.get("source_binding")
                if isinstance(expected_target.get("source_binding"), Mapping)
                else {}
            )
            identity_checks.update(
                {
                    "source.flow_id": (source.get("flow_id"), binding.get("flow_id")),
                    "source.event_sha256": (
                        source.get("event_sha256"),
                        binding.get("event_sha256"),
                    ),
                }
            )
            for label, (observed, expected) in identity_checks.items():
                if str(observed or "").casefold() != str(expected or "").casefold():
                    errors.append(f"dry-run target lock {label} drifted")
            creation_time = compare_creation_times(
                process.get("creation_time_utc"),
                expected_target.get("creation_time_utc"),
            )
            creation_time_comparison = creation_time.to_dict()
            if not creation_time.matches:
                errors.append("dry-run target lock creation_time_utc drifted")
            for protected in protected_processes:
                if not isinstance(protected, Mapping):
                    continue
                same_pid = int(process.get("pid") or 0) == int(protected.get("pid") or 0)
                same_path = str(process.get("path") or "").casefold() == str(
                    protected.get("path") or protected.get("canonical_path") or ""
                ).casefold()
                if same_pid or same_path:
                    errors.append("dry-run target lock collides with a protected process")
                    break
    return {
        "schema_version": "c2trace.bench.dry_gate.v4",
        "passed": not errors,
        "errors": errors,
        "creation_time_comparison": creation_time_comparison,
    }


def _recent_file_baseline_errors(casefile: Mapping[str, Any]) -> list[str]:
    """Validate generic discovery completeness without inspecting case answers."""

    errors: list[str] = []
    strategy = (
        casefile.get("strategy_tree")
        if isinstance(casefile.get("strategy_tree"), Mapping)
        else {}
    )
    nodes = strategy.get("nodes") if isinstance(strategy.get("nodes"), list) else []
    baseline_nodes = [
        node
        for node in nodes
        if isinstance(node, Mapping)
        and isinstance(node.get("metadata"), Mapping)
        and node["metadata"].get("c2trace_policy")
        == "c2trace.baseline.recent_files.v1"
    ]
    if len(baseline_nodes) != 1:
        return [
            "dry-run requires exactly one system-owned recent-file baseline node"
        ]
    node = baseline_nodes[0]
    if node.get("type") != "investigate" or node.get("tool") != "check_recent_files":
        errors.append("recent-file baseline node has the wrong type or tool")

    raw_results = casefile.get("action_results")
    results = raw_results if isinstance(raw_results, list) else []
    baseline_results = [
        result
        for result in results
        if isinstance(result, Mapping)
        and result.get("tool") == "check_recent_files"
        and result.get("node_id") == node.get("node_id")
    ]
    if len(baseline_results) != 1:
        errors.append("dry-run requires exactly one recent-file baseline ActionResult")
        return errors
    result = baseline_results[0]
    if result.get("success") is not True:
        errors.append("recent-file baseline ActionResult was not successful")

    arguments = (
        result.get("arguments")
        if isinstance(result.get("arguments"), Mapping)
        else {}
    )
    if arguments.get("root_aliases") != ["users_public", "appdata"]:
        errors.append("recent-file baseline did not request both fixed roots")
    if arguments.get("max_depth") != 0:
        errors.append("recent-file baseline was not root-only")
    if not isinstance(arguments.get("since_utc"), str) or not isinstance(
        arguments.get("until_utc"), str
    ):
        errors.append("recent-file baseline lacks a frozen UTC window")

    data = result.get("data") if isinstance(result.get("data"), Mapping) else {}
    files = data.get("files") if isinstance(data.get("files"), list) else None
    scan = data.get("scan") if isinstance(data.get("scan"), Mapping) else {}
    roots = scan.get("roots") if isinstance(scan.get("roots"), list) else []
    root_state = {
        str(item.get("alias") or ""): item.get("exists") is True
        for item in roots
        if isinstance(item, Mapping)
    }
    if files is None:
        errors.append("recent-file baseline returned no files array")
    if root_state != {"users_public": True, "appdata": True}:
        errors.append("recent-file baseline did not scan both fixed roots")
    if scan.get("truncated") is not False:
        errors.append("recent-file baseline scan was truncated")
    matching_count = scan.get("matching_file_count")
    if (
        isinstance(matching_count, bool)
        or not isinstance(matching_count, int)
        or matching_count < 0
    ):
        errors.append("recent-file baseline lacks a valid matching-file count")
    elif files is not None and matching_count != len(files):
        errors.append("recent-file baseline omitted matching files")
    return errors


def response_tools_from_ground_truth(ground_truth: Mapping[str, Any]) -> list[str]:
    supported = {
        "kill_process",
        "remove_file",
        "remove_registry",
        "remove_scheduled_task",
        "remove_service",
    }
    values = {
        str(row.get("tool") or "")
        for row in ground_truth.get("response_actions", [])
        if isinstance(row, Mapping)
    }
    if not values or not values <= supported:
        raise ControllerSupportError(
            f"Ground Truth response tools are empty or unsupported: {sorted(values)}"
        )
    return sorted(values)
