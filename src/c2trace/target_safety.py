from __future__ import annotations

import hashlib
import json
import ntpath
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from c2trace.models import CaseFile, StrategyNode
from c2trace.time_identity import (
    CREATION_TIME_TOLERANCE_SECONDS,
    creation_times_match as _shared_creation_times_match,
    normalize_creation_time as _shared_normalize_creation_time,
    parse_utc_datetime as _shared_parse_utc_datetime,
)


PROTECTED_PROCESSES_SCHEMA_V1 = "c2trace.protected_processes.v1"
PROTECTED_PROCESSES_SCHEMA_V2 = "c2trace.protected_processes.v2"
PROTECTED_PROCESSES_SCHEMA = PROTECTED_PROCESSES_SCHEMA_V1
TARGET_LOCK_SCHEMA_V1 = "c2trace.response_target_lock.v1"
TARGET_LOCK_SCHEMA_V2 = "c2trace.response_target_lock.v2"
TARGET_LOCK_SCHEMA = TARGET_LOCK_SCHEMA_V1
TARGET_TYPES_V2 = frozenset(
    {
        "manx_tcp_client",
        "sandcat_http_client",
        "windows_webshell_http_listener",
        "sliver_mtls_outbound",
        "meterpreter_reverse_tcp_outbound",
        "carbanak_cscript_https_rat_outbound",
        "exaramel_https_outbound",
        "sidetwist_http_outbound",
        "emotet_dll_http_outbound",
        "plugx_http_outbound",
        "other",
    }
)
NETWORK_MODES_V2 = frozenset({"outbound_active_flow", "inbound_listener"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_LOLBIN_HOSTS = frozenset({
    "rundll32.exe", "cscript.exe", "wscript.exe", "regsvr32.exe",
    "mshta.exe", "powershell.exe", "cmd.exe", "msiexec.exe",
    "python.exe", "pythonw.exe", "py.exe",
})
_LOLBIN_HOST_BASENAMES = frozenset(
    ntpath.basename(p) for p in _LOLBIN_HOSTS
)


def _extract_lolbin_payload_path(command_line, process_path):
    """Extract the payload file path from a LOLBin host process command line.

    Returns the extracted path when the host process is a known LOLBin and the
    command line references a file whose extension indicates a loadable payload
    (.dll, .vbs, .js, .hta, .ps1, .msi).  Returns an empty string otherwise.
    """
    if not command_line or not process_path:
        return ""
    host_base = ntpath.basename(process_path).casefold()
    if host_base not in _LOLBIN_HOST_BASENAMES:
        return ""
    tokens = []
    for raw_token in command_line.split():
        token = raw_token.strip('"').strip("'").rstrip(",")
        if token:
            for part in token.split(","):
                part = part.strip()
                if part:
                    tokens.append(part)
    payload_exts = {".dll", ".vbs", ".js", ".hta", ".ps1", ".msi", ".py"}
    for token in tokens:
        ext = ntpath.splitext(token)[1].casefold()
        if ext in payload_exts and _normalize_path(token) != _normalize_path(process_path):
            return token
    return ""


_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class TargetSafetyInputError(ValueError):
    """Raised when a safety input cannot be validated before a run."""


class TargetSafetyError(RuntimeError):
    """A fail-closed response denial with a stable terminal status."""

    def __init__(
        self,
        status: str,
        message: str,
        *,
        error_type: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.error_type = error_type or status
        self.details = dict(details or {})


@dataclass(frozen=True, slots=True)
class LoadedSafetyInput:
    path: str
    sha256: str
    payload: dict[str, Any]


def load_protected_processes(path: str | Path, *, strict_safe: bool = False) -> LoadedSafetyInput:
    loaded = _load_json_object(path, "protected-process manifest")
    payload = loaded.payload
    schema = str(payload.get("schema_version") or "")
    if schema not in {PROTECTED_PROCESSES_SCHEMA_V1, PROTECTED_PROCESSES_SCHEMA_V2}:
        raise TargetSafetyInputError(
            "protected-process manifest schema_version must be "
            f"{PROTECTED_PROCESSES_SCHEMA_V1} or {PROTECTED_PROCESSES_SCHEMA_V2}"
        )
    processes = payload.get("processes")
    if not isinstance(processes, list) or not processes:
        raise TargetSafetyInputError("protected-process manifest requires a non-empty processes list")
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(processes):
        if not isinstance(item, dict):
            raise TargetSafetyInputError(f"protected process #{index + 1} must be an object")
        normalized.append(_normalize_protected_process(item, index=index))
    run_id = str(payload.get("run_id") or "").strip()
    # Fail-closed: when strict_safe is True (used by run_case.py), the protected
    # manifest must NOT contain any Ground Truth fields.  This prevents the
    # tested C2 target's real identity from entering C2Trace's runtime.
    if strict_safe:
        _GT_FORBIDDEN_KEYS = frozenset({
            "expected_target", "target_profile", "ground_truth",
            "cleanup_ground_truth", "scoring_casefile",
        })
        for key in _GT_FORBIDDEN_KEYS:
            if key in payload:
                raise TargetSafetyInputError(
                    f"strict_safe protected-process manifest must not contain '{key}'; "
                    f"Ground Truth must be isolated in cleanup_ground_truth.json"
                )
    expected_payload = payload.get("expected_target", payload.get("target_profile"))
    if run_id and not _RUN_ID_RE.fullmatch(run_id):
        raise TargetSafetyInputError(
            "protected-process manifest run_id must be 1-128 path-safe characters"
        )
    if expected_payload is not None and not isinstance(expected_payload, dict):
        raise TargetSafetyInputError("protected-process manifest expected_target must be an object")
    expected_target = (
        _normalize_expected_target(expected_payload, schema_version=schema)
        if isinstance(expected_payload, dict)
        else None
    )
    if expected_target is not None and not run_id:
        raise TargetSafetyInputError(
            "protected-process manifest requires run_id when expected_target is supplied"
        )
    return LoadedSafetyInput(
        path=loaded.path,
        sha256=loaded.sha256,
        payload={
            **payload,
            "processes": normalized,
            "run_id": run_id,
            "expected_target": expected_target,
            "target_lock_schema_version": (
                TARGET_LOCK_SCHEMA_V2
                if schema == PROTECTED_PROCESSES_SCHEMA_V2
                else TARGET_LOCK_SCHEMA_V1
            ),
        },
    )


def load_reviewed_target(path: str | Path) -> LoadedSafetyInput:
    loaded = _load_json_object(path, "reviewed-target CaseFile")
    root = loaded.payload
    candidate = root.get("response_target_lock", root)
    if not isinstance(candidate, dict):
        raise TargetSafetyInputError(
            "reviewed-target input requires a response_target_lock object"
        )
    normalized = _normalize_target_lock(candidate)
    return LoadedSafetyInput(path=loaded.path, sha256=loaded.sha256, payload=normalized)


class TargetSafetyGuard:
    """Compatibility implementation behind Auditor's TargetIdentityValidator.

    The Auditor-owned validator acquires a live target identity before the first
    response action.  It then freezes that identity so file and persistence
    cleanup can continue safely after ``kill_process`` removes the live C2
    connection.  The protected-process manifest and reviewed dry-run target
    never enter Planner or Auditor LLM prompt context.
    """

    def __init__(
        self,
        *,
        tool_runner: Any,
        protected_processes: list[dict[str, Any]] | None = None,
        reviewed_target: dict[str, Any] | None = None,
        run_id: str = "",
        expected_target: dict[str, Any] | None = None,
        target_lock_schema_version: str = "",
    ) -> None:
        self.tool_runner = tool_runner
        self.protected_processes = [dict(item) for item in (protected_processes or [])]
        self.reviewed_target = (
            _normalize_target_lock(reviewed_target) if reviewed_target is not None else None
        )
        self.run_id = str(run_id or "").strip()
        if self.run_id and not _RUN_ID_RE.fullmatch(self.run_id):
            raise TargetSafetyInputError("target-safety run_id is invalid")
        reviewed_schema = str((reviewed_target or {}).get("schema_version") or "")
        requested_schema = str(target_lock_schema_version or reviewed_schema or "")
        if not requested_schema and isinstance(expected_target, dict):
            if expected_target.get("target_type") or expected_target.get("network_mode"):
                requested_schema = TARGET_LOCK_SCHEMA_V2
        self.target_lock_schema_version = requested_schema or TARGET_LOCK_SCHEMA_V1
        if self.target_lock_schema_version not in {TARGET_LOCK_SCHEMA_V1, TARGET_LOCK_SCHEMA_V2}:
            raise TargetSafetyInputError("unsupported response target lock schema version")
        manifest_schema = (
            PROTECTED_PROCESSES_SCHEMA_V2
            if self.target_lock_schema_version == TARGET_LOCK_SCHEMA_V2
            else PROTECTED_PROCESSES_SCHEMA_V1
        )
        self.expected_target = (
            _normalize_expected_target(expected_target, schema_version=manifest_schema)
            if expected_target is not None
            else None
        )
        if self.expected_target is not None and not self.run_id:
            raise TargetSafetyInputError("target-safety run_id is required with expected_target")
        self._lock: dict[str, Any] | None = None

    def validate_case_input(self, case: CaseFile) -> None:
        """Bind a reviewed lock to this exact case and seed before planning."""
        if self.target_lock_schema_version == TARGET_LOCK_SCHEMA_V2:
            self._validate_v2_source_event(case)
        if self.reviewed_target is None:
            return
        reviewed = self.reviewed_target
        if str(reviewed.get("case_id") or "") != case.case_id:
            raise TargetSafetyError(
                "target_drift",
                "reviewed target case_id does not match the current case",
                details={
                    "reviewed_case_id": reviewed.get("case_id"),
                    "current_case_id": case.case_id,
                },
            )
        network = reviewed["network"]
        current_seed = {
            "remote_address": _normalize_ip(case.source_alert.get("remote_ip")),
            "remote_port": _normalize_port(case.source_alert.get("remote_port")),
            "protocol": _normalize_protocol(case.source_alert.get("protocol")),
        }
        reviewed_seed = {
            "remote_address": _normalize_ip(network.get("remote_address")),
            "remote_port": _normalize_port(network.get("remote_port")),
            "protocol": _normalize_protocol(network.get("protocol")),
        }
        if current_seed != reviewed_seed:
            raise TargetSafetyError(
                "target_drift",
                "reviewed target does not match the current alert tuple",
                details={"reviewed": reviewed_seed, "current": current_seed},
            )
        reviewed_flow = str(reviewed.get("source", {}).get("flow_id") or "")
        current_flow = _source_flow_id(case)
        if reviewed_flow and current_flow and reviewed_flow != current_flow:
            raise TargetSafetyError(
                "target_drift",
                "reviewed target flow_id does not match the current source event",
                details={"reviewed_flow_id": reviewed_flow, "current_flow_id": current_flow},
            )
        if self.run_id and str(reviewed.get("run_id") or "") != self.run_id:
            raise TargetSafetyError(
                "target_drift",
                "reviewed target run_id does not match the protected-process context",
                details={"reviewed_run_id": reviewed.get("run_id"), "current_run_id": self.run_id},
            )
        if self.expected_target is not None:
            metadata_checks = {
                (
                    "target_paw"
                    if self.target_lock_schema_version == TARGET_LOCK_SCHEMA_V2
                    else "manx_paw"
                ): self.expected_target["paw"],
                "group": self.expected_target["group"],
                "host": self.expected_target["host"],
                "contact": self.expected_target["contact"],
            }
            differences = [
                key
                for key, expected in metadata_checks.items()
                if _normalize_text(reviewed.get(key)) != _normalize_text(expected)
            ]
            if differences:
                raise TargetSafetyError(
                    "target_drift",
                    "reviewed target identity does not match the expected target context",
                    details={"differences": differences},
                )

    def _validate_v2_source_event(self, case: CaseFile) -> None:
        """Bind a v2 target to the exact, fresh event selected by the controller."""

        event = _source_event(case)
        if not event:
            raise TargetSafetyError("target_drift", "v2 target lock requires an exact source event")
        event_hash = _source_event_sha256(case)
        if not event_hash:
            raise TargetSafetyError(
                "target_drift",
                "v2 target lock requires the frozen source-event SHA-256",
            )
        expected = self.expected_target or {}
        expected_network = expected.get("network_identity")
        if isinstance(expected_network, dict):
            observed = _event_network_identity(
                case,
                network_mode=str(expected.get("network_mode") or "outbound_active_flow"),
            )
            differences = _network_identity_differences(expected_network, observed)
            if differences:
                raise TargetSafetyError(
                    "target_drift",
                    "source event differs from the pre-registered target network identity",
                    details={"differences": differences},
                )
        not_before = _parse_utc_datetime(
            expected.get("source_not_before_utc")
            or expected.get("not_before_utc")
            or expected.get("created_at")
        )
        event_time = _parse_utc_datetime(event.get("timestamp"))
        if not_before is not None:
            if event_time is None or event_time < not_before:
                raise TargetSafetyError(
                    "target_drift",
                    "selected source event predates the target instance",
                    details={
                        "event_timestamp": event.get("timestamp"),
                        "not_before_utc": not_before.isoformat(),
                    },
                )

    def prepare_response(
        self,
        case: CaseFile,
        node: StrategyNode,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Acquire/validate the target and authorize one response target shape."""
        if self._lock is None:
            current = self._acquire_live_lock(case)
            protected = self._match_protected(current)
            if protected is not None:
                raise TargetSafetyError(
                    "protected_target_blocked",
                    "the C2-attributed process matches a protected control process",
                    error_type="wrong_target",
                    details={
                        "matched_by": protected["matched_by"],
                        "protected_label": protected["process"].get("label", ""),
                        "protected_paw": protected["process"].get("paw", ""),
                    },
                )
            if self.expected_target is not None:
                differences = _expected_target_differences(self.expected_target, current)
                if differences:
                    raise TargetSafetyError(
                        "target_drift",
                        "live response target differs from the expected Manx identity",
                        details={"differences": differences},
                    )
            if self.reviewed_target is not None:
                differences = _target_differences(self.reviewed_target, current)
                if differences:
                    raise TargetSafetyError(
                        "target_drift",
                        "live response target differs from the reviewed dry-run target",
                        details={"differences": differences},
                    )
            self._lock = current
            case.response_target_lock = dict(current)
            case.add_timeline(
                "response_target_lock_acquired",
                "Exact response target identity was locked before response",
                "auditor",
                details={
                    "lock_id": current["lock_id"],
                    "schema_version": current["schema_version"],
                },
            )

        self._validate_response_arguments(node.tool, arguments)
        # Sibling C2 kill_process: the locked primary process may already be
        # terminated, so skip the live-artifact recheck for the primary PID.
        is_sibling = False
        if node.tool == "kill_process":
            req_pid = _as_pid(arguments.get("pid"))
            locked_pid = self._lock["process"]["pid"]
            if req_pid != locked_pid:
                is_sibling = True
        if not is_sibling:
            self._validate_current_artifact(node.tool, arguments)
        return dict(self._lock)

    def _acquire_live_lock(self, case: CaseFile) -> dict[str, Any]:
        expected = self.expected_target or {}
        network_mode = str(
            expected.get("network_mode")
            or (self.reviewed_target or {}).get("network_mode")
            or (self.reviewed_target or {}).get("network", {}).get("mode")
            or ""
        ).strip().lower()
        if not network_mode:
            # GT-blocked path: infer network_mode from Suricata event direction.
            # If src_ip is the remote C2 and dest_ip is the victim, this is an
            # inbound listener (e.g. webshell). Otherwise default to outbound.
            event = _source_event(case)
            victim_ip = _normalize_ip(case.source_alert.get("victim_ip"))
            remote_ip = _normalize_ip(case.source_alert.get("remote_ip"))
            src_ip = _normalize_ip(event.get("src_ip"))
            dest_ip = _normalize_ip(event.get("dest_ip"))
            if src_ip == remote_ip and dest_ip == victim_ip:
                network_mode = "inbound_listener"
            else:
                network_mode = "outbound_active_flow"
        if network_mode not in NETWORK_MODES_V2:
            raise TargetSafetyError("target_drift", f"unsupported target network mode: {network_mode}")
        event_network = _event_network_identity(case, network_mode=network_mode)
        remote_ip = event_network["remote_address"]
        remote_port = event_network["remote_port"]
        local_address = event_network["local_address"]
        local_port = event_network["local_port"]
        protocol = event_network["protocol"]
        if not remote_ip or not local_address or not local_port or protocol != "tcp":
            raise TargetSafetyError(
                "target_drift",
                "an exact TCP source event is required to lock a response target",
                details={**event_network, "network_mode": network_mode},
            )
        if network_mode == "outbound_active_flow" and not remote_port:
            raise TargetSafetyError(
                "target_drift",
                "an outbound target requires an exact remote port",
                details=event_network,
            )

        network_params: dict[str, Any]
        if network_mode == "outbound_active_flow":
            network_params = {
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "local_port": local_port,
            }
        else:
            network_params = {
                "network_mode": "inbound_listener",
                "local_ip": local_address,
                "local_port": local_port,
            }
        network_result = self.tool_runner.run("check_network", network_params)
        if not network_result.success or not isinstance(network_result.data, dict):
            raise TargetSafetyError(
                "target_drift",
                "unable to revalidate the target network identity immediately before response",
                details={"error": network_result.error or "malformed check_network result"},
            )
        connections: list[dict[str, Any]] = []
        for item in network_result.data.get("connections", []):
            if not isinstance(item, dict) or _normalize_port(item.get("local_port")) != local_port:
                continue
            if network_mode == "outbound_active_flow":
                if (
                    _normalize_ip(item.get("remote_address")) != remote_ip
                    or _normalize_port(item.get("remote_port")) != remote_port
                    or _normalize_text(item.get("state")) != "established"
                ):
                    continue
            else:
                observed_local = _normalize_ip(item.get("local_address"))
                if observed_local not in {local_address, "0.0.0.0", "::", "::0"}:
                    continue
                if _normalize_text(item.get("state")) not in {"listen", "listening"}:
                    continue
            connections.append(item)
        if len(connections) != 1:
            raise TargetSafetyError(
                "target_drift",
                "response target requires exactly one live owner of the exact network identity",
                details={
                    "network_mode": network_mode,
                    "matching_connections": len(connections),
                    "local_port": local_port,
                },
            )
        connection = connections[0]
        try:
            pid = int(connection.get("pid") or connection.get("owning_process") or 0)
        except (TypeError, ValueError):
            pid = 0
        if pid <= 0:
            raise TargetSafetyError("target_drift", "live alert tuple has no owning PID")

        process_result = self.tool_runner.run("check_process", {"pid": pid})
        if not process_result.success or not isinstance(process_result.data, dict):
            raise TargetSafetyError(
                "target_drift",
                "unable to revalidate the owning process immediately before response",
                details={"error": process_result.error or "malformed check_process result"},
            )
        processes = [
            item
            for item in process_result.data.get("processes", [])
            if isinstance(item, dict) and _as_pid(item.get("pid") or item.get("process_id")) == pid
        ]
        if len(processes) != 1:
            raise TargetSafetyError(
                "target_drift",
                "response target requires exactly one process for the network owner PID",
                details={"pid": pid, "matching_processes": len(processes)},
            )
        process = processes[0]
        path = str(
            process.get("path")
            or process.get("process_path")
            or process.get("executable_path")
            or connection.get("process_path")
            or ""
        ).strip()
        canonical_path = _normalize_path(path)
        creation_time = _normalize_creation_time(
            process.get("creation_time_utc") or process.get("creation_date")
        )
        if not canonical_path or not creation_time:
            raise TargetSafetyError(
                "target_drift",
                "response target process path and creation time are required",
                details={"pid": pid, "path_present": bool(path), "creation_time_present": bool(creation_time)},
            )

        process_file_result = self.tool_runner.run("check_file_metadata", {"file_path": path})
        process_file_info = (
            process_file_result.data.get("file")
            if process_file_result.success and isinstance(process_file_result.data, dict)
            else None
        )
        if not isinstance(process_file_info, dict) or process_file_info.get("exists") is not True:
            raise TargetSafetyError(
                "target_drift",
                "response target executable must exist while the target lock is acquired",
                details={
                    "path": path,
                    "error": process_file_result.error or "file not found",
                },
            )
        process_file_path = str(process_file_info.get("path") or path)
        process_file_hash = _normalize_sha256(process_file_info.get("sha256"))
        if _normalize_path(process_file_path) != canonical_path or not process_file_hash:
            raise TargetSafetyError(
                "target_drift",
                "response target executable path/hash could not be bound exactly",
                details={"process_path": path, "file_path": process_file_path},
            )
        expected_process_hash = _normalize_sha256(
            expected.get("executable_sha256") or expected.get("sha256")
        )
        if expected_process_hash and expected_process_hash != process_file_hash:
            raise TargetSafetyError(
                "target_drift",
                "live target process hash differs from the pre-registered identity",
            )

        response_file_path = str(expected.get("payload_path") or "")
        if not response_file_path:
            command_line = str(process.get("command_line") or "")
            lolbin_path = _extract_lolbin_payload_path(command_line, path)
            if lolbin_path:
                response_file_path = lolbin_path
        if not response_file_path:
            response_file_path = process_file_path
        response_file_result = (
            process_file_result
            if _normalize_path(response_file_path) == canonical_path
            else self.tool_runner.run(
                "check_file_metadata", {"file_path": response_file_path}
            )
        )
        response_file_info = (
            response_file_result.data.get("file")
            if response_file_result.success and isinstance(response_file_result.data, dict)
            else None
        )
        if not isinstance(response_file_info, dict) or response_file_info.get("exists") is not True:
            raise TargetSafetyError(
                "target_drift",
                "response target file must exist while the target lock is acquired",
                details={
                    "path": response_file_path,
                    "error": response_file_result.error or "file not found",
                },
            )
        response_file_path = str(response_file_info.get("path") or response_file_path)
        response_file_hash = _normalize_sha256(response_file_info.get("sha256"))
        if not response_file_hash:
            raise TargetSafetyError("target_drift", "response target file hash is missing")
        expected_payload_hash = _normalize_sha256(expected.get("payload_sha256"))
        if expected_payload_hash and expected_payload_hash != response_file_hash:
            raise TargetSafetyError(
                "target_drift",
                "response target file hash differs from the pre-registered identity",
            )

        observed_listener_address = _normalize_ip(connection.get("local_address"))
        if network_mode == "outbound_active_flow":
            if observed_listener_address != local_address:
                raise TargetSafetyError(
                    "target_drift",
                    "live connection local address does not match the victim endpoint",
                    details={
                        "connection_local": observed_listener_address,
                        "victim_ip": local_address,
                    },
                )
        elif observed_listener_address not in {local_address, "0.0.0.0", "::", "::0"}:
            raise TargetSafetyError(
                "target_drift",
                "live listener address does not cover the victim endpoint",
                details={
                    "listener_address": observed_listener_address,
                    "victim_ip": local_address,
                },
            )

        lock_material = {
            "case_id": case.case_id,
            "run_id": self.run_id,
            (
                "target_paw"
                if self.target_lock_schema_version == TARGET_LOCK_SCHEMA_V2
                else "manx_paw"
            ): expected.get("paw", ""),
            "group": self.expected_target.get("group", "") if self.expected_target else "",
            "host": self.expected_target.get("host", "") if self.expected_target else "",
            "contact": self.expected_target.get("contact", "") if self.expected_target else "",
            "network": {
                "protocol": protocol,
                "local_address": local_address,
                "local_port": local_port,
                "remote_address": remote_ip,
                "remote_port": remote_port,
            },
            "process": {
                "pid": pid,
                "name": str(process.get("name") or process.get("process_name") or ""),
                "creation_time_utc": creation_time,
                "path": process_file_path,
                "canonical_path": canonical_path,
                "sha256": process_file_hash,
            },
            "file": {
                "path": response_file_path,
                "canonical_path": _normalize_path(response_file_path),
                "sha256": response_file_hash,
                "artifact_role": (
                    "webshell_payload"
                    if str(expected.get("target_type") or "")
                    == "windows_webshell_http_listener"
                    else "implant_executable"
                ),
            },
            "source": {
                "flow_id": _source_flow_id(case),
                "event_sha256": _source_event_sha256(case),
                "timestamp": str(_source_event(case).get("timestamp") or ""),
            },
            "persistence_targets": _persistence_targets(case),
            "secondary_pid": self._resolve_secondary_pid(case, expected, pid),
        }
        if self.target_lock_schema_version == TARGET_LOCK_SCHEMA_V2:
            lock_material.update(
                {
                    "target_type": str(expected.get("target_type") or "other"),
                    "network_mode": network_mode,
                    "response_policy": dict(expected.get("response_policy") or {}),
                }
            )
            lock_material["network"].update(
                {
                    "mode": network_mode,
                    "direction": (
                        "victim_to_remote"
                        if network_mode == "outbound_active_flow"
                        else "remote_to_victim"
                    ),
                    "listener_address": (
                        observed_listener_address
                        if network_mode == "inbound_listener"
                        else ""
                    ),
                }
            )
        lock_id = hashlib.sha256(
            json.dumps(lock_material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return {
            "schema_version": self.target_lock_schema_version,
            "lock_id": lock_id,
            "acquired_at": datetime.now(timezone.utc).isoformat(),
            **lock_material,
        }

    def _resolve_secondary_pid(self, case: CaseFile, expected: Mapping[str, Any], primary_pid: int) -> int:
        """Resolve the secondary C2 PID without relying on Ground Truth.

        Prefer C2Trace's own investigation findings (sibling_c2_processes)
        over the pre-registered expected_target, so the lock stays valid
        after GT removal.
        """
        gt_secondary = int(expected.get("secondary_pid") or 0)
        if gt_secondary > 0:
            return gt_secondary
        discovered = 0
        try:
            siblings = case.sibling_c2_processes()
        except Exception:
            siblings = []
        for sibling in siblings:
            sibling_pid = int(sibling.get("pid") or 0)
            if sibling_pid > 0 and sibling_pid != primary_pid:
                discovered = sibling_pid
                break
        return discovered

    def _match_protected(self, current: dict[str, Any]) -> dict[str, Any] | None:
        process = current["process"]
        process_hash = _normalize_sha256(process.get("sha256"))
        for protected in self.protected_processes:
            matched_by: list[str] = []
            protected_pid = _as_pid(protected.get("pid"))
            if protected_pid and protected_pid == process["pid"]:
                protected_creation = _normalize_creation_time(protected.get("creation_time_utc"))
                if not protected_creation or _creation_times_match(
                    protected_creation, process["creation_time_utc"]
                ):
                    matched_by.append("pid_creation_time")
            if _normalize_path(protected.get("canonical_path") or protected.get("path")) == process["canonical_path"]:
                matched_by.append("canonical_path")
            if _normalize_sha256(protected.get("sha256")) == process_hash:
                matched_by.append("sha256")
            # A run-scoped target Sandcat can legitimately have the same
            # binary hash as the batch control Sandcat.  In v2 a digest alone
            # is therefore not a process identity; PID+creation or exact path
            # must also match.  v1 preserves its historical conservative rule.
            strong_match = any(item in {"pid_creation_time", "canonical_path"} for item in matched_by)
            if matched_by and (
                self.target_lock_schema_version == TARGET_LOCK_SCHEMA_V1 or strong_match
            ):
                return {"matched_by": matched_by, "process": protected}
        return None

    def _validate_response_arguments(self, tool: str, arguments: dict[str, Any]) -> None:
        assert self._lock is not None
        process = self._lock["process"]
        if tool == "kill_process":
            policy = self._lock.get("response_policy")
            if isinstance(policy, dict) and policy.get("allow_process_termination") is False:
                raise TargetSafetyError(
                    "protected_target_blocked",
                    "target profile forbids terminating the listener owner process",
                    error_type="wrong_target",
                )
            req_pid = _as_pid(arguments.get("pid"))
            if req_pid != process["pid"]:
                secondary_pid = int(
                    (self.expected_target or {}).get("secondary_pid")
                    or self._lock.get("secondary_pid")
                    or 0
                )
                if req_pid != secondary_pid:
                    raise TargetSafetyError("target_drift", "kill_process PID differs from the locked target")
            expected_path = _normalize_path(arguments.get("expected_path"))
            if expected_path != process["canonical_path"]:
                raise TargetSafetyError("target_drift", "kill_process path differs from the locked target")
            return
        if tool == "remove_file":
            policy = self._lock.get("response_policy")
            if isinstance(policy, dict) and policy.get("allow_file_removal") is False:
                raise TargetSafetyError(
                    "protected_target_blocked",
                    "target profile forbids removing the locked target file",
                    error_type="wrong_target",
                )
            locked_file = self._lock.get("file") if isinstance(self._lock.get("file"), dict) else {}
            if _normalize_path(arguments.get("file_path")) != locked_file.get("canonical_path"):
                raise TargetSafetyError("target_drift", "remove_file path differs from the locked target")
            return
        category = {
            "remove_registry": "registry_run_keys",
            "remove_scheduled_task": "scheduled_tasks",
            "remove_service": "services",
        }.get(tool)
        if not category:
            raise TargetSafetyError("target_drift", f"unsupported response target lock tool: {tool}")
        if not any(
            _persistence_arguments_match(category, item, arguments)
            for item in self._lock.get("persistence_targets", [])
            if isinstance(item, dict) and item.get("category") == category
        ):
            raise TargetSafetyError(
                "target_drift",
                f"{tool} target was not frozen as persistence linked to the locked executable",
            )

    def _validate_current_artifact(self, tool: str, arguments: dict[str, Any]) -> None:
        """Recheck the mutable object when it still exists; retain lock after kill."""
        assert self._lock is not None
        if tool == "kill_process":
            result = self.tool_runner.run("check_process", {"pid": self._lock["process"]["pid"]})
            items = result.data.get("processes", []) if result.success and isinstance(result.data, dict) else []
            matching = [
                item
                for item in items
                if isinstance(item, dict)
                and _as_pid(item.get("pid") or item.get("process_id")) == self._lock["process"]["pid"]
                and _creation_times_match(
                    item.get("creation_time_utc") or item.get("creation_date"),
                    self._lock["process"]["creation_time_utc"],
                )
                and _normalize_path(item.get("path") or item.get("process_path") or item.get("executable_path"))
                == self._lock["process"]["canonical_path"]
            ]
            if len(matching) != 1:
                raise TargetSafetyError("target_drift", "locked process identity changed before kill_process")
        elif tool == "remove_file":
            result = self.tool_runner.run("check_file_metadata", {"file_path": arguments.get("file_path")})
            file_info = result.data.get("file") if result.success and isinstance(result.data, dict) else None
            if not isinstance(file_info, dict) or file_info.get("exists") is not True:
                raise TargetSafetyError("target_drift", "locked executable disappeared before remove_file")
            if _normalize_sha256(file_info.get("sha256")) != self._lock["file"]["sha256"]:
                raise TargetSafetyError("target_drift", "locked executable hash changed before remove_file")
        elif tool in {"remove_registry", "remove_scheduled_task", "remove_service"}:
            result = self.tool_runner.run("check_persistence_all", {})
            if not result.success or not isinstance(result.data, dict):
                raise TargetSafetyError("target_drift", "unable to revalidate locked persistence target")
            category = {
                "remove_registry": "registry_run_keys",
                "remove_scheduled_task": "scheduled_tasks",
                "remove_service": "services",
            }[tool]
            live_items = result.data.get(category, [])
            if not any(
                isinstance(item, dict) and _persistence_arguments_match(category, item, arguments)
                for item in live_items if isinstance(live_items, list)
            ):
                raise TargetSafetyError("target_drift", f"locked {category} target changed before response")


def _load_json_object(path: str | Path, label: str) -> LoadedSafetyInput:
    target = Path(path).resolve()
    try:
        raw = target.read_bytes()
        payload = json.loads(raw.decode("utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TargetSafetyInputError(f"unable to load {label}: {exc}") from exc
    if not isinstance(payload, dict):
        raise TargetSafetyInputError(f"{label} root must be a JSON object")
    return LoadedSafetyInput(
        path=str(target),
        sha256=hashlib.sha256(raw).hexdigest(),
        payload=payload,
    )


def _normalize_protected_process(item: dict[str, Any], *, index: int) -> dict[str, Any]:
    pid = _as_pid(item.get("pid"))
    creation = _normalize_creation_time(
        item.get("creation_time_utc") or item.get("creation_time") or item.get("creation_date")
    )
    path = str(item.get("path") or item.get("canonical_path") or "").strip()
    digest = _normalize_sha256(item.get("sha256"))
    missing = [
        name
        for name, value in (
            ("pid", pid),
            ("creation_time_utc", creation),
            ("path", path),
            ("sha256", digest),
        )
        if not value
    ]
    if missing:
        raise TargetSafetyInputError(
            f"protected process #{index + 1} is missing/invalid: {', '.join(missing)}"
        )
    return {
        **item,
        "pid": pid,
        "creation_time_utc": creation,
        "path": path,
        "canonical_path": _normalize_path(path),
        "sha256": digest,
    }


def _normalize_expected_target(
    item: dict[str, Any],
    *,
    schema_version: str = PROTECTED_PROCESSES_SCHEMA_V1,
) -> dict[str, Any]:
    if schema_version == PROTECTED_PROCESSES_SCHEMA_V1:
        pid = _as_pid(item.get("pid"))
        creation = _normalize_creation_time(
            item.get("creation_time_utc")
            or item.get("creation_time")
            or item.get("creation_date")
        )
        path = str(item.get("path") or item.get("canonical_path") or "").strip()
        digest = _normalize_sha256(item.get("sha256"))
        normalized = {
            **item,
            "paw": str(item.get("paw") or "").strip(),
            "pid": pid,
            "creation_time_utc": creation,
            "path": path,
            "canonical_path": _normalize_path(path),
            "sha256": digest,
            "group": str(item.get("group") or "").strip(),
            "host": str(item.get("host") or "").strip(),
            "contact": str(item.get("contact") or "").strip().lower(),
        }
        missing = [
            key
            for key in (
                "paw",
                "pid",
                "creation_time_utc",
                "canonical_path",
                "sha256",
                "group",
                "host",
                "contact",
            )
            if not normalized[key]
        ]
        if missing:
            raise TargetSafetyInputError(
                f"expected_target is missing/invalid: {', '.join(missing)}"
            )
        return normalized

    if schema_version != PROTECTED_PROCESSES_SCHEMA_V2:
        raise TargetSafetyInputError("unsupported expected_target schema version")
    profile_target = item.get("target") if isinstance(item.get("target"), dict) else {}
    process_identity = item.get("process_identity")
    if not isinstance(process_identity, dict):
        process_identity = item.get("listener_owner")
    if not isinstance(process_identity, dict):
        process_identity = item
    target_type = str(
        item.get("target_type") or profile_target.get("target_type") or "other"
    ).strip().lower()
    network_mode = str(
        item.get("network_mode")
        or profile_target.get("network_mode")
        or (
            "inbound_listener"
            if target_type == "windows_webshell_http_listener"
            else "outbound_active_flow"
        )
    ).strip().lower()
    if target_type not in TARGET_TYPES_V2:
        raise TargetSafetyInputError(f"expected_target target_type is invalid: {target_type}")
    if network_mode not in NETWORK_MODES_V2:
        raise TargetSafetyInputError(f"expected_target network_mode is invalid: {network_mode}")

    path = str(
        process_identity.get("path")
        or process_identity.get("normalized_path")
        or process_identity.get("canonical_path")
        or ""
    ).strip()
    payload_path = str(item.get("payload_path") or "").strip()
    payload_sha256 = _normalize_sha256(item.get("payload_sha256"))
    artifacts = item.get("payload_artifacts")
    if isinstance(artifacts, list):
        primary = next(
            (
                value
                for value in artifacts
                if isinstance(value, dict)
                and value.get("artifact_role") == "webshell_payload"
            ),
            next((value for value in artifacts if isinstance(value, dict)), None),
        )
        if isinstance(primary, dict):
            payload_path = payload_path or str(
                primary.get("path") or primary.get("normalized_path") or ""
            ).strip()
            payload_sha256 = payload_sha256 or _normalize_sha256(primary.get("sha256"))
    if not payload_path and target_type != "windows_webshell_http_listener":
        payload_path = path
    if not payload_sha256 and target_type != "windows_webshell_http_listener":
        payload_sha256 = _normalize_sha256(process_identity.get("sha256"))

    contact_value = item.get("contact")
    if isinstance(contact_value, dict):
        contact_value = contact_value.get("protocol")
    if not contact_value and isinstance(profile_target.get("contact"), dict):
        contact_value = profile_target["contact"].get("protocol")
    network_identity = _normalize_network_identity(
        item.get("network_identity")
        if isinstance(item.get("network_identity"), dict)
        else {}
    )
    response_policy = item.get("response_policy")
    if not isinstance(response_policy, dict):
        response_policy = {}
    default_kill = target_type != "windows_webshell_http_listener"
    normalized = {
        **item,
        "target_type": target_type,
        "network_mode": network_mode,
        "paw": str(item.get("paw") or process_identity.get("paw") or "").strip(),
        "pid": _as_pid(process_identity.get("pid")),
        "creation_time_utc": _normalize_creation_time(
            process_identity.get("creation_time_utc")
            or process_identity.get("created_at")
            or process_identity.get("creation_time")
            or process_identity.get("creation_date")
        ),
        "path": path,
        "canonical_path": _normalize_path(path),
        "sha256": _normalize_sha256(process_identity.get("sha256")),
        "payload_path": payload_path,
        "payload_canonical_path": _normalize_path(payload_path),
        "payload_sha256": payload_sha256,
        "group": str(item.get("group") or process_identity.get("group") or "").strip(),
        "host": str(item.get("host") or process_identity.get("host") or "").strip(),
        "contact": str(contact_value or process_identity.get("contact") or "").strip().lower(),
        "network_identity": network_identity,
        "response_policy": {
            "allow_process_termination": bool(
                response_policy.get("allow_process_termination", default_kill)
            ),
            "allow_file_removal": bool(response_policy.get("allow_file_removal", True)),
        },
        "source_not_before_utc": str(
            item.get("source_not_before_utc")
            or item.get("not_before_utc")
            or item.get("created_at")
            or ""
        ).strip(),
    }
    required = [
        "pid",
        "creation_time_utc",
        "canonical_path",
        "sha256",
        "payload_canonical_path",
        "payload_sha256",
        "host",
    ]
    if target_type in {"manx_tcp_client", "sandcat_http_client"}:
        required.extend(["paw", "group", "contact"])
    missing = [key for key in required if not normalized.get(key)]
    if missing:
        raise TargetSafetyInputError(
            f"expected_target v2 is missing/invalid: {', '.join(missing)}"
        )
    return normalized


def _normalize_target_lock(candidate: dict[str, Any]) -> dict[str, Any]:
    schema = str(candidate.get("schema_version") or "")
    if schema not in {TARGET_LOCK_SCHEMA_V1, TARGET_LOCK_SCHEMA_V2}:
        raise TargetSafetyInputError(
            "reviewed target schema_version must be "
            f"{TARGET_LOCK_SCHEMA_V1} or {TARGET_LOCK_SCHEMA_V2}"
        )
    case_id = str(candidate.get("case_id") or "").strip()
    network = candidate.get("network") if isinstance(candidate.get("network"), dict) else {}
    process = candidate.get("process") if isinstance(candidate.get("process"), dict) else {}
    file_info = candidate.get("file") if isinstance(candidate.get("file"), dict) else {}
    normalized_network = {
        **network,
        "mode": str(
            network.get("mode")
            or candidate.get("network_mode")
            or "outbound_active_flow"
        ).strip().lower(),
        "protocol": _normalize_protocol(network.get("protocol")),
        "local_address": _normalize_ip(network.get("local_address")),
        "local_port": _normalize_port(network.get("local_port")),
        "remote_address": _normalize_ip(network.get("remote_address")),
        "remote_port": _normalize_port(network.get("remote_port")),
    }
    normalized_process = {
        **process,
        "pid": _as_pid(process.get("pid")),
        "creation_time_utc": _normalize_creation_time(
            process.get("creation_time_utc") or process.get("creation_date")
        ),
        "canonical_path": _normalize_path(process.get("canonical_path") or process.get("path")),
        "sha256": _normalize_sha256(process.get("sha256")),
    }
    normalized_file = {
        **file_info,
        "canonical_path": _normalize_path(file_info.get("canonical_path") or file_info.get("path")),
        "sha256": _normalize_sha256(file_info.get("sha256")),
    }
    required_values = {
        "case_id": case_id,
        "protocol": normalized_network["protocol"],
        "local_address": normalized_network["local_address"],
        "local_port": normalized_network["local_port"],
        "remote_address": normalized_network["remote_address"],
        "remote_port": normalized_network["remote_port"],
        "pid": normalized_process["pid"],
        "creation_time_utc": normalized_process["creation_time_utc"],
        "canonical_path": normalized_process["canonical_path"],
        "file_sha256": normalized_file["sha256"],
    }
    if schema == TARGET_LOCK_SCHEMA_V2:
        required_values.update(
            {
                "target_type": str(candidate.get("target_type") or "")
                if str(candidate.get("target_type") or "") in TARGET_TYPES_V2
                else "",
                "network_mode": normalized_network["mode"]
                if normalized_network["mode"] in NETWORK_MODES_V2
                else "",
                "process_sha256": normalized_process["sha256"],
                "file_canonical_path": normalized_file["canonical_path"],
            }
        )
    missing = [key for key, value in required_values.items() if not value]
    path_mismatch = (
        schema == TARGET_LOCK_SCHEMA_V1
        and normalized_process["canonical_path"] != normalized_file["canonical_path"]
    )
    if missing or path_mismatch:
        detail = ", ".join(missing or ["process/file canonical_path mismatch"])
        raise TargetSafetyInputError(f"reviewed target lock is incomplete or invalid: {detail}")
    return {
        **candidate,
        "case_id": case_id,
        "network": normalized_network,
        "network_mode": normalized_network["mode"],
        "process": normalized_process,
        "file": normalized_file,
        "source": candidate.get("source") if isinstance(candidate.get("source"), dict) else {},
        "persistence_targets": [
            dict(item)
            for item in candidate.get("persistence_targets", [])
            if isinstance(item, dict)
        ],
        "response_policy": (
            dict(candidate.get("response_policy"))
            if isinstance(candidate.get("response_policy"), dict)
            else {}
        ),
    }


def _target_differences(reviewed: dict[str, Any], current: dict[str, Any]) -> list[str]:
    schema = str(reviewed.get("schema_version") or TARGET_LOCK_SCHEMA_V1)
    paw_field = "target_paw" if schema == TARGET_LOCK_SCHEMA_V2 else "manx_paw"
    checks = {
        "run_id": (str(reviewed.get("run_id") or ""), str(current.get("run_id") or "")),
        paw_field: (
            _normalize_text(reviewed.get(paw_field)),
            _normalize_text(current.get(paw_field)),
        ),
        "group": (_normalize_text(reviewed.get("group")), _normalize_text(current.get("group"))),
        "host": (_normalize_text(reviewed.get("host")), _normalize_text(current.get("host"))),
        "contact": (
            _normalize_text(reviewed.get("contact")),
            _normalize_text(current.get("contact")),
        ),
        "network.protocol": (reviewed["network"]["protocol"], current["network"]["protocol"]),
        "network.local_address": (reviewed["network"]["local_address"], current["network"]["local_address"]),
        "network.local_port": (reviewed["network"]["local_port"], current["network"]["local_port"]),
        "network.remote_address": (reviewed["network"]["remote_address"], current["network"]["remote_address"]),
        "network.remote_port": (reviewed["network"]["remote_port"], current["network"]["remote_port"]),
        "process.pid": (reviewed["process"]["pid"], current["process"]["pid"]),
        "process.creation_time_utc": (
            reviewed["process"]["creation_time_utc"],
            current["process"]["creation_time_utc"],
        ),
        "process.canonical_path": (
            reviewed["process"]["canonical_path"],
            current["process"]["canonical_path"],
        ),
        "file.sha256": (reviewed["file"]["sha256"], current["file"]["sha256"]),
    }
    if schema == TARGET_LOCK_SCHEMA_V2:
        checks.update(
            {
                "target_type": (reviewed.get("target_type"), current.get("target_type")),
                "network_mode": (reviewed.get("network_mode"), current.get("network_mode")),
                "process.sha256": (
                    reviewed["process"].get("sha256"),
                    current["process"].get("sha256"),
                ),
                "file.canonical_path": (
                    reviewed["file"].get("canonical_path"),
                    current["file"].get("canonical_path"),
                ),
                "network.listener_address": (
                    reviewed["network"].get("listener_address", ""),
                    current["network"].get("listener_address", ""),
                ),
                "source.event_sha256": (
                    _normalize_sha256(reviewed.get("source", {}).get("event_sha256")),
                    _normalize_sha256(current.get("source", {}).get("event_sha256")),
                ),
            }
        )
    reviewed_flow = str(reviewed.get("source", {}).get("flow_id") or "")
    current_flow = str(current.get("source", {}).get("flow_id") or "")
    if reviewed_flow:
        checks["source.flow_id"] = (reviewed_flow, current_flow)
    return [
        name
        for name, values in checks.items()
        if not _field_values_match(name, values[0], values[1])
    ]


def _expected_target_differences(
    expected: dict[str, Any],
    current: dict[str, Any],
) -> list[str]:
    checks = {
        "process.pid": (expected["pid"], current["process"]["pid"]),
        "process.creation_time_utc": (
            expected["creation_time_utc"],
            current["process"]["creation_time_utc"],
        ),
        "process.canonical_path": (
            expected.get("executable_path") or expected.get("canonical_path"),
            current["process"]["canonical_path"],
        ),
        "file.sha256": (expected["sha256"], current["file"]["sha256"]),
    }
    if expected.get("target_type"):
        checks["target_type"] = (expected.get("target_type"), current.get("target_type"))
        checks["network_mode"] = (expected.get("network_mode"), current.get("network_mode"))
        checks["process.sha256"] = (
            expected.get("executable_sha256") or expected.get("sha256"),
            current["process"].get("sha256"),
        )
        checks["file.canonical_path"] = (
            expected.get("payload_canonical_path"),
            current["file"].get("canonical_path"),
        )
        checks["file.sha256"] = (
            expected.get("payload_sha256"),
            current["file"].get("sha256"),
        )
    return [
        name
        for name, values in checks.items()
        if not _field_values_match(name, values[0], values[1])
    ]


def _persistence_targets(case: CaseFile) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in case.findings:
        if finding.finding_type != "persistence_linked_to_payload":
            continue
        item = dict(finding.details) if isinstance(finding.details, dict) else {}
        category = str(item.get("category") or "")
        if category not in {"registry_run_keys", "scheduled_tasks", "services"}:
            continue
        fingerprint = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
        if fingerprint not in seen:
            seen.add(fingerprint)
            targets.append(item)
    return targets


def _persistence_arguments_match(
    category: str,
    item: dict[str, Any],
    arguments: dict[str, Any],
) -> bool:
    if category == "registry_run_keys":
        return (
            _normalize_path(item.get("path")) == _normalize_path(arguments.get("reg_path"))
            and _normalize_text(item.get("name")) == _normalize_text(arguments.get("value_name"))
            and (
                not arguments.get("expected_value")
                or _normalize_path(item.get("value")) == _normalize_path(arguments.get("expected_value"))
            )
        )
    if category == "scheduled_tasks":
        return (
            _normalize_text(item.get("name")) == _normalize_text(arguments.get("task_name"))
            and (
                not arguments.get("task_path")
                or _normalize_path(item.get("path")) == _normalize_path(arguments.get("task_path"))
            )
        )
    if category == "services":
        return _normalize_text(item.get("name")) == _normalize_text(arguments.get("service_name"))
    return False


def _source_local_port(case: CaseFile) -> int:
    victim = _normalize_ip(case.source_alert.get("victim_ip"))
    remote = _normalize_ip(case.source_alert.get("remote_ip"))
    for event in reversed(case.source_events):
        src = _normalize_ip(event.get("src_ip"))
        dest = _normalize_ip(event.get("dest_ip"))
        if src == victim and dest == remote:
            return _normalize_port(event.get("src_port"))
        if dest == victim and src == remote:
            return _normalize_port(event.get("dest_port"))
    return 0


def _source_event(case: CaseFile) -> dict[str, Any]:
    for event in reversed(case.source_events):
        if isinstance(event, dict):
            return event
    return {}


def _event_network_identity(case: CaseFile, *, network_mode: str) -> dict[str, Any]:
    event = _source_event(case)
    victim = _normalize_ip(case.source_alert.get("victim_ip"))
    remote = _normalize_ip(case.source_alert.get("remote_ip"))
    src = _normalize_ip(event.get("src_ip"))
    dest = _normalize_ip(event.get("dest_ip"))
    src_port = _normalize_port(event.get("src_port"))
    dest_port = _normalize_port(event.get("dest_port"))
    protocol = _normalize_protocol(event.get("proto") or case.source_alert.get("protocol"))
    if network_mode == "inbound_listener":
        local_port = dest_port if dest == victim else src_port if src == victim else 0
        remote_port = src_port if src == remote else dest_port if dest == remote else 0
        direction = "remote_to_victim"
    else:
        local_port = src_port if src == victim else dest_port if dest == victim else 0
        remote_port = dest_port if dest == remote else src_port if src == remote else 0
        direction = "victim_to_remote"
    alert = event.get("alert") if isinstance(event.get("alert"), dict) else {}
    return {
        "protocol": protocol,
        "local_address": victim,
        "local_port": local_port,
        "remote_address": remote,
        "remote_port": remote_port,
        "direction": direction,
        "signature_id": str(alert.get("signature_id") or event.get("signature_id") or ""),
    }


def _normalize_network_identity(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocol": _normalize_protocol(value.get("protocol")),
        "local_address": _normalize_ip(value.get("local_address") or value.get("local_ip")),
        "local_port": _normalize_port(value.get("local_port")),
        "remote_address": _normalize_ip(value.get("remote_address") or value.get("remote_ip")),
        "remote_port": _normalize_port(value.get("remote_port")),
        "direction": _normalize_text(value.get("direction")),
        "signature_id": str(value.get("signature_id") or "").strip(),
    }


def _network_identity_differences(
    expected: dict[str, Any], observed: dict[str, Any]
) -> list[str]:
    differences: list[str] = []
    for field in (
        "protocol",
        "local_address",
        "local_port",
        "remote_address",
        "remote_port",
        "direction",
        "signature_id",
    ):
        expected_value = expected.get(field)
        if expected_value not in (None, "", 0) and expected_value != observed.get(field):
            differences.append(f"network_identity.{field}")
    return differences


def _source_flow_id(case: CaseFile) -> str:
    for event in reversed(case.source_events):
        if event.get("flow_id") not in (None, ""):
            return str(event["flow_id"])
    return ""


def _source_event_sha256(case: CaseFile) -> str:
    for artifact in reversed(case.source_artifacts):
        value = _normalize_sha256(artifact.get("event_sha256"))
        if value:
            return value
    return ""


def _normalize_path(value: Any) -> str:
    text = str(value or "").strip().strip('"')
    if not text:
        return ""
    return ntpath.normcase(ntpath.normpath(text.replace("/", "\\")))


def _normalize_sha256(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if _SHA256_RE.fullmatch(text) else ""


def _normalize_creation_time(value: Any) -> str:
    return _shared_normalize_creation_time(value)


def _parse_utc_datetime(value: Any) -> datetime | None:
    return _shared_parse_utc_datetime(value)


# Windows Win32_Process.CreationDate, converted via ToUniversalTime().ToString("o"),
# can return sub-second values that jitter by a few tens of milliseconds between two
# reads of the SAME process (ManagementDateTimeConverter / DST rounding).  A strict
# string compare of the frozen vs. gate-time creation stamp therefore raised a false
# target_drift even though PID, path and hash all matched.  Treat two creation times
# as the same instant when they parse to timestamps within this tolerance; fall back
# to an exact normalized-string compare when either value cannot be parsed.
_CREATION_TIME_TOLERANCE_SECONDS = CREATION_TIME_TOLERANCE_SECONDS


def _creation_times_match(left: Any, right: Any) -> bool:
    return _shared_creation_times_match(left, right)


def _field_values_match(field_name: str, left: Any, right: Any) -> bool:
    if field_name == "process.creation_time_utc":
        return _creation_times_match(left, right)
    if field_name in ("process.canonical_path", "file.canonical_path"):
        return _normalize_path(left) == _normalize_path(right)
    return left == right


def _normalize_ip(value: Any) -> str:
    return str(value or "").strip().lower()


def _normalize_protocol(value: Any) -> str:
    text = str(value or "").strip().lower()
    return "tcp" if text in {"tcp", "http", "https", "tls"} else text


def _normalize_port(value: Any) -> int:
    try:
        port = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return port if 1 <= port <= 65535 else 0


def _as_pid(value: Any) -> int:
    try:
        pid = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return pid if pid > 0 else 0


def _normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()
