from __future__ import annotations

"""Evidence-bound Bench v4 transaction artifacts.

This module is intentionally independent from the live controller.  It only
consumes already-frozen CALDERA links, target identity, host observations and
the selected Suricata source event.  In particular, no C2Trace investigation
output is accepted by the Ground Truth materializer.
"""

import base64
from copy import deepcopy
import hashlib
import json
import ntpath
import re
from typing import Any, Mapping, Sequence

from c2trace.bench_v3.caldera_client import link_ability_id
from c2trace.time_identity import creation_times_match, parse_utc_datetime
from c2trace.target_safety import (
    PROTECTED_PROCESSES_SCHEMA_V2,
    TARGET_LOCK_SCHEMA_V2,
)

from .runtime import BenchV4RuntimeError, RuntimeCase, RuntimeValues, render_runtime_value


_FILL_RE = re.compile(r"FILL_[A-Z0-9_]+")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class TransactionError(BenchV4RuntimeError):
    """A frozen v4 transaction input is incomplete, ambiguous or drifted."""


def _facts(values: RuntimeValues) -> dict[str, Any]:
    return {
        "run_id": values.run_id,
        "victim_ip": values.victim_ip,
        "kali_ip": values.kali_ip,
        "webshell_port": values.webshell_port or "",
        # APPDATA is a host-resolved runtime value carried separately from the
        # target-profile runtime_facts.  Include it explicitly so the legacy
        # %APPDATA% ground-truth trace notation is rendered by
        # render_runtime_value.  An empty value is left unresolved and therefore
        # still fails closed.
        "c2trace.appdata": values.appdata,
        **values.facts,
    }


def _normalise_path(value: Any) -> str:
    text = str(value or "").strip().strip('"')
    return ntpath.normcase(ntpath.normpath(text)) if text else ""


def _normalise_time(value: Any) -> str:
    if not str(value or "").strip():
        return ""
    parsed = parse_utc_datetime(value)
    if parsed is None:
        raise TransactionError(f"invalid identity timestamp: {value}")
    return parsed.isoformat()


def _sha256(value: Any, *, label: str) -> str:
    digest = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(digest):
        raise TransactionError(f"{label} requires an exact SHA-256")
    return digest


def _operation_id(operation: Mapping[str, Any], role: str) -> str:
    identifier = str(operation.get("id") or operation.get("operation_id") or "").strip()
    if not identifier:
        raise TransactionError(f"{role} operation has no ID")
    return identifier


def _link_id(link: Mapping[str, Any]) -> str:
    return str(link.get("id") or link.get("link_id") or "").strip()


def _link_succeeded(link: Mapping[str, Any]) -> bool:
    value = link.get("status")
    if isinstance(value, bool) or value is None:
        return False
    try:
        return int(value) == 0
    except (TypeError, ValueError):
        return False


def _trace_observations(evidence: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    observations: dict[str, dict[str, Any]] = {}
    captures = evidence.get("captures")
    if not isinstance(captures, list):
        raise TransactionError("frozen evidence has no captures list")
    for capture in captures:
        if not isinstance(capture, Mapping):
            continue
        result = capture.get("result")
        if not isinstance(result, Mapping):
            continue
        rows = result.get("trace_observations")
        if not isinstance(rows, Mapping):
            continue
        for trace_id, raw in rows.items():
            if not isinstance(raw, Mapping):
                raise TransactionError(f"trace observation {trace_id} is malformed")
            key = str(trace_id)
            if key in observations and observations[key] != dict(raw):
                raise TransactionError(f"trace observation {key} is ambiguous")
            observations[key] = dict(raw)
    return observations


def _suricata_capture(evidence: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]] | None:
    captures = evidence.get("captures")
    if not isinstance(captures, list):
        return None
    found: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for capture in captures:
        if not isinstance(capture, Mapping) or capture.get("collector") != "suricata":
            continue
        result = capture.get("result")
        if not isinstance(result, Mapping):
            continue
        event = result.get("source_event")
        artifact = result.get("source_artifact")
        if isinstance(event, Mapping) and isinstance(artifact, Mapping):
            found.append((dict(event), dict(artifact)))
    if len(found) > 1 and any(row != found[0] for row in found[1:]):
        raise TransactionError("frozen evidence contains conflicting Suricata selections")
    return found[0] if found else None


def _data(observation: Mapping[str, Any]) -> dict[str, Any]:
    data = observation.get("data")
    if not isinstance(data, Mapping):
        raise TransactionError("host observation has no probe data")
    return dict(data)


def _matching_file(observation: Mapping[str, Any], expected_path: str) -> dict[str, Any]:
    data = _data(observation)
    candidates: list[Mapping[str, Any]] = []
    if isinstance(data.get("file"), Mapping):
        candidates.append(data["file"])
    if isinstance(data.get("files"), list):
        candidates.extend(row for row in data["files"] if isinstance(row, Mapping))
    matches = [
        dict(row)
        for row in candidates
        if _normalise_path(row.get("path") or row.get("file_path"))
        == _normalise_path(expected_path)
    ]
    if len(matches) != 1 or matches[0].get("exists") is not True:
        raise TransactionError(f"frozen file evidence is not unique/present: {expected_path}")
    return matches[0]


def _matching_process(
    observation: Mapping[str, Any],
    *,
    pid: int,
    expected_path: str,
    match_command_line: bool = False,
) -> dict[str, Any]:
    rows = _data(observation).get("processes")
    if not isinstance(rows, list):
        raise TransactionError("frozen process evidence has no processes list")
    if match_command_line:
        matches = [
            dict(row)
            for row in rows
            if isinstance(row, Mapping)
            and int(row.get("pid") or row.get("process_id") or 0) == pid
            and _normalise_path(expected_path).casefold()
            in str(row.get("command_line") or "").casefold()
        ]
    else:
        matches = [
            dict(row)
            for row in rows
            if isinstance(row, Mapping)
            and int(row.get("pid") or row.get("process_id") or 0) == pid
            and _normalise_path(row.get("path") or row.get("executable_path"))
            == _normalise_path(expected_path)
        ]
    if len(matches) != 1:
        raise TransactionError("frozen process evidence does not uniquely match the target")
    return matches[0]


def _persistence_rows(observation: Mapping[str, Any], trace_type: str) -> list[dict[str, Any]]:
    data = _data(observation)
    keys = {
        "registry_value": ("registry_values", "registry_run_keys"),
        "registry_run_key": ("registry_values", "registry_run_keys"),
        "scheduled_task": ("targeted_tasks", "scheduled_tasks"),
        "service": ("targeted_services", "services"),
    }[trace_type]
    rows: list[dict[str, Any]] = []
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            rows.extend(dict(row) for row in value if isinstance(row, Mapping))
    return rows


def _validate_persistence_observation(
    trace_type: str, observation: Mapping[str, Any], expected: Mapping[str, Any]
) -> None:
    rows = _persistence_rows(observation, trace_type)
    if trace_type in {"registry_value", "registry_run_key"}:
        def matches(row: Mapping[str, Any]) -> bool:
            hive = str(row.get("hive") or "").casefold()
            path = str(row.get("key_path") or row.get("path") or "").replace("/", "\\").casefold()
            name = str(row.get("value_name") or row.get("name") or "").casefold()
            return (
                hive == str(expected.get("hive") or "").casefold()
                and path.endswith(str(expected.get("key_path") or "").replace("/", "\\").casefold())
                and name == str(expected.get("value_name") or "").casefold()
            )
    elif trace_type == "scheduled_task":
        def matches(row: Mapping[str, Any]) -> bool:
            return str(row.get("name") or row.get("task_name") or "").casefold() == str(
                expected.get("task_name") or expected.get("name") or ""
            ).casefold()
    else:
        def matches(row: Mapping[str, Any]) -> bool:
            return str(row.get("name") or row.get("service_name") or "").casefold() == str(
                expected.get("service_name") or expected.get("name") or ""
            ).casefold()
    matches_rows = [row for row in rows if matches(row)]
    if len(matches_rows) != 1:
        raise TransactionError(f"frozen {trace_type} evidence is not unique/present")
    if trace_type in {"registry_value", "registry_run_key"} and "value_data" in expected:
        actual = str(matches_rows[0].get("value_data") or matches_rows[0].get("value") or "")
        if actual != str(expected["value_data"]):
            raise TransactionError(f"frozen {trace_type} value data drifted")


def _target_parts(target_identity: Mapping[str, Any]) -> tuple[int, str, str]:
    process = (
        target_identity.get("process")
        if isinstance(target_identity.get("process"), Mapping)
        else target_identity
    )
    pid = int(process.get("pid") or 0)
    created = _normalise_time(
        process.get("creation_time_utc")
        or process.get("creation_time")
        or process.get("created_at")
        or process.get("created")
    )
    path = str(
        process.get("path")
        or process.get("location")
        or process.get("exe_name")
        or process.get("canonical_path")
        or ""
    )
    if not pid or not created or not path:
        raise TransactionError("target identity requires PID, creation time and path")
    return pid, created, path


def _fill_trace_expected(
    trace: Mapping[str, Any],
    expected: dict[str, Any],
    observation: Mapping[str, Any],
    *,
    target_identity: Mapping[str, Any],
    source_event: Mapping[str, Any],
    values: RuntimeValues,
    match_command_line: bool = False,
) -> dict[str, Any]:
    trace_type = str(trace.get("trace_type") or "")
    pid, created, target_path = _target_parts(target_identity)
    result = deepcopy(expected)
    if trace_type == "file":
        path = str(result.get("path") or "")
        file_row = _matching_file(observation, path)
        if result.get("sha256") == "FILL_FROM_BEFORE_RESPONSE":
            result["sha256"] = _sha256(file_row.get("sha256"), label=f"{trace['trace_id']} file")
    elif trace_type == "process":
        is_secondary = result.get("pid") == "FILL_FROM_TARGET_SECONDARY"
        effective_pid = int(target_identity.get("secondary_pid") or 0) if is_secondary else pid
        effective_created = (
            _normalise_time(target_identity.get("secondary_creation_time_utc"))
            if is_secondary
            else created
        )
        raw_path = str(result.get("path") or "")
        path = target_path if raw_path == "FILL_FROM_EXECUTABLE_PATH" else (raw_path or target_path)
        process_row = _matching_process(
            observation, pid=effective_pid, expected_path=path,
            match_command_line=match_command_line,
        )
        if result.get("path") == "FILL_FROM_EXECUTABLE_PATH":
            result["path"] = str(
                target_identity.get("executable_path")
                or process_row.get("path")
                or process_row.get("executable_path")
                or path
            )
        elif match_command_line:
            result["path"] = str(
                process_row.get("path")
                or process_row.get("executable_path")
                or result.get("path")
                or ""
            )
        if result.get("pid") in ("FILL_FROM_TARGET", "FILL_FROM_TARGET_SECONDARY"):
            result["pid"] = effective_pid
        if result.get("creation_time") == "FILL_FROM_BEFORE_RESPONSE":
            observed_created = _normalise_time(
                process_row.get("creation_time_utc")
                or process_row.get("creation_time")
                or process_row.get("created_at")
            )
            if not creation_times_match(observed_created, effective_created):
                raise TransactionError("target creation time differs from frozen process evidence")
            result["creation_time"] = effective_created
    elif trace_type == "network_connection":
        is_secondary_net = result.get("pid") == "FILL_FROM_TARGET_SECONDARY"
        if result.get("src_port") == "FILL_FROM_SURICATA":
            # The alert identifies the primary connection only.  A secondary
            # implant can use a different ephemeral source port, so its port
            # must come from the frozen host observation rather than the
            # Suricata alert.  Existing templates use the explicit
            # FILL_FROM_BEFORE_RESPONSE marker for this case.
            if is_secondary_net:
                result["src_port"] = "FILL_FROM_BEFORE_RESPONSE"
            else:
                result["src_port"] = int(source_event.get("src_port") or 0)
        if result.get("dst_port") == "FILL_FROM_SURICATA":
            result["dst_port"] = int(source_event.get("dest_port") or 0)
        if result.get("pid") == "FILL_FROM_TARGET":
            result["pid"] = pid
        elif result.get("pid") == "FILL_FROM_TARGET_SECONDARY":
            result["pid"] = int(target_identity.get("secondary_pid") or 0)
        rows = _data(observation).get("connections")
        if not isinstance(rows, list):
            raise TransactionError("frozen host network evidence has no connections list")
        match_pid = int(result.get("pid") or pid)
        if result.get("src_port") == "FILL_FROM_BEFORE_RESPONSE":
            candidates = []
            for row in rows:
                if not isinstance(row, Mapping) or int(row.get("pid") or 0) != match_pid:
                    continue
                remote_address = str(
                    row.get("remote_address") or row.get("destination_ip") or ""
                )
                remote_port = int(row.get("remote_port") or row.get("destination_port") or 0)
                if remote_address == str(source_event.get("dest_ip") or "") and remote_port == int(source_event.get("dest_port") or 0):
                    candidates.append(row)
            if len(candidates) != 1:
                raise TransactionError("frozen host network evidence does not uniquely match secondary connection")
            result["src_port"] = int(
                candidates[0].get("local_port") or candidates[0].get("source_port") or 0
            )
        expected_tuple = (
            str(result.get("src_ip") or ""),
            int(result.get("src_port") or 0),
            str(result.get("dst_ip") or ""),
            int(result.get("dst_port") or 0),
        )
        observed_tuple = (
            str(source_event.get("src_ip") or ""),
            int(source_event.get("src_port") or 0),
            str(source_event.get("dest_ip") or ""),
            int(source_event.get("dest_port") or 0),
        )
        if is_secondary_net:
            same_remote = expected_tuple[2:] == observed_tuple[2:]
            if (
                not same_remote
                or expected_tuple[0] != observed_tuple[0]
                or not all((*expected_tuple[:2], *expected_tuple[2:]))
            ):
                raise TransactionError("Ground Truth secondary network tuple differs from frozen evidence")
        elif expected_tuple != observed_tuple or not all((*expected_tuple[:2], *expected_tuple[2:])):
            raise TransactionError("Ground Truth network tuple differs from frozen source event")
        protocol = str(source_event.get("proto") or "tcp").lower()
        if protocol not in {"tcp", "tcp6"} or str(result.get("protocol") or "").lower() != "tcp":
            raise TransactionError("Ground Truth source event is not the expected TCP flow")
        # The host observation must also contain this exact target PID/flow.
        outbound = observed_tuple[0] == values.victim_ip
        is_secondary_net = is_secondary_net or (
            match_pid != pid and match_pid == int(target_identity.get("secondary_pid") or 0)
        )
        matched = []
        for row in rows:
            if not isinstance(row, Mapping) or int(row.get("pid") or 0) != match_pid:
                continue
            local_address = str(
                row.get("local_address") or row.get("source_ip") or ""
            )
            local_port = int(row.get("local_port") or row.get("source_port") or 0)
            remote_address = str(
                row.get("remote_address") or row.get("destination_ip") or ""
            )
            remote_port = int(row.get("remote_port") or row.get("destination_port") or 0)
            if is_secondary_net:
                exact = (
                    local_address == expected_tuple[0]
                    and local_port == expected_tuple[1]
                    and remote_address == observed_tuple[2]
                    and remote_port == observed_tuple[3]
                )
            elif outbound:
                exact = (
                    local_address == observed_tuple[0]
                    and local_port == observed_tuple[1]
                    and remote_address == observed_tuple[2]
                    and remote_port == observed_tuple[3]
                )
            else:
                exact = (
                    local_address in {observed_tuple[2], "0.0.0.0", "::"}
                    and local_port == observed_tuple[3]
                )
            if exact:
                matched.append(row)
        if len(matched) != 1:
            raise TransactionError("frozen host network evidence does not uniquely match source flow")
    elif trace_type in {"registry_value", "registry_run_key", "scheduled_task", "service"}:
        if result.get("value_data") == "FILL_BASE64_FROM_RUN_ID":
            source_value = str(values.facts.get("c2trace.target_name") or values.run_id)
            result["value_data"] = base64.b64encode(source_value.encode("utf-8")).decode("ascii")
        _validate_persistence_observation(trace_type, observation, result)
    elif trace_type in {"process_parent_edge", "powershell_history", "dns_cache"}:
        # These selectors carry no currently defined FILL token, but their
        # presence is still required to prevent post-hoc Ground Truth.
        _data(observation)
    else:
        raise TransactionError(f"unsupported Ground Truth trace type: {trace_type}")
    return result


def _replace_target_fills(
    value: Any,
    *,
    pid: int,
    secondary_pid: int | None = None,
    executable_path: str | None = None,
) -> Any:
    if isinstance(value, str):
        if value == "FILL_FROM_TARGET":
            return pid
        if value == "FILL_FROM_TARGET_SECONDARY" and secondary_pid is not None:
            return secondary_pid
        if value == "FILL_FROM_EXECUTABLE_PATH" and executable_path is not None:
            return executable_path
        return value
    if isinstance(value, list):
        return [
            _replace_target_fills(
                row, pid=pid, secondary_pid=secondary_pid, executable_path=executable_path
            )
            for row in value
        ]
    if isinstance(value, dict):
        return {
            key: _replace_target_fills(
                row, pid=pid, secondary_pid=secondary_pid, executable_path=executable_path
            )
            for key, row in value.items()
        }
    return value


def _assert_no_fill(value: Any, path: str = "$") -> None:
    if isinstance(value, str) and _FILL_RE.search(value):
        raise TransactionError(f"unresolved Ground Truth placeholder at {path}: {value}")
    if isinstance(value, list):
        for index, row in enumerate(value):
            _assert_no_fill(row, f"{path}[{index}]")
    elif isinstance(value, Mapping):
        for key, row in value.items():
            _assert_no_fill(row, f"{path}.{key}")


def materialize_ground_truth(
    runtime: RuntimeCase,
    values: RuntimeValues,
    *,
    bootstrap_operation: Mapping[str, Any],
    bootstrap_links: Sequence[Mapping[str, Any]],
    scenario_operation: Mapping[str, Any],
    scenario_links: Sequence[Mapping[str, Any]],
    target_identity: Mapping[str, Any],
    before_response_evidence: Mapping[str, Any],
    source_event: Mapping[str, Any],
    source_artifact: Mapping[str, Any],
) -> dict[str, Any]:
    """Materialize Ground Truth solely from pre-registered/frozen inputs."""

    embedded = _suricata_capture(before_response_evidence)
    if embedded is not None and embedded != (dict(source_event), dict(source_artifact)):
        raise TransactionError("explicit source event differs from frozen evidence selection")
    observations = _trace_observations(before_response_evidence)
    result = render_runtime_value(deepcopy(runtime.ground_truth), _facts(values))
    if not isinstance(result, dict):  # pragma: no cover - RuntimeCase contract
        raise TransactionError("Ground Truth template did not render to an object")
    pid, _, _ = _target_parts(target_identity)
    target_type = str(runtime.target.get("target_type") or "")
    operations = {
        "bootstrap": (_operation_id(bootstrap_operation, "bootstrap"), bootstrap_links),
        "scenario": (_operation_id(scenario_operation, "scenario"), scenario_links),
    }
    for ability in result.get("ability_instances", []):
        if not isinstance(ability, dict):
            raise TransactionError("Ground Truth ability instance is malformed")
        role = str(ability.get("operation_role") or "")
        if role not in operations:
            raise TransactionError(f"unsupported Ground Truth operation role: {role}")
        operation_id, links = operations[role]
        matches = [
            dict(link)
            for link in links
            if isinstance(link, Mapping)
            and link_ability_id(link) == str(ability.get("ability_id") or "")
        ]
        if len(matches) != 1 or not _link_id(matches[0]):
            raise TransactionError(
                f"{ability.get('instance_key')} has {len(matches)} unambiguous CALDERA links"
            )
        ability["operation_id"] = operation_id
        ability["link_id"] = _link_id(matches[0])
        ability["executed"] = _link_succeeded(matches[0])
        if ability.get("mandatory") is True and ability["executed"] is not True:
            raise TransactionError(f"mandatory ability failed: {ability.get('instance_key')}")
        for trace in ability.get("trace_facts", []):
            if not isinstance(trace, dict):
                raise TransactionError("Ground Truth trace fact is malformed")
            trace_id = str(trace.get("trace_id") or "")
            observation = observations.get(trace_id)
            if observation is None:
                raise TransactionError(f"frozen before-response evidence lacks {trace_id}")
            expected = trace.get("expected_value")
            if not isinstance(expected, dict):
                raise TransactionError(f"Ground Truth trace {trace_id} has no expected selector")
            trace["expected_value"] = _fill_trace_expected(
                trace,
                expected,
                observation,
                target_identity=target_identity,
                source_event=source_event,
                values=values,
                match_command_line=(
                    target_type in (
                        "carbanak_cscript_https_rat_outbound",
                        "emotet_dll_http_outbound",
                        "plugx_http_outbound",
                    )
                ),
            )
    secondary_pid = target_identity.get("secondary_pid")
    if secondary_pid is not None:
        secondary_pid = int(secondary_pid)
    executable_path = str(target_identity.get("executable_path") or "")
    result = _replace_target_fills(
        result,
        pid=pid,
        secondary_pid=secondary_pid,
        executable_path=executable_path or None,
    )
    result.update(
        {
            "status": "materialized",
            "run_id": values.run_id,
            "source_event": dict(source_event),
            "source_artifact": dict(source_artifact),
            "materialization_policy": {
                "ground_truth_template": "frozen_case_contract",
                "caldera_binding": "exact_operation_role_ability_link",
                "trace_values": "frozen_pre_response_evidence",
                "c2trace_output_read": False,
            },
        }
    )
    _assert_no_fill(result)
    return result


def _find_target_file(
    evidence: Mapping[str, Any], *, target_path: str
) -> dict[str, Any]:
    observations = _trace_observations(evidence)
    preferred = observations.get("target.file")
    if preferred is not None:
        return _matching_file(preferred, target_path)
    matches: list[dict[str, Any]] = []
    for observation in observations.values():
        try:
            matches.append(_matching_file(observation, target_path))
        except TransactionError:
            continue
    unique = {str(row.get("sha256") or "").lower(): row for row in matches}
    if len(unique) != 1:
        raise TransactionError("target file is absent or ambiguous in frozen evidence")
    return next(iter(unique.values()))


def _agent_field(identity: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if identity.get(name) not in (None, ""):
            return identity[name]
    return ""


def build_expected_target_v2(
    runtime: RuntimeCase,
    values: RuntimeValues,
    *,
    target_identity: Mapping[str, Any],
    before_response_evidence: Mapping[str, Any],
    source_event: Mapping[str, Any],
    source_artifact: Mapping[str, Any],
    source_not_before_utc: str,
) -> dict[str, Any]:
    """Build the safety-only target input from the exact frozen transaction."""

    pid, created, path = _target_parts(target_identity)
    if _normalise_path(path) != _normalise_path(values.target_path):
        raise TransactionError("target identity path differs from frozen runtime path")
    target_file = _find_target_file(before_response_evidence, target_path=values.target_path)
    digest = _sha256(target_file.get("sha256"), label="target file")
    event = dict(source_event)
    protocol = str(event.get("proto") or "tcp").lower()
    if protocol not in {"tcp", "tcp6"}:
        raise TransactionError("expected target requires a TCP source event")
    src_ip = str(event.get("src_ip") or "")
    dst_ip = str(event.get("dest_ip") or "")
    src_port = int(event.get("src_port") or 0)
    dst_port = int(event.get("dest_port") or 0)
    if not src_ip or not dst_ip or not src_port or not dst_port:
        raise TransactionError("expected target source event lacks a complete five-tuple")
    target = runtime.target
    mode = str(target.get("network_mode") or "")
    if mode == "outbound_active_flow":
        if src_ip != values.victim_ip or dst_ip != values.kali_ip:
            raise TransactionError("outbound target source event direction drifted")
        local_ip, local_port, remote_ip, remote_port = src_ip, src_port, dst_ip, dst_port
        direction = "victim_to_remote"
    elif mode == "inbound_listener":
        if src_ip != values.kali_ip or dst_ip != values.victim_ip:
            raise TransactionError("inbound target source event direction drifted")
        local_ip, local_port, remote_ip, remote_port = dst_ip, dst_port, src_ip, src_port
        direction = "remote_to_victim"
    else:
        raise TransactionError(f"unsupported target network mode: {mode}")
    expected = {
        "target_type": str(target.get("target_type") or "other"),
        "network_mode": mode,
        "paw": str(_agent_field(target_identity, "paw", "id") or ""),
        "pid": pid,
        "creation_time_utc": created,
        "path": values.target_path,
        "sha256": digest,
        "payload_path": values.target_path,
        "payload_sha256": digest,
        "group": str(_agent_field(target_identity, "group") or values.target_group),
        "host": str(_agent_field(target_identity, "host", "hostname") or ""),
        "contact": str(
            _agent_field(target_identity, "contact")
            or target.get("contact", {}).get("protocol")
            or ""
        ).lower(),
        "network_identity": {
            "protocol": "tcp",
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "direction": direction,
            "signature_id": int(
                event.get("signature_id")
                or target.get("contact", {}).get("suricata_signature_id")
                or 0
            ),
        },
        "source_not_before_utc": _normalise_time(source_not_before_utc),
        "source_binding": {
            "flow_id": str(event.get("flow_id") or ""),
            "event_sha256": _sha256(
                source_artifact.get("event_sha256"), label="Suricata source event"
            ),
            "file_sha256": _sha256(
                source_artifact.get("file_sha256"), label="Suricata source file"
            ),
            **{
                key: source_artifact[key]
                for key in ("path", "line_number", "record_index", "raw_record_sha256")
                if key in source_artifact
            },
        },
        "response_policy": {
            "allow_process_termination": True,
            "allow_file_removal": True,
        },
    }
    secondary_pid = int(target_identity.get("secondary_pid") or 0)
    executable_sha256 = str(target_identity.get("executable_sha256") or "").strip().lower()
    if executable_sha256 and _SHA256_RE.fullmatch(executable_sha256):
        expected["executable_sha256"] = executable_sha256
        expected["executable_path"] = str(target_identity.get("executable_path") or "")
    if secondary_pid > 0:
        expected["secondary_pid"] = secondary_pid
        secondary_created = _normalise_time(target_identity.get("secondary_creation_time_utc"))
        if secondary_created:
            expected["secondary_creation_time_utc"] = secondary_created
    if target.get("agent_backed") is True:
        missing = [key for key in ("paw", "group", "host", "contact") if not expected[key]]
        if missing:
            raise TransactionError(f"agent-backed expected target lacks: {', '.join(missing)}")
    elif not expected["host"]:
        raise TransactionError("listener expected target lacks its victim host")
    if expected["target_type"] == "windows_webshell_http_listener":
        expected["payload_artifacts"] = [
            {
                "path": values.target_path,
                "sha256": digest,
                "artifact_role": "webshell_payload",
            }
        ]
    return expected


def build_protected_processes_v2(
    runtime: RuntimeCase,
    values: RuntimeValues,
    *,
    control_identity: Mapping[str, Any],
    target_identity: Mapping[str, Any],
    before_response_evidence: Mapping[str, Any],
    source_event: Mapping[str, Any],
    source_artifact: Mapping[str, Any],
    source_not_before_utc: str,
) -> dict[str, Any]:
    """Build a complete protected-processes.v2 manifest and target profile."""

    control_pid, control_created, control_path = _target_parts(control_identity)
    process = {
        "label": "control-sandcat",
        "paw": str(_agent_field(control_identity, "paw", "id") or ""),
        "pid": control_pid,
        "creation_time_utc": control_created,
        "path": control_path,
        "canonical_path": _normalise_path(control_path),
        "sha256": _sha256(control_identity.get("sha256"), label="control Sandcat"),
        "group": str(_agent_field(control_identity, "group") or ""),
        "host": str(_agent_field(control_identity, "host", "hostname") or ""),
        "contact": str(_agent_field(control_identity, "contact") or "").lower(),
    }
    missing = [key for key in ("paw", "group", "host", "contact") if not process[key]]
    if missing:
        raise TransactionError(f"protected control identity lacks: {', '.join(missing)}")
    expected = build_expected_target_v2(
        runtime,
        values,
        target_identity=target_identity,
        before_response_evidence=before_response_evidence,
        source_event=source_event,
        source_artifact=source_artifact,
        source_not_before_utc=source_not_before_utc,
    )
    if (
        process["pid"] == expected["pid"]
        and creation_times_match(
            process["creation_time_utc"], expected["creation_time_utc"]
        )
    ) or _normalise_path(process["path"]) == _normalise_path(expected["path"]):
        raise TransactionError("target identity collides with the protected control Sandcat")
    return {
        "schema_version": PROTECTED_PROCESSES_SCHEMA_V2,
        "case_id": runtime.case_id,
        "run_id": values.run_id,
        "target_lock_schema_version": TARGET_LOCK_SCHEMA_V2,
        "processes": [process],
        "expected_target": expected,
    }


def build_protected_manifest_safe(
    protected_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a safe protected-process manifest WITHOUT any Ground Truth.

    This file is the ONLY protected-process input that C2Trace's run_case.py
    is allowed to read.  It contains only system-safety objects (control
    agent, driver agent, system critical processes) and metadata that does
    not reveal the tested C2 target's identity.
    """
    processes = [
        dict(row)
        for row in protected_manifest.get("processes", [])
        if isinstance(row, Mapping)
    ]
    return {
        "schema_version": protected_manifest.get("schema_version", ""),
        "case_id": protected_manifest.get("case_id", ""),
        "run_id": protected_manifest.get("run_id", ""),
        "target_lock_schema_version": protected_manifest.get("target_lock_schema_version", ""),
        "processes": processes,
    }


def build_cleanup_ground_truth(
    protected_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a cleanup-only Ground Truth file.

    This file contains the real target identity (PID, path, SHA-256, network
    identity, source_binding) and is ONLY used by the experiment controller's
    cleanup logic AFTER C2Trace has finished execution and scoring.  It must
    NEVER be passed to C2Trace's run_case.py, TargetIdentityValidator, or any
    C2Trace agent.
    """
    return {
        "schema_version": "c2trace.bench.cleanup_ground_truth.v1",
        "case_id": protected_manifest.get("case_id", ""),
        "run_id": protected_manifest.get("run_id", ""),
        "expected_target": dict(protected_manifest.get("expected_target") or {}),
    }


def _stable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _stable(row) for key, row in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, list):
        rows = [_stable(row) for row in value]
        return sorted(rows, key=lambda row: json.dumps(row, sort_keys=True, default=str))
    return value


def _semantic_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    observations = _trace_observations(snapshot)
    return {
        key: _stable(_data(row))
        for key, row in sorted(observations.items())
    }


def snapshot_unchanged(
    before_response: Mapping[str, Any], after_dryrun: Mapping[str, Any]
) -> dict[str, Any]:
    """Compare only read-only host semantics, not capture metadata."""

    before = _semantic_snapshot(before_response)
    after = _semantic_snapshot(after_dryrun)
    keys = sorted(set(before) | set(after))
    changed = [key for key in keys if before.get(key) != after.get(key)]
    encode = lambda value: hashlib.sha256(  # noqa: E731 - compact local canonicalizer
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": "c2trace.bench.snapshot_comparison.v4",
        "unchanged": not changed,
        "changed_keys": changed,
        "before_sha256": encode(before),
        "after_sha256": encode(after),
    }


def evaluate_baseline_clean(
    runtime: RuntimeCase, baseline: Mapping[str, Any]
) -> dict[str, Any]:
    """Require every pre-registered static selector to be absent at baseline."""

    observations = _trace_observations(baseline)
    if "target.network" in observations or "target.process" in observations:
        raise TransactionError(
            "baseline must not query a not-yet-created target process/network"
        )
    trace_types = {
        str(trace.get("trace_id") or ""): str(trace.get("trace_type") or "")
        for ability in runtime.ground_truth.get("ability_instances", [])
        if isinstance(ability, Mapping)
        for trace in ability.get("trace_facts", [])
        if isinstance(trace, Mapping)
    }
    residuals: list[str] = []
    for trace_id, observation in observations.items():
        if trace_id == "target.file":
            absent = _observation_absent(observation, "file")
        elif trace_types.get(trace_id) == "file":
            absent = _observation_absent(observation, "file")
        elif trace_types.get(trace_id) in {
            "registry_value",
            "registry_run_key",
            "scheduled_task",
            "service",
        }:
            absent = _targeted_persistence_absent(
                observation, trace_types[trace_id]
            )
        else:
            continue
        if not absent:
            residuals.append(trace_id)
    required = {
        "target.file",
        *{
            trace_id
            for trace_id, trace_type in trace_types.items()
            if trace_type
            in {"file", "registry_value", "registry_run_key", "scheduled_task", "service"}
        },
    }
    missing = sorted(required - set(observations))
    return {
        "schema_version": "c2trace.bench.baseline_validation.v4",
        "case_id": runtime.case_id,
        "clean": not residuals and not missing,
        "residual_trace_ids": sorted(residuals),
        "missing_trace_ids": missing,
        "network_queried": False,
    }


def _observation_absent(observation: Mapping[str, Any], kind: str) -> bool:
    data = _data(observation)
    if kind == "network":
        return isinstance(data.get("connections"), list) and not data["connections"]
    if kind == "process":
        return isinstance(data.get("processes"), list) and not data["processes"]
    if kind == "file":
        file_row = data.get("file")
        return isinstance(file_row, Mapping) and file_row.get("exists") is False
    if kind == "persistence":
        keys = (
            "registry_values",
            "registry_run_keys",
            "targeted_tasks",
            "scheduled_tasks",
            "targeted_services",
            "services",
        )
        present_lists = [data[key] for key in keys if isinstance(data.get(key), list)]
        return bool(present_lists) and all(not rows for rows in present_lists)
    raise TransactionError(f"unsupported absence kind: {kind}")


def _targeted_persistence_absent(
    observation: Mapping[str, Any], trace_type: str
) -> bool:
    data = _data(observation)
    preferred = {
        "registry_value": "registry_values",
        "registry_run_key": "registry_values",
        "scheduled_task": "targeted_tasks",
        "service": "targeted_services",
    }[trace_type]
    rows = data.get(preferred)
    # A targeted check always returns its dedicated list.  Refuse to infer
    # absence from a broad inventory that may contain unrelated host state.
    return isinstance(rows, list) and not rows


def _same_identity(expected: Mapping[str, Any], observed: Mapping[str, Any]) -> bool:
    try:
        return (
            int(expected.get("pid") or 0) == int(observed.get("pid") or 0)
            and creation_times_match(
                expected.get("creation_time_utc") or expected.get("creation_time"),
                observed.get("creation_time_utc") or observed.get("creation_time"),
            )
            and _normalise_path(expected.get("path")) == _normalise_path(observed.get("path"))
            and str(expected.get("sha256") or "").lower()
            == str(observed.get("sha256") or "").lower()
            and str(expected.get("paw") or "") == str(observed.get("paw") or "")
        )
    except TransactionError:
        return False


def evaluate_post_response(
    runtime: RuntimeCase,
    after_execute: Mapping[str, Any],
    *,
    protected_manifest: Mapping[str, Any],
    observed_control: Mapping[str, Any] | None,
    expected_driver: Mapping[str, Any] | None = None,
    observed_driver: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate generic target absence and protected-agent survival."""

    observations = _trace_observations(after_execute)
    network = observations.get("target.network")
    process = observations.get("target.process")
    target_file = observations.get("target.file")
    response_persistence_types = {
        {
            "remove_registry": "registry",
            "remove_scheduled_task": "scheduled_task",
            "remove_service": "service",
        }[str(action.get("tool") or "")]
        for action in runtime.ground_truth.get("response_actions", [])
        if isinstance(action, Mapping)
        and str(action.get("tool") or "")
        in {"remove_registry", "remove_scheduled_task", "remove_service"}
        and action.get("required") is True
    }
    persistence = [
        (
            str(trace.get("trace_type") or ""),
            observations.get(str(trace.get("trace_id") or "")),
        )
        for ability in runtime.ground_truth.get("ability_instances", [])
        if isinstance(ability, Mapping)
        for trace in ability.get("trace_facts", [])
        if isinstance(trace, Mapping)
        and str(trace.get("trace_type") or "")
        in {"registry_value", "registry_run_key", "scheduled_task", "service"}
        and (
            (
                str(trace.get("trace_type") or "")
                in {"registry_value", "registry_run_key"}
                and "registry" in response_persistence_types
            )
            or str(trace.get("trace_type") or "") in response_persistence_types
        )
    ]
    persistence = [
        (trace_type, row)
        for trace_type, row in persistence
        if isinstance(row, Mapping)
    ]
    processes = protected_manifest.get("processes")
    if not isinstance(processes, list) or len(processes) != 1 or not isinstance(processes[0], Mapping):
        raise TransactionError("post-response evaluation requires one protected control identity")
    control_alive = (
        _same_identity(processes[0], observed_control)
        if isinstance(observed_control, Mapping)
        else False
    )
    driver_alive: bool | None = None
    if expected_driver is not None:
        driver_alive = (
            _same_identity(expected_driver, observed_driver)
            if isinstance(observed_driver, Mapping)
            else False
        )
    result = {
        "schema_version": "c2trace.bench.post_response_validation.v4",
        "case_id": runtime.case_id,
        "target_network_absent": bool(network and _observation_absent(network, "network")),
        "target_process_absent": bool(process and _observation_absent(process, "process")),
        "target_file_absent": bool(target_file and _observation_absent(target_file, "file")),
        "target_persistence_absent": all(
            _targeted_persistence_absent(row, trace_type)
            for trace_type, row in persistence
        ) if persistence else True,
        "control_sandcat_alive": control_alive,
        "driver_agent_alive": driver_alive,
        "wrong_target": not control_alive or driver_alive is False,
    }
    required = [
        "target_network_absent",
        "target_process_absent",
        "target_file_absent",
        "target_persistence_absent",
        "control_sandcat_alive",
    ]
    if expected_driver is not None:
        required.append("driver_agent_alive")
    result["passed"] = all(result[key] is True for key in required) and result["wrong_target"] is False
    return result
