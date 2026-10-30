from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Any, Mapping, Sequence

from .validation import REQUIRED_QUALIFICATION_CHECKS


WEBSHELL_SCENARIO_ABILITIES = frozenset(
    {
        "dc934e5a-3184-5b6f-8535-a78cc2adfac5",
        "87bd9d84-f8b7-5810-9a53-ce0a9cdb589d",
    }
)


def _parse_utc(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _observations(evidence: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for capture in evidence.get("captures") or []:
        if not isinstance(capture, Mapping):
            continue
        capture_result = (
            capture.get("result") if isinstance(capture.get("result"), Mapping) else {}
        )
        rows = capture_result.get("trace_observations")
        if isinstance(rows, Mapping):
            result.update(
                (str(key), dict(value))
                for key, value in rows.items()
                if isinstance(value, Mapping)
            )
    return result


def _data(observation: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if not isinstance(observation, Mapping):
        return {}
    return observation.get("data") if isinstance(observation.get("data"), Mapping) else {}


def _file_present(observation: Mapping[str, Any] | None) -> bool:
    row = _data(observation).get("file")
    return isinstance(row, Mapping) and row.get("exists") is True


def _scenario_ability_id(link: Mapping[str, Any]) -> str:
    ability = link.get("ability") if isinstance(link.get("ability"), Mapping) else {}
    return str(link.get("ability_id") or ability.get("ability_id") or "")


def _link_succeeded(link: Mapping[str, Any]) -> bool:
    status = link.get("status")
    return status in {0, "0", "success", "completed"}


def _target_present(
    observations: Mapping[str, Mapping[str, Any]],
    target: Mapping[str, Any],
) -> bool:
    pid = int(target.get("pid") or 0)
    path = str(target.get("path") or "").casefold()
    process_rows = _data(observations.get("target.process")).get("processes")
    network_rows = _data(observations.get("target.network")).get("connections")
    file_row = _data(observations.get("target.file")).get("file")
    process_ok = (
        isinstance(process_rows, list)
        and len(process_rows) == 1
        and isinstance(process_rows[0], Mapping)
        and int(process_rows[0].get("pid") or 0) == pid
        and str(process_rows[0].get("path") or "").casefold() == path
    )
    network_ok = (
        isinstance(network_rows, list)
        and len(network_rows) == 1
        and isinstance(network_rows[0], Mapping)
        and int(network_rows[0].get("pid") or 0) == pid
    )
    file_ok = (
        isinstance(file_row, Mapping)
        and file_row.get("exists") is True
        and str(file_row.get("path") or "").casefold() == path
        and str(file_row.get("sha256") or "").casefold()
        == str(target.get("sha256") or "").casefold()
    )
    return process_ok and network_ok and file_ok


def evaluate_pre_cleanup_qualification(
    *,
    static_checks: Mapping[str, bool],
    kali_ip: str,
    victim_ip: str,
    listener_port: int,
    target: Mapping[str, Any],
    source_event: Mapping[str, Any],
    scenario_links: Sequence[Mapping[str, Any]],
    before_response: Mapping[str, Any],
    reference_response: Mapping[str, Any],
    fresh_poststate: Mapping[str, Any],
    poststate_validation: Mapping[str, Any],
) -> dict[str, Any]:
    """Deterministically evaluate the qualification gate before external cleanup."""

    observations = _observations(before_response)
    scenario = [dict(row) for row in scenario_links if isinstance(row, Mapping)]
    ability_ids = {_scenario_ability_id(row) for row in scenario}
    scenario_ok = (
        len(scenario) == len(WEBSHELL_SCENARIO_ABILITIES)
        and ability_ids == WEBSHELL_SCENARIO_ABILITIES
        and all(_link_succeeded(row) for row in scenario)
    )
    command_outputs_present = all(
        _file_present(observations.get(trace_id))
        for trace_id in ("trace.webshell.groups.file", "trace.webshell.tasks.file")
    )
    event_ok = (
        source_event.get("event_type") == "alert"
        and str(source_event.get("src_ip") or "") == kali_ip
        and str(source_event.get("dest_ip") or "") == victim_ip
        and int(source_event.get("dest_port") or 0) == int(listener_port)
        and int(source_event.get("signature_id") or 0) == 9204005
        and bool(source_event.get("flow_id"))
    )
    target_present = _target_present(observations, target)
    target_complete = (
        int(target.get("pid") or 0) > 0
        and bool(str(target.get("creation_time_utc") or ""))
        and bool(str(target.get("path") or ""))
        and len(str(target.get("sha256") or "")) == 64
    )
    reference_actions = [
        row
        for row in reference_response.get("actions") or []
        if isinstance(row, Mapping)
    ]
    reference_ok = (
        reference_response.get("actual_state_changed") is True
        and reference_response.get("all_actions_prevalidated") is True
        and reference_response.get("c2trace_used") is False
        and reference_response.get("llm_used") is False
        and [row.get("tool") for row in reference_actions]
        == ["stop_process", "remove_file"]
        and all(row.get("state_changed") is True for row in reference_actions)
    )
    response_completed = _parse_utc(reference_response.get("completed_at_utc"))
    post_captured = _parse_utc(fresh_poststate.get("captured_at_utc"))
    fresh_ok = (
        fresh_poststate.get("new_collector_instance") is True
        and fresh_poststate.get("read_only") is True
        and response_completed is not None
        and post_captured is not None
        and post_captured >= response_completed
        and poststate_validation.get("passed") is True
    )
    protected_ok = (
        poststate_validation.get("control_sandcat_alive") is True
        and poststate_validation.get("driver_agent_alive") is not False
        and poststate_validation.get("wrong_target") is False
    )

    checks = {name: bool(static_checks.get(name, False)) for name in REQUIRED_QUALIFICATION_CHECKS}
    checks.update(
        {
            "real_cross_host_c2": event_ok and kali_ip != victim_ip,
            "suricata_alert_captured": event_ok,
            "windows_owner_attributed": target_present,
            "action_traversed_c2_channel": scenario_ok and command_outputs_present and event_ok,
            "response_objects_measurable": target_complete and target_present,
            "no_success_stub": scenario_ok and command_outputs_present,
            "no_pre_response_auto_cleanup": target_present and command_outputs_present,
            "reference_response_changed_real_state": reference_ok,
            "reference_poststate_fresh_query": fresh_ok,
            "oracle_independently_measurable": (
                target_complete
                and target_present
                and event_ok
                and reference_response.get("c2trace_used") is False
                and reference_response.get("llm_used") is False
            ),
            "protected_objects_unchanged": protected_ok,
            "cleanup_after_scoring": False,
        }
    )
    failed = [name for name in REQUIRED_QUALIFICATION_CHECKS if not checks[name]]
    return {
        "schema_version": "c2trace.benchmark.v1.pre_cleanup_qualification",
        "checks": checks,
        "failed_checks": failed,
        "technical_gate_passed": not [name for name in failed if name != "cleanup_after_scoring"],
        "cleanup_pending": True,
        "c2trace_used": False,
        "llm_used": False,
    }


def finalize_cleanup_check(
    pre_cleanup_score: Mapping[str, Any],
    *,
    pre_cleanup_score_path: str | Path,
    cleanup_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    score_path = Path(pre_cleanup_score_path).resolve()
    raw = score_path.read_bytes()
    score_sha256 = hashlib.sha256(raw).hexdigest()
    cleanup_time = _parse_utc(cleanup_receipt.get("completed_at"))
    cleanup_ok = (
        pre_cleanup_score.get("cleanup_pending") is True
        and pre_cleanup_score.get("technical_gate_passed") is True
        and cleanup_receipt.get("all_actions_prevalidated") is True
        and cleanup_receipt.get("manual_review_required") is False
        and str(cleanup_receipt.get("score_sha256") or "").casefold() == score_sha256
        and Path(str(cleanup_receipt.get("score_path") or "")).resolve() == score_path
        and cleanup_time is not None
    )
    checks = {
        name: bool((pre_cleanup_score.get("checks") or {}).get(name, False))
        for name in REQUIRED_QUALIFICATION_CHECKS
    }
    checks["cleanup_after_scoring"] = cleanup_ok
    failed = [name for name in REQUIRED_QUALIFICATION_CHECKS if not checks[name]]
    return {
        "schema_version": "c2trace.benchmark.v1.qualification_check_result",
        "checks": checks,
        "failed_checks": failed,
        "passed": not failed,
        "pre_cleanup_score_sha256": score_sha256,
        "cleanup_completed_at_utc": cleanup_receipt.get("completed_at"),
        "c2trace_used": False,
        "llm_used": False,
    }


__all__ = [
    "WEBSHELL_SCENARIO_ABILITIES",
    "evaluate_pre_cleanup_qualification",
    "finalize_cleanup_check",
]
