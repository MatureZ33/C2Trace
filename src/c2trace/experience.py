from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any
from uuid import uuid4

from c2trace.models import CaseFile, MinimalAlert, ValidationError, utc_now, validate_case_id
from c2trace.tools import RESPONSE_TOOLS


SCHEMA_VERSION = "c2trace.experience.v2"
DEFAULT_HISTORY_DIR = Path("results/experience_history")
REQUIRED_CLEANUP_VERIFICATION_FINDINGS = frozenset({
    "cleanup_network_verified",
    "cleanup_process_verified",
    "cleanup_file_verified",
    "cleanup_persistence_verified",
})


class ExperienceEligibilityError(ValueError):
    """Raised when a case is unsafe to promote into reusable experience."""


def experience_eligibility(case: CaseFile) -> tuple[bool, str]:
    try:
        validate_case_id(case.case_id)
    except ValidationError as exc:
        return False, str(exc)
    if case.final_status != "completed":
        return False, f"final_status={case.final_status!r} is not eligible; expected 'completed'"
    response_results = [result for result in case.action_results if result.tool in RESPONSE_TOOLS]
    if not response_results:
        return False, "no audited response action was recorded"
    if any(not result.success for result in response_results):
        return False, "at least one response action failed"
    if any(isinstance(result.data, dict) and result.data.get("dry_run") is True for result in response_results):
        return False, "dry-run response actions are not eligible for reusable experience"
    decisions = {decision.decision_id: decision for decision in case.audit_decisions}
    node_map = case.strategy_tree.node_map() if case.strategy_tree else {}
    unaudited: list[str] = []
    for result in response_results:
        decision = decisions.get(str(result.audit_decision_id or ""))
        node = node_map.get(result.node_id)
        if (
            decision is None
            or decision.verdict.value != "approved"
            or decision.node_id != result.node_id
            or node is None
            or node.audit_decision_id != decision.decision_id
        ):
            unaudited.append(result.node_id)
    if unaudited:
        return False, f"response action(s) lack approved audit decisions bound to their results: {sorted(set(unaudited))}"

    last_response_index = max(case.action_results.index(result) for result in response_results)
    successful_verifications = {
        result.result_id
        for result in case.action_results[last_response_index + 1:]
        if result.tool == "verify_cleanup" and result.success
    }
    if not successful_verifications:
        return False, "no successful post-response cleanup verification was recorded"
    verified_actions = [
        finding.details
        for finding in case.findings
        if finding.finding_type == "cleanup_action_verified"
        and isinstance(finding.details, dict)
        and str(finding.details.get("verification_result_id") or "") in successful_verifications
    ]
    missing_results = sorted(
        result.result_id
        for result in response_results
        if not any(
            str(details.get("response_result_id") or "") == result.result_id
            and str(details.get("tool") or "") == result.tool
            and details.get("arguments") == result.arguments
            for details in verified_actions
        )
    )
    if missing_results:
        return False, f"response action(s) lack exact post-response verification: {missing_results}"
    network_verified = any(
        finding.finding_type == "cleanup_network_verified"
        and isinstance(finding.details, dict)
        and str(finding.details.get("verification_result_id") or "") in successful_verifications
        for finding in case.findings
    )
    if not network_verified:
        return False, "post-response C2 network cleanup was not verified"
    return True, "completed response with bound audit and exact post-response cleanup verification"


def build_experience_record(case: CaseFile) -> dict[str, Any]:
    alert = case.source_alert
    first_source_event = case.source_events[0] if case.source_events else {}
    finding_types = {finding.finding_type for finding in case.findings}
    audit_counts = Counter(decision.verdict.value for decision in case.audit_decisions)
    action_tools = [
        result.tool
        for result in case.action_results
        if result.tool
        and result.success
        and not (isinstance(result.data, dict) and result.data.get("dry_run") is True)
    ]
    response_tools = [tool for tool in action_tools if tool in RESPONSE_TOOLS]

    node_types: list[str] = []
    tool_sequence: list[str] = []
    if case.strategy_tree:
        for node in case.strategy_tree.nodes:
            node_types.append(node.type.value)
            if node.tool:
                tool_sequence.append(node.tool)

    record = {
        "schema_version": SCHEMA_VERSION,
        "case_id": case.case_id,
        "created_at": utc_now(),
        "alert_pattern": {
            "source": alert.get("source"),
            "alert_type": alert.get("alert_type"),
            "protocol": alert.get("protocol"),
            "remote_port": alert.get("remote_port"),
            "app_proto": first_source_event.get("app_proto"),
            "signature_id": first_source_event.get("signature_id"),
        },
        "strategy_pattern": {
            "node_types": _unique_preserve_order(node_types),
            "tool_sequence": tool_sequence,
        },
        "evidence_chain_pattern": _evidence_chain_pattern(finding_types),
        "audit_pattern": {
            "approved": audit_counts.get("approved", 0),
            "rejected": audit_counts.get("rejected", 0),
            "need_more_evidence": audit_counts.get("need_more_evidence", 0),
        },
        "response_pattern": {
            "executed_tools": _unique_preserve_order(response_tools),
        },
        "verification_pattern": _verification_pattern(finding_types),
        "lessons": _generic_lessons(alert, finding_types, response_tools),
    }
    return _drop_empty(record)


def write_experience(case: CaseFile, root: str | Path = DEFAULT_HISTORY_DIR) -> Path:
    eligible, reason = experience_eligibility(case)
    if not eligible:
        raise ExperienceEligibilityError(f"case {case.case_id} is not eligible for experience: {reason}")
    case_id = validate_case_id(case.case_id)
    root_path = Path(root).resolve()
    cases_dir = root_path / "cases"
    cases_dir.mkdir(parents=True, exist_ok=True)
    record = build_experience_record(case)
    case_path = (cases_dir / f"{case_id}.experience.json").resolve()
    if not case_path.is_relative_to(cases_dir.resolve()):
        raise ExperienceEligibilityError("experience case path escapes the configured history root")
    _atomic_write_text(case_path, json.dumps(record, ensure_ascii=False, indent=2))
    index_path = root_path / "index.jsonl"
    records = _load_index_records(index_path)
    records = [item for item in records if str(item.get("case_id") or "") != case_id]
    records.append(record)
    index_text = "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in records)
    _atomic_write_text(index_path, index_text)
    return case_path


def load_experience_context(
    root: str | Path,
    alert: MinimalAlert,
    *,
    top_k: int = 3,
) -> list[dict[str, Any]]:
    index_path = Path(root) / "index.jsonl"
    if top_k <= 0 or not index_path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in index_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    scored = sorted(
        ((score_experience(item, alert), item) for item in records),
        key=lambda pair: pair[0],
        reverse=True,
    )
    return [experience_to_prompt_context(item) for score, item in scored[:top_k] if score > 0]


def score_experience(record: dict[str, Any], alert: MinimalAlert) -> int:
    pattern = record.get("alert_pattern") if isinstance(record.get("alert_pattern"), dict) else {}
    payload = alert.to_dict()
    score = 0
    if pattern.get("alert_type") and pattern.get("alert_type") == payload.get("alert_type"):
        score += 4
    if pattern.get("protocol") and pattern.get("protocol") == payload.get("protocol"):
        score += 3
    if pattern.get("remote_port") and pattern.get("remote_port") == payload.get("remote_port"):
        score += 2
    if pattern.get("source") and pattern.get("source") == payload.get("source"):
        score += 1
    return score


def experience_to_prompt_context(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "alert_pattern": record.get("alert_pattern", {}),
        "strategy_pattern": record.get("strategy_pattern", {}),
        "evidence_chain_pattern": record.get("evidence_chain_pattern", []),
        "audit_pattern": record.get("audit_pattern", {}),
        "response_pattern": record.get("response_pattern", {}),
        "verification_pattern": record.get("verification_pattern", {}),
        "lessons": record.get("lessons", []),
    }


def _evidence_chain_pattern(finding_types: set[str]) -> list[str]:
    pattern: list[str] = []
    if finding_types & {"network_confirmed", "network_connection", "minimal_c2_seed_alert"}:
        pattern.append("network")
    if finding_types & {"c2_process_attributed", "process_detail", "process_tree"}:
        pattern.append("process")
    if finding_types & {"file_metadata", "payload_file_verified", "suspicious_process_path"}:
        pattern.append("file")
    if finding_types & {"persistence_summary", "persistence_linked_to_payload"}:
        pattern.append("persistence")
    if any(item.startswith("cleanup_") for item in finding_types):
        pattern.append("verification")
    return pattern


def _verification_pattern(finding_types: set[str]) -> dict[str, str]:
    return {
        finding_type: "observed" if finding_type in finding_types else "not_observed"
        for finding_type in sorted(REQUIRED_CLEANUP_VERIFICATION_FINDINGS)
    }


def _generic_lessons(alert: dict[str, Any], finding_types: set[str], response_tools: list[str]) -> list[str]:
    protocol = str(alert.get("protocol") or "network").lower()
    lessons = [
        f"{protocol.upper()} C2 seeds should be traced from network connection to process, file, persistence, and cleanup verification.",
    ]
    if "persistence_linked_to_payload" in finding_types:
        lessons.append("Persistence cleanup should be gated by evidence linking the persistence item to the attributed payload.")
    if response_tools:
        lessons.append("Audited response actions should be followed by verification of network, process, file, and persistence state.")
    return lessons


def _unique_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        output.append(item)
    return output


def _drop_empty(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _drop_empty(item) for key, item in value.items() if item not in (None, "", [], {})}
    if isinstance(value, list):
        return [_drop_empty(item) for item in value if item not in (None, "", [], {})]
    return value


def _load_index_records(index_path: Path) -> list[dict[str, Any]]:
    if not index_path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in index_path.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def _atomic_write_text(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()
