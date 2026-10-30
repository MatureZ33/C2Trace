import json

import pytest

from c2trace.experience import (
    ExperienceEligibilityError,
    build_experience_record,
    experience_eligibility,
    load_experience_context,
    write_experience,
)
from c2trace.models import (
    ActionResult,
    AuditDecision,
    AuditVerdict,
    CaseFile,
    Finding,
    MinimalAlert,
    StrategyTree,
)


def _alert():
    return MinimalAlert.from_dict({
        "case_id": "S002",
        "alert_id": "S002-A001",
        "source": "suricata_eve",
        "alert_type": "c2_http_beacon",
        "victim_ip": "192.168.21.138",
        "remote_ip": "192.168.21.132",
        "remote_port": 8888,
        "protocol": "http",
        "confidence": 0.75,
    })


def _source_event():
    return {
        "timestamp": "2026-07-04T15:40:00.000000+0800",
        "event_type": "alert",
        "src_ip": "192.168.21.138",
        "src_port": 50555,
        "dest_ip": "192.168.21.132",
        "dest_port": 8888,
        "proto": "tcp",
        "app_proto": "http",
        "signature": "C2TRACE Possible HTTP C2 Beacon",
        "signature_id": 9000001,
        "category": "Potential C2",
        "severity": 2,
        "flow_id": 12345,
    }


def _case():
    case = CaseFile.from_alert(_alert(), source_events=[_source_event()])
    case.strategy_tree = StrategyTree.from_dict({
        "tree_id": "tree-s002",
        "root_objective": "Trace C2",
        "nodes": [
            {"node_id": "n1", "type": "investigate", "goal": "network", "tool": "check_network"},
            {"node_id": "n2", "type": "decision", "goal": "evidence_sufficient_for_response"},
            {"node_id": "n3", "type": "response", "goal": "kill", "tool": "kill_process", "requires": ["n2"]},
            {"node_id": "n4", "type": "verify", "goal": "verify", "tool": "verify_cleanup", "requires": ["n3"]},
        ],
    })
    case.add_finding(Finding(
        finding_type="network_confirmed",
        value="192.168.21.132:8888",
        evidence="PID 5252 owns the connection",
        source="executor",
        details={"pid": 5252, "process_path": "C:\\Users\\Public\\sandcat_s002.exe"},
    ))
    case.add_finding(Finding(
        finding_type="persistence_linked_to_payload",
        value="S002Sandcat",
        evidence="Run key points to attributed payload",
        source="executor",
        details={"path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "S002Sandcat"},
    ))
    case.add_finding(Finding(
        finding_type="cleanup_file_verified",
        value="removed",
        evidence="Payload file no longer exists",
        source="executor",
    ))
    for finding_type in (
        "cleanup_network_verified",
        "cleanup_process_verified",
        "cleanup_persistence_verified",
    ):
        case.add_finding(Finding(
            finding_type=finding_type,
            value="verified",
            evidence=f"{finding_type} observed",
            source="executor",
        ))
    decision = case.add_audit_decision(
        AuditDecision(node_id="n3", verdict=AuditVerdict.APPROVED, reason="Evidence chain complete")
    )
    case.strategy_tree.node_map()["n3"].audit_decision_id = decision.decision_id
    response = case.add_result(ActionResult(
        node_id="n3",
        tool="kill_process",
        success=True,
        data={"executed": True},
        arguments={"pid": 5252},
        audit_decision_id=decision.decision_id,
    ))
    verification = case.add_result(ActionResult(
        node_id="n4",
        tool="verify_cleanup",
        success=True,
        data={"network_checked": True, "network_clean": True},
    ))
    case.add_finding(Finding(
        finding_type="cleanup_action_verified",
        value=response.result_id,
        evidence="Exact response target was absent",
        source="executor",
        details={
            "response_result_id": response.result_id,
            "verification_result_id": verification.result_id,
            "tool": "kill_process",
            "arguments": {"pid": 5252},
        },
    ))
    case.add_finding(Finding(
        finding_type="cleanup_network_verified",
        value="192.168.21.132",
        evidence="C2 connection was absent",
        source="executor",
        details={"verification_result_id": verification.result_id},
    ))
    case.final_status = "completed"
    return case


def test_casefile_records_sanitized_source_event():
    case = CaseFile.from_alert(
        _alert(),
        source_events=[_source_event()],
        source_artifacts=[{
            "artifact_type": "suricata_eve",
            "path": "C:\\Program Files\\Suricata\\log\\eve.json",
            "file_sha256": "a" * 64,
            "event_sha256": "b" * 64,
            "line_number": 7,
        }],
    )

    payload = case.to_dict()
    assert payload["source_events"][0]["signature_id"] == 9000001
    assert payload["source_artifacts"][0]["artifact_type"] == "suricata_eve"
    assert payload["source_artifacts"][0]["line_number"] == 7
    assert "pid" not in payload["source_events"][0]
    assert "process_path" not in payload["source_events"][0]
    assert "payload_path" not in payload["source_events"][0]
    assert "run_key" not in payload["source_events"][0]


def test_experience_record_is_sanitized():
    record = build_experience_record(_case())
    text = json.dumps(record, ensure_ascii=False)

    assert record["alert_pattern"]["remote_port"] == 8888
    assert record["alert_pattern"]["signature_id"] == 9000001
    assert "kill_process" in record["response_pattern"]["executed_tools"]
    assert "192.168.21." not in text
    assert "5252" not in text
    assert "C:\\Users" not in text
    assert "HKCU" not in text
    assert "S002Sandcat" not in text
    assert "sandcat_s002.exe" not in text
    assert record["verification_pattern"] == {
        "cleanup_file_verified": "observed",
        "cleanup_network_verified": "observed",
        "cleanup_persistence_verified": "observed",
        "cleanup_process_verified": "observed",
    }


def test_write_and_load_experience_context(tmp_path):
    case_path = write_experience(_case(), tmp_path)

    assert case_path.exists()
    assert (tmp_path / "index.jsonl").exists()

    context = load_experience_context(tmp_path, _alert(), top_k=3)
    context_text = json.dumps(context, ensure_ascii=False)

    assert context
    assert context[0]["alert_pattern"]["alert_type"] == "c2_http_beacon"
    assert "192.168.21." not in context_text
    assert "C:\\Users" not in context_text
    assert "S002Sandcat" not in context_text


@pytest.mark.parametrize("status", ["response_failed", "verification_failed", "completed_dry_run"])
def test_failed_or_dry_run_case_is_not_written_to_experience(tmp_path, status):
    case = _case()
    case.final_status = status

    eligible, reason = experience_eligibility(case)
    assert eligible is False
    assert "final_status" in reason
    with pytest.raises(ExperienceEligibilityError, match="not eligible"):
        write_experience(case, tmp_path)

    assert not (tmp_path / "index.jsonl").exists()


def test_completed_case_missing_exact_action_verification_is_not_written(tmp_path):
    case = _case()
    case.findings = [
        finding
        for finding in case.findings
        if finding.finding_type != "cleanup_action_verified"
    ]

    eligible, reason = experience_eligibility(case)
    assert eligible is False
    assert "exact post-response verification" in reason
    with pytest.raises(ExperienceEligibilityError):
        write_experience(case, tmp_path)


def test_completed_case_with_unaudited_response_is_not_written(tmp_path):
    case = _case()
    case.audit_decisions.clear()

    eligible, reason = experience_eligibility(case)
    assert eligible is False
    assert "lack approved audit" in reason
    with pytest.raises(ExperienceEligibilityError):
        write_experience(case, tmp_path)


def test_experience_path_cannot_escape_history_root_via_case_id(tmp_path):
    case = _case()
    case.case_id = "..\\..\\escaped"

    eligible, reason = experience_eligibility(case)

    assert eligible is False
    assert "path-safe" in reason
    with pytest.raises(ExperienceEligibilityError):
        write_experience(case, tmp_path)
    assert not (tmp_path.parent / "escaped.experience.json").exists()


def test_rewriting_same_case_replaces_index_record_instead_of_duplicating(tmp_path):
    write_experience(_case(), tmp_path)
    write_experience(_case(), tmp_path)

    records = [json.loads(line) for line in (tmp_path / "index.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [item["case_id"] for item in records] == ["S002"]


def test_experience_requires_result_to_decision_id_binding():
    case = _case()
    response = next(result for result in case.action_results if result.tool == "kill_process")
    response.audit_decision_id = "different-decision"

    eligible, reason = experience_eligibility(case)

    assert eligible is False
    assert "bound" in reason
