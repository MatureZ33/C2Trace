from datetime import datetime, timedelta, timezone

import pytest

from c2trace.agents import AuditorAgent, ExecutorAgent
from c2trace.authorization import (
    ResponseAuthorizationIssuer,
    ResponseAuthorizationVerifier,
)
from c2trace.agents.target_identity import revalidate_target_before_response
from c2trace.execution import PreparedToolCall
from c2trace.models import (
    AuditDecision,
    AuditVerdict,
    CaseFile,
    Finding,
    MinimalAlert,
    StrategyNode,
)
from c2trace.time_identity import compare_creation_times, creation_times_match
from c2trace.tools import ToolResult


def _target_lock() -> dict:
    return {
        "schema_version": "c2trace.response_target_lock.v2",
        "lock_id": "a" * 64,
        "case_id": "AUTH-CASE-001",
        "process": {
            "pid": 4242,
            "path": r"C:\Users\Public\implant.exe",
            "canonical_path": r"c:\users\public\implant.exe",
            "creation_time_utc": "2026-07-16t11:01:43.100000z",
            "sha256": "b" * 64,
        },
        "file": {
            "path": r"C:\Users\Public\implant.exe",
            "canonical_path": r"c:\users\public\implant.exe",
            "sha256": "b" * 64,
        },
        "persistence_targets": [],
    }


def _authorization():
    issuer = ResponseAuthorizationIssuer()
    decision = AuditDecision(
        node_id="n-response",
        verdict=AuditVerdict.APPROVED,
        reason="test",
    )
    call = PreparedToolCall.create(
        node_id="n-response",
        tool="kill_process",
        arguments={
            "pid": 4242,
            "expected_path": r"C:\Users\Public\implant.exe",
        },
    )
    authorization = issuer.issue(
        case_id="AUTH-CASE-001",
        decision=decision,
        call=call,
        target_lock=_target_lock(),
    )
    return issuer, call, authorization


def test_ed25519_authorization_is_exact_and_one_shot():
    issuer, call, authorization = _authorization()
    verifier = ResponseAuthorizationVerifier(issuer.public_key_b64)

    verified = verifier.verify(
        authorization.to_wire(),
        case_id="AUTH-CASE-001",
        call_id=call.call_id,
        node_id=call.node_id,
        tool=call.tool,
        arguments_sha256=call.arguments_sha256,
    )
    assert verified.valid is True
    verifier.consume(verified)

    replay = verifier.verify(
        authorization.to_wire(),
        case_id="AUTH-CASE-001",
        call_id=call.call_id,
        node_id=call.node_id,
        tool=call.tool,
        arguments_sha256=call.arguments_sha256,
    )
    assert replay.valid is False
    assert "consumed" in replay.reason


def test_authorization_rejects_argument_or_expiry_changes():
    issuer, call, authorization = _authorization()
    verifier = ResponseAuthorizationVerifier(issuer.public_key_b64)

    wrong_args = verifier.verify(
        authorization.to_wire(),
        case_id="AUTH-CASE-001",
        call_id=call.call_id,
        node_id=call.node_id,
        tool=call.tool,
        arguments_sha256="0" * 64,
    )
    assert wrong_args.valid is False
    assert "arguments_sha256" in wrong_args.reason

    expired = verifier.verify(
        authorization.to_wire(),
        case_id="AUTH-CASE-001",
        call_id=call.call_id,
        node_id=call.node_id,
        tool=call.tool,
        arguments_sha256=call.arguments_sha256,
        now=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    assert expired.valid is False
    assert "expired" in expired.reason


def test_creation_time_comparison_handles_lowercase_iso_and_records_delta():
    comparison = compare_creation_times(
        "2026-07-16T11:01:43.100000Z",
        "2026-07-16t11:01:43.188000z",
    )
    assert comparison.matches is True
    assert comparison.parsed is True
    assert comparison.delta_ms == pytest.approx(88.0)


def test_creation_time_comparison_rejects_distinct_process_instance():
    assert creation_times_match(
        "2026-07-16T11:01:43.100000Z",
        "2026-07-16t11:02:19.100000z",
    ) is False


def test_creation_time_comparison_falls_back_to_exact_normalized_text():
    assert creation_times_match("NOT-A-TIME", "not-a-time") is True
    assert creation_times_match("NOT-A-TIME-A", "not-a-time-b") is False


class _IdentityBackend:
    def __init__(self, creation_time: str, *, path: str = r"C:\Users\Public\implant.exe"):
        self.creation_time = creation_time
        self.path = path

    def run(self, tool, params):
        if tool == "check_process":
            return ToolResult(True, data={"processes": [{
                "pid": 4242,
                "path": self.path,
                "creation_time_utc": self.creation_time,
            }]})
        if tool == "check_file_metadata":
            return ToolResult(True, data={"file": {
                "exists": True,
                "path": self.path,
                "sha256": "b" * 64,
            }})
        raise AssertionError(tool)


def test_toctou_recheck_allows_88ms_only_when_other_identity_fields_match():
    receipt = revalidate_target_before_response(
        _IdentityBackend("2026-07-16t11:01:43.188000z"),
        tool="kill_process",
        arguments={"pid": 4242, "expected_path": r"C:\Users\Public\implant.exe"},
        target_lock=_target_lock(),
    )
    assert receipt["passed"] is True
    assert receipt["comparisons"]["creation_time_utc"]["delta_ms"] == pytest.approx(88.0)

    with pytest.raises(PermissionError, match="identity drift"):
        revalidate_target_before_response(
            _IdentityBackend(
                "2026-07-16t11:01:43.188000z",
                path=r"C:\Users\Public\different.exe",
            ),
            tool="kill_process",
            arguments={"pid": 4242, "expected_path": r"C:\Users\Public\implant.exe"},
            target_lock=_target_lock(),
        )


def test_toctou_recheck_rejects_36_second_process_instance_change():
    with pytest.raises(PermissionError, match="identity drift"):
        revalidate_target_before_response(
            _IdentityBackend("2026-07-16t11:02:19.100000z"),
            tool="kill_process",
            arguments={"pid": 4242, "expected_path": r"C:\Users\Public\implant.exe"},
            target_lock=_target_lock(),
        )


class _ApprovedReasonLLM:
    def chat_json(self, **_kwargs):
        return {"reason": "evidence and target identity approved"}


class _LockingValidator:
    def validate_case_input(self, _case):
        return None

    def lock_response(self, case, _node, _arguments):
        lock = _target_lock()
        case.response_target_lock = lock
        return lock


class _CapturingToolClient:
    def __init__(self):
        self.authorization = None

    def run(self, tool, params, *, authorization=None):
        self.authorization = authorization
        return ToolResult(True, data={"dry_run": True, "tool": tool, "params": params})


def test_auditor_owns_target_lock_and_executor_only_relays_authorization():
    alert = MinimalAlert.from_dict({
        "case_id": "AUTH-CASE-001",
        "alert_id": "AUTH-CASE-001-A",
        "source": "unit_test",
        "alert_type": "c2_http_beacon",
        "victim_ip": "192.0.2.10",
        "remote_ip": "192.0.2.20",
        "remote_port": 443,
        "protocol": "tcp",
    })
    case = CaseFile.from_alert(alert)
    case.add_finding(Finding(
        finding_type="network_connection",
        value="192.0.2.20:443",
        evidence="test",
        source="executor",
        details={"remote_address": "192.0.2.20", "remote_port": 443, "pid": 4242},
    ))
    case.add_finding(Finding(
        finding_type="c2_process_attributed",
        value="implant.exe",
        evidence="test",
        source="executor",
        details={
            "pid": 4242,
            "process_name": "implant.exe",
            "process_path": r"C:\Users\Public\implant.exe",
        },
    ))
    case.add_finding(Finding(
        finding_type="process_detail",
        value="implant.exe",
        evidence="test",
        source="executor",
        details={
            "pid": 4242,
            "name": "implant.exe",
            "path": r"C:\Users\Public\implant.exe",
        },
    ))
    node = StrategyNode.from_dict({
        "node_id": "n-response",
        "type": "response",
        "goal": "terminate exact C2 owner",
        "tool": "kill_process",
        "arguments": {},
    })
    client = _CapturingToolClient()
    executor = ExecutorAgent(tool_client=client)
    observed = executor.observe_target(case, node, "check_process", {"pid": 4242})
    assert observed.success is True
    assert case.target_observations[-1]["tool"] == "check_process"
    with pytest.raises(PermissionError, match="cannot call response tool"):
        executor.observe_target(case, node, "kill_process", {"pid": 4242})
    prepared = executor.prepare(case, node, {
        "pid": 4242,
        "process_name": "implant",
        "expected_path": r"C:\Users\Public\implant.exe",
    })
    auditor = AuditorAgent(
        llm_client=_ApprovedReasonLLM(),
        target_validator=_LockingValidator(),
    )

    decision = auditor.audit(case, node, prepared)
    authorization = auditor.authorization_for(decision.decision_id)
    assert decision.verdict == AuditVerdict.APPROVED
    assert case.response_target_lock["lock_id"] == "a" * 64
    assert authorization is not None
    assert decision.authorization_receipt["token_sha256"] == authorization.token_sha256

    node.audit_decision_id = decision.decision_id
    executor.execute(case, node, prepared, authorization=authorization)
    assert client.authorization is authorization
