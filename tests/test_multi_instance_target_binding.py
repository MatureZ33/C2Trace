import pytest

from c2trace.agents.executor import ExecutorAgent
from c2trace.models import ActionResult, CaseFile, Finding, MinimalAlert, NodeType, NodeStatus, StrategyNode
from c2trace.orchestrator import WorkflowController
from c2trace.tools import ToolResult


def test_dual_c2_attribution_follows_alert_local_port() -> None:
    alert = MinimalAlert.from_dict({
        "case_id": "AURORA-CHAIN-002",
        "alert_id": "AURORA-CHAIN-002-A001",
        "source": "suricata_eve",
        "alert_type": "c2_tcp_beacon",
        "victim_ip": "192.168.21.145",
        "remote_ip": "192.168.21.132",
        "remote_port": 18447,
        "protocol": "tcp",
        "confidence": 0.6,
    })
    case = CaseFile.from_alert(
        alert,
        source_events=[{
            "src_ip": "192.168.21.145",
            "src_port": 60933,
            "dest_ip": "192.168.21.132",
            "dest_port": 18447,
            "proto": "TCP",
        }],
    )
    payload = r"C:\Users\Public\dual.exe"
    case.add_finding(Finding(
        finding_type="network_connection",
        value="192.168.21.132:18447",
        evidence="two same-endpoint C2 connections",
        source="test",
        details={
            "connections": [
                {
                    "local_address": "192.168.21.145",
                    "local_port": 60933,
                    "remote_address": "192.168.21.132",
                    "remote_port": 18447,
                    "pid": 3868,
                    "process_name": "dual",
                    "process_path": payload,
                },
                {
                    "local_address": "192.168.21.145",
                    "local_port": 60931,
                    "remote_address": "192.168.21.132",
                    "remote_port": 18447,
                    "pid": 10580,
                    "process_name": "dual",
                    "process_path": payload,
                },
            ]
        },
    ))

    assert case.attributed_process()["pid"] == 3868
    assert case.attributed_process()["process_path"] == payload
    assert [item["pid"] for item in case.sibling_c2_processes()] == [10580]

    node = StrategyNode(
        node_id="response",
        type=NodeType.RESPONSE,
        goal="terminate primary C2 process",
        tool="kill_process",
        arguments={
            "pid": "{{evidence.pid}}",
            "expected_path": "{{evidence.process_path}}",
        },
        requires=["evidence_gate"],
    )
    resolved = WorkflowController(planner=None, auditor=None, executor=None)._resolve_arguments(case, node)
    assert resolved["pid"] == 3868
    assert resolved["expected_path"] == payload


class _ProcessIdentityRunner:
    def run(self, tool, params=None):
        assert tool == "check_process"
        return ToolResult(True, data={"processes": [{
            "pid": 10580,
            "name": "dual.exe",
            "path": r"C:\Users\Public\dual.exe",
            "creation_time": "2026-10-03T20:57:28+00:00",
        }]})


def test_check_process_enriches_prior_c2_attribution_identity() -> None:
    alert = MinimalAlert.from_dict({
        "case_id": "identity-enrichment",
        "victim_ip": "192.168.21.145",
        "remote_ip": "192.168.21.132",
        "remote_port": 18447,
        "protocol": "tcp",
    })
    case = CaseFile.from_alert(alert)
    case.add_finding(Finding(
        finding_type="c2_process_attributed",
        value="dual",
        evidence="network owner",
        source="executor",
        details={
            "pid": 10580,
            "process_name": "dual",
            "process_path": r"C:\Users\Public\dual.exe",
        },
    ))
    node = StrategyNode(
        node_id="identity",
        type=NodeType.INVESTIGATE,
        goal="confirm process identity",
        tool="check_process",
        arguments={"pid": "10580"},
    )
    result = ExecutorAgent(tool_runner=_ProcessIdentityRunner()).execute(
        case, node, {"pid": 10580}
    )

    assert result.success is True
    attributed = next(f for f in case.findings if f.finding_type == "c2_process_attributed")
    assert attributed.details["creation_time"] == "2026-10-03T20:57:28+00:00"
    assert any(f.finding_type == "process_detail" for f in case.findings)


def test_check_process_resolution_uses_sibling_pid() -> None:
    case = CaseFile.from_alert(MinimalAlert.from_dict({
        "case_id": "identity-binding",
        "victim_ip": "192.168.21.145",
        "remote_ip": "192.168.21.132",
        "remote_port": 18447,
        "protocol": "tcp",
    }))
    case.add_finding(Finding(
        finding_type="network_connection",
        value="192.168.21.132:18447",
        evidence="dual C2 connections",
        source="executor",
        details={"connections": [{
            "pid": 3868,
            "process_name": "dual",
            "process_path": r"C:\Users\Public\dual.exe",
        }, {
            "pid": 10580,
            "process_name": "dual",
            "process_path": r"C:\Users\Public\dual.exe",
        }]},
    ))
    node = StrategyNode(
        node_id="sibling-identity",
        type=NodeType.INVESTIGATE,
        goal="confirm sibling identity",
        tool="check_process",
        arguments={"pid": "10580"},
        metadata={"sibling_c2_process": True, "sibling_pid": 10580},
    )

    resolved = WorkflowController(planner=None, auditor=None, executor=None)._resolve_arguments(case, node)

    assert resolved == {"pid": 10580}


def _sibling_case_for_identity_gate() -> CaseFile:
    case = CaseFile.from_alert(MinimalAlert.from_dict({
        "case_id": "identity-gate",
        "victim_ip": "192.168.21.145",
        "remote_ip": "192.168.21.132",
        "remote_port": 18447,
        "protocol": "tcp",
    }))
    case.strategy_tree = object()
    case.add_finding(Finding(
        finding_type="network_connection",
        value="192.168.21.132:18447",
        evidence="dual C2 connections",
        source="executor",
        details={"connections": [{
            "pid": 3868,
            "process_name": "dual",
            "process_path": r"C:\Users\Public\dual.exe",
        }, {
            "pid": 10580,
            "process_name": "dual",
            "process_path": r"C:\Users\Public\dual.exe",
        }]},
    ))
    case.add_result(ActionResult(
        node_id="primary-kill",
        tool="kill_process",
        success=True,
        arguments={"pid": 3868},
    ))
    return case


def _run_identity_gate(process_rows):
    controller = WorkflowController(planner=None, auditor=None, executor=None)
    response_nodes = []

    def fake_execute(case, node, **_kwargs):
        node.status = NodeStatus.SUCCEEDED
        result = ActionResult(
            node_id=node.node_id,
            tool=node.tool,
            success=True,
            data={"processes": process_rows},
            arguments={"pid": 10580},
        )
        case.add_result(result)
        node.result_id = result.result_id

    controller._execute_node = fake_execute
    controller._audit_then_execute_response = lambda case, node: response_nodes.append(node)
    case = _sibling_case_for_identity_gate()
    controller._auto_kill_sibling_c2_processes(case)
    return case, response_nodes


def test_sibling_identity_gate_allows_exact_identity_only() -> None:
    case, response_nodes = _run_identity_gate([{
        "pid": 10580,
        "name": "dual.exe",
        "path": r"C:\Users\Public\dual.exe",
        "creation_time": "2026-10-03T20:57:28+00:00",
    }])

    assert len(response_nodes) == 1
    assert case.final_status == "initialized"


@pytest.mark.parametrize("rows", [
    [],
    [{"pid": 10580, "path": r"C:\Users\Public\dual.exe"}],
    [{"pid": 10580, "path": r"C:\Users\Public\other.exe", "creation_time": "2026-10-03T20:57:28+00:00"}],
    [
        {"pid": 10580, "path": r"C:\Users\Public\dual.exe", "creation_time": "2026-10-03T20:57:28+00:00"},
        {"pid": 10580, "path": r"C:\Users\Public\dual.exe", "creation_time": "2026-10-03T20:57:29+00:00"},
    ],
])
def test_sibling_identity_gate_fails_closed_for_incomplete_or_ambiguous_rows(rows) -> None:
    case, response_nodes = _run_identity_gate(rows)

    assert response_nodes == []
    assert case.final_status == "target_identity_incomplete"
    assert case.errors[-1]["error_type"] == "sibling_identity_incomplete"
