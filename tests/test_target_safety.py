import json

import pytest

from c2trace.agents import AuditorAgent, ExecutorAgent
from c2trace.agents.target_identity import TargetIdentityValidator
from c2trace.models import (
    AuditDecision,
    AuditVerdict,
    CaseFile,
    Finding,
    MinimalAlert,
    StrategyTree,
)
from c2trace.orchestrator import C2TraceOrchestrator
from c2trace.target_safety import (
    PROTECTED_PROCESSES_SCHEMA,
    TARGET_LOCK_SCHEMA,
    TargetSafetyError,
    TargetSafetyGuard,
    TargetSafetyInputError,
    load_protected_processes,
    load_reviewed_target,
)
from c2trace.tools import ToolResult


PATH = r"C:\Users\Public\c2t_run_001.exe"
HASH = "a" * 64
CREATED = "2026-07-14t01:02:03.0000000z"
REG_PATH = r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"


class SafetyRunner:
    def __init__(self):
        self.execute_response = False
        self.process_alive = True
        self.file_exists = True
        self.file_hash = HASH
        self.calls = []

    def run(self, tool, params=None):
        params = dict(params or {})
        self.calls.append((tool, params))
        if tool == "check_network":
            connections = []
            if self.process_alive:
                connections = [{
                    "local_address": "192.168.21.138",
                    "local_port": 49152,
                    "remote_address": "192.168.21.132",
                    "remote_port": 7010,
                    "state": "Established",
                    "pid": 4242,
                    "process_name": "c2t_run_001",
                    "process_path": PATH,
                }]
            return ToolResult(True, data={"connections": connections})
        if tool == "check_process":
            processes = []
            if self.process_alive:
                processes = [{
                    "pid": 4242,
                    "name": "c2t_run_001.exe",
                    "path": PATH,
                    "creation_time_utc": CREATED,
                }]
            return ToolResult(True, data={"processes": processes})
        if tool == "check_file_metadata":
            return ToolResult(True, data={"file": {
                "exists": self.file_exists,
                "path": PATH,
                "sha256": self.file_hash if self.file_exists else "",
            }})
        if tool == "check_persistence_all":
            return ToolResult(True, data={
                "registry_run_keys": [{"path": REG_PATH, "name": "C2TManx", "value": PATH}],
                "scheduled_tasks": [],
                "services": [],
            })
        if tool == "kill_process":
            self.process_alive = False
            return ToolResult(True, data={"killed": True})
        if tool == "remove_file":
            self.file_exists = False
            return ToolResult(True, data={"removed": True})
        return ToolResult(True, data={"dry_run": True, "tool": tool, "params": params})


def _case() -> CaseFile:
    alert = MinimalAlert.from_dict({
        "case_id": "AF-MAAS-WIN-01-r01",
        "alert_id": "AF-MAAS-WIN-01-r01-alert",
        "source": "suricata",
        "alert_type": "c2_tcp_beacon",
        "victim_ip": "192.168.21.138",
        "remote_ip": "192.168.21.132",
        "remote_port": 7010,
        "protocol": "tcp",
    })
    case = CaseFile.from_alert(alert, source_events=[{
        "event_type": "alert",
        "src_ip": "192.168.21.138",
        "src_port": 49152,
        "dest_ip": "192.168.21.132",
        "dest_port": 7010,
        "proto": "TCP",
        "flow_id": "987654321",
    }])
    case.add_finding(Finding(
        finding_type="network_connection",
        value="192.168.21.132:7010",
        evidence="exact C2 tuple",
        source="executor",
        details={
            "local_address": "192.168.21.138",
            "local_port": 49152,
            "remote_address": "192.168.21.132",
            "remote_port": 7010,
            "pid": 4242,
            "process_name": "c2t_run_001",
            "process_path": PATH,
        },
    ))
    case.add_finding(Finding(
        finding_type="process_detail",
        value="c2t_run_001.exe",
        evidence="live process",
        source="executor",
        details={"pid": 4242, "name": "c2t_run_001.exe", "path": PATH, "creation_time_utc": CREATED},
    ))
    case.add_finding(Finding(
        finding_type="payload_file_verified",
        value=PATH,
        evidence="file metadata",
        source="executor",
        details={"exists": True, "path": PATH, "sha256": HASH},
    ))
    case.add_finding(Finding(
        finding_type="persistence_linked_to_payload",
        value="C2TManx",
        evidence="Run key points to target",
        source="executor",
        details={
            "category": "registry_run_keys",
            "path": REG_PATH,
            "name": "C2TManx",
            "value": PATH,
        },
    ))
    return case


def _response_node(tool="kill_process"):
    payload = {
        "root_objective": "target-safety test",
        "nodes": [
            {"node_id": "i", "type": "investigate", "goal": "investigate", "tool": "check_network"},
            {"node_id": "d", "type": "decision", "goal": "evidence_sufficient_for_response", "condition": "evidence_sufficient_for_response", "requires": ["i"]},
            {
                "node_id": "r",
                "type": "response",
                "goal": "respond",
                "tool": tool,
                "requires": ["d"],
                "arguments": (
                    {"pid": "{{evidence.pid}}", "expected_path": "{{evidence.process_path}}"}
                    if tool == "kill_process"
                    else {}
                ),
            },
            {"node_id": "v", "type": "verify", "goal": "verify", "tool": "verify_cleanup", "requires": ["r"]},
        ],
    }
    return StrategyTree.from_dict(payload)


def _expected_target(**overrides):
    target = {
        "paw": "manx-paw-001",
        "pid": 4242,
        "creation_time_utc": CREATED,
        "path": PATH,
        "sha256": HASH,
        "group": "c2t-run-001-target",
        "host": "WIN10",
        "contact": "tcp",
    }
    target.update(overrides)
    return target


def test_target_lock_survives_kill_for_file_and_persistence_cleanup():
    case = _case()
    runner = SafetyRunner()
    guard = TargetSafetyGuard(tool_runner=runner)
    kill = _response_node().node_map()["r"]

    lock = guard.prepare_response(
        case,
        kill,
        {"pid": 4242, "process_name": "c2t_run_001", "expected_path": PATH},
    )
    assert lock["schema_version"] == TARGET_LOCK_SCHEMA
    assert lock["network"]["local_port"] == 49152
    assert lock["process"]["creation_time_utc"] == CREATED
    assert lock["file"]["sha256"] == HASH
    assert case.response_target_lock["lock_id"] == lock["lock_id"]

    # Simulate the first response having removed the live network/process.
    runner.process_alive = False
    file_node = _response_node("remove_file").node_map()["r"]
    assert guard.prepare_response(case, file_node, {"file_path": PATH})["lock_id"] == lock["lock_id"]
    reg_node = _response_node("remove_registry").node_map()["r"]
    assert guard.prepare_response(case, reg_node, {
        "reg_path": REG_PATH,
        "value_name": "C2TManx",
        "expected_value": PATH,
    })["lock_id"] == lock["lock_id"]


def test_protected_control_process_is_blocked_as_wrong_target():
    case = _case()
    runner = SafetyRunner()
    guard = TargetSafetyGuard(tool_runner=runner, protected_processes=[{
        "label": "control-sandcat",
        "paw": "control-paw",
        "pid": 4242,
        "creation_time_utc": CREATED,
        "path": PATH,
        "canonical_path": PATH.lower(),
        "sha256": HASH,
    }])

    with pytest.raises(TargetSafetyError) as caught:
        guard.prepare_response(
            case,
            _response_node().node_map()["r"],
            {"pid": 4242, "expected_path": PATH},
        )
    assert caught.value.status == "protected_target_blocked"
    assert caught.value.error_type == "wrong_target"
    assert "canonical_path" in caught.value.details["matched_by"]


def test_protected_process_time_uses_shared_utc_comparison():
    case = _case()
    runner = SafetyRunner()
    guard = TargetSafetyGuard(tool_runner=runner, protected_processes=[{
        "label": "control-sandcat",
        "paw": "control-paw",
        "pid": 4242,
        "creation_time_utc": "2026-07-14T01:02:03+00:00",
        "path": r"C:\Different\control.exe",
        "canonical_path": r"c:\different\control.exe",
        "sha256": HASH,
    }])

    with pytest.raises(TargetSafetyError) as caught:
        guard.prepare_response(
            case,
            _response_node().node_map()["r"],
            {"pid": 4242, "expected_path": PATH},
        )

    assert caught.value.status == "protected_target_blocked"
    assert "pid_creation_time" in caught.value.details["matched_by"]


def test_reviewed_target_pid_drift_fails_closed():
    case = _case()
    first = TargetSafetyGuard(tool_runner=SafetyRunner())
    reviewed = first.prepare_response(
        case,
        _response_node().node_map()["r"],
        {"pid": 4242, "expected_path": PATH},
    )
    reviewed = json.loads(json.dumps(reviewed))
    reviewed["process"]["pid"] = 9999

    guard = TargetSafetyGuard(tool_runner=SafetyRunner(), reviewed_target=reviewed)
    guard.validate_case_input(_case())
    with pytest.raises(TargetSafetyError) as caught:
        guard.prepare_response(
            _case(),
            _response_node().node_map()["r"],
            {"pid": 4242, "expected_path": PATH},
        )
    assert caught.value.status == "target_drift"
    assert "process.pid" in caught.value.details["differences"]


def test_expected_manx_identity_is_bound_to_response_lock():
    case = _case()
    guard = TargetSafetyGuard(
        tool_runner=SafetyRunner(),
        run_id="run-safety-001",
        expected_target=_expected_target(),
    )

    lock = guard.prepare_response(
        case,
        _response_node().node_map()["r"],
        {"pid": 4242, "expected_path": PATH},
    )

    assert lock["run_id"] == "run-safety-001"
    assert lock["manx_paw"] == "manx-paw-001"
    assert lock["group"] == "c2t-run-001-target"
    assert lock["host"] == "WIN10"
    assert lock["contact"] == "tcp"
    prompt_projection = json.dumps(case.compact_summary())
    assert "run-safety-001" not in prompt_projection
    assert "manx-paw-001" not in prompt_projection


def test_expected_manx_identity_drift_is_blocked_before_response():
    guard = TargetSafetyGuard(
        tool_runner=SafetyRunner(),
        run_id="AF-MAAS-WIN-01-r01",
        expected_target=_expected_target(pid=9191),
    )

    with pytest.raises(TargetSafetyError) as caught:
        guard.prepare_response(
            _case(),
            _response_node().node_map()["r"],
            {"pid": 4242, "expected_path": PATH},
        )

    assert caught.value.status == "target_drift"
    assert "process.pid" in caught.value.details["differences"]


def test_orchestrator_preserves_protected_target_terminal_status():
    case = _case()
    case.strategy_tree = _response_node()
    node = case.strategy_tree.node_map()["r"]
    decision = case.add_audit_decision(AuditDecision(
        node_id=node.node_id,
        verdict=AuditVerdict.APPROVED,
        reason="test",
    ))
    node.audit_decision_id = decision.decision_id
    guard = TargetSafetyGuard(tool_runner=SafetyRunner(), protected_processes=[{
        "label": "control-sandcat",
        "pid": 4242,
        "creation_time_utc": CREATED,
        "path": PATH,
        "canonical_path": PATH.lower(),
        "sha256": HASH,
    }])
    orchestrator = C2TraceOrchestrator(
        planner=object(),
        auditor=AuditorAgent(target_validator=TargetIdentityValidator(guard)),
        executor=ExecutorAgent(tool_runner=guard.tool_runner),
    )

    with pytest.raises(TargetSafetyError) as caught:
        orchestrator.auditor.target_validator.lock_response(
            case,
            node,
            {"pid": 4242, "expected_path": PATH},
        )
    orchestrator._fail_target_safety(
        case,
        node,
        {"pid": 4242, "expected_path": PATH},
        caught.value,
    )
    orchestrator._finalize_status(case)

    assert case.final_status == "protected_target_blocked"
    assert case.errors[-1]["error_type"] == "wrong_target"
    assert not any(tool == "kill_process" for tool, _ in guard.tool_runner.calls)


def test_safety_input_loaders_validate_and_compact_summary_does_not_leak(tmp_path):
    manifest = tmp_path / "protected.json"
    manifest.write_text(json.dumps({
        "schema_version": PROTECTED_PROCESSES_SCHEMA,
        "processes": [{
            "label": "control-sandcat",
            "paw": "control-paw",
            "pid": 1111,
            "creation_time_utc": CREATED,
            "path": r"C:\Users\Public\control_sandcat.exe",
            "sha256": "b" * 64,
            "group": "c2t-control",
            "host": "WIN10",
            "contact": "http",
        }],
    }), encoding="utf-8")
    loaded = load_protected_processes(manifest)
    assert loaded.payload["processes"][0]["canonical_path"].endswith("control_sandcat.exe")

    case = _case()
    lock = TargetSafetyGuard(tool_runner=SafetyRunner()).prepare_response(
        case,
        _response_node().node_map()["r"],
        {"pid": 4242, "expected_path": PATH},
    )
    casefile = tmp_path / "casefile.json"
    casefile.write_text(json.dumps(case.to_dict()), encoding="utf-8")
    reviewed = load_reviewed_target(casefile)
    assert reviewed.payload["lock_id"] == lock["lock_id"]
    assert "response_target_lock" not in case.compact_summary()
    assert "control-sandcat" not in json.dumps(case.compact_summary())

    invalid = tmp_path / "invalid.json"
    invalid.write_text(json.dumps({"schema_version": PROTECTED_PROCESSES_SCHEMA, "processes": [{}]}), encoding="utf-8")
    with pytest.raises(TargetSafetyInputError):
        load_protected_processes(invalid)


def test_protected_manifest_normalizes_optional_run_and_expected_manx_context(tmp_path):
    manifest = tmp_path / "protected-with-target.json"
    manifest.write_text(json.dumps({
        "schema_version": PROTECTED_PROCESSES_SCHEMA,
        "run_id": "AF-MAAS-WIN-01-r01",
        "expected_target": _expected_target(),
        "processes": [{
            "label": "control-sandcat",
            "pid": 1111,
            "creation_time_utc": CREATED,
            "path": r"C:\Users\Public\control_sandcat.exe",
            "sha256": "b" * 64,
        }],
    }), encoding="utf-8")

    loaded = load_protected_processes(manifest)

    assert loaded.payload["run_id"] == "AF-MAAS-WIN-01-r01"
    assert loaded.payload["expected_target"]["paw"] == "manx-paw-001"
    assert loaded.payload["expected_target"]["canonical_path"].endswith("c2t_run_001.exe")

    missing_run = tmp_path / "missing-run.json"
    missing_run.write_text(json.dumps({
        "schema_version": PROTECTED_PROCESSES_SCHEMA,
        "expected_target": _expected_target(),
        "processes": loaded.payload["processes"],
    }), encoding="utf-8")
    with pytest.raises(TargetSafetyInputError, match="requires run_id"):
        load_protected_processes(missing_run)
