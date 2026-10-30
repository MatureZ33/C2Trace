from c2trace.agents import AuditorAgent, ExecutorAgent, PlannerAgent
from c2trace.kb import C2KnowledgePack
from c2trace.models import ActionResult, CaseFile, Finding, MinimalAlert, NodeStatus, StrategyTree
from c2trace.orchestrator import C2TraceOrchestrator
from c2trace.reporter import Reporter
from c2trace.tools import ToolResult


def _kb():
    return C2KnowledgePack("template", "tools", "evidence", "safety")


def _alert():
    return MinimalAlert.from_dict({
        "case_id": "S002",
        "alert_id": "S002-A001",
        "source": "benchmark_seed_alert",
        "alert_type": "c2_http_beacon",
        "victim_ip": "192.168.21.138",
        "remote_ip": "192.168.21.132",
        "remote_port": 8888,
        "protocol": "http",
        "confidence": 0.75,
    })


class S002LLM:
    def __init__(self):
        self.calls = 0

    def chat_json(self, **kwargs):
        self.calls += 1
        return {
            "tree_id": "tree-s002",
            "root_objective": "Trace HTTP C2 seed",
            "nodes": [
                {"node_id": "n1", "type": "investigate", "goal": "confirm C2 connection", "tool": "check_network", "arguments": {"remote_ip": "{{alert.remote_ip}}", "remote_port": "{{alert.remote_port}}"}, "on_success": ["n2"], "on_failure": ["n11"]},
                {"node_id": "n2", "type": "decision", "goal": "active_connection_found?", "condition": "active_connection_found", "requires": ["n1"], "on_success": ["n3", "n4", "n5"], "on_failure": ["n11"]},
                {"node_id": "n3", "type": "investigate", "goal": "process tree", "tool": "check_process_tree", "arguments": {"pid": "{{evidence.pid}}"}, "requires": ["n2"]},
                {"node_id": "n4", "type": "investigate", "goal": "file metadata", "tool": "check_file_metadata", "arguments": {"file_path": "{{evidence.process_path}}"}, "requires": ["n2"]},
                {"node_id": "n5", "type": "investigate", "goal": "persistence", "tool": "check_persistence_all", "arguments": {"process_path": "{{evidence.process_path}}"}, "requires": ["n2"]},
                {"node_id": "n6", "type": "decision", "goal": "evidence_sufficient_for_response?", "condition": "evidence_sufficient_for_response", "requires": ["n3", "n4", "n5"], "on_success": ["n7", "n8", "n9"], "on_failure": ["n11"]},
                {"node_id": "n7", "type": "response", "goal": "kill process", "tool": "kill_process", "arguments": {"pid": "{{evidence.pid}}", "expected_path": "{{evidence.process_path}}"}, "requires": ["n6"]},
                {"node_id": "n8", "type": "response", "goal": "remove file", "tool": "remove_file", "arguments": {"file_path": "{{evidence.process_path}}"}, "requires": ["n6"]},
                {"node_id": "n9", "type": "response", "goal": "remove registry", "tool": "remove_registry", "arguments": {"reg_path": "{{evidence.persistence.reg_path}}", "value_name": "{{evidence.persistence.value_name}}", "expected_value": "{{evidence.persistence.expected_value}}"}, "requires": ["n6"]},
                {"node_id": "n10", "type": "verify", "goal": "verify cleanup", "tool": "verify_cleanup", "arguments": {"remote_ip": "{{alert.remote_ip}}", "remote_port": "{{alert.remote_port}}", "file_path": "{{evidence.process_path}}", "pid": "{{evidence.pid}}"}, "requires": ["n7", "n8", "n9"]},
                {"node_id": "n11", "type": "verify", "goal": "verify no cleanup", "tool": "verify_cleanup", "arguments": {"remote_ip": "{{alert.remote_ip}}"}, "requires": ["n1"]},
            ],
        }


class FakeRunner:
    def __init__(self, execute_response=True):
        self.execute_response = execute_response
        self.calls = []

    def run(self, tool, params=None):
        params = params or {}
        self.calls.append((tool, params))
        path = "C:\\Users\\Public\\sandcat_s002.exe"
        if tool == "check_network":
            return ToolResult(True, data={"connections": [{
                "remote_address": "192.168.21.132",
                "remote_port": 8888,
                "pid": 5252,
                "process_name": "sandcat_s002",
                "process_path": path,
            }]})
        if tool == "check_process_tree":
            return ToolResult(True, data={"trees": [{"root": {"pid": 5252, "name": "sandcat_s002.exe", "path": path}, "chain": [{"pid": 5252, "name": "sandcat_s002.exe", "path": path}, {"pid": 111, "name": "powershell.exe"}]}]})
        if tool == "check_file_metadata":
            return ToolResult(True, data={"file": {"exists": True, "path": path, "sha256": "abc"}})
        if tool == "check_persistence_all":
            return ToolResult(True, data={"registry_run_keys": [{"path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "S002Sandcat", "value": path}], "scheduled_tasks": [], "services": []})
        if tool in {"kill_process", "remove_file", "remove_registry", "remove_scheduled_task"}:
            if not self.execute_response:
                return ToolResult(True, data={"dry_run": True, "tool": tool, "params": params})
            return ToolResult(True, data={"executed": True, "tool": tool, **params})
        if tool == "verify_cleanup":
            return ToolResult(True, data={"network": {"connections": []}, "file_exists": False, "processes": [], "persistence": {"registry_run_keys": [], "scheduled_tasks": [], "services": []}})
        return ToolResult(True, data={})


class InboundFakeRunner(FakeRunner):
    def run(self, tool, params=None):
        params = params or {}
        if tool == "check_network" and params.get("network_mode") == "inbound_listener":
            self.calls.append((tool, params))
            return ToolResult(True, data={"connections": [{
                "local_address": "192.168.21.138",
                "local_port": 18768,
                "remote_address": "0.0.0.0",
                "remote_port": 0,
                "state": "Listen",
                "pid": 5252,
                "process_name": "sandcat_s002",
                "process_path": r"C:\Users\Public\sandcat_s002.exe",
            }]})
        return super().run(tool, params)


class ConvergingBranchLLM:
    def __init__(self):
        self.calls = 0

    def chat_json(self, **kwargs):
        self.calls += 1
        return {
            "tree_id": "tree-converging-branch",
            "root_objective": "Keep shared branch convergence nodes eligible",
            "nodes": [
                {"node_id": "n1", "type": "investigate", "goal": "confirm C2 connection", "tool": "check_network", "arguments": {"remote_ip": "{{alert.remote_ip}}", "remote_port": "{{alert.remote_port}}"}, "on_success": ["n2"]},
                {"node_id": "n2", "type": "decision", "goal": "active_connection_found?", "condition": "active_connection_found", "requires": ["n1"], "on_success": ["n3"], "on_failure": ["n6"]},
                {"node_id": "n3", "type": "investigate", "goal": "process tree", "tool": "check_process_tree", "arguments": {"pid": "{{evidence.pid}}"}, "requires": ["n2"], "on_success": ["n4"], "on_failure": ["n4"]},
                {"node_id": "n4", "type": "decision", "goal": "evidence_sufficient_for_response?", "condition": "evidence_sufficient_for_response", "requires": ["n3"], "on_success": ["n5"], "on_failure": ["n6"]},
                {"node_id": "n5", "type": "response", "goal": "kill process", "tool": "kill_process", "arguments": {"pid": "{{evidence.pid}}"}, "requires": ["n4"]},
                {"node_id": "n6", "type": "verify", "goal": "verify no cleanup", "tool": "verify_cleanup", "arguments": {"remote_ip": "{{alert.remote_ip}}"}, "requires": ["n4"]},
            ],
        }


def test_shared_on_success_and_on_failure_node_is_not_skipped():
    llm = ConvergingBranchLLM()
    orchestrator = C2TraceOrchestrator(
        planner=PlannerAgent(llm_client=llm, knowledge_pack=_kb()),
        auditor=AuditorAgent(llm_client=llm),
        executor=ExecutorAgent(tool_runner=FakeRunner(execute_response=False)),
        max_steps=10,
    )

    case = orchestrator.run_alert(_alert())
    nodes = case.strategy_tree.node_map()

    assert nodes["n4"].status != NodeStatus.SKIPPED
    assert any(event.event_type == "node_selected" and "n4 decision" in event.summary for event in case.timeline)


def test_full_s002_flow_executes_audited_response():
    llm = S002LLM()
    runner = FakeRunner(execute_response=True)
    orchestrator = C2TraceOrchestrator(
        planner=PlannerAgent(llm_client=llm, knowledge_pack=_kb()),
        auditor=AuditorAgent(llm_client=llm),
        executor=ExecutorAgent(tool_runner=runner),
        max_steps=30,
    )

    case = orchestrator.run_alert(_alert())

    assert llm.calls >= 1
    assert case.final_status == "completed"
    assert any(f.finding_type == "network_confirmed" for f in case.findings)
    assert any(f.finding_type == "persistence_linked_to_payload" for f in case.findings)
    assert any(f.finding_type == "response_action_executed" for f in case.findings)
    assert any(d.verdict.value == "approved" for d in case.audit_decisions)
    assert any(tool == "kill_process" and params.get("process_name") == "sandcat_s002" for tool, params in runner.calls)
    assert ("remove_file", {"file_path": "C:\\Users\\Public\\sandcat_s002.exe"}) in runner.calls
    assert case.final_report is not None
    assert "## Evidence Chain" in Reporter.to_markdown(case.final_report)


def test_full_inbound_listener_flow_executes_audited_response():
    alert = MinimalAlert.from_dict({
        "case_id": "inbound-flow",
        "alert_id": "inbound-flow-alert",
        "source": "suricata_eve",
        "alert_type": "c2_http_beacon",
        "victim_ip": "192.168.21.138",
        "remote_ip": "192.168.21.132",
        "remote_port": 46182,
        "protocol": "http",
        "confidence": 0.75,
    })
    source_event = {
        "src_ip": "192.168.21.132",
        "src_port": 46182,
        "dest_ip": "192.168.21.138",
        "dest_port": 18768,
        "proto": "tcp",
    }
    llm = S002LLM()
    runner = InboundFakeRunner(execute_response=True)
    orchestrator = C2TraceOrchestrator(
        planner=PlannerAgent(llm_client=llm, knowledge_pack=_kb()),
        auditor=AuditorAgent(llm_client=llm),
        executor=ExecutorAgent(tool_runner=runner),
        max_steps=30,
    )

    case = orchestrator.run_alert(alert, source_events=[source_event])

    assert case.final_status == "completed"
    assert any(
        tool == "check_network"
        and params.get("network_mode") == "inbound_listener"
        and params.get("local_port") == 18768
        for tool, params in runner.calls
    )
    assert case.attributed_process()["pid"] == 5252
    assert any(f.finding_type == "response_action_executed" for f in case.findings)


def test_response_dry_run_without_execute_response():
    runner = FakeRunner(execute_response=False)
    orchestrator = C2TraceOrchestrator(
        planner=PlannerAgent(llm_client=S002LLM(), knowledge_pack=_kb()),
        auditor=AuditorAgent(llm_client=S002LLM()),
        executor=ExecutorAgent(tool_runner=runner),
        max_steps=30,
    )

    case = orchestrator.run_alert(_alert())

    assert case.final_status == "completed_dry_run"
    assert any(f.finding_type == "response_action_dry_run" for f in case.findings)
    assert any(tool == "kill_process" and params.get("process_name") == "sandcat_s002" for tool, params in runner.calls)
    assert ("remove_file", {"file_path": "C:\\Users\\Public\\sandcat_s002.exe"}) in runner.calls


class ScheduledTaskLLM(S002LLM):
    def chat_json(self, **kwargs):
        self.calls += 1
        return {
            "tree_id": "tree-s003-scheduled-task",
            "root_objective": "Trace HTTP C2 seed with scheduled task persistence",
            "nodes": [
                {"node_id": "n1", "type": "investigate", "goal": "confirm C2 connection", "tool": "check_network", "arguments": {"remote_ip": "{{alert.remote_ip}}", "remote_port": "{{alert.remote_port}}"}, "on_success": ["n2"]},
                {"node_id": "n2", "type": "decision", "goal": "active_connection_found?", "condition": "active_connection_found", "requires": ["n1"], "on_success": ["n3", "n4", "n5"], "on_failure": ["n10"]},
                {"node_id": "n3", "type": "investigate", "goal": "process tree", "tool": "check_process_tree", "arguments": {"pid": "{{evidence.pid}}"}, "requires": ["n2"]},
                {"node_id": "n4", "type": "investigate", "goal": "file metadata", "tool": "check_file_metadata", "arguments": {"file_path": "{{evidence.process_path}}"}, "requires": ["n2"]},
                {"node_id": "n5", "type": "investigate", "goal": "persistence", "tool": "check_persistence_all", "arguments": {"process_path": "{{evidence.process_path}}"}, "requires": ["n2"]},
                {"node_id": "n6", "type": "decision", "goal": "evidence_sufficient_for_response?", "condition": "evidence_sufficient_for_response", "requires": ["n3", "n4", "n5"], "on_success": ["n7", "n8", "n9"], "on_failure": ["n10"]},
                {"node_id": "n7", "type": "response", "goal": "kill process", "tool": "kill_process", "arguments": {"pid": "{{evidence.pid}}", "expected_path": "{{evidence.process_path}}"}, "requires": ["n6"]},
                {"node_id": "n8", "type": "response", "goal": "remove file", "tool": "remove_file", "arguments": {"file_path": "{{evidence.process_path}}"}, "requires": ["n6"]},
                {"node_id": "n9", "type": "response", "goal": "remove scheduled task", "tool": "remove_scheduled_task", "arguments": {"task_name": "{{evidence.persistence.task_name}}", "task_path": "{{evidence.persistence.task_path}}"}, "requires": ["n6"]},
                {"node_id": "n10", "type": "verify", "goal": "verify cleanup", "tool": "verify_cleanup", "arguments": {"remote_ip": "{{alert.remote_ip}}", "remote_port": "{{alert.remote_port}}", "file_path": "{{evidence.process_path}}", "pid": "{{evidence.pid}}"}, "requires": ["n7", "n8", "n9"]},
            ],
        }


class ScheduledTaskRunner(FakeRunner):
    def run(self, tool, params=None):
        params = params or {}
        if tool == "check_persistence_all":
            self.calls.append((tool, params))
            path = "C:\\Users\\Public\\sandcat_s002.exe"
            return ToolResult(True, data={
                "registry_run_keys": [],
                "scheduled_tasks": [{"name": "S003SandcatTask", "path": "\\", "actions": [path]}],
                "services": [],
            })
        return super().run(tool, params)


def test_scheduled_task_persistence_cleanup_uses_task_response_tool():
    runner = ScheduledTaskRunner(execute_response=False)
    orchestrator = C2TraceOrchestrator(
        planner=PlannerAgent(llm_client=ScheduledTaskLLM(), knowledge_pack=_kb()),
        auditor=AuditorAgent(llm_client=ScheduledTaskLLM()),
        executor=ExecutorAgent(tool_runner=runner),
        max_steps=30,
    )

    case = orchestrator.run_alert(_alert())

    assert case.final_status == "completed_dry_run"
    assert any(f.finding_type == "persistence_linked_to_payload" and f.details.get("category") == "scheduled_tasks" for f in case.findings)
    assert ("remove_scheduled_task", {"task_name": "S003SandcatTask", "task_path": "\\"}) in runner.calls


class RegistryOnlyPersistenceLLM(S002LLM):
    def chat_json(self, **kwargs):
        self.calls += 1
        return {
            "tree_id": "tree-registry-only-persistence-plan",
            "root_objective": "Trace HTTP C2 seed with persistence coverage added by planner normalization",
            "nodes": [
                {"node_id": "n1", "type": "investigate", "goal": "confirm C2 connection", "tool": "check_network", "arguments": {"remote_ip": "{{alert.remote_ip}}", "remote_port": "{{alert.remote_port}}"}, "on_success": ["n2"]},
                {"node_id": "n2", "type": "decision", "goal": "active_connection_found?", "condition": "active_connection_found", "requires": ["n1"], "on_success": ["n3", "n4", "n5"], "on_failure": ["n10"]},
                {"node_id": "n3", "type": "investigate", "goal": "process tree", "tool": "check_process_tree", "arguments": {"pid": "{{evidence.pid}}"}, "requires": ["n2"]},
                {"node_id": "n4", "type": "investigate", "goal": "file metadata", "tool": "check_file_metadata", "arguments": {"file_path": "{{evidence.process_path}}"}, "requires": ["n2"]},
                {"node_id": "n5", "type": "investigate", "goal": "persistence", "tool": "check_persistence_all", "arguments": {"process_path": "{{evidence.process_path}}"}, "requires": ["n2"]},
                {"node_id": "n6", "type": "decision", "goal": "evidence_sufficient_for_response?", "condition": "evidence_sufficient_for_response", "requires": ["n3", "n4", "n5"], "on_success": ["n7", "n8", "n9"], "on_failure": ["n10"]},
                {"node_id": "n7", "type": "response", "goal": "kill process", "tool": "kill_process", "arguments": {"pid": "{{evidence.pid}}", "expected_path": "{{evidence.process_path}}"}, "requires": ["n6"]},
                {"node_id": "n8", "type": "response", "goal": "remove file", "tool": "remove_file", "arguments": {"file_path": "{{evidence.process_path}}"}, "requires": ["n6"]},
                {"node_id": "n9", "type": "response", "goal": "remove registry", "tool": "remove_registry", "arguments": {"reg_path": "{{evidence.persistence.reg_path}}", "value_name": "{{evidence.persistence.value_name}}", "expected_value": "{{evidence.persistence.expected_value}}"}, "requires": ["n6"]},
                {"node_id": "n10", "type": "verify", "goal": "verify cleanup", "tool": "verify_cleanup", "arguments": {"remote_ip": "{{alert.remote_ip}}", "remote_port": "{{alert.remote_port}}", "file_path": "{{evidence.process_path}}", "pid": "{{evidence.pid}}"}, "requires": ["n7", "n8", "n9"]},
            ],
        }


class MissingPathScheduledTaskRunner(FakeRunner):
    def run(self, tool, params=None):
        params = params or {}
        self.calls.append((tool, params))
        sandcat_name = "sandcat_s003.exe"
        if tool == "check_network":
            return ToolResult(True, data={"connections": [{
                "remote_address": "192.168.21.132",
                "remote_port": 8888,
                "pid": 11376,
                "process_name": "sandcat_s003",
                "process_path": None,
            }]})
        if tool == "check_process_tree":
            return ToolResult(True, data={"trees": [{
                "root": {"pid": 11376, "name": sandcat_name, "path": None, "parent_pid": 1808},
                "chain": [
                    {"pid": 11376, "name": sandcat_name, "path": None, "parent_pid": 1808},
                    {"pid": 1808, "name": "powershell.exe", "path": None, "parent_pid": 5808},
                    {"pid": 5808, "name": "explorer.exe", "path": "C:\\Windows\\Explorer.EXE"},
                ],
            }]})
        if tool == "check_file_metadata":
            return ToolResult(True, data={"file": {"exists": False, "path": params.get("file_path", "")}})
        if tool == "check_persistence_all":
            return ToolResult(True, data={
                "registry_run_keys": [{"path": "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "SecurityHealth", "value": "C:\\Windows\\system32\\SecurityHealthSystray.exe"}],
                "scheduled_tasks": [{"name": "S003SandcatTask", "path": "\\", "actions": ['"C:\\Users\\Public\\sandcat_s003.exe" -server http://192.168.21.132:8888 -group red -v']}],
                "services": [],
            })
        if tool in {"kill_process", "remove_file", "remove_registry", "remove_scheduled_task", "remove_service"}:
            if not self.execute_response:
                return ToolResult(True, data={"dry_run": True, "tool": tool, "params": params})
            return ToolResult(True, data={"executed": True, "tool": tool, **params})
        return ToolResult(True, data={})


def test_missing_process_path_does_not_promote_parent_or_system_run_key():
    runner = MissingPathScheduledTaskRunner(execute_response=False)
    orchestrator = C2TraceOrchestrator(
        planner=PlannerAgent(llm_client=RegistryOnlyPersistenceLLM(), knowledge_pack=_kb()),
        auditor=AuditorAgent(llm_client=RegistryOnlyPersistenceLLM()),
        executor=ExecutorAgent(tool_runner=runner),
        max_steps=40,
    )

    case = orchestrator.run_alert(_alert())

    assert case.latest_process_path() == ""
    assert ("check_file_metadata", {"file_path": "C:\\Windows\\Explorer.EXE"}) not in runner.calls
    assert any(f.finding_type == "persistence_linked_to_payload" and f.value == "S003SandcatTask" for f in case.findings)
    assert not any(f.finding_type == "persistence_linked_to_payload" and f.value == "SecurityHealth" for f in case.findings)
    assert ("remove_scheduled_task", {"task_name": "S003SandcatTask", "task_path": "\\"}) in runner.calls


class ProtectedPathLLM:
    def __init__(self):
        self.calls = 0

    def chat_json(self, **kwargs):
        self.calls += 1
        return {
            "tree_id": "tree-reject",
            "root_objective": "Reject unsafe response target",
            "nodes": [
                {"node_id": "n1", "type": "investigate", "goal": "confirm C2 connection", "tool": "check_network", "arguments": {"remote_ip": "{{alert.remote_ip}}", "remote_port": "{{alert.remote_port}}"}, "on_success": ["n2a", "n2b"]},
                {"node_id": "n2a", "type": "investigate", "goal": "process tree", "tool": "check_process_tree", "arguments": {"pid": "{{evidence.pid}}"}, "requires": ["n1"]},
                {"node_id": "n2b", "type": "investigate", "goal": "file metadata", "tool": "check_file_metadata", "arguments": {"file_path": "{{evidence.process_path}}"}, "requires": ["n1"]},
                {"node_id": "n2", "type": "decision", "goal": "evidence_sufficient_for_response?", "condition": "evidence_sufficient_for_response", "requires": ["n2a", "n2b"], "on_success": ["n3"], "on_failure": ["n4"]},
                {"node_id": "n3", "type": "response", "goal": "unsafe remove", "tool": "remove_file", "arguments": {"file_path": "C:\\Windows\\System32\\kernel32.dll"}, "requires": ["n2"]},
                {"node_id": "n4", "type": "verify", "goal": "verify no cleanup", "tool": "verify_cleanup", "arguments": {"remote_ip": "{{alert.remote_ip}}"}, "requires": ["n3"]},
            ],
        }


def test_planner_supplied_protected_path_is_overridden_by_attributed_evidence():
    llm = ProtectedPathLLM()
    orchestrator = C2TraceOrchestrator(
        planner=PlannerAgent(llm_client=llm, knowledge_pack=_kb()),
        auditor=AuditorAgent(llm_client=llm),
        executor=ExecutorAgent(tool_runner=FakeRunner(execute_response=True)),
        max_steps=20,
    )

    case = orchestrator.run_alert(_alert())
    response_node = case.strategy_tree.node_map()["n3"]

    assert any(d.verdict.value == "approved" for d in case.audit_decisions)
    assert response_node.status == NodeStatus.SUCCEEDED
    assert not any(
        tool == "remove_file" and params.get("file_path") == "C:\\Windows\\System32\\kernel32.dll"
        for tool, params in orchestrator.executor.tool_runner.calls
    )
    assert (
        "remove_file",
        {"file_path": "C:\\Users\\Public\\sandcat_s002.exe"},
    ) in orchestrator.executor.tool_runner.calls


def test_orchestrator_blocks_direct_response_execution_without_audit():
    runner = FakeRunner(execute_response=True)
    orchestrator = C2TraceOrchestrator(
        planner=PlannerAgent(llm_client=S002LLM(), knowledge_pack=_kb()),
        auditor=AuditorAgent(llm_client=S002LLM()),
        executor=ExecutorAgent(tool_runner=runner),
    )
    case = CaseFile.from_alert(_alert())
    case.strategy_tree = StrategyTree.from_dict(S002LLM().chat_json())
    response = case.strategy_tree.node_map()["n7"]

    orchestrator._execute_node(case, response)

    assert not runner.calls
    assert response.status == NodeStatus.FAILED
    assert case.action_results[-1].success is False
    assert "approved audit" in (case.action_results[-1].error or "")


class VerificationFailureRunner(FakeRunner):
    def run(self, tool, params=None):
        if tool == "verify_cleanup":
            self.calls.append((tool, params or {}))
            return ToolResult(False, error="verification command failed")
        return super().run(tool, params)


def test_executed_response_is_not_completed_when_verification_fails():
    runner = VerificationFailureRunner(execute_response=True)
    orchestrator = C2TraceOrchestrator(
        planner=PlannerAgent(llm_client=S002LLM(), knowledge_pack=_kb()),
        auditor=AuditorAgent(llm_client=S002LLM()),
        executor=ExecutorAgent(tool_runner=runner),
        max_steps=30,
    )

    case = orchestrator.run_alert(_alert())

    assert any(f.finding_type == "response_action_executed" for f in case.findings)
    assert case.final_status == "verification_failed"
    assert any(error["error_type"] == "cleanup_verification_failed" for error in case.errors)


class ResponseFailureRunner(FakeRunner):
    def run(self, tool, params=None):
        if tool == "remove_file":
            self.calls.append((tool, params or {}))
            return ToolResult(False, error="remove failed")
        return super().run(tool, params)


def test_one_successful_response_does_not_hide_another_response_failure():
    runner = ResponseFailureRunner(execute_response=True)
    orchestrator = C2TraceOrchestrator(
        planner=PlannerAgent(llm_client=S002LLM(), knowledge_pack=_kb()),
        auditor=AuditorAgent(llm_client=S002LLM()),
        executor=ExecutorAgent(tool_runner=runner),
        max_steps=30,
    )

    case = orchestrator.run_alert(_alert())

    assert any(f.finding_type == "response_action_executed" for f in case.findings)
    assert any(result.tool == "remove_file" and not result.success for result in case.action_results)
    assert case.final_status == "response_failed"


class LiteralResponseTargetLLM(S002LLM):
    def chat_json(self, **kwargs):
        payload = super().chat_json(**kwargs)
        for node in payload.get("nodes", []):
            if node.get("tool") == "kill_process":
                node["arguments"] = {"pid": 4, "process_name": "System", "expected_path": ""}
        return payload


def test_llm_literal_response_identity_is_overridden_by_network_evidence():
    runner = FakeRunner(execute_response=False)
    orchestrator = C2TraceOrchestrator(
        planner=PlannerAgent(llm_client=LiteralResponseTargetLLM(), knowledge_pack=_kb()),
        auditor=AuditorAgent(llm_client=LiteralResponseTargetLLM()),
        executor=ExecutorAgent(tool_runner=runner),
        max_steps=30,
    )

    case = orchestrator.run_alert(_alert())

    kill_calls = [params for tool, params in runner.calls if tool == "kill_process"]
    assert case.final_status == "completed_dry_run"
    assert kill_calls
    assert kill_calls[0]["pid"] == 5252
    assert kill_calls[0]["process_name"] == "sandcat_s002"
    assert kill_calls[0]["expected_path"] == "C:\\Users\\Public\\sandcat_s002.exe"


def test_auditor_does_not_match_pid_by_substring():
    case = CaseFile.from_alert(_alert())
    case.add_finding(Finding(
        "network_connection",
        "192.168.21.132:8888",
        "PID 5252 owns the exact C2 connection on port 443",
        "executor",
        details={
            "remote_address": "192.168.21.132",
            "remote_port": 8888,
            "pid": 5252,
            "process_name": "sandcat_s002",
        },
    ))
    node = StrategyTree.from_dict(S002LLM().chat_json()).node_map()["n7"]

    decision = AuditorAgent(llm_client=S002LLM()).audit(case, node, {"pid": 4})

    assert decision.verdict.value != "approved"
    assert "exactly match" in decision.reason


def test_auditor_strict_llm_failure_rejects_without_authorization():
    class FailingAuditorLLM:
        usage_records = []

        def chat_json(self, **_kwargs):
            from c2trace.llm import LLMError

            raise LLMError("DeepSeek HTTP 503")

    case = CaseFile.from_alert(_alert())
    case.add_finding(Finding(
        "network_connection",
        "192.168.21.132:8888",
        "exact network owner",
        "executor",
        details={
            "remote_address": "192.168.21.132",
            "remote_port": 8888,
            "pid": 5252,
            "process_name": "sandcat_s002",
        },
    ))
    node = StrategyTree.from_dict(S002LLM().chat_json()).node_map()["n7"]
    auditor = AuditorAgent(llm_client=FailingAuditorLLM(), require_llm=True)

    decision = auditor.audit(case, node, {"pid": 5252})

    assert decision.verdict.value == "rejected"
    assert auditor.authorization_for(decision.decision_id) is None
    assert any(error["error_type"] == "auditor_llm_failed" for error in case.to_dict()["errors"])


def test_domain_only_seed_cannot_promote_unfiltered_connections_to_c2_evidence():
    alert = MinimalAlert.from_dict({
        "case_id": "domain-only",
        "remote_domain": "c2.example",
        "remote_port": 8888,
        "protocol": "http",
    })
    runner = FakeRunner(execute_response=False)
    orchestrator = C2TraceOrchestrator(
        planner=PlannerAgent(llm_client=S002LLM(), knowledge_pack=_kb()),
        auditor=AuditorAgent(llm_client=S002LLM()),
        executor=ExecutorAgent(tool_runner=runner),
        max_steps=30,
    )

    case = orchestrator.run_alert(alert)

    assert not any(f.finding_type == "network_confirmed" for f in case.findings)
    assert not any(tool in {"kill_process", "remove_file"} for tool, _ in runner.calls)
    assert case.final_status == "attribution_inconclusive"


def test_outbound_network_query_does_not_filter_by_local_port():
    """Multi-instance C2 implants may use different ephemeral local ports to the
    same remote C2 endpoint.  Outbound check_network must NOT inject local_port
    so that ALL sibling connections are discovered for sibling-process attribution."""
    case = CaseFile.from_alert(_alert(), source_events=[{
        "src_ip": "192.168.21.138",
        "src_port": 50123,
        "dest_ip": "192.168.21.132",
        "dest_port": 8888,
    }])
    tree = StrategyTree.from_dict(S002LLM().chat_json())
    case.strategy_tree = tree
    orchestrator = C2TraceOrchestrator(planner=None, auditor=None, executor=None)

    args = orchestrator._resolve_arguments(case, tree.node_map()["n1"])

    assert args == {
        "remote_ip": "192.168.21.132",
        "remote_port": 8888,
        "network_mode": "outbound_active_flow",
    }


def test_inbound_suricata_flow_is_bound_to_exact_listener_and_process():
    inbound_alert = MinimalAlert.from_dict({
        "case_id": "inbound",
        "victim_ip": "192.168.21.138",
        "remote_ip": "192.168.21.132",
        "remote_port": 46182,
        "protocol": "http",
    })
    case = CaseFile.from_alert(inbound_alert, source_events=[{
        "src_ip": "192.168.21.132",
        "src_port": 46182,
        "dest_ip": "192.168.21.138",
        "dest_port": 18768,
        "proto": "tcp",
    }])
    tree = StrategyTree.from_dict(S002LLM().chat_json())
    case.strategy_tree = tree
    orchestrator = C2TraceOrchestrator(planner=None, auditor=None, executor=None)
    node = tree.node_map()["n1"]

    args = orchestrator._resolve_arguments(case, node)

    assert args == {
        "remote_ip": "192.168.21.132",
        "remote_port": 46182,
        "local_port": 18768,
        "network_mode": "inbound_listener",
        "local_ip": "192.168.21.138",
    }

    result = ActionResult(
        node_id="n1",
        tool="check_network",
        success=True,
        data={
            "connections": [{
                "local_address": "192.168.21.138",
                "local_port": 18768,
                "remote_address": "0.0.0.0",
                "remote_port": 0,
                "state": "Listen",
                "pid": 14360,
                "process_name": "webshell",
                "process_path": r"C:\Users\Public\webshell.exe",
            }]
        },
        arguments=args,
    )
    executor = ExecutorAgent(tool_runner=FakeRunner(execute_response=False))
    for finding in executor._derive_findings(case, node, result, args):
        case.add_finding(finding)

    assert case.attributed_process() == {
        "pid": 14360,
        "process_name": "webshell",
        "process_path": r"C:\Users\Public\webshell.exe",
    }
    assert AuditorAgent._has_network_evidence(case) is True
    network = next(
        finding for finding in case.findings
        if finding.finding_type == "network_connection"
    )
    assert network.details["src_ip"] == "192.168.21.132"
    assert network.details["dest_port"] == 18768
    assert network.details["listener"]["state"] == "Listen"


def test_completion_requires_verification_for_each_response_result():
    case = CaseFile.from_alert(_alert())
    first = case.add_result(ActionResult(
        node_id="r1",
        tool="remove_file",
        success=True,
        data={"removed": True},
        arguments={"file_path": "C:\\Users\\Public\\a.exe"},
    ))
    second = case.add_result(ActionResult(
        node_id="r2",
        tool="remove_file",
        success=True,
        data={"removed": True},
        arguments={"file_path": "C:\\Users\\Public\\b.exe"},
    ))
    verification = case.add_result(ActionResult(
        node_id="v",
        tool="verify_cleanup",
        success=True,
        data={},
    ))
    case.add_finding(Finding(
        "cleanup_action_verified",
        first.result_id,
        "Only the first file was checked",
        "executor",
        details={
            "response_result_id": first.result_id,
            "verification_result_id": verification.result_id,
            "tool": "remove_file",
            "arguments": {"file_path": "C:\\Users\\Public\\a.exe"},
        },
    ))
    case.add_finding(Finding(
        "cleanup_network_verified",
        "192.168.21.132",
        "Network was checked",
        "executor",
        details={"verification_result_id": verification.result_id},
    ))
    orchestrator = C2TraceOrchestrator(planner=None, auditor=None, executor=None)

    orchestrator._finalize_status(case)

    assert case.final_status == "cleanup_incomplete"
    assert case.errors[-1]["details"]["missing_response_actions"][0]["result_id"] == second.result_id
