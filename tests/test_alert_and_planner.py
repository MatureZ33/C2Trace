import json
import io
import urllib.error

import pytest

import c2trace.llm as llm_module
from c2trace.agents import PlannerAgent, PlannerError
from c2trace.kb import C2KnowledgePack
from c2trace.llm import DeepSeekClient, LLMError
from c2trace.models import CaseFile, MinimalAlert, StrategyTree, ValidationError


def test_deepseek_client_records_usage_without_prompt_content(monkeypatch):
    class FakeResponse:
        headers = {"x-request-id": "req-test-001"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps(
                {
                    "id": "chat-test-001",
                    "model": "deepseek-v4-pro",
                    "choices": [{"message": {"content": '{"ok": true}'}}],
                    "usage": {
                        "prompt_tokens": 11,
                        "completion_tokens": 4,
                        "total_tokens": 15,
                    },
                }
            ).encode("utf-8")

    monkeypatch.setattr(llm_module.urllib.request, "urlopen", lambda *_args, **_kwargs: FakeResponse())
    client = DeepSeekClient(api_key="test-key", model="deepseek-chat")

    assert client.chat_json(system_prompt="secret system", user_payload={"secret": "value"}) == {"ok": True}
    record = client.usage_records[0]
    assert record["total_tokens"] == 15
    assert record["call_id"]
    assert record["endpoint_host"] == "api.deepseek.com"
    assert record["request_id"] == "req-test-001"
    assert record["model"] == "deepseek-chat"
    assert record["response_model"] == "deepseek-v4-pro"
    assert record["api_key_sha256"]
    assert len(record["prompt_sha256"]) == 64
    assert len(record["response_sha256"]) == 64
    assert len(record["parsed_response_sha256"]) == 64
    assert record["started_at"] <= record["finished_at"]
    serialized = json.dumps(client.usage_records)
    assert "test-key" not in serialized
    assert "secret system" not in serialized
    assert "value" not in serialized


def test_deepseek_client_retries_one_transient_http_error_and_sanitizes_body(monkeypatch):
    class FakeResponse:
        headers = {"x-request-id": "req-success"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({
                "choices": [{"message": {"content": '{"ok":true}'}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            }).encode("utf-8")

    responses = [
        urllib.error.HTTPError(
            "https://api.deepseek.com/chat/completions",
            429,
            "rate limited",
            {"Retry-After": "0", "x-request-id": "req-rate"},
            io.BytesIO(b'{"error":{"code":"rate_limit","message":"secret body"}}'),
        ),
        FakeResponse(),
    ]
    monkeypatch.setattr(llm_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        llm_module.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(responses.pop(0))
        if isinstance(responses[0], Exception)
        else responses.pop(0),
    )
    client = DeepSeekClient(api_key="test-key", model="deepseek-v4-flash")

    assert client.chat_json(system_prompt="return json", user_payload={}) == {"ok": True}
    assert [row["attempt"] for row in client.usage_records] == [1, 2]
    assert client.usage_records[0]["http_status"] == 429
    assert client.usage_records[0]["provider_error_code"] == "rate_limit"
    assert client.usage_records[1]["success"] is True
    assert "secret body" not in json.dumps(client.usage_records)


def test_deepseek_client_does_not_retry_non_transient_http_error(monkeypatch):
    error = urllib.error.HTTPError(
        "https://api.deepseek.com/chat/completions",
        401,
        "unauthorized",
        {"x-request-id": "req-auth"},
        io.BytesIO(b'{"error":{"code":"invalid_key","message":"do not persist"}}'),
    )
    calls = 0

    def fail(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise error

    monkeypatch.setattr(llm_module.urllib.request, "urlopen", fail)
    client = DeepSeekClient(api_key="bad-key")

    with pytest.raises(LLMError, match="DeepSeek HTTP 401"):
        client.chat_json(system_prompt="return json", user_payload={})
    assert calls == 1
    assert client.usage_records[0]["error_type"] == "http_error"
    assert "do not persist" not in json.dumps(client.usage_records)


def _kb():
    return C2KnowledgePack(
        template="generic HTTP C2 investigation",
        tool_catalog="check_network check_process_tree check_file_metadata check_persistence_all kill_process remove_file verify_cleanup",
        evidence_rules="network->pid->process_path required",
        response_safety_rules="response requires audit",
    )


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


class FakeLLM:
    def __init__(self, payload):
        self.payload = payload
        self.calls = 0
        self.last_kwargs = {}
        self.usage_records = []

    def chat_json(self, **kwargs):
        self.calls += 1
        self.last_kwargs = kwargs
        self.usage_records.append({
            "call_id": f"planner-call-{self.calls}",
            "parsed_response_sha256": "a" * 64,
        })
        return self.payload


class SequenceLLM:
    def __init__(self, payloads):
        self.payloads = list(payloads)
        self.calls = 0
        self.kwargs = []
        self.usage_records = []

    def chat_json(self, **kwargs):
        self.calls += 1
        self.kwargs.append(kwargs)
        if not self.payloads:
            raise AssertionError("unexpected extra Planner LLM call")
        self.usage_records.append({
            "call_id": f"planner-call-{self.calls}",
            "parsed_response_sha256": str(self.calls) * 64,
        })
        return self.payloads.pop(0)


def _tree_payload():
    return {
        "tree_id": "tree-test",
        "root_objective": "Trace HTTP C2 seed",
        "nodes": [
            {"node_id": "n1", "type": "investigate", "goal": "check network", "tool": "check_network", "arguments": {"remote_ip": "{{alert.remote_ip}}", "remote_port": "{{alert.remote_port}}"}, "on_success": ["n2"]},
            {"node_id": "n2", "type": "decision", "goal": "evidence_sufficient_for_response?", "condition": "evidence_sufficient_for_response", "requires": ["n1"], "on_success": ["n3"], "on_failure": ["n4"]},
            {"node_id": "n3", "type": "response", "goal": "kill process", "tool": "kill_process", "arguments": {"pid": "{{evidence.pid}}"}, "requires": ["n2"]},
            {"node_id": "n4", "type": "verify", "goal": "verify cleanup", "tool": "verify_cleanup", "arguments": {"remote_ip": "{{alert.remote_ip}}"}, "requires": ["n1"]},
        ],
    }


def test_minimal_alert_rejects_ground_truth_fields():
    with pytest.raises(ValidationError):
        MinimalAlert.from_dict({
            "case_id": "bad",
            "remote_ip": "10.0.0.8",
            "remote_port": 8888,
            "protocol": "http",
            "pid": 5252,
        })


def test_minimal_alert_rejects_path_unsafe_case_id():
    with pytest.raises(ValidationError, match="path-safe"):
        MinimalAlert.from_dict({
            "case_id": "..\\..\\outside",
            "remote_ip": "10.0.0.8",
            "protocol": "http",
        })


def test_planner_must_call_llm_and_build_strategy_tree():
    case = CaseFile.from_alert(_alert())
    fake = FakeLLM(_tree_payload())

    tree = PlannerAgent(llm_client=fake, knowledge_pack=_kb()).create_strategy_tree(case)

    assert fake.calls == 1
    assert "Planner Initial StrategyTree Prompt" in fake.last_kwargs["system_prompt"]
    assert fake.last_kwargs["user_payload"]["minimal_c2_seed_alert"]["remote_ip"] == "192.168.21.132"
    assert "c2_kb" in fake.last_kwargs["user_payload"]
    assert "casefile_summary" in fake.last_kwargs["user_payload"]
    assert "allowed_tools" in fake.last_kwargs["user_payload"]
    assert isinstance(tree, StrategyTree)
    assert case.strategy_tree is tree
    assert {node.type.value for node in tree.nodes} == {"investigate", "decision", "response", "verify"}
    assert tree.provenance["source"] == "llm"
    assert tree.provenance["llm_call_id"] == "planner-call-1"
    assert tree.provenance["llm_response_sha256"] == "a" * 64
    assert len(tree.provenance["strategy_tree_sha256"]) == 64
    assert fake.last_kwargs["temperature"] == 0.0


def test_planner_repairs_dependency_edges_once_before_any_execution():
    original = _tree_payload()
    # A missing evidence-gate edge is repaired deterministically before the LLM.
    # An unknown dependency exercises the bounded LLM repair path instead.
    original["nodes"][2]["requires"] = ["missing-node"]
    repaired = {
        "dependency_updates": [{"node_id": "n3", "requires": ["n2"]}]
    }
    case = CaseFile.from_alert(_alert())
    fake = SequenceLLM([original, repaired])

    tree = PlannerAgent(llm_client=fake, knowledge_pack=_kb()).create_strategy_tree(case)

    assert fake.calls == 2
    assert [row["temperature"] for row in fake.kwargs] == [0.0, 0.0]
    assert tree.node_map()["n3"].requires == ["n2"]
    assert tree.provenance["llm_call_id"] == "planner-call-1"
    repair = tree.provenance["dependency_repair"]
    assert repair["attempted"] is True
    assert repair["max_attempts"] == 1
    assert repair["repair_call_id"] == "planner-call-2"
    assert repair["changes"] == [
        {
            "node_id": "n3",
            "field": "requires",
            "before": ["missing-node", "n2"],
            "after": ["n2"],
        }
    ]
    assert case.action_results == []
    assert case.audit_decisions == []


def test_planner_dependency_repair_rejects_non_dependency_changes():
    original = _tree_payload()
    original["nodes"][2]["requires"] = ["missing-node"]
    repaired = {
        "dependency_updates": [
            {"node_id": "n3", "requires": ["n2"], "tool": "remove_file"}
        ]
    }
    case = CaseFile.from_alert(_alert())
    fake = SequenceLLM([original, repaired])

    with pytest.raises(PlannerError, match="unsupported field"):
        PlannerAgent(llm_client=fake, knowledge_pack=_kb()).create_strategy_tree(case)

    assert fake.calls == 2
    assert case.final_status == "planner_failed"
    assert case.action_results == []


def test_planner_dependency_repair_is_bounded_to_one_attempt():
    original = _tree_payload()
    original["nodes"][2]["requires"] = ["missing-node"]
    still_invalid = {
        "dependency_updates": [
            {"node_id": "n3", "requires": ["missing-node"]}
        ]
    }
    case = CaseFile.from_alert(_alert())
    fake = SequenceLLM([original, still_invalid])

    with pytest.raises(PlannerError, match="unknown node"):
        PlannerAgent(llm_client=fake, knowledge_pack=_kb()).create_strategy_tree(case)

    assert fake.calls == 2
    assert case.final_status == "planner_failed"
    assert case.action_results == []


def test_planner_invalid_llm_marks_case_failed():
    case = CaseFile.from_alert(_alert())
    fake = FakeLLM({"tree_id": "bad", "nodes": []})

    with pytest.raises(PlannerError):
        PlannerAgent(llm_client=fake, knowledge_pack=_kb()).create_strategy_tree(case)

    assert case.final_status == "planner_failed"
    assert case.errors


def test_planner_cannot_select_system_owned_recent_file_tool():
    case = CaseFile.from_alert(_alert())
    payload = _tree_payload()
    payload["nodes"][0]["tool"] = "check_recent_files"
    fake = FakeLLM(payload)

    with pytest.raises(PlannerError, match="system-owned"):
        PlannerAgent(llm_client=fake, knowledge_pack=_kb()).create_strategy_tree(case)

    allowed = fake.last_kwargs["user_payload"]["allowed_tools"]
    assert "check_recent_files" not in allowed


def test_planner_replay_accepts_reviewed_system_recent_file_node():
    case = CaseFile.from_alert(_alert())
    payload = _tree_payload()
    payload["nodes"][0].update({
        "tool": "check_recent_files",
        "arguments": {
            "since_utc": "2026-07-15T09:00:00Z",
            "until_utc": "2026-07-15T09:10:00Z",
            "root_aliases": ["users_public", "appdata"],
            "max_depth": 0,
            "max_results": 128,
            "max_file_size": 4194304,
        },
        "metadata": {
            "c2trace_policy": "c2trace.baseline.recent_files.v1",
            "ground_truth_independent": True,
        },
    })

    tree = PlannerAgent(
        knowledge_pack=_kb(),
        strategy_tree_template=payload,
    ).create_strategy_tree(case)

    assert tree.node_map()["n1"].tool == "check_recent_files"
    assert tree.created_by == "planner_strategy_tree_replay"


@pytest.mark.parametrize("node_type", ["investigate", "verify"])
def test_strategy_tree_rejects_destructive_tool_in_read_only_node(node_type):
    payload = _tree_payload()
    payload["nodes"][0].update({"type": node_type, "tool": "remove_file"})

    with pytest.raises(ValidationError, match="read-only tool"):
        StrategyTree.from_dict(payload)


def test_strategy_tree_rejects_response_without_evidence_gate():
    payload = _tree_payload()
    payload["nodes"][1].update({"goal": "active connection", "condition": "active_connection_found"})

    with pytest.raises(ValidationError, match="evidence_sufficient_for_response"):
        StrategyTree.from_dict(payload)


def test_more_evidence_planning_rejects_destructive_tool():
    case = CaseFile.from_alert(_alert())
    case.strategy_tree = StrategyTree.from_dict(_tree_payload())
    blocked = case.strategy_tree.node_map()["n3"]
    malicious = FakeLLM({
        "nodes": [
            {
                "node_id": "e1",
                "type": "investigate",
                "goal": "pretend cleanup is evidence collection",
                "tool": "remove_file",
                "arguments": {"file_path": "{{evidence.process_path}}"},
            }
        ]
    })

    with pytest.raises(PlannerError, match="read-only tool"):
        PlannerAgent(llm_client=malicious, knowledge_pack=_kb()).plan_more_evidence(case, blocked, "missing evidence")


def test_deepseek_client_without_key_fails_fast(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    case = CaseFile.from_alert(_alert())

    with pytest.raises(PlannerError):
        PlannerAgent(llm_client=DeepSeekClient(api_key=""), knowledge_pack=_kb()).create_strategy_tree(case)

    assert case.final_status == "planner_failed"


def test_persistence_normalization_accepts_generic_evidence_sufficient_gate():
    payload = {
        "tree_id": "generic-gate",
        "root_objective": "trace and clean persistence",
        "nodes": [
            {"node_id": "p", "type": "investigate", "goal": "persistence", "tool": "check_persistence_all"},
            {
                "node_id": "d",
                "type": "decision",
                "goal": "evidence_sufficient",
                "condition": "evidence_sufficient",
                "requires": ["p"],
            },
            {
                "node_id": "r",
                "type": "response",
                "goal": "kill process",
                "tool": "kill_process",
                "arguments": {"pid": "{{evidence.pid}}"},
                "requires": ["d"],
            },
            {
                "node_id": "v",
                "type": "verify",
                "goal": "verify",
                "tool": "verify_cleanup",
                "requires": ["r"],
            },
        ],
    }
    case = CaseFile.from_alert(_alert())

    tree = PlannerAgent(llm_client=FakeLLM(payload), knowledge_pack=_kb()).create_strategy_tree(case)

    added = [node for node in tree.nodes if node.node_id.startswith("auto_remove_")]
    assert {node.tool for node in added} == {
        "remove_registry",
        "remove_scheduled_task",
        "remove_service",
    }
    assert all(node.requires == ["d"] for node in added)


def test_planner_response_allowlist_projects_persistence_to_read_only():
    payload = {
        "tree_id": "wave1-policy",
        "root_objective": "trace C2 with a restricted response scope",
        "nodes": [
            {
                "node_id": "p",
                "type": "investigate",
                "goal": "inspect persistence",
                "tool": "check_persistence_all",
                "on_success": ["d"],
            },
            {
                "node_id": "d",
                "type": "decision",
                "goal": "evidence_sufficient_for_response",
                "condition": "evidence_sufficient_for_response",
                "requires": ["p"],
                "on_success": ["kill", "file", "reg", "task", "service"],
            },
            {
                "node_id": "kill",
                "type": "response",
                "goal": "kill attributed process",
                "tool": "kill_process",
                "arguments": {"pid": "{{evidence.pid}}"},
                "requires": ["d"],
            },
            {
                "node_id": "file",
                "type": "response",
                "goal": "remove attributed payload",
                "tool": "remove_file",
                "arguments": {"file_path": "{{evidence.process_path}}"},
                "requires": ["d"],
            },
            {
                "node_id": "reg",
                "type": "response",
                "goal": "remove registry persistence",
                "tool": "remove_registry",
                "arguments": {"reg_path": "{{evidence.persistence.reg_path}}"},
                "requires": ["d"],
            },
            {
                "node_id": "task",
                "type": "response",
                "goal": "remove task persistence",
                "tool": "remove_scheduled_task",
                "arguments": {"task_name": "{{evidence.persistence.task_name}}"},
                "requires": ["d"],
            },
            {
                "node_id": "service",
                "type": "response",
                "goal": "remove service persistence",
                "tool": "remove_service",
                "arguments": {"service_name": "{{evidence.persistence.service_name}}"},
                "requires": ["d"],
            },
            {
                "node_id": "v",
                "type": "verify",
                "goal": "verify cleanup",
                "tool": "verify_cleanup",
                "requires": ["kill", "file", "reg", "task", "service"],
            },
        ],
    }
    case = CaseFile.from_alert(_alert())
    fake = FakeLLM(payload)

    tree = PlannerAgent(
        llm_client=fake,
        knowledge_pack=_kb(),
        allowed_response_tools={"kill_process", "remove_file"},
    ).create_strategy_tree(case)

    response_nodes = [node for node in tree.nodes if node.type.value == "response"]
    assert {node.tool for node in response_nodes} == {"kill_process", "remove_file"}
    assert len(response_nodes) == 2
    assert tree.node_map()["v"].requires == ["kill", "file"]
    assert tree.node_map()["d"].on_success == ["kill", "file"]
    assert fake.last_kwargs["user_payload"]["allowed_response_tools"] == [
        "kill_process",
        "remove_file",
    ]
    assert all(
        tool not in fake.last_kwargs["user_payload"]["allowed_tools"]
        for tool in ("remove_registry", "remove_scheduled_task", "remove_service")
    )
    assert {
        row["tool"] for row in case.timeline[-1].details["pruned_response_nodes"]
    } == {"remove_registry", "remove_scheduled_task", "remove_service"}


def test_planner_replays_reviewed_strategy_tree_without_second_llm_call():
    payload = _tree_payload()
    for node in payload["nodes"]:
        node["status"] = "succeeded"
        node["evidence_refs"] = ["old-finding"]
        node["assigned_to"] = "old-agent"
    fake = FakeLLM({"tree_id": "must-not-be-used", "nodes": []})
    case = CaseFile.from_alert(_alert())

    tree = PlannerAgent(
        llm_client=fake,
        knowledge_pack=_kb(),
        allowed_response_tools={"kill_process", "remove_file"},
        strategy_tree_template=payload,
    ).create_strategy_tree(case)

    assert fake.calls == 0
    assert tree.tree_id == "tree-test"
    assert tree.created_by == "planner_strategy_tree_replay"
    assert all(not node.evidence_refs for node in tree.nodes)
    assert all(node.assigned_to is None for node in tree.nodes)
    assert tree.node_map()["n1"].status.value == "ready"
    assert tree.node_map()["n3"].status.value == "pending"
    assert case.timeline[-1].details["planning_mode"] == "strategy_tree_replay"


def test_more_evidence_unknown_requirement_is_normalized_to_planner_error():
    case = CaseFile.from_alert(_alert())
    case.strategy_tree = StrategyTree.from_dict(_tree_payload())
    blocked = case.strategy_tree.node_map()["n3"]
    llm = FakeLLM({
        "nodes": [{
            "node_id": "e1",
            "type": "investigate",
            "goal": "collect process evidence",
            "tool": "check_process_tree",
            "requires": ["does-not-exist"],
        }],
    })

    with pytest.raises(PlannerError, match="unknown requirement"):
        PlannerAgent(llm_client=llm, knowledge_pack=_kb()).plan_more_evidence(
            case, blocked, "missing process evidence"
        )
