import json
import sys
from types import SimpleNamespace

from run_case import (
    cli_exit_code_for_status,
    main,
    summarize_llm_usage,
    summarize_tool_usage,
    write_outputs,
)


class _CaseStub:
    final_report = None

    def to_dict(self):
        return {
            "case_id": "CB-WIN-0001",
            "final_status": "completed",
            "timeline": [{"event_type": "run_input_recorded"}],
        }


def test_write_outputs_persists_reproducible_run_metadata(tmp_path):
    metadata = {
        "schema_version": "c2trace.run.v1",
        "run_id": "test-run-id",
        "input": {
            "source_type": "suricata_eve",
            "requested_selection": {"policy": "latest", "flow_id": "12345"},
            "selected_source_artifact": {
                "line_number": 17,
                "event_sha256": "a" * 64,
                "raw_record_sha256": "b" * 64,
            },
        },
        "result": {"final_status": "completed", "cli_exit_code": 0},
    }

    write_outputs(_CaseStub(), str(tmp_path), run_metadata=metadata)

    persisted = json.loads((tmp_path / "run_metadata.json").read_text(encoding="utf-8"))
    assert persisted == metadata
    assert (tmp_path / "casefile.json").exists()
    assert (tmp_path / "execution_log.jsonl").exists()


def test_cli_exit_code_fails_closed_for_unsuccessful_terminal_statuses():
    assert cli_exit_code_for_status("completed") == 0
    assert cli_exit_code_for_status("completed_dry_run") == 0
    for status in (
        "planner_failed",
        "failed_max_steps",
        "attribution_inconclusive",
        "response_not_executed",
        "response_failed",
        "verification_failed",
        "cleanup_verification_missing",
        "cleanup_incomplete",
    ):
        assert cli_exit_code_for_status(status) == 1


def test_usage_summaries_are_deterministic_and_do_not_include_prompts():
    planner = SimpleNamespace(
        llm_client=SimpleNamespace(
            usage_records=[
                {
                    "model": "deepseek-chat",
                    "temperature": 0.2,
                    "max_tokens": 3200,
                    "elapsed_ms": 125.5,
                    "success": True,
                    "prompt_tokens": 100,
                    "completion_tokens": 25,
                    "total_tokens": 125,
                }
            ]
        )
    )
    auditor = SimpleNamespace(
        llm_client=SimpleNamespace(
            usage_records=[
                {
                    "model": "deepseek-chat",
                    "temperature": 0.1,
                    "max_tokens": 600,
                    "elapsed_ms": 50,
                    "success": False,
                    "prompt_tokens": 20,
                    "completion_tokens": 0,
                    "total_tokens": 20,
                }
            ]
        )
    )
    llm = summarize_llm_usage(planner, auditor)
    assert llm["call_count"] == 2
    assert llm["successful_call_count"] == 1
    assert llm["total_tokens"] == 145
    assert {item["role"] for item in llm["calls"]} == {"planner", "auditor"}
    assert "system_prompt" not in json.dumps(llm)
    assert "user_payload" not in json.dumps(llm)

    case = SimpleNamespace(
        strategy_tree=SimpleNamespace(
            nodes=[
                SimpleNamespace(node_id="n1", type=SimpleNamespace(value="investigate")),
                SimpleNamespace(node_id="n2", type=SimpleNamespace(value="response")),
            ]
        ),
        action_results=[
            SimpleNamespace(node_id="n1", tool="check_network", success=True, elapsed_ms=10.25),
            SimpleNamespace(node_id="n2", tool="kill_process", success=False, elapsed_ms=5.75),
        ],
    )
    tools = summarize_tool_usage(case)
    assert tools["call_count"] == 2
    assert tools["success_count"] == 1
    assert tools["failure_count"] == 1
    assert tools["elapsed_ms"] == 16.0
    assert tools["phase_elapsed_ms"]["investigate"] == 10.25
    assert tools["phase_elapsed_ms"]["response"] == 5.75


def test_main_returns_input_error_for_malformed_alert_json(tmp_path, monkeypatch):
    alert = tmp_path / "broken.json"
    alert.write_text("{not-json", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["run_case.py", "--alert", str(alert)])

    assert main() == 2


def test_live_response_requires_both_auditor_safety_inputs(tmp_path, monkeypatch):
    alert = tmp_path / "alert.json"
    alert.write_text("{}", encoding="utf-8")

    for extra_args in (
        [],
        ["--protected-processes", str(tmp_path / "protected.json")],
        ["--reviewed-target-from", str(tmp_path / "reviewed.json")],
    ):
        monkeypatch.setattr(
            sys,
            "argv",
            ["run_case.py", "--alert", str(alert), "--execute-response", *extra_args],
        )
        assert main() == 2


