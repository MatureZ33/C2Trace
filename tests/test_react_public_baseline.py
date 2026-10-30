"""Offline boundary tests for the neutral ReAct baseline."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from c2trace.baseline.neutral_records import ReActRunRecord, project_for_scoring
from c2trace.baseline.public_output import parse_public_output
from c2trace.baseline.public_task import DEFAULT_SPEC_ROOT, build_public_system_prompt, load_public_task_spec
from c2trace.baseline.react_agent import ToolCallRecorder, build_tools
from c2trace.tools.system import WindowsToolBackend


ALERT = {
    "schema_version": "c2trace.alert.v1",
    "alert_id": "offline-alert",
    "case_id": "AURORA-CHAIN-001",
    "source": "suricata_eve",
    "alert_type": "c2_http_beacon",
    "victim_ip": "192.0.2.20",
    "remote_ip": "192.0.2.10",
    "remote_port": 443,
    "protocol": "tcp",
}


def test_public_spec_is_present_and_has_no_answer_values() -> None:
    spec = load_public_task_spec(DEFAULT_SPEC_ROOT)
    assert set(spec) == {"task", "tools", "safety", "output"}
    for path in DEFAULT_SPEC_ROOT.glob("*.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        assert "ground_truth.json" not in json.dumps(value)
        assert "target_identity" not in json.dumps(value)


def test_public_prompt_has_no_private_framework_fields() -> None:
    prompt = build_public_system_prompt(ALERT)
    lowered = prompt.casefold()
    assert "casefile" not in lowered
    assert "strategy tree" not in lowered
    assert "target lock" not in lowered
    assert "ground_truth" not in lowered
    assert "creation_time_utc is mandatory" not in lowered
    assert "evidence chain rules" not in lowered


def test_public_tools_are_neutral_and_include_optional_post_check() -> None:
    recorder = ToolCallRecorder(WindowsToolBackend(), max_calls=4)
    names = {tool.name for tool in build_tools(recorder)}
    assert len(names) == 14
    assert "check_post_state" in names
    assert "verify_cleanup" not in names


def test_output_parser_is_strict_and_rejects_private_fields() -> None:
    parsed = parse_public_output('{"observations":[{"kind":"process","details":{"pid":1,"path":"C:\\\\Users\\\\Public\\\\x.exe"}}],"actions":[]}')
    assert parsed["observations"][0]["kind"] == "process"
    with pytest.raises(ValueError):
        parse_public_output('{"observations":[],"actions":[],"casefile":{}}')
    with pytest.raises(ValueError):
        parse_public_output('{"observations":[{"kind":"process","details":{}}],"actions":[]}')


def test_neutral_record_does_not_promote_tool_observation_to_claim() -> None:
    record = ReActRunRecord(
        case_id=ALERT["case_id"],
        alert=ALERT,
        tool_calls=[{
            "tool": "check_process",
            "classification": "investigation",
            "success": True,
            "data": {"processes": [{"pid": 12, "path": r"C:\Users\Public\x.exe"}]},
        }],
    )
    evaluation, projection = project_for_scoring(record.to_dict())
    assert evaluation.observations == []
    assert projection["findings"] == []


def test_projection_keeps_only_explicit_valid_model_observations() -> None:
    record = ReActRunRecord(
        case_id=ALERT["case_id"],
        alert=ALERT,
        model_output={
            "observations": [{
                "kind": "process",
                "details": {"pid": 12, "path": r"C:\Users\Public\x.exe", "creation_time_utc": "2026-01-01T00:00:00Z"},
                "evidence_refs": ["tool-1"],
            }],
            "actions": [],
        },
    )
    _, projection = project_for_scoring(record.to_dict())
    assert len(projection["findings"]) == 1
    assert projection["findings"][0]["finding_type"] == "process_detail"


def test_response_sandbox_is_target_agnostic_but_protects_system() -> None:
    recorder = ToolCallRecorder(WindowsToolBackend(execute_response=True), max_calls=3)
    blocked = recorder.call("kill_process", process_name="c2t_control.exe")
    assert blocked.success is False
    allowed = recorder.call("kill_process", pid=424242, expected_path=r"C:\Users\Public\x.exe")
    # The live backend may report absence; the important boundary property is
    # that no case-specific target identity was required before the call.
    assert recorder.calls[-1]["safety_decision"]["allowed"] is True
    assert recorder.calls[-1]["classification"] == "response"
