"""Neutral records for the independent ReAct baseline.

The baseline runtime writes these records without importing C2Trace's agent
models or report structures.  A scoring adapter may consume a completed
record later, after Ground Truth has been materialized by the controller.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


SCHEMA_VERSION = "c2trace.public_react_run.v1"
EVALUATION_SCHEMA_VERSION = "c2trace.public_react_evaluation.v1"
FORBIDDEN_INPUT_KEYS = frozenset(
    {
        "ground_truth",
        "cleanup_ground_truth",
        "target_identity",
        "expected_response",
        "post_state",
        "target_lock",
        "response_target_lock",
        "scoring_casefile",
        "casefile",
        "strategy_tree",
        "prediction_ir",
    }
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _forbidden_paths(value: Any, path: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key).casefold()
            child_path = f"{path}.{key}"
            if key_text in FORBIDDEN_INPUT_KEYS:
                found.append(child_path)
            found.extend(_forbidden_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_forbidden_paths(child, f"{path}[{index}]"))
    return found


def assert_public_input(value: Any) -> None:
    paths = _forbidden_paths(value)
    if paths:
        raise ValueError("forbidden evaluation-only fields in baseline input: " + ", ".join(paths))


def sanitize_alert(alert: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only the canonical alert and benign sensor metadata."""
    value = dict(alert)
    assert_public_input(value)
    allowed = {
        "schema_version", "alert_id", "case_id", "source", "alert_type",
        "victim_ip", "remote_ip", "remote_port", "protocol", "local_ip",
        "local_port", "signature", "signature_id", "flow_id", "timestamp",
        "time_window", "confidence", "description", "category", "severity",
    }
    cleaned = {key: item for key, item in value.items() if key in allowed}
    assert_public_input(cleaned)
    return cleaned


@dataclass(slots=True)
class ReActRunRecord:
    schema_version: str = SCHEMA_VERSION
    case_id: str = ""
    alert: dict[str, Any] = field(default_factory=dict)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    model_output: dict[str, Any] = field(default_factory=lambda: {"observations": [], "actions": []})
    executed_actions: list[dict[str, Any]] = field(default_factory=list)
    post_state_observation: dict[str, Any] | None = None
    operational_metrics: dict[str, Any] = field(default_factory=dict)
    llm_audit: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now)

    def validate(self) -> "ReActRunRecord":
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported ReAct run schema: {self.schema_version}")
        if not self.case_id.strip():
            raise ValueError("case_id is required")
        if not isinstance(self.alert, dict):
            raise ValueError("alert must be an object")
        assert_public_input(self.alert)
        if not isinstance(self.model_output, dict):
            raise ValueError("model_output must be an object")
        if set(self.model_output) - {"observations", "actions"}:
            raise ValueError("model_output may contain only observations and actions")
        if not isinstance(self.model_output.get("observations"), list):
            raise ValueError("model_output.observations must be a list")
        if not isinstance(self.model_output.get("actions"), list):
            raise ValueError("model_output.actions must be a list")
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.validate() and asdict(self)

    def write_json(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
        return target


@dataclass(slots=True)
class EvaluationRecord:
    """Post-run neutral projection used by an evaluator, never by the agent."""

    schema_version: str = EVALUATION_SCHEMA_VERSION
    case_id: str = ""
    observations: list[dict[str, Any]] = field(default_factory=list)
    requested_actions: list[dict[str, Any]] = field(default_factory=list)
    executed_actions: list[dict[str, Any]] = field(default_factory=list)
    operational_metrics: dict[str, Any] = field(default_factory=dict)
    source_run_record: str = ""
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        if self.schema_version != EVALUATION_SCHEMA_VERSION:
            raise ValueError("unsupported evaluation record schema")
        if not self.case_id.strip():
            raise ValueError("case_id is required")
        return asdict(self)

    def write_json(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
        return target


def project_for_scoring(
    run_record: Mapping[str, Any],
    *,
    response_record: Mapping[str, Any] | None = None,
    operational_metrics: Mapping[str, Any] | None = None,
) -> tuple[EvaluationRecord, dict[str, Any]]:
    """Project model claims and successful actions into the frozen scorer wire format.

    This function is intentionally called only after the agent has returned.
    It does not add entities or actions from any answer file. Missing or
    malformed model claims remain missing.
    """
    case_id = str(run_record.get("case_id") or "")
    output = run_record.get("model_output") if isinstance(run_record.get("model_output"), Mapping) else {}
    neutral_observations = output.get("observations") if isinstance(output.get("observations"), list) else []
    findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    kind_map = {"network": "network_connection", "process": "process_detail", "file": "file_metadata", "persistence": "persistence_linked_to_payload"}
    required = {
        "network_connection": ("local_address", "remote_address", "remote_port"),
        "process_detail": ("pid", "path", "creation_time_utc"),
        "file_metadata": ("path",),
        "persistence_linked_to_payload": ("category",),
    }
    for index, raw in enumerate(neutral_observations, start=1):
        if not isinstance(raw, Mapping):
            continue
        kind = str(raw.get("kind") or "").strip().casefold()
        finding_type = kind_map.get(kind)
        details = raw.get("details") if isinstance(raw.get("details"), Mapping) else {}
        if not finding_type or any(key not in details or details[key] in (None, "", []) for key in required[finding_type]):
            continue
        detail_copy = dict(details)
        value = str(raw.get("value") or detail_copy.get("path") or detail_copy.get("pid") or "")
        finding = {
            "finding_id": f"react-observation-{index:04d}",
            "finding_type": finding_type,
            "value": value,
            "details": detail_copy,
            "evidence": str(raw.get("evidence_refs") or "tool_result"),
            "source": "public_react_model_output",
            "confidence": float(raw.get("confidence", 0.0) or 0.0),
            "created_at": utc_now(),
        }
        findings.append(finding)
        observations.append({"kind": kind, "details": detail_copy, "evidence_refs": raw.get("evidence_refs", [])})

    investigation_calls = run_record.get("tool_calls") if isinstance(run_record.get("tool_calls"), list) else []
    response_source = response_record if isinstance(response_record, Mapping) else run_record
    response_calls = response_source.get("tool_calls") if isinstance(response_source.get("tool_calls"), list) else []
    tool_calls = list(investigation_calls)
    if response_source is not run_record:
        tool_calls.extend(response_calls)
    action_results: list[dict[str, Any]] = []
    executed_actions: list[dict[str, Any]] = []
    for index, call in enumerate(tool_calls, start=1):
        if not isinstance(call, Mapping) or call.get("classification") != "response":
            continue
        action = {
            "result_id": f"react-action-{index:04d}",
            "tool": str(call.get("tool") or ""),
            "arguments": dict(call.get("arguments") or {}) if isinstance(call.get("arguments"), Mapping) else {},
            "success": call.get("success") is True,
            "data": call.get("data"),
            "error": call.get("error"),
        }
        action_results.append(action)
        if action["success"]:
            executed_actions.append({"tool": action["tool"], "arguments": action["arguments"]})

    requested_actions = output.get("actions") if isinstance(output.get("actions"), list) else []
    evaluation = EvaluationRecord(
        case_id=case_id,
        observations=observations,
        requested_actions=[dict(item) for item in requested_actions if isinstance(item, Mapping)],
        executed_actions=executed_actions,
        operational_metrics=dict(operational_metrics or response_source.get("operational_metrics") or run_record.get("operational_metrics") or {}),
    )
    scoring_casefile = {
        "case_id": case_id,
        "source_alert": dict(run_record.get("alert") or {}),
        "findings": findings,
        "action_results": action_results,
        "proposed_actions": [dict(item) for item in requested_actions if isinstance(item, Mapping)],
        "tool_observations": list(tool_calls),
        "operational_metrics": dict(evaluation.operational_metrics),
        "final_status": "completed" if not run_record.get("errors") else "completed_with_errors",
    }
    return evaluation, scoring_casefile


__all__ = [
    "SCHEMA_VERSION",
    "EVALUATION_SCHEMA_VERSION",
    "ReActRunRecord",
    "EvaluationRecord",
    "assert_public_input",
    "sanitize_alert",
    "project_for_scoring",
]
