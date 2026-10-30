"""Neutral prediction interchange format used by baseline adapters.

The IR deliberately separates observations returned by tools from claims made
by the model and from actions that were actually executed.  This prevents a
baseline adapter from turning a tool observation into a model prediction.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping


SENSITIVE_KEYS = {
    "ground_truth",
    "cleanup_ground_truth",
    "scoring_casefile",
    "target_lock",
    "response_target_lock",
}


def _list_of_dicts(value: Any, field_name: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{field_name} must be a list of JSON objects")
    return [dict(item) for item in value]


@dataclass(slots=True)
class PredictionIR:
    schema_version: str = "c2trace.baseline.prediction.v1"
    case_id: str = ""
    observed_entities: list[dict[str, Any]] = field(default_factory=list)
    proposed_actions: list[dict[str, Any]] = field(default_factory=list)
    executed_actions: list[dict[str, Any]] = field(default_factory=list)
    tool_observations: list[dict[str, Any]] = field(default_factory=list)
    tool_call_log: list[dict[str, Any]] = field(default_factory=list)
    llm_call_count: int = 0
    token_usage: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> "PredictionIR":
        if self.schema_version != "c2trace.baseline.prediction.v1":
            raise ValueError(f"unsupported PredictionIR schema: {self.schema_version}")
        if not isinstance(self.case_id, str) or not self.case_id.strip():
            raise ValueError("PredictionIR.case_id is required")
        for name in (
            "observed_entities",
            "proposed_actions",
            "executed_actions",
            "tool_observations",
            "tool_call_log",
        ):
            setattr(self, name, _list_of_dicts(getattr(self, name), name))
        if isinstance(self.llm_call_count, bool) or self.llm_call_count < 0:
            raise ValueError("llm_call_count must be a non-negative integer")
        if not isinstance(self.token_usage, dict):
            raise ValueError("token_usage must be an object")
        for key, value in self.token_usage.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"token_usage.{key} must be a non-negative integer")
        if not isinstance(self.errors, list) or not all(isinstance(x, str) for x in self.errors):
            raise ValueError("errors must be a list of strings")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be an object")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "PredictionIR":
        if not isinstance(payload, Mapping):
            raise ValueError("PredictionIR must be a JSON object")
        result = cls(
            schema_version=str(payload.get("schema_version") or ""),
            case_id=str(payload.get("case_id") or ""),
            observed_entities=payload.get("observed_entities", []),
            proposed_actions=payload.get("proposed_actions", []),
            executed_actions=payload.get("executed_actions", []),
            tool_observations=payload.get("tool_observations", []),
            tool_call_log=payload.get("tool_call_log", []),
            llm_call_count=payload.get("llm_call_count", 0),
            token_usage=payload.get("token_usage", {}),
            errors=payload.get("errors", []),
            metadata=payload.get("metadata", {}),
        )
        return result.validate()

    @classmethod
    def from_json(cls, path: str | Path) -> "PredictionIR":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def write_json(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return target


__all__ = ["PredictionIR"]
