"""Strict parser for the neutral ReAct final output."""
from __future__ import annotations

import json
import re
from typing import Any

from c2trace.baseline.neutral_records import FORBIDDEN_INPUT_KEYS


ALLOWED_KINDS = frozenset({"network", "process", "file", "persistence"})
ALLOWED_ACTIONS = frozenset({"kill_process", "remove_file", "remove_registry", "remove_scheduled_task", "remove_service"})


def _forbidden(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).casefold() in FORBIDDEN_INPUT_KEYS:
                errors.append(f"{path}.{key}")
            errors.extend(_forbidden(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_forbidden(child, f"{path}[{index}]"))
    return errors


def _extract_json(text: str) -> dict[str, Any]:
    candidate = text.strip()
    try:
        value = json.loads(candidate)
    except json.JSONDecodeError:
        match = re.search(r"\{[\s\S]*\}", candidate)
        if not match:
            raise ValueError("no JSON object in model output")
        value = json.loads(match.group(0))
    if not isinstance(value, dict):
        raise ValueError("model output must be a JSON object")
    return value


def parse_public_output(text: str) -> dict[str, list[dict[str, Any]]]:
    value = _extract_json(str(text or ""))
    if set(value) != {"observations", "actions"}:
        raise ValueError("output must contain exactly observations and actions")
    forbidden = _forbidden(value)
    if forbidden:
        raise ValueError("output contains forbidden private fields: " + ", ".join(forbidden))
    observations = value.get("observations")
    actions = value.get("actions")
    if not isinstance(observations, list) or not isinstance(actions, list):
        raise ValueError("observations and actions must be arrays")
    normalized_observations: list[dict[str, Any]] = []
    for index, raw in enumerate(observations, start=1):
        if not isinstance(raw, dict):
            raise ValueError(f"observations[{index}] must be an object")
        kind = str(raw.get("kind") or "").strip().casefold()
        details = raw.get("details")
        if kind not in ALLOWED_KINDS or not isinstance(details, dict) or not details:
            raise ValueError(f"observations[{index}] has invalid kind/details")
        normalized_observations.append({
            "kind": kind,
            "details": dict(details),
            "evidence_refs": raw.get("evidence_refs", []),
            **({"confidence": raw["confidence"]} if "confidence" in raw else {}),
            **({"value": raw["value"]} if "value" in raw else {}),
        })
    normalized_actions: list[dict[str, Any]] = []
    for index, raw in enumerate(actions, start=1):
        if not isinstance(raw, dict):
            raise ValueError(f"actions[{index}] must be an object")
        tool = str(raw.get("tool") or "").strip()
        arguments = raw.get("arguments")
        if tool not in ALLOWED_ACTIONS or not isinstance(arguments, dict):
            raise ValueError(f"actions[{index}] has invalid tool/arguments")
        normalized_actions.append({"tool": tool, "arguments": dict(arguments)})
    return {"observations": normalized_observations, "actions": normalized_actions}


__all__ = ["parse_public_output", "ALLOWED_KINDS", "ALLOWED_ACTIONS"]
