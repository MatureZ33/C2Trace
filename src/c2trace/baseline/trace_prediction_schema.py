"""Frozen shared TracePrediction IR schema for C2Trace / ReAct / LLM-Direct.

Both systems must serialize their investigation findings into the same
structured format so the v4 scorer can compare them on equal terms.

The schema is deliberately restrictive: only the ``finding_type`` values
listed below are accepted, and each must carry structured ``details``
fields.  The free-text ``value`` field is retained for human readability
but the scorer never reads it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SCHEMA_VERSION = "c2trace.baseline.trace_prediction.v1"

# Allowed finding_type values and the required structured detail keys.
# Optional keys are listed separately; the scorer uses whatever is present.
ALLOWED_FINDING_TYPES: dict[str, dict[str, Any]] = {
    "network_connection": {
        "required": ("local_address", "remote_address", "remote_port"),
        "optional": ("local_port", "pid", "protocol", "state", "process_name", "process_path"),
        "scorer_trace_type": "network_connection",
    },
    "c2_process_attributed": {
        "required": ("pid",),
        "optional": ("local_address", "local_port", "remote_address", "remote_port",
                      "state", "process_name", "process_path"),
        "scorer_trace_type": "network_connection",  # also yields a process obs
    },
    "process_detail": {
        "required": ("pid", "path", "creation_time_utc"),
        "optional": ("name", "command_line", "parent_pid", "creation_date"),
        "scorer_trace_type": "process",
    },
    "suspicious_process_path": {
        "required": ("path",),
        "optional": ("pid", "name", "command_line", "parent_pid",
                      "creation_date", "creation_time_utc"),
        "scorer_trace_type": "process",
    },
    "process_tree": {
        "required": ("root",),
        "optional": ("chain",),
        "scorer_trace_type": "process",
    },
    "file_metadata": {
        "required": ("path",),
        "optional": ("sha256", "exists", "name", "length", "size",
                      "creation_time_utc", "last_write_time_utc",
                      "signature_status", "signer"),
        "scorer_trace_type": "file",
    },
    "payload_file_verified": {
        "required": ("path",),
        "optional": ("sha256", "exists", "name", "length",
                      "creation_time_utc", "last_write_time_utc",
                      "signature_status", "signer"),
        "scorer_trace_type": "file",
    },
    "network_confirmed": {
        "required": ("connections",),
        "optional": (),
        "scorer_trace_type": "network_connection",
    },
    "persistence_linked_to_payload": {
        "required": ("category",),
        "optional": ("path", "name", "value", "key_path", "value_name", "value_data"),
        "scorer_trace_type": "persistence",
    },
    "powershell_history_hit": {
        "required": ("command",),
        "optional": (),
        "scorer_trace_type": "powershell_history",
    },
    "dns_cache_confirmed": {
        "required": ("entries",),
        "optional": (),
        "scorer_trace_type": "dns_cache",
    },
}


def validate_observed_entity(entity: dict[str, Any]) -> list[str]:
    """Return a list of validation errors for a single observed entity."""
    errors: list[str] = []
    finding_type = str(entity.get("finding_type") or "").strip()
    if finding_type not in ALLOWED_FINDING_TYPES:
        errors.append(f"finding_type '{finding_type}' is not in the allowed set")
        return errors
    spec = ALLOWED_FINDING_TYPES[finding_type]
    details = entity.get("details")
    if not isinstance(details, dict):
        errors.append(f"finding_type '{finding_type}' must have a details object")
        return errors
    for key in spec["required"]:
        if key not in details or details[key] in (None, "", []):
            errors.append(f"finding_type '{finding_type}' is missing required detail '{key}'")
    return errors


def normalize_entity(entity: dict[str, Any], index: int) -> dict[str, Any]:
    """Normalize a raw entity into the frozen IR format."""
    finding_type = str(entity.get("finding_type") or "").strip()
    spec = ALLOWED_FINDING_TYPES.get(finding_type, {})
    details = entity.get("details") if isinstance(entity.get("details"), dict) else {}
    # Keep only the keys the scorer cares about
    kept: dict[str, Any] = {}
    for key in (*spec.get("required", ()), *spec.get("optional", ())):
        if key in details and details[key] is not None:
            kept[key] = details[key]
    value = str(entity.get("value") or "")
    return {
        "finding_id": str(entity.get("finding_id") or f"ir-entity-{index:04d}"),
        "finding_type": finding_type,
        "value": value,
        "details": kept,
        "evidence": str(entity.get("evidence") or "explicit model prediction"),
        "source": str(entity.get("source") or "trace_prediction_ir"),
        "confidence": float(entity.get("confidence", 0.0) or 0.0),
    }


def normalize_entities(entities: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Normalize and validate a list of observed entities."""
    result: list[dict[str, Any]] = []
    for index, entity in enumerate(entities or [], start=1):
        if not isinstance(entity, dict):
            continue
        finding_type = str(entity.get("finding_type") or "").strip()
        if finding_type not in ALLOWED_FINDING_TYPES:
            continue
        # The scorer must never receive a finding whose required identity
        # fields were omitted.  ``normalize_entity`` intentionally preserves
        # only schema fields, so validation has to happen before normalization.
        if validate_observed_entity(entity):
            continue
        result.append(normalize_entity(entity, index))
    return result


__all__ = [
    "SCHEMA_VERSION",
    "ALLOWED_FINDING_TYPES",
    "validate_observed_entity",
    "normalize_entity",
    "normalize_entities",
]
