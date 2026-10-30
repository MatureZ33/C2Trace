"""Remove oracle and run-internal labels from evidence before baseline use."""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


EXACT_REMOVED_KEYS = frozenset(
    {
        "trace_id",
        "expected_target",
        "target_profile",
        "ground_truth",
        "cleanup_ground_truth",
        "scoring_casefile",
        "response_target_lock",
        "target_lock",
        "target",
        "selection",
        "source_binding",
        "trace_fact_ids",
        "ability_instance_id",
        "operation_id",
        "link_id",
    }
)
PREFIX_REMOVED_KEYS = ("target.", "oracle.", "groundtruth.")


@dataclass(frozen=True, slots=True)
class SanitizationReport:
    removed_paths: tuple[str, ...]
    input_sha256: str
    output_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "c2trace.baseline.evidence_sanitization.v1",
            "removed_paths": list(self.removed_paths),
            "removed_count": len(self.removed_paths),
            "input_sha256": self.input_sha256,
            "output_sha256": self.output_sha256,
        }


def _key_removed(key: str) -> bool:
    lowered = key.lower()
    return lowered in {item.lower() for item in EXACT_REMOVED_KEYS} or any(
        lowered.startswith(prefix) for prefix in PREFIX_REMOVED_KEYS
    )


def _walk(value: Any, path: str, removed: list[str]) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            child_path = f"{path}.{key}" if path else key
            if _key_removed(key):
                removed.append(child_path)
                continue
            result[key] = _walk(raw_value, child_path, removed)
        return result
    if isinstance(value, list):
        return [_walk(item, f"{path}[{index}]", removed) for index, item in enumerate(value)]
    return copy.deepcopy(value)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sanitize_evidence_bundle(bundle: Mapping[str, Any]) -> tuple[dict[str, Any], SanitizationReport]:
    if not isinstance(bundle, Mapping):
        raise ValueError("evidence bundle must be a JSON object")
    source = dict(bundle)
    removed: list[str] = []
    sanitized = _walk(source, "", removed)
    if not isinstance(sanitized, dict):
        raise ValueError("sanitized evidence must remain a JSON object")
    report = SanitizationReport(
        removed_paths=tuple(removed),
        input_sha256=hashlib.sha256(_canonical_bytes(source)).hexdigest(),
        output_sha256=hashlib.sha256(_canonical_bytes(sanitized)).hexdigest(),
    )
    assert_sanitized(sanitized)
    return sanitized, report


def assert_sanitized(bundle: Mapping[str, Any]) -> None:
    if not isinstance(bundle, Mapping):
        raise AssertionError("sanitized evidence must be a mapping")
    leaked: list[str] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                key_text = str(key)
                child = f"{path}.{key_text}" if path else key_text
                if _key_removed(key_text):
                    leaked.append(child)
                visit(item, child)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{path}[{index}]")

    visit(bundle, "")
    if leaked:
        raise AssertionError(f"sanitized evidence still contains oracle keys: {leaked}")


def sanitize_evidence_file(source: str | Path, target: str | Path, report_path: str | Path | None = None) -> SanitizationReport:
    source_path = Path(source)
    payload = json.loads(source_path.read_text(encoding="utf-8-sig"))
    sanitized, report = sanitize_evidence_bundle(payload)
    target_path = Path(target)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(json.dumps(sanitized, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if report_path is not None:
        report_target = Path(report_path)
        report_target.parent.mkdir(parents=True, exist_ok=True)
        report_target.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


__all__ = ["SanitizationReport", "sanitize_evidence_bundle", "sanitize_evidence_file", "assert_sanitized"]
