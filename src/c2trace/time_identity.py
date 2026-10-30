from __future__ import annotations

"""Canonical UTC comparison used by response, cleanup, and live safety."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


CREATION_TIME_TOLERANCE_SECONDS = 2.0


def normalize_creation_time(value: Any) -> str:
    # Preserve the historical CaseFile representation while parsing it safely.
    return str(value or "").strip().lower()


def parse_utc_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if len(text) > 10 and text[10] in {"t", "T"}:
        text = text[:10] + "T" + text[11:]
    if text.endswith(("z", "Z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class CreationTimeComparison:
    matches: bool
    left_normalized: str
    right_normalized: str
    parsed: bool
    delta_ms: float | None
    tolerance_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "matches": self.matches,
            "left_normalized": self.left_normalized,
            "right_normalized": self.right_normalized,
            "parsed": self.parsed,
            "delta_ms": self.delta_ms,
            "tolerance_ms": self.tolerance_ms,
        }


def compare_creation_times(
    left: Any,
    right: Any,
    *,
    tolerance_seconds: float = CREATION_TIME_TOLERANCE_SECONDS,
) -> CreationTimeComparison:
    left_normalized = normalize_creation_time(left)
    right_normalized = normalize_creation_time(right)
    left_dt = parse_utc_datetime(left)
    right_dt = parse_utc_datetime(right)
    tolerance_ms = max(0.0, float(tolerance_seconds)) * 1000.0
    if left_dt is not None and right_dt is not None:
        delta_ms = abs((left_dt - right_dt).total_seconds()) * 1000.0
        return CreationTimeComparison(
            matches=delta_ms <= tolerance_ms,
            left_normalized=left_normalized,
            right_normalized=right_normalized,
            parsed=True,
            delta_ms=round(delta_ms, 3),
            tolerance_ms=tolerance_ms,
        )
    return CreationTimeComparison(
        matches=left_normalized == right_normalized,
        left_normalized=left_normalized,
        right_normalized=right_normalized,
        parsed=False,
        delta_ms=None,
        tolerance_ms=tolerance_ms,
    )


def creation_times_match(left: Any, right: Any) -> bool:
    return compare_creation_times(left, right).matches

