from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Iterable

from .models import ClaimTier, FidelityReceipt, MappingType, StepMapping, content_hash


ALLOWED_REPLACEMENT_REASONS = {
    "environment_unsupported",
    "component_unavailable_or_unsafe",
    "out_of_scope",
}


def build_fidelity_receipt(
    *,
    root_id: str,
    source_version: str,
    claim_tier: ClaimTier,
    mappings: Iterable[StepMapping],
    reviewer: str,
    reviewed_at_utc: str | None = None,
    notes: str = "",
) -> FidelityReceipt:
    rows = tuple(mappings)
    critical = [row for row in rows if row.critical]
    mapped_critical = [
        row
        for row in critical
        if row.mapping_type in {MappingType.EXACT, MappingType.EQUIVALENT}
    ]
    coverage = len(mapped_critical) / len(critical) if critical else 0.0
    counts = Counter(row.mapping_type.value for row in rows)
    status = "accepted" if critical and coverage == 1.0 else "rejected"
    reviewed_at = reviewed_at_utc or datetime.now(timezone.utc).isoformat()
    material = {
        "root_id": root_id,
        "source_version": source_version,
        "claim_tier": claim_tier.value,
        "mappings": [row.to_dict() for row in rows],
        "reviewer": reviewer,
        "reviewed_at_utc": reviewed_at,
        "status": status,
        "core_step_coverage": coverage,
        "mapping_counts": dict(sorted(counts.items())),
        "notes": notes,
    }
    return FidelityReceipt(
        receipt_id=content_hash(material),
        root_id=root_id,
        source_version=source_version,
        claim_tier=claim_tier,
        mappings=rows,
        reviewer=reviewer,
        reviewed_at_utc=reviewed_at,
        status=status,
        core_step_coverage=coverage,
        mapping_counts=dict(sorted(counts.items())),
        notes=notes,
    )

