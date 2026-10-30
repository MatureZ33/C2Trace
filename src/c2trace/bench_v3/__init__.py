"""Deterministic evaluation helpers for C2Trace Bench v3."""

from .scorer import (
    ScoreValidationError,
    load_json_object,
    render_markdown_summary,
    score_case,
    score_files,
    write_score_outputs,
)
from .aggregation import (
    aggregate_scores,
    render_aggregate_markdown,
    write_aggregate_outputs,
)
from .qualification import (
    QualificationError,
    admission_path,
    build_admission_receipt,
    validate_admission_receipt,
    write_admission_receipt,
)

__all__ = [
    "ScoreValidationError",
    "load_json_object",
    "render_markdown_summary",
    "score_case",
    "score_files",
    "write_score_outputs",
    "aggregate_scores",
    "render_aggregate_markdown",
    "write_aggregate_outputs",
    "QualificationError",
    "admission_path",
    "build_admission_receipt",
    "validate_admission_receipt",
    "write_admission_receipt",
]
