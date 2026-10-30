from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable, Mapping

from c2trace.bench_v3.aggregation import (
    aggregate_scores as _aggregate_scores_v3,
    render_aggregate_markdown as _render_aggregate_markdown_v3,
)
from c2trace.bench_v3.scorer import ScoreValidationError

from .contracts import DATASET_STRATA, SOURCE_KINDS, SOURCE_STRATUM


_GENERIC_TO_LEGACY = {
    "target_network_absent": "manx_network_absent",
    "target_process_absent": "manx_process_absent",
    "target_file_absent": "manx_file_absent",
    "target_persistence_absent": "manx_run_key_absent",
    "control_agent_alive": "control_sandcat_alive",
}


def _score_object(trial: Mapping[str, Any]) -> Mapping[str, Any]:
    return trial.get("score") if isinstance(trial.get("score"), Mapping) else trial


def _stratum(trial: Mapping[str, Any]) -> str:
    score = _score_object(trial)
    return str(trial.get("dataset_stratum") or score.get("dataset_stratum") or "")


def _source_kind(trial: Mapping[str, Any]) -> str:
    score = _score_object(trial)
    return str(trial.get("source_kind") or score.get("source_kind") or "")


def _with_legacy_operational_aliases(trial: Mapping[str, Any]) -> dict[str, Any]:
    value = deepcopy(dict(trial))
    score = value.get("score") if isinstance(value.get("score"), Mapping) else value
    operational = None
    if isinstance(value.get("operational_metrics"), Mapping):
        operational = dict(value["operational_metrics"])
        value["operational_metrics"] = operational
    elif isinstance(score.get("operational_metrics"), Mapping):
        operational = dict(score["operational_metrics"])
        score["operational_metrics"] = operational
    if operational is not None:
        for generic, legacy in _GENERIC_TO_LEGACY.items():
            if legacy not in operational and isinstance(operational.get(generic), bool):
                operational[legacy] = operational[generic]
    return value


def _generic_operational_view(operational: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(operational)
    for generic, legacy in _GENERIC_TO_LEGACY.items():
        if generic not in result and legacy in operational:
            result[generic] = operational[legacy]
    return result


def _decorate_report(report: dict[str, Any]) -> dict[str, Any]:
    overall = report.get("overall") if isinstance(report.get("overall"), Mapping) else {}
    operational = (
        overall.get("operational")
        if isinstance(overall.get("operational"), Mapping)
        else {}
    )
    report["generic_operational"] = _generic_operational_view(operational)
    return report


def aggregate_scores(
    trials: Iterable[Mapping[str, Any]],
    *,
    bootstrap_samples: int = 10_000,
    seed: int = 20260714,
) -> dict[str, Any]:
    rows = [
        _with_legacy_operational_aliases(item)
        for item in trials
        if isinstance(item, Mapping)
    ]
    for index, item in enumerate(rows, start=1):
        stratum = _stratum(item)
        source_kind = _source_kind(item)
        score = _score_object(item)
        nested_stratum = str(score.get("dataset_stratum") or "")
        nested_source_kind = str(score.get("source_kind") or "")
        if stratum not in DATASET_STRATA:
            raise ScoreValidationError(
                f"v4 trial {index} has no valid dataset_stratum"
            )
        if source_kind not in SOURCE_KINDS:
            raise ScoreValidationError(f"v4 trial {index} has no valid source_kind")
        if SOURCE_STRATUM.get(source_kind) != stratum:
            raise ScoreValidationError(
                f"v4 trial {index} source_kind/dataset_stratum pairing is invalid"
            )
        if nested_stratum and nested_stratum != stratum:
            raise ScoreValidationError(
                f"v4 trial {index} wrapper and score dataset_stratum differ"
            )
        if nested_source_kind and nested_source_kind != source_kind:
            raise ScoreValidationError(
                f"v4 trial {index} wrapper and score source_kind differ"
            )
    overall = _decorate_report(
        _aggregate_scores_v3(
            rows, bootstrap_samples=bootstrap_samples, seed=seed
        )
    )
    per_stratum: dict[str, Any] = {}
    for stratum in sorted(DATASET_STRATA):
        selected = [item for item in rows if _stratum(item) == stratum]
        if selected:
            per_stratum[stratum] = _decorate_report(
                _aggregate_scores_v3(
                    selected, bootstrap_samples=bootstrap_samples, seed=seed
                )
            )
    per_source: dict[str, Any] = {}
    for source_kind in sorted(SOURCE_KINDS):
        selected = [item for item in rows if _source_kind(item) == source_kind]
        if selected:
            per_source[source_kind] = _decorate_report(
                _aggregate_scores_v3(
                    selected, bootstrap_samples=bootstrap_samples, seed=seed
                )
            )
    overall["schema_version"] = "c2trace.bench.aggregate.v4"
    overall["per_stratum"] = per_stratum
    overall["per_source_kind"] = per_source
    overall["stratification_policy"] = {
        "primary_reporting": "per_stratum",
        "overall_reporting": "supplemental",
        "reason": (
            "Named chain projections, compound Micro Plans, and platform-native "
            "controls have different ability-instance semantics."
        ),
        "unknown_stratum_trials": sum(
            _stratum(item) not in DATASET_STRATA for item in rows
        ),
        "unknown_source_kind_trials": sum(
            _source_kind(item) not in SOURCE_KINDS for item in rows
        ),
    }
    return overall


def render_aggregate_markdown(report: Mapping[str, Any]) -> str:
    base = _render_aggregate_markdown_v3(report).replace(
        "# C2Trace Bench v3 Aggregate Report",
        "# C2Trace Bench v4 Aggregate Report",
        1,
    )
    lines = [base.rstrip(), "", "## Target-neutral response outcomes", ""]
    operational = (
        report.get("generic_operational")
        if isinstance(report.get("generic_operational"), Mapping)
        else {}
    )
    lines.extend(["| Outcome | Available n | Success/true rate |", "|---|---:|---:|"])
    for key in (
        "wrong_target",
        "target_network_absent",
        "target_process_absent",
        "target_file_absent",
        "target_persistence_absent",
        "control_agent_alive",
    ):
        summary = operational.get(key) if isinstance(operational.get(key), Mapping) else {}
        lines.append(f"| `{key}` | {summary.get('n', 0)} | {summary.get('rate')} |")
    lines.extend(["", "## Dataset strata", ""])
    strata = report.get("per_stratum") if isinstance(report.get("per_stratum"), Mapping) else {}
    if not strata:
        lines.append("No stratum-labelled trials were available.")
    for name, child in sorted(strata.items()):
        counts = child.get("counts") if isinstance(child, Mapping) and isinstance(child.get("counts"), Mapping) else {}
        macro = (
            child.get("overall", {}).get("macro", {}).get("by_scene", {})
            if isinstance(child, Mapping)
            else {}
        )
        lines.extend(
            [
                f"### {name}",
                "",
                f"- Evaluation-valid trials: `{counts.get('evaluation_valid_trials', 0)}`",
                f"- Scenes: `{counts.get('scenes', 0)}`",
                f"- Ability Any-Trace Recall: `{macro.get('ability_any_trace_recall')}`",
                f"- Trace F1: `{macro.get('trace_f1')}`",
                f"- Response Action F1: `{macro.get('response_action_f1')}`",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def write_aggregate_outputs(
    report: Mapping[str, Any], json_path: str | Path, markdown_path: str | Path
) -> None:
    import json

    json_target = Path(json_path)
    markdown_target = Path(markdown_path)
    json_target.parent.mkdir(parents=True, exist_ok=True)
    markdown_target.parent.mkdir(parents=True, exist_ok=True)
    json_target.write_text(
        json.dumps(dict(report), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown_target.write_text(render_aggregate_markdown(report), encoding="utf-8")


__all__ = [
    "aggregate_scores",
    "render_aggregate_markdown",
    "write_aggregate_outputs",
]
