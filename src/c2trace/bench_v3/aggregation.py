from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
from statistics import fmean
from typing import Any, Iterable, Mapping, Sequence

from .scorer import ScoreValidationError


VALID_EVALUATION_CLASSES = frozenset(
    {"evaluation_valid_pass", "evaluation_valid_fail"}
)
TRIAL_CLASSES = frozenset({"infrastructure_invalid", *VALID_EVALUATION_CLASSES})

METRIC_KEYS = (
    "ability_any_trace_recall",
    "mean_ability_trace_coverage",
    "strict_ability_recall",
    "trace_producing_ability_ratio",
    "trace_precision",
    "trace_recall",
    "trace_f1",
    "response_action_precision",
    "response_action_recall",
    "response_action_f1",
)

BOOLEAN_OPERATIONAL_KEYS = (
    "wrong_target",
    "manx_network_absent",
    "manx_process_absent",
    "manx_file_absent",
    "manx_run_key_absent",
    "control_sandcat_alive",
)

NUMERIC_OPERATIONAL_KEYS = (
    "end_to_end_duration_ms",
    "investigation_duration_ms",
    "response_duration_ms",
    "verification_duration_ms",
    "case_duration_ms",
    "llm_calls",
    "tool_calls",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
)

_OPERATIONAL_ALIASES: dict[str, tuple[str, ...]] = {
    "wrong_target": ("wrong_target", "wrong_target_detected"),
    "manx_network_absent": ("manx_network_absent", "network_absent"),
    "manx_process_absent": ("manx_process_absent", "process_absent"),
    "manx_file_absent": ("manx_file_absent", "file_absent"),
    "manx_run_key_absent": (
        "manx_run_key_absent",
        "manx_persistence_absent",
        "run_key_absent",
        "persistence_absent",
    ),
    "control_sandcat_alive": (
        "control_sandcat_alive",
        "sandcat_alive",
        "control_alive",
    ),
    "end_to_end_duration_ms": (
        "end_to_end_duration_ms",
        "total_duration_ms",
    ),
    "investigation_duration_ms": (
        "investigation_duration_ms",
        "traceback_duration_ms",
    ),
    "response_duration_ms": ("response_duration_ms",),
    "verification_duration_ms": ("verification_duration_ms",),
    "case_duration_ms": ("case_duration_ms", "duration_ms", "elapsed_ms"),
    "llm_calls": ("llm_calls", "llm_call_count"),
    "tool_calls": ("tool_calls", "tool_call_count"),
    "prompt_tokens": ("prompt_tokens", "input_tokens"),
    "completion_tokens": ("completion_tokens", "output_tokens"),
    "total_tokens": ("total_tokens", "token_count"),
}


def aggregate_scores(
    trials: Iterable[Mapping[str, Any]],
    *,
    bootstrap_samples: int = 10_000,
    seed: int = 20260714,
) -> dict[str, Any]:
    """Aggregate scored trials without changing their validity classification.

    A trial may be a score object itself or a batch trial wrapper containing a
    ``score`` object. Infrastructure-invalid attempts are counted but never
    enter effect metrics. All bootstrap intervals use a stable derived seed and
    the percentile interval of the resampled arithmetic mean.
    """

    if isinstance(bootstrap_samples, bool) or int(bootstrap_samples) <= 0:
        raise ScoreValidationError("bootstrap_samples must be a positive integer")
    if isinstance(seed, bool):
        raise ScoreValidationError("seed must be an integer")
    try:
        seed = int(seed)
    except (TypeError, ValueError) as exc:
        raise ScoreValidationError("seed must be an integer") from exc
    bootstrap_samples = int(bootstrap_samples)

    normalized = [
        _normalise_trial(item, index)
        for index, item in enumerate(trials, 1)
        if isinstance(item, Mapping)
    ]
    normalized.sort(key=lambda item: (item["case_id"], item["trial_id"]))

    by_scene: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for trial in normalized:
        by_scene[trial["case_id"]].append(trial)

    per_scene = [
        _aggregate_group(
            scene_trials,
            group_name=f"scene:{case_id}",
            bootstrap_samples=bootstrap_samples,
            seed=seed,
            case_id=case_id,
        )
        for case_id, scene_trials in sorted(by_scene.items())
    ]
    valid_trials = [
        trial for trial in normalized if trial["trial_class"] in VALID_EVALUATION_CLASSES
    ]
    trial_macro, trial_distributions = _macro_and_distributions(
        valid_trials,
        group_name="overall:trials",
        bootstrap_samples=bootstrap_samples,
        seed=seed,
    )
    scene_macro, scene_distributions = _scene_macro_and_distributions(
        per_scene,
        bootstrap_samples=bootstrap_samples,
        seed=seed,
    )
    class_counts = _class_counts(normalized)
    overall_operational = _aggregate_operational(
        valid_trials,
        group_name="overall:operational",
        bootstrap_samples=bootstrap_samples,
        seed=seed,
    )

    return {
        "schema_version": "c2trace.bench.aggregate.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "bootstrap": {
            "samples": bootstrap_samples,
            "seed": seed,
            "confidence": 0.95,
            "method": "percentile bootstrap interval of the arithmetic mean",
        },
        "counts": {
            "attempted_trials": len(normalized),
            "evaluation_valid_trials": len(valid_trials),
            "scenes": len(per_scene),
            "trial_class": class_counts,
        },
        "ability_precision": None,
        "ability_f1": None,
        "ability_precision_status": (
            "N/A: C2Trace does not independently predict CALDERA ability IDs"
        ),
        "per_scene": per_scene,
        "overall": {
            "trial_class": class_counts,
            "macro": {
                "by_trial": trial_macro,
                "by_scene": scene_macro,
            },
            "micro": _micro_metrics(valid_trials),
            "distributions": {
                "by_trial": trial_distributions,
                "by_scene": scene_distributions,
            },
            "operational": overall_operational,
        },
        "aggregation_policy": {
            "effect_metric_trials": sorted(VALID_EVALUATION_CLASSES),
            "infrastructure_invalid_in_effect_denominator": False,
            "macro_by_trial": "mean of available evaluation-valid trial metric values",
            "macro_by_scene": "mean of available per-scene trial macro values",
            "micro": "recomputed from pooled TP/FP/FN and ability hit/denominator counts",
            "missing_values": "excluded from the applicable statistic and reported as unavailable/N/A",
            "ability_precision": "not_applicable",
        },
    }


def render_aggregate_markdown(report: Mapping[str, Any]) -> str:
    overall = report.get("overall") if isinstance(report.get("overall"), Mapping) else {}
    macro = overall.get("macro") if isinstance(overall.get("macro"), Mapping) else {}
    trial_macro = macro.get("by_trial") if isinstance(macro.get("by_trial"), Mapping) else {}
    scene_macro = macro.get("by_scene") if isinstance(macro.get("by_scene"), Mapping) else {}
    micro = overall.get("micro") if isinstance(overall.get("micro"), Mapping) else {}
    distributions = (
        overall.get("distributions", {}).get("by_trial", {})
        if isinstance(overall.get("distributions"), Mapping)
        else {}
    )
    counts = report.get("counts") if isinstance(report.get("counts"), Mapping) else {}
    class_counts = counts.get("trial_class") if isinstance(counts.get("trial_class"), Mapping) else {}
    lines = [
        "# C2Trace Bench v3 Aggregate Report",
        "",
        f"- Attempted trials: {counts.get('attempted_trials', 0)}",
        f"- Evaluation-valid trials: {counts.get('evaluation_valid_trials', 0)}",
        f"- Scenes: {counts.get('scenes', 0)}",
        "- Ability Precision/F1: **N/A**",
        "",
        "## Trial classification",
        "",
        "| Class | Count |",
        "|---|---:|",
    ]
    for trial_class in sorted(TRIAL_CLASSES):
        lines.append(f"| `{trial_class}` | {class_counts.get(trial_class, 0)} |")
    lines.extend(
        [
            "",
            "## Overall effectiveness",
            "",
            "| Metric | Trial macro | Scene macro | Micro | Median | IQR | Bootstrap mean 95% CI |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for key in METRIC_KEYS:
        distribution = distributions.get(key) if isinstance(distributions.get(key), Mapping) else {}
        ci = (
            distribution.get("bootstrap_mean_ci95")
            if isinstance(distribution.get("bootstrap_mean_ci95"), Mapping)
            else {}
        )
        ci_text = (
            f"[{_format_number(ci.get('low'))}, {_format_number(ci.get('high'))}]"
            if ci
            else "N/A"
        )
        lines.append(
            "| {} | {} | {} | {} | {} | {} | {} |".format(
                key,
                _format_number(trial_macro.get(key)),
                _format_number(scene_macro.get(key)),
                _format_number(micro.get(key)),
                _format_number(distribution.get("median")),
                _format_number(distribution.get("iqr")),
                ci_text,
            )
        )

    lines.extend(
        [
            "",
            "## Per-scene effectiveness",
            "",
            "| Scene | Attempts | Valid | Any-Trace Recall (macro/micro) | Trace F1 (macro/micro) | Action F1 (macro/micro) |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    scenes = report.get("per_scene") if isinstance(report.get("per_scene"), list) else []
    for scene in scenes:
        if not isinstance(scene, Mapping):
            continue
        scene_macro_value = scene.get("macro") if isinstance(scene.get("macro"), Mapping) else {}
        scene_micro = scene.get("micro") if isinstance(scene.get("micro"), Mapping) else {}
        lines.append(
            "| {} | {} | {} | {}/{} | {}/{} | {}/{} |".format(
                scene.get("case_id") or "unknown",
                scene.get("attempted_trials") or 0,
                scene.get("evaluation_valid_trials") or 0,
                _format_number(scene_macro_value.get("ability_any_trace_recall")),
                _format_number(scene_micro.get("ability_any_trace_recall")),
                _format_number(scene_macro_value.get("trace_f1")),
                _format_number(scene_micro.get("trace_f1")),
                _format_number(scene_macro_value.get("response_action_f1")),
                _format_number(scene_micro.get("response_action_f1")),
            )
        )

    operational = overall.get("operational") if isinstance(overall.get("operational"), Mapping) else {}
    lines.extend(
        [
            "",
            "## Safety and cleanup",
            "",
            "| Outcome | Available n | Success/true rate |",
            "|---|---:|---:|",
        ]
    )
    for key in BOOLEAN_OPERATIONAL_KEYS:
        summary = operational.get(key) if isinstance(operational.get(key), Mapping) else {}
        lines.append(
            f"| {key} | {summary.get('n', 0)} | {_format_number(summary.get('rate'))} |"
        )
    lines.extend(
        [
            "",
            "## Runtime and resource distributions",
            "",
            "| Field | n | Median | IQR | Bootstrap mean 95% CI |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for key in NUMERIC_OPERATIONAL_KEYS:
        summary = operational.get(key) if isinstance(operational.get(key), Mapping) else {}
        ci = summary.get("bootstrap_mean_ci95") if isinstance(summary.get("bootstrap_mean_ci95"), Mapping) else {}
        ci_text = (
            f"[{_format_number(ci.get('low'))}, {_format_number(ci.get('high'))}]"
            if ci
            else "N/A"
        )
        lines.append(
            f"| {key} | {summary.get('n', 0)} | {_format_number(summary.get('median'))} | "
            f"{_format_number(summary.get('iqr'))} | {ci_text} |"
        )
    lines.append("")
    return "\n".join(lines)


def write_aggregate_outputs(
    report: Mapping[str, Any],
    json_path: str | Path,
    markdown_path: str | Path,
) -> None:
    json_target = Path(json_path)
    markdown_target = Path(markdown_path)
    json_target.parent.mkdir(parents=True, exist_ok=True)
    markdown_target.parent.mkdir(parents=True, exist_ok=True)
    json_target.write_text(
        json.dumps(dict(report), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown_target.write_text(render_aggregate_markdown(report), encoding="utf-8")


def _normalise_trial(raw: Mapping[str, Any], index: int) -> dict[str, Any]:
    nested_score = raw.get("score")
    score = nested_score if isinstance(nested_score, Mapping) else raw
    case_id = str(raw.get("case_id") or score.get("case_id") or "unknown").strip() or "unknown"
    trial_id = str(
        raw.get("trial_id") or score.get("trial_id") or f"trial-{index:04d}"
    ).strip()
    trial_class = str(raw.get("trial_class") or score.get("trial_class") or "").strip()
    if trial_class not in TRIAL_CLASSES:
        trial_class = "infrastructure_invalid" if not isinstance(nested_score, Mapping) else "evaluation_valid_fail"
    metrics = score.get("metrics") if isinstance(score.get("metrics"), Mapping) else {}
    return {
        "case_id": case_id,
        "trial_id": trial_id,
        "trial_class": trial_class,
        "score": score,
        "metrics": {
            key: _as_number(metrics.get(key)) for key in METRIC_KEYS
        },
        "operational": _extract_operational(raw, score),
    }


def _aggregate_group(
    trials: Sequence[dict[str, Any]],
    *,
    group_name: str,
    bootstrap_samples: int,
    seed: int,
    case_id: str,
) -> dict[str, Any]:
    valid = [trial for trial in trials if trial["trial_class"] in VALID_EVALUATION_CLASSES]
    macro, distributions = _macro_and_distributions(
        valid,
        group_name=group_name,
        bootstrap_samples=bootstrap_samples,
        seed=seed,
    )
    return {
        "case_id": case_id,
        "attempted_trials": len(trials),
        "evaluation_valid_trials": len(valid),
        "trial_class": _class_counts(trials),
        "macro": macro,
        "micro": _micro_metrics(valid),
        "distributions": distributions,
        "operational": _aggregate_operational(
            valid,
            group_name=f"{group_name}:operational",
            bootstrap_samples=bootstrap_samples,
            seed=seed,
        ),
    }


def _macro_and_distributions(
    trials: Sequence[dict[str, Any]],
    *,
    group_name: str,
    bootstrap_samples: int,
    seed: int,
) -> tuple[dict[str, float | None], dict[str, dict[str, Any]]]:
    macro: dict[str, float | None] = {}
    distributions: dict[str, dict[str, Any]] = {}
    for key in METRIC_KEYS:
        values = [
            value
            for trial in trials
            if (value := _as_number(trial.get("metrics", {}).get(key))) is not None
        ]
        macro[key] = fmean(values) if values else None
        distributions[key] = _distribution(
            values,
            name=f"{group_name}:{key}",
            bootstrap_samples=bootstrap_samples,
            seed=seed,
        )
    return macro, distributions


def _scene_macro_and_distributions(
    scenes: Sequence[Mapping[str, Any]],
    *,
    bootstrap_samples: int,
    seed: int,
) -> tuple[dict[str, float | None], dict[str, dict[str, Any]]]:
    macro: dict[str, float | None] = {}
    distributions: dict[str, dict[str, Any]] = {}
    for key in METRIC_KEYS:
        values = [
            value
            for scene in scenes
            if isinstance(scene.get("macro"), Mapping)
            and (value := _as_number(scene["macro"].get(key))) is not None
        ]
        macro[key] = fmean(values) if values else None
        distributions[key] = _distribution(
            values,
            name=f"overall:scenes:{key}",
            bootstrap_samples=bootstrap_samples,
            seed=seed,
        )
    return macro, distributions


def _micro_metrics(trials: Sequence[dict[str, Any]]) -> dict[str, Any]:
    ability_hits: list[int] = []
    ability_denominators: list[int] = []
    strict_hits: list[int] = []
    strict_denominators: list[int] = []
    trace_producing: list[int] = []
    executed_mandatory: list[int] = []
    coverages: list[float] = []
    trace_counts: list[tuple[int, int, int]] = []
    action_counts: list[tuple[int, int, int]] = []

    for trial in trials:
        score = trial["score"]
        ability_metrics = score.get("ability_metrics") if isinstance(score.get("ability_metrics"), Mapping) else {}
        counts = score.get("counts") if isinstance(score.get("counts"), Mapping) else {}
        hit = _as_int(ability_metrics.get("hit_count"))
        denominator = _as_int(ability_metrics.get("denominator"))
        if hit is not None and denominator is not None:
            ability_hits.append(hit)
            ability_denominators.append(denominator)
        strict = _as_int(ability_metrics.get("strict_hit_count"))
        if strict is None:
            strict = sum(
                1
                for item in _per_ability(score)
                if item.get("included_in_ability_denominator") is True
                and item.get("strict_hit") is True
            )
        if denominator is not None:
            strict_hits.append(strict)
            strict_denominators.append(denominator)
        for item in _per_ability(score):
            if item.get("included_in_ability_denominator") is not True:
                continue
            coverage = _as_number(item.get("coverage"))
            if coverage is not None:
                coverages.append(coverage)
        producing = _as_int(counts.get("trace_producing_abilities"))
        executed = _as_int(counts.get("executed_attack_mapped_mandatory_abilities"))
        if producing is not None and executed is not None:
            trace_producing.append(producing)
            executed_mandatory.append(executed)
        trace_tuple = _metric_count_tuple(score, prefix="trace")
        if trace_tuple is not None:
            trace_counts.append(trace_tuple)
        action_tuple = _metric_count_tuple(score, prefix="response_action")
        if action_tuple is not None:
            action_counts.append(action_tuple)

    trace_tp, trace_fp, trace_fn = _sum_count_tuples(trace_counts)
    action_tp, action_fp, action_fn = _sum_count_tuples(action_counts)
    trace_precision, trace_recall, trace_f1 = _prf(trace_tp, trace_fp, trace_fn, bool(trace_counts))
    action_precision, action_recall, action_f1 = _prf(
        action_tp, action_fp, action_fn, bool(action_counts)
    )
    return {
        "ability_any_trace_recall": _ratio(sum(ability_hits), sum(ability_denominators))
        if ability_denominators
        else None,
        "mean_ability_trace_coverage": fmean(coverages) if coverages else None,
        "strict_ability_recall": _ratio(sum(strict_hits), sum(strict_denominators))
        if strict_denominators
        else None,
        "trace_producing_ability_ratio": _ratio(
            sum(trace_producing), sum(executed_mandatory)
        )
        if executed_mandatory
        else None,
        "trace_precision": trace_precision,
        "trace_recall": trace_recall,
        "trace_f1": trace_f1,
        "response_action_precision": action_precision,
        "response_action_recall": action_recall,
        "response_action_f1": action_f1,
        "pooled_counts": {
            "ability_hits": sum(ability_hits),
            "ability_denominator": sum(ability_denominators),
            "strict_ability_hits": sum(strict_hits),
            "strict_ability_denominator": sum(strict_denominators),
            "ability_coverage_values": len(coverages),
            "trace_producing_abilities": sum(trace_producing),
            "executed_attack_mapped_mandatory_abilities": sum(executed_mandatory),
            "trace_tp": trace_tp,
            "trace_fp": trace_fp,
            "trace_fn": trace_fn,
            "response_action_tp": action_tp,
            "response_action_fp": action_fp,
            "response_action_fn": action_fn,
            "trace_trials_with_counts": len(trace_counts),
            "response_action_trials_with_counts": len(action_counts),
        },
    }


def _aggregate_operational(
    trials: Sequence[dict[str, Any]],
    *,
    group_name: str,
    bootstrap_samples: int,
    seed: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in BOOLEAN_OPERATIONAL_KEYS:
        values = [
            value
            for trial in trials
            if isinstance((value := trial.get("operational", {}).get(key)), bool)
        ]
        true_count = sum(values)
        result[key] = {
            "available": bool(values),
            "n": len(values),
            "true": true_count,
            "false": len(values) - true_count,
            "rate": _ratio(true_count, len(values)),
        }
    for key in NUMERIC_OPERATIONAL_KEYS:
        values = [
            value
            for trial in trials
            if (value := _as_number(trial.get("operational", {}).get(key))) is not None
        ]
        result[key] = _distribution(
            values,
            name=f"{group_name}:{key}",
            bootstrap_samples=bootstrap_samples,
            seed=seed,
        )
    return result


def _extract_operational(raw: Mapping[str, Any], score: Mapping[str, Any]) -> dict[str, Any]:
    sources: list[Mapping[str, Any]] = []
    for parent in (raw, score):
        for container_key in (
            "operational_metrics",
            "operational",
            "outcomes",
            "cleanup",
            "timings",
            "usage",
            "llm_usage",
            "run_metadata",
        ):
            candidate = parent.get(container_key)
            if isinstance(candidate, Mapping):
                sources.append(candidate)
        sources.append(parent)
    result: dict[str, Any] = {}
    for key in (*BOOLEAN_OPERATIONAL_KEYS, *NUMERIC_OPERATIONAL_KEYS):
        value = _first_alias_value(sources, _OPERATIONAL_ALIASES[key])
        if key in BOOLEAN_OPERATIONAL_KEYS:
            result[key] = value if isinstance(value, bool) else None
        else:
            result[key] = _as_number(value)
    return result


def _first_alias_value(sources: Sequence[Mapping[str, Any]], aliases: Sequence[str]) -> Any:
    for source in sources:
        for alias in aliases:
            if alias in source and source.get(alias) is not None:
                return source.get(alias)
    return None


def _distribution(
    values: Sequence[float],
    *,
    name: str,
    bootstrap_samples: int,
    seed: int,
) -> dict[str, Any]:
    clean = sorted(float(value) for value in values)
    if not clean:
        return {
            "available": False,
            "n": 0,
            "mean": None,
            "median": None,
            "q1": None,
            "q3": None,
            "iqr": None,
            "bootstrap_mean_ci95": None,
        }
    q1 = _quantile(clean, 0.25)
    q3 = _quantile(clean, 0.75)
    derived_seed = _derived_seed(seed, name)
    rng = random.Random(derived_seed)
    length = len(clean)
    bootstrap_means = sorted(
        fmean(clean[rng.randrange(length)] for _ in range(length))
        for _ in range(bootstrap_samples)
    )
    return {
        "available": True,
        "n": length,
        "mean": fmean(clean),
        "median": _quantile(clean, 0.5),
        "q1": q1,
        "q3": q3,
        "iqr": q3 - q1,
        "bootstrap_mean_ci95": {
            "low": _quantile(bootstrap_means, 0.025),
            "high": _quantile(bootstrap_means, 0.975),
            "samples": bootstrap_samples,
            "seed": derived_seed,
        },
    }


def _quantile(sorted_values: Sequence[float], probability: float) -> float:
    if not sorted_values:
        raise ValueError("quantile requires at least one value")
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    position = (len(sorted_values) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(sorted_values) - 1)
    weight = position - lower
    return float(sorted_values[lower] * (1 - weight) + sorted_values[upper] * weight)


def _derived_seed(seed: int, name: str) -> int:
    digest = hashlib.sha256(f"{seed}:{name}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def _class_counts(trials: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts = Counter(str(trial.get("trial_class") or "") for trial in trials)
    return {trial_class: counts.get(trial_class, 0) for trial_class in sorted(TRIAL_CLASSES)}


def _per_ability(score: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    values = score.get("per_ability")
    return [item for item in values if isinstance(item, Mapping)] if isinstance(values, list) else []


def _metric_count_tuple(score: Mapping[str, Any], *, prefix: str) -> tuple[int, int, int] | None:
    counts = score.get("counts") if isinstance(score.get("counts"), Mapping) else {}
    metric_container_key = "trace_metrics" if prefix == "trace" else "response_action_metrics"
    metric_container = (
        score.get(metric_container_key)
        if isinstance(score.get(metric_container_key), Mapping)
        else {}
    )
    values = []
    for suffix in ("tp", "fp", "fn"):
        value = _as_int(counts.get(f"{prefix}_{suffix}"))
        if value is None:
            value = _as_int(metric_container.get(suffix))
        if value is None:
            return None
        values.append(value)
    return values[0], values[1], values[2]


def _sum_count_tuples(values: Sequence[tuple[int, int, int]]) -> tuple[int, int, int]:
    return (
        sum(value[0] for value in values),
        sum(value[1] for value in values),
        sum(value[2] for value in values),
    )


def _prf(
    tp: int, fp: int, fn: int, available: bool
) -> tuple[float | None, float | None, float | None]:
    if not available:
        return None, None, None
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    if precision is None or recall is None:
        f1 = None
    elif precision + recall:
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = 0.0
    return precision, recall, f1


def _ratio(numerator: int | float, denominator: int | float) -> float | None:
    return numerator / denominator if denominator else None


def _as_number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number or number in {float("inf"), float("-inf")}:
        return None
    return number


def _as_int(value: Any) -> int | None:
    number = _as_number(value)
    if number is None or not number.is_integer() or number < 0:
        return None
    return int(number)


def _format_number(value: Any) -> str:
    number = _as_number(value)
    return "N/A" if number is None else f"{number:.4f}"
