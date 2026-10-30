from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import ntpath
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence


SUPPORTED_TRACE_TYPES = frozenset(
    {
        "network_connection",
        "process",
        "process_parent_edge",
        "file",
        "registry_run_key",
        "scheduled_task",
        "service",
        "powershell_history",
        "dns_cache",
    }
)

RESPONSE_TOOLS = frozenset(
    {
        "kill_process",
        "remove_file",
        "remove_registry",
        "remove_scheduled_task",
        "remove_service",
    }
)

_IGNORED_FINDING_TYPES = frozenset(
    {
        "minimal_c2_seed_alert",
        "persistence_candidate",
        "persistence_summary",
        "cleanup_verification",
        "cleanup_network_verified",
        "cleanup_process_verified",
        "cleanup_file_verified",
        "cleanup_persistence_verified",
        "cleanup_action_verified",
        "response_action_dry_run",
        "response_action_executed",
    }
)


class ScoreValidationError(ValueError):
    """Raised when a score input cannot be interpreted deterministically."""


@dataclass(slots=True)
class TraceFact:
    trace_id: str
    trace_type: str
    ability_instance_id: str
    fields: dict[str, Any]
    canonical_key: str = ""
    required: bool = True
    discriminative: bool = False
    anchor: bool = False
    shared_context: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AbilityInstance:
    ability_instance_id: str
    operation_id: str
    link_id: str
    ability_id: str
    attack_mapped: bool
    mandatory: bool
    executed: bool
    metric_eligible: bool
    atomic_trace_eligible: bool
    metric_exclusion_reason: str
    registered_trace_count: int
    traces: list[TraceFact]


@dataclass(slots=True)
class Observation:
    observation_id: str
    trace_type: str
    fields: dict[str, Any]
    finding_ids: list[str]
    finding_types: list[str]
    explicit_key: str = ""

    @property
    def canonical_key(self) -> str:
        if self.explicit_key:
            return self.explicit_key
        return _generated_key(self.trace_type, self.fields)


def load_json_object(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ScoreValidationError(f"cannot read JSON object {source}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ScoreValidationError(f"JSON root must be an object: {source}")
    return payload


def score_files(ground_truth_path: str | Path, casefile_path: str | Path) -> dict[str, Any]:
    return score_case(load_json_object(ground_truth_path), load_json_object(casefile_path))


def score_case(ground_truth: Mapping[str, Any], casefile: Mapping[str, Any]) -> dict[str, Any]:
    """Score one CaseFile against pre-registered Bench v3 ground truth.

    Trace matching is global, deterministic, and one-to-one.  In particular,
    one shared C2 observation can never give credit to two ability instances.
    """

    if not isinstance(ground_truth, Mapping) or not isinstance(casefile, Mapping):
        raise ScoreValidationError("ground_truth and casefile must be JSON objects")

    abilities = _load_ability_instances(ground_truth)
    eligible_abilities = [
        item
        for item in abilities
        if item.attack_mapped and item.mandatory and item.executed
    ]
    scoreable_abilities = [
        item for item in eligible_abilities if item.metric_eligible and item.traces
    ]
    # Ability Recall is intentionally limited to executed, attack-mapped,
    # mandatory ability instances. Atomic trace P/R/F1 has a different
    # universe: every scoreable trace from an executed ability is ground truth,
    # including a support ability. Otherwise a correct finding for a run-scoped
    # artifact (for example the Manx file staged by Bootstrap) would be counted
    # as an FP solely because its producer is outside the Ability denominator.
    # Per-trace ``scoreable_by_c2trace`` remains the explicit opt-in switch.
    facts = [
        trace
        for item in abilities
        if item.executed and item.atomic_trace_eligible
        for trace in item.traces
    ]
    _validate_unique_trace_ids(facts)

    observations = _extract_observations(
        casefile,
        include_process_parent_edges=any(
            fact.trace_type == "process_parent_edge" for fact in facts
        ),
    )
    trace_matches = _maximum_one_to_one_trace_matches(facts, observations)
    matched_fact_ids = set(trace_matches)
    matched_observation_indexes = set(trace_matches.values())

    trace_tp = len(trace_matches)
    trace_fp = len(observations) - len(matched_observation_indexes)
    trace_fn = len(facts) - len(matched_fact_ids)
    trace_precision = _ratio(trace_tp, trace_tp + trace_fp)
    trace_recall = _ratio(trace_tp, trace_tp + trace_fn)

    per_ability: list[dict[str, Any]] = []
    ability_hits = 0
    strict_hits = 0
    coverage_values: list[float] = []
    scoreable_instance_ids = {
        ability.ability_instance_id for ability in scoreable_abilities
    }
    for ability in abilities:
        included_in_denominator = ability.ability_instance_id in scoreable_instance_ids
        evaluated_traces = ability.traces if included_in_denominator else []
        atomic_traces = (
            ability.traces
            if ability.executed and ability.atomic_trace_eligible
            else []
        )
        matched = [trace for trace in evaluated_traces if trace.trace_id in matched_fact_ids]
        unmatched = [trace for trace in evaluated_traces if trace.trace_id not in matched_fact_ids]
        atomic_matched = [
            trace for trace in atomic_traces if trace.trace_id in matched_fact_ids
        ]
        atomic_unmatched = [
            trace for trace in atomic_traces if trace.trace_id not in matched_fact_ids
        ]
        is_scoreable = included_in_denominator
        hit = bool(matched) if is_scoreable else None
        coverage = _ratio(len(matched), len(evaluated_traces))
        strict_traces = [
            trace
            for trace in evaluated_traces
            if trace.required or trace.anchor
        ]
        strict_hit = (
            bool(strict_traces)
            and all(trace.trace_id in matched_fact_ids for trace in strict_traces)
            if is_scoreable
            else None
        )
        if hit:
            ability_hits += 1
        if strict_hit:
            strict_hits += 1
        if is_scoreable and coverage is not None:
            coverage_values.append(coverage)
        per_ability.append(
            {
                "ability_instance_id": ability.ability_instance_id,
                "operation_id": ability.operation_id,
                "link_id": ability.link_id,
                "ability_id": ability.ability_id,
                "attack_mapped": ability.attack_mapped,
                "mandatory": ability.mandatory,
                "executed": ability.executed,
                "metric_eligible": ability.metric_eligible,
                "atomic_trace_eligible": ability.atomic_trace_eligible,
                "metric_exclusion_reason": ability.metric_exclusion_reason or None,
                "included_in_ability_denominator": included_in_denominator,
                "scoreable": is_scoreable,
                "registered_trace_count": ability.registered_trace_count,
                "scoreable_trace_count": len(ability.traces),
                "trace_count": len(evaluated_traces),
                "matched_trace_count": len(matched),
                "unmatched_trace_count": len(unmatched),
                "atomic_trace_count": len(atomic_traces),
                "atomic_matched_trace_count": len(atomic_matched),
                "atomic_unmatched_trace_count": len(atomic_unmatched),
                "hit": hit,
                "coverage": coverage,
                "strict_hit": strict_hit,
                "matched_traces": [
                    _trace_match_detail(trace, observations[trace_matches[trace.trace_id]])
                    for trace in matched
                ],
                "unmatched_traces": [_trace_public(trace) for trace in unmatched],
                "atomic_matched_traces": [
                    _trace_match_detail(
                        trace, observations[trace_matches[trace.trace_id]]
                    )
                    for trace in atomic_matched
                ],
                "atomic_unmatched_traces": [
                    _trace_public(trace) for trace in atomic_unmatched
                ],
            }
        )

    expected_actions = _load_expected_actions(ground_truth)
    predicted_actions = _extract_predicted_actions(casefile)
    action_matches = _maximum_one_to_one_action_matches(expected_actions, predicted_actions)
    action_tp = len(action_matches)
    action_fp = len(predicted_actions) - len(set(action_matches.values()))
    action_fn = len(expected_actions) - len(action_matches)
    action_precision = _ratio(action_tp, action_tp + action_fp)
    action_recall = _ratio(action_tp, action_tp + action_fn)

    case_id = str(casefile.get("case_id") or ground_truth.get("case_id") or "")
    metrics = {
        "ability_any_trace_recall": _ratio(ability_hits, len(scoreable_abilities)),
        "mean_ability_trace_coverage": (
            sum(coverage_values) / len(coverage_values) if coverage_values else None
        ),
        "strict_ability_recall": _ratio(strict_hits, len(scoreable_abilities)),
        "trace_producing_ability_ratio": _ratio(
            len(scoreable_abilities), len(eligible_abilities)
        ),
        "trace_precision": trace_precision,
        "trace_recall": trace_recall,
        "trace_f1": _f1(trace_precision, trace_recall),
        "response_action_precision": action_precision,
        "response_action_recall": action_recall,
        "response_action_f1": _f1(action_precision, action_recall),
    }
    explicit_trial_class = str(
        casefile.get("trial_class") or ground_truth.get("trial_class") or ""
    ).strip()
    if explicit_trial_class not in {
        "infrastructure_invalid",
        "evaluation_valid_pass",
        "evaluation_valid_fail",
    }:
        if abilities and not eligible_abilities:
            explicit_trial_class = "infrastructure_invalid"
        elif trace_fn == 0 and trace_fp == 0 and action_fn == 0 and action_fp == 0:
            explicit_trial_class = "evaluation_valid_pass"
        else:
            explicit_trial_class = "evaluation_valid_fail"

    result = {
        "schema_version": "c2trace.bench.evaluation.v2",
        "case_id": case_id,
        "trial_class": explicit_trial_class,
        "ground_truth_schema_version": str(ground_truth.get("schema_version") or ""),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ability_precision": None,
        "ability_precision_status": "N/A: C2Trace does not independently predict CALDERA ability IDs",
        "counts": {
            "executed_attack_mapped_mandatory_abilities": len(eligible_abilities),
            "trace_producing_abilities": len(scoreable_abilities),
            "ground_truth_trace_facts": len(facts),
            "ability_denominator_trace_facts": sum(
                len(item.traces) for item in scoreable_abilities
            ),
            "non_ability_atomic_trace_facts": len(facts)
            - sum(len(item.traces) for item in scoreable_abilities),
            "predicted_trace_observations": len(observations),
            "trace_tp": trace_tp,
            "trace_fp": trace_fp,
            "trace_fn": trace_fn,
            "expected_response_actions": len(expected_actions),
            "predicted_response_actions": len(predicted_actions),
            "response_action_tp": action_tp,
            "response_action_fp": action_fp,
            "response_action_fn": action_fn,
        },
        "metrics": metrics,
        "ability_metrics": {
            "precision": None,
            "precision_status": "not_applicable",
            "any_trace_recall": metrics["ability_any_trace_recall"],
            "mean_trace_coverage": metrics["mean_ability_trace_coverage"],
            "strict_recall": metrics["strict_ability_recall"],
            "trace_producing_ratio": metrics["trace_producing_ability_ratio"],
            "hit_count": ability_hits,
            "strict_hit_count": strict_hits,
            "denominator": len(scoreable_abilities),
        },
        "trace_metrics": {
            "precision": metrics["trace_precision"],
            "recall": metrics["trace_recall"],
            "f1": metrics["trace_f1"],
            "tp": trace_tp,
            "fp": trace_fp,
            "fn": trace_fn,
        },
        "response_action_metrics": {
            "precision": metrics["response_action_precision"],
            "recall": metrics["response_action_recall"],
            "f1": metrics["response_action_f1"],
            "tp": action_tp,
            "fp": action_fp,
            "fn": action_fn,
        },
        "operational_metrics": _derive_operational_metrics(ground_truth, casefile),
        "per_ability": per_ability,
        "trace_matching": {
            "matches": [
                _trace_match_detail(fact, observations[trace_matches[fact.trace_id]])
                for fact in facts
                if fact.trace_id in trace_matches
            ],
            "unmatched_ground_truth": [
                _trace_public(fact) for fact in facts if fact.trace_id not in matched_fact_ids
            ],
            "unmatched_observations": [
                _observation_public(observation)
                for index, observation in enumerate(observations)
                if index not in matched_observation_indexes
            ],
        },
        "response_action_matching": {
            "matches": [
                {
                    "expected": expected_actions[index],
                    "observed": predicted_actions[action_matches[index]],
                }
                for index in sorted(action_matches)
            ],
            "unmatched_expected": [
                action for index, action in enumerate(expected_actions) if index not in action_matches
            ],
            "unmatched_observed": [
                action
                for index, action in enumerate(predicted_actions)
                if index not in set(action_matches.values())
            ],
        },
        "scoring_policy": {
            "trace_matching": "deterministic_global_one_to_one",
            "valid_window": (
                "semantic after_scenario_before_response window enforced by the controller's "
                "before_response and unchanged-after-dry-run evidence gates"
            ),
            "ability_precision": "not_applicable",
            "empty_denominator": "null",
            "ignored_findings": sorted(_IGNORED_FINDING_TYPES),
            "unlinked_persistence_candidates": "ignored",
            "seed_alert": "ignored",
            "summary_response_cleanup_findings": "ignored",
            "process_parent_edges": "evaluated_only_when_preregistered",
        },
    }
    return result


def _derive_operational_metrics(
    ground_truth: Mapping[str, Any], casefile: Mapping[str, Any]
) -> dict[str, Any]:
    final_status = str(casefile.get("final_status") or "").strip().lower()
    errors = casefile.get("errors") if isinstance(casefile.get("errors"), list) else []
    error_types = {
        str(item.get("error_type") or "").strip().lower()
        for item in errors
        if isinstance(item, Mapping)
    }
    wrong_markers = {"wrong_target", "protected_target_blocked"}
    if final_status in wrong_markers or error_types & wrong_markers:
        wrong_target: bool | None = True
    elif final_status:
        wrong_target = False
    else:
        wrong_target = None

    observed = ground_truth.get("observed")
    post = observed.get("post_response") if isinstance(observed, Mapping) else None
    if isinstance(post, Mapping):
        process_absent: bool | None = not bool(post.get("target"))
        file_absent: bool | None = not bool(post.get("target_file"))
        network_absent: bool | None = not bool(post.get("network_connections"))
        run_key_absent: bool | None = not bool(post.get("run_key"))
        control_alive: bool | None = bool(post.get("control"))
    else:
        process_absent = file_absent = network_absent = run_key_absent = control_alive = None

    duration_ms: float | None = None
    started = _parse_iso_datetime(casefile.get("created_at"))
    finished = _parse_iso_datetime(casefile.get("updated_at"))
    if started is not None and finished is not None and finished >= started:
        duration_ms = (finished - started).total_seconds() * 1000
    action_results = casefile.get("action_results")
    tool_calls = len(action_results) if isinstance(action_results, list) else None
    return {
        "wrong_target": wrong_target,
        "manx_network_absent": network_absent,
        "manx_process_absent": process_absent,
        "manx_file_absent": file_absent,
        "manx_run_key_absent": run_key_absent,
        "manx_persistence_absent": run_key_absent,
        "control_sandcat_alive": control_alive,
        "case_duration_ms": duration_ms,
        "tool_calls": tool_calls,
        "llm_calls": None,
        "prompt_tokens": None,
        "completion_tokens": None,
        "total_tokens": None,
    }


def _parse_iso_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def write_score_outputs(
    score: Mapping[str, Any],
    json_path: str | Path,
    markdown_path: str | Path,
) -> None:
    json_target = Path(json_path)
    markdown_target = Path(markdown_path)
    json_target.parent.mkdir(parents=True, exist_ok=True)
    markdown_target.parent.mkdir(parents=True, exist_ok=True)
    json_target.write_text(
        json.dumps(dict(score), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown_target.write_text(render_markdown_summary(score), encoding="utf-8")


def render_markdown_summary(score: Mapping[str, Any]) -> str:
    metrics = score.get("metrics") if isinstance(score.get("metrics"), Mapping) else {}
    counts = score.get("counts") if isinstance(score.get("counts"), Mapping) else {}
    rows = [
        ("Ability Any-Trace Recall", metrics.get("ability_any_trace_recall")),
        ("Mean Ability Trace Coverage", metrics.get("mean_ability_trace_coverage")),
        ("Strict Ability Recall", metrics.get("strict_ability_recall")),
        ("Trace-Producing Ability Ratio", metrics.get("trace_producing_ability_ratio")),
        ("Trace Precision", metrics.get("trace_precision")),
        ("Trace Recall", metrics.get("trace_recall")),
        ("Trace F1", metrics.get("trace_f1")),
        ("Response Action Precision", metrics.get("response_action_precision")),
        ("Response Action Recall", metrics.get("response_action_recall")),
        ("Response Action F1", metrics.get("response_action_f1")),
    ]
    lines = [
        f"# C2Trace Bench v3 Score: {score.get('case_id') or 'unknown'}",
        "",
        "Ability Precision: **N/A**（C2Trace 不独立预测 CALDERA ability ID）。",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    lines.extend(f"| {name} | {_format_metric(value)} |" for name, value in rows)
    lines.extend(
        [
            "",
            "## Counts",
            "",
            "| Count | Value |",
            "|---|---:|",
        ]
    )
    for key, value in counts.items():
        lines.append(f"| `{key}` | {value} |")
    lines.extend(
        [
            "",
            "## Per-ability details",
            "",
            "| Ability instance | Ability ID | Traces | Matched | Hit | Coverage | Strict |",
            "|---|---|---:|---:|---|---:|---|",
        ]
    )
    abilities = score.get("per_ability") if isinstance(score.get("per_ability"), list) else []
    for ability in abilities:
        if not isinstance(ability, Mapping):
            continue
        lines.append(
            "| `{}` | `{}` | {} | {} | {} | {} | {} |".format(
                ability.get("ability_instance_id") or "",
                ability.get("ability_id") or "",
                ability.get("trace_count") or 0,
                ability.get("matched_trace_count") or 0,
                _format_bool(ability.get("hit")),
                _format_metric(ability.get("coverage")),
                _format_bool(ability.get("strict_hit")),
            )
        )
    unmatched_gt = (
        score.get("trace_matching", {}).get("unmatched_ground_truth", [])
        if isinstance(score.get("trace_matching"), Mapping)
        else []
    )
    unmatched_observed = (
        score.get("trace_matching", {}).get("unmatched_observations", [])
        if isinstance(score.get("trace_matching"), Mapping)
        else []
    )
    lines.extend(
        [
            "",
            "## Trace mismatches",
            "",
            f"- Unmatched Ground Truth traces: {len(unmatched_gt)}",
            f"- Unmatched C2Trace observations: {len(unmatched_observed)}",
            "",
        ]
    )
    return "\n".join(lines)


def _load_ability_instances(ground_truth: Mapping[str, Any]) -> list[AbilityInstance]:
    raw_abilities: Any = ground_truth.get("ability_instances")
    if not isinstance(raw_abilities, list):
        caldera = ground_truth.get("caldera")
        raw_abilities = caldera.get("ability_instances") if isinstance(caldera, Mapping) else None
    if not isinstance(raw_abilities, list):
        raw_abilities = []

    abilities: list[AbilityInstance] = []
    for index, raw in enumerate(raw_abilities):
        if not isinstance(raw, Mapping):
            raise ScoreValidationError(f"ability_instances[{index}] must be an object")
        ability_id = str(raw.get("ability_id") or "").strip()
        operation_id = str(raw.get("operation_id") or raw.get("operation") or "").strip()
        link_id = str(raw.get("link_id") or "").strip()
        instance_id = str(
            raw.get("ability_instance_id")
            or raw.get("instance_id")
            or raw.get("instance_key")
            or ""
        ).strip()
        if not instance_id:
            if not ability_id:
                raise ScoreValidationError(
                    f"ability_instances[{index}] requires ability_instance_id or ability_id"
                )
            instance_id = ":".join(item or "unknown" for item in (operation_id, link_id, ability_id))
        raw_traces = raw.get("trace_facts")
        if raw_traces is None:
            raw_traces = raw.get("traces", [])
        if not isinstance(raw_traces, list):
            raise ScoreValidationError(f"ability {instance_id} trace_facts must be a list")
        traces = _load_trace_facts(raw_traces, instance_id)
        status = str(raw.get("status") or "").strip().lower()
        if "executed" in raw:
            executed = _as_bool(raw.get("executed"), False)
        else:
            executed = status in {"success", "succeeded", "completed"}
        attack_mapped = _as_bool(raw.get("attack_mapped"), True)
        mandatory = _as_bool(raw.get("mandatory"), True)
        metric_eligible = _as_bool(raw.get("metric_eligible"), True)
        abilities.append(
            AbilityInstance(
                ability_instance_id=instance_id,
                operation_id=operation_id,
                link_id=link_id,
                ability_id=ability_id,
                attack_mapped=attack_mapped,
                mandatory=mandatory,
                executed=executed,
                metric_eligible=metric_eligible,
                atomic_trace_eligible=_as_bool(
                    raw.get("atomic_trace_eligible"),
                    attack_mapped and mandatory and metric_eligible,
                ),
                metric_exclusion_reason=str(raw.get("metric_exclusion_reason") or ""),
                registered_trace_count=len(raw_traces),
                traces=traces,
            )
        )

    top_level_traces = ground_truth.get("trace_facts")
    if isinstance(top_level_traces, list):
        by_id = {ability.ability_instance_id: ability for ability in abilities}
        grouped: dict[str, list[Mapping[str, Any]]] = {}
        for index, raw_trace in enumerate(top_level_traces):
            if not isinstance(raw_trace, Mapping):
                raise ScoreValidationError(f"trace_facts[{index}] must be an object")
            producer = str(raw_trace.get("producer_ability_instance") or "").strip()
            if not producer:
                raise ScoreValidationError(f"trace_facts[{index}] requires producer_ability_instance")
            grouped.setdefault(producer, []).append(raw_trace)
        for producer, raw_group in grouped.items():
            traces = _load_trace_facts(raw_group, producer)
            if producer in by_id:
                existing_ids = {trace.trace_id for trace in by_id[producer].traces}
                by_id[producer].traces.extend(
                    trace for trace in traces if trace.trace_id not in existing_ids
                )
            else:
                ability = AbilityInstance(
                    ability_instance_id=producer,
                    operation_id="",
                    link_id="",
                    ability_id="",
                    attack_mapped=True,
                    mandatory=True,
                    executed=True,
                    metric_eligible=True,
                    atomic_trace_eligible=True,
                    metric_exclusion_reason="",
                    registered_trace_count=len(raw_group),
                    traces=traces,
                )
                abilities.append(ability)
                by_id[producer] = ability

    instance_ids = [ability.ability_instance_id for ability in abilities]
    if len(instance_ids) != len(set(instance_ids)):
        raise ScoreValidationError("ability_instance_id values must be unique")
    return abilities


def _load_trace_facts(raw_traces: Sequence[Any], ability_instance_id: str) -> list[TraceFact]:
    traces: list[TraceFact] = []
    for index, raw in enumerate(raw_traces):
        if not isinstance(raw, Mapping):
            raise ScoreValidationError(
                f"ability {ability_instance_id} trace_facts[{index}] must be an object"
            )
        if _as_bool(
            raw.get("scoreable_by_c2trace", raw.get("scoreable")), True
        ) is False:
            continue
        trace_type = str(raw.get("trace_type") or raw.get("type") or "").strip().lower()
        if trace_type not in SUPPORTED_TRACE_TYPES:
            continue
        trace_id = str(raw.get("trace_id") or "").strip()
        if not trace_id:
            raise ScoreValidationError(
                f"ability {ability_instance_id} scoreable trace_facts[{index}] requires trace_id"
            )
        producer = str(raw.get("producer_ability_instance") or ability_instance_id).strip()
        if producer != ability_instance_id:
            raise ScoreValidationError(
                f"trace {trace_id} producer {producer!r} does not match container {ability_instance_id!r}"
            )
        expected = raw.get("expected_value", raw.get("expected", {}))
        fields = _normalise_trace_fields(trace_type, expected)
        canonical_key = _normalise_text(raw.get("canonical_key"))
        if not fields and not canonical_key:
            raise ScoreValidationError(
                f"trace {trace_id} requires expected_value fields or canonical_key"
            )
        traces.append(
            TraceFact(
                trace_id=trace_id,
                trace_type=trace_type,
                ability_instance_id=ability_instance_id,
                fields=fields,
                canonical_key=canonical_key,
                required=_as_bool(raw.get("required"), True),
                discriminative=_as_bool(raw.get("discriminative"), False),
                anchor=_as_bool(raw.get("anchor"), False),
                shared_context=_as_bool(raw.get("shared_context"), False),
                raw=dict(raw),
            )
        )
    return traces


def _validate_unique_trace_ids(facts: Sequence[TraceFact]) -> None:
    ids = [fact.trace_id for fact in facts]
    if len(ids) != len(set(ids)):
        raise ScoreValidationError("trace_id values must be globally unique")


def _extract_observations(
    casefile: Mapping[str, Any], *, include_process_parent_edges: bool = True
) -> list[Observation]:
    raw_findings = casefile.get("findings", [])
    if not isinstance(raw_findings, list):
        raise ScoreValidationError("CaseFile findings must be a list")
    observations: list[Observation] = []
    for index, finding in enumerate(raw_findings):
        if not isinstance(finding, Mapping):
            continue
        finding_type = str(finding.get("finding_type") or "").strip().lower()
        if not finding_type or finding_type in _IGNORED_FINDING_TYPES:
            continue
        if finding_type.endswith("_summary") or finding_type.startswith(("response_", "cleanup_")):
            continue
        finding_id = str(finding.get("finding_id") or f"finding-{index}")
        details = finding.get("details") if isinstance(finding.get("details"), Mapping) else {}
        raw_observations: list[tuple[str, Any]] = []

        if finding_type == "network_confirmed":
            for connection in _dict_items(details.get("connections")):
                raw_observations.append(("network_connection", connection))
        elif finding_type == "network_connection":
            raw_observations.append(("network_connection", details))
        elif finding_type == "c2_process_attributed":
            raw_observations.extend(
                [("network_connection", details), ("process", details)]
            )
        elif finding_type in {"process_detail", "suspicious_process_path"}:
            raw_observations.append(("process", details or {"path": finding.get("value")}))
        elif finding_type == "process_tree":
            root = details.get("root") if isinstance(details.get("root"), Mapping) else None
            chain = _dict_items(details.get("chain"))
            if root is None and chain:
                root = chain[0]
            if root is not None:
                raw_observations.append(("process", root))
            # A process_tree finding always proves its root process. Parent
            # edges become independent benchmark assertions only when that
            # trace type was pre-registered. For Manx, Start-Process gives it
            # a transient CALDERA PowerShell parent that normally exits before
            # investigation; Win32_Process then retains only a stale
            # parent_pid. An opportunistically live ancestor is not reliable
            # frozen Ground Truth and must not become an automatic FP.
            if include_process_parent_edges:
                for child, parent in zip(chain, chain[1:]):
                    raw_observations.append(
                        ("process_parent_edge", {"child": child, "parent": parent})
                    )
        elif finding_type in {"file_metadata", "payload_file_verified"}:
            if details.get("exists") is not False:
                raw_observations.append(
                    ("file", details or {"path": finding.get("value")})
                )
        elif finding_type == "persistence_linked_to_payload":
            category = str(details.get("category") or "").lower()
            trace_type = {
                "registry_run_keys": "registry_run_key",
                "registry_run_key": "registry_run_key",
                "scheduled_tasks": "scheduled_task",
                "scheduled_task": "scheduled_task",
                "services": "service",
                "service": "service",
            }.get(category)
            if trace_type:
                raw_observations.append((trace_type, details))
        elif finding_type == "powershell_history_hit":
            raw_observations.append(
                ("powershell_history", details or {"command": finding.get("value")})
            )
        elif finding_type == "dns_cache_confirmed":
            for entry in _dict_items(details.get("entries")):
                raw_observations.append(("dns_cache", entry))

        for trace_type, raw_value in raw_observations:
            fields = _normalise_trace_fields(trace_type, raw_value)
            if not fields:
                continue
            observation = Observation(
                observation_id=f"obs-{len(observations) + 1:04d}",
                trace_type=trace_type,
                fields=fields,
                finding_ids=[finding_id],
                finding_types=[finding_type],
                explicit_key=_normalise_text(details.get("canonical_key")),
            )
            _merge_or_append_observation(observations, observation)

    observations.sort(key=lambda item: (item.trace_type, item.canonical_key, item.observation_id))
    for index, observation in enumerate(observations, 1):
        observation.observation_id = f"obs-{index:04d}"
    return observations



def _strip_exe_suffix(text: str) -> str:
    if text.endswith(".exe"):
        return text[:-4]
    return text

def _normalise_trace_fields(trace_type: str, raw_value: Any) -> dict[str, Any]:
    if isinstance(raw_value, Mapping):
        raw = raw_value
    elif raw_value is None:
        raw = {}
    else:
        raw = _scalar_trace_value(trace_type, raw_value)

    if trace_type == "network_connection":
        fields = {
            "protocol": _normalise_text(_first(raw, "protocol", "proto") or "tcp"),
            "local_address": _normalise_ip(
                _first(raw, "local_address", "local_ip", "source_ip", "src_ip")
            ),
            "local_port": _normalise_int(
                _first(raw, "local_port", "source_port", "src_port")
            ),
            "remote_address": _normalise_ip(
                _first(
                    raw,
                    "remote_address",
                    "remote_ip",
                    "destination_ip",
                    "dest_ip",
                )
            ),
            "remote_port": _normalise_int(
                _first(raw, "remote_port", "destination_port", "dest_port")
            ),
            "pid": _normalise_int(_first(raw, "pid", "owning_process", "process_id")),
            "state": _normalise_text(raw.get("state")),
        }
    elif trace_type == "process":
        fields = {
            "pid": _normalise_int(_first(raw, "pid", "process_id")),
            "creation_time": _normalise_datetime(
                _first(raw, "creation_time", "creation_time_utc", "creation_date", "start_time")
            ),
            "path": _normalise_windows_path(
                _first(raw, "path", "process_path", "executable_path", "image")
            ),
            "name": _strip_exe_suffix(_normalise_text(_first(raw, "name", "process_name"))),
        }
    elif trace_type == "process_parent_edge":
        child = raw.get("child") if isinstance(raw.get("child"), Mapping) else raw
        parent = raw.get("parent") if isinstance(raw.get("parent"), Mapping) else raw
        fields = {
            "child_pid": _normalise_int(_first(child, "pid", "process_id", "child_pid")),
            "parent_pid": _normalise_int(
                _first(parent, "pid", "process_id") or _first(raw, "parent_pid", "ppid")
            ),
            "child_name": _normalise_text(
                _first(child, "name", "process_name", "child_name")
            ),
            "parent_name": _normalise_text(
                _first(parent, "name", "process_name", "parent_name")
            ),
            "child_path": _normalise_windows_path(
                _first(child, "path", "process_path", "child_path")
            ),
            "parent_path": _normalise_windows_path(
                _first(parent, "path", "process_path", "parent_path")
            ),
        }
    elif trace_type == "file":
        fields = {
            "path": _normalise_windows_path(_first(raw, "path", "file_path")),
            "sha256": _normalise_hash(_first(raw, "sha256", "file_sha256", "hash")),
            "size": _normalise_int(_first(raw, "size", "length")),
        }
    elif trace_type == "registry_run_key":
        key_path = _first(raw, "key_path", "reg_path", "path")
        fields = {
            "hive": _normalise_registry_hive(raw.get("hive"), key_path),
            "key_path": _normalise_registry_path(key_path),
            "value_name": _normalise_text(_first(raw, "value_name", "name")),
            "value_data": _normalise_command(_first(raw, "value_data", "value", "expected_value")),
        }
    elif trace_type == "scheduled_task":
        actions = _first(raw, "actions", "action")
        fields = {
            "task_path": _normalise_task_path(_first(raw, "task_path", "path")),
            "task_name": _normalise_text(_first(raw, "task_name", "name")),
            "actions": _normalise_sequence(actions, _normalise_command),
        }
    elif trace_type == "service":
        fields = {
            "service_name": _normalise_text(_first(raw, "service_name", "name")),
            "binary_path": _normalise_command(
                _first(raw, "binary_path", "binary_path_name", "path_name", "path")
            ),
        }
    elif trace_type == "powershell_history":
        command = _normalise_command(_first(raw, "command", "value", "line"))
        command_hash = _normalise_hash(_first(raw, "command_hash", "sha256"))
        if command and not command_hash:
            command_hash = hashlib.sha256(command.encode("utf-8")).hexdigest()
        fields = {"command": command, "command_hash": command_hash}
    elif trace_type == "dns_cache":
        fields = {
            "name": _normalise_domain(_first(raw, "name", "domain", "entry")),
            "record_type": _normalise_text(_first(raw, "record_type", "type")),
            "data": _normalise_ip_or_text(_first(raw, "data", "address", "value")),
        }
    else:
        fields = {}
    return {key: value for key, value in fields.items() if value not in (None, "", ())}


def _scalar_trace_value(trace_type: str, value: Any) -> dict[str, Any]:
    if trace_type in {"process", "file"}:
        return {"path": value}
    if trace_type == "service":
        return {"service_name": value}
    if trace_type == "powershell_history":
        return {"command": value}
    if trace_type == "dns_cache":
        return {"name": value}
    if trace_type == "registry_run_key":
        return {"value_name": value}
    if trace_type == "scheduled_task":
        return {"task_name": value}
    if trace_type == "network_connection":
        text = str(value)
        host, separator, port = text.rpartition(":")
        return {
            "remote_address": host if separator else text,
            "remote_port": port if separator else "",
        }
    return {}


def _merge_or_append_observation(
    observations: list[Observation], candidate: Observation
) -> None:
    for existing in observations:
        if not _observations_can_merge(existing, candidate):
            continue
        for key, value in candidate.fields.items():
            if key not in existing.fields:
                existing.fields[key] = value
        existing.finding_ids = sorted(set(existing.finding_ids + candidate.finding_ids))
        existing.finding_types = sorted(set(existing.finding_types + candidate.finding_types))
        if not existing.explicit_key:
            existing.explicit_key = candidate.explicit_key
        return
    observations.append(candidate)


def _observations_can_merge(left: Observation, right: Observation) -> bool:
    if left.trace_type != right.trace_type:
        return False
    selectors = {
        "network_connection": (
            "protocol",
            "local_address",
            "local_port",
            "remote_address",
            "remote_port",
            "pid",
        ),
        "process": ("pid", "creation_time", "path", "name"),
        "process_parent_edge": ("child_pid", "parent_pid", "child_name", "parent_name"),
        "file": ("path",),
        "registry_run_key": ("hive", "key_path", "value_name"),
        "scheduled_task": ("task_path", "task_name"),
        "service": ("service_name",),
        "powershell_history": ("command_hash",),
        "dns_cache": ("name", "record_type", "data"),
    }[left.trace_type]
    shared = 0
    for key in selectors:
        left_value = left.fields.get(key)
        right_value = right.fields.get(key)
        if left_value in (None, "", ()) or right_value in (None, "", ()):
            continue
        shared += 1
        if left_value != right_value:
            return False
    return shared > 0


def _maximum_one_to_one_trace_matches(
    facts: Sequence[TraceFact], observations: Sequence[Observation]
) -> dict[str, int]:
    candidates: dict[int, list[int]] = {}
    for fact_index, fact in enumerate(facts):
        candidates[fact_index] = [
            observation_index
            for observation_index, observation in enumerate(observations)
            if _trace_matches_observation(fact, observation)
        ]
    order = sorted(
        range(len(facts)),
        key=lambda index: (
            facts[index].shared_context,
            not (facts[index].required or facts[index].anchor or facts[index].discriminative),
            -len(facts[index].fields),
            facts[index].ability_instance_id,
            facts[index].trace_id,
        ),
    )
    observation_owner: dict[int, int] = {}

    def assign(fact_index: int, seen: set[int]) -> bool:
        for observation_index in candidates[fact_index]:
            if observation_index in seen:
                continue
            seen.add(observation_index)
            owner = observation_owner.get(observation_index)
            if owner is None or assign(owner, seen):
                observation_owner[observation_index] = fact_index
                return True
        return False

    for fact_index in order:
        assign(fact_index, set())
    return {
        facts[fact_index].trace_id: observation_index
        for observation_index, fact_index in observation_owner.items()
    }


def _trace_matches_observation(fact: TraceFact, observation: Observation) -> bool:
    if fact.trace_type != observation.trace_type:
        return False
    if fact.fields:
        return all(observation.fields.get(key) == value for key, value in fact.fields.items())
    return bool(fact.canonical_key) and fact.canonical_key in {
        observation.explicit_key,
        observation.canonical_key,
    }


def _load_expected_actions(ground_truth: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw_actions = ground_truth.get("response_actions")
    if not isinstance(raw_actions, list):
        expected = ground_truth.get("expected")
        raw_actions = expected.get("response") if isinstance(expected, Mapping) else []
    if not isinstance(raw_actions, list):
        return []
    actions: list[dict[str, Any]] = []
    for raw in raw_actions:
        if not isinstance(raw, Mapping) or not _as_bool(raw.get("required"), True):
            continue
        action = _normalise_action(raw)
        if action:
            _append_unique(actions, action)
    return sorted(actions, key=_json_sort_key)


def _extract_predicted_actions(casefile: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw_results = casefile.get("action_results", [])
    if not isinstance(raw_results, list):
        raise ScoreValidationError("CaseFile action_results must be a list")
    actions: list[dict[str, Any]] = []
    for raw in raw_results:
        if not isinstance(raw, Mapping):
            continue
        # Response-effect metrics describe actions that were actually executed
        # successfully.  A dry-run proposal is evaluated by the controller's
        # plan gate, while a failed action remains a false negative for the
        # corresponding required Ground Truth action.  Counting either here
        # would turn action-selection into an artificial response success.
        data = raw.get("data") if isinstance(raw.get("data"), Mapping) else {}
        if raw.get("success") is not True or data.get("dry_run") is True:
            continue
        action = _normalise_action(raw)
        if action:
            _append_unique(actions, action)
    return sorted(actions, key=_json_sort_key)


def _normalise_action(raw: Mapping[str, Any]) -> dict[str, Any]:
    tool = _normalise_text(raw.get("tool"))
    if tool not in RESPONSE_TOOLS:
        return {}
    arguments = raw.get("arguments") if isinstance(raw.get("arguments"), Mapping) else raw
    scalar_target = raw.get("target") if not isinstance(raw.get("target"), Mapping) else ""
    if tool == "kill_process":
        target = {
            "pid": _normalise_int(arguments.get("pid")),
            "process_name": _normalise_text(arguments.get("process_name")),
            "path": _normalise_windows_path(
                _first(arguments, "expected_path", "process_path", "path") or scalar_target
            ),
        }
    elif tool == "remove_file":
        target = {
            "path": _normalise_windows_path(
                _first(arguments, "file_path", "path") or scalar_target
            )
        }
    elif tool == "remove_registry":
        target_key_path = _first(arguments, "reg_path", "key_path")
        target_value_name = arguments.get("value_name")
        if scalar_target and "::" in str(scalar_target):
            target_key_path, target_value_name = str(scalar_target).split("::", 1)
        target = {
            "key_path": _normalise_registry_path(target_key_path),
            "value_name": _normalise_text(target_value_name),
            "value_data": _normalise_command(
                _first(arguments, "expected_value", "value_data", "value")
            ),
        }
    elif tool == "remove_scheduled_task":
        target = {
            "task_path": _normalise_task_path(arguments.get("task_path")),
            "task_name": _normalise_text(arguments.get("task_name") or scalar_target),
        }
    else:
        target = {
            "service_name": _normalise_text(arguments.get("service_name") or scalar_target)
        }
    return {
        "tool": tool,
        "target": {
            key: value for key, value in target.items() if value not in (None, "", ())
        },
    }


def _maximum_one_to_one_action_matches(
    expected: Sequence[Mapping[str, Any]], predicted: Sequence[Mapping[str, Any]]
) -> dict[int, int]:
    matches: dict[int, int] = {}
    used: set[int] = set()
    expected_order = sorted(
        range(len(expected)),
        key=lambda index: (-len(expected[index].get("target", {})), _json_sort_key(expected[index])),
    )
    for expected_index in expected_order:
        for predicted_index, observed in enumerate(predicted):
            if predicted_index in used:
                continue
            if _action_matches(expected[expected_index], observed):
                matches[expected_index] = predicted_index
                used.add(predicted_index)
                break
    return matches


def _action_matches(expected: Mapping[str, Any], observed: Mapping[str, Any]) -> bool:
    if expected.get("tool") != observed.get("tool"):
        return False
    expected_target = expected.get("target") if isinstance(expected.get("target"), Mapping) else {}
    observed_target = observed.get("target") if isinstance(observed.get("target"), Mapping) else {}
    return all(observed_target.get(key) == value for key, value in expected_target.items())


def _trace_match_detail(trace: TraceFact, observation: Observation) -> dict[str, Any]:
    return {
        "trace_id": trace.trace_id,
        "trace_type": trace.trace_type,
        "ability_instance_id": trace.ability_instance_id,
        "required": trace.required,
        "discriminative": trace.discriminative,
        "anchor": trace.anchor,
        "shared_context": trace.shared_context,
        "observable_by": trace.raw.get("observable_by", []),
        "valid_window": trace.raw.get("valid_window"),
        "source_evidence": trace.raw.get("source_evidence"),
        "expected_fields": trace.fields,
        "observation": _observation_public(observation),
    }


def _trace_public(trace: TraceFact) -> dict[str, Any]:
    return {
        "trace_id": trace.trace_id,
        "trace_type": trace.trace_type,
        "ability_instance_id": trace.ability_instance_id,
        "canonical_key": trace.canonical_key,
        "expected_fields": trace.fields,
        "required": trace.required,
        "discriminative": trace.discriminative,
        "anchor": trace.anchor,
        "shared_context": trace.shared_context,
        "observable_by": trace.raw.get("observable_by", []),
        "valid_window": trace.raw.get("valid_window"),
        "source_evidence": trace.raw.get("source_evidence"),
    }


def _observation_public(observation: Observation) -> dict[str, Any]:
    return {
        "observation_id": observation.observation_id,
        "trace_type": observation.trace_type,
        "canonical_key": observation.canonical_key,
        "fields": observation.fields,
        "finding_ids": observation.finding_ids,
        "finding_types": observation.finding_types,
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None:
        return None
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0


def _as_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.strip().lower() in {"true", "yes", "1"}:
            return True
        if value.strip().lower() in {"false", "no", "0"}:
            return False
    return bool(value)


def _first(raw: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = raw.get(key)
        if value not in (None, "", []):
            return value
    return ""


def _normalise_text(value: Any) -> str:
    return str(value or "").strip().casefold()


def _normalise_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalise_ip(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text.casefold()


def _normalise_ip_or_text(value: Any) -> str:
    return _normalise_ip(value)


def _normalise_windows_path(value: Any) -> str:
    text = str(value or "").strip().strip('"').replace("/", "\\")
    if not text:
        return ""
    if text.startswith("\\\\?\\"):
        text = text[4:]
    try:
        text = ntpath.normpath(text)
    except (TypeError, ValueError):
        pass
    return text.casefold()


def _normalise_registry_path(value: Any) -> str:
    text = str(value or "").strip().strip('"').replace("/", "\\")
    text = re.sub(r"\\+", r"\\", text)
    text = re.sub(r"^(hkey_current_user|hkcu):?", "hkcu", text, flags=re.I)
    text = re.sub(r"^(hkey_local_machine|hklm):?", "hklm", text, flags=re.I)
    return text.rstrip("\\").casefold()


def _normalise_registry_hive(value: Any, key_path: Any = "") -> str:
    text = str(value or "").strip().rstrip(":\\/")
    if not text:
        path = str(key_path or "").strip().replace("/", "\\")
        match = re.match(r"^([^:\\]+):?(?:\\|$)", path)
        text = match.group(1) if match else ""
    aliases = {
        "hkey_current_user": "hkcu",
        "hkcu": "hkcu",
        "hkey_local_machine": "hklm",
        "hklm": "hklm",
        "hkey_classes_root": "hkcr",
        "hkcr": "hkcr",
        "hkey_users": "hku",
        "hku": "hku",
        "hkey_current_config": "hkcc",
        "hkcc": "hkcc",
    }
    return aliases.get(text.casefold(), "")


def _normalise_task_path(value: Any) -> str:
    text = str(value or "").strip().replace("/", "\\")
    if not text:
        return ""
    text = "\\" + text.strip("\\") + "\\"
    return text.casefold()


def _normalise_command(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return " | ".join(_normalise_command(item) for item in value if str(item or "").strip())
    text = str(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    return text.casefold()


def _normalise_hash(value: Any) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value or "").casefold())


def _normalise_domain(value: Any) -> str:
    return str(value or "").strip().rstrip(".").casefold()


def _normalise_datetime(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    iso_candidate = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(iso_candidate)
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc)
        return parsed.replace(microsecond=0).isoformat()
    except ValueError:
        pass
    for pattern in ("%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, pattern).replace(microsecond=0).isoformat()
        except ValueError:
            continue
    return text.casefold()


def _normalise_sequence(value: Any, normaliser: Any) -> str:
    if value in (None, ""):
        return ""
    items = value if isinstance(value, (list, tuple)) else [value]
    values = sorted({normaliser(item) for item in items if normaliser(item)})
    return " | ".join(values)


def _dict_items(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _generated_key(trace_type: str, fields: Mapping[str, Any]) -> str:
    return f"{trace_type}:" + json.dumps(
        dict(sorted(fields.items())), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _json_sort_key(value: Mapping[str, Any]) -> str:
    return json.dumps(dict(value), sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _append_unique(
    target: list[dict[str, Any]],
    item: dict[str, Any],
    *,
    ignore_keys: set[str] | None = None,
) -> None:
    ignore = ignore_keys or set()
    key = _json_sort_key({name: value for name, value in item.items() if name not in ignore})
    existing_keys = {
        _json_sort_key({name: value for name, value in existing.items() if name not in ignore})
        for existing in target
    }
    if key not in existing_keys:
        target.append(item)


def _format_metric(value: Any) -> str:
    if value is None:
        return "N/A"
    try:
        return f"{float(value):.4f}"
    except (TypeError, ValueError):
        return str(value)


def _format_bool(value: Any) -> str:
    if value is None:
        return "N/A"
    return "yes" if value else "no"
