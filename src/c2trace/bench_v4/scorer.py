from __future__ import annotations

from copy import deepcopy
import math
from pathlib import Path
import re
from typing import Any, Mapping

from c2trace.bench_v3.scorer import (  # v3 remains frozen; v4 adapts its proven core
    ScoreValidationError,
    load_json_object,
    score_case as _score_case_v3,
)

from .contracts import CASE_ID_RE, SOURCE_KINDS, SOURCE_STRATUM, expected_source_kind


_GENERIC_TO_LEGACY_OPERATIONAL = {
    "target_network_absent": "manx_network_absent",
    "target_process_absent": "manx_process_absent",
    "target_file_absent": "manx_file_absent",
    "target_persistence_absent": "manx_run_key_absent",
    "control_agent_alive": "control_sandcat_alive",
}

_NUMERIC_OPERATIONAL_KEYS = (
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

_REGISTRY_HIVE_ALIASES = {
    "hkey_current_user": "HKCU",
    "hkcu": "HKCU",
    "hkey_local_machine": "HKLM",
    "hklm": "HKLM",
}
_REGISTRY_PATH_ROOT_RE = re.compile(
    r"^(?P<hive>hkey_current_user|hkcu|hkey_local_machine|hklm):?(?:\\|$)",
    flags=re.IGNORECASE,
)


def _canonical_registry_identity(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Canonicalize an exact registry hive/key pair without weakening identity.

    CALDERA persistence findings commonly put the hive in ``path`` even when
    C2Trace also emits a separate ``hive`` field.  Frozen v3 normalization
    retains that path prefix, so ``HKCU`` + ``Software\\...`` did not match
    ``HKCU`` + ``HKCU:\\Software\\...``.  v4 uses a relative key path plus a
    canonical hive.  A conflicting explicit/path hive is intentionally left
    conflicting so it cannot match either hive accidentally.
    """

    result = dict(raw)
    path_keys = tuple(
        key for key in ("key_path", "reg_path", "path") if key in result
    )
    if not path_keys:
        return result

    path = str(result.get(path_keys[0]) or "").strip().strip('"').replace("/", "\\")
    path = re.sub(r"\\+", r"\\", path).strip("\\")
    root_match = _REGISTRY_PATH_ROOT_RE.match(path)
    path_hive = (
        _REGISTRY_HIVE_ALIASES[root_match.group("hive").casefold()]
        if root_match
        else ""
    )

    explicit_raw = str(result.get("hive") or "").strip().rstrip(":\\/")
    explicit_hive = _REGISTRY_HIVE_ALIASES.get(explicit_raw.casefold(), "")
    explicit_is_unknown = bool(explicit_raw) and not explicit_hive
    hives_conflict = bool(explicit_hive and path_hive and explicit_hive != path_hive)

    if not explicit_is_unknown and not hives_conflict:
        canonical_hive = explicit_hive or path_hive
        if canonical_hive:
            result["hive"] = canonical_hive
        if root_match:
            path = path[root_match.end() :].strip("\\")

    # Update every supplied alias because v3 selects key_path before path.
    # Leaving one prefixed alias behind would reintroduce the mismatch.
    for key in path_keys:
        result[key] = path
    return result


def _response_arguments(action: Mapping[str, Any]) -> dict[str, Any]:
    arguments = action.get("arguments")
    result = dict(arguments) if isinstance(arguments, Mapping) else {}
    target = action.get("target")
    if not isinstance(target, Mapping):
        return result
    tool = str(action.get("tool") or "")
    if tool == "kill_process":
        derived = {
            "pid": target.get("pid"),
            "process_name": target.get("process_name") or target.get("name"),
            "expected_path": target.get("path") or target.get("process_path"),
        }
    elif tool == "remove_file":
        derived = {"file_path": target.get("path") or target.get("file_path")}
    elif tool == "remove_registry":
        derived = {
            "reg_path": target.get("key_path") or target.get("reg_path"),
            "value_name": target.get("value_name"),
            "expected_value": target.get("value_data") or target.get("expected_value"),
        }
    elif tool == "remove_scheduled_task":
        derived = {
            "task_path": target.get("task_path"),
            "task_name": target.get("task_name") or target.get("name"),
        }
    elif tool == "remove_service":
        derived = {"service_name": target.get("service_name") or target.get("name")}
    else:
        derived = {}
    # Explicit arguments win, but a partially populated legacy argument object
    # must not discard identity fields carried by the v4 generic target.
    return {**{key: value for key, value in derived.items() if value is not None}, **result}


def normalize_ground_truth(ground_truth: Mapping[str, Any]) -> dict[str, Any]:
    """Translate v4 generic response targets into the stable v3 scoring wire shape."""

    value = deepcopy(dict(ground_truth))
    for ability in value.get("ability_instances", []):
        if not isinstance(ability, dict):
            continue
        for trace in ability.get("trace_facts", []):
            if not isinstance(trace, dict):
                continue
            if trace.get("trace_type") in {"registry_value", "registry_run_key"}:
                expected = trace.get("expected_value")
                if isinstance(expected, Mapping):
                    trace["expected_value"] = _canonical_registry_identity(expected)
            if trace.get("trace_type") == "registry_value":
                # The frozen v3 matcher already has the exact hive/key/name/data
                # normalization needed here. This private wire alias is restored
                # in every public v4 score field after matching.
                trace["trace_type"] = "registry_run_key"
    actions = value.get("response_actions")
    if isinstance(actions, list):
        normalized = []
        for raw in actions:
            if not isinstance(raw, Mapping):
                normalized.append(raw)
                continue
            action = dict(raw)
            action["arguments"] = _response_arguments(action)
            normalized.append(action)
        value["response_actions"] = normalized
    return value


def normalize_casefile(casefile: Mapping[str, Any]) -> dict[str, Any]:
    """Accept explicit arbitrary-registry findings without calling them persistence."""

    value = deepcopy(dict(casefile))
    action_results = value.get("action_results")
    if isinstance(action_results, list):
        normalized_actions = []
        for raw in action_results:
            if not isinstance(raw, Mapping):
                normalized_actions.append(raw)
                continue
            action = dict(raw)
            action["arguments"] = _response_arguments(action)
            normalized_actions.append(action)
        value["action_results"] = normalized_actions
    findings = value.get("findings")
    if not isinstance(findings, list):
        return value
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        finding_type = str(finding.get("finding_type") or "")
        details = (
            finding.get("details")
            if isinstance(finding.get("details"), Mapping)
            else {}
        )
        category = str(details.get("category") or "").casefold()
        is_registry_persistence = (
            finding_type == "persistence_linked_to_payload"
            and category in {"registry_run_key", "registry_run_keys"}
        )
        if is_registry_persistence:
            finding["details"] = _canonical_registry_identity(details)
            continue
        if finding_type not in {
            "registry_value",
            "registry_value_observed",
            "registry_value_confirmed",
        }:
            continue
        details = _canonical_registry_identity(details)
        finding["finding_type"] = "persistence_linked_to_payload"
        finding["details"] = {
            **dict(details),
            "category": "registry_run_key",
            "path": details.get("path") or details.get("key_path"),
            "name": details.get("name") or details.get("value_name"),
            "value": details.get("value") or details.get("value_data"),
        }
    return value


def _restore_registry_value_types(value: Any, trace_ids: set[str]) -> None:
    if isinstance(value, dict):
        if str(value.get("trace_id") or "") in trace_ids and value.get("trace_type") == "registry_run_key":
            value["trace_type"] = "registry_value"
        for child in value.values():
            _restore_registry_value_types(child, trace_ids)
    elif isinstance(value, list):
        for child in value:
            _restore_registry_value_types(child, trace_ids)


def _first_bool(*values: Any) -> bool | None:
    return next((value for value in values if isinstance(value, bool)), None)


def _absent_when_present(snapshot: Mapping[str, Any], *keys: str) -> bool | None:
    present = [snapshot.get(key) for key in keys if key in snapshot]
    return not any(bool(value) for value in present) if present else None


def normalize_operational_metrics(
    ground_truth: Mapping[str, Any],
    casefile: Mapping[str, Any],
    legacy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Expose target-neutral fields while retaining all v3 Manx aliases."""

    result = dict(legacy or {})
    explicit = (
        casefile.get("operational_metrics")
        if isinstance(casefile.get("operational_metrics"), Mapping)
        else {}
    )
    observed = (
        ground_truth.get("observed")
        if isinstance(ground_truth.get("observed"), Mapping)
        else {}
    )
    post = (
        observed.get("post_response")
        if isinstance(observed.get("post_response"), Mapping)
        else {}
    )
    persistence_absent = _first_bool(
        explicit.get("target_persistence_absent"),
        explicit.get("manx_persistence_absent"),
        explicit.get("manx_run_key_absent"),
        _absent_when_present(post, "persistence", "run_key", "scheduled_tasks", "services"),
        result.get("manx_persistence_absent"),
        result.get("manx_run_key_absent"),
    )
    generic = {
        "wrong_target": _first_bool(explicit.get("wrong_target"), result.get("wrong_target")),
        "target_network_absent": _first_bool(
            explicit.get("target_network_absent"),
            explicit.get("manx_network_absent"),
            result.get("manx_network_absent"),
            _absent_when_present(post, "network_connections", "target_network"),
        ),
        "target_process_absent": _first_bool(
            explicit.get("target_process_absent"),
            explicit.get("manx_process_absent"),
            result.get("manx_process_absent"),
            _absent_when_present(post, "target", "target_process"),
        ),
        "target_file_absent": _first_bool(
            explicit.get("target_file_absent"),
            explicit.get("manx_file_absent"),
            result.get("manx_file_absent"),
            _absent_when_present(post, "target_file", "payload_file"),
        ),
        "target_persistence_absent": persistence_absent,
        "control_agent_alive": _first_bool(
            explicit.get("control_agent_alive"),
            explicit.get("control_sandcat_alive"),
            result.get("control_sandcat_alive"),
            bool(post.get("control")) if "control" in post else None,
        ),
    }
    result.update(generic)
    for key in _NUMERIC_OPERATIONAL_KEYS:
        if key not in explicit:
            continue
        value = explicit.get(key)
        if value is None:
            # The controller records missing run_metadata measurements as null
            # instead of falling back to an action count with different
            # semantics.
            result[key] = None
            continue
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) < 0
        ):
            raise ScoreValidationError(
                f"CaseFile operational metric {key} must be a non-negative number or null"
            )
        result[key] = value
    for generic_key, legacy_key in _GENERIC_TO_LEGACY_OPERATIONAL.items():
        if isinstance(generic[generic_key], bool):
            result[legacy_key] = generic[generic_key]
    if isinstance(persistence_absent, bool):
        result["manx_persistence_absent"] = persistence_absent
    return result


def score_case(
    ground_truth: Mapping[str, Any], casefile: Mapping[str, Any]
) -> dict[str, Any]:
    if str(ground_truth.get("schema_version") or "") != "c2trace.bench.ground_truth.v4":
        raise ScoreValidationError("v4 scoring requires c2trace.bench.ground_truth.v4")
    case_id = str(ground_truth.get("case_id") or "")
    source_kind = str(ground_truth.get("source_kind") or "")
    stratum = str(ground_truth.get("dataset_stratum") or "")
    if not CASE_ID_RE.fullmatch(case_id):
        raise ScoreValidationError("Ground Truth has an invalid v4 case_id")
    if source_kind not in SOURCE_KINDS or expected_source_kind(case_id) != source_kind:
        raise ScoreValidationError("Ground Truth case_id/source_kind pairing is invalid")
    if SOURCE_STRATUM.get(source_kind) != stratum:
        raise ScoreValidationError("Ground Truth source_kind/dataset_stratum pairing is invalid")
    if not str(ground_truth.get("source_id") or "").strip():
        raise ScoreValidationError("Ground Truth source_id is required")
    normalized_ground_truth = normalize_ground_truth(ground_truth)
    normalized_casefile = normalize_casefile(casefile)
    result = _score_case_v3(normalized_ground_truth, normalized_casefile)
    registry_value_ids = {
        str(trace.get("trace_id") or "")
        for ability in ground_truth.get("ability_instances", [])
        if isinstance(ability, Mapping)
        for trace in ability.get("trace_facts", [])
        if isinstance(trace, Mapping) and trace.get("trace_type") == "registry_value"
    }
    _restore_registry_value_types(result, registry_value_ids)
    result["schema_version"] = "c2trace.bench.evaluation.v4"
    result["ground_truth_schema_version"] = str(
        ground_truth.get("schema_version") or ""
    )
    result["dataset_stratum"] = stratum
    result["source_id"] = str(ground_truth.get("source_id") or "")
    result["source_kind"] = source_kind
    result["target_kind"] = str(ground_truth.get("target_kind") or "")
    result["operational_metrics"] = normalize_operational_metrics(
        ground_truth,
        casefile,
        result.get("operational_metrics")
        if isinstance(result.get("operational_metrics"), Mapping)
        else {},
    )
    result["compatibility"] = {
        "trace_and_action_core": "c2trace.bench_v3.scorer",
        "legacy_operational_aliases_retained": True,
    }
    return result


def score_files(
    ground_truth_path: str | Path, casefile_path: str | Path
) -> dict[str, Any]:
    return score_case(
        load_json_object(ground_truth_path), load_json_object(casefile_path)
    )


def _format_metric(value: Any) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def render_markdown_summary(score: Mapping[str, Any]) -> str:
    metrics = score.get("metrics") if isinstance(score.get("metrics"), Mapping) else {}
    counts = score.get("counts") if isinstance(score.get("counts"), Mapping) else {}
    operational = (
        score.get("operational_metrics")
        if isinstance(score.get("operational_metrics"), Mapping)
        else {}
    )
    metric_rows = (
        ("Ability Any-Trace Recall", "ability_any_trace_recall"),
        ("Mean Ability Trace Coverage", "mean_ability_trace_coverage"),
        ("Strict Ability Recall", "strict_ability_recall"),
        ("Trace-Producing Ability Ratio", "trace_producing_ability_ratio"),
        ("Trace Precision", "trace_precision"),
        ("Trace Recall", "trace_recall"),
        ("Trace F1", "trace_f1"),
        ("Response Action Precision", "response_action_precision"),
        ("Response Action Recall", "response_action_recall"),
        ("Response Action F1", "response_action_f1"),
    )
    lines = [
        f"# C2Trace Bench v4 Score: {score.get('case_id') or 'unknown'}",
        "",
        f"- Dataset stratum: `{score.get('dataset_stratum') or 'unknown'}`",
        f"- Source kind: `{score.get('source_kind') or 'unknown'}`",
        f"- Target kind: `{score.get('target_kind') or 'unknown'}`",
        "- Ability Precision/F1: **N/A** (C2Trace does not independently predict CALDERA ability IDs)",
        "",
        "## Effectiveness metrics",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    lines.extend(
        f"| {label} | {_format_metric(metrics.get(key))} |"
        for label, key in metric_rows
    )
    lines.extend(["", "## Counts", "", "| Count | Value |", "|---|---:|"])
    lines.extend(f"| `{key}` | {value} |" for key, value in counts.items())
    lines.extend(
        [
            "",
            "## Target-neutral response outcomes",
            "",
            "| Outcome | Value |",
            "|---|---:|",
        ]
    )
    for key in (
        "wrong_target",
        "target_network_absent",
        "target_process_absent",
        "target_file_absent",
        "target_persistence_absent",
        "control_agent_alive",
    ):
        lines.append(f"| `{key}` | {_format_metric(operational.get(key))} |")
    lines.extend(
        [
            "",
            "## Runtime and resource measurements",
            "",
            "| Measurement | Value |",
            "|---|---:|",
        ]
    )
    for key in _NUMERIC_OPERATIONAL_KEYS:
        lines.append(f"| `{key}` | {_format_metric(operational.get(key))} |")
    lines.extend(
        [
            "",
            "## Per-ability details",
            "",
            "| Ability instance | Ability ID | Traces | Matched | Hit | Coverage | Strict |",
            "|---|---|---:|---:|---|---:|---|",
        ]
    )
    for ability in score.get("per_ability", []):
        if not isinstance(ability, Mapping):
            continue
        lines.append(
            "| `{}` | `{}` | {} | {} | {} | {} | {} |".format(
                ability.get("ability_instance_id") or "",
                ability.get("ability_id") or "",
                ability.get("trace_count") or 0,
                ability.get("matched_trace_count") or 0,
                _format_metric(ability.get("hit")),
                _format_metric(ability.get("coverage")),
                _format_metric(ability.get("strict_hit")),
            )
        )
    matching = score.get("trace_matching") if isinstance(score.get("trace_matching"), Mapping) else {}
    lines.extend(
        [
            "",
            "## Trace mismatches",
            "",
            f"- Unmatched Ground Truth traces: {len(matching.get('unmatched_ground_truth') or [])}",
            f"- Unmatched C2Trace observations: {len(matching.get('unmatched_observations') or [])}",
            "",
        ]
    )
    return "\n".join(lines)


def write_score_outputs(
    score: Mapping[str, Any], json_path: str | Path, markdown_path: str | Path
) -> None:
    import json

    json_target = Path(json_path)
    markdown_target = Path(markdown_path)
    json_target.parent.mkdir(parents=True, exist_ok=True)
    markdown_target.parent.mkdir(parents=True, exist_ok=True)
    json_target.write_text(
        json.dumps(dict(score), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown_target.write_text(render_markdown_summary(score), encoding="utf-8")


__all__ = [
    "ScoreValidationError",
    "load_json_object",
    "normalize_ground_truth",
    "normalize_casefile",
    "normalize_operational_metrics",
    "render_markdown_summary",
    "score_case",
    "score_files",
    "write_score_outputs",
]
