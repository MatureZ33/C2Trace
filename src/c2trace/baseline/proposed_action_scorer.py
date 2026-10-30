"""Score action selection independently from action execution."""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from c2trace.bench_v3 import scorer as _core


def _normalise_proposed(raw: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {}
    # A PredictionIR action may store parameters under ``arguments`` or use
    # the same flat shape as a CaseFile action result.
    candidate = dict(raw)
    if "arguments" not in candidate and isinstance(candidate.get("params"), Mapping):
        candidate["arguments"] = dict(candidate["params"])
    return _core._normalise_action(candidate)


def _unique(actions: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for action in actions:
        normalized = _normalise_proposed(action)
        if normalized and normalized not in result:
            result.append(normalized)
    return sorted(result, key=_core._json_sort_key)


def score_proposed_actions(
    ground_truth: Mapping[str, Any],
    proposed_actions: Sequence[Mapping[str, Any]] | Mapping[str, Any],
) -> dict[str, Any]:
    """Return P/R/F1 for proposed actions without requiring success=true.

    This scorer is intentionally separate from ``score_case``.  A proposal is
    a model prediction; it is not evidence that a response changed the host.
    """
    expected = _core._load_expected_actions(ground_truth)
    if isinstance(proposed_actions, Mapping):
        raw = proposed_actions.get("proposed_actions", [])
    else:
        raw = proposed_actions
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise ValueError("proposed_actions must be a sequence of objects")
    predicted = _unique([item for item in raw if isinstance(item, Mapping)])
    matches = _core._maximum_one_to_one_action_matches(expected, predicted)
    tp = len(matches)
    fp = len(predicted) - len(set(matches.values()))
    fn = len(expected) - tp
    precision = _core._ratio(tp, tp + fp)
    recall = _core._ratio(tp, tp + fn)
    f1 = _core._f1(precision, recall)
    return {
        "schema_version": "c2trace.baseline.proposed_action_score.v1",
        "expected_count": len(expected),
        "proposed_count": len(predicted),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "matches": [
            {"expected": expected[e], "proposed": predicted[p]}
            for e, p in sorted(matches.items())
        ],
        "unmatched_expected": [item for index, item in enumerate(expected) if index not in matches],
        "unmatched_proposed": [item for index, item in enumerate(predicted) if index not in set(matches.values())],
    }


__all__ = ["score_proposed_actions"]
