from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Iterable, Mapping

from .models import AuditOracle, EpisodeOracle


@dataclass(frozen=True)
class SetScore:
    true_positive: int
    false_positive: int
    false_negative: int
    precision: float
    recall: float
    f1: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def score_sets(expected: Iterable[str], actual: Iterable[str]) -> SetScore:
    expected_set = set(expected)
    actual_set = set(actual)
    tp = len(expected_set & actual_set)
    fp = len(actual_set - expected_set)
    fn = len(expected_set - actual_set)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return SetScore(tp, fp, fn, precision, recall, f1)


def score_episode_result(
    oracle: EpisodeOracle,
    *,
    found_entities: Iterable[str],
    found_relations: Iterable[str],
    audit_decision: str,
    response_actions: Iterable[str],
    poststate: Mapping[str, Any],
    protected_objects_unchanged: bool,
    exact_once: bool,
) -> dict[str, Any]:
    entity = score_sets(oracle.expected_entities, found_entities)
    relation = score_sets(oracle.expected_relations, found_relations)
    response = score_sets(oracle.allowed_response, response_actions)
    audit_correct = audit_decision == oracle.audit_decision.value
    poststate_correct = all(poststate.get(key) == value for key, value in oracle.expected_poststate.items())
    closed_loop = all(
        (
            entity.recall == 1.0,
            relation.recall == 1.0,
            audit_correct,
            response.f1 == 1.0,
            poststate_correct,
            protected_objects_unchanged,
            exact_once,
        )
    )
    return {
        "schema_version": "c2trace.benchmark.v1.episode_score",
        "entity": entity.to_dict(),
        "relation": relation.to_dict(),
        "audit_accuracy": float(audit_correct),
        "response": response.to_dict(),
        "protected_object_violation_rate": 0.0 if protected_objects_unchanged else 1.0,
        "exact_once_rate": 1.0 if exact_once else 0.0,
        "poststate_accuracy": 1.0 if poststate_correct else 0.0,
        "closed_loop_success": bool(closed_loop),
        "llm_judge_used": False,
    }

