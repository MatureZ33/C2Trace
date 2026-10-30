from __future__ import annotations

from collections import Counter
from typing import Iterable

from .models import (
    AuditOracle,
    EpisodeTemplate,
    QualificationReceipt,
    SourceRoot,
    TrialClass,
    TrialReceipt,
)


VALID_EVALUATION_CLASSES = {
    TrialClass.EVALUATION_VALID_PASS,
    TrialClass.EVALUATION_VALID_FAIL,
}


def _response_outcome(episode: EpisodeTemplate) -> str:
    if episode.oracle.audit_decision == AuditOracle.REJECT:
        return "reject_response"
    if episode.oracle.audit_decision == AuditOracle.NEED_MORE_EVIDENCE:
        return "continue_investigation"
    if len(episode.oracle.allowed_response) >= 2:
        return "full_response"
    return "partial_response"


def release_readiness(
    qualifications: Iterable[QualificationReceipt],
    episodes: Iterable[EpisodeTemplate],
    trials: Iterable[TrialReceipt],
    roots: Iterable[SourceRoot] = (),
) -> dict[str, object]:
    admitted = {row.root_id for row in qualifications if row.status == "admitted"}
    root_rows = {row.root_id: row for row in roots if row.root_id in admitted}
    episode_rows = [row for row in episodes if row.root_id in admitted]
    episode_by_id = {row.episode_id: row for row in episode_rows}
    trial_rows = [row for row in trials if row.episode_id in episode_by_id]
    valid_trials = [row for row in trial_rows if row.trial_class in VALID_EVALUATION_CLASSES]
    executed_episode_ids = {row.episode_id for row in valid_trials}
    executed_episodes = [episode_by_id[episode_id] for episode_id in sorted(executed_episode_ids)]

    source_kinds = {row.source_kind for row in root_rows.values()}
    tool_families = {row.tool_family for row in root_rows.values()}
    c2_mechanisms = {
        mechanism for row in root_rows.values() for mechanism in row.c2_mechanisms
    }
    execution_objects = {
        object_type
        for row in root_rows.values()
        for object_type in row.execution_object_types
    }
    response_outcomes = {_response_outcome(row) for row in executed_episodes}
    coverage_checks = {
        "source_kind_count_at_least_3": len(source_kinds) >= 3,
        "tool_family_count_at_least_4": len(tool_families) >= 4,
        "c2_mechanism_count_at_least_3": len(c2_mechanisms) >= 3,
        "execution_object_type_count_at_least_2": len(execution_objects) >= 2,
        "response_outcomes_complete": response_outcomes
        >= {"full_response", "partial_response", "reject_response", "continue_investigation"},
    }
    coverage_ready = all(coverage_checks.values())
    minimum = len(admitted) >= 8 and len(executed_episodes) >= 48 and coverage_ready
    target = len(admitted) >= 10 and len(executed_episodes) >= 80 and coverage_ready
    return {
        "schema_version": "c2trace.benchmark.v1.release_readiness",
        "admitted_root_count": len(admitted),
        "episode_template_count": len(episode_rows),
        "executed_episode_count": len(executed_episodes),
        "trial_count": len(trial_rows),
        "valid_trial_count": len(valid_trials),
        "trial_class_counts": dict(Counter(row.trial_class.value for row in trial_rows)),
        "coverage": {
            "source_kind_count": len(source_kinds),
            "tool_family_count": len(tool_families),
            "c2_mechanism_count": len(c2_mechanisms),
            "execution_object_type_count": len(execution_objects),
            "response_outcomes": sorted(response_outcomes),
            "checks": coverage_checks,
        },
        "target_release_ready": target,
        "minimum_release_ready": minimum,
        "required_label": "benchmark_v1" if minimum else "pilot_evaluation",
    }

