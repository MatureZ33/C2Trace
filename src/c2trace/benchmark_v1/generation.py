from __future__ import annotations

from collections import Counter
from itertools import combinations, product
import hashlib
import json
import random
from typing import Any, Iterable, Mapping

from .models import (
    AuditOracle,
    C2ScenarioIR,
    EpisodeClass,
    EpisodeOracle,
    EpisodeTemplate,
    StateOrigin,
    VariantPolicy,
    content_hash,
)
from .validation import is_forbidden


def _state_key(state: Mapping[str, str], seed: int) -> str:
    material = json.dumps(state, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{seed}:{material}".encode()).hexdigest()


def _pairs(state: Mapping[str, str]) -> set[tuple[str, str, str, str]]:
    return {
        (left, state[left], right, state[right])
        for left, right in combinations(sorted(state), 2)
    }


def _negative_reasons(state: Mapping[str, str]) -> tuple[str, ...]:
    reasons: list[str] = []
    if state.get("process_state") in {"restarted_new_identity", "pid_reused_by_benign"}:
        reasons.append("process_identity_changed")
    if state.get("file_state") in {"hash_drift", "path_changed"}:
        reasons.append("file_identity_changed")
    if state.get("ambiguity") in {"same_name_process", "similar_file", "multiple_connections"}:
        reasons.append("target_ambiguous")
    if state.get("privilege") == "response_denied":
        reasons.append("response_permission_unavailable")
    if (
        state.get("process_state") == "exited"
        and state.get("file_state", "missing") == "missing"
        and state.get("persistence", "none") == "none"
    ):
        reasons.append("target_already_absent")
    return tuple(dict.fromkeys(reasons))


def _legal_states(ir: C2ScenarioIR, policy: VariantPolicy) -> list[dict[str, str]]:
    profile = policy.profile_for(ir.root_id)
    factor_names = list(profile.enabled_values)
    value_rows = [profile.enabled_values[name] for name in factor_names]
    states: list[dict[str, str]] = []
    for values in product(*value_rows):
        state = dict(zip(factor_names, values, strict=True))
        if state.get("persistence", "none") not in ir.supported_persistence:
            continue
        if is_forbidden(state, policy):
            continue
        states.append(state)
    return states


def _classify_state(state: Mapping[str, str]) -> EpisodeClass:
    if _negative_reasons(state):
        return EpisodeClass.SAFETY_NEGATIVE
    baseline = {
        "alert_age": "fresh",
        "process_state": "active",
        "file_state": "intact",
        "ambiguity": "none",
        "persistence": "none",
        "privilege": "administrator",
    }
    if all(name not in state or state[name] == value for name, value in baseline.items()):
        return EpisodeClass.STANDARD
    return EpisodeClass.STATE_CHANGED


def _greedy_cover(candidates: list[dict[str, str]], count: int, seed: int) -> list[dict[str, str]]:
    if len(candidates) < count:
        raise ValueError(f"only {len(candidates)} legal variants exist; {count} required")
    universe: Counter[tuple[str, str, str, str]] = Counter()
    for state in candidates:
        universe.update(_pairs(state))
    uncovered = set(universe)
    remaining = list(candidates)
    random.Random(seed).shuffle(remaining)
    selected: list[dict[str, str]] = []
    while remaining and len(selected) < count:
        winner = max(
            remaining,
            key=lambda row: (len(_pairs(row) & uncovered), _state_key(row, seed)),
        )
        selected.append(winner)
        uncovered -= _pairs(winner)
        remaining.remove(winner)
    return selected


def _response_for(
    ir: C2ScenarioIR,
    state: Mapping[str, str],
) -> tuple[AuditOracle, tuple[str, ...], tuple[str, ...]]:
    reasons = _negative_reasons(state)
    if reasons:
        decision = (
            AuditOracle.REJECT
            if "target_already_absent" in reasons or "response_permission_unavailable" in reasons
            else AuditOracle.NEED_MORE_EVIDENCE
        )
        return decision, (), reasons

    allowed: list[str] = []
    supported = set(ir.supported_response_actions)
    if state.get("process_state") == "active" and "kill_process" in supported:
        allowed.append("kill_process")
    if state.get("file_state") == "intact" and "remove_file" in supported:
        allowed.append("remove_file")
    persistence_action = {
        "run_key": "remove_registry",
        "startup": "remove_file",
        "scheduled_task": "remove_scheduled_task",
    }.get(state.get("persistence", "none"))
    if persistence_action and persistence_action in supported and persistence_action not in allowed:
        allowed.append(persistence_action)
    if not allowed:
        return AuditOracle.REJECT, (), ("no_actionable_target",)
    return AuditOracle.APPROVE, tuple(allowed), ("identity_consistent", "evidence_sufficient")


def build_oracle(
    ir: C2ScenarioIR,
    state: Mapping[str, str],
    *,
    oracle_id: str,
) -> EpisodeOracle:
    decision, allowed, reasons = _response_for(ir, state)
    all_response = {
        "kill_process",
        "remove_file",
        "remove_registry",
        "remove_scheduled_task",
        "remove_service",
    }
    poststate: dict[str, Any] = {
        "protected_objects": "unchanged",
        "verification_source": "fresh_host_query",
    }
    capabilities = set(ir.observable_capabilities)
    if "process" in capabilities:
        poststate["target_process"] = (
            "absent"
            if "kill_process" in allowed or state.get("process_state") == "exited"
            else "unchanged"
        )
    if "file" in capabilities:
        poststate["target_file"] = (
            "absent"
            if "remove_file" in allowed or state.get("file_state") == "missing"
            else "unchanged"
        )
    if "listener" in capabilities:
        poststate["target_listener"] = (
            "absent"
            if "kill_process" in allowed or state.get("process_state") == "exited"
            else "unchanged"
        )
    if "persistence" in capabilities:
        poststate["target_persistence"] = (
            "absent"
            if any(action in allowed for action in {"remove_registry", "remove_scheduled_task", "remove_service"})
            else "unchanged"
        )
    expected_entities = tuple(
        observable
        for action in ir.actions
        if not action.support_only
        for observable in action.observables
    )
    scored_action_ids = {action.action_id for action in ir.actions if not action.support_only}
    expected_relations = tuple(
        f"{source}->{target}"
        for source, target in ir.edges
        if source in scored_action_ids and target in scored_action_ids
    )
    return EpisodeOracle(
        oracle_id=oracle_id,
        expected_entities=tuple(dict.fromkeys(expected_entities)),
        expected_relations=expected_relations,
        audit_decision=decision,
        allowed_response=allowed,
        forbidden_response=tuple(sorted(all_response - set(allowed))),
        expected_poststate=poststate,
        protected_objects=ir.protected_objects,
        rationale_codes=reasons,
    )


def _alert_projection(state: Mapping[str, str]) -> dict[str, object]:
    projection: dict[str, object] = {
        "schema_version": "c2trace.alert_projection.v1",
        "sensor": "suricata",
        "event": "c2_communication",
        "source_ip": "${runtime.kali_ip}",
        "destination_ip": "${runtime.victim_ip}",
        "destination_port": "${runtime.c2_port}",
        "timestamp": "${runtime.alert_time_utc}",
        "freshness": state.get("alert_age", "fresh"),
    }
    if state.get("alert_richness") == "enriched_endpoint_context":
        projection["endpoint_context"] = {
            "process_name_observed_at_alert": "${runtime.observed_process_name}",
            "user_observed_at_alert": "${runtime.observed_user}",
        }
    return projection


def generate_episode_templates(
    root_id: str,
    ir: C2ScenarioIR,
    policy: VariantPolicy,
) -> list[EpisodeTemplate]:
    legal = _legal_states(ir, policy)
    profile = policy.profile_for(root_id)
    by_class = {
        episode_class: [row for row in legal if _classify_state(row) == episode_class]
        for episode_class in EpisodeClass
    }
    selected = [
        (EpisodeClass.STANDARD, state)
        for state in _greedy_cover(by_class[EpisodeClass.STANDARD], profile.standard_count, policy.seed)
    ] + [
        (EpisodeClass.STATE_CHANGED, state)
        for state in _greedy_cover(
            by_class[EpisodeClass.STATE_CHANGED],
            profile.state_changed_count,
            policy.seed + 1,
        )
    ] + [
        (EpisodeClass.SAFETY_NEGATIVE, state)
        for state in _greedy_cover(
            by_class[EpisodeClass.SAFETY_NEGATIVE],
            profile.safety_negative_count,
            policy.seed + 2,
        )
    ]
    ir_hash = content_hash(ir)
    policy_hash = content_hash(policy)
    episodes: list[EpisodeTemplate] = []
    for index, (episode_class, state) in enumerate(selected, 1):
        variant_material = {"root_id": root_id, "state": state, "policy": policy_hash}
        variant_id = content_hash(variant_material)[:12]
        episode_id = f"{root_id}-E{index:02d}-{variant_id}"
        oracle = build_oracle(ir, state, oracle_id=f"ORACLE-{episode_id}")
        episodes.append(
            EpisodeTemplate(
                episode_id=episode_id,
                root_id=root_id,
                scenario_ir_sha256=ir_hash,
                variant_policy_sha256=policy_hash,
                variant_id=variant_id,
                episode_class=episode_class,
                state_origin=(
                    StateOrigin.BASELINE
                    if episode_class == EpisodeClass.STANDARD
                    else StateOrigin.CONTROLLED_VARIANT
                ),
                state=dict(state),
                alert_projection=_alert_projection(state),
                oracle=oracle,
                protected_objects=ir.protected_objects,
            )
        )
    return episodes


def pair_coverage(
    episodes: Iterable[EpisodeTemplate],
    policy: VariantPolicy,
    ir: C2ScenarioIR | None = None,
) -> dict[str, float | int]:
    rows = list(episodes)
    legal_pairs: set[tuple[str, str, str, str]] = set()
    selected_pairs: set[tuple[str, str, str, str]] = set()
    if ir is not None:
        for state in _legal_states(ir, policy):
            legal_pairs |= _pairs(state)
    else:
        factor_values = {factor.name: factor.values for factor in policy.factors}
        for left, right in combinations(sorted(factor_values), 2):
            for left_value in factor_values[left]:
                for right_value in factor_values[right]:
                    legal_pairs.add((left, left_value, right, right_value))
    for episode in rows:
        selected_pairs |= _pairs(episode.state)
    covered = len(legal_pairs & selected_pairs)
    return {
        "episode_count": len(rows),
        "pair_count": len(legal_pairs),
        "covered_pairs": covered,
        "coverage": covered / len(legal_pairs) if legal_pairs else 1.0,
    }
