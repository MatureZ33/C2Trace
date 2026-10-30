from __future__ import annotations

from collections import defaultdict, deque
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from .models import (
    AuditOracle,
    C2ScenarioIR,
    EpisodeClass,
    EpisodeTemplate,
    FidelityReceipt,
    MappingType,
    QualificationReceipt,
    StateOrigin,
    SourceRoot,
    VariantPolicy,
    content_hash,
)


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_QUALIFICATION_CHECKS = (
    "source_locked",
    "license_recorded",
    "fidelity_receipt_valid",
    "core_steps_fully_mapped",
    "real_cross_host_c2",
    "suricata_alert_captured",
    "windows_owner_attributed",
    "action_traversed_c2_channel",
    "response_objects_measurable",
    "no_success_stub",
    "no_pre_response_auto_cleanup",
    "reference_response_changed_real_state",
    "reference_poststate_fresh_query",
    "oracle_independently_measurable",
    "protected_objects_unchanged",
    "cleanup_after_scoring",
)


class BenchmarkValidationError(ValueError):
    pass


def _require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def validate_source_root(root: SourceRoot) -> list[str]:
    errors: list[str] = []
    _require(root.schema_version == "c2trace.benchmark.v1.source_root", "source schema_version mismatch", errors)
    _require(bool(re.fullmatch(r"[A-Z0-9][A-Z0-9._-]{2,127}", root.root_id)), "invalid root_id", errors)
    _require(root.source_url.startswith("https://"), "source_url must use https", errors)
    _require(bool(root.version.strip()), "source version is not frozen", errors)
    _require(bool(root.license.strip()), "source license is missing", errors)
    _require(bool(root.preserved_c2_slice), "preserved C2 slice is empty", errors)
    _require(bool(root.tool_family.strip()), "source tool_family is missing", errors)
    _require(bool(root.c2_mechanisms), "source C2 mechanisms are missing", errors)
    _require(bool(root.execution_object_types), "source execution object types are missing", errors)
    _require(bool(root.fidelity_receipt_path.strip()), "source fidelity receipt path is missing", errors)
    _require(
        bool(SHA256_RE.fullmatch(root.fidelity_receipt_sha256)),
        "source fidelity receipt hash is invalid",
        errors,
    )
    for artifact in root.artifacts:
        _require(bool(SHA256_RE.fullmatch(artifact.sha256)), f"invalid artifact hash: {artifact.path}", errors)
        _require(artifact.size >= 0, f"invalid artifact size: {artifact.path}", errors)
    return errors


def validate_fidelity_receipt(receipt: FidelityReceipt, *, root: SourceRoot | None = None) -> list[str]:
    from .fidelity import ALLOWED_REPLACEMENT_REASONS

    errors: list[str] = []
    _require(
        receipt.schema_version == "c2trace.benchmark.v1.fidelity_receipt",
        "fidelity schema_version mismatch",
        errors,
    )
    if root is not None:
        _require(receipt.root_id == root.root_id, "fidelity root_id does not match SourceRoot", errors)
        _require(receipt.source_version == root.version, "fidelity source version does not match", errors)
        _require(receipt.claim_tier == root.claim_tier, "fidelity claim tier does not match", errors)
        _require(receipt.receipt_id == root.fidelity_receipt_sha256, "fidelity receipt hash does not match SourceRoot", errors)
    _require(bool(receipt.reviewer.strip()), "fidelity reviewer is missing", errors)
    _require(bool(receipt.reviewed_at_utc.strip()), "fidelity review time is missing", errors)
    mapping_ids = [row.mapping_id for row in receipt.mappings]
    _require(bool(mapping_ids), "fidelity receipt has no mappings", errors)
    _require(len(mapping_ids) == len(set(mapping_ids)), "fidelity mapping IDs are not unique", errors)
    critical = [row for row in receipt.mappings if row.critical]
    _require(bool(critical), "fidelity receipt has no critical steps", errors)
    for row in receipt.mappings:
        _require(bool(row.source_step.strip()), f"mapping {row.mapping_id} has no source step", errors)
        _require(bool(row.source_citations), f"mapping {row.mapping_id} has no source citation", errors)
        if row.critical:
            _require(
                row.mapping_type in {MappingType.EXACT, MappingType.EQUIVALENT},
                f"critical mapping {row.mapping_id} is not exact/equivalent",
                errors,
            )
        if row.mapping_type == MappingType.EQUIVALENT:
            _require(
                row.replacement_reason in ALLOWED_REPLACEMENT_REASONS,
                f"equivalent mapping {row.mapping_id} has invalid replacement reason",
                errors,
            )
            _require(bool(row.rationale.strip()), f"equivalent mapping {row.mapping_id} has no rationale", errors)
        if row.mapping_type == MappingType.OMITTED:
            _require(
                row.replacement_reason in ALLOWED_REPLACEMENT_REASONS,
                f"omitted mapping {row.mapping_id} has invalid replacement reason",
                errors,
            )
    mapped_critical = [
        row for row in critical if row.mapping_type in {MappingType.EXACT, MappingType.EQUIVALENT}
    ]
    expected_coverage = len(mapped_critical) / len(critical) if critical else 0.0
    _require(abs(receipt.core_step_coverage - expected_coverage) < 1e-9, "fidelity core coverage is inconsistent", errors)
    _require(receipt.status == ("accepted" if expected_coverage == 1.0 else "rejected"), "fidelity status is inconsistent", errors)
    material = {
        "root_id": receipt.root_id,
        "source_version": receipt.source_version,
        "claim_tier": receipt.claim_tier.value,
        "mappings": [row.to_dict() for row in receipt.mappings],
        "reviewer": receipt.reviewer,
        "reviewed_at_utc": receipt.reviewed_at_utc,
        "status": receipt.status,
        "core_step_coverage": receipt.core_step_coverage,
        "mapping_counts": dict(sorted(receipt.mapping_counts.items())),
        "notes": receipt.notes,
    }
    _require(receipt.receipt_id == content_hash(material), "fidelity receipt content hash is invalid", errors)
    return errors


def validate_source_artifacts(root: SourceRoot, project_root: str | Path) -> list[str]:
    import hashlib

    errors: list[str] = []
    base = Path(project_root).resolve()
    for artifact in root.artifacts:
        path = (base / artifact.path).resolve()
        try:
            path.relative_to(base)
        except ValueError:
            errors.append(f"source artifact escapes project root: {artifact.path}")
            continue
        if not path.is_file():
            errors.append(f"source artifact is missing: {artifact.path}")
            continue
        if path.stat().st_size != artifact.size:
            errors.append(f"source artifact size drifted: {artifact.path}")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != artifact.sha256:
            errors.append(f"source artifact hash drifted: {artifact.path}")
    return errors


def validate_scenario_ir(
    ir: C2ScenarioIR,
    *,
    root: SourceRoot | None = None,
    fidelity: FidelityReceipt | None = None,
) -> list[str]:
    errors: list[str] = []
    _require(ir.schema_version == "c2trace.benchmark.v1.scenario_ir", "IR schema_version mismatch", errors)
    if root is not None:
        _require(ir.root_id == root.root_id, "IR root_id does not match SourceRoot", errors)
    action_ids = [action.action_id for action in ir.actions]
    _require(bool(action_ids), "IR has no actions", errors)
    _require(len(action_ids) == len(set(action_ids)), "IR action_id values are not unique", errors)
    known = set(action_ids)
    graph: dict[str, list[str]] = defaultdict(list)
    indegree = {action_id: 0 for action_id in action_ids}
    for source, target in ir.edges:
        _require(source in known and target in known, f"IR edge references unknown action: {source}->{target}", errors)
        if source in known and target in known:
            graph[source].append(target)
            indegree[target] += 1
    queue = deque(sorted(key for key, degree in indegree.items() if degree == 0))
    visited = 0
    while queue:
        current = queue.popleft()
        visited += 1
        for target in graph[current]:
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
    _require(visited == len(action_ids), "IR action graph contains a cycle", errors)
    for action in ir.actions:
        _require(bool(action.source_citations), f"action {action.action_id} has no source citation", errors)
        _require(bool(action.backend_binding.get("backend")), f"action {action.action_id} has no backend binding", errors)
        _require(bool(action.mapping_id.strip()), f"action {action.action_id} has no fidelity mapping", errors)
        if not action.support_only:
            _require(bool(action.observables), f"scored action {action.action_id} has no observables", errors)
    if fidelity is not None:
        mappings = {row.mapping_id: row for row in fidelity.mappings}
        for action in ir.actions:
            _require(action.mapping_id in mappings, f"action {action.action_id} references unknown mapping", errors)
            if action.mapping_id in mappings:
                mapping = mappings[action.mapping_id]
                _require(
                    action.support_only == (mapping.mapping_type == MappingType.SUPPORT_ONLY),
                    f"action {action.action_id} support_only disagrees with fidelity mapping",
                    errors,
                )
        action_mapping_ids = {action.mapping_id for action in ir.actions}
        missing_critical = [
            row.mapping_id
            for row in fidelity.mappings
            if row.critical and row.mapping_id not in action_mapping_ids
        ]
        _require(not missing_critical, "critical mappings have no executable action: " + ", ".join(missing_critical), errors)
    _require(bool(ir.cleanup_actions), "IR has no external cleanup actions", errors)
    _require(bool(ir.protected_objects), "IR has no protected objects", errors)
    _require(bool(ir.observable_capabilities), "IR has no observable capabilities", errors)
    _require(bool(ir.supported_response_actions), "IR has no supported response actions", errors)
    return errors


def validate_variant_policy(policy: VariantPolicy) -> list[str]:
    errors: list[str] = []
    names = [factor.name for factor in policy.factors]
    _require(policy.schema_version == "c2trace.benchmark.v1.variant_policy", "variant policy schema_version mismatch", errors)
    _require(len(names) == len(set(names)), "variant factor names are not unique", errors)
    value_map = {factor.name: set(factor.values) for factor in policy.factors}
    for factor in policy.factors:
        _require(len(factor.values) >= 2, f"factor {factor.name} has fewer than two values", errors)
        _require(len(factor.values) == len(set(factor.values)), f"factor {factor.name} repeats values", errors)
    for forbidden in policy.forbidden_combinations:
        for name, value in forbidden.when.items():
            _require(name in value_map, f"forbidden combination references unknown factor {name}", errors)
            if name in value_map:
                _require(value in value_map[name], f"forbidden combination uses unknown value {name}={value}", errors)
    profile_ids = [profile.root_id for profile in policy.root_profiles]
    _require(bool(profile_ids), "variant policy has no root profiles", errors)
    _require(len(profile_ids) == len(set(profile_ids)), "variant root profiles are not unique", errors)
    for profile in policy.root_profiles:
        _require(
            profile.standard_count > 0
            and profile.state_changed_count > 0
            and profile.safety_negative_count > 0,
            f"variant counts must be positive for {profile.root_id}",
            errors,
        )
        _require(bool(profile.enabled_values), f"variant profile {profile.root_id} enables no factors", errors)
        for name, values in profile.enabled_values.items():
            _require(name in value_map, f"variant profile {profile.root_id} uses unknown factor {name}", errors)
            _require(bool(values), f"variant profile {profile.root_id} has no values for {name}", errors)
            if name in value_map:
                unknown = sorted(set(values) - value_map[name])
                _require(
                    not unknown,
                    f"variant profile {profile.root_id} uses unknown {name} values: {', '.join(unknown)}",
                    errors,
                )
    return errors


def is_forbidden(state: Mapping[str, str], policy: VariantPolicy) -> bool:
    return any(all(state.get(key) == value for key, value in row.when.items()) for row in policy.forbidden_combinations)


def _contains_ground_truth_key(value: Any, path: str = "$") -> list[str]:
    forbidden = {
        "oracle",
        "oracle_id",
        "ground_truth",
        "allowed_response",
        "forbidden_response",
        "expected_entities",
        "expected_relations",
        "expected_poststate",
        "rationale_codes",
        "target_pid",
        "target_path",
        "target_sha256",
    }
    findings: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).lower() in forbidden:
                findings.append(f"{path}.{key}")
            findings.extend(_contains_ground_truth_key(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(_contains_ground_truth_key(child, f"{path}[{index}]"))
    return findings


def validate_episode(episode: EpisodeTemplate, ir: C2ScenarioIR, policy: VariantPolicy) -> list[str]:
    errors: list[str] = []
    _require(episode.root_id == ir.root_id, "episode root_id does not match IR", errors)
    _require(episode.scenario_ir_sha256 == content_hash(ir), "episode IR hash mismatch", errors)
    _require(episode.variant_policy_sha256 == content_hash(policy), "episode variant policy hash mismatch", errors)
    _require(not is_forbidden(episode.state, policy), "episode state violates a compatibility constraint", errors)
    try:
        profile = policy.profile_for(episode.root_id)
    except ValueError as exc:
        errors.append(str(exc))
        profile = None
    if profile is not None:
        _require(set(episode.state) == set(profile.enabled_values), "episode state factors do not match root profile", errors)
        for name, value in episode.state.items():
            _require(
                value in profile.enabled_values.get(name, ()),
                f"episode state uses disabled value {name}={value}",
                errors,
            )
    leakage = _contains_ground_truth_key(episode.alert_projection)
    _require(not leakage, "alert projection leaks ground truth at: " + ", ".join(leakage), errors)
    oracle = episode.oracle
    if oracle.audit_decision == AuditOracle.APPROVE:
        _require(bool(oracle.allowed_response), "approved episode has no allowed response", errors)
    else:
        _require(not oracle.allowed_response, "rejected/incomplete episode permits response", errors)
    if episode.episode_class == EpisodeClass.SAFETY_NEGATIVE:
        _require(oracle.audit_decision != AuditOracle.APPROVE, "safety-negative episode is approved", errors)
    if episode.episode_class == EpisodeClass.STANDARD:
        _require(episode.state_origin == StateOrigin.BASELINE, "standard episode is not baseline-origin", errors)
        _require(oracle.audit_decision == AuditOracle.APPROVE, "standard episode is not approved", errors)
    else:
        _require(
            episode.state_origin == StateOrigin.CONTROLLED_VARIANT,
            "non-standard episode is not controlled-variant origin",
            errors,
        )
    _require(set(episode.protected_objects) == set(oracle.protected_objects), "episode and oracle protected objects differ", errors)
    return errors


def validate_qualification(receipt: QualificationReceipt) -> list[str]:
    errors: list[str] = []
    missing = [name for name in REQUIRED_QUALIFICATION_CHECKS if name not in receipt.checks]
    _require(not missing, "qualification checks missing: " + ", ".join(missing), errors)
    if receipt.status == "admitted":
        failed = [name for name in REQUIRED_QUALIFICATION_CHECKS if not receipt.checks.get(name, False)]
        _require(not failed, "admitted qualification has failed checks: " + ", ".join(failed), errors)
        _require(len(set(receipt.stable_trial_ids)) >= 3, "admission requires three distinct stable trials", errors)
        _require(bool(receipt.evidence_hashes), "admission requires evidence hashes", errors)
        _require(bool(receipt.vm_snapshot_id.strip()), "admission requires VM snapshot ID", errors)
        _require(bool(SHA256_RE.fullmatch(receipt.software_lock_sha256)), "software lock hash is invalid", errors)
    for path, digest in receipt.evidence_hashes.items():
        _require(bool(path), "qualification evidence path is empty", errors)
        _require(bool(SHA256_RE.fullmatch(digest)), f"invalid evidence hash: {path}", errors)
    material = {
        "root_id": receipt.root_id,
        "checks": dict(receipt.checks),
        "evidence_hashes": dict(sorted(receipt.evidence_hashes.items())),
        "stable_trial_ids": tuple(receipt.stable_trial_ids),
        "vm_snapshot_id": receipt.vm_snapshot_id,
        "software_lock_sha256": receipt.software_lock_sha256,
    }
    _require(receipt.qualification_id == content_hash(material), "qualification receipt content hash is invalid", errors)
    return errors


def require_valid(errors: Iterable[str], *, label: str) -> None:
    rows = list(errors)
    if rows:
        raise BenchmarkValidationError(f"{label} validation failed: " + "; ".join(rows))
