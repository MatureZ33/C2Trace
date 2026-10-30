from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
import hashlib
import json
from typing import Any, Mapping, Protocol, Sequence


SCHEMA_PREFIX = "c2trace.benchmark.v1"


class ClaimTier(StrEnum):
    SOURCE_FAITHFUL = "source_faithful"
    SOURCE_DERIVED = "source_derived"


class MappingType(StrEnum):
    EXACT = "exact"
    EQUIVALENT = "equivalent"
    SUPPORT_ONLY = "support_only"
    OMITTED = "omitted"


class StateOrigin(StrEnum):
    BASELINE = "baseline"
    CONTROLLED_VARIANT = "controlled_variant"


class RootStatus(StrEnum):
    CANDIDATE = "candidate"
    STATIC_REJECTED = "static_rejected"
    QUALIFICATION_PENDING = "qualification_pending"
    EVIDENCE_AVAILABLE = "evidence_available_pending_stability"
    ADMITTED = "admitted"


class SplitName(StrEnum):
    DEVELOPMENT = "development"
    SEEN_ROOT_UNSEEN_STATE = "seen_root_unseen_state_test"
    UNSEEN_ROOT_TOOL = "unseen_root_tool_test"


class EpisodeClass(StrEnum):
    STANDARD = "standard"
    STATE_CHANGED = "state_changed"
    SAFETY_NEGATIVE = "safety_negative"


class TemplateStatus(StrEnum):
    PROVISIONAL_PRE_ADMISSION = "provisional_pre_admission"
    ADMITTED = "admitted"


class AuditOracle(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"
    NEED_MORE_EVIDENCE = "need_more_evidence"


class TrialClass(StrEnum):
    INFRASTRUCTURE_INVALID = "infrastructure_invalid"
    QUALIFICATION_REJECTED = "qualification_rejected"
    EVALUATION_VALID_PASS = "evaluation_valid_pass"
    EVALUATION_VALID_FAIL = "evaluation_valid_fail"


def canonical_json(value: Any) -> str:
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    elif hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def content_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SourceArtifact:
    path: str
    sha256: str
    size: int


@dataclass(frozen=True)
class StepMapping:
    mapping_id: str
    source_step: str
    critical: bool
    mapping_type: MappingType
    local_implementation: str
    source_citations: tuple[str, ...]
    replacement_reason: str | None = None
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["mapping_type"] = self.mapping_type.value
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "StepMapping":
        return cls(
            mapping_id=str(value["mapping_id"]),
            source_step=str(value["source_step"]),
            critical=bool(value["critical"]),
            mapping_type=MappingType(value["mapping_type"]),
            local_implementation=str(value.get("local_implementation", "")),
            source_citations=tuple(value.get("source_citations", ())),
            replacement_reason=value.get("replacement_reason"),
            rationale=str(value.get("rationale", "")),
        )


@dataclass(frozen=True)
class FidelityReceipt:
    receipt_id: str
    root_id: str
    source_version: str
    claim_tier: ClaimTier
    mappings: tuple[StepMapping, ...]
    reviewer: str
    reviewed_at_utc: str
    status: str
    core_step_coverage: float
    mapping_counts: Mapping[str, int]
    notes: str = ""
    schema_version: str = f"{SCHEMA_PREFIX}.fidelity_receipt"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["claim_tier"] = self.claim_tier.value
        value["mappings"] = [mapping.to_dict() for mapping in self.mappings]
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FidelityReceipt":
        return cls(
            receipt_id=str(value["receipt_id"]),
            root_id=str(value["root_id"]),
            source_version=str(value["source_version"]),
            claim_tier=ClaimTier(value["claim_tier"]),
            mappings=tuple(StepMapping.from_dict(row) for row in value.get("mappings", ())),
            reviewer=str(value.get("reviewer", "")),
            reviewed_at_utc=str(value.get("reviewed_at_utc", "")),
            status=str(value.get("status", "")),
            core_step_coverage=float(value.get("core_step_coverage", 0.0)),
            mapping_counts={str(key): int(count) for key, count in value.get("mapping_counts", {}).items()},
            notes=str(value.get("notes", "")),
            schema_version=str(value.get("schema_version", f"{SCHEMA_PREFIX}.fidelity_receipt")),
        )


@dataclass(frozen=True)
class SourceRoot:
    root_id: str
    title: str
    source_url: str
    source_kind: str
    version: str
    license: str
    claim_tier: ClaimTier
    status: RootStatus
    original_behavior: str
    preserved_c2_slice: tuple[str, ...]
    omitted_behavior: tuple[str, ...] = ()
    tool_family: str = ""
    c2_mechanisms: tuple[str, ...] = ()
    execution_object_types: tuple[str, ...] = ()
    environment: tuple[str, ...] = ()
    artifacts: tuple[SourceArtifact, ...] = ()
    fidelity_receipt_path: str = ""
    fidelity_receipt_sha256: str = ""
    notes: str = ""
    schema_version: str = f"{SCHEMA_PREFIX}.source_root"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["claim_tier"] = self.claim_tier.value
        value["status"] = self.status.value
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SourceRoot":
        artifacts = tuple(SourceArtifact(**row) for row in value.get("artifacts", ()))
        return cls(
            root_id=str(value["root_id"]),
            title=str(value["title"]),
            source_url=str(value["source_url"]),
            source_kind=str(value["source_kind"]),
            version=str(value["version"]),
            license=str(value["license"]),
            claim_tier=ClaimTier(value["claim_tier"]),
            status=RootStatus(value["status"]),
            original_behavior=str(value["original_behavior"]),
            preserved_c2_slice=tuple(value["preserved_c2_slice"]),
            omitted_behavior=tuple(value.get("omitted_behavior", ())),
            tool_family=str(value.get("tool_family", "")),
            c2_mechanisms=tuple(value.get("c2_mechanisms", ())),
            execution_object_types=tuple(value.get("execution_object_types", ())),
            environment=tuple(value.get("environment", ())),
            artifacts=artifacts,
            fidelity_receipt_path=str(value.get("fidelity_receipt_path", "")),
            fidelity_receipt_sha256=str(value.get("fidelity_receipt_sha256", "")),
            notes=str(value.get("notes", "")),
            schema_version=str(value.get("schema_version", f"{SCHEMA_PREFIX}.source_root")),
        )


@dataclass(frozen=True)
class ScenarioAction:
    action_id: str
    actor: str
    host: str
    operation: str
    preconditions: tuple[str, ...]
    effects: tuple[str, ...]
    observables: tuple[str, ...]
    source_citations: tuple[str, ...]
    backend_binding: Mapping[str, Any]
    mapping_id: str
    support_only: bool = False


@dataclass(frozen=True)
class C2ScenarioIR:
    scenario_id: str
    root_id: str
    title: str
    actions: tuple[ScenarioAction, ...]
    edges: tuple[tuple[str, str], ...]
    cleanup_actions: tuple[str, ...]
    protected_objects: tuple[str, ...]
    observable_capabilities: tuple[str, ...] = ()
    supported_response_actions: tuple[str, ...] = ()
    supported_persistence: tuple[str, ...] = ("none",)
    schema_version: str = f"{SCHEMA_PREFIX}.scenario_ir"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "C2ScenarioIR":
        return cls(
            scenario_id=str(value["scenario_id"]),
            root_id=str(value["root_id"]),
            title=str(value["title"]),
            actions=tuple(
                ScenarioAction(
                    action_id=str(row["action_id"]),
                    actor=str(row["actor"]),
                    host=str(row["host"]),
                    operation=str(row["operation"]),
                    preconditions=tuple(row.get("preconditions", ())),
                    effects=tuple(row.get("effects", ())),
                    observables=tuple(row.get("observables", ())),
                    source_citations=tuple(row.get("source_citations", ())),
                    backend_binding=dict(row.get("backend_binding", {})),
                    mapping_id=str(row.get("mapping_id", "")),
                    support_only=bool(row.get("support_only", False)),
                )
                for row in value["actions"]
            ),
            edges=tuple(tuple(edge) for edge in value.get("edges", ())),
            cleanup_actions=tuple(value.get("cleanup_actions", ())),
            protected_objects=tuple(value.get("protected_objects", ())),
            observable_capabilities=tuple(value.get("observable_capabilities", ())),
            supported_response_actions=tuple(value.get("supported_response_actions", ())),
            supported_persistence=tuple(value.get("supported_persistence", ("none",))),
            schema_version=str(value.get("schema_version", f"{SCHEMA_PREFIX}.scenario_ir")),
        )


@dataclass(frozen=True)
class Factor:
    name: str
    values: tuple[str, ...]


@dataclass(frozen=True)
class ForbiddenCombination:
    when: Mapping[str, str]
    reason: str


@dataclass(frozen=True)
class RootVariantProfile:
    root_id: str
    enabled_values: Mapping[str, tuple[str, ...]]
    standard_count: int
    state_changed_count: int
    safety_negative_count: int

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RootVariantProfile":
        return cls(
            root_id=str(value["root_id"]),
            enabled_values={
                str(name): tuple(values)
                for name, values in value.get("enabled_values", {}).items()
            },
            standard_count=int(value.get("standard_count", 1)),
            state_changed_count=int(value.get("state_changed_count", 1)),
            safety_negative_count=int(value.get("safety_negative_count", 1)),
        )


@dataclass(frozen=True)
class VariantPolicy:
    policy_id: str
    seed: int
    factors: tuple[Factor, ...]
    forbidden_combinations: tuple[ForbiddenCombination, ...]
    root_profiles: tuple[RootVariantProfile, ...]
    schema_version: str = f"{SCHEMA_PREFIX}.variant_policy"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VariantPolicy":
        return cls(
            policy_id=str(value["policy_id"]),
            seed=int(value["seed"]),
            factors=tuple(Factor(str(row["name"]), tuple(row["values"])) for row in value["factors"]),
            forbidden_combinations=tuple(
                ForbiddenCombination(dict(row["when"]), str(row["reason"]))
                for row in value.get("forbidden_combinations", ())
            ),
            root_profiles=tuple(
                RootVariantProfile.from_dict(row) for row in value.get("root_profiles", ())
            ),
            schema_version=str(value.get("schema_version", f"{SCHEMA_PREFIX}.variant_policy")),
        )

    def profile_for(self, root_id: str) -> RootVariantProfile:
        matches = [profile for profile in self.root_profiles if profile.root_id == root_id]
        if len(matches) != 1:
            raise ValueError(f"variant policy requires exactly one profile for {root_id}; found {len(matches)}")
        return matches[0]


@dataclass(frozen=True)
class EpisodeOracle:
    oracle_id: str
    expected_entities: tuple[str, ...]
    expected_relations: tuple[str, ...]
    audit_decision: AuditOracle
    allowed_response: tuple[str, ...]
    forbidden_response: tuple[str, ...]
    expected_poststate: Mapping[str, Any]
    protected_objects: tuple[str, ...]
    rationale_codes: tuple[str, ...]
    schema_version: str = f"{SCHEMA_PREFIX}.episode_oracle"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["audit_decision"] = self.audit_decision.value
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EpisodeOracle":
        return cls(
            oracle_id=str(value["oracle_id"]),
            expected_entities=tuple(value.get("expected_entities", ())),
            expected_relations=tuple(value.get("expected_relations", ())),
            audit_decision=AuditOracle(value["audit_decision"]),
            allowed_response=tuple(value.get("allowed_response", ())),
            forbidden_response=tuple(value.get("forbidden_response", ())),
            expected_poststate=dict(value.get("expected_poststate", {})),
            protected_objects=tuple(value.get("protected_objects", ())),
            rationale_codes=tuple(value.get("rationale_codes", ())),
            schema_version=str(value.get("schema_version", f"{SCHEMA_PREFIX}.episode_oracle")),
        )


@dataclass(frozen=True)
class EpisodeTemplate:
    episode_id: str
    root_id: str
    scenario_ir_sha256: str
    variant_policy_sha256: str
    variant_id: str
    episode_class: EpisodeClass
    state_origin: StateOrigin
    state: Mapping[str, str]
    alert_projection: Mapping[str, Any]
    oracle: EpisodeOracle
    protected_objects: tuple[str, ...]
    template_status: TemplateStatus = TemplateStatus.PROVISIONAL_PRE_ADMISSION
    split: SplitName | None = None
    schema_version: str = f"{SCHEMA_PREFIX}.episode_template"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["episode_class"] = self.episode_class.value
        value["state_origin"] = self.state_origin.value
        value["oracle"]["audit_decision"] = self.oracle.audit_decision.value
        value["template_status"] = self.template_status.value
        value["split"] = self.split.value if self.split else None
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EpisodeTemplate":
        split = value.get("split")
        return cls(
            episode_id=str(value["episode_id"]),
            root_id=str(value["root_id"]),
            scenario_ir_sha256=str(value["scenario_ir_sha256"]),
            variant_policy_sha256=str(value["variant_policy_sha256"]),
            variant_id=str(value["variant_id"]),
            episode_class=EpisodeClass(value["episode_class"]),
            state_origin=StateOrigin(value["state_origin"]),
            state=dict(value["state"]),
            alert_projection=dict(value["alert_projection"]),
            oracle=EpisodeOracle.from_dict(value["oracle"]),
            protected_objects=tuple(value["protected_objects"]),
            template_status=TemplateStatus(
                value.get("template_status", TemplateStatus.PROVISIONAL_PRE_ADMISSION.value)
            ),
            split=SplitName(split) if split else None,
            schema_version=str(value.get("schema_version", f"{SCHEMA_PREFIX}.episode_template")),
        )


@dataclass(frozen=True)
class ActionReceipt:
    action_id: str
    backend: str
    started_at_utc: str
    ended_at_utc: str
    success: bool
    request_sha256: str
    result: Mapping[str, Any]
    error_type: str | None = None


class AttackBackend(Protocol):
    name: str

    def prepare(self, scenario: C2ScenarioIR, parameters: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def execute(self, prepared: Mapping[str, Any]) -> Sequence[ActionReceipt]: ...

    def query_state(self, prepared: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def cleanup(self, prepared: Mapping[str, Any]) -> Sequence[ActionReceipt]: ...


@dataclass(frozen=True)
class QualificationReceipt:
    qualification_id: str
    root_id: str
    status: str
    checks: Mapping[str, bool]
    evidence_hashes: Mapping[str, str]
    stable_trial_ids: tuple[str, ...]
    vm_snapshot_id: str
    software_lock_sha256: str
    reasons: tuple[str, ...] = ()
    schema_version: str = f"{SCHEMA_PREFIX}.qualification_receipt"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "QualificationReceipt":
        return cls(
            qualification_id=str(value["qualification_id"]),
            root_id=str(value["root_id"]),
            status=str(value["status"]),
            checks=dict(value["checks"]),
            evidence_hashes=dict(value.get("evidence_hashes", {})),
            stable_trial_ids=tuple(value.get("stable_trial_ids", ())),
            vm_snapshot_id=str(value.get("vm_snapshot_id", "")),
            software_lock_sha256=str(value.get("software_lock_sha256", "")),
            reasons=tuple(value.get("reasons", ())),
            schema_version=str(value.get("schema_version", f"{SCHEMA_PREFIX}.qualification_receipt")),
        )


@dataclass(frozen=True)
class TrialReceipt:
    trial_id: str
    episode_id: str
    repetition: int
    trial_class: TrialClass
    started_at_utc: str
    ended_at_utc: str
    evidence_hashes: Mapping[str, str]
    metrics: Mapping[str, float]
    response_actions: tuple[Mapping[str, Any], ...]
    poststate: Mapping[str, Any]
    failure_reason: str | None = None
    schema_version: str = f"{SCHEMA_PREFIX}.trial_receipt"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["trial_class"] = self.trial_class.value
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TrialReceipt":
        return cls(
            trial_id=str(value["trial_id"]),
            episode_id=str(value["episode_id"]),
            repetition=int(value["repetition"]),
            trial_class=TrialClass(value["trial_class"]),
            started_at_utc=str(value["started_at_utc"]),
            ended_at_utc=str(value["ended_at_utc"]),
            evidence_hashes=dict(value.get("evidence_hashes", {})),
            metrics=dict(value.get("metrics", {})),
            response_actions=tuple(value.get("response_actions", ())),
            poststate=dict(value.get("poststate", {})),
            failure_reason=value.get("failure_reason"),
            schema_version=str(value.get("schema_version", f"{SCHEMA_PREFIX}.trial_receipt")),
        )


@dataclass(frozen=True)
class SplitPolicy:
    development_roots: int = 2
    minimum_unseen_root_tool_roots: int = 6
    experience_history_forbidden_splits: tuple[SplitName, ...] = field(
        default=(SplitName.SEEN_ROOT_UNSEEN_STATE, SplitName.UNSEEN_ROOT_TOOL)
    )
