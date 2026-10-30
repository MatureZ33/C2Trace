from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from .admission import AdmissionError, validate_admission_receipt
from .contracts import (
    CASE_ID_RE,
    SCHEMA_FILES,
    SOURCE_STRATUM,
    SUPPORTED_TRACE_TYPES,
    expected_source_kind,
)
from .jsonschema import validate_instance


class BenchValidationError(ValueError):
    """Raised when Bench v4 static assets are not internally consistent."""


def read_json(path: str | Path) -> dict[str, Any]:
    target = Path(path)
    try:
        value = json.loads(target.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BenchValidationError(f"unable to read JSON {target}: {exc}") from exc
    if not isinstance(value, dict):
        raise BenchValidationError(f"JSON root must be an object: {target}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _contained(root: Path, relative: Any, label: str) -> Path:
    raw = str(relative or "").strip()
    if not raw or Path(raw).is_absolute():
        raise BenchValidationError(f"{label} must be a non-empty Bench-relative path")
    path = (root / raw).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise BenchValidationError(f"{label} escapes the Bench root") from exc
    if not path.is_file():
        raise BenchValidationError(f"{label} is missing: {path}")
    return path


def load_schemas(bench_root: str | Path) -> dict[str, dict[str, Any]]:
    root = Path(bench_root).resolve() / "schemas"
    schemas: dict[str, dict[str, Any]] = {}
    for version, name in SCHEMA_FILES.items():
        schema = read_json(root / name)
        if str(schema.get("$id") or "").strip() in {
            str(item.get("$id") or "").strip() for item in schemas.values()
        }:
            raise BenchValidationError(f"duplicate schema $id in {name}")
        schemas[version] = schema
    return schemas


def _schema_errors(
    document: Mapping[str, Any],
    schemas: Mapping[str, Mapping[str, Any]],
    label: str,
) -> list[str]:
    version = str(document.get("schema_version") or "")
    schema = schemas.get(version)
    if schema is None:
        return [f"{label}: unsupported schema_version {version!r}"]
    return [f"{label}: {error}" for error in validate_instance(document, schema)]


def _source_lock_paths(root: Path) -> list[Path]:
    return sorted(
        {
            path.resolve()
            for path in root.rglob("source_lock.json")
            if "schemas" not in path.parts
        },
        key=lambda item: item.relative_to(root).as_posix(),
    )


def _case_paths(root: Path) -> list[Path]:
    return sorted(
        {path.resolve() for path in root.rglob("case.json") if "cases" in path.parts},
        key=lambda item: item.relative_to(root).as_posix(),
    )


def _validate_source_lock(
    root: Path, path: Path, source: Mapping[str, Any], errors: list[str]
) -> None:
    source_kind = str(source.get("source_kind") or "")
    expected_stratum = SOURCE_STRATUM.get(source_kind)
    if str(source.get("dataset_stratum") or "") != expected_stratum:
        errors.append(f"{path}: source_kind/stratum pairing is invalid")
    artifacts = [item for item in source.get("artifacts", []) if isinstance(item, Mapping)]
    artifact_ids = [str(item.get("artifact_id") or "") for item in artifacts]
    if len(artifact_ids) != len(set(artifact_ids)):
        errors.append(f"{path}: artifact_id values must be unique")
    for row in artifacts:
        try:
            artifact_path = _contained(root, row.get("path"), "source artifact")
        except BenchValidationError as exc:
            errors.append(f"{path}: {exc}")
            continue
        if sha256_file(artifact_path) != str(row.get("sha256") or ""):
            errors.append(f"{path}: source artifact hash drifted: {row.get('path')}")
        if "size" in row and artifact_path.stat().st_size != int(row.get("size") or 0):
            errors.append(f"{path}: source artifact size drifted: {row.get('path')}")
    license_row = source.get("license") if isinstance(source.get("license"), Mapping) else {}
    try:
        license_path = _contained(root, license_row.get("path"), "source license")
    except BenchValidationError as exc:
        errors.append(f"{path}: {exc}")
    else:
        if sha256_file(license_path) != str(license_row.get("sha256") or ""):
            errors.append(f"{path}: source license hash drifted")


def _validate_mapping(mapping: Mapping[str, Any], label: str, errors: list[str]) -> None:
    steps = [item for item in mapping.get("source_steps", []) if isinstance(item, Mapping)]
    step_ids = [str(item.get("step_id") or "") for item in steps]
    if len(step_ids) != len(set(step_ids)):
        errors.append(f"{label}: source step IDs must be unique")
    step_set = set(step_ids)
    for relation in mapping.get("source_relations", []):
        if not isinstance(relation, Mapping):
            continue
        if str(relation.get("source_step_id") or "") not in step_set or str(
            relation.get("target_step_id") or ""
        ) not in step_set:
            errors.append(f"{label}: source relation references an unknown step")
    mandatory_steps = [item for item in steps if item.get("role") == "mandatory"]
    mapped_abilities: list[str] = []
    for step in steps:
        role = str(step.get("role") or "")
        fidelity = str(step.get("fidelity") or "")
        implementation = step.get("implementation")
        if role == "mandatory":
            if fidelity == "unmapped" or not isinstance(implementation, Mapping):
                errors.append(
                    f"{label}: mandatory step {step.get('step_id')} is not implemented"
                )
            elif implementation.get("kind") not in {"target_runtime", "external_cleanup"}:
                ability_id = str(implementation.get("ability_id") or "")
                if not ability_id:
                    errors.append(
                        f"{label}: mandatory step {step.get('step_id')} lacks an ability ID"
                    )
                else:
                    mapped_abilities.append(ability_id)
            if isinstance(implementation, Mapping):
                kind = str(implementation.get("kind") or "")
                platform = str(implementation.get("execution_platform") or "")
                executor = str(implementation.get("executor") or "")
                operation_role = str(implementation.get("operation_role") or "")
                if platform == "linux" and executor != "sh":
                    errors.append(f"{label}: Linux implementation must use sh")
                if platform == "windows" and executor not in {"cmd", "psh"}:
                    errors.append(f"{label}: Windows implementation must use cmd or psh")
                if kind == "external_cleanup":
                    if implementation.get("ability_id") is not None:
                        errors.append(f"{label}: external cleanup must not fabricate an ability ID")
                    if operation_role != "external_cleanup" or not str(
                        implementation.get("cleanup_action_id") or ""
                    ):
                        errors.append(f"{label}: external cleanup requires its cleanup action binding")
                    if implementation.get("cleanup_policy") != "deferred_external":
                        errors.append(f"{label}: external cleanup must be deferred until after scoring")
                elif kind == "target_runtime":
                    if implementation.get("ability_id") is not None:
                        errors.append(f"{label}: target runtime is not a fabricated ability link")
                elif operation_role not in {"bootstrap", "scenario"}:
                    errors.append(f"{label}: CALDERA ability has an invalid Operation role")
        if role == "out_of_scope" and (
            fidelity != "unmapped" or implementation is not None
        ):
            errors.append(
                f"{label}: out-of-scope step {step.get('step_id')} must remain unmapped"
            )
    if len(mapped_abilities) != len(set(mapped_abilities)):
        errors.append(
            f"{label}: every source step requires a distinct ability instance ID"
        )
    linear = (
        mapping.get("linearization")
        if isinstance(mapping.get("linearization"), Mapping)
        else {}
    )
    if set(linear.get("source_step_order") or []) != {
        str(item.get("step_id") or "") for item in mandatory_steps
    }:
        errors.append(f"{label}: source_step_order must cover every mandatory step exactly")
    if list(linear.get("ability_order") or []) != mapped_abilities:
        errors.append(
            f"{label}: linearized ability order must follow mandatory source-step order"
        )


def _operation_rows(plan: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {
        str(item.get("role") or ""): item
        for item in plan.get("operations", [])
        if isinstance(item, Mapping)
    }


def _validate_operation_plan(
    plan: Mapping[str, Any], label: str, errors: list[str]
) -> None:
    operations = [item for item in plan.get("operations", []) if isinstance(item, Mapping)]
    roles = [str(item.get("role") or "") for item in operations]
    if sorted(roles) != ["bootstrap", "scenario"]:
        errors.append(f"{label}: exactly one bootstrap and one scenario Operation are required")
    all_abilities: list[str] = []
    for operation in operations:
        ordering = [str(item) for item in operation.get("atomic_ordering", [])]
        mandatory = [str(item) for item in operation.get("mandatory_ability_ids", [])]
        if not set(mandatory).issubset(ordering):
            errors.append(
                f"{label}: {operation.get('role')} mandatory abilities are not a subset of atomic_ordering"
            )
        all_abilities.extend(ordering)
    if len(all_abilities) != len(set(all_abilities)):
        errors.append(f"{label}: ability IDs must be unique across both Operations")
    by_role = _operation_rows(plan)
    if by_role.get("bootstrap", {}).get("execution_agent_role") != "control":
        errors.append(f"{label}: Bootstrap must execute on the protected control agent")
    if by_role.get("scenario", {}).get("execution_agent_role") not in {"target", "driver"}:
        errors.append(f"{label}: Scenario must execute on the target or Kali driver")


def _validate_ground_truth(
    ground_truth: Mapping[str, Any],
    operation_plan: Mapping[str, Any],
    mapping: Mapping[str, Any],
    label: str,
    errors: list[str],
) -> None:
    operations = _operation_rows(operation_plan)
    ability_instances = [
        item
        for item in ground_truth.get("ability_instances", [])
        if isinstance(item, Mapping)
    ]
    instance_keys = [str(item.get("instance_key") or "") for item in ability_instances]
    if len(instance_keys) != len(set(instance_keys)):
        errors.append(f"{label}: instance_key values must be unique")
    trace_ids: list[str] = []
    ability_ids = [str(item.get("ability_id") or "") for item in ability_instances]
    if len(ability_ids) != len(set(ability_ids)):
        errors.append(f"{label}: ability IDs must be unique ability instances")
    planned_abilities = {
        str(ability_id): {
            "role": role,
            "mandatory": str(ability_id) in set(operation.get("mandatory_ability_ids") or []),
        }
        for role, operation in operations.items()
        for ability_id in operation.get("atomic_ordering", [])
    }
    if set(ability_ids) != set(planned_abilities):
        errors.append(
            f"{label}: ability instances must cover every planned Operation ability exactly"
        )
    mapping_steps = {
        str(step.get("step_id") or ""): step
        for step in mapping.get("source_steps", [])
        if isinstance(step, Mapping)
    }
    mapped_steps_by_ability: dict[str, set[str]] = {}
    for step_id, step in mapping_steps.items():
        implementation = step.get("implementation")
        if not isinstance(implementation, Mapping) or not implementation.get("ability_id"):
            continue
        mapped_steps_by_ability.setdefault(
            str(implementation.get("ability_id")), set()
        ).add(step_id)
    mapped_gt_abilities: set[str] = set()
    trace_ids_by_ability: dict[str, set[str]] = {}
    for ability in ability_instances:
        role = str(ability.get("operation_role") or "")
        operation = operations.get(role, {})
        ability_id = str(ability.get("ability_id") or "")
        if ability_id not in set(operation.get("atomic_ordering") or []):
            errors.append(
                f"{label}: ability {ability_id} is not in its {role} Operation"
            )
        planned = planned_abilities.get(ability_id, {})
        if planned and str(planned.get("role") or "") != role:
            errors.append(f"{label}: ability {ability_id} has the wrong Operation role")
        attack_mapped = ability.get("attack_mapped") is True
        mandatory = ability.get("mandatory") is True
        if attack_mapped and mandatory and planned and not bool(planned.get("mandatory")):
            errors.append(
                f"{label}: source-mandatory ability {ability_id} is not an Operation-mandatory link"
            )
        expected_ability_role = (
            "attack_mapped_mandatory"
            if attack_mapped and mandatory
            else "attack_mapped_optional"
            if attack_mapped
            else "support"
        )
        if str(ability.get("ability_role") or "") != expected_ability_role:
            errors.append(f"{label}: ability {ability_id} has inconsistent ability_role flags")
        declared_source_steps = set(ability.get("source_step_ids") or [])
        if not declared_source_steps.issubset(mapping_steps):
            errors.append(f"{label}: ability {ability_id} references an unknown source step")
        if attack_mapped and declared_source_steps != mapped_steps_by_ability.get(ability_id, set()):
            errors.append(f"{label}: ability {ability_id} source-step binding differs from mapping")
        traces = [item for item in ability.get("trace_facts", []) if isinstance(item, Mapping)]
        trace_ids_by_ability[ability_id] = {
            str(item.get("trace_id") or "") for item in traces
        }
        scoreable = [item for item in traces if item.get("scoreable_by_c2trace") is True]
        if ability.get("metric_eligible") is True and not scoreable:
            errors.append(
                f"{label}: metric-eligible ability {ability.get('instance_key')} has no scoreable trace"
            )
        if ability.get("metric_eligible") is False and not str(
            ability.get("metric_exclusion_reason") or ""
        ).strip():
            errors.append(
                f"{label}: metric-ineligible ability {ability.get('instance_key')} lacks an exclusion reason"
            )
        for trace in traces:
            trace_ids.append(str(trace.get("trace_id") or ""))
            if str(trace.get("producer_ability_instance") or "") != str(
                ability.get("instance_key") or ""
            ):
                errors.append(
                    f"{label}: trace {trace.get('trace_id')} producer differs from its ability instance"
                )
            if str(trace.get("trace_type") or "") not in SUPPORTED_TRACE_TYPES:
                errors.append(f"{label}: unsupported trace type {trace.get('trace_type')}")
        if ability.get("attack_mapped") is True and ability.get("mandatory") is True:
            mapped_gt_abilities.add(ability_id)
    if len(trace_ids) != len(set(trace_ids)):
        errors.append(f"{label}: trace_id values must be globally unique")
    mapped_source_abilities = {
        str(implementation.get("ability_id") or "")
        for step in mapping.get("source_steps", [])
        if isinstance(step, Mapping)
        and step.get("role") == "mandatory"
        and isinstance((implementation := step.get("implementation")), Mapping)
        and implementation.get("kind") not in {"target_runtime", "external_cleanup"}
    }
    if mapped_gt_abilities != mapped_source_abilities:
        errors.append(
            f"{label}: attack-mapped mandatory Ground Truth abilities differ from the source mapping"
        )
    for step in mapping.get("source_steps", []):
        if not isinstance(step, Mapping):
            continue
        implementation = step.get("implementation")
        if not isinstance(implementation, Mapping) or not implementation.get("ability_id"):
            continue
        ability_id = str(implementation.get("ability_id") or "")
        if not set(implementation.get("trace_fact_ids") or []).issubset(
            trace_ids_by_ability.get(ability_id, set())
        ):
            errors.append(
                f"{label}: mapping trace IDs are not owned by ability {ability_id}"
            )


def _validate_case_cross_contracts(
    root: Path,
    case_path: Path,
    case: Mapping[str, Any],
    source_locks: Mapping[str, Mapping[str, Any]],
    schemas: Mapping[str, Mapping[str, Any]],
    errors: list[str],
) -> None:
    case_id = str(case.get("case_id") or "")
    if not CASE_ID_RE.fullmatch(case_id):
        return
    if case_path.parent.name != case_id:
        errors.append(f"{case_path}: case directory differs from case_id")
    source_kind = str(case.get("source_kind") or "")
    if expected_source_kind(case_id) != source_kind:
        errors.append(f"{case_path}: case prefix does not match source_kind")
    if SOURCE_STRATUM.get(source_kind) != str(case.get("dataset_stratum") or ""):
        errors.append(f"{case_path}: source_kind does not match dataset_stratum")
    source_ref = case.get("source") if isinstance(case.get("source"), Mapping) else {}
    source_id = str(source_ref.get("source_id") or "")
    source_lock = source_locks.get(source_id)
    if source_lock is None:
        errors.append(f"{case_path}: source_id {source_id!r} has no source lock")
    else:
        if str(source_lock.get("source_kind") or "") != source_kind:
            errors.append(f"{case_path}: case/source-lock kind mismatch")
        try:
            lock_path = _contained(root, source_ref.get("source_lock"), "case source lock")
        except BenchValidationError as exc:
            errors.append(f"{case_path}: {exc}")
        else:
            if read_json(lock_path) != dict(source_lock):
                errors.append(f"{case_path}: case references the wrong source lock")
        artifacts = {
            str(item.get("artifact_id") or ""): item
            for item in source_lock.get("artifacts", [])
            if isinstance(item, Mapping)
        }
        artifact = artifacts.get(str(source_ref.get("artifact_id") or ""))
        if artifact is None:
            errors.append(f"{case_path}: source artifact is absent from its lock")
        elif (
            str(artifact.get("path") or "") != str(source_ref.get("artifact_path") or "")
            or str(artifact.get("sha256") or "")
            != str(source_ref.get("artifact_sha256") or "")
        ):
            errors.append(f"{case_path}: source artifact binding drifted")
    contracts = case.get("contracts") if isinstance(case.get("contracts"), Mapping) else {}
    documents: dict[str, dict[str, Any]] = {}
    for field in (
        "mapping",
        "ground_truth",
        "target_profile",
        "operation_plan",
        "evidence_plan",
        "cleanup_plan",
    ):
        try:
            path = _contained(root, contracts.get(field), f"contracts.{field}")
            document = read_json(path)
        except BenchValidationError as exc:
            errors.append(f"{case_path}: {exc}")
            continue
        documents[field] = document
        errors.extend(_schema_errors(document, schemas, str(path)))
        if str(document.get("case_id") or "") != case_id:
            errors.append(f"{path}: case_id differs from case.json")
        if str(document.get("source_id") or "") != source_id:
            errors.append(f"{path}: source_id differs from case.json")
        if str(document.get("dataset_stratum") or "") != str(
            case.get("dataset_stratum") or ""
        ):
            errors.append(f"{path}: dataset_stratum differs from case.json")
    mapping = documents.get("mapping")
    operation_plan = documents.get("operation_plan")
    target_profile = documents.get("target_profile")
    ground_truth = documents.get("ground_truth")
    evidence_plan = documents.get("evidence_plan")
    cleanup_plan = documents.get("cleanup_plan")
    if mapping is not None:
        _validate_mapping(mapping, f"{case_id} mapping", errors)
        if str(mapping.get("source_kind") or "") != source_kind:
            errors.append(f"{case_id}: mapping source_kind differs from case.json")
    if operation_plan is not None:
        _validate_operation_plan(operation_plan, f"{case_id} operation plan", errors)
    if mapping is not None and operation_plan is not None:
        mapped_order = list((mapping.get("linearization") or {}).get("ability_order") or [])
        all_order = [
            str(ability_id)
            for row in operation_plan.get("operations", [])
            if isinstance(row, Mapping)
            for ability_id in row.get("atomic_ordering", [])
        ]
        if not set(mapped_order).issubset(all_order):
            errors.append(f"{case_id}: mapped abilities are missing from the Operation plan")
        planned_mandatory = {
            str(ability_id)
            for row in operation_plan.get("operations", [])
            if isinstance(row, Mapping)
            for ability_id in row.get("mandatory_ability_ids", [])
        }
        if not set(mapped_order).issubset(planned_mandatory):
            errors.append(
                f"{case_id}: attack-mapped abilities must be mandatory Operation links"
            )
        implementation_by_ability = {
            str(implementation.get("ability_id") or ""): implementation
            for step in mapping.get("source_steps", [])
            if isinstance(step, Mapping)
            and isinstance((implementation := step.get("implementation")), Mapping)
            and implementation.get("ability_id")
        }
        for operation in operation_plan.get("operations", []):
            if not isinstance(operation, Mapping):
                continue
            operation_role = str(operation.get("role") or "")
            agent_role = str(operation.get("execution_agent_role") or "")
            for ability_id in operation.get("atomic_ordering", []):
                implementation = implementation_by_ability.get(str(ability_id))
                if implementation is None:
                    continue
                if str(implementation.get("operation_role") or "") != operation_role:
                    errors.append(f"{case_id}: mapped ability is assigned to the wrong Operation")
                platform = str(implementation.get("execution_platform") or "")
                executor = str(implementation.get("executor") or "")
                if agent_role == "driver" and (platform, executor) != ("linux", "sh"):
                    errors.append(f"{case_id}: driver abilities must execute on Linux with sh")
                if agent_role in {"control", "target"} and (
                    platform != "windows" or executor not in {"cmd", "psh"}
                ):
                    errors.append(f"{case_id}: Windows control/target abilities require cmd or psh")
    if target_profile is not None and operation_plan is not None:
        target_facts = {
            str(item.get("trait") or "")
            for item in target_profile.get("runtime_facts", [])
            if isinstance(item, Mapping)
        }
        planned_facts = set(
            (operation_plan.get("runtime_source") or {}).get("facts") or []
        )
        if target_facts != planned_facts:
            errors.append(f"{case_id}: runtime facts differ between target profile and Operation plan")
        target = target_profile.get("target") if isinstance(target_profile.get("target"), Mapping) else {}
        identity = (
            target_profile.get("identity_requirements")
            if isinstance(target_profile.get("identity_requirements"), Mapping)
            else {}
        )
        agent_backed = target.get("agent_backed") is True
        if bool(identity.get("new_paw")) != agent_backed:
            errors.append(f"{case_id}: new_paw must match whether the target is CALDERA-agent-backed")
        target_kind = str(target.get("kind") or "")
        contact = target.get("contact") if isinstance(target.get("contact"), Mapping) else {}
        network_mode = str(target.get("network_mode") or "")
        expected_direction = {
            "outbound_active_flow": "outbound",
            "inbound_listener": "inbound",
        }.get(network_mode)
        if str(contact.get("direction") or "") != expected_direction:
            errors.append(f"{case_id}: contact direction differs from target network_mode")
        if target_kind in {"ctid_windows_webshell", "webshell"}:
            if agent_backed or identity.get("new_paw") is not False:
                errors.append(f"{case_id}: Windows WebShell must not claim a new CALDERA PAW")
            if network_mode != "inbound_listener":
                errors.append(f"{case_id}: Windows WebShell must use inbound-listener semantics")
        elif target_kind in {"manx", "sandcat"}:
            if not agent_backed or network_mode != "outbound_active_flow":
                errors.append(f"{case_id}: agent target must be an outbound active flow")
    if ground_truth is not None and mapping is not None and operation_plan is not None:
        if str(ground_truth.get("source_kind") or "") != source_kind:
            errors.append(f"{case_id}: Ground Truth source_kind differs from case.json")
        _validate_ground_truth(
            ground_truth,
            operation_plan,
            mapping,
            f"{case_id} Ground Truth",
            errors,
        )
        if target_profile is not None and str(ground_truth.get("target_kind") or "") != str(
            (target_profile.get("target") or {}).get("kind") or ""
        ):
            errors.append(f"{case_id}: Ground Truth target_kind differs from target profile")
        all_gt_trace_ids = {
            str(trace.get("trace_id") or "")
            for ability in ground_truth.get("ability_instances", [])
            if isinstance(ability, Mapping)
            for trace in ability.get("trace_facts", [])
            if isinstance(trace, Mapping)
        }
        for step in mapping.get("source_steps", []):
            implementation = step.get("implementation") if isinstance(step, Mapping) else None
            if not isinstance(implementation, Mapping):
                continue
            declared = set(implementation.get("trace_fact_ids") or [])
            if not declared.issubset(all_gt_trace_ids):
                errors.append(f"{case_id}: mapping declares unknown Ground Truth trace IDs")
    if evidence_plan is not None and ground_truth is not None:
        all_gt_trace_ids = {
            str(trace.get("trace_id") or "")
            for ability in ground_truth.get("ability_instances", [])
            if isinstance(ability, Mapping)
            for trace in ability.get("trace_facts", [])
            if isinstance(trace, Mapping)
        }
        scoreable_trace_ids = {
            str(trace.get("trace_id") or "")
            for ability in ground_truth.get("ability_instances", [])
            if isinstance(ability, Mapping)
            for trace in ability.get("trace_facts", [])
            if isinstance(trace, Mapping) and trace.get("scoreable_by_c2trace") is True
        }
        declared_capture_trace_ids = {
            str(trace_id)
            for capture in evidence_plan.get("captures", [])
            if isinstance(capture, Mapping)
            for trace_id in capture.get("trace_fact_ids", [])
        }
        if not declared_capture_trace_ids.issubset(all_gt_trace_ids):
            errors.append(f"{case_id}: evidence plan references unknown Ground Truth traces")
        captured = {
            str(trace_id)
            for capture in evidence_plan.get("captures", [])
            if isinstance(capture, Mapping)
            and capture.get("required") is True
            and capture.get("collector") != "caldera_report"
            for trace_id in capture.get("trace_fact_ids", [])
        }
        if not scoreable_trace_ids.issubset(captured):
            errors.append(
                f"{case_id}: required non-CALDERA evidence capture misses scoreable traces"
            )
    if cleanup_plan is not None and mapping is not None:
        actions = [
            action for action in cleanup_plan.get("actions", []) if isinstance(action, Mapping)
        ]
        action_ids = [str(action.get("action_id") or "") for action in actions]
        if len(action_ids) != len(set(action_ids)):
            errors.append(f"{case_id}: cleanup action IDs must be unique")
        action_by_id = {str(action.get("action_id") or ""): action for action in actions}
        source_step_ids = {
            str(step.get("step_id") or "")
            for step in mapping.get("source_steps", [])
            if isinstance(step, Mapping)
        }
        for action in actions:
            if not set(action.get("source_step_ids") or []).issubset(source_step_ids):
                errors.append(f"{case_id}: cleanup action references an unknown source step")
        for step in mapping.get("source_steps", []):
            if not isinstance(step, Mapping):
                continue
            implementation = step.get("implementation")
            if not isinstance(implementation, Mapping) or implementation.get(
                "cleanup_policy"
            ) != "deferred_external":
                continue
            action = action_by_id.get(str(implementation.get("cleanup_action_id") or ""))
            if action is None or str(step.get("step_id") or "") not in set(
                action.get("source_step_ids") or []
            ):
                errors.append(f"{case_id}: external cleanup step is not bound to cleanup_plan")
    try:
        bundle_path = _contained(root, contracts.get("caldera_bundle"), "contracts.caldera_bundle")
        bundle = read_json(bundle_path)
    except BenchValidationError as exc:
        errors.append(f"{case_path}: {exc}")
    else:
        if str(bundle.get("case_id") or "") != case_id:
            errors.append(f"{bundle_path}: CALDERA bundle case_id mismatch")
        if bundle.get("source_id") is not None and str(bundle.get("source_id")) != source_id:
            errors.append(f"{bundle_path}: CALDERA bundle source_id mismatch")
        bundle_rows: dict[str, list[Mapping[str, Any]]] = {}
        for collection in ("abilities", "adversaries", "sources", "payloads"):
            raw_rows = bundle.get(collection, [])
            if not isinstance(raw_rows, list):
                errors.append(f"{bundle_path}: {collection} must be an array")
                continue
            rows = [row for row in raw_rows if isinstance(row, Mapping)]
            if len(rows) != len(raw_rows):
                errors.append(f"{bundle_path}: {collection} entries must be objects")
            bundle_rows[collection] = rows
            row_ids = [str(row.get("id") or "") for row in rows]
            if len(row_ids) != len(set(row_ids)):
                errors.append(f"{bundle_path}: {collection} IDs must be unique")
            for index, row in enumerate(rows):
                try:
                    asset_path = _contained(
                        root,
                        row.get("path"),
                        f"CALDERA bundle {collection}[{index}].path",
                    )
                except BenchValidationError as exc:
                    errors.append(f"{bundle_path}: {exc}")
                    continue
                if sha256_file(asset_path) != str(row.get("sha256") or ""):
                    errors.append(
                        f"{bundle_path}: {collection} asset hash drifted: {row.get('path')}"
                    )
        if operation_plan is not None and "abilities" in bundle:
            bundled_abilities = {
                str(row.get("id") or ""): row for row in bundle_rows["abilities"]
            }
            planned_abilities = {
                str(ability_id): str(operation.get("role") or "")
                for operation in operation_plan.get("operations", [])
                if isinstance(operation, Mapping)
                for ability_id in operation.get("atomic_ordering", [])
            }
            if set(bundled_abilities) != set(planned_abilities):
                errors.append(
                    f"{bundle_path}: bundled abilities differ from Operation atomic_ordering"
                )
            for ability_id, role in planned_abilities.items():
                row = bundled_abilities.get(ability_id, {})
                if row and str(row.get("role") or "") != role:
                    errors.append(
                        f"{bundle_path}: ability {ability_id} has the wrong Operation role"
                    )
            bundled_adversaries = {
                str(row.get("id") or ""): row
                for row in bundle_rows.get("adversaries", [])
            }
            planned_adversaries = {
                str(operation.get("adversary_id") or ""): operation
                for operation in operation_plan.get("operations", [])
                if isinstance(operation, Mapping)
            }
            if "adversaries" in bundle and set(bundled_adversaries) != set(planned_adversaries):
                errors.append(
                    f"{bundle_path}: bundled adversaries differ from Operation plan"
                )
            for adversary_id, operation in planned_adversaries.items():
                row = bundled_adversaries.get(adversary_id, {})
                if "adversaries" in bundle and row and (
                    str(row.get("operation_role") or "")
                    != str(operation.get("role") or "")
                    or str(row.get("execution_agent_role") or "")
                    != str(operation.get("execution_agent_role") or "")
                ):
                    errors.append(
                        f"{bundle_path}: adversary {adversary_id} role binding drifted"
                    )
            if mapping is not None:
                command_hashes = {
                    str(implementation.get("ability_id") or ""): str(
                        implementation.get("command_sha256") or ""
                    )
                    for step in mapping.get("source_steps", [])
                    if isinstance(step, Mapping)
                    and isinstance((implementation := step.get("implementation")), Mapping)
                    and implementation.get("ability_id")
                }
                for ability_id, expected_hash in command_hashes.items():
                    observed_hash = str(
                        bundled_abilities.get(ability_id, {}).get("command_sha256")
                        or ""
                    )
                    if observed_hash != expected_hash:
                        errors.append(
                            f"{bundle_path}: ability {ability_id} command hash differs from mapping"
                        )


def validate_bench(
    bench_root: str | Path,
    *,
    project_root: str | Path | None = None,
    require_sources: bool = True,
    require_cases: bool = True,
    case_ids: set[str] | None = None,
) -> dict[str, Any]:
    root = Path(bench_root).resolve()
    project = Path(project_root).resolve() if project_root is not None else root.parents[1]
    schemas = load_schemas(root)
    errors: list[str] = []
    warnings: list[str] = []
    source_paths = _source_lock_paths(root)
    if require_sources and not source_paths:
        errors.append("no Bench v4 source locks were found")
    source_locks: dict[str, dict[str, Any]] = {}
    for path in source_paths:
        try:
            source = read_json(path)
        except BenchValidationError as exc:
            errors.append(str(exc))
            continue
        errors.extend(_schema_errors(source, schemas, str(path)))
        source_id = str(source.get("source_id") or "")
        if source_id in source_locks:
            errors.append(f"duplicate source_id {source_id!r}")
        source_locks[source_id] = source
        _validate_source_lock(root, path, source, errors)
    registry_path = root / "source_registry.json"
    if registry_path.is_file():
        registry = read_json(registry_path)
        errors.extend(_schema_errors(registry, schemas, str(registry_path)))
        registry_ids: list[str] = []
        for row in registry.get("sources", []):
            if not isinstance(row, Mapping):
                continue
            registry_ids.append(str(row.get("source_id") or ""))
            try:
                lock_path = _contained(root, row.get("lock_path"), "registry lock_path")
            except BenchValidationError as exc:
                errors.append(f"{registry_path}: {exc}")
                continue
            if sha256_file(lock_path) != str(row.get("lock_sha256") or ""):
                errors.append(f"{registry_path}: source lock hash drifted: {row.get('source_id')}")
                continue
            try:
                locked_source = read_json(lock_path)
            except BenchValidationError as exc:
                errors.append(f"{registry_path}: {exc}")
                continue
            for field in ("source_id", "source_kind", "dataset_stratum"):
                if str(row.get(field) or "") != str(locked_source.get(field) or ""):
                    errors.append(
                        f"{registry_path}: registry {field} differs from "
                        f"the referenced source lock: {row.get('source_id')}"
                    )
        if len(registry_ids) != len(set(registry_ids)):
            errors.append("source_registry source_id values must be unique")
        if set(registry_ids) != set(source_locks):
            errors.append("source_registry membership differs from discovered source locks")
    elif source_paths:
        warnings.append("source_registry.json is absent; individual locks were still validated")
    case_paths = _case_paths(root)
    if case_ids is not None:
        selected_case_ids = set(case_ids)
        filtered_case_paths: list[Path] = []
        for candidate_path in case_paths:
            try:
                candidate_case = read_json(candidate_path)
            except BenchValidationError as exc:
                errors.append(str(exc))
                continue
            if str(candidate_case.get("case_id") or "") in selected_case_ids:
                filtered_case_paths.append(candidate_path)
        case_paths = filtered_case_paths
    if require_cases and not case_paths:
        errors.append("no Bench v4 case definitions were found")
    for case_path in case_paths:
        try:
            case = read_json(case_path)
        except BenchValidationError as exc:
            errors.append(str(exc))
            continue
        errors.extend(_schema_errors(case, schemas, str(case_path)))
        _validate_case_cross_contracts(
            root, case_path, case, source_locks, schemas, errors
        )
    admissions_root = root / "admissions"
    if admissions_root.is_dir():
        for receipt_path in sorted(admissions_root.glob("*.admission.json")):
            try:
                receipt = read_json(receipt_path)
                errors.extend(_schema_errors(receipt, schemas, str(receipt_path)))
                validate_admission_receipt(project, root, receipt)
            except (AdmissionError, BenchValidationError) as exc:
                errors.append(f"{receipt_path}: {exc}")
    return {
        "schema_version": "c2trace.bench.validation.v4",
        "valid": not errors,
        "counts": {
            "schemas": len(schemas),
            "sources": len(source_locks),
            "cases": len(case_paths),
            "admissions": len(list(admissions_root.glob("*.admission.json")))
            if admissions_root.is_dir()
            else 0,
            "errors": len(errors),
            "warnings": len(warnings),
        },
        "errors": errors,
        "warnings": warnings,
    }


def require_valid_bench(*args: Any, **kwargs: Any) -> dict[str, Any]:
    report = validate_bench(*args, **kwargs)
    if not report["valid"]:
        raise BenchValidationError("; ".join(report["errors"]))
    return report


__all__ = [
    "BenchValidationError",
    "load_schemas",
    "read_json",
    "require_valid_bench",
    "sha256_file",
    "validate_bench",
]
