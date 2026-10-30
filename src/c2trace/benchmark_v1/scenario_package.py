from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


SCHEMA_VERSION = "c2trace.benchmark.v1.scenario_package"
REQUIRED_CONTRACT_ROLES = (
    "source",
    "fidelity",
    "ir",
    "dossier",
    "paper_description",
    "runtime_manifest",
)
REQUIRED_COMPONENT_ROLES = (
    "backend",
    "sensor",
    "oracle",
    "reference_response",
    "offline_test",
    "paper_description",
    "runtime_manifest",
)
OFFLINE_READINESS_GATES = (
    "static_contract",
    "implementation",
    "sensor",
    "oracle",
    "reference_response",
    "offline_tests",
    "software_lock_gate",
)


@dataclass(frozen=True)
class ScenarioFileRef:
    path: str
    sha256: str
    size: int

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ScenarioFileRef":
        return cls(
            path=str(value["path"]),
            sha256=str(value["sha256"]),
            size=int(value["size"]),
        )


@dataclass(frozen=True)
class ScenarioPackage:
    root_id: str
    title: str
    package_status: str
    offline_ready: bool
    source_root_status: str
    contracts: Mapping[str, ScenarioFileRef]
    components: Mapping[str, tuple[ScenarioFileRef, ...]]
    runtime_constraints: Mapping[str, Any]
    readiness: Mapping[str, Any]
    live_actions_performed: bool
    schema_version: str = SCHEMA_VERSION

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ScenarioPackage":
        return cls(
            root_id=str(value["root_id"]),
            title=str(value["title"]),
            package_status=str(value["package_status"]),
            offline_ready=bool(value["offline_ready"]),
            source_root_status=str(value["source_root_status"]),
            contracts={
                str(role): ScenarioFileRef.from_dict(row)
                for role, row in value.get("contracts", {}).items()
            },
            components={
                str(role): tuple(ScenarioFileRef.from_dict(row) for row in rows)
                for role, rows in value.get("components", {}).items()
            },
            runtime_constraints=dict(value.get("runtime_constraints", {})),
            readiness=dict(value.get("readiness", {})),
            live_actions_performed=bool(value.get("live_actions_performed", False)),
            schema_version=str(value.get("schema_version", SCHEMA_VERSION)),
        )


def load_scenario_package(path: str | Path) -> ScenarioPackage:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("scenario package must be a JSON object")
    return ScenarioPackage.from_dict(value)


def _is_safe_relative_path(value: str) -> bool:
    path = Path(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts


def _validate_ref(
    role: str,
    ref: ScenarioFileRef,
    *,
    project_root: Path,
) -> list[str]:
    errors: list[str] = []
    if not _is_safe_relative_path(ref.path):
        return [f"{role} path must be project-relative without traversal: {ref.path}"]
    path = project_root / ref.path
    if not path.is_file():
        return [f"{role} file is missing: {ref.path}"]
    data = path.read_bytes()
    observed = hashlib.sha256(data).hexdigest()
    if observed != ref.sha256:
        errors.append(f"{role} SHA-256 drift: {ref.path}")
    if len(data) != ref.size:
        errors.append(f"{role} size drift: {ref.path}")
    return errors


def validate_scenario_package(
    package: ScenarioPackage,
    *,
    package_path: str | Path,
    project_root: str | Path,
) -> list[str]:
    project = Path(project_root).resolve()
    path = Path(package_path).resolve()
    errors: list[str] = []
    if package.schema_version != SCHEMA_VERSION:
        errors.append(f"unexpected schema version: {package.schema_version}")
    if path.name != "scenario.json" or path.parent.name != package.root_id:
        errors.append("scenario.json must reside in scenarios/<root_id>/")
    if package.package_status not in {"offline_ready", "offline_incomplete"}:
        errors.append(f"invalid package_status: {package.package_status}")
    if package.live_actions_performed:
        errors.append("offline scenario package cannot report live actions")
    missing_contracts = set(REQUIRED_CONTRACT_ROLES) - set(package.contracts)
    if missing_contracts:
        errors.append("missing contract roles: " + ", ".join(sorted(missing_contracts)))
    missing_components = set(REQUIRED_COMPONENT_ROLES) - {
        role for role, rows in package.components.items() if rows
    }
    if missing_components:
        errors.append("missing component roles: " + ", ".join(sorted(missing_components)))
    for role, ref in package.contracts.items():
        errors.extend(_validate_ref(f"contract:{role}", ref, project_root=project))
    for role, rows in package.components.items():
        for index, ref in enumerate(rows):
            errors.extend(_validate_ref(f"component:{role}[{index}]", ref, project_root=project))
    for gate in OFFLINE_READINESS_GATES:
        if not isinstance(package.readiness.get(gate), bool):
            errors.append(f"readiness gate must be boolean: {gate}")
    repetitions = package.readiness.get("qualification_repetitions")
    if not isinstance(repetitions, int) or repetitions < 0:
        errors.append("qualification_repetitions must be a non-negative integer")
    unlocked = package.readiness.get("episode_generation_unlocked")
    if not isinstance(unlocked, bool):
        errors.append("episode_generation_unlocked must be boolean")
    gates_pass = all(package.readiness.get(gate) is True for gate in OFFLINE_READINESS_GATES)
    if package.offline_ready != gates_pass:
        errors.append("offline_ready must equal the conjunction of all offline readiness gates")
    expected_status = "offline_ready" if package.offline_ready else "offline_incomplete"
    if package.package_status != expected_status:
        errors.append("package_status does not match offline_ready")
    if package.source_root_status != "admitted" and unlocked is True:
        errors.append("Episode generation cannot unlock before root admission")
    constraints = package.runtime_constraints
    if constraints.get("private_network_only") is not True:
        errors.append("runtime must be private-network-only")
    if constraints.get("arbitrary_command_execution") is not False:
        errors.append("runtime must reject arbitrary command execution")
    if constraints.get("overwrite_existing_evidence") is not False:
        errors.append("runtime must reject evidence overwrite")
    if constraints.get("automatic_retry") is not False:
        errors.append("runtime must forbid automatic retry")
    return errors
