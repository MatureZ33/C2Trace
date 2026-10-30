from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .io import load_fidelity_receipt, load_scenario_ir, load_source_root, read_json
from .validation import (
    REQUIRED_QUALIFICATION_CHECKS,
    validate_fidelity_receipt,
    validate_scenario_ir,
    validate_source_artifacts,
    validate_source_root,
)


ROOT_ID = "CTID-WEBSHELL-001"
ATTESTATION_NAME = "C2TRACE_EVIDENCE_ROOT_ATTESTATION.json"


class QualificationPreflightError(RuntimeError):
    pass


def build_static_qualification_gate(
    project_root: str | Path,
    *,
    root_id: str = ROOT_ID,
) -> dict[str, Any]:
    project = Path(project_root).resolve()
    if not root_id or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        for character in root_id
    ):
        raise QualificationPreflightError("root_id is not a safe Benchmark identifier")
    bench = project / "experiments" / "c2trace_benchmark_v1"
    source = load_source_root(bench / "sources" / f"{root_id}.json")
    fidelity = load_fidelity_receipt(bench / "fidelity" / f"{root_id}.json")
    scenario = load_scenario_ir(bench / "ir" / f"{root_id}.json")

    source_errors = validate_source_root(source) + validate_source_artifacts(source, project)
    fidelity_errors = validate_fidelity_receipt(fidelity, root=source)
    scenario_errors = validate_scenario_ir(scenario, root=source, fidelity=fidelity)
    critical = [row for row in fidelity.mappings if row.critical]
    core_complete = (
        fidelity.status == "accepted"
        and fidelity.core_step_coverage == 1.0
        and bool(critical)
        and not fidelity_errors
        and not scenario_errors
    )
    checks = {name: False for name in REQUIRED_QUALIFICATION_CHECKS}
    checks.update(
        {
            "source_locked": not source_errors,
            "license_recorded": bool(source.license.strip()),
            "fidelity_receipt_valid": not fidelity_errors,
            "core_steps_fully_mapped": core_complete,
        }
    )
    errors = {
        "source": source_errors,
        "fidelity": fidelity_errors,
        "scenario_ir": scenario_errors,
    }
    return {
        "schema_version": "c2trace.benchmark.v1.static_qualification_gate",
        "root_id": root_id,
        "checks": checks,
        "passed": all(
            checks[name]
            for name in (
                "source_locked",
                "license_recorded",
                "fidelity_receipt_valid",
                "core_steps_fully_mapped",
            )
        ),
        "errors": errors,
        "source_version": source.version,
        "license": source.license,
        "fidelity_receipt_id": fidelity.receipt_id,
        "core_step_coverage": fidelity.core_step_coverage,
        "c2trace_used": False,
        "llm_used": False,
        "live_actions_performed": False,
    }


def validate_external_evidence_root(
    project_root: str | Path,
    evidence_root: str | Path,
) -> dict[str, Any]:
    project = Path(project_root).resolve()
    requested = Path(evidence_root)
    if not requested.is_absolute():
        raise QualificationPreflightError("EvidenceRoot must be an absolute path")
    root = requested.resolve()
    if not root.is_dir():
        raise QualificationPreflightError("EvidenceRoot must already exist as a directory")
    try:
        root.relative_to(project)
    except ValueError:
        pass
    else:
        raise QualificationPreflightError(
            "EvidenceRoot is inside the VM project tree and may be lost on snapshot restore"
        )
    attestation_path = root / ATTESTATION_NAME
    if not attestation_path.is_file():
        raise QualificationPreflightError(
            f"EvidenceRoot attestation is missing: {attestation_path}"
        )
    attestation = read_json(attestation_path)
    expected_schema = "c2trace.benchmark.v1.external_evidence_root_attestation"
    if attestation.get("schema_version") != expected_schema:
        raise QualificationPreflightError("EvidenceRoot attestation schema is invalid")
    if Path(str(attestation.get("evidence_root") or "")).resolve() != root:
        raise QualificationPreflightError("EvidenceRoot attestation path differs from the requested root")
    if attestation.get("survives_vm_snapshot_restore") is not True:
        raise QualificationPreflightError("EvidenceRoot is not attested as snapshot-persistent")
    if attestation.get("operator_attested") is not True:
        raise QualificationPreflightError("EvidenceRoot lacks explicit operator attestation")
    storage_type = str(attestation.get("storage_type") or "")
    if storage_type not in {"vmware_shared_folder", "host_mounted_volume"}:
        raise QualificationPreflightError("EvidenceRoot storage_type is not an allowed host-backed type")
    return {
        "schema_version": "c2trace.benchmark.v1.external_evidence_root_validation",
        "evidence_root": str(root),
        "attestation_path": str(attestation_path.resolve()),
        "storage_type": storage_type,
        "survives_vm_snapshot_restore": True,
        "operator_attested": True,
        "writable_check_deferred_to_administrator_preflight": True,
        "valid": True,
        "live_actions_performed": False,
    }


__all__ = [
    "ATTESTATION_NAME",
    "QualificationPreflightError",
    "build_static_qualification_gate",
    "validate_external_evidence_root",
]
