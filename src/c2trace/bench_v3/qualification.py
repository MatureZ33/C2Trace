from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping


ADMISSION_SCHEMA = "c2trace.bench.admission.v1"
VALID_TRIAL_CLASSES = frozenset(
    {"evaluation_valid_pass", "evaluation_valid_fail"}
)
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REQUIRED_TRIAL_JSON = (
    "post_bootstrap_target_identity_gate.json",
    "pre_response_gate.json",
    "after_dryrun_gate.json",
    "caldera_bootstrap_report.json",
    "caldera_scenario_report.json",
    "protected_processes.json",
    "suricata_event.json",
    "suricata_artifact.json",
    "scoring_casefile.json",
    "ground_truth.json",
    "score.json",
)
_REQUIRED_TRIAL_FILES = (
    *_REQUIRED_TRIAL_JSON,
    "evidence/post_bootstrap_target_identity.json",
    "evidence/before_response.json",
    "evidence/after_dryrun.json",
    "caldera_bootstrap_event_logs.json",
    "caldera_scenario_event_logs.json",
)
_BASE_DATASET_FILES = (
    "source_lock.json",
    "cases/{case_id}/case.json",
    "mappings/{case_id}.mapping.json",
    "ground_truth/{case_id}.template.json",
)


class QualificationError(ValueError):
    """Raised when a live qualification cannot support scenario admission."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_admission_receipt(
    project_root: str | Path,
    *,
    batch_id: str,
    case_id: str,
) -> dict[str, Any]:
    """Validate one Smoke trial and bind its qualification evidence immutably.

    Admission is about whether the public-flow projection executed with valid
    Ground Truth and target isolation.  An evaluation-valid C2Trace failure is
    intentionally admissible: excluding it would bias the effectiveness data.
    """

    root = Path(project_root).resolve()
    _require_safe_id(batch_id, "batch_id")
    _require_safe_id(case_id, "case_id")
    bench_root = root / "experiments" / "c2trace_bench_v3"
    batch_root = _contained(root / "results" / "c2trace_bench_v3" / batch_id, root)
    context = _read_json(batch_root / "batch_context.json")
    if str(context.get("batch_id") or "") != batch_id:
        raise QualificationError("batch_context batch_id mismatch")
    if str(context.get("mode") or "").lower() != "smoke":
        raise QualificationError("only a Smoke batch can qualify a scenario")
    if str(context.get("status") or "") != "completed":
        raise QualificationError("qualification batch must be completed")

    candidates = [
        item
        for item in context.get("trials", [])
        if isinstance(item, Mapping) and str(item.get("case_id") or "") == case_id
    ]
    if len(candidates) != 1:
        raise QualificationError(
            f"qualification requires exactly one {case_id} trial; found {len(candidates)}"
        )
    trial = dict(candidates[0])
    trial_class = str(trial.get("trial_class") or "")
    if trial_class not in VALID_TRIAL_CLASSES:
        raise QualificationError(
            "scenario admission requires an evaluation-valid trial, not an infrastructure-invalid attempt"
        )
    trial_id = str(trial.get("trial_id") or trial.get("run_id") or "")
    _require_safe_id(trial_id, "trial_id")
    trial_root = _resolve_trial_root(batch_root, trial, case_id)
    expected_trial_root = _contained(batch_root / case_id / trial_id, batch_root)
    if trial_root != expected_trial_root:
        raise QualificationError(
            "qualification result_root is not the registered case/trial directory"
        )

    software_lock_path = batch_root / "software_lock.json"
    software_lock = _read_json(software_lock_path)
    _validate_software_lock_files(root, software_lock)
    snapshot_id = str(
        software_lock.get("experiment_configuration", {}).get("vm_snapshot_id")
        if isinstance(software_lock.get("experiment_configuration"), Mapping)
        else ""
    ).strip()
    if not snapshot_id:
        raise QualificationError("software_lock has no VM snapshot identity")
    source_lock = _read_json(bench_root / "source_lock.json")
    locked_commit = str(source_lock.get("commit") or "")
    observed_commit = str(
        software_lock.get("attack_flow", {}).get("commit")
        if isinstance(software_lock.get("attack_flow"), Mapping)
        else ""
    )
    if not locked_commit or observed_commit != locked_commit:
        raise QualificationError("software_lock Attack Flow commit mismatch")

    install_receipt_path = batch_root / "caldera_install_receipt.json"
    install_receipt = _read_json(install_receipt_path)
    bundle_root, bundle_receipt = _validate_caldera_install_receipt(
        bench_root=bench_root,
        receipt=install_receipt,
        case_id=case_id,
        locked_commit=locked_commit,
    )

    parsed: dict[str, dict[str, Any]] = {}
    for relative in _REQUIRED_TRIAL_JSON:
        parsed[relative] = _read_json(trial_root / relative)
    for gate_name in (
        "post_bootstrap_target_identity_gate.json",
        "pre_response_gate.json",
        "after_dryrun_gate.json",
    ):
        if parsed[gate_name].get("passed") is not True:
            raise QualificationError(f"qualification gate did not pass: {gate_name}")

    protected = parsed["protected_processes.json"]
    if str(protected.get("schema_version") or "") != "c2trace.protected_processes.v1":
        raise QualificationError("protected-process manifest schema mismatch")
    expected_target = (
        protected.get("expected_target")
        if isinstance(protected.get("expected_target"), Mapping)
        else {}
    )
    protected_rows = [
        item for item in protected.get("processes", []) if isinstance(item, Mapping)
    ]
    if len(protected_rows) != 1:
        raise QualificationError("qualification requires exactly one protected control process")
    if int(expected_target.get("pid") or 0) <= 0 or int(
        expected_target.get("pid") or 0
    ) == int(protected_rows[0].get("pid") or 0):
        raise QualificationError("target Manx PID is absent or equals the control Sandcat PID")
    if str(expected_target.get("paw") or "") == str(protected_rows[0].get("paw") or ""):
        raise QualificationError("target Manx PAW equals the control Sandcat PAW")
    if str(expected_target.get("contact") or "").lower() != "tcp":
        raise QualificationError("qualified target is not a TCP Manx")

    ground_truth = parsed["ground_truth.json"]
    if str(ground_truth.get("case_id") or "") != case_id:
        raise QualificationError("Ground Truth case_id mismatch")
    if str(ground_truth.get("trial_class") or "") != trial_class:
        raise QualificationError("Ground Truth trial_class mismatch")
    mandatory = [
        item
        for item in ground_truth.get("ability_instances", [])
        if isinstance(item, Mapping)
        and item.get("attack_mapped") is True
        and item.get("mandatory") is True
    ]
    if not mandatory or any(item.get("executed") is not True for item in mandatory):
        raise QualificationError("not all attack-mapped mandatory abilities executed")
    for item in ground_truth.get("ability_instances", []):
        if not isinstance(item, Mapping) or item.get("executed") is not True:
            continue
        if not str(item.get("operation_id") or "") or not str(item.get("link_id") or ""):
            raise QualificationError("executed ability instance lacks operation/link identity")

    score = parsed["score.json"]
    if str(score.get("trial_class") or "") != trial_class:
        raise QualificationError("score trial_class mismatch")
    scoring_case = parsed["scoring_casefile.json"]
    if str(scoring_case.get("case_id") or "") != trial_id:
        raise QualificationError("scoring CaseFile trial identity mismatch")
    if str(scoring_case.get("trial_class") or "") != trial_class:
        raise QualificationError("scoring CaseFile trial_class mismatch")
    scoring_sources = (
        scoring_case.get("benchmark_scoring_sources")
        if isinstance(scoring_case.get("benchmark_scoring_sources"), Mapping)
        else {}
    )
    if str(scoring_sources.get("investigation") or "") != "dry_run":
        raise QualificationError(
            "qualification scoring findings are not frozen from dry-run"
        )
    if str(scoring_sources.get("response") or "") not in {
        "execute",
        "not_executed",
    }:
        raise QualificationError("qualification scoring response source is invalid")
    if str(score.get("case_id") or "") != trial_id:
        raise QualificationError("score trial identity mismatch")
    artifact = parsed["suricata_artifact.json"]
    event_digest = str(artifact.get("event_sha256") or "").lower()
    if len(event_digest) != 64 or any(ch not in "0123456789abcdef" for ch in event_digest):
        raise QualificationError("Suricata event digest is missing or invalid")

    evidence_hashes = {
        relative: sha256_file(_required_file(trial_root / relative))
        for relative in _REQUIRED_TRIAL_FILES
    }
    dataset_hashes: dict[str, str] = {}
    for template in _BASE_DATASET_FILES:
        relative = template.format(case_id=case_id)
        dataset_hashes[relative] = sha256_file(_required_file(bench_root / relative))
    for path in _bundle_dataset_files(bundle_root):
        relative = path.relative_to(bench_root).as_posix()
        dataset_hashes[relative] = sha256_file(_required_file(path))

    install_receipt_sha256 = sha256_file(install_receipt_path)

    receipt_material = {
        "case_id": case_id,
        "batch_id": batch_id,
        "trial_id": trial_id,
        "trial_class": trial_class,
        "attack_flow_commit": locked_commit,
        "software_lock_sha256": sha256_file(software_lock_path),
        "caldera_install_receipt_sha256": install_receipt_sha256,
        "evidence_hashes": evidence_hashes,
        "dataset_hashes": dataset_hashes,
    }
    admission_id = _admission_id(receipt_material)
    return {
        "schema_version": ADMISSION_SCHEMA,
        "admission_id": admission_id,
        "status": "admitted",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "case_id": case_id,
        "source_claim": "scope-complete single-Windows-endpoint projection",
        "qualification": {
            "batch_id": batch_id,
            "trial_id": receipt_material["trial_id"],
            "trial_class": trial_class,
            "result_root": trial_root.relative_to(root).as_posix(),
            "policy": (
                "CALDERA/target/evidence qualification is independent of the C2Trace effect outcome; "
                "both evaluation-valid pass and fail are admissible"
            ),
        },
        "attack_flow": {"commit": locked_commit},
        "vm_snapshot_id": snapshot_id,
        "software_lock": {
            "path": software_lock_path.relative_to(root).as_posix(),
            "sha256": receipt_material["software_lock_sha256"],
        },
        "caldera_install_receipt": {
            "path": install_receipt_path.relative_to(root).as_posix(),
            "sha256": install_receipt_sha256,
            "bundle_root": bundle_root.relative_to(bench_root).as_posix() or ".",
            "manifest_sha256": str(bundle_receipt.get("manifest_sha256") or ""),
        },
        "dataset_hashes": dataset_hashes,
        "evidence_hashes": evidence_hashes,
        "c2trace_outcome": {
            "trial_class": trial_class,
            "metrics": score.get("metrics") if isinstance(score.get("metrics"), Mapping) else {},
        },
    }


def validate_admission_receipt(
    project_root: str | Path,
    receipt: Mapping[str, Any] | str | Path,
) -> dict[str, Any]:
    """Fail closed if an admission no longer matches its dataset or evidence."""

    root = Path(project_root).resolve()
    payload = _read_json(Path(receipt)) if isinstance(receipt, (str, Path)) else dict(receipt)
    if str(payload.get("schema_version") or "") != ADMISSION_SCHEMA:
        raise QualificationError("admission receipt schema mismatch")
    if str(payload.get("status") or "") != "admitted":
        raise QualificationError("admission receipt is not admitted")
    case_id = str(payload.get("case_id") or "")
    _require_safe_id(case_id, "case_id")
    bench_root = root / "experiments" / "c2trace_bench_v3"
    source_lock = _read_json(bench_root / "source_lock.json")
    attack_flow = (
        payload.get("attack_flow")
        if isinstance(payload.get("attack_flow"), Mapping)
        else {}
    )
    locked_commit = str(source_lock.get("commit") or "")
    if str(attack_flow.get("commit") or "") != locked_commit:
        raise QualificationError("admission Attack Flow commit drifted")
    _validate_hash_mapping(bench_root, payload.get("dataset_hashes"), "dataset")
    qualification = (
        payload.get("qualification")
        if isinstance(payload.get("qualification"), Mapping)
        else {}
    )
    trial_root = _contained(root / str(qualification.get("result_root") or ""), root)
    _validate_hash_mapping(trial_root, payload.get("evidence_hashes"), "evidence")
    software = (
        payload.get("software_lock")
        if isinstance(payload.get("software_lock"), Mapping)
        else {}
    )
    software_path = _contained(root / str(software.get("path") or ""), root)
    if sha256_file(_required_file(software_path)) != str(software.get("sha256") or ""):
        raise QualificationError("admission software lock drifted")
    software_lock = _read_json(software_path)
    _validate_software_lock_files(root, software_lock)
    software_attack_flow = (
        software_lock.get("attack_flow")
        if isinstance(software_lock.get("attack_flow"), Mapping)
        else {}
    )
    if str(software_attack_flow.get("commit") or "") != locked_commit:
        raise QualificationError("admission software lock Attack Flow commit drifted")
    experiment_configuration = (
        software_lock.get("experiment_configuration")
        if isinstance(software_lock.get("experiment_configuration"), Mapping)
        else {}
    )
    snapshot_id = str(experiment_configuration.get("vm_snapshot_id") or "").strip()
    if not snapshot_id or str(payload.get("vm_snapshot_id") or "") != snapshot_id:
        raise QualificationError("admission VM snapshot identity drifted")

    install_binding = (
        payload.get("caldera_install_receipt")
        if isinstance(payload.get("caldera_install_receipt"), Mapping)
        else {}
    )
    install_path = _contained(root / str(install_binding.get("path") or ""), root)
    install_sha256 = str(install_binding.get("sha256") or "")
    if sha256_file(_required_file(install_path)) != install_sha256:
        raise QualificationError("admission CALDERA install receipt drifted")
    install_receipt = _read_json(install_path)
    bundle_root, bundle_receipt = _validate_caldera_install_receipt(
        bench_root=bench_root,
        receipt=install_receipt,
        case_id=case_id,
        locked_commit=locked_commit,
    )
    expected_bundle_relative = bundle_root.relative_to(bench_root).as_posix() or "."
    if str(install_binding.get("bundle_root") or "") != expected_bundle_relative:
        raise QualificationError("admission CALDERA bundle root drifted")
    if str(install_binding.get("manifest_sha256") or "") != str(
        bundle_receipt.get("manifest_sha256") or ""
    ):
        raise QualificationError("admission CALDERA bundle manifest drifted")

    batch_id = str(qualification.get("batch_id") or "")
    trial_id = str(qualification.get("trial_id") or "")
    trial_class = str(qualification.get("trial_class") or "")
    _require_safe_id(batch_id, "qualification.batch_id")
    _require_safe_id(trial_id, "qualification.trial_id")
    if trial_class not in VALID_TRIAL_CLASSES:
        raise QualificationError("admission trial class is not evaluation-valid")
    outcome = (
        payload.get("c2trace_outcome")
        if isinstance(payload.get("c2trace_outcome"), Mapping)
        else {}
    )
    if str(outcome.get("trial_class") or "") != trial_class:
        raise QualificationError("admission C2Trace outcome class drifted")
    frozen_score = _read_json(trial_root / "score.json")
    if str(frozen_score.get("trial_class") or "") != trial_class:
        raise QualificationError("admission frozen score class drifted")
    frozen_metrics = (
        frozen_score.get("metrics")
        if isinstance(frozen_score.get("metrics"), Mapping)
        else {}
    )
    outcome_metrics = (
        outcome.get("metrics") if isinstance(outcome.get("metrics"), Mapping) else {}
    )
    if dict(outcome_metrics) != dict(frozen_metrics):
        raise QualificationError("admission C2Trace outcome metrics drifted")
    receipt_material = {
        "case_id": case_id,
        "batch_id": batch_id,
        "trial_id": trial_id,
        "trial_class": trial_class,
        "attack_flow_commit": locked_commit,
        "software_lock_sha256": str(software.get("sha256") or ""),
        "caldera_install_receipt_sha256": install_sha256,
        "evidence_hashes": dict(payload.get("evidence_hashes") or {}),
        "dataset_hashes": dict(payload.get("dataset_hashes") or {}),
    }
    if str(payload.get("admission_id") or "") != _admission_id(receipt_material):
        raise QualificationError("admission receipt identity drifted")
    return payload


def write_admission_receipt(
    project_root: str | Path,
    receipt: Mapping[str, Any],
    *,
    output_path: str | Path | None = None,
) -> Path:
    root = Path(project_root).resolve()
    validated = validate_admission_receipt(root, receipt)
    case_id = str(validated["case_id"])
    if output_path is not None:
        requested = Path(output_path)
        target = (requested if requested.is_absolute() else root / requested).resolve()
    else:
        target = (
            root
            / "experiments"
            / "c2trace_bench_v3"
            / "admissions"
            / f"{case_id}.admission.json"
        )
    _contained(target, root)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        existing = validate_admission_receipt(root, target)
        if str(existing.get("admission_id") or "") != str(
            validated.get("admission_id") or ""
        ):
            raise QualificationError(
                "refusing to overwrite an immutable admission receipt"
            )
        return target
    target.write_text(
        json.dumps(validated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return target


def admission_path(project_root: str | Path, case_id: str) -> Path:
    _require_safe_id(case_id, "case_id")
    return (
        Path(project_root).resolve()
        / "experiments"
        / "c2trace_bench_v3"
        / "admissions"
        / f"{case_id}.admission.json"
    )


def _resolve_trial_root(
    batch_root: Path, trial: Mapping[str, Any], case_id: str
) -> Path:
    raw = str(trial.get("result_root") or "").strip()
    candidate = Path(raw) if raw else batch_root / case_id / str(trial.get("trial_id") or "")
    if not candidate.is_absolute():
        candidate = batch_root / candidate
    return _contained(candidate, batch_root)


def _expected_bundle_root(bench_root: Path, case_id: str) -> Path:
    case_bundle = bench_root / "caldera" / "cases" / case_id
    if (case_bundle / "deployment_manifest.json").is_file():
        return case_bundle.resolve()
    return (bench_root / "caldera").resolve()


def _bundle_dataset_files(bundle_root: Path) -> list[Path]:
    selected = [bundle_root / "deployment_manifest.json"]
    for directory in ("abilities", "adversaries", "sources"):
        root = bundle_root / directory
        if root.is_dir():
            selected.extend(
                path
                for path in sorted(root.rglob("*"))
                if path.is_file() and path.suffix.lower() in {".json", ".yaml", ".yml"}
            )
    return selected


def _validate_caldera_install_receipt(
    *,
    bench_root: Path,
    receipt: Mapping[str, Any],
    case_id: str,
    locked_commit: str,
) -> tuple[Path, Mapping[str, Any]]:
    if str(receipt.get("schema_version") or "") != "c2trace.bench.caldera_install.v3":
        raise QualificationError("CALDERA install receipt schema mismatch")
    rows = [
        row
        for row in receipt.get("bundles", [])
        if isinstance(row, Mapping) and str(row.get("case_id") or "") == case_id
    ]
    if len(rows) != 1:
        raise QualificationError(
            f"CALDERA install receipt requires exactly one bundle for {case_id}"
        )
    row = rows[0]
    bundle_root = _expected_bundle_root(bench_root, case_id)
    observed_root = Path(str(row.get("bundle_root") or ""))
    if not observed_root.is_absolute():
        observed_root = bench_root / observed_root
    if _contained(observed_root, bench_root) != bundle_root:
        raise QualificationError("CALDERA install receipt bundle root mismatch")
    manifest = _read_json(bundle_root / "deployment_manifest.json")
    if str(manifest.get("case_id") or "") != case_id:
        raise QualificationError("CALDERA bundle manifest case_id mismatch")
    if str(manifest.get("source_commit") or "") != locked_commit:
        raise QualificationError("CALDERA bundle source commit mismatch")
    manifest_sha256 = sha256_file(bundle_root / "deployment_manifest.json")
    if str(row.get("manifest_sha256") or "") != manifest_sha256:
        raise QualificationError("CALDERA install receipt manifest hash mismatch")
    if str(row.get("source_commit") or "") != locked_commit:
        raise QualificationError("CALDERA install receipt source commit mismatch")
    return bundle_root, row


def _validate_hash_mapping(base: Path, value: Any, label: str) -> None:
    if not isinstance(value, Mapping) or not value:
        raise QualificationError(f"admission has no {label} hash mapping")
    for relative, expected in value.items():
        path = _contained(base / str(relative), base)
        if sha256_file(_required_file(path)) != str(expected or ""):
            raise QualificationError(f"admission {label} evidence drifted: {relative}")


def _validate_software_lock_files(root: Path, software_lock: Mapping[str, Any]) -> None:
    rows = software_lock.get("files")
    if not isinstance(rows, list) or not rows:
        raise QualificationError("software_lock has no frozen file inventory")
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise QualificationError(f"software_lock file row #{index + 1} is invalid")
        relative = str(row.get("path") or "")
        path = _contained(root / relative, root)
        expected = str(row.get("sha256") or "")
        if sha256_file(_required_file(path)) != expected:
            raise QualificationError(f"software_lock file drifted: {relative}")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise QualificationError(f"unable to read JSON {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise QualificationError(f"JSON root must be an object: {path}")
    return payload


def _required_file(path: Path) -> Path:
    if not path.is_file():
        raise QualificationError(f"required qualification artifact is missing: {path}")
    return path


def _contained(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise QualificationError(f"qualification path escapes its root: {resolved}") from exc
    return resolved


def _require_safe_id(value: str, label: str) -> None:
    if not _SAFE_ID.fullmatch(str(value or "")):
        raise QualificationError(f"{label} is not a path-safe identifier")


def _admission_id(material: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            dict(material), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
