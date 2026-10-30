from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from .contracts import DATASET_STRATA, SHA256_RE


class AdmissionError(ValueError):
    """Raised when a v4 dependency lock or admission binding has drifted."""


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AdmissionError(f"unable to read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AdmissionError(f"JSON root must be an object: {path}")
    return value


def _contained(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise AdmissionError(f"dependency path escapes its root: {path}") from exc
    return resolved


def _bench_file(bench_root: Path, relative: Any, label: str) -> Path:
    raw = str(relative or "").strip()
    if not raw or Path(raw).is_absolute():
        raise AdmissionError(f"{label} must be a non-empty Bench-relative path")
    path = _contained(bench_root / raw, bench_root)
    if not path.is_file():
        raise AdmissionError(f"{label} is missing: {path}")
    return path


def dependency_paths(bench_root: str | Path, case_path: str | Path) -> list[Path]:
    """Return the exact static files on which one case admission depends."""

    root = Path(bench_root).resolve()
    requested = Path(case_path)
    case_file = _contained(requested if requested.is_absolute() else root / requested, root)
    if not case_file.is_file():
        raise AdmissionError(f"case file is missing: {case_file}")
    case = _read_json(case_file)
    selected: set[Path] = {case_file}
    source = case.get("source") if isinstance(case.get("source"), Mapping) else {}
    for field in ("source_lock", "artifact_path"):
        selected.add(_bench_file(root, source.get(field), f"source.{field}"))
    contracts = (
        case.get("contracts") if isinstance(case.get("contracts"), Mapping) else {}
    )
    for field in (
        "mapping",
        "ground_truth",
        "target_profile",
        "operation_plan",
        "evidence_plan",
        "cleanup_plan",
        "caldera_bundle",
    ):
        selected.add(_bench_file(root, contracts.get(field), f"contracts.{field}"))
    bundle_path = _bench_file(
        root, contracts.get("caldera_bundle"), "contracts.caldera_bundle"
    )
    bundle = _read_json(bundle_path)
    for collection in ("abilities", "adversaries", "sources", "payloads"):
        rows = bundle.get(collection, [])
        if not isinstance(rows, list):
            raise AdmissionError(f"CALDERA bundle {collection} must be an array")
        for index, row in enumerate(rows):
            if not isinstance(row, Mapping):
                raise AdmissionError(
                    f"CALDERA bundle {collection}[{index}] must be an object"
                )
            selected.add(
                _bench_file(
                    root,
                    row.get("path"),
                    f"CALDERA bundle {collection}[{index}].path",
                )
            )
    for index, relative in enumerate(case.get("dependency_paths") or []):
        selected.add(_bench_file(root, relative, f"dependency_paths[{index}]"))
    schema_root = root / "schemas"
    if not schema_root.is_dir():
        raise AdmissionError(f"v4 schema directory is missing: {schema_root}")
    selected.update(path.resolve() for path in schema_root.glob("*.schema.json"))
    return sorted(selected, key=lambda item: item.relative_to(root).as_posix())


def build_dependency_lock(
    bench_root: str | Path, case_path: str | Path
) -> dict[str, Any]:
    root = Path(bench_root).resolve()
    requested = Path(case_path)
    case_file = _contained(requested if requested.is_absolute() else root / requested, root)
    case = _read_json(case_file)
    rows: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    for path in dependency_paths(root, case_file):
        relative = path.relative_to(root).as_posix()
        file_hash = sha256_file(path)
        size = path.stat().st_size
        rows.append({"path": relative, "size": size, "sha256": file_hash})
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_hash.encode("ascii"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\n")
    return {
        "schema_version": "c2trace.bench.dependency_lock.v4",
        "case_id": str(case.get("case_id") or ""),
        "dataset_stratum": str(case.get("dataset_stratum") or ""),
        "case_path": case_file.relative_to(root).as_posix(),
        "file_count": len(rows),
        "files": rows,
        "tree_sha256": digest.hexdigest(),
    }


def validate_dependency_lock(
    bench_root: str | Path, lock: Mapping[str, Any]
) -> dict[str, Any]:
    if str(lock.get("schema_version") or "") != "c2trace.bench.dependency_lock.v4":
        raise AdmissionError("dependency lock schema mismatch")
    root = Path(bench_root).resolve()
    case_path = _bench_file(root, lock.get("case_path"), "dependency_lock.case_path")
    observed = build_dependency_lock(root, case_path)
    if dict(lock) != observed:
        raise AdmissionError("case dependency lock drifted")
    return observed


def build_admission_receipt(
    project_root: str | Path,
    bench_root: str | Path,
    case_path: str | Path,
    *,
    trial_class: str,
    qualification_artifacts: Iterable[str | Path],
    vm_snapshot_id: str,
    software_lock_sha256: str,
) -> dict[str, Any]:
    """Bind an evaluation-valid qualification to all static case dependencies."""

    if trial_class not in {"evaluation_valid_pass", "evaluation_valid_fail"}:
        raise AdmissionError("only an evaluation-valid trial can qualify a v4 case")
    snapshot = str(vm_snapshot_id or "").strip()
    if not snapshot:
        raise AdmissionError("vm_snapshot_id is required")
    software_hash = str(software_lock_sha256 or "").lower()
    if not SHA256_RE.fullmatch(software_hash):
        raise AdmissionError("software_lock_sha256 is invalid")
    project = Path(project_root).resolve()
    requested_bench = Path(bench_root)
    bench = _contained(
        requested_bench if requested_bench.is_absolute() else project / requested_bench,
        project,
    )
    lock = build_dependency_lock(bench, case_path)
    if lock["dataset_stratum"] not in DATASET_STRATA:
        raise AdmissionError("case dependency lock has an invalid dataset stratum")
    qualification_hashes: dict[str, str] = {}
    for raw in qualification_artifacts:
        requested = Path(raw)
        path = _contained(
            requested if requested.is_absolute() else project / requested,
            project,
        )
        if not path.is_file():
            raise AdmissionError(f"qualification artifact is missing: {path}")
        relative = path.relative_to(project).as_posix()
        qualification_hashes[relative] = sha256_file(path)
    if not qualification_hashes:
        raise AdmissionError("at least one qualification artifact is required")
    material = {
        "case_id": lock["case_id"],
        "dataset_stratum": lock["dataset_stratum"],
        "trial_class": trial_class,
        "dependency_tree_sha256": lock["tree_sha256"],
        "qualification_hashes": dict(sorted(qualification_hashes.items())),
        "vm_snapshot_id": snapshot,
        "software_lock_sha256": software_hash,
    }
    admission_id = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": "c2trace.bench.admission.v4",
        "admission_id": admission_id,
        "status": "admitted",
        "case_id": lock["case_id"],
        "dataset_stratum": lock["dataset_stratum"],
        "trial_class": trial_class,
        "dependency_lock": lock,
        "qualification_hashes": material["qualification_hashes"],
        "vm_snapshot_id": snapshot,
        "software_lock_sha256": software_hash,
    }


def validate_admission_receipt(
    project_root: str | Path,
    bench_root: str | Path,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    if str(receipt.get("schema_version") or "") != "c2trace.bench.admission.v4":
        raise AdmissionError("admission receipt schema mismatch")
    if str(receipt.get("status") or "") != "admitted":
        raise AdmissionError("admission receipt is not admitted")
    project = Path(project_root).resolve()
    requested_bench = Path(bench_root)
    bench = _contained(
        requested_bench if requested_bench.is_absolute() else project / requested_bench,
        project,
    )
    lock_raw = receipt.get("dependency_lock")
    if not isinstance(lock_raw, Mapping):
        raise AdmissionError("admission receipt has no dependency lock")
    lock = validate_dependency_lock(bench, lock_raw)
    if str(receipt.get("case_id") or "") != str(lock.get("case_id") or ""):
        raise AdmissionError("admission receipt case_id differs from its dependency lock")
    if str(receipt.get("dataset_stratum") or "") != str(
        lock.get("dataset_stratum") or ""
    ):
        raise AdmissionError(
            "admission receipt dataset_stratum differs from its dependency lock"
        )
    trial_class = str(receipt.get("trial_class") or "")
    if trial_class not in {"evaluation_valid_pass", "evaluation_valid_fail"}:
        raise AdmissionError("admission receipt trial_class is not evaluation-valid")
    snapshot = str(receipt.get("vm_snapshot_id") or "").strip()
    if not snapshot:
        raise AdmissionError("admission receipt vm_snapshot_id is empty")
    software_hash = str(receipt.get("software_lock_sha256") or "").lower()
    if not SHA256_RE.fullmatch(software_hash):
        raise AdmissionError("admission receipt software_lock_sha256 is invalid")
    hashes = receipt.get("qualification_hashes")
    if not isinstance(hashes, Mapping) or not hashes:
        raise AdmissionError("admission receipt has no qualification hashes")
    normalized_hashes: dict[str, str] = {}
    for relative, expected in hashes.items():
        path = _contained(project / str(relative), project)
        expected_hash = str(expected or "").lower()
        if not SHA256_RE.fullmatch(expected_hash):
            raise AdmissionError(f"qualification artifact hash is invalid: {relative}")
        if not path.is_file() or sha256_file(path) != expected_hash:
            raise AdmissionError(f"qualification artifact drifted: {relative}")
        normalized_hashes[str(relative)] = expected_hash
    material = {
        "case_id": lock["case_id"],
        "dataset_stratum": lock["dataset_stratum"],
        "trial_class": trial_class,
        "dependency_tree_sha256": lock["tree_sha256"],
        "qualification_hashes": dict(sorted(normalized_hashes.items())),
        "vm_snapshot_id": snapshot,
        "software_lock_sha256": software_hash,
    }
    expected_id = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if str(receipt.get("admission_id") or "") != expected_id:
        raise AdmissionError("admission receipt identity drifted")
    return dict(receipt)


def write_admission_receipt(path: str | Path, receipt: Mapping[str, Any]) -> Path:
    target = Path(path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        existing = _read_json(target)
        if str(existing.get("admission_id") or "") != str(
            receipt.get("admission_id") or ""
        ):
            raise AdmissionError("refusing to overwrite an immutable admission receipt")
        return target
    target.write_text(
        json.dumps(dict(receipt), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return target
