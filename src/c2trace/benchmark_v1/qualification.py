from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence

from .models import QualificationReceipt, content_hash
from .validation import REQUIRED_QUALIFICATION_CHECKS, validate_qualification


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
QUALIFICATION_TRIAL_SCHEMA = "c2trace.benchmark.v1.root_qualification_trial"


def build_qualification_receipt(
    *,
    root_id: str,
    checks: Mapping[str, bool],
    evidence_hashes: Mapping[str, str],
    stable_trial_ids: Iterable[str],
    vm_snapshot_id: str,
    software_lock_sha256: str,
) -> QualificationReceipt:
    normalized_checks = {name: bool(checks.get(name, False)) for name in REQUIRED_QUALIFICATION_CHECKS}
    trial_ids = tuple(dict.fromkeys(str(value) for value in stable_trial_ids if str(value)))
    failed = tuple(name for name, passed in normalized_checks.items() if not passed)
    status = "admitted" if not failed and len(trial_ids) >= 3 else "rejected"
    material = {
        "root_id": root_id,
        "checks": normalized_checks,
        "evidence_hashes": dict(sorted(evidence_hashes.items())),
        "stable_trial_ids": trial_ids,
        "vm_snapshot_id": vm_snapshot_id,
        "software_lock_sha256": software_lock_sha256,
    }
    receipt = QualificationReceipt(
        qualification_id=content_hash(material),
        root_id=root_id,
        status=status,
        checks=normalized_checks,
        evidence_hashes=dict(sorted(evidence_hashes.items())),
        stable_trial_ids=trial_ids,
        vm_snapshot_id=vm_snapshot_id,
        software_lock_sha256=software_lock_sha256,
        reasons=failed + (() if len(trial_ids) >= 3 else ("three_stable_trials_required",)),
    )
    if receipt.status == "admitted":
        errors = validate_qualification(receipt)
        if errors:
            raise ValueError("invalid admission receipt: " + "; ".join(errors))
    return receipt


def hash_evidence(paths: Iterable[str | Path], *, root: str | Path) -> dict[str, str]:
    base = Path(root).resolve()
    hashes: dict[str, str] = {}
    for raw in paths:
        path = Path(raw).resolve()
        try:
            relative = path.relative_to(base).as_posix()
        except ValueError as exc:
            raise ValueError(f"evidence escapes qualification root: {path}") from exc
        if not path.is_file():
            raise ValueError(f"evidence is missing: {path}")
        import hashlib

        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        hashes[relative] = digest.hexdigest()
    return dict(sorted(hashes.items()))


def build_root_qualification_trial(
    *,
    root_id: str,
    trial_id: str,
    run_id: str,
    repetition: int,
    checks: Mapping[str, bool],
    evidence_hashes: Mapping[str, str],
    vm_snapshot_id: str,
    software_lock_sha256: str,
    started_at_utc: str,
    ended_at_utc: str,
    reference_response: Mapping[str, Any],
    poststate: Mapping[str, Any],
    failure_reason: str | None = None,
) -> dict[str, Any]:
    normalized = {
        name: bool(checks.get(name, False)) for name in REQUIRED_QUALIFICATION_CHECKS
    }
    stable = all(normalized.values()) and failure_reason is None
    material = {
        "root_id": root_id,
        "trial_id": trial_id,
        "run_id": run_id,
        "repetition": int(repetition),
        "checks": normalized,
        "evidence_hashes": dict(sorted(evidence_hashes.items())),
        "vm_snapshot_id": vm_snapshot_id,
        "software_lock_sha256": software_lock_sha256.casefold(),
        "started_at_utc": started_at_utc,
        "ended_at_utc": ended_at_utc,
        "reference_response": dict(reference_response),
        "poststate": dict(poststate),
        "failure_reason": failure_reason,
    }
    receipt = {
        "schema_version": QUALIFICATION_TRIAL_SCHEMA,
        **material,
        "receipt_sha256": content_hash(material),
        "stable": stable,
        "automatic_retry": False,
        "c2trace_used": False,
        "llm_used": False,
        "live_actions_performed": bool(reference_response),
    }
    errors = validate_root_qualification_trial(receipt)
    if errors:
        raise ValueError("invalid root qualification Trial: " + "; ".join(errors))
    return receipt


def validate_root_qualification_trial(receipt: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if receipt.get("schema_version") != QUALIFICATION_TRIAL_SCHEMA:
        errors.append("qualification Trial schema_version mismatch")
    if not str(receipt.get("root_id") or ""):
        errors.append("qualification Trial root_id is empty")
    if not str(receipt.get("trial_id") or "") or not str(receipt.get("run_id") or ""):
        errors.append("qualification Trial identifiers are empty")
    if int(receipt.get("repetition") or 0) <= 0:
        errors.append("qualification Trial repetition must be positive")
    checks = receipt.get("checks") if isinstance(receipt.get("checks"), Mapping) else {}
    missing = [name for name in REQUIRED_QUALIFICATION_CHECKS if name not in checks]
    if missing:
        errors.append("qualification Trial checks missing: " + ", ".join(missing))
    stable_expected = (
        not missing
        and all(checks.get(name) is True for name in REQUIRED_QUALIFICATION_CHECKS)
        and receipt.get("failure_reason") is None
    )
    if receipt.get("stable") is not stable_expected:
        errors.append("qualification Trial stable flag is inconsistent")
    evidence = (
        receipt.get("evidence_hashes")
        if isinstance(receipt.get("evidence_hashes"), Mapping)
        else {}
    )
    if receipt.get("stable") is True and not evidence:
        errors.append("stable qualification Trial requires evidence hashes")
    for path, digest in evidence.items():
        if not str(path) or not SHA256_RE.fullmatch(str(digest).casefold()):
            errors.append(f"invalid qualification Trial evidence hash: {path}")
    if not SHA256_RE.fullmatch(str(receipt.get("software_lock_sha256") or "").casefold()):
        errors.append("qualification Trial software lock hash is invalid")
    if receipt.get("automatic_retry") is not False:
        errors.append("qualification Trial must forbid automatic retry")
    if receipt.get("c2trace_used") is not False or receipt.get("llm_used") is not False:
        errors.append("qualification Trial must be independent of C2Trace and LLMs")
    material = {
        key: receipt.get(key)
        for key in (
            "root_id",
            "trial_id",
            "run_id",
            "repetition",
            "checks",
            "evidence_hashes",
            "vm_snapshot_id",
            "software_lock_sha256",
            "started_at_utc",
            "ended_at_utc",
            "reference_response",
            "poststate",
            "failure_reason",
        )
    }
    if receipt.get("receipt_sha256") != content_hash(material):
        errors.append("qualification Trial content hash is invalid")
    return errors


def finalize_root_qualification(
    trials: Sequence[Mapping[str, Any]],
    *,
    root_id: str,
    vm_snapshot_id: str,
    software_lock_sha256: str,
) -> QualificationReceipt:
    rows = [dict(row) for row in trials]
    if not rows or len(rows) > 3:
        raise ValueError("qualification finalization requires one to three Trials")
    for row in rows:
        errors = validate_root_qualification_trial(row)
        if errors:
            raise ValueError("invalid qualification Trial: " + "; ".join(errors))
        if row.get("root_id") != root_id:
            raise ValueError("qualification Trials contain another root")
        if row.get("vm_snapshot_id") != vm_snapshot_id:
            raise ValueError("qualification Trials contain another VM snapshot")
        if str(row.get("software_lock_sha256") or "").casefold() != software_lock_sha256.casefold():
            raise ValueError("qualification Trials contain another software lock")
    if len({str(row["trial_id"]) for row in rows}) != len(rows):
        raise ValueError("qualification Trial IDs are not distinct")
    if len({str(row["run_id"]) for row in rows}) != len(rows):
        raise ValueError("qualification RunIds are not distinct")
    if sorted(int(row["repetition"]) for row in rows) != list(range(1, len(rows) + 1)):
        raise ValueError("qualification repetitions are not contiguous from one")

    checks = {
        name: all(row["checks"].get(name) is True for row in rows)
        for name in REQUIRED_QUALIFICATION_CHECKS
    }
    evidence: dict[str, str] = {}
    for row in rows:
        for path, digest in row["evidence_hashes"].items():
            qualified_path = (
                Path("trials")
                / str(row["run_id"])
                / "transaction"
                / Path(str(path))
            ).as_posix()
            if qualified_path in evidence and evidence[qualified_path] != digest:
                raise ValueError(
                    f"qualification evidence path has conflicting hashes: {qualified_path}"
                )
            evidence[qualified_path] = str(digest)
    stable_ids = [str(row["trial_id"]) for row in rows if row.get("stable") is True]
    return build_qualification_receipt(
        root_id=root_id,
        checks=checks,
        evidence_hashes=evidence,
        stable_trial_ids=stable_ids,
        vm_snapshot_id=vm_snapshot_id,
        software_lock_sha256=software_lock_sha256.casefold(),
    )
