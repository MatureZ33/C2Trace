"""Auditable manifest for baseline outputs and deterministic re-scoring."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


def sha256_file(path: str | Path) -> str:
    source = Path(path)
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_record(path: str | Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    target = Path(path)
    record: dict[str, Any] = {"path": str(target)}
    if target.is_file():
        record["exists"] = True
        record["size"] = target.stat().st_size
        record["sha256"] = sha256_file(target)
    else:
        record["exists"] = False
    return record


def build_result_manifest(
    *,
    case_id: str,
    pair_id: str,
    run_id: str,
    system: str,
    model: str,
    config: Mapping[str, Any] | None = None,
    tool_schema_hash: str = "",
    kb_hash: str = "",
    prompt_hash: str = "",
    prompt_dry_run_hash: str = "",
    prompt_execute_hash: str = "",
    input_evidence_hash: str = "",
    model_output_hash: str = "",
    prediction_ir: str | Path | None = None,
    casefile: str | Path | None = None,
    run_record: str | Path | None = None,
    evaluation_record: str | Path | None = None,
    scoring_projection: str | Path | None = None,
    score: str | Path | None = None,
    ground_truth: str | Path | None = None,
    post_state: str | Path | None = None,
    trial_result: str | Path | None = None,
    failure_record: str | Path | None = None,
    trial_class: str = "",
    recompute_command: str = "",
    inconsistencies: list[str] | None = None,
) -> dict[str, Any]:
    files = {
        key: record
        for key, record in {
            "prediction_ir": _file_record(prediction_ir),
            "casefile": _file_record(casefile),
            "run_record": _file_record(run_record),
            "evaluation_record": _file_record(evaluation_record),
            "scoring_projection": _file_record(scoring_projection),
            "score": _file_record(score),
            "ground_truth": _file_record(ground_truth),
            "post_state": _file_record(post_state),
            "trial_result": _file_record(trial_result),
            "failure_record": _file_record(failure_record),
        }.items()
        if record is not None
    }
    return {
        "schema_version": "c2trace.baseline.formal_result_manifest.v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "case_id": case_id,
        "pair_id": pair_id,
        "run_id": run_id,
        "system": system,
        "model": model,
        "temperature": (config or {}).get("temperature"),
        "config": dict(config or {}),
        "tool_schema_sha256": tool_schema_hash,
        "kb_sha256": kb_hash,
        # ``prompt_sha256`` remains for compatibility with exploratory pilot
        # manifests. Formal baseline runs must populate both phase-specific
        # hashes below.
        "prompt_sha256": prompt_hash,
        "prompt_dry_run_sha256": prompt_dry_run_hash,
        "prompt_execute_sha256": prompt_execute_hash,
        "input_evidence_sha256": input_evidence_hash,
        "model_output_sha256": model_output_hash,
        "files": files,
        "trial_class": trial_class,
        "recompute_command": recompute_command,
        "inconsistencies": list(inconsistencies or []),
    }


def write_result_manifest(path: str | Path, manifest: Mapping[str, Any]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dict(manifest), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return target


__all__ = ["build_result_manifest", "write_result_manifest", "sha256_file"]
