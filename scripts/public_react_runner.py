"""Adapter used by the eight case launchers for the neutral ReAct baseline."""
from __future__ import annotations

import json
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from typing import Any

from c2trace.baseline.react_runner import (
    BASELINE_MODEL,
    MAX_LLM_CALLS,
    MAX_TOOL_CALLS,
    MAX_TOTAL_TOKENS,
    event_to_baseline_minimal_alert,
    run_react_agent,
)
from c2trace.baseline.formal_result_manifest import build_result_manifest, write_result_manifest
from c2trace.baseline.hash_utils import compute_baseline_prompt_hashes, compute_public_task_spec_hash, compute_tool_schema_hash
from c2trace.baseline.react_agent import ToolCallRecorder, build_tools
from c2trace.tools.system import WindowsToolBackend


ROOT = Path(__file__).resolve().parents[1]


def _protected_process_name(row: dict[str, Any]) -> str:
    """Return an OS process name without treating a logical label as one."""
    for key in ("process_name", "name"):
        value = str(row.get(key) or "").strip()
        if value:
            return value
    path = str(row.get("path") or row.get("canonical_path") or "").strip()
    if path:
        return PureWindowsPath(path).name
    return ""


def make_public_react_runner(*, case_id: str = "", run_id: str = ""):
    """Return a c2trace_runner-compatible callable with no private inputs."""

    def runner(
        *,
        project_root: Path,
        python: Path,
        case_id: str,
        victim_ip: str,
        eve_path: Path,
        event: dict[str, Any],
        artifact: dict[str, Any],
        output_dir: Path,
        log_path: Path,
        protected_manifest: Path,
        response_tools: list[str],
        reviewed_casefile: Path | None = None,
        execute: bool = False,
    ):
        del project_root, python, eve_path, artifact, log_path, response_tools, reviewed_casefile
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        safe_manifest = json.loads(Path(protected_manifest).read_text(encoding="utf-8"))
        protected = [row for row in safe_manifest.get("processes", []) if isinstance(row, dict)]
        protected_names = {_protected_process_name(row) for row in protected if _protected_process_name(row)}
        protected_paths = {str(row.get("path") or row.get("canonical_path") or "").strip() for row in protected if str(row.get("path") or row.get("canonical_path") or "").strip()}
        protected_pids = {int(row["pid"]) for row in protected if str(row.get("pid") or "").strip().isdigit()}
        alert_obj, _ = event_to_baseline_minimal_alert(event, case_id=case_id, victim_ip=victim_ip)
        record = run_react_agent(
            case_id=case_id,
            source_alert=alert_obj.to_dict(),
            output_dir=out,
            execute_response=execute,
            max_tool_calls=MAX_TOOL_CALLS,
            max_llm_calls=MAX_LLM_CALLS,
            max_total_tokens=MAX_TOTAL_TOKENS,
            model=BASELINE_MODEL,
            protected_process_names=protected_names,
            protected_process_paths=protected_paths,
            protected_process_pids=protected_pids,
        )
        status = "completed" if not record.get("errors") else "completed_with_errors"
        metadata_path = out / "run_metadata.json"
        if metadata_path.is_file():
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        else:
            metadata = {"duration_ms": record.get("operational_metrics", {}).get("case_duration_ms"), "llm_usage": {}, "tool_usage": {}, "budget": {}}
        # controller_support.build_operational_metrics consumes the neutral
        # ``call_count`` field. Keep ``llm_calls`` as a compatibility alias,
        # but never leave the canonical aggregate null when the phase record
        # contains a measured count.
        llm_usage = metadata.setdefault("llm_usage", {})
        if llm_usage.get("call_count") is None:
            llm_usage["call_count"] = record.get("operational_metrics", {}).get("llm_calls")
        if llm_usage.get("llm_calls") is None:
            llm_usage["llm_calls"] = llm_usage.get("call_count")
        if not llm_usage.get("response_models"):
            llm_usage["response_models"] = record.get("operational_metrics", {}).get("response_models", [])
        llm_usage["response_model_source"] = record.get("operational_metrics", {}).get("response_model_source", "unknown")
        metadata["run_contract"] = "public_task_neutral_v1"
        metadata["phase"] = "execute" if execute else "dry_run"
        metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        # The live controller only needs a process exit status. All semantic
        # output is in run_record.json; no synthetic plan or lock is created.
        return SimpleNamespace(returncode=2 if record.get("operational_metrics", {}).get("budget_exceeded") or record.get("errors") else 0)

    return runner


__all__ = ["make_public_react_runner"]


def write_public_formal_manifest(*, batch_root: Path, trial_root: Path, runtime: Any, run_id: str, model: str) -> Path:
    """Write a manifest for neutral run/evaluation records."""
    execute_record = trial_root / "c2trace_execute" / "run_record.json"
    dry_record = trial_root / "c2trace_dryrun" / "run_record.json"
    run_record = execute_record if execute_record.is_file() else dry_record
    score_path = trial_root / "score.json"
    eval_path = trial_root / "evaluation_record.json"
    projection_path = trial_root / "scoring_projection.json"
    trial_result = trial_root / "trial_result.json"
    failure = trial_root / "infrastructure_invalid.json"
    prompt_hashes = compute_baseline_prompt_hashes(ROOT / "kb")
    schema_recorder = ToolCallRecorder(WindowsToolBackend(), max_calls=MAX_TOOL_CALLS)
    input_manifest = trial_root / "model_input_manifest.json"
    execute_output = trial_root / "c2trace_execute" / "model_output.json"
    dry_output = trial_root / "c2trace_dryrun" / "model_output.json"
    model_output = execute_output if execute_output.is_file() else dry_output
    manifest = build_result_manifest(
        case_id=runtime.case_id,
        pair_id=f"{runtime.case_id}-react-public",
        run_id=run_id,
        system="langgraph-react-public-task",
        model=model,
        config={"temperature": 0, "max_tool_calls": MAX_TOOL_CALLS, "max_llm_calls": MAX_LLM_CALLS, "max_total_tokens": MAX_TOTAL_TOKENS, "execution_contract": "public_task_neutral_v1"},
        tool_schema_hash=compute_tool_schema_hash(build_tools(schema_recorder)),
        prompt_dry_run_hash=prompt_hashes["dry_run"],
        prompt_execute_hash=prompt_hashes["execute"],
        run_record=run_record,
        evaluation_record=eval_path,
        scoring_projection=projection_path,
        score=score_path,
        ground_truth=trial_root / "ground_truth.json",
        post_state=trial_root / "post_response_validation.json",
        trial_result=trial_result if trial_result.is_file() else None,
        failure_record=failure if failure.is_file() else None,
        input_evidence_hash=(sha256_file(input_manifest) if input_manifest.is_file() else ""),
        model_output_hash=(sha256_file(model_output) if model_output.is_file() else ""),
        trial_class=(json.loads((trial_result if trial_result.is_file() else failure).read_text(encoding="utf-8")).get("trial_class", "") if (trial_result.is_file() or failure.is_file()) else ""),
        recompute_command=f"python -m c2trace.bench_v4.scorer --ground-truth {trial_root / 'ground_truth.json'} --casefile {projection_path}",
    )
    manifest["public_task_spec_sha256"] = compute_public_task_spec_hash()
    manifest["response_model_observation"] = _response_model_observation(trial_root)
    target = batch_root / "formal_result_manifest.json"
    write_result_manifest(target, manifest)
    return target


def sha256_file(path: Path) -> str:
    import hashlib
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _response_model_observation(trial_root: Path) -> dict[str, Any]:
    """Aggregate response models from immutable per-call audit records."""
    rows: list[dict[str, Any]] = []
    for phase in ("c2trace_dryrun", "c2trace_execute"):
        path = trial_root / phase / "llm_call_audit.json"
        if not path.is_file():
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, list):
            rows.extend(item for item in value if isinstance(item, dict))
    models = sorted({str(row.get("response_model") or "").strip() for row in rows if str(row.get("response_model") or "").strip()})
    return {
        "requested_model": BASELINE_MODEL,
        "observed_response_models": models,
        "observed_call_count": len(rows),
        "source": "phase_llm_call_audit",
        "provider_omitted_model_count": sum(1 for row in rows if not str(row.get("response_model") or "").strip()),
    }



