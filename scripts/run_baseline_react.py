"""Run one independent public-task ReAct episode.

This command never reads evaluation truth before the agent returns. Scoring is
an explicit post-run operation and writes a neutral evaluation projection.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from c2trace.baseline.formal_result_manifest import build_result_manifest, write_result_manifest
from c2trace.baseline.hash_utils import compute_public_task_spec_hash, compute_tool_schema_hash
from c2trace.baseline.neutral_records import project_for_scoring
from c2trace.baseline.public_task import DEFAULT_SPEC_ROOT
from c2trace.baseline.react_agent import ToolCallRecorder, build_tools
from c2trace.baseline.react_runner import BASELINE_MODEL, run_react_agent
from c2trace.tools.system import WindowsToolBackend


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--alert", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--task-spec-root", type=Path, default=DEFAULT_SPEC_ROOT)
    parser.add_argument("--max-tool-calls", type=int, default=50)
    parser.add_argument("--max-llm-calls", type=int, default=20)
    parser.add_argument("--max-total-tokens", type=int, default=300000)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--ground-truth", type=Path, help="Optional post-run scoring input")
    args = parser.parse_args()

    alert = json.loads(args.alert.read_text(encoding="utf-8-sig"))
    record = run_react_agent(
        case_id=args.case_id,
        source_alert=alert,
        output_dir=args.output_dir,
        max_tool_calls=args.max_tool_calls,
        max_llm_calls=args.max_llm_calls,
        max_total_tokens=args.max_total_tokens,
        execute_response=not args.dry_run,
        model=BASELINE_MODEL,
        task_spec_root=args.task_spec_root,
    )

    score_path = None
    evaluation_path = None
    projection_path = None
    if args.ground_truth:
        ground_truth = json.loads(args.ground_truth.read_text(encoding="utf-8-sig"))
        evaluation, projection = project_for_scoring(record)
        from c2trace.bench_v4.scorer import score_case
        score = score_case(ground_truth, projection)
        evaluation_path = args.output_dir / "evaluation_record.json"
        projection_path = args.output_dir / "scoring_projection.json"
        evaluation.write_json(evaluation_path)
        projection_path.write_text(json.dumps(projection, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
        score_path = args.output_dir / "score.json"
        score_path.write_text(json.dumps(score, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")

    backend = WindowsToolBackend(execute_response=not args.dry_run)
    schema_recorder = ToolCallRecorder(backend, max_calls=args.max_tool_calls)
    tool_schema_hash = compute_tool_schema_hash(build_tools(schema_recorder))
    manifest = build_result_manifest(
        case_id=args.case_id,
        pair_id=f"{args.case_id}-react-public",
        run_id=f"{args.case_id}-react-public",
        system="langgraph-react-public-task",
        model=BASELINE_MODEL,
        config={"temperature": 0, "tool_calls": args.max_tool_calls, "llm_calls": args.max_llm_calls, "execute_response": not args.dry_run, "task_spec_root": str(args.task_spec_root)},
        tool_schema_hash=tool_schema_hash,
        input_evidence_hash="",
        run_record=args.output_dir / "run_record.json",
        evaluation_record=evaluation_path,
        scoring_projection=projection_path,
        score=score_path,
        ground_truth=args.ground_truth,
        recompute_command=f"python scripts/run_baseline_react.py --case-id {args.case_id} --alert <canonical-alert> --output-dir <out>",
        inconsistencies=["budget_exceeded=true"] if record.get("operational_metrics", {}).get("budget_exceeded") else [],
    )
    manifest["public_task_spec_sha256"] = compute_public_task_spec_hash(args.task_spec_root)
    write_result_manifest(args.output_dir / "formal_result_manifest.json", manifest)
    print(json.dumps({"case_id": args.case_id, "output_dir": str(args.output_dir), "metrics": record.get("operational_metrics", {}), "run_record": str(args.output_dir / "run_record.json")}, ensure_ascii=False, default=str))
    return 0 if not record.get("operational_metrics", {}).get("budget_exceeded") else 2


if __name__ == "__main__":
    raise SystemExit(main())
