"""Run the LLM-Direct baseline on a de-labelled frozen evidence file.

This command never sends Ground Truth to the model and never executes a host
tool.  Any optional action score is computed after the model call, outside the
prompt, for auditability.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from c2trace.baseline.formal_result_manifest import build_result_manifest, write_result_manifest
from c2trace.baseline.evidence_sanitizer import sanitize_evidence_bundle
from c2trace.baseline.llm_direct import prediction_to_casefile, run_llm_direct
from c2trace.baseline.proposed_action_scorer import score_proposed_actions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--alert", type=Path, help="Optional minimal alert JSON; not sent as Ground Truth")
    parser.add_argument("--ground-truth", type=Path, help="Optional post-call scoring input; never sent to the model")
    parser.add_argument("--model", default="deepseek-chat")
    args = parser.parse_args()

    evidence = json.loads(args.evidence.read_text(encoding="utf-8-sig"))
    sanitized_evidence, sanitization = sanitize_evidence_bundle(evidence)
    prediction, details = run_llm_direct(case_id=args.case_id, evidence=sanitized_evidence, model=args.model)
    alert = json.loads(args.alert.read_text(encoding="utf-8-sig")) if args.alert else {}
    casefile = prediction_to_casefile(prediction, alert)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    prediction.write_json(args.output_dir / "prediction_ir.json")
    (args.output_dir / "sanitized_evidence.json").write_text(
        json.dumps(sanitized_evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "sanitizer_receipt.json").write_text(
        json.dumps(sanitization.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "casefile.json").write_text(json.dumps(casefile, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "llm_call.json").write_text(json.dumps(details, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
    score_path = None
    if args.ground_truth:
        ground_truth = json.loads(args.ground_truth.read_text(encoding="utf-8-sig"))
        proposed_score = score_proposed_actions(ground_truth, prediction.proposed_actions)
        (args.output_dir / "proposed_action_score.json").write_text(json.dumps(proposed_score, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        from c2trace.bench_v4.scorer import score_case
        score = score_case(ground_truth, casefile)
        score_path = args.output_dir / "score.json"
        score_path.write_text(json.dumps(score, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    prompt_hash = hashlib.sha256(str(details.get("prompt") or "").encode("utf-8")).hexdigest()
    output_hash = hashlib.sha256(str(details.get("raw_output") or "").encode("utf-8")).hexdigest()
    manifest = build_result_manifest(
        case_id=args.case_id,
        pair_id=f"{args.case_id}-llm-direct",
        run_id=f"{args.case_id}-llm-direct",
        system="llm-direct",
        model=args.model,
        prediction_ir=args.output_dir / "prediction_ir.json",
        casefile=args.output_dir / "casefile.json",
        score=score_path,
        ground_truth=args.ground_truth,
        prompt_hash=prompt_hash,
        input_evidence_hash=sanitization.output_sha256,
        model_output_hash=output_hash,
        config={
            "temperature": 0,
            "tool_calls": 0,
            "llm_calls": 1,
            "input_evidence_sha256": sanitization.output_sha256,
            "model_output_sha256": output_hash,
        },
        recompute_command="python scripts/baseline_llm_direct.py --case-id <case> --evidence <de-labelled-evidence> --output-dir <out>",
    )
    write_result_manifest(args.output_dir / "formal_result_manifest.json", manifest)
    print(json.dumps({"case_id": args.case_id, "output_dir": str(args.output_dir), "llm_calls": 1, "tool_calls": 0}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
