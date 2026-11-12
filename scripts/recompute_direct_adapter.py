"""Replay the Offline Direct LLM adapter alignment from retained predictions.

Uses the checked-in archive and repository scorer without model requests, host
tools, credentials, or external packages. Ground truth is passed only to scorers.
The archive and retained predictions are never modified by this command.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
import zipfile
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from c2trace.baseline.llm_direct import prediction_to_casefile
from c2trace.baseline.prediction_ir import PredictionIR
from c2trace.baseline.proposed_action_scorer import score_proposed_actions
from c2trace.bench_v4.scorer import score_case

FIELDS = ("tp", "fp", "fn", "precision", "recall", "f1")
CASE_ORDER = (
    "AURORA-CHAIN-001", "AURORA-CHAIN-002", "AEL-OILRIG-SIDETWIST-001",
    "AEL-SANDWORM-EXARAMEL-WIN-001", "AEL-WIZARD-EMOTET-001",
    "AEL-CARBANAK-RAT-001", "AEL-MUSTANG-PANDA-PLUGX-001",
    "MEP-WINDOWS-WEBSHELL-01",
)


def metric(value):
    return {key: value[key] for key in FIELDS}


def aggregate(values):
    tp, fp, fn = (sum(value[key] for value in values) for key in FIELDS[:3])
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    macro = {}
    for key in FIELDS[3:]:
        defined = [value[key] for value in values if value[key] is not None]
        macro[key] = sum(defined) / len(defined) if defined else None
    return {"micro": dict(zip(FIELDS, (tp, fp, fn, precision, recall, f1))), "macro": macro}


def require_equal(actual, expected, label):
    if actual != expected:
        raise ValueError(f"Replay mismatch: {label}")


def public_comparison(value):
    """Ignore only the case of the fixed, previously exported profile token.

    The exporter inserted LAB_USER after original scoring; a replay's Windows
    path normalization produces lab_user. This does not alter score decisions.
    """
    if isinstance(value, dict):
        return {key: public_comparison(item) for key, item in value.items()}
    if isinstance(value, list):
        return [public_comparison(item) for item in value]
    if isinstance(value, str):
        return value.replace("\\LAB_USER\\", "\\lab_user\\").replace("/LAB_USER/", "/lab_user/")
    return value


def compare_score(actual, expected, label):
    # The scorer records the wall-clock replay time; every other field is checked.
    fields = set(actual) | set(expected)
    for key in fields - {"generated_at"}:
        require_equal(public_comparison(actual.get(key)), public_comparison(expected.get(key)),
                      f"{label}/{key}")


def align_casefile(prediction, original):
    """Convert predictions without accepting ground truth as an input."""
    entities = prediction["observed_entities"]
    findings = original["findings"]
    require_equal(len(entities), len(findings), "entity/finding count")
    for index, (entity, finding) in enumerate(zip(entities, findings)):
        for key in ("finding_type", "value", "details"):
            require_equal(entity[key], finding[key], f"entity {index}/{key}")

    converted = prediction_to_casefile(PredictionIR.from_dict(prediction))
    adapted = copy.deepcopy(original)
    adapted["findings"] = converted["findings"]
    changes = []
    for index, (old, new) in enumerate(zip(findings, adapted["findings"])):
        expected = copy.deepcopy(old)
        old_type = old["finding_type"]
        if old_type in {"process", "file"}:
            expected["finding_type"] = {"process": "process_detail", "file": "file_metadata"}[old_type]
            path_source = "unchanged"
            if old_type == "file":
                if expected["details"].get("path"):
                    path_source = "observed_entities.details.path (retained)"
                else:
                    expected["details"]["path"] = entities[index]["value"]
                    path_source = "observed_entities.value"
            changes.append({"entity_index": index, "old_type": old_type,
                            "new_type": expected["finding_type"], "path_source": path_source})
        require_equal(new, expected, f"adapter change boundary/entity {index}")
    require_equal(adapted["proposed_actions"], original["proposed_actions"], "unchanged proposals")
    require_equal(adapted["action_results"], original["action_results"], "unchanged action results")
    return adapted, changes


def replay(archive_path):
    before = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    records = []
    with zipfile.ZipFile(archive_path) as archive:
        for number, case_id in enumerate(CASE_ORDER, 1):
            prefix = f"data/llm_direct/{case_id}/"
            file_hashes = {}

            def read(name):
                raw = archive.read(prefix + name)
                file_hashes[name] = hashlib.sha256(raw).hexdigest()
                return json.loads(raw.decode("utf-8-sig"))

            prediction = read("prediction_ir.json")
            original = read("casefile.json")
            old_score = read("score_before_adapter_alignment.json")
            saved_score = read("score.json")
            gt = read("ground_truth.json")
            proposal_archive = read("proposed_action_score.json")
            adapted_archive = read("adapted_casefile.json")
            manifest = read("formal_result_manifest.json")
            for item in manifest["files"].values():
                raw = archive.read(item["path"])
                require_equal(hashlib.sha256(raw).hexdigest(), item["sha256"],
                              f"{case_id}/manifest hash/{item['path'].split('/')[-1]}")

            compare_score(score_case(gt, original), old_score, f"{case_id}/original score")
            adapted, changes = align_casefile(prediction, original)
            require_equal(adapted, adapted_archive, f"{case_id}/adapted casefile")
            corrected = score_case(gt, adapted)
            compare_score(corrected, saved_score, f"{case_id}/corrected score")
            proposal = score_proposed_actions(gt, prediction)
            require_equal(public_comparison(proposal), public_comparison(proposal_archive),
                          f"{case_id}/action proposal score")
            require_equal(corrected["counts"]["ground_truth_trace_facts"],
                          old_score["counts"]["ground_truth_trace_facts"], f"{case_id}/GT count")
            require_equal(corrected["response_action_metrics"], old_score["response_action_metrics"],
                          f"{case_id}/unchanged response metrics")
            records.append({
                "case": f"C{number}", "case_id": case_id,
                "original_score_reproduced": True, "corrected_score_reproduced": True,
                "action_proposal_score_reproduced": True,
                "ground_truth_reference_count": corrected["counts"]["ground_truth_trace_facts"],
                "trace_original": metric(old_score["trace_metrics"]),
                "trace_adapter_corrected": metric(corrected["trace_metrics"]),
                "action_proposals_unchanged": metric(proposal),
                "adapter_changes": changes, "archive_member_sha256": file_hashes,
            })
    require_equal(hashlib.sha256(archive_path.read_bytes()).hexdigest(), before, "unchanged archive")
    return {
        "schema_version": "llm_direct.adapter_alignment_replay.v1",
        "semantics": "offline scoring correction of retained model outputs; no new experiment",
        "comparison_normalization": "Ignore replay timestamp and LAB_USER profile-token case only",
        "n_cases": len(records), "all_original_scores_reproduced": True,
        "all_corrected_scores_reproduced": True, "all_action_proposal_scores_reproduced": True,
        "ground_truth_reference_count": sum(row["ground_truth_reference_count"] for row in records),
        "trace_original": aggregate([row["trace_original"] for row in records]),
        "trace_adapter_corrected": aggregate([row["trace_adapter_corrected"] for row in records]),
        "action_proposals_unchanged": aggregate([row["action_proposals_unchanged"] for row in records]),
        "archive_sha256": before, "archive_unchanged": True,
        "scorer_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
            "src/c2trace/bench_v3/scorer.py", "src/c2trace/bench_v4/scorer.py",
            "src/c2trace/baseline/proposed_action_scorer.py")},
        "cases": records,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=ROOT / "archives/llm_direct.zip")
    parser.add_argument("--output", type=Path, help="Optional JSON report; defaults to a console summary")
    args = parser.parse_args()
    if args.output:
        destination = args.output.resolve()
        if destination == args.archive.resolve() or destination.is_relative_to(ROOT / "src"):
            parser.error("The report must not overwrite the archive or source code")
    result = replay(args.archive)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in (
        "n_cases", "all_original_scores_reproduced", "all_corrected_scores_reproduced",
        "all_action_proposal_scores_reproduced", "ground_truth_reference_count",
        "trace_adapter_corrected", "action_proposals_unchanged")}, indent=2))


if __name__ == "__main__":
    main()
