from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from c2trace.bench_v4 import (
    aggregate_scores,
    score_case,
    write_aggregate_outputs,
    write_score_outputs,
)
from c2trace.bench_v4 import ScoreValidationError


A = "11111111-1111-4111-8111-111111111111"


def _ground_truth(*, stratum: str = "micro_emulation_plan") -> dict:
    return {
        "schema_version": "c2trace.bench.ground_truth.v4",
        "case_id": "MEP-REGISTRY-01",
        "source_id": "ctid-micro",
        "source_kind": "ctid_micro",
        "dataset_stratum": stratum,
        "target_kind": "manx",
        "ability_instances": [
            {
                "instance_key": "scenario.registry",
                "operation_role": "scenario",
                "operation_id": "op-1",
                "link_id": "link-1",
                "ability_id": A,
                "attack_mapped": True,
                "mandatory": True,
                "executed": True,
                "ability_role": "attack_mapped_mandatory",
                "source_step_ids": ["registry.write"],
                "expected_status": "success",
                "metric_eligible": True,
                "atomic_trace_eligible": True,
                "metric_exclusion_reason": None,
                "trace_facts": [
                    {
                        "trace_id": "trace.registry.value",
                        "trace_type": "registry_value",
                        "canonical_key": "registry:hive+key+name+data",
                        "required": True,
                        "discriminative": True,
                        "anchor": True,
                        "shared_context": False,
                        "observable_by": ["c2trace:registry_value_confirmed"],
                        "valid_window": "after_scenario_before_response",
                        "producer_ability_instance": "scenario.registry",
                        "expected_value": {
                            "hive": "HKCU",
                            "key_path": "HKCU\\Software\\C2TraceBench\\Registry",
                            "value_name": "Demo",
                            "value_data": "not-a-run-key",
                        },
                        "source_evidence": {
                            "artifact": "evidence/before_response.json",
                            "json_pointer": "/registry_values/0",
                            "capture_stage": "before_response",
                        },
                        "scoreable_by_c2trace": True,
                        "eligibility_reason": "Exact arbitrary registry value.",
                    }
                ],
            }
        ],
        "response_actions": [
            {
                "tool": "remove_registry",
                "required": True,
                "arguments": {},
                "target": {
                    "key_path": "HKCU\\Software\\C2TraceBench\\Registry",
                    "value_name": "Demo",
                    "value_data": "not-a-run-key",
                },
            }
        ],
        "scoring_policy": {
            "one_to_one_trace_matching": True,
            "ability_precision": "not_applicable_without_independent_ability_predictions",
            "seed_alert_scored": False,
        },
        "observed": {
            "post_response": {
                "target": None,
                "target_file": None,
                "network_connections": [],
                "persistence": [],
                "control": {"pid": 10},
            }
        },
    }


def _casefile() -> dict:
    return {
        "case_id": "MEP-REGISTRY-01-r01",
        "trial_class": "evaluation_valid_pass",
        "final_status": "completed",
        "findings": [
            {
                "finding_id": "f-reg",
                "finding_type": "registry_value_confirmed",
                "details": {
                    "hive": "HKCU",
                    "key_path": "HKCU\\Software\\C2TraceBench\\Registry",
                    "value_name": "Demo",
                    "value_data": "not-a-run-key",
                },
            }
        ],
        "action_results": [
            {
                "tool": "remove_registry",
                "success": True,
                "arguments": {
                    "reg_path": "HKCU\\Software\\C2TraceBench\\Registry",
                    "value_name": "Demo",
                    "expected_value": "not-a-run-key",
                },
                "data": {"dry_run": False},
            }
        ],
        "operational_metrics": {
            "target_network_absent": True,
            "target_process_absent": True,
            "target_file_absent": True,
            "target_persistence_absent": True,
            "control_agent_alive": True,
        },
    }


def test_registry_value_is_scored_without_misreporting_it_as_run_key() -> None:
    score = score_case(_ground_truth(), _casefile())
    assert score["schema_version"] == "c2trace.bench.evaluation.v4"
    assert score["trace_metrics"] == {
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
        "tp": 1,
        "fp": 0,
        "fn": 0,
    }
    assert score["response_action_metrics"]["f1"] == 1.0
    match = score["trace_matching"]["matches"][0]
    assert match["trace_type"] == "registry_value"
    assert score["per_ability"][0]["matched_traces"][0]["trace_type"] == "registry_value"


def _run_key_inputs(
    *,
    expected_hive: str,
    expected_path: str,
    observed_hive: str | None,
    observed_path: str,
) -> tuple[dict, dict]:
    ground_truth = _ground_truth()
    trace = ground_truth["ability_instances"][0]["trace_facts"][0]
    trace["trace_type"] = "registry_run_key"
    trace["expected_value"].update(
        {
            "hive": expected_hive,
            "key_path": expected_path,
            "value_name": "Demo",
            "value_data": "not-a-run-key",
        }
    )
    casefile = _casefile()
    details = {
        "category": "registry_run_keys",
        "path": observed_path,
        "name": "Demo",
        "value": "not-a-run-key",
    }
    if observed_hive is not None:
        details["hive"] = observed_hive
    casefile["findings"] = [
        {
            "finding_id": "f-reg",
            "finding_type": "persistence_linked_to_payload",
            "details": details,
        }
    ]
    return ground_truth, casefile


@pytest.mark.parametrize(
    ("expected_hive", "expected_path", "observed_hive", "observed_path"),
    [
        (
            "HKCU",
            r"Software\C2TraceBench\Registry",
            "hKeY_cUrReNt_UsEr",
            r"hKcU:\SOFTWARE\C2TRACEBENCH\REGISTRY",
        ),
        (
            "HKEY_LOCAL_MACHINE",
            r"SOFTWARE\C2TraceBench\Registry",
            None,
            r"hKlM\software\c2tracebench\registry",
        ),
        (
            "hklm",
            "HKLM:\\Software\\C2TraceBench\\Registry\\",
            "HKLM:",
            r"software/C2TraceBench/Registry",
        ),
    ],
)
def test_registry_matcher_canonicalizes_hive_prefix_colon_slashes_and_case(
    expected_hive: str,
    expected_path: str,
    observed_hive: str | None,
    observed_path: str,
) -> None:
    ground_truth, casefile = _run_key_inputs(
        expected_hive=expected_hive,
        expected_path=expected_path,
        observed_hive=observed_hive,
        observed_path=observed_path,
    )
    score = score_case(ground_truth, casefile)
    assert score["trace_metrics"]["tp"] == 1
    assert score["trace_metrics"]["fn"] == 0


@pytest.mark.parametrize(
    ("observed_hive", "observed_path"),
    [
        ("HKLM", r"HKLM:\Software\C2TraceBench\Registry"),
        ("HKCU", r"HKCU:\Software\C2TraceBench\OtherKey"),
        # Explicit/path disagreement must stay contradictory, not be repaired
        # into an HKCU match by merely stripping the path's HKLM root.
        ("HKCU", r"HKLM:\Software\C2TraceBench\Registry"),
    ],
)
def test_registry_matcher_does_not_cross_hives_or_keys(
    observed_hive: str, observed_path: str
) -> None:
    ground_truth, casefile = _run_key_inputs(
        expected_hive="HKCU",
        expected_path=r"Software\C2TraceBench\Registry",
        observed_hive=observed_hive,
        observed_path=observed_path,
    )
    score = score_case(ground_truth, casefile)
    assert score["trace_metrics"]["tp"] == 0
    assert score["trace_metrics"]["fn"] == 1
    assert score["trace_metrics"]["fp"] == 1


def test_target_neutral_operational_fields_retain_v3_aliases() -> None:
    score = score_case(_ground_truth(), _casefile())
    operational = score["operational_metrics"]
    assert operational["target_process_absent"] is True
    assert operational["control_agent_alive"] is True
    assert operational["manx_process_absent"] is True
    assert operational["control_sandcat_alive"] is True


def test_runtime_resource_metrics_survive_v4_scoring_and_aggregation() -> None:
    casefile = _casefile()
    casefile["operational_metrics"].update(
        {
            "end_to_end_duration_ms": 500.0,
            "investigation_duration_ms": 50.5,
            "response_duration_ms": 13.0,
            "verification_duration_ms": 15.0,
            "case_duration_ms": 301.0,
            "llm_calls": 3,
            "tool_calls": 8,
            "prompt_tokens": 170,
            "completion_tokens": 70,
            "total_tokens": 240,
        }
    )
    score = score_case(_ground_truth(), casefile)
    operational = score["operational_metrics"]
    assert operational["end_to_end_duration_ms"] == 500.0
    assert operational["investigation_duration_ms"] == 50.5
    assert operational["llm_calls"] == 3
    assert operational["tool_calls"] == 8
    assert operational["total_tokens"] == 240

    report = aggregate_scores(
        [
            {
                "case_id": "MEP-REGISTRY-01",
                "trial_id": "mep-r01",
                "trial_class": "evaluation_valid_pass",
                "dataset_stratum": "micro_emulation_plan",
                "source_kind": "ctid_micro",
                "score": score,
            }
        ],
        bootstrap_samples=100,
        seed=7,
    )
    runtime = report["overall"]["operational"]
    assert runtime["end_to_end_duration_ms"]["n"] == 1
    assert runtime["end_to_end_duration_ms"]["mean"] == 500.0
    assert runtime["llm_calls"]["mean"] == 3.0
    assert runtime["total_tokens"]["mean"] == 240.0


def test_explicit_missing_runtime_metrics_remain_null() -> None:
    casefile = _casefile()
    casefile["operational_metrics"].update(
        {
            "case_duration_ms": None,
            "llm_calls": None,
            "tool_calls": None,
        }
    )
    score = score_case(_ground_truth(), casefile)
    assert score["operational_metrics"]["case_duration_ms"] is None
    assert score["operational_metrics"]["llm_calls"] is None
    assert score["operational_metrics"]["tool_calls"] is None


def test_runtime_metric_rejects_non_numeric_values() -> None:
    casefile = _casefile()
    casefile["operational_metrics"]["llm_calls"] = "three"
    with pytest.raises(ScoreValidationError, match="llm_calls"):
        score_case(_ground_truth(), casefile)


def test_v4_score_markdown_uses_target_neutral_labels(tmp_path: Path) -> None:
    score = score_case(_ground_truth(), _casefile())
    write_score_outputs(score, tmp_path / "score.json", tmp_path / "score.md")
    markdown = (tmp_path / "score.md").read_text(encoding="utf-8")
    assert markdown.startswith("# C2Trace Bench v4 Score")
    assert "target_process_absent" in markdown
    assert "Runtime and resource measurements" in markdown
    assert "| `llm_calls` | N/A |" in markdown
    assert "C2Trace Bench v3" not in markdown


def test_generic_action_result_target_is_compatible_with_v3_action_matching() -> None:
    casefile = _casefile()
    casefile["action_results"][0] = {
        "tool": "remove_registry",
        "success": True,
        "arguments": {"expected_value": "not-a-run-key"},
        "target": {
            "key_path": "HKCU\\Software\\C2TraceBench\\Registry",
            "value_name": "Demo",
            "value_data": "not-a-run-key",
        },
        "data": {"dry_run": False},
    }
    score = score_case(_ground_truth(), casefile)
    assert score["response_action_metrics"] == {
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
        "tp": 1,
        "fp": 0,
        "fn": 0,
    }


def test_generic_persistence_absence_checks_every_persistence_channel() -> None:
    ground_truth = _ground_truth()
    ground_truth["observed"]["post_response"].update(
        {
            "persistence": [],
            "run_key": None,
            "scheduled_tasks": [],
            "services": [{"service_name": "still-present"}],
        }
    )
    casefile = _casefile()
    casefile.pop("operational_metrics")
    score = score_case(ground_truth, casefile)
    assert score["operational_metrics"]["target_persistence_absent"] is False
    assert score["operational_metrics"]["manx_run_key_absent"] is False


def test_aggregation_is_primary_by_stratum_and_keeps_overall_supplemental(
    tmp_path: Path,
) -> None:
    micro = score_case(_ground_truth(), _casefile())
    assert micro["source_kind"] == "ctid_micro"
    chain_gt = _ground_truth(stratum="named_chain_projection")
    chain_gt["case_id"] = "AF-DEMO-01"
    chain_gt["source_kind"] = "attack_flow"
    chain_gt["source_id"] = "attack-flow"
    chain_case = deepcopy(_casefile())
    chain_case["case_id"] = "AF-DEMO-01-r01"
    chain = score_case(chain_gt, chain_case)
    assert chain["source_kind"] == "attack_flow"
    report = aggregate_scores(
        [
            {
                "case_id": "MEP-REGISTRY-01",
                "trial_id": "mep-r01",
                "trial_class": "evaluation_valid_pass",
                "dataset_stratum": "micro_emulation_plan",
                "source_kind": "ctid_micro",
                "score": micro,
                "operational_metrics": micro["operational_metrics"],
            },
            {
                "case_id": "AF-DEMO-01",
                "trial_id": "af-r01",
                "trial_class": "evaluation_valid_pass",
                "dataset_stratum": "named_chain_projection",
                "source_kind": "attack_flow",
                "score": chain,
                "operational_metrics": chain["operational_metrics"],
            },
        ],
        bootstrap_samples=100,
        seed=7,
    )
    assert report["schema_version"] == "c2trace.bench.aggregate.v4"
    assert set(report["per_stratum"]) == {
        "micro_emulation_plan",
        "named_chain_projection",
    }
    assert set(report["per_source_kind"]) == {"attack_flow", "ctid_micro"}
    assert report["stratification_policy"]["primary_reporting"] == "per_stratum"
    assert report["generic_operational"]["target_process_absent"]["rate"] == 1.0
    write_aggregate_outputs(
        report, tmp_path / "aggregate.json", tmp_path / "aggregate.md"
    )
    assert "## Dataset strata" in (tmp_path / "aggregate.md").read_text(encoding="utf-8")
    assert "# C2Trace Bench v4 Aggregate Report" in (
        tmp_path / "aggregate.md"
    ).read_text(encoding="utf-8")


def test_aggregation_rejects_unstratified_or_mislabeled_v4_trials() -> None:
    score = score_case(_ground_truth(), _casefile())
    with pytest.raises(ScoreValidationError, match="pairing"):
        aggregate_scores(
            [
                {
                    "case_id": "MEP-REGISTRY-01",
                    "trial_id": "mep-r01",
                    "trial_class": "evaluation_valid_pass",
                    "dataset_stratum": "named_chain_projection",
                    "source_kind": "ctid_micro",
                    "score": score,
                }
            ],
            bootstrap_samples=10,
        )
