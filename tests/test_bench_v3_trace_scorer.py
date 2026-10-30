from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from c2trace.bench_v3 import render_markdown_summary, score_case, write_score_outputs


def _ability(
    instance_id: str,
    ability_id: str,
    traces: list[dict],
    **overrides: object,
) -> dict:
    value = {
        "ability_instance_id": instance_id,
        "operation_id": "op-scenario",
        "link_id": f"link-{instance_id}",
        "ability_id": ability_id,
        "attack_mapped": True,
        "mandatory": True,
        "executed": True,
        "trace_facts": traces,
    }
    value.update(overrides)
    return value


def _trace(trace_id: str, trace_type: str, expected: dict, **overrides: object) -> dict:
    value = {
        "trace_id": trace_id,
        "trace_type": trace_type,
        "canonical_key": f"key-{trace_id}",
        "required": True,
        "discriminative": True,
        "observable_by": ["c2trace"],
        "valid_window": {"start": "2026-07-14T00:00:00Z", "end": "2026-07-15T00:00:00Z"},
        "expected_value": expected,
        "source_evidence": {"kind": "host_snapshot"},
    }
    value.update(overrides)
    return value


def _finding(finding_id: str, finding_type: str, details: dict, value: str = "") -> dict:
    return {
        "finding_id": finding_id,
        "finding_type": finding_type,
        "value": value,
        "source": "executor",
        "evidence": "test",
        "details": details,
    }


def test_scores_inbound_listener_correlation_using_suricata_flow_direction() -> None:
    flow = {
        "protocol": "tcp",
        "src_ip": "192.168.21.132",
        "src_port": 46182,
        "dest_ip": "192.168.21.140",
        "dest_port": 18768,
        "pid": 14360,
    }
    ground_truth = {
        "schema_version": "c2trace.bench.ground_truth.v3",
        "case_id": "inbound",
        "ability_instances": [
            _ability(
                "listener",
                "ability-listener",
                [_trace("trace-listener", "network_connection", flow)],
            )
        ],
        "response_actions": [],
    }
    casefile = {
        "case_id": "inbound",
        "findings": [
            _finding(
                "network",
                "network_connection",
                {
                    **flow,
                    "network_mode": "inbound_listener",
                    "state": "Listen",
                    "listener": {
                        "local_address": "192.168.21.140",
                        "local_port": 18768,
                        "remote_address": "0.0.0.0",
                        "remote_port": 0,
                        "pid": 14360,
                    },
                },
            )
        ],
        "action_results": [],
    }

    score = score_case(ground_truth, casefile)

    assert score["trace_metrics"] == {
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
        "tp": 1,
        "fp": 0,
        "fn": 0,
    }


def test_scores_ability_recall_trace_metrics_actions_and_exclusions() -> None:
    manx_path = r"C:\Users\Public\C2T_RUN.EXE"
    ground_truth = {
        "schema_version": "c2trace.bench.ground_truth.v3",
        "case_id": "AF-MAAS-WIN-01",
        "ability_instances": [
            _ability(
                "a1",
                "ability-network",
                [
                    _trace(
                        "t-network",
                        "network_connection",
                        {
                            "protocol": "TCP",
                            "local_address": "192.168.21.140",
                            "local_port": 51001,
                            "remote_address": "192.168.21.132",
                            "remote_port": 7010,
                            "pid": 4242,
                        },
                    ),
                    _trace(
                        "t-process",
                        "process",
                        {"pid": 4242, "path": manx_path, "name": "C2T_RUN.exe"},
                    ),
                ],
            ),
            _ability(
                "a2",
                "ability-persist",
                [
                    _trace(
                        "t-file",
                        "file",
                        {"path": manx_path, "sha256": "AA" * 32},
                    ),
                    _trace(
                        "t-reg",
                        "registry_run_key",
                        {
                            "key_path": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
                            "value_name": "C2TraceManx",
                            "value_data": f'"{manx_path}"',
                        },
                    ),
                ],
            ),
            _ability(
                "a3",
                "ability-task",
                [
                    _trace(
                        "t-task",
                        "scheduled_task",
                        {"task_path": "\\", "task_name": "C2TraceMissing"},
                    )
                ],
            ),
            _ability("a4", "ability-no-trace", []),
            _ability(
                "a5-not-mandatory",
                "ability-outside-denominator",
                [_trace("t-out", "service", {"service_name": "outside"})],
                mandatory=False,
            ),
        ],
        "expected": {
            "response": [
                {"tool": "kill_process", "required": True, "arguments": {"pid": 4242}},
                {
                    "tool": "remove_file",
                    "required": True,
                    "arguments": {"file_path": manx_path},
                },
            ]
        },
    }
    connection = {
        "local_address": "192.168.21.140",
        "local_port": "51001",
        "remote_address": "192.168.21.132",
        "remote_port": "7010",
        "state": "Established",
        "pid": "4242",
        "process_name": "c2t_run.EXE",
        "process_path": r"c:/users/public/c2t_run.exe",
    }
    casefile = {
        "case_id": "AF-MAAS-WIN-01",
        "findings": [
            _finding("seed", "minimal_c2_seed_alert", {}, "192.168.21.132:7010"),
            _finding("n-summary", "network_confirmed", {"connections": [connection]}),
            _finding("n-alias", "network_connection", connection),
            _finding("p-alias", "c2_process_attributed", connection),
            _finding(
                "p-detail",
                "process_detail",
                {
                    "pid": 4242,
                    "name": "C2T_RUN.exe",
                    "path": r"C:\USERS\PUBLIC\C2T_RUN.EXE",
                },
            ),
            _finding(
                "file-one",
                "payload_file_verified",
                {"exists": True, "path": r"c:/users/public/c2t_run.exe", "sha256": "aa" * 32},
            ),
            _finding(
                "file-alias",
                "file_metadata",
                {"exists": True, "path": manx_path, "sha256": "AA" * 32},
            ),
            _finding(
                "noise-persistence",
                "persistence_candidate",
                {
                    "category": "registry_run_keys",
                    "path": r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
                    "name": "UnlinkedNoise",
                    "value": "noise.exe",
                },
            ),
            _finding(
                "reg-linked",
                "persistence_linked_to_payload",
                {
                    "category": "registry_run_keys",
                    "path": r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
                    "name": "c2tracemanx",
                    "value": f'"{manx_path.lower()}"',
                },
            ),
            _finding(
                "extra-service",
                "persistence_linked_to_payload",
                {"category": "services", "name": "unexpected", "path": manx_path},
            ),
            _finding("cleanup", "cleanup_file_verified", {"path": manx_path}),
            _finding("response", "response_action_executed", {"tool": "remove_file"}),
        ],
        "action_results": [
            {"tool": "check_network", "success": True, "arguments": {}},
            {"tool": "kill_process", "success": True, "arguments": {"pid": 4242}, "data": {}},
            {
                "tool": "remove_file",
                "success": True,
                "arguments": {"file_path": manx_path.lower()},
                "data": {},
            },
            {
                "tool": "remove_service",
                "success": True,
                "arguments": {"service_name": "unexpected"},
                "data": {},
            },
        ],
    }

    score = score_case(ground_truth, casefile)

    assert score["ability_precision"] is None
    assert score["counts"] == {
        "executed_attack_mapped_mandatory_abilities": 4,
        "trace_producing_abilities": 3,
        "ground_truth_trace_facts": 5,
        "ability_denominator_trace_facts": 5,
        "non_ability_atomic_trace_facts": 0,
        "predicted_trace_observations": 5,
        "trace_tp": 4,
        "trace_fp": 1,
        "trace_fn": 1,
        "expected_response_actions": 2,
        "predicted_response_actions": 3,
        "response_action_tp": 2,
        "response_action_fp": 1,
        "response_action_fn": 0,
    }
    metrics = score["metrics"]
    assert metrics["ability_any_trace_recall"] == pytest.approx(2 / 3)
    assert metrics["mean_ability_trace_coverage"] == pytest.approx(2 / 3)
    assert metrics["strict_ability_recall"] == pytest.approx(2 / 3)
    assert metrics["trace_producing_ability_ratio"] == pytest.approx(3 / 4)
    assert metrics["trace_precision"] == pytest.approx(0.8)
    assert metrics["trace_recall"] == pytest.approx(0.8)
    assert metrics["trace_f1"] == pytest.approx(0.8)
    assert metrics["response_action_precision"] == pytest.approx(2 / 3)
    assert metrics["response_action_recall"] == pytest.approx(1.0)
    assert metrics["response_action_f1"] == pytest.approx(0.8)
    assert [item["ability_instance_id"] for item in score["per_ability"]] == [
        "a1",
        "a2",
        "a3",
        "a4",
        "a5-not-mandatory",
    ]
    assert score["per_ability"][3]["hit"] is None
    assert score["per_ability"][4]["included_in_ability_denominator"] is False
    unmatched_types = {
        item["trace_type"] for item in score["trace_matching"]["unmatched_observations"]
    }
    assert unmatched_types == {"service"}


def test_supports_all_nine_trace_types() -> None:
    path = r"C:\Users\Public\manx.exe"
    traces = [
        _trace(
            "n",
            "network_connection",
            {"destination_ip": "10.0.0.1", "destination_port": 7010, "pid": 100},
        ),
        _trace("p", "process", {"pid": 100, "path": path}),
        _trace("e", "process_parent_edge", {"child_pid": 100, "parent_pid": 50}),
        _trace("f", "file", {"path": path, "sha256": "12" * 32}),
        _trace(
            "r",
            "registry_run_key",
            {"key_path": r"HKCU\Software\X\Run", "value_name": "manx", "value_data": path},
        ),
        _trace(
            "t",
            "scheduled_task",
            {"task_path": "\\Lab\\", "task_name": "Manx", "actions": [path]},
        ),
        _trace("s", "service", {"service_name": "ManxSvc", "binary_path": path}),
        _trace("h", "powershell_history", {"command": f"Start-Process '{path}'"}),
        _trace("d", "dns_cache", {"name": "C2.EXAMPLE.", "type": "A", "data": "10.0.0.1"}),
    ]
    ground_truth = {"ability_instances": [_ability("all", "ability-all", traces)]}
    casefile = {
        "findings": [
            _finding(
                "n1",
                "network_connection",
                {"remote_address": "10.0.0.1", "remote_port": 7010, "pid": 100},
            ),
            _finding(
                "tree",
                "process_tree",
                {
                    "root": {"pid": 100, "path": path, "name": "manx.exe", "parent_pid": 50},
                    "chain": [
                        {"pid": 100, "path": path, "name": "manx.exe", "parent_pid": 50},
                        {"pid": 50, "path": r"C:\Windows\explorer.exe", "name": "explorer.exe"},
                    ],
                },
            ),
            _finding("file", "file_metadata", {"exists": True, "path": path, "sha256": "12" * 32}),
            _finding(
                "reg",
                "persistence_linked_to_payload",
                {"category": "registry_run_keys", "path": r"HKCU:\Software\X\Run", "name": "manx", "value": path},
            ),
            _finding(
                "task",
                "persistence_linked_to_payload",
                {"category": "scheduled_tasks", "path": r"\Lab", "name": "Manx", "actions": [path]},
            ),
            _finding(
                "service",
                "persistence_linked_to_payload",
                {"category": "services", "name": "manxsvc", "path": path},
            ),
            _finding(
                "history",
                "powershell_history_hit",
                {"command": f"  START-PROCESS   '{path.lower()}' "},
            ),
            _finding(
                "dns",
                "dns_cache_confirmed",
                {"entries": [{"name": "c2.example", "type": "a", "data": "10.0.0.1"}]},
            ),
        ],
        "action_results": [],
    }

    score = score_case(ground_truth, casefile)
    assert score["counts"]["ground_truth_trace_facts"] == 9
    assert score["counts"]["predicted_trace_observations"] == 9
    assert score["counts"]["trace_tp"] == 9
    assert score["metrics"]["trace_precision"] == 1.0
    assert score["metrics"]["trace_recall"] == 1.0
    assert score["metrics"]["ability_any_trace_recall"] == 1.0


def test_shared_context_and_duplicate_findings_never_credit_two_abilities() -> None:
    expected = {"remote_address": "192.0.2.10", "remote_port": 7010, "pid": 900}
    ground_truth = {
        "ability_instances": [
            _ability("a", "ability-a", [_trace("shared-a", "network_connection", expected, shared_context=True)]),
            _ability("b", "ability-b", [_trace("shared-b", "network_connection", expected, shared_context=True)]),
        ]
    }
    connection = {**expected, "local_address": "192.0.2.20", "local_port": 50000}
    casefile = {
        "findings": [
            _finding("one", "network_confirmed", {"connections": [connection]}),
            _finding("two", "network_connection", connection),
        ],
        "action_results": [],
    }

    score = score_case(ground_truth, casefile)
    assert score["counts"]["predicted_trace_observations"] == 1
    assert score["counts"]["trace_tp"] == 1
    assert score["counts"]["trace_fn"] == 1
    assert score["metrics"]["ability_any_trace_recall"] == pytest.approx(0.5)
    assert sum(item["hit"] is True for item in score["per_ability"]) == 1


def test_empty_denominators_are_null_not_invented_zeroes() -> None:
    score = score_case({"ability_instances": []}, {"case_id": "empty", "findings": [], "action_results": []})
    assert score["ability_precision"] is None
    assert all(value is None for value in score["metrics"].values())
    markdown = render_markdown_summary(score)
    assert "N/A" in markdown


def test_strict_recall_requires_a_preregistered_required_or_anchor_trace() -> None:
    discriminative_only = _trace(
        "disc-only",
        "process",
        {"pid": 4242, "path": r"C:\Users\Public\manx.exe"},
        required=False,
        anchor=False,
        discriminative=True,
    )
    score = score_case(
        {"ability_instances": [_ability("a1", "ability-a1", [discriminative_only])]},
        {
            "findings": [
                _finding(
                    "process",
                    "process_detail",
                    {"pid": 4242, "path": r"C:\Users\Public\manx.exe"},
                )
            ],
            "action_results": [],
        },
    )

    assert score["metrics"]["ability_any_trace_recall"] == 1.0
    assert score["metrics"]["strict_ability_recall"] == 0.0
    assert score["per_ability"][0]["strict_hit"] is False


def test_real_dataset_template_contract_and_null_execution_are_safe() -> None:
    root = Path(__file__).resolve().parents[1]
    template_path = (
        root
        / "tests"
        / "fixtures"
        / "scorer_ground_truth_template.json"
    )
    template = json.loads(template_path.read_text(encoding="utf-8"))
    empty_casefile = {
        "case_id": "AF-MAAS-WIN-01",
        "findings": [],
        "action_results": [],
    }

    template_score = score_case(template, empty_casefile)
    assert template_score["trial_class"] == "infrastructure_invalid"
    assert template_score["counts"]["executed_attack_mapped_mandatory_abilities"] == 0
    assert template_score["counts"]["trace_producing_abilities"] == 0
    assert template_score["counts"]["ground_truth_trace_facts"] == 0
    assert [item["ability_instance_id"] for item in template_score["per_ability"]] == [
        "bootstrap.stage_manx",
        "bootstrap.start_manx",
        "scenario.shell_proof",
        "scenario.run_key",
    ]
    assert all(item["executed"] is False for item in template_score["per_ability"])
    assert template_score["per_ability"][0]["registered_trace_count"] == 1
    assert template_score["per_ability"][0]["scoreable_trace_count"] == 1
    assert template_score["per_ability"][0]["atomic_trace_eligible"] is True
    assert template_score["per_ability"][0]["atomic_trace_count"] == 0
    assert template_score["per_ability"][2]["metric_eligible"] is False
    assert template_score["per_ability"][2]["scoreable_trace_count"] == 0

    finalized = deepcopy(template)
    for ability in finalized["ability_instances"]:
        ability["executed"] = True
    finalized_score = score_case(finalized, empty_casefile)
    assert finalized_score["counts"]["executed_attack_mapped_mandatory_abilities"] == 3
    assert finalized_score["counts"]["trace_producing_abilities"] == 2
    assert finalized_score["counts"]["ground_truth_trace_facts"] == 4
    assert finalized_score["counts"]["ability_denominator_trace_facts"] == 3
    assert finalized_score["counts"]["non_ability_atomic_trace_facts"] == 1
    assert finalized_score["metrics"]["trace_producing_ability_ratio"] == pytest.approx(2 / 3)
    assert finalized_score["ability_metrics"]["denominator"] == 2
    assert finalized_score["per_ability"][0]["included_in_ability_denominator"] is False
    assert finalized_score["per_ability"][0]["atomic_trace_count"] == 1
    assert finalized_score["per_ability"][0]["atomic_unmatched_trace_count"] == 1
    assert finalized_score["per_ability"][2]["included_in_ability_denominator"] is False

    target_path = finalized["target"]["path"]
    action_casefile = {
        **empty_casefile,
        "action_results": [
            {
                "tool": "kill_process",
                "success": True,
                "arguments": {"expected_path": target_path},
                "data": {},
            },
            {
                "tool": "remove_file",
                "success": True,
                "arguments": {"file_path": target_path},
                "data": {},
            },
            {
                "tool": "remove_registry",
                "success": True,
                "arguments": {
                    "reg_path": r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    "value_name": "C2TraceBench_#{c2trace.manx_name}",
                },
                "data": {},
            },
        ],
    }
    action_score = score_case(finalized, action_casefile)
    assert action_score["counts"]["response_action_tp"] == 3
    assert action_score["counts"]["response_action_fp"] == 0
    assert action_score["counts"]["response_action_fn"] == 0


def test_executed_support_trace_scores_atomically_but_not_as_an_ability_hit() -> None:
    path = r"C:\Users\Public\c2t_support.exe"
    ground_truth = {
        "case_id": "support-scope",
        "ability_instances": [
            _ability(
                "support-stage",
                "support-ability",
                [_trace("support-file", "file", {"path": path, "sha256": "ab" * 32})],
                attack_mapped=False,
                mandatory=False,
                metric_eligible=False,
                atomic_trace_eligible=True,
            ),
            _ability(
                "mapped-network",
                "mapped-ability",
                [
                    _trace(
                        "mapped-network-trace",
                        "network_connection",
                        {"remote_address": "10.0.0.2", "remote_port": 7010},
                    )
                ],
                atomic_trace_eligible=True,
            ),
        ],
    }
    casefile = {
        "case_id": "support-scope",
        "findings": [
            _finding(
                "payload",
                "payload_file_verified",
                {"exists": True, "path": path, "sha256": "AB" * 32},
            )
        ],
        "action_results": [],
    }

    score = score_case(ground_truth, casefile)

    assert score["counts"]["ground_truth_trace_facts"] == 2
    assert score["counts"]["ability_denominator_trace_facts"] == 1
    assert score["counts"]["non_ability_atomic_trace_facts"] == 1
    assert score["counts"]["trace_tp"] == 1
    assert score["counts"]["trace_fp"] == 0
    assert score["counts"]["trace_fn"] == 1
    assert score["ability_metrics"]["denominator"] == 1
    support = score["per_ability"][0]
    assert support["hit"] is None
    assert support["coverage"] is None
    assert support["atomic_matched_trace_count"] == 1
    assert support["atomic_matched_traces"][0]["trace_id"] == "support-file"


def test_unregistered_transient_process_parent_edge_is_not_an_atomic_fp() -> None:
    ground_truth = {
        "case_id": "transient-parent",
        "ability_instances": [
            _ability(
                "start",
                "start-ability",
                [_trace("process", "process", {"pid": 9001, "path": r"C:\x.exe"})],
                atomic_trace_eligible=True,
            )
        ],
    }
    root = {"pid": 9001, "path": r"C:\x.exe", "name": "x.exe"}
    transient_parent = {"pid": 8123, "path": r"C:\Windows\powershell.exe", "name": "powershell.exe"}
    casefile = {
        "case_id": "transient-parent",
        "findings": [
            _finding(
                "tree",
                "process_tree",
                {"root": root, "chain": [root, transient_parent]},
            )
        ],
        "action_results": [],
    }

    score = score_case(ground_truth, casefile)

    assert score["counts"]["trace_tp"] == 1
    assert score["counts"]["trace_fp"] == 0
    assert score["counts"]["predicted_trace_observations"] == 1


def test_response_metrics_ignore_dry_run_and_failed_actions() -> None:
    ground_truth = {
        "case_id": "response-outcome",
        "ability_instances": [],
        "expected": {
            "response": [
                {"tool": "kill_process", "target": r"C:\Temp\target.exe", "required": True},
                {"tool": "remove_file", "target": r"C:\Temp\target.exe", "required": True},
            ]
        },
    }
    casefile = {
        "case_id": "response-outcome",
        "findings": [],
        "action_results": [
            {
                "tool": "kill_process",
                "success": True,
                "arguments": {"expected_path": r"C:\Temp\target.exe"},
                "data": {"dry_run": True},
            },
            {
                "tool": "remove_file",
                "success": False,
                "arguments": {"file_path": r"C:\Temp\target.exe"},
                "data": {},
            },
        ],
    }

    score = score_case(ground_truth, casefile)

    assert score["counts"]["predicted_response_actions"] == 0
    assert score["counts"]["response_action_tp"] == 0
    assert score["counts"]["response_action_fn"] == 2
    assert score["metrics"]["response_action_recall"] == 0.0


def test_writes_json_markdown_and_cli(tmp_path: Path) -> None:
    gt = {"case_id": "cli", "ability_instances": []}
    casefile = {"case_id": "cli", "findings": [], "action_results": []}
    score = score_case(gt, casefile)
    direct = tmp_path / "direct"
    write_score_outputs(score, direct / "score.json", direct / "score.md")
    assert json.loads((direct / "score.json").read_text(encoding="utf-8"))["case_id"] == "cli"
    assert "C2Trace Bench v3 Score" in (direct / "score.md").read_text(encoding="utf-8")

    gt_path = tmp_path / "ground_truth.json"
    case_path = tmp_path / "casefile.json"
    gt_path.write_text(json.dumps(gt), encoding="utf-8")
    case_path.write_text(json.dumps(casefile), encoding="utf-8")
    output = tmp_path / "cli-out"
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/score_c2trace_bench_v3.py",
            "--ground-truth",
            str(gt_path),
            "--casefile",
            str(case_path),
            "--output-dir",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert (output / "score.json").exists()
    assert (output / "score.md").exists()
