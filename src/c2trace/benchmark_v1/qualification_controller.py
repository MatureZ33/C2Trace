from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from c2trace.bench_v4.cleanup import execute_cleanup, prepare_cleanup
from c2trace.bench_v4.controller_support import (
    PersistentJournal,
    selected_source,
    utc_now,
    write_json_atomic,
)
from c2trace.bench_v4.evidence import PlanDrivenEvidenceCollector
from c2trace.bench_v4.live_controller import (
    TrialExecutionConfig,
    _agent_identity,
    _capture_with_wait,
    _cleanup_lock,
    _frozen_artifacts,
    _registry_expectations,
    _run_split_caldera_transaction,
    control_identity_from_preflight,
    freeze_target_identity,
    refresh_control_identity,
    refresh_driver_identity,
)
from c2trace.bench_v4.live_safety import (
    PayloadWriteAuthorization,
    PowerShellCleanupBackend,
)
from c2trace.bench_v4.runtime import (
    CalderaBootstrapPhaseResult,
    CalderaScenarioPhaseResult,
    CalderaTargetCandidate,
    RuntimeCase,
    RuntimeValues,
    resolve_caldera_target_phase,
    run_caldera_bootstrap_phase,
    run_caldera_scenario_phase,
)
from c2trace.bench_v4.transaction import (
    build_protected_processes_v2,
    evaluate_baseline_clean,
    evaluate_post_response,
)
from c2trace.bench_v4.windows_adapter import PowerShellCleanupTransport
from c2trace.bench_v4.windows_admin import BenchWindowsAdmin

from .qualification import build_root_qualification_trial, hash_evidence
from .qualification_checks import (
    evaluate_pre_cleanup_qualification,
    finalize_cleanup_check,
)
from .reference_response import build_reference_response_plan, execute_reference_response


ROOT_ID = "CTID-WEBSHELL-001"
EXECUTION_CASE_ID = "MEP-WINDOWS-WEBSHELL-01"


class QualificationControllerError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class QualificationExecutionConfig:
    project_root: Path
    result_root: Path
    eve_path: Path
    caldera_server: str
    trial_id: str
    repetition: int
    vm_snapshot_id: str
    software_lock_sha256: str
    root_id: str = ROOT_ID
    operation_timeout: float = 360.0
    poll_seconds: float = 3.0
    evidence_timeout: float = 45.0


def _default_cleanup(
    *,
    runtime: RuntimeCase,
    values: RuntimeValues,
    protected_manifest: Mapping[str, Any],
    before_response: Mapping[str, Any],
    score_path: Path,
    transport: PowerShellCleanupTransport,
) -> dict[str, Any]:
    target_lock = _cleanup_lock(protected_manifest, None)
    prepared = prepare_cleanup(
        runtime,
        values,
        target_lock=target_lock,
        protected_processes=protected_manifest["processes"],
        score_artifact=score_path,
        frozen_artifacts=_frozen_artifacts(before_response),
    )
    expected = protected_manifest["expected_target"]
    expected_hashes = {
        str(expected["path"]): str(expected["sha256"]).casefold()
    }
    backend = PowerShellCleanupBackend(
        transport=transport,
        actions=prepared.actions,
        run_id=values.run_id,
        allowed_roots=[r"C:\Users\Public"],
        expected_file_hashes=expected_hashes,
        registry_expectations=_registry_expectations(prepared.actions, before_response),
    )
    return execute_cleanup(prepared, backend)


def run_root_qualification_trial(
    *,
    client: Any,
    runtime: RuntimeCase,
    values: RuntimeValues,
    preflight_receipt: Mapping[str, Any],
    payload_authorization: PayloadWriteAuthorization,
    static_checks: Mapping[str, bool],
    config: QualificationExecutionConfig,
    runner: BenchWindowsAdmin | None = None,
    cleanup_transport: PowerShellCleanupTransport | None = None,
    bootstrap_phase_runner: Callable[..., CalderaBootstrapPhaseResult] = (
        run_caldera_bootstrap_phase
    ),
    target_phase_resolver: Callable[..., CalderaTargetCandidate] = (
        resolve_caldera_target_phase
    ),
    scenario_phase_runner: Callable[..., CalderaScenarioPhaseResult] = (
        run_caldera_scenario_phase
    ),
    target_freezer: Callable[..., dict[str, Any]] = freeze_target_identity,
    phase_transaction: Callable[..., Any] = _run_split_caldera_transaction,
    collector_factory: Callable[..., Any] = PlanDrivenEvidenceCollector,
    protected_builder: Callable[..., dict[str, Any]] = build_protected_processes_v2,
    poststate_evaluator: Callable[..., dict[str, Any]] = evaluate_post_response,
    reference_plan_builder: Callable[..., dict[str, Any]] = build_reference_response_plan,
    reference_executor: Callable[..., dict[str, Any]] = execute_reference_response,
    cleanup_executor: Callable[..., dict[str, Any]] = _default_cleanup,
    control_refresher: Callable[..., dict[str, Any] | None] = refresh_control_identity,
    driver_refresher: Callable[..., dict[str, Any] | None] = refresh_driver_identity,
) -> dict[str, Any]:
    """Qualify one root without invoking C2Trace, an LLM, or an Executor."""

    if config.root_id != ROOT_ID or runtime.case_id != EXECUTION_CASE_ID:
        raise QualificationControllerError("qualification controller is locked to CTID WebShell")
    if config.repetition not in {1, 2, 3}:
        raise QualificationControllerError("qualification repetition must be one, two, or three")
    if values.run_id not in config.trial_id:
        raise QualificationControllerError("trial_id must be bound to the unique RunId")
    trial_root = config.result_root.resolve()
    if trial_root.exists():
        raise QualificationControllerError(f"qualification Trial root already exists: {trial_root}")
    trial_root.mkdir(parents=True)
    journal = PersistentJournal(trial_root / "state.jsonl")
    started_at = utc_now()
    journal.append(
        "qualification_preregistered",
        details={
            "root_id": config.root_id,
            "case_id": runtime.case_id,
            "run_id": values.run_id,
            "trial_id": config.trial_id,
            "repetition": config.repetition,
            "c2trace_used": False,
            "llm_used": False,
        },
    )
    runner = runner or BenchWindowsAdmin(execute_response=False)
    cleanup_transport = cleanup_transport or PowerShellCleanupTransport(
        project_root=config.project_root, runner=runner
    )
    control_identity = control_identity_from_preflight(preflight_receipt)
    cleanup_completed = False
    side_effect_started = False
    try:
        baseline_collector = collector_factory(runtime=runtime, values=values, probe=runner)
        baseline = baseline_collector.capture_stage("baseline")
        write_json_atomic(trial_root / "evidence" / "baseline.json", baseline)
        baseline_gate = evaluate_baseline_clean(runtime, baseline)
        write_json_atomic(trial_root / "baseline_gate.json", baseline_gate)
        if baseline_gate.get("clean") is not True:
            raise QualificationControllerError("run-scoped residue exists at baseline")
        journal.append("baseline_captured")

        source_not_before = utc_now()
        journal.append("caldera_write_intent", status="intent")
        side_effect_started = True
        phase_config = TrialExecutionConfig(
            project_root=config.project_root,
            result_root=trial_root,
            eve_path=config.eve_path,
            python=config.project_root / ".venv" / "Scripts" / "python.exe",
            caldera_server=config.caldera_server,
            operation_timeout=config.operation_timeout,
            poll_seconds=config.poll_seconds,
            evidence_timeout=config.evidence_timeout,
        )
        phase, target_identity = phase_transaction(
            client=client,
            runtime=runtime,
            values=values,
            payload_authorization=payload_authorization,
            config=phase_config,
            runner=runner,
            trial_root=trial_root,
            journal=journal,
            bootstrap_phase_runner=bootstrap_phase_runner,
            target_phase_resolver=target_phase_resolver,
            scenario_phase_runner=scenario_phase_runner,
            target_freezer=target_freezer,
            checkpoint_hook=None,
        )

        before_collector = collector_factory(
            runtime=runtime,
            values=values,
            probe=runner,
            target_identity=target_identity,
            suricata_eve=config.eve_path,
            source_not_before_utc=source_not_before,
        )
        before = _capture_with_wait(
            before_collector,
            "before_response",
            timeout=config.evidence_timeout,
            poll_seconds=config.poll_seconds,
        )
        write_json_atomic(trial_root / "evidence" / "before_response.json", before)
        source_event, source_artifact = selected_source(before)
        write_json_atomic(trial_root / "suricata_event.json", source_event)
        write_json_atomic(trial_root / "suricata_artifact.json", source_artifact)
        protected = protected_builder(
            runtime,
            values,
            control_identity=control_identity,
            target_identity=target_identity,
            before_response_evidence=before,
            source_event=source_event,
            source_artifact=source_artifact,
            source_not_before_utc=source_not_before,
        )
        write_json_atomic(trial_root / "protected_processes.v2.json", protected)
        target = protected["expected_target"]
        plan = reference_plan_builder(
            root_id=config.root_id,
            run_id=values.run_id,
            target=target,
            protected_processes=protected["processes"],
        )
        write_json_atomic(trial_root / "reference_response_plan.json", plan)
        reference_receipt = reference_executor(plan, cleanup_transport)
        write_json_atomic(trial_root / "reference_response_receipt.json", reference_receipt)
        journal.append("reference_response_complete")

        # A new collector instance is deliberately created after the response.
        post_collector = collector_factory(
            runtime=runtime,
            values=values,
            probe=runner,
            target_identity=target_identity,
            suricata_eve=config.eve_path,
            source_not_before_utc=source_not_before,
        )
        after = post_collector.capture_stage("after_execute")
        write_json_atomic(trial_root / "evidence" / "fresh_poststate.json", after)
        observed_control = control_refresher(client, runner, control_identity)
        expected_driver = _agent_identity(phase.driver_agent)
        observed_driver = driver_refresher(client, phase.driver_agent)
        post = poststate_evaluator(
            runtime,
            after,
            protected_manifest=protected,
            observed_control=observed_control,
            expected_driver=expected_driver,
            observed_driver=observed_driver,
        )
        write_json_atomic(trial_root / "poststate_validation.json", post)
        fresh_poststate = {
            "schema_version": "c2trace.benchmark.v1.fresh_poststate_receipt",
            "new_collector_instance": post_collector is not before_collector,
            "read_only": after.get("read_only") is True,
            "captured_at_utc": after.get("captured_at"),
            "evidence_path": str(trial_root / "evidence" / "fresh_poststate.json"),
            "c2trace_used": False,
            "llm_used": False,
        }
        write_json_atomic(trial_root / "fresh_poststate_receipt.json", fresh_poststate)

        pre_score = evaluate_pre_cleanup_qualification(
            static_checks=static_checks,
            kali_ip=values.kali_ip,
            victim_ip=values.victim_ip,
            listener_port=int(values.webshell_port or 0),
            target=target,
            source_event=source_event,
            scenario_links=phase.scenario_links,
            before_response=before,
            reference_response=reference_receipt,
            fresh_poststate=fresh_poststate,
            poststate_validation=post,
        )
        pre_score.update(
            {
                "root_id": config.root_id,
                "trial_id": config.trial_id,
                "run_id": values.run_id,
                "scored_at_utc": utc_now(),
            }
        )
        score_path = write_json_atomic(trial_root / "pre_cleanup_score.json", pre_score)
        journal.append("qualification_scored_before_cleanup")
        if pre_score.get("technical_gate_passed") is not True:
            raise QualificationControllerError(
                "qualification technical gate failed before external cleanup"
            )

        cleanup_receipt = cleanup_executor(
            runtime=runtime,
            values=values,
            protected_manifest=protected,
            before_response=before,
            score_path=score_path,
            transport=cleanup_transport,
        )
        write_json_atomic(trial_root / "external_cleanup.json", cleanup_receipt)
        cleanup_completed = True
        final_checks = finalize_cleanup_check(
            pre_score,
            pre_cleanup_score_path=score_path,
            cleanup_receipt=cleanup_receipt,
        )
        write_json_atomic(trial_root / "qualification_checks.json", final_checks)
        if final_checks.get("passed") is not True:
            raise QualificationControllerError("post-scoring cleanup gate failed")
        journal.append("external_cleanup_complete")
        journal.append("qualification_evidence_frozen")

        evidence_paths = [
            path
            for path in trial_root.rglob("*")
            if path.is_file() and path.name != "qualification_trial.json"
        ]
        evidence_hashes = hash_evidence(evidence_paths, root=trial_root)
        trial_receipt = build_root_qualification_trial(
            root_id=config.root_id,
            trial_id=config.trial_id,
            run_id=values.run_id,
            repetition=config.repetition,
            checks=final_checks["checks"],
            evidence_hashes=evidence_hashes,
            vm_snapshot_id=config.vm_snapshot_id,
            software_lock_sha256=config.software_lock_sha256,
            started_at_utc=started_at,
            ended_at_utc=utc_now(),
            reference_response=reference_receipt,
            poststate={"fresh_query": fresh_poststate, "validation": post},
        )
        write_json_atomic(trial_root / "qualification_trial.json", trial_receipt)
        return trial_receipt
    except Exception as exc:
        failure = {
            "schema_version": "c2trace.benchmark.v1.qualification_failure",
            "root_id": config.root_id,
            "trial_id": config.trial_id,
            "run_id": values.run_id,
            "repetition": config.repetition,
            "failed_at_utc": utc_now(),
            "error_type": type(exc).__name__,
            "error": str(exc),
            "cleanup_completed": cleanup_completed,
            "automatic_retry": False,
            "manual_reconciliation_required": side_effect_started and not cleanup_completed,
            "c2trace_used": False,
            "llm_used": False,
        }
        write_json_atomic(trial_root / "qualification_failure.json", failure)
        journal.append("qualification_trial_failed", status="failed", details=failure)
        raise QualificationControllerError(str(exc)) from exc


__all__ = [
    "QualificationControllerError",
    "QualificationExecutionConfig",
    "run_root_qualification_trial",
]
