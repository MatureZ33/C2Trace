"""C2Trace Bench v4 AURORA-CHAIN-002 ReAct baseline runner.

Deploys the same Sliver/Aurora attack as the C2Trace runner, but replaces
the C2Trace agent with a LangGraph ReAct agent.  Reuses run_live_trial for
attack deployment, evidence collection, scoring, and cleanup.
"""
from __future__ import annotations
import argparse, os, sys, time, json
from pathlib import Path
from urllib.parse import urlparse
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c2trace.bench_v3.caldera_client import CalderaClient
from c2trace.bench_v4.runtime import BenchV4RuntimeError, build_runtime_values, discover_case_paths, load_runtime_case
from c2trace.bench_v4.controller_support import start_suricata, stop_suricata, write_json_atomic
from c2trace.bench_v4.live_controller import TrialExecutionConfig, run_live_trial
from c2trace.bench_v4.live_safety import LivePreflightConfig, run_live_preflight, validate_payload_staging_receipt
from c2trace.bench_v4.reproducibility import build_software_lock
from c2trace.bench_v4.meterpreter_runner import run_meterpreter_bootstrap_phase, resolve_meterpreter_target_phase, run_meterpreter_scenario_phase
from c2trace.bench_v4.windows_adapter import WindowsLivePreflightDependencies
from c2trace.config import load_env_file
from c2trace.baseline.formal_result_manifest import build_result_manifest, write_result_manifest
from c2trace.baseline.react_runner import (
    BASELINE_MODEL,
    MAX_LLM_CALLS,
    MAX_TOOL_CALLS,
    MAX_TOTAL_TOKENS,
    event_to_baseline_minimal_alert,
    resolve_baseline_model,
    run_react_agent,
)


BENCH_ROOT = ROOT / "experiments" / "c2trace_bench_v4"
RESULTS_ROOT = ROOT / "case_study" / "runs"
KB_ROOT = ROOT / "kb"


def _inject_recent_files_baseline(output_dir, case_id, node_id, since_utc, until_utc):
    """Run check_recent_files with correct system-level parameters.

    This mirrors C2Trace's orchestrator auto-injection.  The ReAct model
    may call check_recent_files with wrong root_aliases; rather than depend
    on the model, we inject a correct system-level call.
    """
    from c2trace.tools.system import WindowsToolBackend
    backend = WindowsToolBackend()
    args = {
        "since_utc": since_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "until_utc": until_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "root_aliases": ["users_public", "appdata"],
        "max_depth": 0,
        "max_results": 128,
        "max_file_size": 4194304,
    }
    import time as _time
    started = _time.perf_counter()
    try:
        result = backend.check_recent_files(**args)
        ar = {
            "result_id": "ar-baseline-recent-files",
            "node_id": node_id,
            "tool": "check_recent_files",
            "success": result.success,
            "data": result.data,
            "error": result.error,
            "elapsed_ms": result.elapsed_ms or (_time.perf_counter() - started) * 1000,
            "arguments": args,
            "created_at": _now_utc(),
        }
    except Exception as exc:
        ar = {
            "result_id": "ar-baseline-recent-files",
            "node_id": node_id,
            "tool": "check_recent_files",
            "success": False,
            "data": None,
            "error": str(exc),
            "elapsed_ms": (_time.perf_counter() - started) * 1000,
            "arguments": args,
            "created_at": _now_utc(),
        }
    return ar


def _build_react_target_lock(casefile, case_id, run_id, event, artifact):
    """Build a response_target_lock from ReAct's investigation tool results.

    This extracts the real PID, path, sha256, and network identity that ReAct
    discovered through check_network / check_process / check_file_metadata.
    It does NOT read Ground Truth — only the tool observation data that ReAct
    itself collected.  If the investigation did not find a target, the lock
    fields remain empty and the dry-run gate will reject it (correct behavior).
    """
    import ntpath as _nt
    import re as _re

    def _norm(value):
        text = str(value or "").strip().strip('"')
        return _nt.normcase(_nt.normpath(text)) if text else ""

    action_results = casefile.get("action_results") or []
    network_rows: list[dict] = []
    process_rows: list[dict] = []
    file_rows: list[dict] = []
    for ar in action_results:
        if not isinstance(ar, dict) or ar.get("success") is not True:
            continue
        tool = str(ar.get("tool") or "")
        data = ar.get("data") if isinstance(ar.get("data"), dict) else {}
        if tool == "check_network":
            network_rows.extend(row for row in (data.get("connections") or []) if isinstance(row, dict))
        elif tool == "check_process":
            process_rows.extend(row for row in (data.get("processes") or []) if isinstance(row, dict))
        elif tool == "check_process_tree":
            for tree in data.get("trees") or []:
                root = tree.get("root") if isinstance(tree, dict) else None
                if isinstance(root, dict):
                    process_rows.append(root)
        elif tool == "check_file_metadata":
            row = data.get("file")
            if isinstance(row, dict):
                file_rows.append(row)

    def _int(value):
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    def _same_path(left, right):
        return _norm(left) == _norm(right) and bool(_norm(left))

    validation_errors: list[str] = []
    alert_remote = str(event.get("dest_ip") or "").strip()
    alert_port = _int(event.get("dest_port"))
    matching_network = [
        row for row in network_rows
        if _int(row.get("pid")) > 0
        and (not alert_remote or str(row.get("remote_address") or "") == alert_remote)
        and (not alert_port or _int(row.get("remote_port")) == alert_port)
    ]
    if len(matching_network) != 1:
        validation_errors.append(
            f"network identity is ambiguous or missing ({len(matching_network)} matching rows)"
        )
        connection = matching_network[0] if len(matching_network) == 1 else {}
    else:
        connection = matching_network[0]

    pid = _int(connection.get("pid"))
    network = {
        "protocol": "tcp",
        "local_address": str(connection.get("local_address") or ""),
        "local_port": _int(connection.get("local_port")),
        "remote_address": str(connection.get("remote_address") or ""),
        "remote_port": _int(connection.get("remote_port")),
        "mode": "outbound_active_flow",
        "direction": "victim_to_remote",
        "listener_address": "",
    } if connection else {}

    matching_process = [row for row in process_rows if _int(row.get("pid")) == pid and pid > 0]
    if len(matching_process) != 1:
        validation_errors.append(
            f"process identity does not uniquely match network PID ({len(matching_process)} rows)"
        )
        process_row = matching_process[0] if len(matching_process) == 1 else {}
    else:
        process_row = matching_process[0]
    process_path = str(process_row.get("path") or connection.get("process_path") or "")
    process_name = str(process_row.get("name") or connection.get("process_name") or "")
    creation_time = str(
        process_row.get("creation_time_utc")
        or process_row.get("creation_date")
        or ""
    )
    if not process_path or not creation_time:
        validation_errors.append("process path or creation time is missing")

    matching_file = [row for row in file_rows if _same_path(row.get("path"), process_path)]
    if len(matching_file) != 1:
        validation_errors.append(
            f"file metadata does not uniquely match process path ({len(matching_file)} rows)"
        )
        file_row = matching_file[0] if len(matching_file) == 1 else {}
    else:
        file_row = matching_file[0]
    file_path = str(file_row.get("path") or "")
    file_sha256 = str(file_row.get("sha256") or "").strip().lower()
    if not _re.fullmatch(r"[0-9a-f]{64}", file_sha256):
        validation_errors.append("file metadata does not contain a valid SHA-256")

    process = {
        "pid": pid,
        "name": process_name,
        "creation_time_utc": creation_time,
        "path": process_path,
        "canonical_path": _norm(process_path),
        "sha256": file_sha256,
    }
    file_info = {
        "path": file_path,
        "canonical_path": _norm(file_path),
        "sha256": file_sha256,
        "artifact_role": "implant_executable",
    }
    # Source binding from Suricata event (not Ground Truth — this is the
    # alert that both systems receive as input)
    source = {
        "flow_id": str(event.get("flow_id") or ""),
        "event_sha256": str(artifact.get("event_sha256") or ""),
        "timestamp": str(event.get("timestamp") or ""),
    }

    lock = {
        "schema_version": "c2trace.response_target_lock.v2",
        "lock_id": "",
        "acquired_at": _now_utc(),
        "case_id": case_id,
        "run_id": run_id,
        "target_paw": "",
        "group": "",
        "host": "",
        "contact": "",
        "network": network,
        "process": process,
        "file": file_info,
        "source": source,
        "persistence_targets": [],
        "secondary_pid": 0,
        "target_type": "other",
        "network_mode": "outbound_active_flow",
        "response_policy": {
            "target_lock_valid": not validation_errors,
            "validation_errors": validation_errors,
            "binding_source": "react_investigation_observations",
        },
    }
    return lock


def _now_utc():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _make_react_runner(case_id: str, run_id: str):
    """Create a c2trace_runner-compatible callable that runs ReAct instead of C2Trace."""

    def react_runner(
        *,
        project_root,
        python,
        case_id: str,
        victim_ip: str,
        eve_path,
        event,
        artifact,
        output_dir,
        log_path,
        protected_manifest,
        response_tools,
        reviewed_casefile=None,
        execute=False,
    ):
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Use the same direction-aware MinimalAlert conversion as C2Trace.
        # The alert is the only model-visible seed; Ground Truth is not used.
        minimal_alert_obj, _ = event_to_baseline_minimal_alert(
            event, case_id=case_id, victim_ip=victim_ip
        )
        minimal_alert = minimal_alert_obj.to_dict()
        casefile = run_react_agent(
            case_id=case_id,
            source_alert=minimal_alert,
            kb_root=KB_ROOT,
            output_dir=output_dir,
            execute_response=execute,
            max_tool_calls=MAX_TOOL_CALLS,
            max_llm_calls=MAX_LLM_CALLS,
            max_total_tokens=MAX_TOTAL_TOKENS,
            model=BASELINE_MODEL,
        )

        if execute:
            casefile["final_status"] = "completed"
        else:
            casefile["final_status"] = "completed_dry_run"

        # Build C2Trace-compatible strategy_tree from ReAct tool calls
        tool_calls_list = casefile.get("tool_observations") or []
        nodes_list = []
        for idx_tc, tc in enumerate(tool_calls_list):
            tool_name = str(tc.get("tool") or "")
            node = {
                "node_id": "react-node-" + str(idx_tc),
                "type": "investigate" if tool_name not in ("kill_process", "remove_file", "remove_registry", "remove_scheduled_task", "remove_service") else "respond",
                "goal": "ReAct tool call: " + tool_name,
                "tool": tool_name,
                "arguments": dict(tc.get("arguments") or {}),
                "condition": "",
                "requires": [],
                "status": "completed" if tc.get("success") else "failed",
                "assigned_to": "react-agent",
                "evidence_refs": [],
                "on_success": [],
                "on_failure": [],
                "audit_decision_id": None,
                "result_id": "react-result-" + str(idx_tc),
                "metadata": {},
            }
            if tool_name == "check_recent_files":
                node["metadata"]["c2trace_policy"] = "c2trace.baseline.recent_files.v1"
            nodes_list.append(node)

        # Preserve only observations actually produced during this ReAct run.
        # A post-hoc system observation would not have been visible to the
        # model and would make the CaseFile/Prediction IR provenance unclear.
        action_results = casefile.get("action_results") or []
        for idx_ar, ar in enumerate(action_results):
            if idx_ar < len(nodes_list):
                ar["node_id"] = nodes_list[idx_ar]["node_id"]
        casefile["action_results"] = action_results
        casefile["strategy_tree"] = {"nodes": nodes_list, "edges": []}
        # Build a real response_target_lock from ReAct's own investigation
        # results (tool observations), NOT from Ground Truth.  This mirrors
        # how C2Trace builds its lock from its dry-run StrategyTree findings.
        casefile["response_target_lock"] = _build_react_target_lock(
            casefile, case_id, run_id, event, artifact
        )
        (output_dir / "target_lock_validation.json").write_text(
            json.dumps(
                casefile["response_target_lock"].get("response_policy", {}),
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        (output_dir / "casefile.json").write_text(
            json.dumps(casefile, ensure_ascii=False, indent=2, default=str) + "\n",
            encoding="utf-8",
        )

        metrics = casefile.get("operational_metrics", {})
        phase_elapsed = {"investigate": 0.0, "response": 0.0, "verify": 0.0}
        for call in casefile.get("tool_observations") or []:
            classification = str(call.get("classification") or "")
            phase = {
                "investigation": "investigate",
                "response": "response",
                "verification": "verify",
            }.get(classification)
            if phase:
                phase_elapsed[phase] += float(call.get("elapsed_ms") or 0.0)
        (output_dir / "run_metadata.json").write_text(
            json.dumps(
                {
                    "duration_ms": metrics.get("case_duration_ms"),
                    "llm_usage": {
                        "call_count": metrics.get("llm_calls", 0),
                        "requested_model": metrics.get("requested_model", "deepseek-chat"),
                        "response_models": metrics.get("response_models", []),
                        "prompt_tokens": metrics.get("prompt_tokens", 0),
                        "completion_tokens": metrics.get("completion_tokens", 0),
                        "total_tokens": metrics.get("total_tokens", 0),
                    },
                    "tool_usage": {
                        "call_count": metrics.get("tool_calls", 0),
                        "phase_elapsed_ms": phase_elapsed,
                    },
                    "budget": {
                        "max_tool_calls": metrics.get("max_tool_calls"),
                        "max_llm_calls": metrics.get("max_llm_calls"),
                        "max_total_tokens": metrics.get("max_total_tokens"),
                        "exceeded": metrics.get("budget_exceeded") is True,
                        "agent_error": metrics.get("agent_error") or None,
                    },
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        budget_exceeded = metrics.get("budget_exceeded", False)
        agent_error = bool(metrics.get("agent_error"))
        return SimpleNamespace(returncode=2 if budget_exceeded or agent_error else 0)

    return react_runner


def validate_caldera_url(value, kali_ip):
    url = value or "http://{}:8888".format(kali_ip)
    parsed = urlparse(url)
    if parsed.scheme.lower() != "http" or parsed.hostname != kali_ip or parsed.port != 8888:
        raise BenchV4RuntimeError("CALDERA URL must be http://{}:8888".format(kali_ip))
    return url.rstrip("/")


def _compute_baseline_hashes() -> tuple[str, str, str]:
    """Compute prompt, KB, and tool-schema hashes for the formal manifest."""
    from c2trace.baseline.hash_utils import compute_baseline_prompt_hashes, compute_kb_hash, compute_tool_schema_hash
    from c2trace.tools.system import WindowsToolBackend
    from c2trace.baseline.react_agent import build_tools, ToolCallRecorder
    backend = WindowsToolBackend(execute_response=True)
    recorder = ToolCallRecorder(backend, max_calls=MAX_TOOL_CALLS)
    tools = build_tools(recorder)
    return (compute_baseline_prompt_hashes(KB_ROOT)["execute"], compute_kb_hash(KB_ROOT), compute_tool_schema_hash(tools))


def _compute_baseline_prompt_hashes() -> tuple[str, str]:
    from c2trace.baseline.hash_utils import compute_baseline_prompt_hashes
    hashes = compute_baseline_prompt_hashes(KB_ROOT)
    return hashes["dry_run"], hashes["execute"]


def _write_formal_manifest(*, batch_root: Path, trial_root: Path, runtime, run_id: str, model: str) -> Path:
    """Freeze the hashes needed to deterministically re-score a ReAct trial."""
    execute_prediction = trial_root / "c2trace_execute" / "prediction_ir.json"
    dry_prediction = trial_root / "c2trace_dryrun" / "prediction_ir.json"
    prediction_path = execute_prediction if execute_prediction.is_file() else dry_prediction
    prompt_hash, kb_hash, tool_schema_hash = _compute_baseline_hashes()
    prompt_dry_run_hash, prompt_execute_hash = _compute_baseline_prompt_hashes()
    trial_result_path = trial_root / "trial_result.json"
    failure_record_path = trial_root / "infrastructure_invalid.json"
    result_path = trial_result_path if trial_result_path.is_file() else None
    failure_path = failure_record_path if failure_record_path.is_file() else None
    result_document = {}
    result_document_path = result_path or failure_path
    if result_document_path is not None:
        try:
            result_document = json.loads(result_document_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            result_document = {}
    manifest = build_result_manifest(
        case_id=runtime.case_id,
        pair_id=f"{runtime.case_id}-react",
        run_id=run_id,
        system="react",
        model=model,
        config={
            "temperature": 0,
            "max_tool_calls_per_stage": MAX_TOOL_CALLS,
            "max_llm_calls_per_stage": MAX_LLM_CALLS,
            "max_total_tokens_per_stage": MAX_TOTAL_TOKENS,
            "execution_contract": "independent_response_contract",
        },
        prediction_ir=prediction_path,
        casefile=trial_root / "scoring_casefile.json",
        score=trial_root / "score.json",
        ground_truth=trial_root / "ground_truth.json",
        post_state=trial_root / "post_response_validation.json",
        trial_result=result_path,
        failure_record=failure_path,
        trial_class=str(result_document.get("trial_class") or ""),
        tool_schema_hash=tool_schema_hash,
        kb_hash=kb_hash,
        prompt_hash=prompt_hash,
        prompt_dry_run_hash=prompt_dry_run_hash,
        prompt_execute_hash=prompt_execute_hash,
        recompute_command=(
            "python -m c2trace.bench_v4.scorer "
            f"--ground-truth {trial_root / 'ground_truth.json'} "
            f"--casefile {trial_root / 'scoring_casefile.json'}"
        ),
    )
    target = batch_root / "formal_result_manifest.json"
    write_result_manifest(target, manifest)
    return target


def main():
    parser = argparse.ArgumentParser(description="AURORA-CHAIN-002 ReAct baseline runner")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--kali-ip", default="192.168.21.132")
    parser.add_argument("--victim-ip", default="192.168.21.145")
    parser.add_argument("--interface", default="Ethernet0")
    parser.add_argument("--base-url", default="")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--vm-snapshot-id", default="strategy_a_no_snapshot")
    parser.add_argument("--control-path", default=r"C:\Users\Public\c2t_control_exploratory_20260917.exe")
    parser.add_argument("--control-sha256", default="0BC9E6AB522D4295BDF7768BE2F2DF00E13792AB9B0537A5A711A4FC4727A7EE")
    parser.add_argument("--control-host", default="DESKTOP-G9IIQ2P")
    parser.add_argument("--suricata-exe", default=r"C:\Program Files\Suricata\suricata.exe")
    parser.add_argument("--suricata-config", default=r"C:\Program Files\Suricata\suricata.yaml")
    parser.add_argument("--operation-timeout", type=float, default=360.0)
    parser.add_argument("--poll-seconds", type=float, default=3.0)
    parser.add_argument("--evidence-timeout", type=float, default=45.0)
    args = parser.parse_args()

    load_env_file(ROOT / ".env")
    api_key = args.api_key or os.environ.get("CALDERA_API_KEY", "ADMIN123")
    base_url = validate_caldera_url(args.base_url, args.kali_ip)
    model = resolve_baseline_model(os.environ.get("DEEPSEEK_MODEL"))
    run_id = args.run_id or "react-aurora002-001-{}".format(time.strftime("%Y%m%dT%H%M%SZ"))
    print("[1] Run ID: {}".format(run_id))

    case_paths = discover_case_paths(BENCH_ROOT, collection="aurora", case_id="AURORA-CHAIN-002")
    runtime = load_runtime_case(BENCH_ROOT, case_paths[0])
    print("[2] Loaded case: {}".format(runtime.case_id))

    client = CalderaClient(base_url, api_key)
    print("[3] CALDERA client connected: {}".format(base_url))

    batch_id = "react-aurora-qual-{}".format(time.strftime("%Y%m%dT%H%M%SZ"))
    batch_root = (RESULTS_ROOT / batch_id).resolve()
    batch_root.mkdir(parents=True, exist_ok=True)
    trial_root = batch_root / "trials" / run_id
    write_json_atomic(batch_root / "software_lock.json", build_software_lock(ROOT, vm_snapshot_id=args.vm_snapshot_id, model=model))

    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    preflight_config = LivePreflightConfig(
        case_id=runtime.case_id, kali_ip=args.kali_ip, victim_ip=args.victim_ip,
        suricata_executable=args.suricata_exe, suricata_configuration=args.suricata_config,
        npcap_driver=str(system_root / "System32" / "drivers" / "npcap.sys"),
        capture_interface=args.interface, results_path=str(batch_root),
        allowed_results_root=str(RESULTS_ROOT), vm_snapshot_id=args.vm_snapshot_id,
        control_sandcat_path=args.control_path, control_sandcat_sha256=args.control_sha256.casefold(),
        control_host=args.control_host, require_driver=True, model_name=model)
    dependencies = WindowsLivePreflightDependencies(
        project_root=ROOT, caldera_client=client, active_vm_snapshot_id=args.vm_snapshot_id,
        model_name=model, api_key_present=bool(os.environ.get("DEEPSEEK_API_KEY", "").strip()))
    preflight_receipt = run_live_preflight(preflight_config, dependencies)
    write_json_atomic(batch_root / "preflight.json", preflight_receipt)
    print("[4] Preflight passed")

    payload_authorization = validate_payload_staging_receipt(runtime, caldera_server=base_url, receipt=None)
    print("[5] Payload gate: required={}".format(payload_authorization.required))

    values = build_runtime_values(runtime, run_id=run_id, victim_ip=args.victim_ip, kali_ip=args.kali_ip, webshell_port=None, appdata="")
    print("[6] Target path: {}".format(values.target_path))

    suricata_log_dir = batch_root / "suricata"
    suricata_binding = preflight_receipt.get("suricata", {})
    capture_device = str(suricata_binding.get("capture_device") or "")
    if not capture_device:
        raise BenchV4RuntimeError("preflight did not freeze a Suricata capture device")
    eve_path = start_suricata(
        project_root=ROOT, bench_root=BENCH_ROOT, interface=capture_device,
        kali_ip=args.kali_ip, log_dir=suricata_log_dir,
        log_path=batch_root / "suricata_start.txt",
        suricata_exe=args.suricata_exe, suricata_config=args.suricata_config)
    print("[7] Suricata started: {}".format(eve_path))

    try:
        react_runner_fn = _make_react_runner(case_id=runtime.case_id, run_id=run_id)
        try:
            trial_result = run_live_trial(
                client=client, runtime=runtime, values=values,
                preflight_receipt=preflight_receipt,
                payload_authorization=payload_authorization,
                config=TrialExecutionConfig(
                    project_root=ROOT, result_root=trial_root, eve_path=eve_path,
                    python=Path(sys.executable).resolve(), caldera_server=base_url,
                    operation_timeout=args.operation_timeout,
                    poll_seconds=args.poll_seconds,
                    evidence_timeout=args.evidence_timeout,
                    baseline_mode=True),
                bootstrap_phase_runner=run_meterpreter_bootstrap_phase,
                target_phase_resolver=resolve_meterpreter_target_phase,
                scenario_phase_runner=run_meterpreter_scenario_phase,
                c2trace_runner=react_runner_fn)
            print("[8] Trial result: {}".format(trial_result.get("trial_class")))
            write_json_atomic(batch_root / "trial_result.json", trial_result)
        except Exception:
            # run_live_trial persists infrastructure_invalid.json before
            # raising. Freeze that failure as an auditable manifest too.
            manifest_path = _write_formal_manifest(
                batch_root=batch_root,
                trial_root=trial_root,
                runtime=runtime,
                run_id=run_id,
                model=model,
            )
            print("[8] Formal failure manifest: {}".format(manifest_path))
            raise
        manifest_path = _write_formal_manifest(
            batch_root=batch_root,
            trial_root=trial_root,
            runtime=runtime,
            run_id=run_id,
            model=model,
        )
        print("[8] Formal result manifest: {}".format(manifest_path))
    finally:
        try:
            stop_suricata(
                project_root=ROOT, log_dir=suricata_log_dir,
                log_path=batch_root / "suricata_stop.txt",
                suricata_exe=args.suricata_exe)
            print("[9] Suricata stopped")
        except Exception as exc:
            print("[9] Suricata stop failed: {}".format(exc))


try:
    from scripts.public_react_runner import make_public_react_runner as _make_public_react_runner
    from scripts.public_react_runner import write_public_formal_manifest as _write_public_formal_manifest
except ModuleNotFoundError:
    from public_react_runner import make_public_react_runner as _make_public_react_runner
    from public_react_runner import write_public_formal_manifest as _write_public_formal_manifest
_make_react_runner = _make_public_react_runner
_write_formal_manifest = _write_public_formal_manifest

if __name__ == "__main__":
    main()
