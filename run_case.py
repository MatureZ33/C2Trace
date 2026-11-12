from __future__ import annotations

import argparse
import hashlib
from importlib.metadata import version as package_version
import json
import platform
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from c2trace.agents import AuditorAgent, ExecutorAgent, PlannerAgent
from c2trace.agents.target_identity import TargetIdentityValidator
from c2trace.config import load_env_file
from c2trace.kb import load_c2kb
from c2trace.models import CaseFile, MinimalAlert, ValidationError
from c2trace.orchestrator import RecentFileDiscoveryPolicy, WorkflowController
from c2trace.mcp.client import McpTransportError, StdioMcpToolClient
from c2trace.reporter import Reporter
from c2trace.suricata import (
    SuricataAlertError,
    SuricataFilters,
    SuricataSelection,
    select_suricata_alert_with_artifact,
)
from c2trace.target_safety import (
    TargetSafetyInputError,
    load_protected_processes,
    load_reviewed_target,
)
from c2trace.tools import READ_ONLY_TOOLS, RESPONSE_TOOLS


def write_outputs(case, output: str, *, run_metadata: dict | None = None) -> None:
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "casefile.json").write_text(json.dumps(case.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    if case.final_report:
        (out / "report.md").write_text(Reporter.to_markdown(case.final_report), encoding="utf-8")
    log_lines = [json.dumps(item, ensure_ascii=False) for item in case.to_dict().get("timeline", [])]
    (out / "execution_log.jsonl").write_text("\n".join(log_lines) + ("\n" if log_lines else ""), encoding="utf-8")
    if run_metadata is not None:
        (out / "run_metadata.json").write_text(
            json.dumps(run_metadata, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


def cli_exit_code_for_status(final_status: str) -> int:
    return 0 if final_status in {"completed", "completed_dry_run"} else 1


def summarize_llm_usage(planner: Any, auditor: Any) -> dict[str, Any]:
    calls: list[dict[str, Any]] = []
    for role, agent in (("planner", planner), ("auditor", auditor)):
        client = getattr(agent, "llm_client", None)
        records = getattr(client, "usage_records", [])
        if not isinstance(records, list):
            continue
        for record in records:
            if isinstance(record, dict):
                calls.append({"role": role, **record})
    return {
        "call_count": len(calls),
        "successful_call_count": sum(1 for item in calls if item.get("success") is True),
        "prompt_tokens": sum(int(item.get("prompt_tokens") or 0) for item in calls),
        "completion_tokens": sum(int(item.get("completion_tokens") or 0) for item in calls),
        "total_tokens": sum(int(item.get("total_tokens") or 0) for item in calls),
        "elapsed_ms": round(sum(float(item.get("elapsed_ms") or 0.0) for item in calls), 3),
        "calls": calls,
    }


def summarize_tool_usage(case: Any) -> dict[str, Any]:
    results = list(getattr(case, "action_results", []) or [])
    by_tool: dict[str, dict[str, Any]] = {}
    node_types: dict[str, str] = {}
    strategy = getattr(case, "strategy_tree", None)
    for node in list(getattr(strategy, "nodes", []) or []):
        node_types[str(getattr(node, "node_id", ""))] = str(
            getattr(getattr(node, "type", None), "value", "")
        )
    phase_elapsed_ms = {"investigate": 0.0, "response": 0.0, "verify": 0.0, "other": 0.0}
    for result in results:
        tool = str(getattr(result, "tool", "") or "unknown")
        elapsed = float(getattr(result, "elapsed_ms", 0.0) or 0.0)
        entry = by_tool.setdefault(tool, {"call_count": 0, "success_count": 0, "elapsed_ms": 0.0})
        entry["call_count"] += 1
        entry["success_count"] += int(getattr(result, "success", False) is True)
        entry["elapsed_ms"] += elapsed
        phase = node_types.get(str(getattr(result, "node_id", "")), "other")
        phase = phase if phase in phase_elapsed_ms else "other"
        phase_elapsed_ms[phase] += elapsed
    for entry in by_tool.values():
        entry["elapsed_ms"] = round(float(entry["elapsed_ms"]), 3)
    return {
        "call_count": len(results),
        "success_count": sum(1 for item in results if getattr(item, "success", False) is True),
        "failure_count": sum(1 for item in results if getattr(item, "success", False) is not True),
        "elapsed_ms": round(sum(float(getattr(item, "elapsed_ms", 0.0) or 0.0) for item in results), 3),
        "phase_elapsed_ms": {key: round(value, 3) for key, value in phase_elapsed_ms.items()},
        "by_tool": by_tool,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run C2Trace alert-first C2 traceback case")
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--alert", help="Path to Minimal C2 Seed Alert JSON")
    source_group.add_argument("--suricata-eve", help="Path to Suricata eve.json or JSONL file")
    parser.add_argument("--case-id", help="Case ID required for --suricata-eve")
    parser.add_argument("--victim-ip", help="Victim IP required for --suricata-eve")
    parser.add_argument("--signature-contains", default="", help="Suricata signature substring filter")
    parser.add_argument("--signature-id", default="", help="Suricata signature_id filter")
    parser.add_argument("--app-proto", default="", help="Suricata app_proto filter")
    parser.add_argument("--dest-port", type=int, help="Suricata dest_port filter")
    parser.add_argument(
        "--suricata-selection",
        choices=("latest", "first"),
        default="latest",
        help="Select the latest (formal default) or first matching EVE record in source order",
    )
    parser.add_argument("--flow-id", default="", help="Select a matching Suricata flow_id")
    parser.add_argument("--eve-line", type=int, help="Select an exact physical line in EVE JSONL")
    parser.add_argument("--eve-record-index", type=int, help="Select an exact 1-based record in an EVE JSON array/object")
    parser.add_argument("--event-sha256", default="", help="Select an exact canonical Suricata event SHA-256")
    parser.add_argument("--output", default="results/case", help="Output directory")
    parser.add_argument(
        "--tool-transport",
        choices=("mcp-stdio",),
        default="mcp-stdio",
        help="Executor tool transport; production C2Trace uses local stdio MCP",
    )
    parser.add_argument("--execute-response", action="store_true", help="Actually execute approved destructive response tools")
    parser.add_argument(
        "--require-auditor-llm",
        action="store_true",
        default=str(os.environ.get("C2TRACE_REQUIRE_AUDITOR_LLM") or "").strip().lower() in {"1", "true", "yes"},
        help="Fail closed when Auditor semantic LLM review is unavailable",
    )
    parser.add_argument(
        "--response-tools",
        nargs="+",
        choices=sorted(RESPONSE_TOOLS),
        help=(
            "Run-specific response-tool allowlist. Defaults to all supported response tools; "
            "use an explicit restricted list for scoped experiments."
        ),
    )
    parser.add_argument(
        "--strategy-tree-from",
        help=(
            "Replay a previously reviewed StrategyTree from a StrategyTree JSON or a "
            "C2Trace CaseFile containing strategy_tree."
        ),
    )
    parser.add_argument(
        "--protected-processes",
        help=(
            "Safety-only c2trace.protected_processes.v1/v2 manifest. Its contents are "
            "consumed only by Auditor's deterministic target validator and never sent to an LLM."
        ),
    )
    parser.add_argument(
        "--reviewed-target-from",
        help=(
            "Dry-run CaseFile containing response_target_lock. The live response target "
            "must match it exactly before destructive execution."
        ),
    )
    parser.add_argument("--max-steps", type=int, default=60, help="Maximum StrategyTree execution steps")
    args = parser.parse_args()
    response_tools = sorted(set(args.response_tools or RESPONSE_TOOLS))
    if args.execute_response and not (
        args.protected_processes and args.reviewed_target_from
    ):
        print(
            "Response execution requires both --protected-processes and "
            "--reviewed-target-from",
            file=sys.stderr,
        )
        return 2

    try:
        protected_input = (
            load_protected_processes(args.protected_processes, strict_safe=True)
            if args.protected_processes
            else None
        )
        reviewed_input = (
            load_reviewed_target(args.reviewed_target_from)
            if args.reviewed_target_from
            else None
        )
    except TargetSafetyInputError as exc:
        print(f"Invalid target-safety input: {exc}", file=sys.stderr)
        return 2

    started_at = datetime.now(timezone.utc)
    started_clock = time.perf_counter()
    run_metadata = {
        "schema_version": "c2trace.run.v1",
        "run_id": str(uuid4()),
        "started_at": started_at.isoformat(),
        "command": [str(item) for item in sys.argv],
        "runtime": {
            "python_version": platform.python_version(),
            "python_executable": str(Path(sys.executable).resolve()),
            "platform": platform.platform(),
            "mcp_sdk_version": package_version("mcp"),
            "cryptography_version": package_version("cryptography"),
        },
        "configuration": {
            "output": str(Path(args.output).resolve()),
            "execute_response": args.execute_response,
            "require_auditor_llm": args.require_auditor_llm,
            "tool_transport": args.tool_transport,
            "response_tools": response_tools,
            "strategy_tree_source": "strategy_tree_replay" if args.strategy_tree_from else "llm",
            "strategy_tree_input": "",
            "strategy_tree_input_sha256": "",
            "protected_processes_input": protected_input.path if protected_input else "",
            "protected_processes_sha256": protected_input.sha256 if protected_input else "",
            "reviewed_target_input": reviewed_input.path if reviewed_input else "",
            "reviewed_target_input_sha256": reviewed_input.sha256 if reviewed_input else "",
            "max_steps": args.max_steps,
        },
    }

    load_env_file(ROOT / ".env")
    source_events = []
    source_artifacts = []
    if args.alert:
        run_metadata["input"] = {
            "source_type": "minimal_alert_json",
            "path": str(Path(args.alert).resolve()),
        }
        try:
            alert_payload = json.loads(Path(args.alert).read_text(encoding="utf-8"))
            alert = MinimalAlert.from_dict(alert_payload)
        except (OSError, UnicodeError, json.JSONDecodeError, ValidationError) as exc:
            print(f"Invalid alert: {exc}", file=sys.stderr)
            return 2
    else:
        if not args.case_id or not args.victim_ip:
            parser.error("--suricata-eve requires --case-id and --victim-ip")
        try:
            selection = SuricataSelection(
                policy=args.suricata_selection,
                flow_id=args.flow_id,
                line_number=args.eve_line,
                record_index=args.eve_record_index,
                event_sha256=args.event_sha256,
            )
            alert, source_event, source_artifact = select_suricata_alert_with_artifact(
                args.suricata_eve,
                case_id=args.case_id,
                victim_ip=args.victim_ip,
                filters=SuricataFilters(
                    signature_contains=args.signature_contains,
                    signature_id=args.signature_id,
                    app_proto=args.app_proto,
                    dest_port=args.dest_port,
                ),
                selection=selection,
            )
            source_events = [source_event]
            source_artifacts = [source_artifact]
            run_metadata["input"] = {
                "source_type": "suricata_eve",
                "path": str(Path(args.suricata_eve).resolve()),
                "case_id": args.case_id,
                "victim_ip": args.victim_ip,
                "filters": {
                    "signature_contains": args.signature_contains,
                    "signature_id": args.signature_id,
                    "app_proto": args.app_proto,
                    "dest_port": args.dest_port,
                },
                "requested_selection": selection.to_dict(),
                "selected_source_event": source_event,
                "selected_source_artifact": source_artifact,
            }
        except (OSError, SuricataAlertError) as exc:
            print(f"Invalid Suricata EVE alert input: {exc}", file=sys.stderr)
            return 2

    strategy_tree_template = None
    if args.strategy_tree_from:
        strategy_path = Path(args.strategy_tree_from).resolve()
        try:
            strategy_bytes = strategy_path.read_bytes()
            strategy_payload = json.loads(strategy_bytes.decode("utf-8-sig"))
            if not isinstance(strategy_payload, dict):
                raise ValueError("strategy tree input root must be a JSON object")
            source_case_id = str(strategy_payload.get("case_id") or "")
            if source_case_id and source_case_id != alert.case_id:
                raise ValueError(
                    f"strategy tree source case_id {source_case_id} does not match {alert.case_id}"
                )
            candidate = strategy_payload.get("strategy_tree", strategy_payload)
            if not isinstance(candidate, dict):
                raise ValueError("strategy tree input has no strategy_tree object")
            strategy_tree_template = candidate
            run_metadata["configuration"].update(
                {
                    "strategy_tree_input": str(strategy_path),
                    "strategy_tree_input_sha256": hashlib.sha256(
                        strategy_bytes
                    ).hexdigest(),
                }
            )
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            print(f"Invalid StrategyTree replay input: {exc}", file=sys.stderr)
            return 2

    try:
        kb = load_c2kb(ROOT / "kb")
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"Unable to load C2 knowledge pack: {exc}", file=sys.stderr)
        return 2
    # Auditor creates and exclusively owns the per-run Ed25519 private key.
    # Infrastructure receives only its public key.
    auditor = AuditorAgent(require_llm=args.require_auditor_llm)
    output_root = Path(args.output).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    mcp_stderr_path = output_root / "mcp_server.stderr.log"
    mcp_errlog = mcp_stderr_path.open("a", encoding="utf-8")
    tool_client: StdioMcpToolClient | None = None
    try:
        tool_client = StdioMcpToolClient(
            case_id=alert.case_id,
            response_enabled=args.execute_response,
            public_key_b64=auditor.authorization_public_key_b64,
            cwd=ROOT,
            errlog=mcp_errlog,
        )
    except (McpTransportError, OSError, RuntimeError, ValueError) as exc:
        mcp_errlog.close()
        failed_case = CaseFile.from_alert(
            alert,
            source_events=source_events,
            source_artifacts=source_artifacts,
        )
        failed_case.final_status = "infrastructure_invalid"
        failed_case.record_error(
            "mcp_transport_error",
            str(exc),
            {"transport": "mcp-stdio", "stderr_path": str(mcp_stderr_path)},
        )
        Reporter().build(failed_case)
        run_metadata["finished_at"] = datetime.now(timezone.utc).isoformat()
        run_metadata["result"] = {
            "case_id": failed_case.case_id,
            "final_status": failed_case.final_status,
            "cli_exit_code": 1,
        }
        run_metadata["mcp"] = {
            "transport": "stdio",
            "status": "startup_failed",
            "error": str(exc),
            "stderr_path": str(mcp_stderr_path),
        }
        write_outputs(failed_case, args.output, run_metadata=run_metadata)
        print(json.dumps(failed_case.to_dict(), ensure_ascii=False, indent=2))
        return 1

    executor = ExecutorAgent(tool_client=tool_client)
    catalog = executor.list_tools()
    catalog_names = {str(item.get("name") or "") for item in catalog}
    expected_catalog = set(READ_ONLY_TOOLS | RESPONSE_TOOLS)
    if catalog_names != expected_catalog:
        mismatch = (
            "MCP tool catalog mismatch "
            f"missing={sorted(expected_catalog - catalog_names)} "
            f"unexpected={sorted(catalog_names - expected_catalog)}"
        )
        tool_client.close()
        mcp_errlog.close()
        failed_case = CaseFile.from_alert(
            alert,
            source_events=source_events,
            source_artifacts=source_artifacts,
        )
        failed_case.final_status = "infrastructure_invalid"
        failed_case.record_error(
            "mcp_tool_catalog_mismatch",
            mismatch,
            {
                "missing": sorted(expected_catalog - catalog_names),
                "unexpected": sorted(catalog_names - expected_catalog),
            },
        )
        Reporter().build(failed_case)
        run_metadata["finished_at"] = datetime.now(timezone.utc).isoformat()
        run_metadata["result"] = {
            "case_id": failed_case.case_id,
            "final_status": failed_case.final_status,
            "cli_exit_code": 1,
        }
        run_metadata["mcp"] = {
            "transport": "stdio",
            "status": "catalog_mismatch",
            "tool_names": sorted(catalog_names),
            "missing": sorted(expected_catalog - catalog_names),
            "unexpected": sorted(catalog_names - expected_catalog),
            "stderr_path": str(mcp_stderr_path),
        }
        write_outputs(failed_case, args.output, run_metadata=run_metadata)
        print(f"MCP infrastructure invalid: {mismatch}", file=sys.stderr)
        return 1

    target_validator = None
    if protected_input is not None or reviewed_input is not None:
        target_validator = TargetIdentityValidator(
            observer=executor,
            protected_processes=(
                protected_input.payload["processes"] if protected_input is not None else []
            ),
            reviewed_target=reviewed_input.payload if reviewed_input is not None else None,
            run_id=(protected_input.payload.get("run_id", "") if protected_input is not None else ""),
            expected_target=None,
            target_lock_schema_version=(
                protected_input.payload.get("target_lock_schema_version", "")
                if protected_input is not None
                else ""
            ),
        )
    auditor.target_validator = target_validator
    planner = PlannerAgent(
        knowledge_pack=kb,
        allowed_response_tools=set(response_tools),
        strategy_tree_template=strategy_tree_template,
        tool_catalog=catalog,
    )
    recent_file_discovery = RecentFileDiscoveryPolicy()
    run_metadata["configuration"]["recent_file_discovery"] = (
        recent_file_discovery.to_dict()
    )
    workflow = WorkflowController(
        planner=planner,
        auditor=auditor,
        executor=executor,
        recent_file_discovery=recent_file_discovery,
        max_steps=args.max_steps,
    )
    run_metadata["mcp"] = {
        "transport": "stdio",
        "status": "ready",
        "server_mode": "response_enabled" if args.execute_response else "read_only",
        "tool_count": len(catalog),
        "tool_names": sorted(catalog_names),
        "tool_catalog_sha256": tool_client.catalog_hash,
        "authorization_public_key_fingerprint": auditor.authorization_public_key_fingerprint,
        "stderr_path": str(mcp_stderr_path),
    }
    try:
        case = workflow.run_alert(
            alert,
            source_events=source_events,
            source_artifacts=source_artifacts,
        )
    finally:
        tool_client.close()
        mcp_errlog.close()
    case.add_timeline(
        "run_input_recorded",
        "Run input and reproducibility metadata recorded",
        "run_case",
        details=run_metadata["input"],
    )
    finished_at = datetime.now(timezone.utc)
    # A completed Python process is not necessarily a successful incident run.
    # Make shell automation fail closed on attribution/response/verification
    # outcomes while retaining both accepted terminal modes.
    cli_exit_code = cli_exit_code_for_status(case.final_status)
    run_metadata["finished_at"] = finished_at.isoformat()
    run_metadata["duration_ms"] = round((time.perf_counter() - started_clock) * 1000, 3)
    run_metadata["result"] = {
        "case_id": case.case_id,
        "final_status": case.final_status,
        "cli_exit_code": cli_exit_code,
    }
    run_metadata["llm_usage"] = summarize_llm_usage(planner, auditor)
    run_metadata["tool_usage"] = summarize_tool_usage(case)
    run_metadata["strategy_tree"] = (
        {
            "tree_id": case.strategy_tree.tree_id,
            "created_by": case.strategy_tree.created_by,
            "provenance": dict(case.strategy_tree.provenance),
        }
        if case.strategy_tree is not None
        else None
    )
    run_metadata["target_safety"] = {
        "enabled": target_validator is not None,
        "owner": "auditor",
        "protected_process_count": (
            len(protected_input.payload["processes"]) if protected_input is not None else 0
        ),
        "reviewed_target_supplied": reviewed_input is not None,
        "response_target_lock": case.response_target_lock,
    }
    try:
        write_outputs(case, args.output, run_metadata=run_metadata)
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        print(f"Unable to write case outputs: {exc}", file=sys.stderr)
        print(json.dumps(case.to_dict(), ensure_ascii=False, indent=2))
        return 3
    print(json.dumps(case.to_dict(), ensure_ascii=False, indent=2))
    return cli_exit_code


if __name__ == "__main__":
    raise SystemExit(main())
