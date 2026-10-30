"""System prompt builder, finding derivation, CaseFile assembly, and scoring
for the LangGraph ReAct agent baseline."""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

from c2trace.kb import load_c2kb
from c2trace.models import MinimalAlert


def build_system_prompt(kb_root: Path, alert: dict[str, Any], *, execute_response: bool = True) -> str:
    """Build the ReAct agent system prompt with C2-KB and alert context.

    When ``execute_response`` is False (dry-run phase), the prompt instructs
    the model to investigate only and NOT attempt response actions, preventing
    wasted LLM calls on tools that will fail.
    """
    # Reject any caller-supplied process/file/GT fields before they reach the
    # model.  The alert is the minimal investigation seed, not a target hint.
    alert = MinimalAlert.from_dict(dict(alert)).to_dict()
    kb = load_c2kb(kb_root)
    alert_json = json.dumps(alert, ensure_ascii=False, default=str, indent=2)
    if execute_response:
        phase_instruction = [
            "You are a C2 threat investigation and response agent.",
            "",
            "You have received a Suricata C2 alert. Your task is to:",
            "1. Investigate the victim host using the provided read-only tools.",
            "2. Identify the C2 process, payload file, and any persistence mechanisms.",
            "3. Execute response actions (kill process, remove file, remove persistence) when evidence is sufficient.",
            "4. Verify cleanup with verify_cleanup after executing response actions.",
        ]
    else:
        phase_instruction = [
            "You are a C2 threat investigation agent (DRY-RUN PHASE).",
            "",
            "You have received a Suricata C2 alert. Your task is to INVESTIGATE ONLY:",
            "1. Investigate the victim host using the provided read-only tools.",
            "2. Identify the C2 process, payload file, and any persistence mechanisms.",
            "3. DO NOT attempt any response actions (kill_process, remove_file, etc.) in this phase.",
            "4. DO NOT call verify_cleanup in this phase.",
            "5. After investigation, emit your final structured JSON prediction (observed_entities and proposed_actions).",
            "",
            "Response actions will be executed in a separate phase. Focus on investigation now.",
        ]
    parts = phase_instruction + ["",
        "## Investigation Knowledge Template",
        "",
        kb.template,
        "",
        "## Windows Tool Catalog",
        "",
        kb.tool_catalog,
        "",
        "## Evidence Chain Rules",
        "",
        kb.evidence_rules,
        "",
        "## Response Safety Rules",
        "",
        kb.response_safety_rules,
        "",
        "## Investigation Method",
        "",
        "1. Start from the alert remote IP and port. Use check_network to confirm the C2 connection.",
        "2. If a connection is found, extract the owning PID and use check_process / check_process_tree.",
        "3. Use check_file_metadata on the process executable path and any payload file from the command line.",
        "4. If the process is an interpreter host (rundll32, powershell, etc.), inspect command_line for payload paths.",
        "5. Use check_persistence_all to search Run Keys, scheduled tasks, and services.",
        "6. Use check_powershell_history when launch/download traces may help.",
        "",
        "IMPORTANT: When calling check_recent_files, you MUST use these exact",
        "arguments: root_aliases=['users_public', 'appdata'], max_depth=0.",
        "Provide since_utc and until_utc as ISO 8601 UTC strings (e.g. 2026-09-29T08:00:00Z).",
        "Do NOT pass file paths as root_aliases — use only the literal strings 'users_public' and 'appdata'.",
        "7. Only execute response actions after you have linked the C2 seed to a process and file/persistence.",
        "8. After response, use verify_cleanup to confirm the target is gone.",
        "",
        "## Budget Constraints",
        "",
        "You have a maximum of 25 tool calls and 8 LLM reasoning steps.",
        "Be efficient: investigate first, then respond, then verify.",
        "",
        "## Structured Output Contract (MANDATORY)",
        "",
        "After your investigation, you MUST emit one final JSON object with exactly",
        "two top-level arrays: observed_entities and proposed_actions.",
        "",
        "Each observed_entity MUST use one of these finding_type values and MUST",
        "include a details object with structured fields (do NOT leave details empty",
        "or put everything in a value string):",
        "",
        "1. network_connection:",
        '   details: {"local_address": "...", "local_port": 0, "remote_address": "...", "remote_port": 0, "pid": 0}',
        "",
        "2. process_detail:",
        '   details: {"pid": 0, "name": "...", "path": "...", "creation_time_utc": "2026-09-30T14:30:00Z"}',
        "",
        "   creation_time_utc is MANDATORY for process_detail. Get it from check_process output.",
        "   The scorer requires pid + creation_time + path to match; without creation_time the",
        "   process observation will NOT match ground truth.",
        "",
        "3. file_metadata:",
        '   details: {"path": "...", "sha256": "...", "exists": true}',
        "",
        "4. persistence_linked_to_payload:",
        '   details: {"category": "registry_run_key", "path": "...", "name": "...", "value": "..."}',
        "",
        "Copy the field values from your tool observation results. For example,",
        "if check_network returned a connection with pid=1234, put pid:1234 in the",
        "network_connection details. If check_process returned path and sha256,",
        "put them in the corresponding details fields.",
        "",
        "Do NOT use finding_type values like c2_connection, process, payload_file,",
        "or c2_process — use only the four types listed above.",
        "",
        "Each proposed_action MUST include tool and arguments:",
        '   {"tool": "kill_process", "arguments": {"pid": 0, "process_name": "...", "expected_path": "..."}}',
        '   {"tool": "remove_file", "arguments": {"file_path": "..."}}',
        "",
        "## Suricata Alert",
        "",
        "```json",
        alert_json,
        "```",
    ]
    return "\n".join(parts)


def _as_list(value: Any) -> list:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def derive_findings(
    calls: list[dict[str, Any]],
    source_alert: dict[str, Any],
) -> list[dict[str, Any]]:
    """Legacy compatibility function.

    Tool observations are not model findings.  The baseline adapter therefore
    returns an empty prediction list here; explicit model entities are passed
    to :func:`build_casefile` separately.
    """
    return []


def _explicit_findings(entities: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Normalize model-predicted entities through the frozen TracePrediction IR schema.

    Only entities whose finding_type is in the allowed schema set are kept.
    Details are filtered to schema-relevant keys.  This prevents free-text
    finding types (c2_connection, process, payload_file) from entering the
    scorer, and ensures structured details are present for scoring.
    """
    from c2trace.baseline.trace_prediction_schema import normalize_entities

    findings: list[dict[str, Any]] = []
    normalized = normalize_entities(entities)
    for index, entity in enumerate(normalized, start=1):
        findings.append({
            "finding_id": entity["finding_id"],
            "finding_type": entity["finding_type"],
            "value": entity["value"],
            "evidence": entity["evidence"],
            "source": "react_agent_prediction",
            "confidence": entity["confidence"],
            "details": entity["details"],
            "created_at": _now_iso(),
        })
    return findings


def build_action_results(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build CaseFile action_results from recorded tool calls."""
    results = []
    for i, call in enumerate(calls):
        results.append({
            "result_id": "ar-{:04d}".format(i + 1),
            "node_id": "react-{:04d}".format(i + 1),
            "tool": call["tool"],
            "success": call["success"],
            "data": call["data"],
            "error": call["error"],
            "elapsed_ms": call["elapsed_ms"],
            "arguments": call["arguments"],
            "created_at": _now_iso(),
        })
    return results


def build_casefile(
    case_id: str,
    source_alert: dict[str, Any],
    calls: list[dict[str, Any]],
    agent_messages: list[dict[str, Any]] | None = None,
    predicted_entities: list[dict[str, Any]] | None = None,
    proposed_actions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assemble a CaseFile from explicit model predictions and raw observations."""
    findings = _explicit_findings(predicted_entities)
    action_results = build_action_results(calls)
    casefile = {
        "case_id": case_id,
        "case_name": "C2Trace baseline case {}".format(case_id),
        "source_alert": source_alert,
        "source_events": [],
        "source_artifacts": [],
        "findings": findings,
        "action_results": action_results,
        "proposed_actions": list(proposed_actions or []),
        "tool_observations": list(calls),
        "audit_decisions": [],
        "evidence_links": [],
        "timeline": [],
        "final_report": "",
        "final_status": "completed",
        "errors": [],
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    }
    if agent_messages:
        casefile["agent_trace"] = agent_messages
    return casefile


def parse_explicit_prediction(agent_messages: list[dict[str, Any]] | None, case_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str | None]:
    """Parse only a strict JSON prediction emitted by the model."""
    from c2trace.baseline.llm_direct import parse_prediction_text
    for message in reversed(agent_messages or []):
        if message.get("type") != "ai":
            continue
        content = str(message.get("content") or "")
        try:
            prediction = parse_prediction_text(content, case_id=case_id)
        except (ValueError, TypeError, json.JSONDecodeError):
            continue
        return prediction.observed_entities, prediction.proposed_actions, None
    return [], [], "no strict JSON prediction emitted by ReAct agent"


def build_operational_metrics(calls, agent_messages, total_duration_ms):
    tool_calls = len(calls)
    llm_calls = sum(1 for m in agent_messages if m.get("type") == "ai")
    total_tokens = sum(m.get("usage_metadata", {}).get("total_tokens", 0) for m in agent_messages if m.get("type") == "ai")
    prompt_tokens = sum(m.get("usage_metadata", {}).get("input_tokens", 0) for m in agent_messages if m.get("type") == "ai")
    completion_tokens = sum(m.get("usage_metadata", {}).get("output_tokens", 0) for m in agent_messages if m.get("type") == "ai")
    return {
        "tool_calls": tool_calls,
        "llm_calls": llm_calls,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "case_duration_ms": round(total_duration_ms, 3),
        "end_to_end_duration_ms": round(total_duration_ms, 3),
    }


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
