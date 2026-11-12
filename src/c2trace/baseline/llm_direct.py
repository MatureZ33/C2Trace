"""LLM-Direct baseline: frozen-evidence synthesis without host tools."""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Mapping

from .evidence_sanitizer import sanitize_evidence_bundle
from .prediction_ir import PredictionIR


def _json_object_from_text(text: str) -> dict[str, Any]:
    candidate = str(text or "").strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", candidate, flags=re.IGNORECASE | re.DOTALL)
    if fenced:
        candidate = fenced.group(1)
    if not candidate.startswith("{"):
        start, end = candidate.find("{"), candidate.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("model output does not contain a JSON object")
        candidate = candidate[start : end + 1]
    value = json.loads(candidate)
    if not isinstance(value, dict):
        raise ValueError("model output JSON root must be an object")
    return value


def parse_prediction_text(text: str, *, case_id: str) -> PredictionIR:
    payload = _json_object_from_text(text)
    entities = payload.get("observed_entities", payload.get("entities", []))
    actions = payload.get("proposed_actions", payload.get("actions", []))
    if not isinstance(entities, list) or not all(isinstance(item, dict) for item in entities):
        raise ValueError("observed_entities must be a list of objects")
    if not isinstance(actions, list) or not all(isinstance(item, dict) for item in actions):
        raise ValueError("proposed_actions must be a list of objects")
    return PredictionIR(
        case_id=case_id,
        observed_entities=[dict(item) for item in entities],
        proposed_actions=[dict(item) for item in actions],
        executed_actions=[],
        metadata={"parser": "strict_json_object"},
    ).validate()


def build_direct_prompt(evidence: Mapping[str, Any]) -> str:
    sanitized, _ = sanitize_evidence_bundle(evidence)
    evidence_json = json.dumps(sanitized, ensure_ascii=False, sort_keys=True, indent=2)
    return """You are the LLM-Direct C2 evidence synthesis baseline.
You have only a frozen, de-labelled evidence bundle. Do not assume facts that
are not present. Do not call tools and do not claim that any host action was
executed. Return exactly one JSON object with this schema:
{
  \"observed_entities\": [{\"finding_type\": \"process|file|network_connection|persistence_candidate\", \"value\": \"...\", \"details\": {}, \"confidence\": 0.0}],
  \"proposed_actions\": [{\"tool\": \"kill_process|remove_file|remove_registry|remove_scheduled_task|remove_service\", \"arguments\": {}, \"reason\": \"...\"}]
}
Use only facts visible in the evidence below.\n\nFROZEN EVIDENCE:\n""" + evidence_json


def _message_text(message: Any) -> str:
    return str(getattr(message, "content", message) or "")


def _usage(message: Any) -> dict[str, int]:
    raw = getattr(message, "usage_metadata", None) or {}
    def integer(*keys: str) -> int:
        for key in keys:
            value = raw.get(key)
            if isinstance(value, int) and value >= 0:
                return value
        return 0
    prompt = integer("input_tokens", "prompt_tokens")
    completion = integer("output_tokens", "completion_tokens")
    total = integer("total_tokens") or prompt + completion
    return {"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": total}


def run_llm_direct(
    *,
    case_id: str,
    evidence: Mapping[str, Any],
    model: str | None = None,
    llm: Any | None = None,
) -> tuple[PredictionIR, dict[str, Any]]:
    sanitized, sanitization = sanitize_evidence_bundle(evidence)
    prompt = build_direct_prompt(sanitized)
    if llm is None:
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(
            model=model or os.environ.get("DEEPSEEK_MODEL", "deepseek-chat"),
            api_key=os.environ["DEEPSEEK_API_KEY"],
            base_url=os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"),
            temperature=0,
        )
    started = time.perf_counter()
    message = llm.invoke(prompt)
    duration_ms = (time.perf_counter() - started) * 1000
    text = _message_text(message)
    prediction = parse_prediction_text(text, case_id=case_id)
    usage = _usage(message)
    prediction.llm_call_count = 1
    prediction.token_usage = usage
    prediction.metadata.update({
        "model": model or os.environ.get("DEEPSEEK_MODEL", "deepseek-chat"),
        "temperature": 0,
        "evidence_sha256": sanitization.output_sha256,
        "sanitization": sanitization.to_dict(),
        "duration_ms": round(duration_ms, 3),
    })
    prediction.validate()
    return prediction, {"prompt": prompt, "raw_output": text, "usage": usage, "duration_ms": duration_ms, "sanitization": sanitization.to_dict()}


def prediction_to_casefile(prediction: PredictionIR, source_alert: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Convert explicit predictions only; no tool observation becomes a finding."""
    findings: list[dict[str, Any]] = []
    for index, entity in enumerate(prediction.observed_entities, start=1):
        finding_type = str(entity.get("finding_type") or entity.get("type") or "")
        value = str(entity.get("value") or entity.get("path") or entity.get("name") or "")
        if not finding_type or not value:
            continue
        details = dict(entity["details"]) if isinstance(entity.get("details"), dict) else {}
        # Match the scorer's vocabulary using only explicit prediction fields.
        if finding_type == "process":
            finding_type = "process_detail"
        elif finding_type == "file":
            finding_type = "file_metadata"
            if not details.get("path"):
                details["path"] = value
        findings.append({
            "finding_id": f"direct-finding-{index:04d}",
            "finding_type": finding_type,
            "value": value,
            "evidence": str(entity.get("evidence") or "explicit model prediction"),
            "source": "llm_direct_prediction",
            "confidence": float(entity.get("confidence", 0.0) or 0.0),
            "details": details,
        })
    action_results = []
    for index, action in enumerate(prediction.proposed_actions, start=1):
        action_results.append({
            "result_id": f"direct-action-{index:04d}",
            "node_id": f"direct-action-{index:04d}",
            "tool": action.get("tool", ""),
            "arguments": action.get("arguments", {}) if isinstance(action.get("arguments"), dict) else {},
            "success": False,
            "data": {"proposed_only": True},
            "error": "LLM-Direct does not execute host actions",
        })
    return {
        "case_id": prediction.case_id,
        "case_name": f"LLM-Direct baseline case {prediction.case_id}",
        "source_alert": dict(source_alert or {}),
        "findings": findings,
        "action_results": action_results,
        "proposed_actions": prediction.proposed_actions,
        "final_status": "completed_no_execution",
        "operational_metrics": {"tool_calls": 0, "llm_calls": prediction.llm_call_count, **prediction.token_usage},
    }


__all__ = ["build_direct_prompt", "parse_prediction_text", "prediction_to_casefile", "run_llm_direct"]
