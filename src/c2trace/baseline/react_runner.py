"""Run the independent public-task LangGraph ReAct baseline.

The runtime writes a neutral ``run_record.json``. It does not create or load
the treatment's report, strategy, target-binding, or answer structures.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from langchain_core.callbacks import BaseCallbackHandler
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from c2trace.baseline.neutral_records import ReActRunRecord, sanitize_alert, project_for_scoring
from c2trace.baseline.public_output import parse_public_output
from c2trace.baseline.public_task import DEFAULT_SPEC_ROOT, build_public_system_prompt
from c2trace.baseline.react_agent import ToolCallRecorder, build_tools
from c2trace.baseline.safety_mediator import SafetyMediator
from c2trace.tools.system import WindowsToolBackend


MAX_TOOL_CALLS = 50
MAX_LLM_CALLS = 20
MAX_TOTAL_TOKENS = 300_000
RECURSION_LIMIT = MAX_LLM_CALLS * 2 + 2
BASELINE_MODEL = "deepseek-chat"


def resolve_baseline_model(requested: str | None = None) -> str:
    candidate = str(requested or os.environ.get("DEEPSEEK_MODEL") or BASELINE_MODEL).strip()
    if candidate != BASELINE_MODEL:
        raise RuntimeError(f"baseline model mismatch: protocol requires {BASELINE_MODEL!r}, observed {candidate!r}")
    return candidate


def event_to_baseline_minimal_alert(event: dict[str, Any], *, case_id: str, victim_ip: str):
    """Normalize a Suricata event to the shared canonical alert."""
    from c2trace.suricata import event_to_minimal_alert
    normalized = dict(event or {})
    if not isinstance(normalized.get("alert"), dict):
        normalized["alert"] = {key: normalized.get(key) for key in ("signature", "signature_id", "category", "severity") if normalized.get(key) not in (None, "")}
    return event_to_minimal_alert(normalized, case_id=case_id, victim_ip=victim_ip)


class _LLMCallBudgetExceeded(RuntimeError):
    pass


class _HardLLMCallBudget(BaseCallbackHandler):
    raise_error = True

    def __init__(self, limit: int) -> None:
        self.limit = int(limit)
        self.calls = 0
        self._seen_run_ids: set[str] = set()

    def _reserve(self, run_id: Any = None) -> None:
        key = str(run_id) if run_id is not None else f"implicit-{self.calls}"
        if key in self._seen_run_ids:
            return
        if self.calls >= self.limit:
            raise _LLMCallBudgetExceeded(f"LLM call budget exhausted ({self.calls}/{self.limit})")
        self._seen_run_ids.add(key)
        self.calls += 1

    def on_chat_model_start(self, serialized: dict[str, Any], messages: list[Any], **kwargs: Any) -> None:
        self._reserve(kwargs.get("run_id"))

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        self._reserve(kwargs.get("run_id"))


def _audit_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


class _LLMCallAudit(BaseCallbackHandler):
    """Hash-only request/response audit; no prompt or model text is persisted."""
    raise_error = False

    def __init__(self, requested_model: str) -> None:
        self.requested_model = requested_model
        self.records: list[dict[str, Any]] = []
        self._by_run_id: dict[str, dict[str, Any]] = {}

    def _start(self, run_id: Any, payload: Any) -> None:
        key = str(run_id or f"implicit-{len(self.records)}")
        if key in self._by_run_id:
            return
        record = {"run_id": key, "requested_model": self.requested_model, "prompt_sha256": _audit_hash(payload), "response_model": "", "request_id": "", "response_sha256": "", "parsed_response_sha256": "", "status": "started"}
        self._by_run_id[key] = record
        self.records.append(record)

    def on_chat_model_start(self, serialized: dict[str, Any], messages: list[Any], **kwargs: Any) -> None:
        self._start(kwargs.get("run_id"), messages)

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        self._start(kwargs.get("run_id"), prompts)

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        key = str(kwargs.get("run_id") or "")
        record = self._by_run_id.get(key)
        if record is None:
            self._start(key, [])
            record = self._by_run_id.get(key)
        if record is None:
            return
        record["response_sha256"] = _audit_hash(response)
        generations = getattr(response, "generations", None) or []
        message = None
        try:
            generation = generations[0][0]
            message = getattr(generation, "message", None)
            if message is None and isinstance(generation, dict):
                message = generation.get("message")
        except (IndexError, TypeError):
            pass
        metadata = dict(getattr(message, "response_metadata", {}) or {}) if message is not None else {}
        record["response_model"] = str(metadata.get("model") or metadata.get("model_name") or "")
        record["request_id"] = str(metadata.get("id") or metadata.get("request_id") or "")
        content = getattr(message, "content", None) if message is not None else None
        if content is not None:
            record["parsed_response_sha256"] = _audit_hash(content)
        record["status"] = "completed"

    def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        key = str(kwargs.get("run_id") or "")
        record = self._by_run_id.get(key)
        if record is not None:
            record["status"] = "error"
            record["error_type"] = type(error).__name__


def _message_rows(messages: list[Any]) -> tuple[list[dict[str, Any]], str]:
    rows: list[dict[str, Any]] = []
    final_text = ""
    for msg in messages:
        name = type(msg).__name__
        content = str(getattr(msg, "content", "") or "")
        usage = dict(getattr(msg, "usage_metadata", {}) or {})
        if name == "AIMessage" and content:
            final_text = content
        rows.append({"type": name.lower().replace("message", "").strip(), "content_sha256": _audit_hash(content), "usage_metadata": usage, "response_metadata": dict(getattr(msg, "response_metadata", {}) or {})})
    return rows, final_text


def _metrics(calls: list[dict[str, Any]], rows: list[dict[str, Any]], duration_ms: float) -> dict[str, Any]:
    ai_rows = [row for row in rows if row.get("type") == "ai"]
    prompt_tokens = sum(int((row.get("usage_metadata") or {}).get("input_tokens", 0) or 0) for row in ai_rows)
    completion_tokens = sum(int((row.get("usage_metadata") or {}).get("output_tokens", 0) or 0) for row in ai_rows)
    total_tokens = sum(int((row.get("usage_metadata") or {}).get("total_tokens", 0) or 0) for row in ai_rows)
    return {"tool_calls": len(calls), "llm_calls": len(ai_rows), "prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens, "total_tokens": total_tokens, "case_duration_ms": round(duration_ms, 3), "end_to_end_duration_ms": round(duration_ms, 3)}


def run_react_agent(
    case_id: str,
    source_alert: dict[str, Any],
    kb_root: Path | None = None,
    output_dir: Path | None = None,
    max_tool_calls: int = MAX_TOOL_CALLS,
    max_llm_calls: int = MAX_LLM_CALLS,
    max_total_tokens: int | None = MAX_TOTAL_TOKENS,
    execute_response: bool = True,
    model: str | None = None,
    task_spec_root: Path | None = None,
    protected_process_names: set[str] | None = None,
    protected_process_paths: set[str] | None = None,
    protected_process_pids: set[int] | None = None,
) -> dict[str, Any]:
    """Run one public-task episode and return a neutral run record."""
    del kb_root  # retained as a compatibility argument; private KB is unused
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[3] / ".env")
    model_name = resolve_baseline_model(model)
    alert = sanitize_alert(source_alert)
    budget = _HardLLMCallBudget(max_llm_calls)
    audit = _LLMCallAudit(model_name)
    llm = ChatOpenAI(model=model_name, api_key=os.environ["DEEPSEEK_API_KEY"], base_url=os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"), temperature=0, callbacks=[budget, audit])
    backend = WindowsToolBackend(execute_response=execute_response)
    recorder = ToolCallRecorder(
        backend,
        max_calls=max_tool_calls,
        mediator=SafetyMediator(
            protected_process_names=protected_process_names,
            protected_process_paths=protected_process_paths,
            protected_process_pids=protected_process_pids,
        ),
    )
    tools = build_tools(recorder)
    prompt = build_public_system_prompt(alert, spec_root=task_spec_root or DEFAULT_SPEC_ROOT, execute_response=execute_response)
    agent = create_react_agent(llm, tools, prompt=prompt)
    user_msg = (
        "Investigate the supplied alert using the public tools and return the required JSON. "
        + ("You may request suitable response tools and optionally inspect the current state afterward." if execute_response else "Do not request any response or post-state tool in this pass.")
    )
    started = time.perf_counter()
    errors: list[dict[str, Any]] = []
    messages: list[Any] = []
    try:
        result = agent.invoke({"messages": [{"role": "user", "content": user_msg}]}, {"recursion_limit": max_llm_calls * 2 + 2})
        messages = result.get("messages", [])
    except _LLMCallBudgetExceeded as exc:
        errors.append({"type": "llm_budget_exceeded", "message": str(exc)})
    except Exception as exc:
        errors.append({"type": "agent_error", "message": str(exc)})
    duration_ms = (time.perf_counter() - started) * 1000
    rows, final_text = _message_rows(messages)
    model_output: dict[str, Any] = {"observations": [], "actions": []}
    if final_text:
        try:
            model_output = parse_public_output(final_text)
        except ValueError as exc:
            errors.append({"type": "output_parse_error", "message": str(exc)})
    metrics = _metrics(recorder.calls, rows, duration_ms)
    # LangChain providers do not consistently expose the returned model in
    # AIMessage.response_metadata.  The callback audit is the authoritative
    # per-call record, so use it as a fallback for response-model reporting.
    audited_response_models = sorted({
        str(record.get("response_model") or "").strip()
        for record in audit.records
        if str(record.get("response_model") or "").strip()
    })
    metrics.update({"max_tool_calls": max_tool_calls, "max_llm_calls": max_llm_calls, "max_total_tokens": max_total_tokens, "requested_model": model_name, "response_models": sorted({str((row.get("response_metadata") or {}).get("model") or "") for row in rows if (row.get("response_metadata") or {}).get("model")}), "llm_budget_enforced": True, "llm_budget_calls_observed": budget.calls, "llm_call_audit_count": len(audit.records), "budget_exceeded": bool(budget.calls > max_llm_calls or len(recorder.calls) > max_tool_calls or (max_total_tokens is not None and metrics["total_tokens"] > max_total_tokens))})
    if audited_response_models:
        metrics["response_models"] = audited_response_models
        metrics["response_model_source"] = "llm_call_audit"
    elif not metrics["response_models"]:
        metrics["response_model_source"] = "provider_metadata_unavailable"
    executed = [{"tool": row["tool"], "arguments": row["arguments"], "data": row.get("data")} for row in recorder.calls if row.get("classification") == "response" and row.get("success") is True]
    post_state = next((row.get("data") for row in reversed(recorder.calls) if row.get("tool") == "check_post_state" and row.get("success") is True), None)
    record = ReActRunRecord(case_id=case_id, alert=alert, tool_calls=recorder.calls, model_output=model_output, executed_actions=executed, post_state_observation=post_state, operational_metrics=metrics, llm_audit=audit.records, errors=errors)
    payload = record.to_dict()
    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        record.write_json(out / "run_record.json")
        (out / "tool_calls.json").write_text(json.dumps(recorder.calls, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
        (out / "llm_call_audit.json").write_text(json.dumps(audit.records, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
        (out / "model_output.json").write_text(json.dumps(model_output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (out / "run_metadata.json").write_text(json.dumps({"duration_ms": metrics["case_duration_ms"], "llm_usage": {key: metrics[key] for key in ("llm_calls", "requested_model", "response_models", "prompt_tokens", "completion_tokens", "total_tokens")}, "tool_usage": {"call_count": metrics["tool_calls"]}, "budget": {"max_tool_calls": max_tool_calls, "max_llm_calls": max_llm_calls, "max_total_tokens": max_total_tokens, "exceeded": metrics["budget_exceeded"]}, "errors": errors}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload


def score_react_record(run_record: dict[str, Any], ground_truth: dict[str, Any], output_dir: Path | None = None) -> dict[str, Any]:
    """Score only after a completed run record is available."""
    from c2trace.bench_v4.scorer import score_case
    evaluation, scoring_casefile = project_for_scoring(run_record)
    score = score_case(ground_truth, scoring_casefile)
    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        evaluation.write_json(out / "evaluation_record.json")
        (out / "scoring_projection.json").write_text(json.dumps(scoring_casefile, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
        (out / "score.json").write_text(json.dumps(score, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
    return score


__all__ = ["BASELINE_MODEL", "MAX_LLM_CALLS", "MAX_TOOL_CALLS", "MAX_TOTAL_TOKENS", "event_to_baseline_minimal_alert", "resolve_baseline_model", "run_react_agent", "score_react_record", "_HardLLMCallBudget", "_LLMCallBudgetExceeded"]


