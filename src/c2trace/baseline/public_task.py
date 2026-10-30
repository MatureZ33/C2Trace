"""Load and render the public, neutral ReAct task contract."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from c2trace.baseline.neutral_records import assert_public_input, sanitize_alert


DEFAULT_SPEC_ROOT = Path(__file__).resolve().parents[3] / "experiments" / "c2trace_bench_v4" / "baselines" / "public_task_spec"


def _load_json(root: Path, name: str) -> dict[str, Any]:
    path = root / name
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"public task spec must be an object: {path}")
    return value


def load_public_task_spec(root: str | Path | None = None) -> dict[str, Any]:
    task_root = Path(root) if root else DEFAULT_SPEC_ROOT
    return {
        "task": _load_json(task_root, "task_spec.json"),
        "tools": _load_json(task_root, "tool_schema.json"),
        "safety": _load_json(task_root, "system_safety.json"),
        "output": _load_json(task_root, "output_schema.json"),
    }


def public_tool_schema(root: str | Path | None = None) -> dict[str, Any]:
    return load_public_task_spec(root)["tools"]


def build_public_system_prompt(
    alert: Mapping[str, Any],
    *,
    spec_root: str | Path | None = None,
    execute_response: bool = True,
) -> str:
    """Build a prompt without case-specific answers or private policy."""
    clean_alert = sanitize_alert(alert)
    spec = load_public_task_spec(spec_root)
    task = spec["task"].get("task") if isinstance(spec["task"].get("task"), Mapping) else {}
    tools = spec["tools"]
    safety = spec["safety"]
    output = spec["output"]
    phase = (
        "You may request response tools after inspecting the relevant live object. "
        "A response tool result, not your narrative, determines whether an action succeeded."
        if execute_response
        else "This is an observation-only pass. Do not call response tools or the post-state tool."
    )
    response_names = ", ".join(sorted((tools.get("response") or {}).keys()))
    read_names = ", ".join(sorted((tools.get("read_only") or {}).keys()))
    lines = [
        "You are an independent endpoint investigation agent.",
        str(task.get("objective") or "Investigate the supplied network alert using live endpoint tools."),
        phase,
        "Use the alert as a starting hint and choose any useful read-only tools. Do not assume a process, file, or persistence object exists.",
        "Report only values that appear in the alert or in a tool result. Do not invent missing fields.",
        "Read-only tools: " + read_names,
        "Response tools: " + response_names,
        "General protections: system and control processes/services, system registry namespaces, and paths outside the experiment file root are protected.",
        "Do not use or request hidden answer data. Do not include private framework fields in your output.",
        "",
        "Return exactly one JSON object with exactly two top-level arrays:",
        '{"observations": [], "actions": []}',
        "Each observation has kind (network, process, file, or persistence), details copied from a tool result, and optional evidence_refs.",
        "Each action has tool and arguments. Actions are requests; only successful response tool calls count as executed.",
        "",
        "Alert:",
        json.dumps(clean_alert, ensure_ascii=False, indent=2, sort_keys=True, default=str),
        "",
        "Output schema summary:",
        json.dumps({"required": output.get("required"), "properties": output.get("properties")}, ensure_ascii=False, sort_keys=True),
    ]
    return "\n".join(lines)


def assert_public_prompt_inputs(alert: Mapping[str, Any], spec_root: str | Path | None = None) -> None:
    assert_public_input(alert)
    spec = load_public_task_spec(spec_root)
    assert_public_input(spec)


__all__ = ["DEFAULT_SPEC_ROOT", "load_public_task_spec", "public_tool_schema", "build_public_system_prompt", "assert_public_prompt_inputs"]
