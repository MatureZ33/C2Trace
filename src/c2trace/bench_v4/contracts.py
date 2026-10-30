from __future__ import annotations

from pathlib import Path
import re
from typing import Final


BENCH_SCHEMA_VERSION: Final = "v4"
CASE_ID_RE: Final = re.compile(r"^(AF|AEL|AURORA|MEP|STK)-[A-Z0-9][A-Z0-9-]*$")
SAFE_ID_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")

SOURCE_KINDS: Final = frozenset(
    {"attack_flow", "attack_evaluations", "ctid_micro", "caldera_native", "aurora"}
)
DATASET_STRATA: Final = frozenset(
    {"named_chain_projection", "micro_emulation_plan", "platform_native_control", "public_tool_benchmark"}
)
SOURCE_STRATUM: Final = {
    "attack_flow": "named_chain_projection",
    "attack_evaluations": "named_chain_projection",
    "ctid_micro": "micro_emulation_plan",
    "caldera_native": "platform_native_control",
    "aurora": "public_tool_benchmark",
}
CASE_PREFIX_SOURCE_KIND: Final = {
    "AF": "attack_flow",
    "AEL": "attack_evaluations",
    "MEP": "ctid_micro",
    "STK": "caldera_native",
    "AURORA": "aurora",
}

SCHEMA_FILES: Final = {
    "c2trace.bench.source_lock.v4": "source_lock.v4.schema.json",
    "c2trace.bench.source_registry.v4": "source_registry.v4.schema.json",
    "c2trace.bench.case.v4": "case.v4.schema.json",
    "c2trace.bench.mapping.v4": "mapping.v4.schema.json",
    "c2trace.bench.target_profile.v4": "target_profile.v4.schema.json",
    "c2trace.bench.operation_plan.v4": "operation_plan.v4.schema.json",
    "c2trace.bench.evidence_plan.v4": "evidence_plan.v4.schema.json",
    "c2trace.bench.cleanup_plan.v4": "cleanup_plan.v4.schema.json",
    "c2trace.bench.ground_truth.v4": "ground_truth.v4.schema.json",
    "c2trace.bench.admission.v4": "admission.v4.schema.json",
}

SUPPORTED_TRACE_TYPES: Final = frozenset(
    {
        "network_connection",
        "process",
        "process_parent_edge",
        "file",
        "registry_value",
        "registry_run_key",
        "scheduled_task",
        "service",
        "powershell_history",
        "dns_cache",
    }
)
RESPONSE_TOOLS: Final = frozenset(
    {
        "kill_process",
        "remove_file",
        "remove_registry",
        "remove_scheduled_task",
        "remove_service",
    }
)


def schema_directory(project_root: str | Path) -> Path:
    return (
        Path(project_root).resolve()
        / "experiments"
        / "c2trace_bench_v4"
        / "schemas"
    )


def expected_source_kind(case_id: str) -> str | None:
    prefix, separator, _ = str(case_id).partition("-")
    return CASE_PREFIX_SOURCE_KIND.get(prefix) if separator else None
