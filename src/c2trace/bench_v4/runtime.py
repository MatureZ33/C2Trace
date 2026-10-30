from __future__ import annotations

"""Manifest-driven runtime contracts for C2Trace Bench v4.

This module deliberately contains no implicit payload discovery and no shell
command construction.  A live controller may only install the files named by
the frozen deployment manifest, and every run is derived from the case's
target and operation contracts.  The functions are dependency-injectable so
the safety state machine can be exercised without a CALDERA server.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import ntpath
from pathlib import Path
import re
import socket
import time
from typing import Any, Callable, Iterable, Mapping, Sequence
from uuid import NAMESPACE_URL, uuid5

from c2trace.bench_v3.caldera_client import (
    CalderaBenchError,
    agent_executors,
    agent_is_recent,
    agent_paw,
    agent_pid,
    find_control_agent,
    install_bundle,
    parse_caldera_datetime,
    validate_operation_report,
)


BENCH_ROOT_NAME = "c2trace_bench_v4"
CASE_ID_RE = re.compile(r"^(AF|AEL|AURORA|MEP|STK)-[A-Z0-9][A-Z0-9-]*$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,80}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UNRESOLVED_TOKEN_RE = re.compile(r"#\{[^{}]+\}|<[^<>]+>|%[A-Za-z_][A-Za-z0-9_]*%")
COLLECTIONS = (
    "attack_flow",
    "attack_evals",
    "ctid_micro",
    "stockpile_controls",
    "aurora",
)
TRIAL_STAGES = (
    "preregistered",
    "preflight_complete",
    "baseline_captured",
    "bundle_verified",
    "bundle_installed",
    "bootstrap_complete",
    "target_frozen",
    "scenario_complete",
    "reports_exported",
    "before_response_captured",
    "source_event_frozen",
    "dryrun_complete",
    "target_gate_passed",
    "execute_complete",
    "after_execute_captured",
    "scored",
    "cleanup_complete",
    "complete",
)


class BenchV4RuntimeError(RuntimeError):
    """Fail-closed v4 runtime contract violation."""


@dataclass(frozen=True, slots=True)
class RuntimeCase:
    bench_root: Path
    case_root: Path
    case: dict[str, Any]
    mapping: dict[str, Any]
    ground_truth: dict[str, Any]
    target_profile: dict[str, Any]
    operation_plan: dict[str, Any]
    evidence_plan: dict[str, Any]
    cleanup_plan: dict[str, Any]
    deployment_manifest: dict[str, Any]

    @property
    def case_id(self) -> str:
        return str(self.case["case_id"])

    @property
    def target(self) -> dict[str, Any]:
        return dict(self.target_profile["target"])

    def operation(self, role: str) -> dict[str, Any]:
        matches = [
            dict(row)
            for row in self.operation_plan.get("operations", [])
            if isinstance(row, Mapping) and str(row.get("role") or "") == role
        ]
        if len(matches) != 1:
            raise BenchV4RuntimeError(
                f"{self.case_id} requires exactly one {role} operation"
            )
        return matches[0]


@dataclass(frozen=True, slots=True)
class VerifiedDeployment:
    case_id: str
    manifest_sha256: str
    files: tuple[dict[str, Any], ...]
    payloads_require_manual_staging: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class RuntimeValues:
    run_id: str
    victim_ip: str
    kali_ip: str
    webshell_port: int | None
    appdata: str
    facts: dict[str, str]
    target_path: str
    target_group: str
    runtime_source_id: str


@dataclass(frozen=True, slots=True)
class CalderaPhaseResult:
    install_receipt: dict[str, Any]
    runtime_source: dict[str, Any]
    control_agent: dict[str, Any]
    driver_agent: dict[str, Any] | None
    target_identity: dict[str, Any]
    bootstrap_operation: dict[str, Any]
    bootstrap_links: tuple[dict[str, Any], ...]
    bootstrap_report: dict[str, Any]
    bootstrap_event_logs: tuple[dict[str, Any], ...]
    scenario_operation: dict[str, Any]
    scenario_links: tuple[dict[str, Any], ...]
    scenario_report: dict[str, Any]
    scenario_event_logs: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class CalderaBootstrapPhaseResult:
    """Manifest-bound result of the only Bootstrap allowed for one run."""

    case_id: str
    run_id: str
    deployment_manifest_sha256: str
    runtime_source_id: str
    install_receipt: dict[str, Any]
    runtime_source: dict[str, Any]
    control_agent: dict[str, Any]
    driver_agent: dict[str, Any] | None
    baseline_paws: tuple[str, ...]
    started_at_utc: datetime
    bootstrap_operation: dict[str, Any]
    bootstrap_links: tuple[dict[str, Any], ...]
    bootstrap_report: dict[str, Any]
    bootstrap_event_logs: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class CalderaTargetCandidate:
    """Read-only CALDERA candidate awaiting host-level identity freezing."""

    case_id: str
    run_id: str
    deployment_manifest_sha256: str
    runtime_source_id: str
    raw_identity: dict[str, Any]
    scenario_paw: str


@dataclass(frozen=True, slots=True)
class CalderaScenarioPhaseResult:
    """Manifest-bound Scenario result created from a frozen target only."""

    case_id: str
    run_id: str
    deployment_manifest_sha256: str
    runtime_source_id: str
    target_identity: dict[str, Any]
    scenario_operation: dict[str, Any]
    scenario_links: tuple[dict[str, Any], ...]
    scenario_report: dict[str, Any]
    scenario_event_logs: tuple[dict[str, Any], ...]


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BenchV4RuntimeError(f"unable to read {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise BenchV4RuntimeError(f"{label} root must be an object: {path}")
    return value


def _contained_file(root: Path, value: Any, label: str) -> Path:
    raw = str(value or "").strip()
    if not raw or Path(raw).is_absolute():
        raise BenchV4RuntimeError(f"{label} must be a non-empty Bench-relative path")
    target = (root / raw).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError as exc:
        raise BenchV4RuntimeError(f"{label} escapes the Bench root") from exc
    if not target.is_file():
        raise BenchV4RuntimeError(f"{label} is missing: {target}")
    return target


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def discover_case_paths(
    bench_root: str | Path,
    *,
    collection: str = "",
    case_id: str = "",
) -> list[Path]:
    root = Path(bench_root).resolve()
    if collection and collection not in COLLECTIONS:
        raise BenchV4RuntimeError(f"unsupported collection: {collection}")
    if case_id and not CASE_ID_RE.fullmatch(case_id):
        raise BenchV4RuntimeError(f"invalid v4 case ID: {case_id}")
    search_root = root / collection if collection else root
    paths = sorted(
        (path.resolve() for path in search_root.rglob("case.json")),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    if case_id:
        paths = [path for path in paths if path.parent.name == case_id]
    if not paths:
        detail = f" for {case_id}" if case_id else ""
        raise BenchV4RuntimeError(f"no v4 cases discovered{detail}")
    return paths


def load_runtime_case(bench_root: str | Path, case_path: str | Path) -> RuntimeCase:
    root = Path(bench_root).resolve()
    path = Path(case_path).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise BenchV4RuntimeError("case path is outside the v4 Bench root") from exc
    case = _read_json(path, "case")
    case_id = str(case.get("case_id") or "")
    if not CASE_ID_RE.fullmatch(case_id) or path.parent.name != case_id:
        raise BenchV4RuntimeError("case ID/path binding is invalid")
    contracts = case.get("contracts")
    if not isinstance(contracts, Mapping):
        raise BenchV4RuntimeError(f"{case_id} has no contracts object")
    documents: dict[str, dict[str, Any]] = {}
    for field in (
        "mapping",
        "ground_truth",
        "target_profile",
        "operation_plan",
        "evidence_plan",
        "cleanup_plan",
        "caldera_bundle",
    ):
        document_path = _contained_file(root, contracts.get(field), f"contracts.{field}")
        document = _read_json(document_path, field)
        if str(document.get("case_id") or "") != case_id:
            raise BenchV4RuntimeError(f"{field} case_id differs from {case_id}")
        documents[field] = document
    runtime = RuntimeCase(
        bench_root=root,
        case_root=path.parent,
        case=case,
        mapping=documents["mapping"],
        ground_truth=documents["ground_truth"],
        target_profile=documents["target_profile"],
        operation_plan=documents["operation_plan"],
        evidence_plan=documents["evidence_plan"],
        cleanup_plan=documents["cleanup_plan"],
        deployment_manifest=documents["caldera_bundle"],
    )
    # Resolve these now so malformed plans fail before any API call.
    runtime.operation("bootstrap")
    runtime.operation("scenario")
    verify_deployment_manifest(runtime)
    return runtime


def verify_deployment_manifest(runtime: RuntimeCase) -> VerifiedDeployment:
    manifest = runtime.deployment_manifest
    if str(manifest.get("schema_version") or "") != "c2trace.bench.caldera_bundle.v4":
        raise BenchV4RuntimeError("unsupported deployment manifest schema")
    if str(manifest.get("source_id") or "") != str(
        runtime.case.get("source", {}).get("source_id") or ""
    ):
        raise BenchV4RuntimeError("deployment manifest source_id drifted")

    verified: list[dict[str, Any]] = []
    listed_paths: set[Path] = set()
    ids_by_kind: dict[str, set[str]] = {}
    for kind in ("abilities", "adversaries", "sources", "payloads"):
        rows = manifest.get(kind, [])
        if not isinstance(rows, list):
            raise BenchV4RuntimeError(f"deployment manifest {kind} must be a list")
        ids: set[str] = set()
        for index, raw in enumerate(rows):
            if not isinstance(raw, Mapping):
                raise BenchV4RuntimeError(f"deployment {kind} row #{index + 1} is invalid")
            path = _contained_file(runtime.bench_root, raw.get("path"), f"deployment {kind} path")
            expected = str(raw.get("sha256") or "").lower()
            if not SHA256_RE.fullmatch(expected) or _sha256(path) != expected:
                raise BenchV4RuntimeError(f"deployment file hash drifted: {path}")
            try:
                path.relative_to(runtime.case_root / "caldera")
            except ValueError as exc:
                raise BenchV4RuntimeError(
                    f"deployment file is outside the case CALDERA bundle: {path}"
                ) from exc
            if path in listed_paths:
                raise BenchV4RuntimeError(f"deployment path is listed more than once: {path}")
            listed_paths.add(path)
            row = dict(raw)
            row["absolute_path"] = str(path)
            verified.append(row)
            if kind != "payloads":
                identifier = str(raw.get("id") or "")
                if not identifier or identifier in ids:
                    raise BenchV4RuntimeError(f"deployment {kind} IDs must be non-empty and unique")
                ids.add(identifier)
        ids_by_kind[kind] = ids

    bundle = runtime.case_root / "caldera"
    actual_files: set[Path] = set()
    for subdir, patterns in (
        ("abilities", ("*.yml", "*.yaml")),
        ("adversaries", ("*.yml", "*.yaml")),
        ("sources", ("*.yml", "*.yaml")),
        ("payloads", ("*",)),
    ):
        directory = bundle / subdir
        if not directory.is_dir():
            continue
        for pattern in patterns:
            actual_files.update(path.resolve() for path in directory.glob(pattern) if path.is_file())
    if actual_files != listed_paths:
        missing = sorted(str(path) for path in actual_files - listed_paths)
        extra = sorted(str(path) for path in listed_paths - actual_files)
        raise BenchV4RuntimeError(
            f"deployment manifest/file set differs (unlisted={missing}, absent={extra})"
        )

    operation_abilities: set[str] = set()
    operation_adversaries: set[str] = set()
    for role in ("bootstrap", "scenario"):
        operation = runtime.operation(role)
        operation_abilities.update(str(value) for value in operation["atomic_ordering"])
        operation_adversaries.add(str(operation["adversary_id"]))
    if ids_by_kind["abilities"] != operation_abilities:
        raise BenchV4RuntimeError("deployment abilities differ from operation_plan")
    if ids_by_kind["adversaries"] != operation_adversaries:
        raise BenchV4RuntimeError("deployment adversaries differ from operation_plan")
    source_template_id = str(runtime.operation_plan["runtime_source"]["id_template"])
    if ids_by_kind["sources"] != {source_template_id}:
        raise BenchV4RuntimeError("deployment source differs from operation_plan runtime source")

    manifest_path = runtime.case_root / "caldera" / "deployment_manifest.json"
    return VerifiedDeployment(
        case_id=runtime.case_id,
        manifest_sha256=_sha256(manifest_path),
        files=tuple(verified),
        payloads_require_manual_staging=tuple(
            row for row in verified if "caldera_name" in row
        ),
    )


def _replace_tokens(value: Any, replacements: Mapping[str, Any]) -> Any:
    if isinstance(value, str):
        result = value
        for key, replacement in replacements.items():
            result = result.replace(key, str(replacement))
        unresolved = UNRESOLVED_TOKEN_RE.search(result)
        if unresolved:
            raise BenchV4RuntimeError(f"unresolved runtime token: {unresolved.group(0)}")
        return result
    if isinstance(value, list):
        return [_replace_tokens(item, replacements) for item in value]
    if isinstance(value, dict):
        return {str(key): _replace_tokens(item, replacements) for key, item in value.items()}
    return value


def render_runtime_value(value: Any, facts: Mapping[str, Any]) -> Any:
    replacements: dict[str, Any] = {}
    for trait, item in facts.items():
        replacements[f"#{{{trait}}}"] = item
    for token in ("run_id", "victim_ip", "kali_ip"):
        if token in facts:
            replacements[f"<{token}>"] = facts[token]
    if facts.get("webshell_port"):
        replacements["<allocated_18080_18979>"] = facts["webshell_port"]
    if facts.get("c2trace.appdata"):
        replacements["%APPDATA%"] = facts["c2trace.appdata"]
    return _replace_tokens(value, replacements)


def deterministic_runtime_source_id(template_id: str, run_id: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"c2trace-bench-v4-source:{template_id}:{run_id}"))


def build_runtime_values(
    runtime: RuntimeCase,
    *,
    run_id: str,
    victim_ip: str,
    kali_ip: str,
    webshell_port: int | None = None,
    appdata: str = "",
) -> RuntimeValues:
    if not RUN_ID_RE.fullmatch(run_id):
        raise BenchV4RuntimeError("run_id must be 3-81 path-safe characters")
    target = runtime.target
    if target.get("network_mode") == "inbound_listener":
        if webshell_port is None or not 18080 <= int(webshell_port) <= 18979:
            raise BenchV4RuntimeError("WebShell requires an allocated port in 18080-18979")
    elif webshell_port is not None:
        raise BenchV4RuntimeError("only inbound-listener cases may allocate a WebShell port")

    seed: dict[str, Any] = {
        "run_id": run_id,
        "victim_ip": victim_ip,
        "kali_ip": kali_ip,
        "webshell_port": webshell_port or "",
        "c2trace.appdata": appdata,
    }
    facts: dict[str, str] = {}
    for row in runtime.target_profile.get("runtime_facts", []):
        if not isinstance(row, Mapping):
            continue
        trait = str(row.get("trait") or "")
        rendered = render_runtime_value(row.get("value_template"), {**seed, **facts})
        facts[trait] = str(rendered)
    replacements = {**seed, **facts}
    target_path = str(render_runtime_value(target["path_template"], replacements))
    target_group = ""
    if target.get("group_template"):
        target_group = str(render_runtime_value(target["group_template"], replacements))
    template_id = str(runtime.operation_plan["runtime_source"]["id_template"])
    return RuntimeValues(
        run_id=run_id,
        victim_ip=victim_ip,
        kali_ip=kali_ip,
        webshell_port=webshell_port,
        appdata=appdata,
        facts=facts,
        target_path=target_path,
        target_group=target_group,
        runtime_source_id=deterministic_runtime_source_id(template_id, run_id),
    )


def _list_api(value: Any, label: str) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [dict(row) for row in value if isinstance(row, Mapping)]
    if isinstance(value, Mapping):
        for key in (label, "items", "data"):
            rows = value.get(key)
            if isinstance(rows, list):
                return [dict(row) for row in rows if isinstance(row, Mapping)]
    raise BenchV4RuntimeError(f"CALDERA response contains no {label} list")


def create_runtime_source(client: Any, runtime: RuntimeCase, values: RuntimeValues) -> dict[str, Any]:
    allowed = set(runtime.operation_plan["runtime_source"]["facts"])
    if set(values.facts) != allowed:
        raise BenchV4RuntimeError(
            f"runtime facts differ from operation_plan (expected={sorted(allowed)}, "
            f"actual={sorted(values.facts)})"
        )
    payload = {
        "id": values.runtime_source_id,
        "name": f"C2Trace Bench v4 {runtime.case_id} {values.run_id}",
        "facts": [
            {"trait": trait, "value": values.facts[trait]}
            for trait in sorted(values.facts)
        ],
        "rules": [],
        "adjustments": [],
        "relationships": [],
        "plugin": "",
    }
    existing = [
        row
        for row in _list_api(client.request("/api/v2/sources"), "sources")
        if str(row.get("id") or "") == values.runtime_source_id
    ]
    if len(existing) > 1:
        raise BenchV4RuntimeError("duplicate CALDERA runtime source")
    if existing:
        observed = sorted(
            (str(row.get("trait") or ""), str(row.get("value") or ""))
            for row in existing[0].get("facts", [])
            if isinstance(row, Mapping)
        )
        wanted = sorted((row["trait"], row["value"]) for row in payload["facts"])
        if observed != wanted:
            raise BenchV4RuntimeError("existing runtime source facts drifted")
        return dict(existing[0])
    created = client.request("/api/v2/sources", method="POST", payload=payload)
    if not isinstance(created, Mapping) or str(created.get("id") or "") != values.runtime_source_id:
        raise BenchV4RuntimeError("CALDERA returned an invalid runtime source")
    return dict(created)


def install_verified_bundle(client: Any, runtime: RuntimeCase) -> dict[str, Any]:
    verified = verify_deployment_manifest(runtime)
    receipt = install_bundle(client, runtime.case_root / "caldera", case_id=runtime.case_id)
    return {
        **receipt,
        "schema_version": "c2trace.bench.install_receipt.v4",
        "case_id": runtime.case_id,
        "deployment_manifest_sha256": verified.manifest_sha256,
        "verified_file_count": len(verified.files),
        "verified_payloads": [dict(row) for row in verified.payloads_require_manual_staging],
        "payload_staging_via_api_supported": False,
    }


def find_driver_agent(agents: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    candidates = [
        dict(agent)
        for agent in agents
        if str(agent.get("group") or "") == "c2t-driver"
        and str(agent.get("platform") or "").lower() == "linux"
        and "sh" in agent_executors(agent)
        and agent_is_recent(agent)
    ]
    if len(candidates) != 1:
        raise BenchV4RuntimeError(
            f"expected exactly one live Linux c2t-driver agent; found {len(candidates)}"
        )
    if not agent_paw(candidates[0]) or not agent_pid(candidates[0]):
        raise BenchV4RuntimeError("driver Sandcat lacks PAW or PID")
    return candidates[0]


def _normalise_path(value: Any) -> str:
    text = str(value or "").strip().strip('"')
    return ntpath.normcase(ntpath.normpath(text)) if text else ""


def select_new_target_agents(
    agents: Iterable[Mapping[str, Any]],
    *,
    baseline_paws: set[str],
    control_agent: Mapping[str, Any],
    expected_path: str,
    target_profile: Mapping[str, Any],
    created_after: datetime,
) -> list[dict[str, Any]]:
    target = target_profile.get("target") if isinstance(target_profile.get("target"), Mapping) else target_profile
    if not isinstance(target, Mapping) or target.get("agent_backed") is not True:
        raise BenchV4RuntimeError("target-agent selection requires an agent-backed profile")
    target_type = str(target.get("target_type") or "")
    wanted_contact = "tcp" if target_type == "manx_tcp_client" else "http"
    expected_executors = [str(value).lower() for value in target.get("executor_order", [])]
    expected = _normalise_path(expected_path)
    control_pid = agent_pid(control_agent)
    control_host = str(control_agent.get("host") or "").lower()
    matches: list[dict[str, Any]] = []
    for raw in agents:
        paw = agent_paw(raw)
        if not paw or paw in baseline_paws or paw == agent_paw(control_agent):
            continue
        if str(raw.get("platform") or "").lower() != "windows":
            continue
        if str(raw.get("contact") or "").lower() != wanted_contact:
            continue
        if control_host and str(raw.get("host") or "").lower() != control_host:
            continue
        if _normalise_path(raw.get("location") or raw.get("exe_name")) != expected:
            continue
        if not agent_pid(raw) or agent_pid(raw) == control_pid:
            continue
        executors = agent_executors(raw)
        if expected_executors and executors[: len(expected_executors)] != expected_executors:
            continue
        if str(raw.get("group") or "").strip().lower() not in {"", "red"}:
            continue
        created = parse_caldera_datetime(raw.get("created") or raw.get("created_at"))
        if created is None or created < created_after:
            continue
        if not agent_is_recent(raw):
            continue
        matches.append(dict(raw))
    return matches


def wait_for_target_agent(
    client: Any,
    *,
    baseline_paws: set[str],
    control_agent: Mapping[str, Any],
    expected_path: str,
    target_profile: Mapping[str, Any],
    created_after: datetime,
    timeout_seconds: float,
    poll_seconds: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        matches = select_new_target_agents(
            client.agents(),
            baseline_paws=baseline_paws,
            control_agent=control_agent,
            expected_path=expected_path,
            target_profile=target_profile,
            created_after=created_after,
        )
        if len(matches) > 1:
            raise BenchV4RuntimeError("more than one new target agent matched the frozen identity")
        if matches:
            return matches[0]
        time.sleep(poll_seconds)
    raise BenchV4RuntimeError("no uniquely identifiable target agent registered in time")


def default_port_in_use(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.2):
            return True
    except OSError:
        return False


def allocate_listener_port(
    run_id: str,
    victim_ip: str,
    *,
    start: int = 18080,
    end: int = 18979,
    in_use: Callable[[str, int], bool] = default_port_in_use,
) -> int:
    if start < 1 or end > 65535 or start > end:
        raise BenchV4RuntimeError("invalid listener port allocation range")
    width = end - start + 1
    first = int(hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:8], 16) % width
    for offset in range(width):
        port = start + ((first + offset) % width)
        if not in_use(victim_ip, port):
            return port
    raise BenchV4RuntimeError("no free WebShell listener port remains in the allocation range")


class TrialStateJournal:
    """Monotonic, append-only stage guard used by the live controller."""

    def __init__(self) -> None:
        self._position = -1
        self.events: list[dict[str, Any]] = []

    def advance(self, stage: str, details: Mapping[str, Any] | None = None) -> None:
        if stage not in TRIAL_STAGES:
            raise BenchV4RuntimeError(f"unknown trial stage: {stage}")
        index = TRIAL_STAGES.index(stage)
        if index != self._position + 1:
            expected = TRIAL_STAGES[self._position + 1] if self._position + 1 < len(TRIAL_STAGES) else "<terminal>"
            raise BenchV4RuntimeError(
                f"trial stage transition is not monotonic: expected {expected}, got {stage}"
            )
        self._position = index
        self.events.append(
            {
                "schema_version": "c2trace.bench.state_event.v4",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stage": stage,
                "details": dict(details or {}),
            }
        )


_TERMINAL_OPERATION_STATES = frozenset({"finished", "out_of_time"})


def _operation_is_terminal(operation: Mapping[str, Any]) -> bool:
    return bool(str(operation.get("finish") or "").strip()) or str(
        operation.get("state") or ""
    ).strip().casefold() in _TERMINAL_OPERATION_STATES


def _assert_no_unsafe_operations(operations: Sequence[Mapping[str, Any]]) -> None:
    unsafe: list[dict[str, Any]] = []
    for operation in operations:
        if _operation_is_terminal(operation):
            continue
        group = str(operation.get("group") or "").strip()
        name = str(operation.get("name") or "").strip()
        folded_group = group.casefold()
        folded_name = name.casefold()
        if (
            not group
            or folded_group == "red"
            or folded_group.startswith("c2t-")
            or "c2trace v4" in folded_name
            or "c2trace bench v4" in folded_name
        ):
            unsafe.append(dict(operation))
    if unsafe:
        raise BenchV4RuntimeError(
            f"unfinished v4/unscoped/red CALDERA Operations require manual review: {len(unsafe)}"
        )


def _assert_operation_name_unused(
    operations: Sequence[Mapping[str, Any]],
    *,
    name: str,
    role: str,
) -> None:
    matches = [row for row in operations if str(row.get("name") or "") == name]
    if matches:
        raise BenchV4RuntimeError(
            f"{role} Operation already exists for this manifest-bound run; "
            "refusing to create a duplicate"
        )


def _operation_rows(client: Any) -> list[dict[str, Any]]:
    return [dict(row) for row in client.operations() if isinstance(row, Mapping)]


def _manifest_binding(runtime: RuntimeCase, values: RuntimeValues) -> tuple[str, str, str, str]:
    return (
        runtime.case_id,
        values.run_id,
        verify_deployment_manifest(runtime).manifest_sha256,
        values.runtime_source_id,
    )


def _validate_phase_binding(
    runtime: RuntimeCase,
    values: RuntimeValues,
    phase: CalderaBootstrapPhaseResult | CalderaTargetCandidate,
    *,
    label: str,
) -> str:
    expected = _manifest_binding(runtime, values)
    observed = (
        phase.case_id,
        phase.run_id,
        phase.deployment_manifest_sha256,
        phase.runtime_source_id,
    )
    if observed != expected:
        raise BenchV4RuntimeError(f"{label} binding differs from the current case/run/manifest")
    return expected[2]


def _operation_name(runtime: RuntimeCase, values: RuntimeValues, role: str) -> str:
    return f"C2Trace v4 {runtime.case_id} {values.run_id} {role}"


def _capture_failed_operation_artifacts(
    client: Any,
    *,
    role: str,
    created_operation: Mapping[str, Any],
) -> dict[str, Any]:
    """Read as much diagnostic state as possible after an Operation wait fails.

    These calls are read-only from the experiment controller's perspective:
    this helper never starts, pauses, stops, or deletes an Operation.  Every
    read is isolated so one unavailable CALDERA endpoint does not prevent the
    remaining evidence from being captured.
    """

    operation_id = str(created_operation.get("id") or "")
    artifacts: dict[str, Any] = {
        "role": role,
        "operation_id": operation_id,
        # Preserve the create response even if the follow-up GET is unavailable.
        "operation": dict(created_operation),
    }
    errors: dict[str, str] = {}
    readers: tuple[tuple[str, str, Callable[[], Any]], ...] = (
        ("operation", "mapping", lambda: client.operation(operation_id)),
        ("links", "sequence", lambda: client.operation_links(operation_id)),
        ("report", "mapping", lambda: client.operation_report(operation_id)),
        ("event_logs", "sequence", lambda: client.operation_event_logs(operation_id)),
    )
    for label, expected_type, reader in readers:
        try:
            value = reader()
            if expected_type == "mapping" and isinstance(value, Mapping):
                artifacts[label] = dict(value)
            elif expected_type == "sequence" and isinstance(value, (list, tuple)):
                artifacts[label] = [
                    dict(row) if isinstance(row, Mapping) else row for row in value
                ]
            else:
                raise TypeError(f"CALDERA {label} response has an unsupported type")
        except Exception as exc:  # best-effort diagnostics must not replace wait failure
            errors[label] = f"{type(exc).__name__}: {exc}"
    if errors:
        artifacts["capture_errors"] = errors
    return artifacts


def _emit_failed_operation_artifacts(
    client: Any,
    *,
    role: str,
    created_operation: Mapping[str, Any],
    sink: Callable[[Mapping[str, Any]], None] | None,
) -> None:
    if sink is None:
        return
    try:
        sink(
            _capture_failed_operation_artifacts(
                client,
                role=role,
                created_operation=created_operation,
            )
        )
    except Exception:
        # The original wait_operation exception is the authoritative failure.
        # Diagnostic collection and persistence must never mask it.
        return


def run_caldera_bootstrap_phase(
    client: Any,
    runtime: RuntimeCase,
    values: RuntimeValues,
    *,
    operation_timeout: float = 360.0,
    poll_seconds: float = 3.0,
    event_sink: Callable[[str, Mapping[str, Any]], None] | None = None,
    failure_artifact_sink: Callable[[Mapping[str, Any]], None] | None = None,
) -> CalderaBootstrapPhaseResult:
    """Install one frozen bundle and execute exactly one Bootstrap Operation.

    Reusing a run ID after CALDERA already has its exact Bootstrap name fails
    closed.  Callers must carry this result into target resolution and Scenario;
    neither later phase installs assets or starts Bootstrap again.
    """

    agents_before = [dict(row) for row in client.agents() if isinstance(row, Mapping)]
    control = find_control_agent(agents_before)
    operations = _operation_rows(client)
    _assert_no_unsafe_operations(operations)
    bootstrap_name = _operation_name(runtime, values, "bootstrap")
    _assert_operation_name_unused(operations, name=bootstrap_name, role="Bootstrap")

    scenario = runtime.operation("scenario")
    driver = (
        find_driver_agent(agents_before)
        if scenario["execution_agent_role"] == "driver"
        else None
    )
    receipt = install_verified_bundle(client, runtime)
    manifest_sha256 = verify_deployment_manifest(runtime).manifest_sha256
    if str(receipt.get("deployment_manifest_sha256") or "") != manifest_sha256:
        raise BenchV4RuntimeError("install receipt differs from the frozen deployment manifest")
    source = create_runtime_source(client, runtime, values)
    baseline_paws = tuple(
        sorted({agent_paw(agent) for agent in agents_before if agent_paw(agent)})
    )
    started = datetime.now(timezone.utc)
    bootstrap = runtime.operation("bootstrap")
    bootstrap_operation = client.create_operation(
        name=bootstrap_name,
        group=str(
            render_runtime_value(
                bootstrap["agent_group_template"],
                {"run_id": values.run_id, **values.facts},
            )
        ),
        adversary_id=str(bootstrap["adversary_id"]),
        planner_id=str(runtime.operation_plan["planner_id"]),
        source_id=values.runtime_source_id,
    )
    if event_sink is not None:
        event_sink(
            "bootstrap_operation_created",
            {"operation_id": str(bootstrap_operation.get("id") or "")},
        )
    try:
        bootstrap_result = client.wait_operation(
            str(bootstrap_operation["id"]),
            expected_ability_ids=list(bootstrap["mandatory_ability_ids"]),
            expected_paw=agent_paw(control),
            timeout_seconds=operation_timeout,
            poll_seconds=poll_seconds,
        )
    except CalderaBenchError:
        _emit_failed_operation_artifacts(
            client,
            role="bootstrap",
            created_operation=bootstrap_operation,
            sink=failure_artifact_sink,
        )
        raise
    bootstrap_report = client.operation_report(str(bootstrap_operation["id"]))
    validate_operation_report(
        bootstrap_report,
        bootstrap["mandatory_ability_ids"],
        expected_paw=agent_paw(control),
    )
    bootstrap_logs = tuple(client.operation_event_logs(str(bootstrap_operation["id"])))
    return CalderaBootstrapPhaseResult(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=manifest_sha256,
        runtime_source_id=values.runtime_source_id,
        install_receipt=dict(receipt),
        runtime_source=dict(source),
        control_agent=dict(control),
        driver_agent=dict(driver) if driver else None,
        baseline_paws=baseline_paws,
        started_at_utc=started,
        bootstrap_operation=dict(bootstrap_result.operation),
        bootstrap_links=tuple(dict(row) for row in bootstrap_result.links),
        bootstrap_report=dict(bootstrap_report),
        bootstrap_event_logs=bootstrap_logs,
    )


def resolve_caldera_target_phase(
    client: Any,
    runtime: RuntimeCase,
    values: RuntimeValues,
    bootstrap_phase: CalderaBootstrapPhaseResult,
    *,
    timeout_seconds: float = 360.0,
    poll_seconds: float = 3.0,
) -> CalderaTargetCandidate:
    """Resolve a CALDERA candidate without asserting host process identity.

    The returned raw identity must be passed to the host-level freezer before
    :func:`run_caldera_scenario_phase`.  This function performs no CALDERA
    write and never creates Scenario.
    """

    manifest_sha256 = _validate_phase_binding(
        runtime, values, bootstrap_phase, label="Bootstrap phase"
    )
    target = runtime.target
    if target["agent_backed"] is True:
        raw_identity = wait_for_target_agent(
            client,
            baseline_paws=set(bootstrap_phase.baseline_paws),
            control_agent=bootstrap_phase.control_agent,
            expected_path=values.target_path,
            target_profile=runtime.target_profile,
            created_after=bootstrap_phase.started_at_utc,
            timeout_seconds=timeout_seconds,
            poll_seconds=poll_seconds,
        )
        scenario_paw = agent_paw(raw_identity)
        if not scenario_paw:
            raise BenchV4RuntimeError("resolved target agent has no PAW")
    else:
        raw_identity = {}
        scenario_paw = agent_paw(bootstrap_phase.driver_agent or {})
        if not scenario_paw:
            raise BenchV4RuntimeError("inbound-listener Scenario lacks its frozen driver PAW")
    return CalderaTargetCandidate(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=manifest_sha256,
        runtime_source_id=values.runtime_source_id,
        raw_identity=dict(raw_identity),
        scenario_paw=scenario_paw,
    )


def _validated_frozen_target(
    runtime: RuntimeCase,
    values: RuntimeValues,
    bootstrap_phase: CalderaBootstrapPhaseResult,
    candidate: CalderaTargetCandidate,
    frozen_target_identity: Mapping[str, Any],
) -> dict[str, Any]:
    _validate_phase_binding(runtime, values, bootstrap_phase, label="Bootstrap phase")
    _validate_phase_binding(runtime, values, candidate, label="target candidate")
    if not isinstance(frozen_target_identity, Mapping):
        raise BenchV4RuntimeError("host target freezer returned malformed identity")
    frozen = dict(frozen_target_identity)
    pid = int(frozen.get("pid") or frozen.get("process_id") or 0)
    if pid <= 0:
        raise BenchV4RuntimeError("frozen target identity has no PID")
    if pid == agent_pid(bootstrap_phase.control_agent):
        raise BenchV4RuntimeError("frozen target resolved to the protected control process")
    if _normalise_path(frozen.get("path")) != _normalise_path(values.target_path):
        raise BenchV4RuntimeError("frozen target path differs from the manifest-bound path")
    creation = parse_caldera_datetime(frozen.get("creation_time_utc"))
    if creation is None:
        raise BenchV4RuntimeError("frozen target identity has no parseable creation time")
    digest = str(frozen.get("sha256") or "").strip().lower()
    if not SHA256_RE.fullmatch(digest):
        raise BenchV4RuntimeError("frozen target identity has no SHA-256 file binding")
    network = frozen.get("network")
    if not isinstance(network, Mapping):
        raise BenchV4RuntimeError("frozen target identity has no network binding")

    target = runtime.target
    if target["agent_backed"] is True:
        raw_pid = agent_pid(candidate.raw_identity)
        if not raw_pid or pid != raw_pid:
            raise BenchV4RuntimeError("host-frozen PID differs from the CALDERA target agent")
        if agent_paw(frozen) and agent_paw(frozen) != candidate.scenario_paw:
            raise BenchV4RuntimeError("host-frozen PAW differs from the CALDERA target agent")
        if _normalise_path(
            candidate.raw_identity.get("location")
            or candidate.raw_identity.get("exe_name")
        ) != _normalise_path(values.target_path):
            raise BenchV4RuntimeError("CALDERA target path drifted before host freezing")
        if str(frozen.get("remote_address") or network.get("remote_address") or "") != values.kali_ip:
            raise BenchV4RuntimeError("frozen target peer differs from the configured Kali host")
        if int(frozen.get("remote_port") or network.get("remote_port") or 0) != int(
            target["contact"]["listener_port"]
        ):
            raise BenchV4RuntimeError("frozen target peer port differs from the manifest")
    else:
        if int(frozen.get("local_port") or network.get("local_port") or 0) != int(
            values.webshell_port or 0
        ):
            raise BenchV4RuntimeError("listener owner port differs from the allocated port")
    return {**candidate.raw_identity, **frozen, "pid": pid, "sha256": digest}


def _validate_current_target_agent(
    client: Any,
    values: RuntimeValues,
    candidate: CalderaTargetCandidate,
    frozen: Mapping[str, Any],
) -> dict[str, Any]:
    matches = [
        dict(row)
        for row in client.agents()
        if isinstance(row, Mapping) and agent_paw(row) == candidate.scenario_paw
    ]
    if len(matches) != 1:
        raise BenchV4RuntimeError("frozen target PAW is no longer unique in CALDERA")
    current = matches[0]
    if not agent_is_recent(current):
        raise BenchV4RuntimeError("frozen target agent is no longer alive and trusted")
    if agent_pid(current) != int(frozen["pid"]):
        raise BenchV4RuntimeError("frozen target PID drifted before Scenario")
    if _normalise_path(current.get("location") or current.get("exe_name")) != _normalise_path(
        values.target_path
    ):
        raise BenchV4RuntimeError("frozen target path drifted before Scenario")
    group = str(current.get("group") or "").strip()
    if group.casefold() not in {"", "red", values.target_group.casefold()}:
        raise BenchV4RuntimeError("frozen target agent moved to an unexpected group")
    if group != values.target_group:
        patched = client.patch_agent_group(candidate.scenario_paw, values.target_group)
        if not isinstance(patched, Mapping):
            raise BenchV4RuntimeError("CALDERA returned a malformed target group update")
        current = dict(patched)
    if (
        agent_paw(current) != candidate.scenario_paw
        or agent_pid(current) != int(frozen["pid"])
        or str(current.get("group") or "") != values.target_group
    ):
        raise BenchV4RuntimeError("CALDERA target identity drifted during group assignment")
    return current


def run_caldera_scenario_phase(
    client: Any,
    runtime: RuntimeCase,
    values: RuntimeValues,
    bootstrap_phase: CalderaBootstrapPhaseResult,
    target_candidate: CalderaTargetCandidate,
    frozen_target_identity: Mapping[str, Any],
    *,
    operation_timeout: float = 360.0,
    poll_seconds: float = 3.0,
    event_sink: Callable[[str, Mapping[str, Any]], None] | None = None,
    failure_artifact_sink: Callable[[Mapping[str, Any]], None] | None = None,
) -> CalderaScenarioPhaseResult:
    """Validate a complete host identity and then create exactly one Scenario."""

    frozen = _validated_frozen_target(
        runtime,
        values,
        bootstrap_phase,
        target_candidate,
        frozen_target_identity,
    )
    operations = _operation_rows(client)
    _assert_no_unsafe_operations(operations)
    scenario_name = _operation_name(runtime, values, "scenario")
    _assert_operation_name_unused(operations, name=scenario_name, role="Scenario")

    if runtime.target["agent_backed"] is True:
        if not values.target_group:
            raise BenchV4RuntimeError("agent-backed target lacks a target group")
        current = _validate_current_target_agent(
            client, values, target_candidate, frozen
        )
        target_identity = {
            **current,
            **frozen,
            "paw": target_candidate.scenario_paw,
            "group": values.target_group,
        }
    else:
        current_driver = find_driver_agent(client.agents())
        if agent_paw(current_driver) != target_candidate.scenario_paw:
            raise BenchV4RuntimeError("Scenario driver PAW drifted after Bootstrap")
        target_identity = dict(frozen)

    if event_sink is not None:
        event_sink(
            "target_identity_validated",
            {"paw": target_candidate.scenario_paw, "pid": int(target_identity["pid"])},
        )
    scenario = runtime.operation("scenario")
    scenario_group = str(
        render_runtime_value(
            scenario["agent_group_template"],
            {"run_id": values.run_id, **values.facts},
        )
    )
    scenario_operation = client.create_operation(
        name=scenario_name,
        group=scenario_group,
        adversary_id=str(scenario["adversary_id"]),
        planner_id=str(runtime.operation_plan["planner_id"]),
        source_id=values.runtime_source_id,
    )
    if event_sink is not None:
        event_sink(
            "scenario_operation_created",
            {"operation_id": str(scenario_operation.get("id") or "")},
        )
    try:
        scenario_result = client.wait_operation(
            str(scenario_operation["id"]),
            expected_ability_ids=list(scenario["mandatory_ability_ids"]),
            expected_paw=target_candidate.scenario_paw,
            timeout_seconds=operation_timeout,
            poll_seconds=poll_seconds,
        )
    except CalderaBenchError:
        _emit_failed_operation_artifacts(
            client,
            role="scenario",
            created_operation=scenario_operation,
            sink=failure_artifact_sink,
        )
        raise
    scenario_report = client.operation_report(str(scenario_operation["id"]))
    validate_operation_report(
        scenario_report,
        scenario["mandatory_ability_ids"],
        expected_paw=target_candidate.scenario_paw,
    )
    scenario_logs = tuple(client.operation_event_logs(str(scenario_operation["id"])))
    return CalderaScenarioPhaseResult(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=bootstrap_phase.deployment_manifest_sha256,
        runtime_source_id=values.runtime_source_id,
        target_identity=dict(target_identity),
        scenario_operation=dict(scenario_result.operation),
        scenario_links=tuple(dict(row) for row in scenario_result.links),
        scenario_report=dict(scenario_report),
        scenario_event_logs=scenario_logs,
    )


def run_caldera_phase(
    client: Any,
    runtime: RuntimeCase,
    values: RuntimeValues,
    *,
    operation_timeout: float = 360.0,
    poll_seconds: float = 3.0,
    target_resolver: Callable[
        [RuntimeCase, RuntimeValues, Mapping[str, Any]], Mapping[str, Any]
    ]
    | None = None,
    listener_resolver: Callable[[RuntimeCase, RuntimeValues], Mapping[str, Any]] | None = None,
    event_sink: Callable[[str, Mapping[str, Any]], None] | None = None,
) -> CalderaPhaseResult:
    """Compatibility wrapper for Bootstrap, host freeze, and Scenario.

    New callers should execute the three public phase functions explicitly so
    they can persist Bootstrap artifacts and freeze the host identity between
    CALDERA writes.  ``listener_resolver`` is retained for the previous
    two-argument controller callback; unlike the old implementation, it is now
    required for agent-backed targets too when ``target_resolver`` is absent.
    """

    if target_resolver is not None and listener_resolver is not None:
        raise BenchV4RuntimeError("supply only one target identity resolver")
    bootstrap_phase = run_caldera_bootstrap_phase(
        client,
        runtime,
        values,
        operation_timeout=operation_timeout,
        poll_seconds=poll_seconds,
        event_sink=event_sink,
    )
    target_candidate = resolve_caldera_target_phase(
        client,
        runtime,
        values,
        bootstrap_phase,
        timeout_seconds=operation_timeout,
        poll_seconds=poll_seconds,
    )
    if target_resolver is not None:
        frozen_target = target_resolver(
            runtime, values, dict(target_candidate.raw_identity)
        )
    elif listener_resolver is not None:
        frozen_target = listener_resolver(runtime, values)
    else:
        raise BenchV4RuntimeError(
            "Scenario requires a host-level target resolver after Bootstrap"
        )
    scenario_phase = run_caldera_scenario_phase(
        client,
        runtime,
        values,
        bootstrap_phase,
        target_candidate,
        frozen_target,
        operation_timeout=operation_timeout,
        poll_seconds=poll_seconds,
        event_sink=event_sink,
    )
    return CalderaPhaseResult(
        install_receipt=bootstrap_phase.install_receipt,
        runtime_source=bootstrap_phase.runtime_source,
        control_agent=bootstrap_phase.control_agent,
        driver_agent=bootstrap_phase.driver_agent,
        target_identity=scenario_phase.target_identity,
        bootstrap_operation=bootstrap_phase.bootstrap_operation,
        bootstrap_links=bootstrap_phase.bootstrap_links,
        bootstrap_report=bootstrap_phase.bootstrap_report,
        bootstrap_event_logs=bootstrap_phase.bootstrap_event_logs,
        scenario_operation=scenario_phase.scenario_operation,
        scenario_links=scenario_phase.scenario_links,
        scenario_report=scenario_phase.scenario_report,
        scenario_event_logs=scenario_phase.scenario_event_logs,
    )
