from __future__ import annotations

"""Fail-closed live safety adapters for C2Trace Bench v4.

The adapters in this module do not open sockets, invoke PowerShell, or call
CALDERA themselves.  All observations and mutations are supplied through
small dependency-injection protocols.  This makes the live safety contract
testable without touching the experiment VMs and keeps privileged host work
behind an explicit, auditable boundary.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import ntpath
from pathlib import Path
import re
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence, TypeVar
from urllib.parse import urlsplit, urlunsplit

from c2trace.time_identity import creation_times_match as _shared_creation_times_match

from c2trace.bench_v3.caldera_client import (
    agent_executors,
    agent_is_recent,
    agent_paw,
    agent_pid,
)

from .runtime import RuntimeCase, verify_deployment_manifest


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CASE_ID_RE = re.compile(r"^(AF|AEL|AURORA|MEP|STK)-[A-Z0-9][A-Z0-9-]*$")
CASE_ID_IN_TEXT_RE = re.compile(r"(?:^|\s)(?:AF|AEL|AURORA|MEP|STK)-[A-Z0-9][A-Z0-9-]*(?:\s|$)")
UNRESOLVED_RE = re.compile(r"#\{|<[^>]+>|%[^%]+%")
WILDCARD_RE = re.compile(r"[*?\[\]]")
TERMINAL_OPERATION_STATES = frozenset({"finished", "out_of_time"})
NPF_DEVICE_RE = re.compile(
    r"^\\Device\\NPF_\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$"
)


class LiveSafetyError(RuntimeError):
    """A live prerequisite or identity could not be proven safe."""


class PayloadStagingError(LiveSafetyError):
    """A pinned payload does not have a valid server-side staging receipt."""


class CleanupBackendError(LiveSafetyError):
    """A cleanup selector or its live observation is ambiguous or drifted."""


class LivePreflightDependencies(Protocol):
    """Read-only dependencies used by :func:`run_live_preflight`."""

    def is_admin(self) -> bool: ...

    def inspect_file(self, path: str) -> Mapping[str, Any]: ...

    def inspect_directory(self, path: str) -> Mapping[str, Any]: ...

    def tcp_reachable(self, host: str, port: int) -> bool: ...

    def inspect_interface(self, name: str) -> Mapping[str, Any]: ...

    def model_configuration(self) -> Mapping[str, Any]: ...

    def current_vm_snapshot_id(self) -> str: ...

    def caldera_agents(self) -> Sequence[Mapping[str, Any]]: ...

    def caldera_operations(self) -> Sequence[Mapping[str, Any]]: ...

    def inspect_process(self, pid: int) -> Mapping[str, Any]: ...

    def now_utc(self) -> datetime: ...


@dataclass(frozen=True, slots=True)
class LivePreflightConfig:
    case_id: str
    kali_ip: str
    victim_ip: str
    suricata_executable: str
    suricata_configuration: str
    npcap_driver: str
    capture_interface: str
    results_path: str
    allowed_results_root: str
    vm_snapshot_id: str
    control_sandcat_path: str
    control_sandcat_sha256: str
    control_host: str = ""
    require_driver: bool = False
    require_model: bool = True
    require_caldera_tcp: bool = True
    model_name: str = "deepseek-chat"
    caldera_http_port: int = 8888
    caldera_tcp_port: int = 7010


@dataclass(frozen=True, slots=True)
class PayloadWriteAuthorization:
    case_id: str
    caldera_server: str
    required: bool
    verified: bool
    deployment_manifest_sha256: str
    payload_name: str = ""
    payload_sha256: str = ""
    receipt_sha256: str = ""


class PowerShellCleanupTransport(Protocol):
    """Privileged transport implemented by the live Windows harness.

    Implementations may use PowerShell remoting or a local elevated process,
    but must return structured mappings.  The Bench safety layer never builds
    an interpolated script from untrusted values.
    """

    def inspect_process(self, pid: int) -> Mapping[str, Any]: ...

    def inspect_file(self, path: str) -> Mapping[str, Any]: ...

    def inspect_directory(self, path: str) -> Mapping[str, Any]: ...

    def inspect_registry(
        self, hive: str, key_path: str, value_name: str | None
    ) -> Mapping[str, Any]: ...

    def stop_process(self, pid: int) -> Mapping[str, Any]: ...

    def remove_file(self, path: str) -> Mapping[str, Any]: ...

    def remove_directory(self, path: str) -> Mapping[str, Any]: ...

    def remove_registry(
        self, hive: str, key_path: str, value_name: str | None
    ) -> Mapping[str, Any]: ...


def _normalise_windows_path(value: Any) -> str:
    raw = str(value or "").strip().strip('"')
    return ntpath.normcase(ntpath.normpath(raw)) if raw else ""


def _normalise_time(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return raw.casefold()
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


# Windows Win32_Process.CreationDate can jitter by tens of milliseconds between
# two reads of the same process.  Compare the frozen vs. observed creation stamp
# with a small tolerance instead of an exact match; fall back to the normalized
# string compare when either value cannot be parsed as a datetime.
_CREATION_TIME_TOLERANCE_SECONDS = 2.0


def _creation_times_match(left: Any, right: Any) -> bool:
    return _shared_creation_times_match(left, right)


def _require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise LiveSafetyError(f"{label} did not return an unambiguous boolean")
    return value


def _require_exact_file(
    observed: Mapping[str, Any], expected_path: str, label: str
) -> dict[str, Any]:
    if _require_bool(observed.get("exists"), f"{label}.exists") is not True:
        raise LiveSafetyError(f"{label} is missing: {expected_path}")
    if observed.get("is_file") is not True:
        raise LiveSafetyError(f"{label} is not a regular file: {expected_path}")
    actual = _normalise_windows_path(
        observed.get("path") or observed.get("canonical_path")
    )
    if actual != _normalise_windows_path(expected_path):
        raise LiveSafetyError(f"{label} path differs from the configured path")
    return dict(observed)


def _contained_windows_path(path: str, root: str, *, allow_root: bool = False) -> bool:
    child = _normalise_windows_path(path)
    parent = _normalise_windows_path(root)
    if not child or not parent:
        return False
    try:
        common = ntpath.commonpath([child, parent])
    except ValueError:
        return False
    return common == parent and (allow_root or child != parent)


def _normalise_server(value: Any) -> str:
    raw = str(value or "").strip()
    parts = urlsplit(raw)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise PayloadStagingError("CALDERA server must be an absolute HTTP(S) URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise PayloadStagingError("CALDERA server URL contains unsupported components")
    if parts.path not in {"", "/"}:
        raise PayloadStagingError("CALDERA server URL must not contain an API path")
    try:
        port = parts.port
    except ValueError as exc:
        raise PayloadStagingError("CALDERA server URL has an invalid port") from exc
    host = parts.hostname.casefold()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((parts.scheme.casefold(), netloc, "", "", ""))


def _safe_agent_receipt(agent: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "paw": agent_paw(agent),
        "pid": agent_pid(agent),
        "created": str(agent.get("created") or ""),
        "last_seen": str(agent.get("last_seen") or agent.get("last_trusted_seen") or ""),
        # CALDERA 5.x commonly exposes the absolute executable as ``location``
        # and only the basename as ``exe_name``.  Safety binding needs the
        # absolute path, never the display basename.
        "path": str(
            agent.get("location") or agent.get("path") or agent.get("exe_name") or ""
        ),
        "group": str(agent.get("group") or ""),
        "host": str(agent.get("host") or ""),
        "platform": str(agent.get("platform") or ""),
        "contact": str(agent.get("contact") or ""),
        "executors": agent_executors(agent),
    }


def unfinished_operation_risks(
    operations: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return every unfinished v4, blank-group, or red-group Operation."""

    risks: list[dict[str, Any]] = []
    for raw in operations:
        if not isinstance(raw, Mapping):
            continue
        state = str(raw.get("state") or "").strip().casefold()
        if bool(str(raw.get("finish") or "").strip()) or state in TERMINAL_OPERATION_STATES:
            continue
        group = str(raw.get("group") or "").strip()
        group_folded = group.casefold()
        name = str(raw.get("name") or "").strip()
        name_folded = name.casefold()
        is_v4 = (
            "c2trace v4" in name_folded
            or "c2trace bench v4" in name_folded
            or group_folded.startswith("c2t-")
            or CASE_ID_IN_TEXT_RE.search(name) is not None
        )
        reasons: list[str] = []
        if is_v4:
            reasons.append("unfinished_v4")
        if not group:
            reasons.append("unfinished_empty_group")
        if group_folded == "red":
            reasons.append("unfinished_red_group")
        if reasons:
            risks.append(
                {
                    "id": str(raw.get("id") or ""),
                    "name": name,
                    "group": group,
                    "state": str(raw.get("state") or ""),
                    "reasons": reasons,
                }
            )
    return risks


def _select_unique_agent(
    agents: Sequence[Mapping[str, Any]],
    *,
    group: str,
    platform: str,
    required_executor: str,
    now: datetime,
) -> dict[str, Any]:
    candidates = [
        dict(agent)
        for agent in agents
        if str(agent.get("group") or "") == group
        and str(agent.get("platform") or "").casefold() == platform.casefold()
        and required_executor in agent_executors(agent)
        and agent_is_recent(agent, now=now)
    ]
    if len(candidates) != 1:
        raise LiveSafetyError(
            f"expected exactly one live {platform} {group} agent; found {len(candidates)}"
        )
    selected = candidates[0]
    if not agent_paw(selected) or agent_pid(selected) <= 0:
        raise LiveSafetyError(f"{group} agent lacks a PAW or PID")
    return selected


def run_live_preflight(
    config: LivePreflightConfig,
    dependencies: LivePreflightDependencies,
) -> dict[str, Any]:
    """Perform the complete read-only M2 live gate.

    No check is optional: callers that only need static validation must not use
    this function.  The returned receipt contains identities and digests but
    never contains the model API key.
    """

    if not CASE_ID_RE.fullmatch(config.case_id):
        raise LiveSafetyError("preflight case_id is not a v4 case ID")
    if dependencies.is_admin() is not True:
        raise LiveSafetyError("Bench v4 live execution requires Administrator privileges")
    if config.require_model and config.model_name not in {
        "deepseek-chat",
        "deepseek-v4-flash",
        "deepseek-v4-pro",
    }:
        raise LiveSafetyError(
            "Bench v4 model must be deepseek-chat, deepseek-v4-flash, or deepseek-v4-pro"
        )
    if not SHA256_RE.fullmatch(config.control_sandcat_sha256.casefold()):
        raise LiveSafetyError("control Sandcat expected SHA-256 is invalid")
    if not str(config.vm_snapshot_id).strip():
        raise LiveSafetyError("a frozen VM snapshot ID is required")

    suricata_exe = _require_exact_file(
        dependencies.inspect_file(config.suricata_executable),
        config.suricata_executable,
        "Suricata executable",
    )
    suricata_config = _require_exact_file(
        dependencies.inspect_file(config.suricata_configuration),
        config.suricata_configuration,
        "Suricata configuration",
    )
    npcap = _require_exact_file(
        dependencies.inspect_file(config.npcap_driver),
        config.npcap_driver,
        "Npcap driver",
    )

    interface = dependencies.inspect_interface(config.capture_interface)
    if interface.get("exists") is not True or interface.get("up") is not True:
        raise LiveSafetyError("the configured Suricata capture interface is absent or down")
    if interface.get("capture_capable") is not True:
        raise LiveSafetyError("the configured interface is not Npcap capture-capable")
    if str(interface.get("name") or "") != config.capture_interface:
        raise LiveSafetyError("the observed capture interface name drifted")
    addresses = {str(value) for value in interface.get("addresses", [])}
    if config.victim_ip not in addresses:
        raise LiveSafetyError("the capture interface is not bound to the victim IP")
    npf_device = str(interface.get("npf_device") or "").strip()
    if not NPF_DEVICE_RE.fullmatch(npf_device):
        raise LiveSafetyError("the capture interface has no exact Npcap device binding")

    results = dependencies.inspect_directory(config.results_path)
    if (
        results.get("exists") is not True
        or results.get("is_directory") is not True
        or results.get("writable") is not True
    ):
        raise LiveSafetyError("the Bench v4 results path is not an existing writable directory")
    observed_results = str(results.get("path") or results.get("canonical_path") or "")
    if _normalise_windows_path(observed_results) != _normalise_windows_path(
        config.results_path
    ):
        raise LiveSafetyError("the observed results path drifted")
    if not _contained_windows_path(
        config.results_path, config.allowed_results_root, allow_root=True
    ):
        raise LiveSafetyError("the results path is outside the configured results root")

    model: Mapping[str, Any] = {}
    if config.require_model:
        model = dependencies.model_configuration()
        if str(model.get("model") or "") != config.model_name:
            raise LiveSafetyError("DEEPSEEK_MODEL differs from the frozen preflight model")
        if model.get("api_key_present") is not True:
            raise LiveSafetyError("DEEPSEEK_API_KEY is missing")

    observed_snapshot = str(dependencies.current_vm_snapshot_id() or "").strip()
    if observed_snapshot != config.vm_snapshot_id:
        raise LiveSafetyError("the active VM snapshot differs from the frozen snapshot ID")

    if dependencies.tcp_reachable(config.kali_ip, config.caldera_http_port) is not True:
        raise LiveSafetyError("CALDERA HTTP/8888 is unreachable")
    if config.require_caldera_tcp and dependencies.tcp_reachable(
        config.kali_ip, config.caldera_tcp_port
    ) is not True:
        raise LiveSafetyError("CALDERA TCP/7010 is unreachable")

    now = dependencies.now_utc()
    if now.tzinfo is None:
        raise LiveSafetyError("preflight clock must be timezone-aware")
    agents = list(dependencies.caldera_agents())
    control = _select_unique_agent(
        agents,
        group="c2t-control",
        platform="windows",
        required_executor="psh",
        now=now,
    )
    if str(control.get("contact") or "").casefold() != "http":
        raise LiveSafetyError("control Sandcat must use the HTTP contact")
    if config.control_host and str(control.get("host") or "").casefold() != str(
        config.control_host
    ).casefold():
        raise LiveSafetyError("control Sandcat host differs from the configured victim")
    raw_addresses = control.get("host_ip_addrs") or []
    if isinstance(raw_addresses, str):
        raw_addresses = [raw_addresses]
    if config.victim_ip not in {str(value) for value in raw_addresses}:
        raise LiveSafetyError("control Sandcat is not bound to the victim IP")

    expected_control_path = _normalise_windows_path(config.control_sandcat_path)
    agent_path = _normalise_windows_path(
        control.get("location") or control.get("path") or control.get("exe_name")
    )
    if agent_path != expected_control_path:
        raise LiveSafetyError("control Sandcat agent path differs from the protected path")
    process = dependencies.inspect_process(agent_pid(control))
    if process.get("running") is not True or int(process.get("pid") or 0) != agent_pid(control):
        raise LiveSafetyError("control Sandcat process is absent or its PID drifted")
    if _normalise_windows_path(process.get("path")) != expected_control_path:
        raise LiveSafetyError("control Sandcat process path drifted")
    creation = _normalise_time(
        process.get("creation_time_utc") or process.get("creation_time")
    )
    if not creation:
        raise LiveSafetyError("control Sandcat process has no creation-time identity")
    control_file = _require_exact_file(
        dependencies.inspect_file(config.control_sandcat_path),
        config.control_sandcat_path,
        "control Sandcat file",
    )
    if str(control_file.get("sha256") or "").casefold() != str(
        config.control_sandcat_sha256
    ).casefold():
        raise LiveSafetyError("control Sandcat file SHA-256 drifted")

    driver: dict[str, Any] | None = None
    if config.require_driver:
        driver = _select_unique_agent(
            agents,
            group="c2t-driver",
            platform="linux",
            required_executor="sh",
            now=now,
        )
        if agent_pid(driver) == agent_pid(control) and str(driver.get("host") or "") == str(
            control.get("host") or ""
        ):
            raise LiveSafetyError("driver identity collides with the protected control agent")

    unsafe = unfinished_operation_risks(dependencies.caldera_operations())
    if unsafe:
        raise LiveSafetyError(
            "unfinished v4/blank/red CALDERA Operations require manual review: "
            + json.dumps(unsafe, ensure_ascii=False, sort_keys=True)
        )

    return {
        "schema_version": "c2trace.bench.live_preflight.v4",
        "checked_at_utc": now.astimezone(timezone.utc).isoformat(),
        "case_id": config.case_id,
        "vm_snapshot_id": observed_snapshot,
        "admin": True,
        "suricata": {
            "executable": str(suricata_exe.get("path")),
            "configuration": str(suricata_config.get("path")),
            "interface": config.capture_interface,
            "victim_ip": config.victim_ip,
            "capture_device": npf_device,
        },
        "npcap": {"driver": str(npcap.get("path")), "present": True},
        "model": (
            {"name": config.model_name, "api_key_present": True}
            if config.require_model
            else {"required": False, "status": "not_used_by_qualification"}
        ),
        "ports": {
            "caldera_http_8888": True,
            "caldera_tcp_7010": True if config.require_caldera_tcp else "not_required",
        },
        "results_path": observed_results,
        "control_agent": {
            **_safe_agent_receipt(control),
            "process_creation_time_utc": creation,
            "file_sha256": config.control_sandcat_sha256.casefold(),
        },
        "driver_agent": _safe_agent_receipt(driver) if driver is not None else None,
        "unfinished_operation_risks": [],
        "write_authorized": False,
    }


def _canonical_json_hash(value: Mapping[str, Any]) -> str:
    raw = json.dumps(
        dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def validate_payload_staging_receipt(
    runtime: RuntimeCase,
    *,
    caldera_server: str,
    receipt: Mapping[str, Any] | None,
    observed_server_payload_sha256: str | None = None,
) -> PayloadWriteAuthorization:
    """Authorize CALDERA writes only after pinned payload read-back verification."""

    verified = verify_deployment_manifest(runtime)
    payloads = [
        dict(row)
        for row in runtime.deployment_manifest.get("payloads", [])
        if isinstance(row, Mapping)
    ]
    server = _normalise_server(caldera_server)
    target_kind = str(runtime.target.get("kind") or "")
    is_webshell = target_kind in {"ctid_windows_webshell", "webshell"}

    if not is_webshell:
        if payloads:
            raise PayloadStagingError("a non-WebShell case unexpectedly declares a payload")
        if receipt is not None or observed_server_payload_sha256 is not None:
            raise PayloadStagingError("non-WebShell cases must not supply a payload receipt")
        return PayloadWriteAuthorization(
            case_id=runtime.case_id,
            caldera_server=server,
            required=False,
            verified=True,
            deployment_manifest_sha256=verified.manifest_sha256,
        )

    if len(payloads) != 1:
        raise PayloadStagingError("WebShell case requires exactly one pinned payload")
    if not isinstance(receipt, Mapping):
        raise PayloadStagingError("WebShell CALDERA writes require a staging receipt")
    required_fields = {
        "schema_version",
        "receipt_id",
        "case_id",
        "deployment_manifest_sha256",
        "caldera_server",
        "payload_name",
        "expected_sha256",
        "observed_sha256",
        "verified_at_utc",
        "verification_method",
    }
    if set(receipt) != required_fields:
        missing = sorted(required_fields - set(receipt))
        extra = sorted(set(receipt) - required_fields)
        raise PayloadStagingError(
            f"payload receipt field set differs (missing={missing}, extra={extra})"
        )
    if receipt.get("schema_version") != "c2trace.bench.payload_staging_receipt.v4":
        raise PayloadStagingError("payload receipt schema_version is invalid")
    if not str(receipt.get("receipt_id") or "").strip():
        raise PayloadStagingError("payload receipt_id is empty")
    if receipt.get("verification_method") not in {
        "caldera_api_readback_sha256",
        "server_filesystem_sha256",
    }:
        raise PayloadStagingError("payload receipt verification_method is unsupported")
    try:
        timestamp = datetime.fromisoformat(
            str(receipt.get("verified_at_utc") or "").replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise PayloadStagingError("payload receipt timestamp is invalid") from exc
    if timestamp.tzinfo is None:
        raise PayloadStagingError("payload receipt timestamp must be timezone-aware")

    payload = payloads[0]
    expected = str(payload.get("sha256") or "").casefold()
    name = str(payload.get("caldera_name") or "")
    observed = str(observed_server_payload_sha256 or "").casefold()
    receipt_observed = str(receipt.get("observed_sha256") or "").casefold()
    receipt_expected = str(receipt.get("expected_sha256") or "").casefold()
    if not SHA256_RE.fullmatch(expected):
        raise PayloadStagingError("deployment payload SHA-256 is invalid")
    if str(receipt.get("case_id") or "") != runtime.case_id:
        raise PayloadStagingError("payload receipt case_id drifted")
    if str(receipt.get("deployment_manifest_sha256") or "").casefold() != str(
        verified.manifest_sha256
    ).casefold():
        raise PayloadStagingError("payload receipt deployment manifest hash drifted")
    if _normalise_server(receipt.get("caldera_server")) != server:
        raise PayloadStagingError("payload receipt CALDERA server drifted")
    if str(receipt.get("payload_name") or "") != name:
        raise PayloadStagingError("payload receipt name drifted")
    if receipt_expected != expected or receipt_observed != expected:
        raise PayloadStagingError("payload receipt expected/observed hash differs from manifest")
    if observed != expected or observed != receipt_observed:
        raise PayloadStagingError("live server payload read-back hash differs from receipt")
    return PayloadWriteAuthorization(
        case_id=runtime.case_id,
        caldera_server=server,
        required=True,
        verified=True,
        deployment_manifest_sha256=verified.manifest_sha256,
        payload_name=name,
        payload_sha256=expected,
        receipt_sha256=_canonical_json_hash(receipt),
    )


T = TypeVar("T")


def guarded_caldera_write(
    authorization: PayloadWriteAuthorization,
    *,
    case_id: str,
    caldera_server: str,
    writer: Callable[..., T],
    args: Sequence[Any] = (),
    kwargs: Mapping[str, Any] | None = None,
) -> T:
    """Invoke one CALDERA mutation only with a matching verified gate token."""

    if authorization.verified is not True:
        raise PayloadStagingError("CALDERA write authorization is not verified")
    if authorization.case_id != case_id:
        raise PayloadStagingError("CALDERA write case differs from payload gate")
    if authorization.caldera_server != _normalise_server(caldera_server):
        raise PayloadStagingError("CALDERA write server differs from payload gate")
    return writer(*tuple(args), **dict(kwargs or {}))


def _action_fingerprint(action: Mapping[str, Any]) -> str:
    return _canonical_json_hash(action)


def _require_exact_path(path: Any, roots: Sequence[str], run_id: str, label: str) -> str:
    raw = str(path or "").strip().strip('"')
    canonical = _normalise_windows_path(raw)
    if (
        not raw
        or not ntpath.isabs(raw)
        or WILDCARD_RE.search(raw)
        or UNRESOLVED_RE.search(raw)
        or ".." in raw.replace("/", "\\").split("\\")
        or canonical in {"", ".", "\\"}
    ):
        raise CleanupBackendError(f"{label} is not an exact absolute Windows path")
    if not any(_contained_windows_path(canonical, root) for root in roots):
        raise CleanupBackendError(f"{label} is outside every allowed cleanup root")
    if run_id.casefold() not in canonical.casefold():
        raise CleanupBackendError(f"{label} is not bound to run_id {run_id}")
    return canonical


def _normalise_registry_selector(target: Mapping[str, Any]) -> tuple[str, str, str | None]:
    hive = str(target.get("hive") or "").strip().upper()
    key_path = str(target.get("key_path") or "").strip().strip("\\")
    value_name_raw = target.get("value_name")
    value_name = str(value_name_raw).strip() if value_name_raw is not None else None
    if hive not in {"HKCU", "HKLM"}:
        raise CleanupBackendError("registry cleanup hive must be exactly HKCU or HKLM")
    if (
        not key_path
        or key_path in {".", "\\"}
        or WILDCARD_RE.search(key_path)
        or UNRESOLVED_RE.search(key_path)
    ):
        raise CleanupBackendError("registry cleanup key path is not exact")
    if value_name is not None and (
        not value_name or WILDCARD_RE.search(value_name) or UNRESOLVED_RE.search(value_name)
    ):
        raise CleanupBackendError("registry cleanup value name is not exact")
    return hive, key_path, value_name


class PowerShellCleanupBackend:
    """Two-phase backend for the current v4 cleanup-plan action set.

    The constructor statically validates *all* selectors.  ``execute`` remains
    locked until every action has completed at least one read-only inspection.
    ``execute_cleanup`` may then add its own immediate reinspection, providing
    defense in depth against PID reuse and file replacement.
    """

    def __init__(
        self,
        *,
        transport: PowerShellCleanupTransport,
        actions: Sequence[Mapping[str, Any]],
        run_id: str,
        allowed_roots: Sequence[str],
        expected_file_hashes: Mapping[str, str] | None = None,
        registry_expectations: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        if not run_id or any(character in run_id for character in "\\/:*?\"<>|"):
            raise CleanupBackendError("cleanup run_id is empty or path-unsafe")
        roots = tuple(_normalise_windows_path(root) for root in allowed_roots)
        if not roots or any(not root or not ntpath.isabs(root) for root in roots):
            raise CleanupBackendError("cleanup requires exact absolute allowed roots")
        self._transport = transport
        self._run_id = run_id
        self._roots = roots
        self._hashes = {
            _normalise_windows_path(path): str(digest).casefold()
            for path, digest in dict(expected_file_hashes or {}).items()
        }
        if any(not SHA256_RE.fullmatch(digest) for digest in self._hashes.values()):
            raise CleanupBackendError("expected cleanup file SHA-256 is invalid")
        self._registry_expectations = {
            str(key): dict(value)
            for key, value in dict(registry_expectations or {}).items()
        }
        self._actions: dict[str, dict[str, Any]] = {}
        self._fingerprints: dict[str, str] = {}
        self._selectors: dict[str, dict[str, Any]] = {}
        self._inspected: set[str] = set()
        for raw in actions:
            if not isinstance(raw, Mapping):
                raise CleanupBackendError("cleanup backend received a malformed action")
            action = dict(raw)
            action_id = str(action.get("action_id") or "")
            if not action_id or action_id in self._actions:
                raise CleanupBackendError("cleanup action IDs must be non-empty and unique")
            selector = self._validate_static_action(action)
            self._actions[action_id] = action
            self._fingerprints[action_id] = _action_fingerprint(action)
            self._selectors[action_id] = selector
        if not self._actions:
            raise CleanupBackendError("cleanup backend requires at least one action")

    def _validate_static_action(self, action: Mapping[str, Any]) -> dict[str, Any]:
        action_id = str(action.get("action_id") or "")
        tool = str(action.get("tool") or "")
        target = action.get("target") if isinstance(action.get("target"), Mapping) else {}
        expected = (
            action.get("expected") if isinstance(action.get("expected"), Mapping) else {}
        )
        if tool not in {"stop_process", "remove_file", "remove_directory", "remove_registry"}:
            raise CleanupBackendError(f"{action_id} uses an unsupported live cleanup tool")
        if tool == "remove_registry":
            hive, key_path, value_name = _normalise_registry_selector(target)
            identity = " ".join(value for value in (key_path, value_name or "") if value)
            expectation = self._registry_expectations.get(action_id)
            if self._run_id.casefold() not in identity.casefold() and not expectation:
                raise CleanupBackendError(
                    f"{action_id} registry selector is not bound to this run"
                )
            if not isinstance(expectation, Mapping):
                raise CleanupBackendError(
                    f"{action_id} requires a frozen exact registry expectation"
                )
            expected_selector = _normalise_registry_selector(expectation)
            if expected_selector != (hive, key_path, value_name):
                raise CleanupBackendError(f"{action_id} registry expectation selector drifted")
            if value_name is None:
                values = expectation.get("values")
                if not isinstance(values, Mapping) or not values:
                    raise CleanupBackendError(
                        f"{action_id} registry-tree cleanup requires exact frozen values"
                    )
            elif "value_data" not in expectation:
                raise CleanupBackendError(
                    f"{action_id} registry-value cleanup requires exact frozen value_data"
                )
            return {
                "tool": tool,
                "hive": hive,
                "key_path": key_path,
                "value_name": value_name,
                "expectation": dict(expectation),
            }

        canonical = _require_exact_path(
            target.get("path"), self._roots, self._run_id, f"{action_id}.path"
        )
        selector: dict[str, Any] = {"tool": tool, "path": canonical}
        if tool == "stop_process":
            pid = int(expected.get("pid") or 0)
            creation = _normalise_time(expected.get("creation_time_utc"))
            expected_path = _normalise_windows_path(expected.get("canonical_path"))
            if pid <= 0 or not creation or expected_path != canonical:
                raise CleanupBackendError(
                    f"{action_id} process cleanup lacks exact PID/creation/path identity"
                )
            selector.update(pid=pid, creation_time_utc=creation)
            if expected.get("command_line_hosted") is True:
                selector["command_line_hosted"] = True
        expected_hash = str(expected.get("sha256") or "").casefold()
        frozen_hash = self._hashes.get(canonical, "")
        if expected_hash and expected_hash != frozen_hash:
            raise CleanupBackendError(f"{action_id} expected file hash is not frozen")
        if expected_hash:
            selector["sha256"] = expected_hash
        if tool == "stop_process":
            if not frozen_hash:
                raise CleanupBackendError(
                    f"{action_id} process cleanup lacks a frozen image SHA-256"
                )
            selector["sha256"] = frozen_hash
        return selector

    def _known(self, action: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
        action_id = str(action.get("action_id") or "")
        if action_id not in self._actions:
            raise CleanupBackendError("cleanup action was not frozen at backend construction")
        if _action_fingerprint(action) != self._fingerprints[action_id]:
            raise CleanupBackendError(f"cleanup action {action_id} changed after validation")
        return action_id, self._selectors[action_id]

    @staticmethod
    def _present(observed: Mapping[str, Any], label: str) -> bool:
        value = observed.get("present")
        if not isinstance(value, bool):
            raise CleanupBackendError(f"{label} inspection lacks a present boolean")
        return value

    def inspect(self, action: Mapping[str, Any]) -> Mapping[str, Any]:
        action_id, selector = self._known(action)
        tool = selector["tool"]
        if tool == "stop_process":
            observed = dict(self._transport.inspect_process(int(selector["pid"])))
            if self._present(observed, action_id):
                if int(observed.get("pid") or 0) != int(selector["pid"]):
                    raise CleanupBackendError(f"{action_id} PID drifted")
                if selector.get("command_line_hosted") is True:
                    observed_cmd = str(observed.get("command_line") or "")
                    if selector["path"].casefold() not in observed_cmd.casefold():
                        raise CleanupBackendError(
                            f"{action_id} process command line does not contain the payload path"
                        )
                elif _normalise_windows_path(observed.get("path")) != selector["path"]:
                    raise CleanupBackendError(f"{action_id} process path drifted")
                if not _creation_times_match(
                    observed.get("creation_time_utc") or observed.get("creation_time"),
                    selector["creation_time_utc"],
                ):
                    raise CleanupBackendError(f"{action_id} process creation time drifted")
                if selector.get("sha256"):
                    file_row = dict(self._transport.inspect_file(selector["path"]))
                    if self._present(file_row, action_id + ".file") is not True:
                        raise CleanupBackendError(f"{action_id} process image file is absent")
                    if str(file_row.get("sha256") or "").casefold() != selector["sha256"]:
                        raise CleanupBackendError(f"{action_id} process image hash drifted")
                    observed["sha256"] = selector["sha256"]
            observed.setdefault("path", selector["path"])
            observed.setdefault("pid", selector["pid"])
            observed.setdefault("creation_time_utc", selector["creation_time_utc"])
        elif tool == "remove_file":
            observed = dict(self._transport.inspect_file(selector["path"]))
            if self._present(observed, action_id):
                if _normalise_windows_path(observed.get("path")) != selector["path"]:
                    raise CleanupBackendError(f"{action_id} file path drifted")
                if selector.get("sha256") and str(
                    observed.get("sha256") or ""
                ).casefold() != selector["sha256"]:
                    raise CleanupBackendError(f"{action_id} file hash drifted")
            observed.setdefault("path", selector["path"])
        elif tool == "remove_directory":
            observed = dict(self._transport.inspect_directory(selector["path"]))
            if self._present(observed, action_id) and _normalise_windows_path(
                observed.get("path")
            ) != selector["path"]:
                raise CleanupBackendError(f"{action_id} directory path drifted")
            observed.setdefault("path", selector["path"])
        else:
            observed = dict(
                self._transport.inspect_registry(
                    selector["hive"], selector["key_path"], selector["value_name"]
                )
            )
            if self._present(observed, action_id):
                actual_selector = _normalise_registry_selector(observed)
                wanted_selector = (
                    selector["hive"],
                    selector["key_path"],
                    selector["value_name"],
                )
                if actual_selector != wanted_selector:
                    raise CleanupBackendError(f"{action_id} registry selector drifted")
                expectation = selector["expectation"]
                if selector["value_name"] is None:
                    actual_values = observed.get("values")
                    if not isinstance(actual_values, Mapping) or dict(actual_values) != dict(
                        expectation["values"]
                    ):
                        raise CleanupBackendError(f"{action_id} registry tree values drifted")
                elif observed.get("value_data") != expectation.get("value_data"):
                    raise CleanupBackendError(f"{action_id} registry value data drifted")
            observed.setdefault("hive", selector["hive"])
            observed.setdefault("key_path", selector["key_path"])
            if selector["value_name"] is not None:
                observed.setdefault("value_name", selector["value_name"])
        self._inspected.add(action_id)
        return observed

    def execute(self, action: Mapping[str, Any]) -> Mapping[str, Any]:
        action_id, selector = self._known(action)
        if self._inspected != set(self._actions):
            missing = sorted(set(self._actions) - self._inspected)
            raise CleanupBackendError(
                f"all cleanup actions must be inspected before mutation; missing={missing}"
            )
        # Reinspect inside the privileged backend as well.  This protects
        # direct callers and closes the final validation/use window even when
        # an outer transaction layer already performed the same check.
        current = self.inspect(action)
        if current.get("present") is not True:
            raise CleanupBackendError(f"{action_id} target became absent before mutation")
        tool = selector["tool"]
        if tool == "stop_process":
            result = self._transport.stop_process(int(selector["pid"]))
        elif tool == "remove_file":
            result = self._transport.remove_file(selector["path"])
        elif tool == "remove_directory":
            result = self._transport.remove_directory(selector["path"])
        else:
            result = self._transport.remove_registry(
                selector["hive"], selector["key_path"], selector["value_name"]
            )
        if not isinstance(result, Mapping) or result.get("success") is not True:
            raise CleanupBackendError(f"{action_id} mutation did not confirm success")
        return dict(result)


__all__ = [
    "CleanupBackendError",
    "LivePreflightConfig",
    "LivePreflightDependencies",
    "LiveSafetyError",
    "PayloadStagingError",
    "PayloadWriteAuthorization",
    "PowerShellCleanupBackend",
    "PowerShellCleanupTransport",
    "guarded_caldera_write",
    "run_live_preflight",
    "unfinished_operation_risks",
    "validate_payload_staging_receipt",
]
