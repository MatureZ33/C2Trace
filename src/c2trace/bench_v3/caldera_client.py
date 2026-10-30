from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
import ntpath
from pathlib import Path
import re
import time
from typing import Any, Iterable, Mapping, Sequence
import urllib.error
import urllib.parse
import urllib.request
from uuid import NAMESPACE_URL, uuid5


class CalderaBenchError(RuntimeError):
    """Raised when CALDERA state is unsafe or violates the v3 contract."""


_API_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _api_identifier(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text or not _API_IDENTIFIER_RE.fullmatch(text):
        raise CalderaBenchError(
            f"CALDERA {label} must contain only letters, digits, dot, underscore, and hyphen"
        )
    return text


def validate_private_lab_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise CalderaBenchError("CALDERA base URL must be an HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise CalderaBenchError(
            "CALDERA base URL must not contain credentials, a query, or a fragment"
        )
    if parsed.path not in {"", "/"}:
        raise CalderaBenchError("CALDERA base URL must not contain an API path")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise CalderaBenchError(
            "CALDERA base URL must use a literal private or loopback lab IP"
        ) from exc
    if not (_is_rfc1918(address) or address.is_loopback):
        raise CalderaBenchError("CALDERA access is restricted to a private lab IP")
    try:
        port = parsed.port
    except ValueError as exc:
        raise CalderaBenchError("CALDERA base URL contains an invalid port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise CalderaBenchError("CALDERA base URL contains an invalid port")
    return value.rstrip("/")


def _is_rfc1918(address: ipaddress._BaseAddress) -> bool:
    if not isinstance(address, ipaddress.IPv4Address):
        return False
    return any(
        address in network
        for network in (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
    )


def _list_payload(value: Any, label: str) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [dict(item) for item in value if isinstance(item, Mapping)]
    if isinstance(value, Mapping):
        for key in (label, "items", "data"):
            candidate = value.get(key)
            if isinstance(candidate, list):
                return [dict(item) for item in candidate if isinstance(item, Mapping)]
    raise CalderaBenchError(f"CALDERA response did not contain a {label} list")


@dataclass(slots=True)
class OperationResult:
    operation: dict[str, Any]
    links: list[dict[str, Any]]


class CalderaClient:
    def __init__(self, base_url: str, api_key: str, *, timeout: float = 30.0):
        self.base_url = validate_private_lab_url(base_url)
        if not api_key:
            raise CalderaBenchError("CALDERA API key is required")
        self.api_key = api_key
        self.timeout = timeout

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        payload: Mapping[str, Any] | None = None,
    ) -> Any:
        parsed_path = urllib.parse.urlsplit(path)
        decoded_segments = [
            urllib.parse.unquote(segment) for segment in parsed_path.path.split("/")
        ]
        if (
            not parsed_path.path.startswith("/")
            or parsed_path.scheme
            or parsed_path.netloc
            or parsed_path.query
            or parsed_path.fragment
            or "\\" in parsed_path.path
            or any(segment in {".", ".."} for segment in decoded_segments)
            or any("/" in segment or "\\" in segment for segment in decoded_segments)
        ):
            raise CalderaBenchError("CALDERA API path must be absolute and traversal-free")
        body = None
        headers = {"KEY": self.api_key, "Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:1000]
            raise CalderaBenchError(
                f"CALDERA HTTP {exc.code} for {method} {path}: {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            raise CalderaBenchError(
                f"Unable to reach CALDERA for {method} {path}: {exc}"
            ) from exc
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise CalderaBenchError(
                f"CALDERA returned invalid JSON for {method} {path}"
            ) from exc

    def agents(self) -> list[dict[str, Any]]:
        return _list_payload(self.request("/api/v2/agents"), "agents")

    def operations(self) -> list[dict[str, Any]]:
        return _list_payload(self.request("/api/v2/operations"), "operations")

    def operation(self, operation_id: str) -> dict[str, Any]:
        operation_id = _api_identifier(operation_id, "operation ID")
        value = self.request(f"/api/v2/operations/{operation_id}")
        if not isinstance(value, Mapping):
            raise CalderaBenchError("operation response is not an object")
        return dict(value)

    def operation_links(self, operation_id: str) -> list[dict[str, Any]]:
        operation_id = _api_identifier(operation_id, "operation ID")
        return _list_payload(
            self.request(f"/api/v2/operations/{operation_id}/links"), "links"
        )

    def operation_report(self, operation_id: str) -> dict[str, Any]:
        operation_id = _api_identifier(operation_id, "operation ID")
        value = self.request(
            f"/api/v2/operations/{operation_id}/report",
            method="POST",
            payload={"enable_agent_output": True},
        )
        if not isinstance(value, Mapping):
            raise CalderaBenchError("operation report response is not an object")
        return dict(value)

    def operation_event_logs(self, operation_id: str) -> list[dict[str, Any]]:
        operation_id = _api_identifier(operation_id, "operation ID")
        return _list_payload(
            self.request(
                f"/api/v2/operations/{operation_id}/event-logs",
                method="POST",
                payload={"enable_agent_output": True},
            ),
            "event_logs",
        )

    def patch_agent_group(self, paw: str, group: str) -> dict[str, Any]:
        paw = _api_identifier(paw, "agent PAW")
        value = self.request(
            f"/api/v2/agents/{paw}", method="PATCH", payload={"group": group}
        )
        if isinstance(value, list) and len(value) == 1 and isinstance(value[0], Mapping):
            value = value[0]
        if not isinstance(value, Mapping):
            raise CalderaBenchError("agent PATCH response is not an object")
        result = dict(value)
        if str(result.get("group") or "") != group:
            raise CalderaBenchError(f"CALDERA did not set agent {paw} group to {group}")
        return result

    def create_source(
        self,
        *,
        run_id: str,
        http_contact: str,
        tcp_contact: str,
        manx_name: str,
    ) -> dict[str, Any]:
        source_id = deterministic_run_source_id(run_id)
        payload = {
            "id": source_id,
            "name": f"C2Trace Bench v3 runtime facts {run_id}",
            "facts": [
                {"trait": "c2trace.caldera_http", "value": http_contact},
                {"trait": "c2trace.caldera_tcp", "value": tcp_contact},
                {"trait": "c2trace.manx_name", "value": manx_name},
            ],
            "rules": [],
            "adjustments": [],
            "relationships": [],
            "plugin": "",
        }
        existing = [
            item for item in _list_payload(self.request("/api/v2/sources"), "sources")
            if str(item.get("id") or "") == source_id
        ]
        if len(existing) > 1:
            raise CalderaBenchError(f"duplicate CALDERA runtime source {source_id}")
        if existing:
            observed = existing[0]
            wanted_facts = sorted(
                (str(item["trait"]), str(item["value"])) for item in payload["facts"]
            )
            observed_facts = sorted(
                (str(item.get("trait") or ""), str(item.get("value") or ""))
                for item in observed.get("facts", [])
                if isinstance(item, Mapping)
            )
            if wanted_facts != observed_facts:
                raise CalderaBenchError(
                    f"runtime source {source_id} exists with different facts"
                )
            return observed
        value = self.request("/api/v2/sources", method="POST", payload=payload)
        if not isinstance(value, Mapping) or str(value.get("id") or "") != source_id:
            raise CalderaBenchError("CALDERA returned an unexpected runtime source")
        return dict(value)

    def create_operation(
        self,
        *,
        name: str,
        group: str,
        adversary_id: str,
        planner_id: str,
        source_id: str,
    ) -> dict[str, Any]:
        required = {
            "name": name,
            "group": group,
            "adversary_id": adversary_id,
            "planner_id": planner_id,
            "source_id": source_id,
        }
        missing = [key for key, value in required.items() if not str(value or "").strip()]
        if missing:
            raise CalderaBenchError(
                f"operation creation is missing required fields: {', '.join(missing)}"
            )
        payload = {
            "name": name,
            "group": group,
            "adversary": {"adversary_id": adversary_id},
            "planner": {"id": planner_id},
            "source": {"id": source_id},
            "state": "running",
            "autonomous": 1,
            "auto_close": True,
            "obfuscator": "plain-text",
            "use_learning_parsers": False,
            "jitter": "2/8",
        }
        value = self.request("/api/v2/operations", method="POST", payload=payload)
        if not isinstance(value, Mapping):
            raise CalderaBenchError("operation creation response is not an object")
        result = dict(value)
        if not result.get("id"):
            raise CalderaBenchError("CALDERA created an operation without an ID")
        if str(result.get("group") or "") != group:
            raise CalderaBenchError("CALDERA operation group differs from the request")
        observed_adversary = result.get("adversary")
        observed_planner = result.get("planner")
        observed_source = result.get("source")
        if not isinstance(observed_adversary, Mapping) or str(
            observed_adversary.get("adversary_id") or observed_adversary.get("id") or ""
        ) != adversary_id:
            raise CalderaBenchError("CALDERA operation adversary differs from the request")
        if not isinstance(observed_planner, Mapping) or str(
            observed_planner.get("id") or observed_planner.get("planner_id") or ""
        ) != planner_id:
            raise CalderaBenchError("CALDERA operation planner differs from the request")
        if not isinstance(observed_source, Mapping) or str(observed_source.get("id") or "") != source_id:
            raise CalderaBenchError("CALDERA operation source differs from the request")
        return result

    def pause_operation(self, operation_id: str) -> None:
        operation_id = _api_identifier(operation_id, "operation ID")
        value = self.request(
            f"/api/v2/operations/{operation_id}",
            method="PATCH",
            payload={"state": "paused"},
        )
        if not isinstance(value, Mapping):
            raise CalderaBenchError(
                f"operation {operation_id} pause response is not an object"
            )
        state = str(value.get("state") or "").lower()
        if not value.get("finish") and state not in {
            "paused",
            "finished",
            "out_of_time",
        }:
            raise CalderaBenchError(
                f"operation {operation_id} did not enter a safe paused/finished state"
            )

    def wait_operation(
        self,
        operation_id: str,
        *,
        expected_ability_ids: Sequence[str],
        expected_paw: str,
        timeout_seconds: float = 300.0,
        poll_seconds: float = 3.0,
    ) -> OperationResult:
        if timeout_seconds <= 0 or poll_seconds <= 0:
            raise CalderaBenchError("operation wait timeout and poll interval must be positive")
        deadline = time.monotonic() + timeout_seconds
        wanted = [str(item) for item in expected_ability_ids if str(item)]
        if not wanted or len(wanted) != len(set(wanted)):
            raise CalderaBenchError(
                "operation expected ability IDs must be non-empty and unique"
            )
        last_operation: dict[str, Any] = {}
        last_links: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            last_operation = self.operation(operation_id)
            last_links = self.operation_links(operation_id)
            relevant = [link for link in last_links if link_ability_id(link) in wanted]
            failures = [
                link
                for link in relevant
                if _int_or(link.get("status"), -3) in {-5, -4, -2}
                or (
                    bool(link.get("finish"))
                    and _int_or(link.get("status"), -3) != 0
                )
            ]
            if failures:
                detail = ", ".join(
                    f"{link_ability_id(link)} status={link.get('status')}" for link in failures
                )
                raise CalderaBenchError(f"operation {operation_id} failed: {detail}")
            finished = bool(last_operation.get("finish")) or str(
                last_operation.get("state") or ""
            ).lower() in {"finished", "out_of_time"}
            if finished:
                validate_operation_links(relevant, wanted, expected_paw)
                return OperationResult(last_operation, last_links)
            time.sleep(poll_seconds)
        try:
            self.pause_operation(operation_id)
        except CalderaBenchError:
            pass
        raise CalderaBenchError(
            f"operation {operation_id} timed out; it was paused when possible"
        )

    def wait_for_new_manx(
        self,
        *,
        baseline_paws: set[str],
        control_agent: Mapping[str, Any],
        expected_path: str,
        created_after: datetime,
        timeout_seconds: float = 120.0,
        poll_seconds: float = 3.0,
    ) -> dict[str, Any]:
        if timeout_seconds <= 0 or poll_seconds <= 0:
            raise CalderaBenchError("Manx wait timeout and poll interval must be positive")
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            candidates = select_new_manx_agents(
                self.agents(),
                baseline_paws=baseline_paws,
                control_agent=control_agent,
                expected_path=expected_path,
                created_after=created_after,
            )
            if len(candidates) > 1:
                raise CalderaBenchError(
                    "more than one new Manx matched the current run identity"
                )
            if candidates:
                return candidates[0]
            time.sleep(poll_seconds)
        raise CalderaBenchError("no uniquely identifiable new Manx registered in time")


def agent_paw(agent: Mapping[str, Any]) -> str:
    return str(agent.get("paw") or agent.get("id") or "")


def agent_pid(agent: Mapping[str, Any]) -> int:
    return _int_or(agent.get("pid"), 0)


def agent_executors(agent: Mapping[str, Any]) -> list[str]:
    raw = agent.get("executors")
    if isinstance(raw, str):
        values = raw.split(",")
    elif isinstance(raw, (list, tuple)):
        values = [str(item) for item in raw]
    else:
        values = []
    return [item.strip().lower() for item in values if item.strip()]


def agent_is_recent(agent: Mapping[str, Any], *, now: datetime | None = None) -> bool:
    if agent.get("trusted") is False:
        return False
    status = str(agent.get("status") or "").strip().lower()
    if status and status != "alive":
        return False
    timestamp = _parse_datetime(agent.get("last_seen") or agent.get("last_trusted_seen"))
    if timestamp is None:
        return False
    reference = now or datetime.now(timezone.utc)
    return 0 <= (reference - timestamp).total_seconds() <= 180


def find_control_agent(agents: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    candidates = [
        dict(agent)
        for agent in agents
        if str(agent.get("group") or "") == "c2t-control"
        and str(agent.get("platform") or "").lower() == "windows"
        and agent_is_recent(agent)
    ]
    if len(candidates) != 1:
        raise CalderaBenchError(
            f"expected exactly one live Windows c2t-control agent; found {len(candidates)}"
        )
    if not agent_paw(candidates[0]) or not agent_pid(candidates[0]):
        raise CalderaBenchError("control Sandcat lacks PAW or PID")
    return candidates[0]


def unsafe_unfinished_red_operations(
    operations: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return [
        dict(operation)
        for operation in operations
        if operation.get("finish") in {None, ""}
        and str(operation.get("group") or "").strip().lower() in {"", "red"}
    ]


def select_new_manx_agents(
    agents: Iterable[Mapping[str, Any]],
    *,
    baseline_paws: set[str],
    control_agent: Mapping[str, Any],
    expected_path: str,
    created_after: datetime,
) -> list[dict[str, Any]]:
    expected = _normalise_windows_path(expected_path)
    control_pid = agent_pid(control_agent)
    control_host = str(control_agent.get("host") or "").lower()
    result: list[dict[str, Any]] = []
    for raw in agents:
        paw = agent_paw(raw)
        if not paw or paw in baseline_paws:
            continue
        contact = str(raw.get("contact") or "").lower()
        if contact != "tcp":
            continue
        executors = agent_executors(raw)
        if not executors or executors[0] != "cmd" or "psh" not in executors:
            continue
        if control_host and str(raw.get("host") or "").lower() != control_host:
            continue
        location = _normalise_windows_path(
            str(raw.get("location") or raw.get("exe_name") or "")
        )
        if location != expected:
            continue
        pid = agent_pid(raw)
        if not pid or pid == control_pid:
            continue
        if str(raw.get("group") or "").strip().lower() not in {"", "red"}:
            continue
        created = _parse_datetime(raw.get("created") or raw.get("created_at"))
        if created is None or created < created_after:
            continue
        if not agent_is_recent(raw):
            continue
        result.append(dict(raw))
    return result


def link_ability_id(link: Mapping[str, Any]) -> str:
    ability = link.get("ability")
    if isinstance(ability, Mapping):
        return str(ability.get("ability_id") or ability.get("id") or "")
    return str(link.get("ability_id") or ability or "")


def validate_operation_links(
    links: Sequence[Mapping[str, Any]],
    expected_ability_ids: Sequence[str],
    expected_paw: str,
) -> None:
    for ability_id in expected_ability_ids:
        matches = [link for link in links if link_ability_id(link) == ability_id]
        if len(matches) != 1:
            raise CalderaBenchError(
                f"expected one link for ability {ability_id}; found {len(matches)}"
            )
        link = matches[0]
        if str(link.get("paw") or "") != expected_paw:
            raise CalderaBenchError(f"ability {ability_id} ran on the wrong PAW")
        if _int_or(link.get("status"), -3) != 0:
            raise CalderaBenchError(
                f"ability {ability_id} did not finish successfully: {link.get('status')}"
            )


def validate_operation_report(
    report: Mapping[str, Any],
    expected_ability_ids: Sequence[str],
    *,
    expected_paw: str = "",
) -> None:
    """Reject skipped abilities for the agent whose links were validated.

    CALDERA reports skipped abilities for every historical agent in an
    Operation's group, including dead or untrusted agents which never received
    the current links.  Callers which already validated the links against one
    exact PAW must scope this report-level consistency check to that PAW.
    Omitting ``expected_paw`` preserves the legacy all-agent validation used by
    older callers.
    """

    wanted = {str(item) for item in expected_ability_ids}
    skipped_ids: set[str] = set()
    raw_skipped = report.get("skipped_abilities")
    if isinstance(raw_skipped, list):
        for agent_row in raw_skipped:
            if not isinstance(agent_row, Mapping):
                continue
            for paw, rows in agent_row.items():
                if expected_paw and str(paw) != expected_paw:
                    continue
                if not isinstance(rows, list):
                    continue
                for row in rows:
                    if isinstance(row, Mapping):
                        ability_id = str(row.get("ability_id") or "")
                        if ability_id:
                            skipped_ids.add(ability_id)
    if skipped_ids:
        overlap = sorted(wanted & skipped_ids)
        raise CalderaBenchError(
            "operation report contains skipped abilities "
            f"(paw={expected_paw or 'all'}, mandatory={overlap}, "
            f"all={sorted(skipped_ids)})"
        )


def deterministic_run_source_id(run_id: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"c2trace-bench-v3-source:{run_id}"))


def parse_caldera_datetime(value: Any) -> datetime | None:
    """Parse a CALDERA timestamp into UTC for cross-API identity checks."""

    return _parse_datetime(value)


def load_yaml_documents(path: Path) -> list[Any]:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - environment preflight path
        raise CalderaBenchError("PyYAML is required to install CALDERA assets") from exc
    try:
        return list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise CalderaBenchError(f"cannot parse CALDERA YAML {path}: {exc}") from exc


def load_ability_payload(path: Path, *, case_id: str) -> dict[str, Any]:
    documents = load_yaml_documents(path)
    rows: list[Any] = []
    for document in documents:
        if isinstance(document, list):
            rows.extend(document)
        elif isinstance(document, Mapping):
            rows.append(document)
    if len(rows) != 1 or not isinstance(rows[0], Mapping):
        raise CalderaBenchError(f"ability file must contain exactly one ability: {path}")
    ability = rows[0]
    executors: list[dict[str, Any]] = []
    platforms = ability.get("platforms") if isinstance(ability.get("platforms"), Mapping) else {}
    for platform, raw_executors in platforms.items():
        if not isinstance(raw_executors, Mapping):
            continue
        for name, raw in raw_executors.items():
            raw = raw if isinstance(raw, Mapping) else {}
            command = str(raw.get("command") or "").replace("\r\n", "\n").strip()
            executors.append(
                {
                    "name": str(name),
                    "platform": str(platform),
                    "command": command,
                    "payloads": list(raw.get("payloads") or []),
                    "uploads": list(raw.get("uploads") or []),
                    "parsers": list(raw.get("parsers") or []),
                    "cleanup": list(raw.get("cleanup") or []),
                    "timeout": int(raw.get("timeout") or 60),
                }
            )
    technique = ability.get("technique") if isinstance(ability.get("technique"), Mapping) else {}
    result = {
        "ability_id": str(ability.get("id") or ability.get("ability_id") or ""),
        "name": str(ability.get("name") or ""),
        "description": str(ability.get("description") or ""),
        "tactic": str(ability.get("tactic") or ""),
        "technique_name": str(technique.get("name") or ""),
        "technique_id": str(technique.get("attack_id") or ""),
        "executors": executors,
        "requirements": [],
        "privilege": "",
        "repeatable": bool(ability.get("repeatable", False)),
        "buckets": [str(ability.get("tactic") or "")],
        "additional_info": {"c2trace_case_id": case_id},
        "access": {},
        "singleton": False,
        "plugin": "",
        "delete_payload": False,
    }
    if not result["ability_id"] or not result["executors"]:
        raise CalderaBenchError(f"ability requires an ID and at least one executor: {path}")
    if any(
        not str(executor.get(field) or "").strip()
        for executor in result["executors"]
        for field in ("name", "platform", "command")
    ):
        raise CalderaBenchError(f"ability contains an incomplete executor: {path}")
    return result


def load_adversary_payload(path: Path, *, case_id: str) -> dict[str, Any]:
    rows = [item for item in load_yaml_documents(path) if isinstance(item, Mapping)]
    if len(rows) != 1:
        raise CalderaBenchError(f"adversary file must contain one object: {path}")
    row = rows[0]
    raw_ordering = row.get("atomic_ordering")
    if not isinstance(raw_ordering, list):
        raise CalderaBenchError(f"adversary atomic_ordering must be a list: {path}")
    result = {
        "adversary_id": str(row.get("id") or row.get("adversary_id") or ""),
        "name": str(row.get("name") or ""),
        "description": str(row.get("description") or ""),
        "atomic_ordering": [str(item) for item in raw_ordering],
        "tags": [case_id],
        "plugin": "",
    }
    if not result["adversary_id"] or not result["atomic_ordering"]:
        raise CalderaBenchError(f"adversary requires an ID and atomic_ordering: {path}")
    if len(result["atomic_ordering"]) != len(set(result["atomic_ordering"])):
        raise CalderaBenchError(f"adversary atomic_ordering contains duplicate IDs: {path}")
    return result


def install_bundle(
    client: CalderaClient,
    bundle_root: Path,
    *,
    case_id: str,
) -> dict[str, Any]:
    ability_payloads = [
        load_ability_payload(path, case_id=case_id)
        for path in sorted((bundle_root / "abilities").glob("*.yml"))
    ]
    adversary_payloads = [
        load_adversary_payload(path, case_id=case_id)
        for path in sorted((bundle_root / "adversaries").glob("*.yml"))
    ]
    ability_ids = [str(item["ability_id"]) for item in ability_payloads]
    adversary_ids = [str(item["adversary_id"]) for item in adversary_payloads]
    if len(ability_ids) != len(set(ability_ids)):
        raise CalderaBenchError("CALDERA bundle contains duplicate local ability IDs")
    if len(adversary_ids) != len(set(adversary_ids)):
        raise CalderaBenchError("CALDERA bundle contains duplicate local adversary IDs")
    if not ability_payloads or not adversary_payloads:
        raise CalderaBenchError("CALDERA bundle requires abilities and adversaries")

    abilities = _list_payload(client.request("/api/v2/abilities"), "abilities")
    adversaries = _list_payload(client.request("/api/v2/adversaries"), "adversaries")
    ability_matches: dict[str, list[dict[str, Any]]] = {
        ability_id: [
            item
            for item in abilities
            if str(item.get("ability_id") or item.get("id") or "") == ability_id
        ]
        for ability_id in ability_ids
    }
    adversary_matches: dict[str, list[dict[str, Any]]] = {
        adversary_id: [
            item
            for item in adversaries
            if str(item.get("adversary_id") or item.get("id") or "")
            == adversary_id
        ]
        for adversary_id in adversary_ids
    }
    for payload in ability_payloads:
        ability_id = str(payload["ability_id"])
        matches = ability_matches[ability_id]
        if len(matches) > 1:
            raise CalderaBenchError(f"duplicate remote ability {ability_id}")
        if matches and not _ability_equivalent(matches[0], payload):
            raise CalderaBenchError(
                f"remote ability {ability_id} differs; refusing to overwrite"
            )
    for payload in adversary_payloads:
        adversary_id = str(payload["adversary_id"])
        matches = adversary_matches[adversary_id]
        if len(matches) > 1:
            raise CalderaBenchError(f"duplicate remote adversary {adversary_id}")
        if matches and not _adversary_equivalent(matches[0], payload):
            raise CalderaBenchError(
                f"remote adversary {adversary_id} differs; refusing to overwrite"
            )
    available_ability_ids = {
        str(item.get("ability_id") or item.get("id") or "") for item in abilities
    } | set(ability_ids)
    for payload in adversary_payloads:
        missing = sorted(set(payload["atomic_ordering"]) - available_ability_ids)
        if missing:
            raise CalderaBenchError(
                f"adversary {payload['adversary_id']} references missing abilities: {missing}"
            )

    receipt: dict[str, Any] = {
        "created_abilities": [],
        "existing_abilities": [],
        "created_adversaries": [],
        "existing_adversaries": [],
    }
    for payload in ability_payloads:
        ability_id = payload["ability_id"]
        matches = ability_matches[str(ability_id)]
        if matches:
            receipt["existing_abilities"].append(ability_id)
        else:
            created = client.request("/api/v2/abilities", method="POST", payload=payload)
            if not isinstance(created, Mapping) or str(
                created.get("ability_id") or created.get("id") or ""
            ) != ability_id:
                raise CalderaBenchError(f"invalid create response for ability {ability_id}")
            receipt["created_abilities"].append(ability_id)
    for payload in adversary_payloads:
        adversary_id = payload["adversary_id"]
        matches = adversary_matches[str(adversary_id)]
        if matches:
            receipt["existing_adversaries"].append(adversary_id)
        else:
            created = client.request("/api/v2/adversaries", method="POST", payload=payload)
            if not isinstance(created, Mapping) or str(
                created.get("adversary_id") or created.get("id") or ""
            ) != adversary_id:
                raise CalderaBenchError(f"invalid create response for adversary {adversary_id}")
            receipt["created_adversaries"].append(adversary_id)
    return receipt


def _adversary_equivalent(
    observed: Mapping[str, Any], wanted: Mapping[str, Any]
) -> bool:
    observed_order = list(
        observed.get("atomic_ordering") or observed.get("atomic_order") or []
    )
    return (
        str(observed.get("name") or "") == str(wanted.get("name") or "")
        and str(observed.get("description") or "")
        == str(wanted.get("description") or "")
        and observed_order == list(wanted.get("atomic_ordering") or [])
    )


def _ability_equivalent(observed: Mapping[str, Any], wanted: Mapping[str, Any]) -> bool:
    # CALDERA's Ability.store() appends exactly " (2)" to an in-memory
    # display name when a different ability already has the requested name.
    # The command and all other execution fields remain unchanged, and the
    # on-disk definition retains the requested name. Treat only that precise,
    # CALDERA-generated display normalization as equivalent.
    observed_name = str(observed.get("name") or "")
    wanted_name = str(wanted.get("name") or "")
    if observed_name not in {wanted_name, f"{wanted_name} (2)"}:
        return False
    for field in (
        "ability_id",
        "description",
        "tactic",
        "technique_name",
        "technique_id",
    ):
        if str(observed.get(field) or "") != str(wanted.get(field) or ""):
            return False
    if bool(observed.get("repeatable", False)) != bool(wanted.get("repeatable", False)):
        return False
    if list(observed.get("requirements") or []) != list(wanted.get("requirements") or []):
        return False
    if str(observed.get("privilege") or "") != str(wanted.get("privilege") or ""):
        return False
    observed_executors = [
        item for item in observed.get("executors", []) if isinstance(item, Mapping)
    ]
    wanted_executors = wanted.get("executors", [])
    if len(observed_executors) != len(wanted_executors):
        return False
    observed_keys = sorted(
        (
            str(item.get("platform") or "").lower(),
            str(item.get("name") or "").lower(),
            str(item.get("command") or "").replace("\r\n", "\n").strip(),
            tuple(item.get("payloads") or []),
            tuple(item.get("uploads") or []),
            json.dumps(item.get("parsers") or [], sort_keys=True, default=str),
            tuple(item.get("cleanup") or []),
            _int_or(item.get("timeout"), 60),
        )
        for item in observed_executors
    )
    wanted_keys = sorted(
        (
            str(item.get("platform") or "").lower(),
            str(item.get("name") or "").lower(),
            str(item.get("command") or "").replace("\r\n", "\n").strip(),
            tuple(item.get("payloads") or []),
            tuple(item.get("uploads") or []),
            json.dumps(item.get("parsers") or [], sort_keys=True, default=str),
            tuple(item.get("cleanup") or []),
            _int_or(item.get("timeout"), 60),
        )
        for item in wanted_executors
    )
    return observed_keys == wanted_keys


def _normalise_windows_path(value: str) -> str:
    if not value:
        return ""
    return ntpath.normcase(ntpath.normpath(value.strip().strip('"')))


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        result = value
    else:
        text = str(value or "").strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            result = datetime.fromisoformat(text)
        except ValueError:
            return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def _int_or(value: Any, default: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
