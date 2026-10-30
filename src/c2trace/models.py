from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import os
import re
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ValidationError(ValueError):
    pass


SAFE_CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

INTERPRETER_HOSTS = frozenset({
    "rundll32.exe",
    "cscript.exe",
    "wscript.exe",
    "python.exe",
    "pythonw.exe",
    "powershell.exe",
    "mshta.exe",
    "regsvr32.exe",
    "msiexec.exe",
})

PAYLOAD_EXTENSIONS = frozenset({
    ".dll", ".py", ".pyw", ".js", ".jse", ".vbs", ".vbe",
    ".ps1", ".bat", ".cmd", ".hta", ".ocx", ".exe",
})

_EXCLUDED_PATH_PREFIXES = (
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\programdata\\",
)


def extract_payload_from_command_line(command_line: str, process_name: str) -> str:
    """Extract a payload file path from an interpreter host's command line.

    Uses the MITRE ATT&CK LOLBins list to identify interpreter-hosted processes,
    then extracts the first user-writable file path with a known payload extension.
    Does not depend on any case-specific information.
    """
    if not command_line:
        return ""
    tokens = re.findall(r'[A-Za-z]:\\[^\s"<>|*?,]+', command_line)
    for token in tokens:
        token_lower = token.lower()
        if any(token_lower.startswith(prefix) for prefix in _EXCLUDED_PATH_PREFIXES):
            continue
        token_basename = os.path.basename(token_lower)
        if process_name and (token_lower == process_name.lower() or token_basename == process_name.lower()):
            continue
        ext = os.path.splitext(token_lower)[1]
        if ext in PAYLOAD_EXTENSIONS:
            return token
    return ""



def validate_case_id(value: Any) -> str:
    case_id = str(value or "").strip()
    if not case_id or not SAFE_CASE_ID_RE.fullmatch(case_id) or case_id in {".", ".."}:
        raise ValidationError(
            "case_id must be 1-128 path-safe characters: letters, digits, dot, underscore, or hyphen"
        )
    return case_id


class NodeType(str, Enum):
    INVESTIGATE = "investigate"
    DECISION = "decision"
    RESPONSE = "response"
    VERIFY = "verify"


class NodeStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    NEED_MORE_EVIDENCE = "need_more_evidence"
    REJECTED = "rejected"
    SKIPPED = "skipped"
    CLOSED = "closed"


class AuditVerdict(str, Enum):
    APPROVED = "approved"
    NEED_MORE_EVIDENCE = "need_more_evidence"
    REJECTED = "rejected"


# Strategy validation lives in the model layer so an LLM-produced plan cannot
# weaken the execution boundary by assigning a destructive tool to a node that
# the orchestrator would otherwise treat as read-only.
STRATEGY_READ_ONLY_TOOLS = frozenset({
    "check_network",
    "check_process",
    "check_process_tree",
    "check_file_metadata",
    "check_recent_files",
    "check_persistence_all",
    "check_powershell_history",
    "check_dns_cache",
    "verify_cleanup",
})

STRATEGY_RESPONSE_TOOLS = frozenset({
    "kill_process",
    "remove_file",
    "remove_registry",
    "remove_scheduled_task",
    "remove_service",
})


ALLOWED_ALERT_FIELDS = {
    "schema_version",
    "alert_id",
    "case_id",
    "source",
    "alert_type",
    "victim_host",
    "victim_ip",
    "remote_ip",
    "remote_domain",
    "remote_url",
    "remote_port",
    "protocol",
    "time_window",
    "confidence",
    "description",
}

FORBIDDEN_ALERT_FIELDS = {
    "pid",
    "process_id",
    "process_name",
    "process_path",
    "payload_path",
    "payload_hash",
    "run_key",
    "persistence_name",
    "powershell_command",
    "caldera_result",
    "ability_result",
    "parent_process",
    "service_name",
    "task_name",
}


@dataclass(slots=True)
class MinimalAlert:
    payload: dict[str, Any]

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "MinimalAlert":
        if not isinstance(payload, dict):
            raise ValidationError("alert must be a JSON object")
        keys = set(payload)
        forbidden = keys & FORBIDDEN_ALERT_FIELDS
        if forbidden:
            raise ValidationError(f"alert contains forbidden ground-truth field(s): {sorted(forbidden)}")
        unknown = keys - ALLOWED_ALERT_FIELDS
        if unknown:
            raise ValidationError(f"alert contains unsupported field(s): {sorted(unknown)}")
        if not (payload.get("remote_ip") or payload.get("remote_domain") or payload.get("remote_url")):
            raise ValidationError("alert requires remote_ip, remote_domain, or remote_url")
        if not payload.get("protocol"):
            raise ValidationError("alert requires protocol")
        if not payload.get("case_id"):
            payload = {**payload, "case_id": f"case-{uuid4()}"}
        else:
            payload = {**payload, "case_id": validate_case_id(payload.get("case_id"))}
        if not payload.get("alert_id"):
            payload = {**payload, "alert_id": f"alert-{uuid4()}"}
        return cls(payload=dict(payload))

    @property
    def case_id(self) -> str:
        return str(self.payload.get("case_id") or "")

    @property
    def alert_id(self) -> str:
        return str(self.payload.get("alert_id") or "")

    @property
    def seed_value(self) -> str:
        remote = str(
            self.payload.get("remote_url")
            or self.payload.get("remote_domain")
            or self.payload.get("remote_ip")
            or ""
        )
        port = str(self.payload.get("remote_port") or "")
        if port and self.payload.get("remote_ip"):
            return f"{remote}:{port}"
        return remote

    def to_dict(self) -> dict[str, Any]:
        return dict(self.payload)


@dataclass(slots=True)
class StrategyNode:
    node_id: str
    type: NodeType
    goal: str
    tool: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    condition: str = ""
    requires: list[str] = field(default_factory=list)
    status: NodeStatus = NodeStatus.PENDING
    assigned_to: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    on_success: list[str] = field(default_factory=list)
    on_failure: list[str] = field(default_factory=list)
    audit_decision_id: str | None = None
    result_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        try:
            if not isinstance(self.type, NodeType):
                self.type = NodeType(str(self.type))
            if not isinstance(self.status, NodeStatus):
                self.status = NodeStatus(str(self.status))
        except ValueError as exc:
            raise ValidationError(f"invalid strategy node enum value for {self.node_id}") from exc
        self.validate_tool_policy()

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "StrategyNode":
        try:
            node_type = NodeType(str(payload["type"]))
        except (KeyError, ValueError) as exc:
            raise ValidationError(f"invalid node type in {payload}") from exc
        node_id = str(payload.get("node_id") or payload.get("id") or "").strip()
        if not node_id:
            raise ValidationError("strategy node requires node_id")
        return cls(
            node_id=node_id,
            type=node_type,
            goal=str(payload.get("goal") or payload.get("purpose") or ""),
            tool=str(payload.get("tool") or ""),
            arguments=payload.get("arguments", {}) if isinstance(payload.get("arguments", {}), dict) else {},
            condition=str(payload.get("condition") or ""),
            requires=[str(x) for x in payload.get("requires", []) if x],
            status=NodeStatus(str(payload.get("status") or NodeStatus.PENDING.value)),
            assigned_to=payload.get("assigned_to"),
            evidence_refs=[str(x) for x in payload.get("evidence_refs", []) if x],
            on_success=[str(x) for x in payload.get("on_success", []) if x],
            on_failure=[str(x) for x in payload.get("on_failure", []) if x],
            metadata=payload.get("metadata", {}) if isinstance(payload.get("metadata", {}), dict) else {},
        )

    def validate_tool_policy(self) -> None:
        if self.type in {NodeType.INVESTIGATE, NodeType.VERIFY}:
            if self.tool not in STRATEGY_READ_ONLY_TOOLS:
                raise ValidationError(
                    f"{self.type.value} node {self.node_id} requires a read-only tool; got {self.tool or '<empty>'}"
                )
            return
        if self.type == NodeType.RESPONSE:
            if self.tool not in STRATEGY_RESPONSE_TOOLS:
                raise ValidationError(
                    f"response node {self.node_id} requires a response tool; got {self.tool or '<empty>'}"
                )
            return
        if self.type == NodeType.DECISION and self.tool:
            raise ValidationError(f"decision node {self.node_id} must not execute tool {self.tool}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "type": self.type.value,
            "goal": self.goal,
            "tool": self.tool,
            "arguments": self.arguments,
            "condition": self.condition,
            "requires": self.requires,
            "status": self.status.value,
            "assigned_to": self.assigned_to,
            "evidence_refs": self.evidence_refs,
            "on_success": self.on_success,
            "on_failure": self.on_failure,
            "audit_decision_id": self.audit_decision_id,
            "result_id": self.result_id,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class StrategyTree:
    tree_id: str
    root_objective: str
    nodes: list[StrategyNode]
    created_by: str = "planner_llm"
    provenance: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        self.validate()

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "StrategyTree":
        nodes_raw = payload.get("nodes")
        if not isinstance(nodes_raw, list) or not nodes_raw:
            raise ValidationError("StrategyTree requires non-empty nodes list")
        nodes = [StrategyNode.from_dict(item) for item in nodes_raw if isinstance(item, dict)]
        return cls(
            tree_id=str(payload.get("tree_id") or f"tree-{uuid4()}"),
            root_objective=str(payload.get("root_objective") or payload.get("objective") or "C2 traceback response"),
            nodes=nodes,
            created_by=str(payload.get("created_by") or "planner_llm"),
            provenance=dict(payload.get("provenance") or {}),
        )

    def node_map(self) -> dict[str, StrategyNode]:
        return {node.node_id: node for node in self.nodes}

    def add_nodes(self, nodes: list[StrategyNode]) -> None:
        original_length = len(self.nodes)
        existing = self.node_map()
        try:
            for node in nodes:
                node.validate_tool_policy()
                if node.node_id in existing:
                    node.node_id = f"{node.node_id}-{uuid4().hex[:6]}"
                self.nodes.append(node)
                existing[node.node_id] = node
            self.validate()
        except Exception:
            del self.nodes[original_length:]
            raise

    def validate(self) -> None:
        if not self.nodes or not all(isinstance(node, StrategyNode) for node in self.nodes):
            raise ValidationError("StrategyTree requires a non-empty StrategyNode list")
        node_map = self.node_map()
        if len(node_map) != len(self.nodes):
            raise ValidationError("StrategyTree node_id values must be unique")
        types = {node.type for node in self.nodes}
        required = {NodeType.INVESTIGATE, NodeType.DECISION, NodeType.RESPONSE, NodeType.VERIFY}
        missing = required - types
        if missing:
            raise ValidationError(
                f"StrategyTree missing node type(s): {[item.value for item in sorted(missing, key=str)]}"
            )
        for node in self.nodes:
            node.validate_tool_policy()
            unknown_requirements = [requirement for requirement in node.requires if requirement not in node_map]
            if unknown_requirements:
                raise ValidationError(
                    f"strategy node {node.node_id} has unknown requirement(s): {unknown_requirements}"
                )
            if node.type != NodeType.RESPONSE:
                continue
            evidence_gates = [
                node_map[requirement]
                for requirement in node.requires
                if self._is_evidence_sufficient_decision(node_map[requirement])
            ]
            if not evidence_gates:
                raise ValidationError(
                    f"response node {node.node_id} must directly depend on an evidence_sufficient_for_response decision"
                )

    def response_has_evidence_gate(self, node: StrategyNode) -> bool:
        node_map = self.node_map()
        return node.type == NodeType.RESPONSE and any(
            requirement in node_map and self._is_evidence_sufficient_decision(node_map[requirement])
            for requirement in node.requires
        )

    @staticmethod
    def _is_evidence_sufficient_decision(node: StrategyNode) -> bool:
        condition = f"{node.condition} {node.goal}".lower()
        return node.type == NodeType.DECISION and "evidence_sufficient" in condition

    def to_dict(self) -> dict[str, Any]:
        return {
            "tree_id": self.tree_id,
            "root_objective": self.root_objective,
            "created_by": self.created_by,
            "provenance": self.provenance,
            "created_at": self.created_at,
            "nodes": [node.to_dict() for node in self.nodes],
        }


@dataclass(slots=True)
class Finding:
    finding_type: str
    value: str
    evidence: str
    source: str
    confidence: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type,
            "value": self.value,
            "evidence": self.evidence,
            "source": self.source,
            "confidence": self.confidence,
            "details": self.details,
            "created_at": self.created_at,
        }


@dataclass(slots=True)
class ActionResult:
    node_id: str
    tool: str
    success: bool
    data: Any = None
    error: str | None = None
    elapsed_ms: float = 0.0
    arguments: dict[str, Any] = field(default_factory=dict)
    audit_decision_id: str | None = None
    transport_receipt: dict[str, Any] = field(default_factory=dict)
    result_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "result_id": self.result_id,
            "node_id": self.node_id,
            "tool": self.tool,
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "elapsed_ms": self.elapsed_ms,
            "arguments": self.arguments,
            "audit_decision_id": self.audit_decision_id,
            "transport_receipt": self.transport_receipt,
            "created_at": self.created_at,
        }


@dataclass(slots=True)
class AuditDecision:
    node_id: str
    verdict: AuditVerdict
    reason: str
    missing_evidence: list[str] = field(default_factory=list)
    supporting_evidence: list[str] = field(default_factory=list)
    authorization_receipt: dict[str, Any] = field(default_factory=dict)
    decision_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "node_id": self.node_id,
            "verdict": self.verdict.value,
            "reason": self.reason,
            "missing_evidence": self.missing_evidence,
            "supporting_evidence": self.supporting_evidence,
            "authorization_receipt": self.authorization_receipt,
            "created_at": self.created_at,
        }


@dataclass(slots=True)
class EvidenceLink:
    source_id: str
    target_id: str
    relation: str
    confidence: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)
    link_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "link_id": self.link_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation": self.relation,
            "confidence": self.confidence,
            "details": self.details,
            "created_at": self.created_at,
        }


@dataclass(slots=True)
class TimelineEvent:
    event_type: str
    summary: str
    source: str
    refs: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "summary": self.summary,
            "source": self.source,
            "refs": self.refs,
            "details": self.details,
            "created_at": self.created_at,
        }


@dataclass(slots=True)
class FinalReport:
    title: str
    executive_summary: str
    findings: list[str]
    actions: list[str]
    audit_summary: list[str]
    verification: list[str]
    evidence_chain: list[str] = field(default_factory=list)
    report_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "title": self.title,
            "executive_summary": self.executive_summary,
            "findings": self.findings,
            "actions": self.actions,
            "audit_summary": self.audit_summary,
            "verification": self.verification,
            "evidence_chain": self.evidence_chain,
            "created_at": self.created_at,
        }


@dataclass(slots=True)
class CaseFile:
    case_id: str
    case_name: str
    source_alert: dict[str, Any]
    source_events: list[dict[str, Any]] = field(default_factory=list)
    source_artifacts: list[dict[str, Any]] = field(default_factory=list)
    # Acquired by the safety layer immediately before response execution.
    # This field is intentionally omitted from compact_summary(), which is the
    # only CaseFile projection sent to Planner/Auditor.
    response_target_lock: dict[str, Any] | None = None
    target_observations: list[dict[str, Any]] = field(default_factory=list)
    strategy_tree: StrategyTree | None = None
    findings: list[Finding] = field(default_factory=list)
    action_results: list[ActionResult] = field(default_factory=list)
    audit_decisions: list[AuditDecision] = field(default_factory=list)
    evidence_links: list[EvidenceLink] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    final_report: FinalReport | None = None
    final_status: str = "initialized"
    errors: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    @classmethod
    def from_alert(
        cls,
        alert: MinimalAlert,
        source_events: list[dict[str, Any]] | None = None,
        source_artifacts: list[dict[str, Any]] | None = None,
    ) -> "CaseFile":
        case = cls(
            case_id=alert.case_id,
            case_name=f"C2Trace case {alert.case_id}",
            source_alert=alert.to_dict(),
            source_events=list(source_events or []),
            source_artifacts=list(source_artifacts or []),
        )
        case.add_timeline("case_initialized", f"Case initialized from alert {alert.alert_id}", "system")
        for event in case.source_events:
            case.add_timeline("source_event_recorded", "Sanitized source event recorded", str(event.get("event_type") or "source_event"), details=event)
        for artifact in case.source_artifacts:
            case.add_timeline("source_artifact_recorded", "Source artifact reference recorded", str(artifact.get("artifact_type") or "source_artifact"), details=artifact)
        case.add_finding(Finding(
            finding_type="minimal_c2_seed_alert",
            value=alert.seed_value,
            evidence="Minimal C2 Seed Alert accepted as investigation entrypoint",
            source=str(alert.payload.get("source") or "alert"),
            confidence=float(alert.payload.get("confidence") or 0.5),
            details=alert.to_dict(),
        ))
        return case

    def touch(self) -> None:
        self.updated_at = utc_now()

    def add_timeline(self, event_type: str, summary: str, source: str, refs: list[str] | None = None, details: dict[str, Any] | None = None) -> TimelineEvent:
        event = TimelineEvent(event_type=event_type, summary=summary, source=source, refs=refs or [], details=details or {})
        self.timeline.append(event)
        self.touch()
        return event

    def add_finding(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        self.add_timeline("finding_added", f"{finding.finding_type}: {finding.value}", finding.source, [finding.finding_id])
        return finding

    def add_result(self, result: ActionResult) -> ActionResult:
        self.action_results.append(result)
        self.add_timeline("action_result", f"{result.tool} success={result.success}", "executor", [result.result_id, result.node_id])
        return result

    def add_target_observation(self, observation: dict[str, Any]) -> dict[str, Any]:
        frozen = dict(observation)
        self.target_observations.append(frozen)
        self.add_timeline(
            "target_observation_recorded",
            f"Executor recorded target observation from {frozen.get('tool', '')}",
            "executor",
            refs=[str(frozen.get("request_id") or "")],
            details=frozen,
        )
        return frozen

    def add_audit_decision(self, decision: AuditDecision) -> AuditDecision:
        self.audit_decisions.append(decision)
        self.add_timeline("audit_decision", f"{decision.verdict.value}: {decision.reason}", "auditor", [decision.decision_id, decision.node_id])
        return decision

    def add_evidence_link(self, link: EvidenceLink) -> EvidenceLink:
        self.evidence_links.append(link)
        self.touch()
        return link

    def add_source_event(self, event: dict[str, Any]) -> dict[str, Any]:
        self.source_events.append(dict(event))
        self.add_timeline("source_event_recorded", "Sanitized source event recorded", str(event.get("event_type") or "source_event"), details=event)
        return event

    def add_source_artifact(self, artifact: dict[str, Any]) -> dict[str, Any]:
        self.source_artifacts.append(dict(artifact))
        self.add_timeline("source_artifact_recorded", "Source artifact reference recorded", str(artifact.get("artifact_type") or "source_artifact"), details=artifact)
        return artifact

    def record_error(self, error_type: str, message: str, details: dict[str, Any] | None = None) -> None:
        self.errors.append({"error_type": error_type, "message": message, "details": details or {}, "created_at": utc_now()})
        self.add_timeline(error_type, message, "system", details=details or {})

    def compact_summary(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "source_alert": self.source_alert,
            "final_status": self.final_status,
            "findings": [f.to_dict() for f in self.findings[-30:]],
            "audit_decisions": [d.to_dict() for d in self.audit_decisions[-20:]],
            "action_results": [r.to_dict() for r in self.action_results[-20:]],
        }

    def finding_text(self) -> str:
        return " ".join(f"{f.finding_type} {f.value} {f.evidence} {f.details}" for f in self.findings).lower().replace("\\\\", "\\")

    def attributed_process(self) -> dict[str, Any]:
        """Return process identity anchored to an observed C2 network connection.

        Arbitrary process/file findings must never replace the network owner as a
        response target. Process-tree evidence is used only to enrich the exact
        network PID with a missing name/path.
        """
        expected_remote = str(self.source_alert.get("remote_ip") or "").strip().lower()
        expected_port = str(self.source_alert.get("remote_port") or "")
        victim_ip = str(self.source_alert.get("victim_ip") or "").strip().lower()
        expected_local_port = self._source_local_port_for_attribution()
        if not expected_remote:
            return {}
        base: dict[str, Any] = {}
        for finding in reversed(self.findings):
            if finding.finding_type not in {
                "network_confirmed",
                "network_connection",
                "c2_process_attributed",
            }:
                continue
            details = finding.details if isinstance(finding.details, dict) else {}
            candidates = [details]
            connections = details.get("connections") if isinstance(details.get("connections"), list) else []
            candidates.extend(item for item in reversed(connections) if isinstance(item, dict))
            for candidate in candidates:
                remote_address = str(candidate.get("remote_address") or "").strip().lower()
                remote_port = str(candidate.get("remote_port") or "")
                if not remote_address:
                    src_ip = str(candidate.get("src_ip") or "").strip().lower()
                    dest_ip = str(candidate.get("dest_ip") or "").strip().lower()
                    if src_ip == expected_remote and (not victim_ip or dest_ip == victim_ip):
                        remote_address = src_ip
                        remote_port = str(candidate.get("src_port") or "")
                    elif dest_ip == expected_remote and (not victim_ip or src_ip == victim_ip):
                        remote_address = dest_ip
                        remote_port = str(candidate.get("dest_port") or "")
                network_mode = str(candidate.get("network_mode") or "")
                if network_mode == "inbound_listener":
                    listener = candidate.get("listener") if isinstance(candidate.get("listener"), dict) else {}
                    local_port_str = str(listener.get("local_port") or candidate.get("local_port") or "")
                    if local_port_str and expected_port and local_port_str == expected_port:
                        remote_address = expected_remote
                        remote_port = expected_port
                candidate_local_port = candidate.get("local_port")
                if network_mode == "inbound_listener":
                    listener = candidate.get("listener") if isinstance(candidate.get("listener"), dict) else {}
                    candidate_local_port = listener.get("local_port") or candidate_local_port
                elif not candidate_local_port:
                    src_ip = str(candidate.get("src_ip") or "").strip().lower()
                    dest_ip = str(candidate.get("dest_ip") or "").strip().lower()
                    if src_ip == victim_ip:
                        candidate_local_port = candidate.get("src_port")
                    elif dest_ip == victim_ip:
                        candidate_local_port = candidate.get("dest_port")
                if remote_address != expected_remote:
                    continue
                if expected_port and remote_port != expected_port:
                    continue
                if expected_local_port and candidate_local_port:
                    try:
                        if int(candidate_local_port) != expected_local_port:
                            continue
                    except (TypeError, ValueError):
                        continue
                try:
                    pid = int(candidate.get("pid") or candidate.get("owning_process") or 0)
                except (TypeError, ValueError):
                    pid = 0
                if pid:
                    base = {
                        "pid": pid,
                        "process_name": str(candidate.get("process_name") or candidate.get("name") or ""),
                        "process_path": str(candidate.get("process_path") or candidate.get("path") or ""),
                    }
                    break
            if base:
                break
        if not base:
            return {}

        pid = int(base["pid"])
        for finding in reversed(self.findings):
            if finding.finding_type not in {"process_detail", "process_tree", "payload_file_verified", "file_metadata"}:
                continue
            details = finding.details if isinstance(finding.details, dict) else {}
            candidates: list[dict[str, Any]] = [details]
            root = details.get("root") if isinstance(details.get("root"), dict) else None
            if root:
                candidates.append(root)
            chain = details.get("chain") if isinstance(details.get("chain"), list) else []
            candidates.extend(item for item in chain if isinstance(item, dict))
            for candidate in candidates:
                try:
                    candidate_pid = int(candidate.get("pid") or candidate.get("process_id") or 0)
                except (TypeError, ValueError):
                    candidate_pid = 0
                if candidate_pid and candidate_pid != pid:
                    continue
                if candidate_pid == pid:
                    base["process_name"] = base.get("process_name") or str(
                        candidate.get("process_name") or candidate.get("name") or ""
                    )
                    base["process_path"] = base.get("process_path") or str(
                        candidate.get("process_path") or candidate.get("path") or candidate.get("executable_path") or ""
                    )
        # Extract payload_path for interpreter-hosted processes (MITRE ATT&CK LOLBins).
        # When the C2 process is an interpreter host (rundll32, cscript, python, etc.),
        # the ExecutablePath points to the interpreter, not the actual payload.
        # The real payload file path is embedded in the process command line.
        process_name_lower = str(base.get("process_name") or "").lower()
        if process_name_lower and not process_name_lower.endswith(".exe"):
            process_name_lower = process_name_lower + ".exe"
        if process_name_lower in INTERPRETER_HOSTS:
            # 1. Check for a payload_file_verified Finding matching this PID
            for finding in reversed(self.findings):
                if finding.finding_type != "payload_file_verified":
                    continue
                details = finding.details if isinstance(finding.details, dict) else {}
                try:
                    finding_pid = int(details.get("pid") or details.get("process_id") or 0)
                except (TypeError, ValueError):
                    finding_pid = 0
                if not finding_pid or finding_pid == pid:
                    payload = str(finding.value or details.get("path") or "")
                    if payload:
                        base["payload_path"] = payload
                        break
            # 2. If no payload_file_verified Finding, extract from command_line
            if "payload_path" not in base:
                for finding in reversed(self.findings):
                    if finding.finding_type not in {"process_detail", "process_tree", "c2_process_attributed"}:
                        continue
                    details = finding.details if isinstance(finding.details, dict) else {}
                    cmd_candidates = [details]
                    root = details.get("root") if isinstance(details.get("root"), dict) else None
                    if root:
                        cmd_candidates.append(root)
                    chain = details.get("chain") if isinstance(details.get("chain"), list) else []
                    cmd_candidates.extend(item for item in chain if isinstance(item, dict))
                    for candidate in cmd_candidates:
                        try:
                            candidate_pid = int(candidate.get("pid") or candidate.get("process_id") or 0)
                        except (TypeError, ValueError):
                            candidate_pid = 0
                        if candidate_pid and candidate_pid != pid:
                            continue
                        command_line = str(candidate.get("command_line") or "")
                        if command_line:
                            payload_path = extract_payload_from_command_line(
                                command_line, base.get("process_name", "")
                            )
                            if payload_path:
                                base["payload_path"] = payload_path
                                break
                    if "payload_path" in base:
                        break
        return base

    def _source_local_port_for_attribution(self) -> int:
        """Return the local endpoint port from the frozen source alert event.

        A multi-instance implant can have several established connections to the
        same C2 endpoint. The alert's local port identifies which connection is
        the primary target; without this constraint, reverse-order finding
        traversal can select a sibling PID for the primary response action.
        """
        victim_ip = str(self.source_alert.get("victim_ip") or "").strip().lower()
        remote_ip = str(self.source_alert.get("remote_ip") or "").strip().lower()
        for event in reversed(self.source_events):
            src_ip = str(event.get("src_ip") or "").strip().lower()
            dest_ip = str(event.get("dest_ip") or "").strip().lower()
            try:
                if src_ip == victim_ip and dest_ip == remote_ip:
                    return int(event.get("src_port") or 0)
                if dest_ip == victim_ip and src_ip == remote_ip:
                    return int(event.get("dest_port") or 0)
            except (TypeError, ValueError):
                continue
        return 0

    def sibling_c2_processes(self) -> list[dict[str, Any]]:
        """Return C2-attributed processes with PIDs different from the primary.

        These are sibling instances of the same C2 implant running on the host
        (e.g. dual-implant or multi-session meterpreter). Each entry contains at
        least ``pid`` and ``process_name``/``process_path`` derived from
        ``c2_process_attributed`` findings whose PID differs from
        :meth:`attributed_process`.
        """
        primary = self.attributed_process()
        primary_pid = int(primary.get("pid") or 0)
        primary_path = str(primary.get("process_path") or primary.get("process_name") or "").lower()
        seen_pids: set[int] = {primary_pid}
        siblings: list[dict[str, Any]] = []
        for finding in self.findings:
            if finding.finding_type not in {"c2_process_attributed", "network_connection"}:
                continue
            details = finding.details if isinstance(finding.details, dict) else {}
            candidates: list[dict[str, Any]] = [details]
            conns = details.get("connections") if isinstance(details.get("connections"), list) else []
            candidates.extend(item for item in conns if isinstance(item, dict))
            for candidate in candidates:
                try:
                    pid = int(candidate.get("pid") or candidate.get("owning_process") or 0)
                except (TypeError, ValueError):
                    pid = 0
                if pid <= 0 or pid in seen_pids:
                    continue
                proc_path = str(candidate.get("process_path") or candidate.get("path") or "").lower()
                proc_name = str(candidate.get("process_name") or candidate.get("name") or "")
                # Only accept siblings running the same payload executable.
                if primary_path and proc_path and primary_path not in proc_path and proc_path not in primary_path:
                    continue
                seen_pids.add(pid)
                siblings.append({
                    "pid": pid,
                    "process_name": proc_name,
                    "process_path": str(candidate.get("process_path") or candidate.get("path") or ""),
                })
        return siblings

    def latest_pid(self) -> int:
        return int(self.attributed_process().get("pid") or 0)

    def latest_process_path(self) -> str:
        attributed = self.attributed_process()
        if attributed.get("process_path"):
            return str(attributed["process_path"])
        for finding in reversed(self.findings):
            details = finding.details if isinstance(finding.details, dict) else {}
            if finding.finding_type in {"network_confirmed", "network_connection", "c2_process_attributed"}:
                for conn in details.get("connections", []) if isinstance(details.get("connections"), list) else []:
                    value = str(conn.get("process_path") or "")
                    if value and "\\" in value:
                        return value
                value = str(details.get("process_path") or "")
                if value and "\\" in value:
                    return value
            if finding.finding_type in {"process_detail", "process_tree", "suspicious_process_path"}:
                for key in ("process_path", "path", "executable_path"):
                    value = str(details.get(key) or "")
                    if value and "\\" in value:
                        return value
                root = details.get("root") if isinstance(details.get("root"), dict) else {}
                value = str(root.get("path") or root.get("process_path") or "")
                if value and "\\" in value:
                    return value
                chain = details.get("chain", []) if isinstance(details.get("chain"), list) else []
                if chain and isinstance(chain[0], dict):
                    value = str(chain[0].get("path") or chain[0].get("process_path") or "")
                    if value and "\\" in value:
                        return value
        return ""

    def latest_process_name(self) -> str:
        attributed = self.attributed_process()
        if attributed.get("process_name"):
            return str(attributed["process_name"])
        for finding in reversed(self.findings):
            details = finding.details if isinstance(finding.details, dict) else {}
            if finding.finding_type in {"network_confirmed", "network_connection", "c2_process_attributed"}:
                for conn in details.get("connections", []) if isinstance(details.get("connections"), list) else []:
                    value = str(conn.get("process_name") or "")
                    if value:
                        return value
                value = str(details.get("process_name") or "")
                if value:
                    return value
            if finding.finding_type in {"process_detail", "process_tree", "suspicious_process_path"}:
                value = str(details.get("process_name") or details.get("name") or "")
                if value:
                    return value
                root = details.get("root") if isinstance(details.get("root"), dict) else {}
                value = str(root.get("process_name") or root.get("name") or "")
                if value:
                    return value
                chain = details.get("chain", []) if isinstance(details.get("chain"), list) else []
                if chain and isinstance(chain[0], dict):
                    value = str(chain[0].get("process_name") or chain[0].get("name") or "")
                    if value:
                        return value
        return ""

    def latest_persistence(self, category: str = "") -> dict[str, Any]:
        for finding in reversed(self.findings):
            if finding.finding_type == "persistence_linked_to_payload":
                details = finding.details
                if isinstance(details, dict) and (not category or details.get("category") == category):
                    return details
        return {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "case_name": self.case_name,
            "source_alert": self.source_alert,
            "source_events": self.source_events,
            "source_artifacts": self.source_artifacts,
            "response_target_lock": self.response_target_lock,
            "target_observations": list(self.target_observations),
            "strategy_tree": self.strategy_tree.to_dict() if self.strategy_tree else None,
            "findings": [f.to_dict() for f in self.findings],
            "action_results": [r.to_dict() for r in self.action_results],
            "audit_decisions": [d.to_dict() for d in self.audit_decisions],
            "evidence_links": [l.to_dict() for l in self.evidence_links],
            "timeline": [e.to_dict() for e in self.timeline],
            "final_report": self.final_report.to_dict() if self.final_report else None,
            "final_status": self.final_status,
            "errors": self.errors,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
