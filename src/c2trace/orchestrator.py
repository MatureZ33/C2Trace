from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from c2trace.agents import AuditorAgent, ExecutorAgent, PlannerAgent, PlannerError
from c2trace.execution import PreparedToolCall, ResponseAuthorization
from c2trace.models import (
    ActionResult,
    AuditDecision,
    AuditVerdict,
    CaseFile,
    MinimalAlert,
    NodeStatus,
    NodeType,
    StrategyNode,
)
from c2trace.reporter import Reporter
from c2trace.target_safety import TargetSafetyError
from c2trace.tools import READ_ONLY_TOOLS, RESPONSE_TOOLS


TOOL_ARGUMENT_KEYS: dict[str, frozenset[str]] = {
    "check_network": frozenset({
        "remote_ip",
        "remote_port",
        "local_port",
        "network_mode",
        "local_ip",
    }),
    "check_process": frozenset({"pid", "process_name"}),
    "check_process_tree": frozenset({"pid", "process_name"}),
    "check_file_metadata": frozenset({"file_path"}),
    "check_recent_files": frozenset({
        "since_utc",
        "until_utc",
        "root_aliases",
        "max_depth",
        "max_results",
        "max_file_size",
    }),
    "check_persistence_all": frozenset({"process_path"}),
    "check_powershell_history": frozenset({"pattern"}),
    "check_dns_cache": frozenset({"domain_filter"}),
    "kill_process": frozenset({"pid", "process_name", "expected_path"}),
    "remove_file": frozenset({"file_path"}),
    "remove_registry": frozenset({"reg_path", "value_name", "expected_value"}),
    "remove_scheduled_task": frozenset({"task_name", "task_path"}),
    "remove_service": frozenset({"service_name"}),
    "verify_cleanup": frozenset({
        "remote_ip",
        "remote_port",
        "local_port",
        "file_path",
        "pid",
        "process_name",
        "response_actions",
    }),
}


@dataclass(frozen=True, slots=True)
class RecentFileDiscoveryPolicy:
    """Ground-Truth-independent baseline host-file triage policy.

    The policy deliberately exposes only fixed root aliases and bounded limits.
    It never accepts a case-specific path, filename, extension, hash, or CALDERA
    value.  The resolved UTC window is frozen into the StrategyTree so a
    reviewed dry-run and its guarded execute replay the same investigation.
    """

    alert_lookback_minutes: int = 15
    root_aliases: tuple[str, ...] = ("users_public", "appdata")
    max_depth: int = 0
    max_results: int = 128
    max_file_size: int = 4 * 1024 * 1024

    def __post_init__(self) -> None:
        if not 1 <= int(self.alert_lookback_minutes) <= 60:
            raise ValueError("alert_lookback_minutes must be between 1 and 60")
        if tuple(self.root_aliases) != ("users_public", "appdata"):
            raise ValueError("recent-file discovery must use both fixed safe root aliases")
        if int(self.max_depth) != 0:
            raise ValueError("baseline recent-file discovery must remain root-only")
        if not 1 <= int(self.max_results) <= 128:
            raise ValueError("max_results must be between 1 and 128")
        if not 1 <= int(self.max_file_size) <= 16 * 1024 * 1024:
            raise ValueError("max_file_size must be between 1 and 16 MiB")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "c2trace.recent_file_discovery.v1",
            "alert_lookback_minutes": self.alert_lookback_minutes,
            "root_aliases": list(self.root_aliases),
            "max_depth": self.max_depth,
            "max_results": self.max_results,
            "max_file_size": self.max_file_size,
            "ground_truth_independent": True,
        }


class WorkflowController:
    def __init__(
        self,
        *,
        planner: PlannerAgent,
        auditor: AuditorAgent,
        executor: ExecutorAgent,
        reporter: Reporter | None = None,
        recent_file_discovery: RecentFileDiscoveryPolicy | None = None,
        max_steps: int = 60,
    ) -> None:
        self.planner = planner
        self.auditor = auditor
        self.executor = executor
        self.reporter = reporter or Reporter()
        self.recent_file_discovery = recent_file_discovery
        self.max_steps = max_steps

    def run_alert(
        self,
        alert: MinimalAlert,
        source_events: list[dict[str, Any]] | None = None,
        source_artifacts: list[dict[str, Any]] | None = None,
    ) -> CaseFile:
        case = CaseFile.from_alert(alert, source_events=source_events, source_artifacts=source_artifacts)
        validator = getattr(self.auditor, "target_validator", None)
        if validator is not None:
            try:
                validator.validate_case_input(case)
            except TargetSafetyError as exc:
                case.final_status = exc.status
                case.record_error(exc.error_type, str(exc), exc.details)
                self.reporter.build(case)
                return case
        try:
            self.planner.create_strategy_tree(case)
        except PlannerError:
            self.reporter.build(case)
            return case
        if self.recent_file_discovery is not None:
            try:
                self._ensure_recent_file_discovery(case)
            except (TypeError, ValueError) as exc:
                case.final_status = "planner_failed"
                case.record_error(
                    "baseline_triage_invalid",
                    str(exc),
                    {"stage": "recent_file_discovery"},
                )
                self.reporter.build(case)
                return case
        self._run_strategy(case)
        self._finalize_status(case)
        self.reporter.build(case)
        return case

    def _ensure_recent_file_discovery(self, case: CaseFile) -> None:
        tree = case.strategy_tree
        policy = self.recent_file_discovery
        if tree is None or policy is None:
            raise ValueError("recent-file discovery requires a StrategyTree and policy")

        marker = "c2trace.baseline.recent_files.v1"
        existing = [
            node
            for node in tree.nodes
            if node.metadata.get("c2trace_policy") == marker
        ]
        if existing:
            if len(existing) != 1:
                raise ValueError("StrategyTree contains duplicate baseline recent-file nodes")
            self._validate_recent_file_node(existing[0], policy)
            case.add_timeline(
                "baseline_triage_replayed",
                "Reused the reviewed bounded recent-file discovery window",
                "workflow",
                [existing[0].node_id],
                details={"policy": policy.to_dict()},
            )
            return

        now = datetime.now(timezone.utc)
        alert_time = self._alert_window_start(case.source_alert)
        anchor = alert_time or now
        since = anchor - timedelta(minutes=policy.alert_lookback_minutes)
        if since >= now:
            raise ValueError("alert time is too far in the future for recent-file discovery")
        if now - since > timedelta(hours=2):
            raise ValueError("alert is too old for the bounded recent-file discovery window")

        base_id = "c2trace-baseline-recent-files"
        node_id = base_id
        suffix = 2
        existing_ids = set(tree.node_map())
        while node_id in existing_ids:
            node_id = f"{base_id}-{suffix}"
            suffix += 1
        node = StrategyNode(
            node_id=node_id,
            type=NodeType.INVESTIGATE,
            goal="Collect bounded metadata for recently modified files in fixed safe roots",
            tool="check_recent_files",
            arguments={
                "since_utc": self._utc_text(since),
                "until_utc": self._utc_text(now),
                "root_aliases": list(policy.root_aliases),
                "max_depth": policy.max_depth,
                "max_results": policy.max_results,
                "max_file_size": policy.max_file_size,
            },
            status=NodeStatus.READY,
            metadata={
                "c2trace_policy": marker,
                "ground_truth_independent": True,
            },
        )
        tree.nodes.insert(0, node)
        try:
            tree.validate()
        except Exception:
            tree.nodes.remove(node)
            raise
        case.add_timeline(
            "baseline_triage_added",
            "Added bounded recent-file discovery using the alert time window",
            "workflow",
            [node.node_id],
            details={"policy": policy.to_dict(), "arguments": dict(node.arguments)},
        )

    @staticmethod
    def _validate_recent_file_node(
        node: StrategyNode,
        policy: RecentFileDiscoveryPolicy,
    ) -> None:
        if node.type != NodeType.INVESTIGATE or node.tool != "check_recent_files":
            raise ValueError("reviewed baseline recent-file node has the wrong type or tool")
        arguments = node.arguments
        if set(arguments) != set(TOOL_ARGUMENT_KEYS["check_recent_files"]):
            raise ValueError("reviewed baseline recent-file node has unexpected arguments")
        if list(arguments.get("root_aliases") or []) != list(policy.root_aliases):
            raise ValueError("reviewed baseline recent-file roots differ from policy")
        if arguments.get("max_depth") != policy.max_depth:
            raise ValueError("reviewed baseline recent-file depth differs from policy")
        if arguments.get("max_results") != policy.max_results:
            raise ValueError("reviewed baseline recent-file result limit differs from policy")
        if arguments.get("max_file_size") != policy.max_file_size:
            raise ValueError("reviewed baseline recent-file size limit differs from policy")
        since = WorkflowController._parse_alert_time(arguments.get("since_utc"))
        until = WorkflowController._parse_alert_time(arguments.get("until_utc"))
        if since is None or until is None or since >= until or until - since > timedelta(hours=2):
            raise ValueError("reviewed baseline recent-file UTC window is invalid")

    @staticmethod
    def _alert_window_start(alert: dict[str, Any]) -> datetime | None:
        window = alert.get("time_window")
        if not isinstance(window, dict):
            return None
        raw = window.get("start") or window.get("end")
        if raw in (None, ""):
            return None
        parsed = WorkflowController._parse_alert_time(raw)
        if parsed is None:
            raise ValueError("alert time_window must contain a timezone-aware ISO-8601 value")
        return parsed

    @staticmethod
    def _parse_alert_time(value: Any) -> datetime | None:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(
                text[:-1] + "+00:00" if text.endswith("Z") else text
            )
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _utc_text(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def _run_strategy(self, case: CaseFile) -> None:
        tree = case.strategy_tree
        if tree is None:
            case.final_status = "planner_failed"
            return
        for step in range(1, self.max_steps + 1):
            self._refresh_ready_nodes(case)
            ready = [n for n in tree.nodes if n.status == NodeStatus.READY]
            if not ready:
                case.add_timeline("strategy_idle", "No ready strategy nodes remain", "workflow")
                return
            node = ready[0]
            case.add_timeline("node_selected", f"{node.node_id} {node.type.value} {node.tool or node.condition}", "workflow", [node.node_id])
            if node.type in {NodeType.INVESTIGATE, NodeType.VERIFY}:
                self._execute_node(case, node)
            elif node.type == NodeType.DECISION:
                self._evaluate_decision(case, node)
            elif node.type == NodeType.RESPONSE:
                self._audit_then_execute_response(case, node)
            case.add_timeline("strategy_step", f"Completed strategy step {step}", "workflow", [node.node_id])
            if node.metadata.get("c2trace_policy") == "c2trace.baseline.recent_files.v1":
                result = next(
                    (
                        item
                        for item in reversed(case.action_results)
                        if item.result_id == node.result_id
                    ),
                    None,
                )
                completeness_error = self._recent_file_result_error(result)
                if node.status == NodeStatus.FAILED or completeness_error:
                    node.status = NodeStatus.FAILED
                    case.final_status = "baseline_triage_failed"
                    case.record_error(
                        "baseline_triage_failed",
                        completeness_error
                        or (
                            result.error
                            if result is not None
                            else "recent-file discovery failed"
                        )
                        or "recent-file discovery failed",
                        {"node_id": node.node_id, "tool": node.tool},
                    )
                    return
            if case.final_status in {
                "protected_target_blocked",
                "target_drift",
                "wrong_target",
                "infrastructure_invalid",
                "target_identity_incomplete",
            }:
                return
            # After a successful kill_process, immediately kill sibling C2
            # processes before remove_file or other responses run.
            if node.type == NodeType.RESPONSE and node.tool == "kill_process" and node.status == NodeStatus.SUCCEEDED:
                self._auto_kill_sibling_c2_processes(case)
                if case.final_status == "target_identity_incomplete":
                    return
        case.final_status = "failed_max_steps"
        case.record_error("max_steps_exceeded", f"Exceeded max_steps={self.max_steps}")

    @staticmethod
    def _recent_file_result_error(result: ActionResult | None) -> str:
        if result is None:
            return "baseline recent-file discovery produced no ActionResult"
        if not result.success:
            return result.error or "baseline recent-file discovery tool failed"
        data = result.data if isinstance(result.data, dict) else {}
        files = data.get("files")
        scan = data.get("scan") if isinstance(data.get("scan"), dict) else {}
        roots = scan.get("roots") if isinstance(scan.get("roots"), list) else []
        if not isinstance(files, list):
            return "baseline recent-file discovery returned no files array"
        if scan.get("truncated") is not False:
            reasons = scan.get("truncated_reasons") or []
            return f"baseline recent-file discovery was truncated: {reasons}"
        root_state = {
            str(item.get("alias") or ""): item.get("exists") is True
            for item in roots
            if isinstance(item, dict)
        }
        if root_state != {"users_public": True, "appdata": True}:
            return "baseline recent-file discovery did not scan both fixed roots"
        return ""

    def _execute_node(
        self,
        case: CaseFile,
        node: StrategyNode,
        *,
        audit_decision: AuditDecision | None = None,
        prepared_call: PreparedToolCall | None = None,
        authorization: ResponseAuthorization | None = None,
    ) -> None:
        policy_error = self._execution_policy_error(case, node, audit_decision)
        if policy_error:
            self._fail_node_execution(case, node, policy_error)
            return
        node.status = NodeStatus.RUNNING
        node.assigned_to = "executor"
        args = self._resolve_arguments(case, node)
        prepared = prepared_call or self.executor.prepare(case, node, args)
        if node.type == NodeType.RESPONSE:
            if not self.executor.response_enabled:
                result = self.executor.preview_response(case, node, prepared)
                node.status = NodeStatus.SUCCEEDED
                self._activate_branch(case, node, success=True)
                return
            audited_response = getattr(self.executor.tool_runner, "audited_response", None)
            try:
                if authorization is not None:
                    result = self.executor.execute(
                        case,
                        node,
                        prepared,
                        authorization=authorization,
                    )
                elif callable(audited_response):
                    with audited_response(decision=audit_decision, node=node, params=args):
                        result = self.executor.execute(case, node, prepared)
                else:
                    # Test/demonstration runners still sit behind the
                    # workflow's audit checks. The MCP server additionally
                    # requires and consumes its own one-shot capability.
                    result = self.executor.execute(case, node, prepared)
            except (PermissionError, ValueError) as exc:
                self._fail_node_execution(case, node, str(exc))
                return
        else:
            result = self.executor.execute(case, node, prepared)
        if str(result.transport_receipt.get("error_type") or "") == "infrastructure_invalid":
            case.final_status = "infrastructure_invalid"
        node.status = NodeStatus.SUCCEEDED if result.success else NodeStatus.FAILED
        self._activate_branch(case, node, success=result.success)

    def _fail_target_safety(
        self,
        case: CaseFile,
        node: StrategyNode,
        arguments: dict[str, Any],
        error: TargetSafetyError,
    ) -> None:
        result = ActionResult(
            node_id=node.node_id,
            tool=node.tool,
            success=False,
            error=str(error),
            arguments=dict(arguments),
            audit_decision_id=node.audit_decision_id,
        )
        case.add_result(result)
        node.result_id = result.result_id
        node.status = NodeStatus.FAILED
        case.final_status = error.status
        case.record_error(
            error.error_type,
            str(error),
            {
                "node_id": node.node_id,
                "tool": node.tool,
                **error.details,
            },
        )
        self._activate_branch(case, node, success=False)

    def _audit_then_execute_response(self, case: CaseFile, node: StrategyNode) -> None:
        node.status = NodeStatus.IN_REVIEW
        node.assigned_to = "auditor"
        args = self._resolve_arguments(case, node)
        prepared = self.executor.prepare(case, node, args)
        try:
            decision = self.auditor.audit(case, node, prepared)
        except TargetSafetyError as exc:
            self._fail_target_safety(case, node, args, exc)
            return
        node.audit_decision_id = decision.decision_id
        if decision.verdict == AuditVerdict.APPROVED:
            node.status = NodeStatus.APPROVED
            self._execute_node(
                case,
                node,
                audit_decision=decision,
                prepared_call=prepared,
                authorization=self.auditor.authorization_for(decision.decision_id),
            )
            return
        if decision.verdict == AuditVerdict.NEED_MORE_EVIDENCE:
            node.status = NodeStatus.NEED_MORE_EVIDENCE
            try:
                evidence_nodes = self.planner.plan_more_evidence(case, node, decision.reason)
            except PlannerError:
                node.status = NodeStatus.CLOSED
                return
            if case.strategy_tree:
                evidence_ids = [n.node_id for n in evidence_nodes]
                for evidence_node in evidence_nodes:
                    evidence_node.on_success = list(dict.fromkeys([*evidence_node.on_success, node.node_id]))
                try:
                    case.strategy_tree.add_nodes(evidence_nodes)
                except Exception as exc:
                    case.record_error(
                        "planner_failed",
                        str(exc),
                        {"stage": "add_more_evidence", "node_id": node.node_id},
                    )
                    node.status = NodeStatus.CLOSED
                    return
                node.requires = list(dict.fromkeys([*node.requires, *evidence_ids]))
                node.status = NodeStatus.PENDING
                case.add_timeline("evidence_nodes_added", f"Added {len(evidence_nodes)}补证 node(s) for {node.node_id}", "planner", evidence_ids)
            return
        node.status = NodeStatus.REJECTED
        self._close_branch(node, "证据不足关闭该处置分支")

    def _evaluate_decision(self, case: CaseFile, node: StrategyNode) -> None:
        node.status = NodeStatus.RUNNING
        condition = (node.condition or node.goal or "").lower()
        if "active_connection" in condition or "network" in condition:
            success = any(f.finding_type in {"network_confirmed", "network_connection", "network_connected", "network_stale", "network_listening"} for f in case.findings)
        elif "evidence_sufficient" in condition or "response" in condition:
            success = self._evidence_sufficient_for_response(case)
        else:
            success = bool(case.findings)
        node.status = NodeStatus.SUCCEEDED if success else NodeStatus.FAILED
        self._activate_branch(case, node, success=success)

    def _execution_policy_error(
        self,
        case: CaseFile,
        node: StrategyNode,
        audit_decision: AuditDecision | None,
    ) -> str:
        if node.type in {NodeType.INVESTIGATE, NodeType.VERIFY}:
            if node.tool not in READ_ONLY_TOOLS:
                return f"{node.type.value} node cannot execute destructive or unsupported tool {node.tool}"
            return ""
        if node.type != NodeType.RESPONSE:
            return f"node type {node.type.value} cannot be sent to Executor"
        if node.tool not in RESPONSE_TOOLS:
            return f"response node cannot execute non-response tool {node.tool}"
        if node.metadata.get("sibling_c2_process"):
            pass  # Sibling C2 kill_process bypasses evidence gate; validated by audit.
        elif case.strategy_tree is None or not case.strategy_tree.response_has_evidence_gate(node):
            return "response node is not gated by an evidence_sufficient_for_response decision"
        if audit_decision is None or audit_decision.verdict != AuditVerdict.APPROVED:
            return "response execution requires an approved audit decision"
        if audit_decision.node_id != node.node_id or node.audit_decision_id != audit_decision.decision_id:
            return "approved audit decision is not bound to the response node"
        if not any(decision.decision_id == audit_decision.decision_id for decision in case.audit_decisions):
            return "approved audit decision is not recorded in the CaseFile"
        return ""

    def _fail_node_execution(self, case: CaseFile, node: StrategyNode, error: str) -> None:
        result = ActionResult(
            node_id=node.node_id,
            tool=node.tool,
            success=False,
            error=error,
            arguments=self._resolve_arguments(case, node),
            audit_decision_id=node.audit_decision_id,
        )
        case.add_result(result)
        node.result_id = result.result_id
        node.status = NodeStatus.FAILED
        case.record_error(
            "execution_policy_blocked",
            error,
            {"node_id": node.node_id, "node_type": node.type.value, "tool": node.tool},
        )
        self._activate_branch(case, node, success=False)

    def _refresh_ready_nodes(self, case: CaseFile) -> None:
        tree = case.strategy_tree
        if tree is None:
            return
        node_map = tree.node_map()
        for node in tree.nodes:
            if node.status != NodeStatus.PENDING:
                continue
            if all(self._requirement_satisfied(node, node_map.get(req)) for req in node.requires):
                node.status = NodeStatus.READY

    def _activate_branch(self, case: CaseFile, node: StrategyNode, *, success: bool) -> None:
        if case.strategy_tree is None:
            return
        node_map = case.strategy_tree.node_map()
        target_ids = node.on_success if success else node.on_failure
        skipped_ids = node.on_failure if success else node.on_success
        # A node may be used as a convergence point by appearing in both
        # branches. It should remain eligible once its dependencies complete.
        skipped_ids = [node_id for node_id in skipped_ids if node_id not in target_ids]
        for skipped_id in skipped_ids:
            skipped = node_map.get(skipped_id)
            if skipped and skipped.status == NodeStatus.PENDING:
                skipped.status = NodeStatus.SKIPPED
        for target_id in target_ids:
            target = node_map.get(target_id)
            if not target or target.status != NodeStatus.PENDING:
                continue
            other_requirements = [req for req in target.requires if req != node.node_id]
            if all(self._requirement_satisfied(target, node_map.get(req)) for req in other_requirements):
                target.status = NodeStatus.READY

    def _close_branch(self, node: StrategyNode, reason: str) -> None:
        node.status = NodeStatus.CLOSED
        node.metadata["closed_reason"] = reason

    @staticmethod
    def _requirement_satisfied(node: StrategyNode, requirement: StrategyNode | None) -> bool:
        if requirement is None:
            return False
        if requirement.status in {NodeStatus.SUCCEEDED, NodeStatus.APPROVED, NodeStatus.CLOSED}:
            return True
        if node.type == NodeType.VERIFY and requirement.type == NodeType.RESPONSE:
            return requirement.status in {NodeStatus.REJECTED, NodeStatus.CLOSED, NodeStatus.SKIPPED}
        return False

    def _resolve_arguments(self, case: CaseFile, node: StrategyNode) -> dict[str, Any]:
        resolved: dict[str, Any] = {}
        for key, value in node.arguments.items():
            resolved[key] = self._resolve_value(case, value)
        tool = node.tool
        alert = case.source_alert
        attributed = case.attributed_process()
        effective_path = str(attributed.get("payload_path") or attributed.get("process_path") or "")
        if tool == "check_network":
            resolved.pop("target_ip", None)
            resolved.pop("target_port", None)
            self._set_exact(resolved, "remote_ip", alert.get("remote_ip"))
            self._set_exact(resolved, "remote_port", alert.get("remote_port"))
            network = self._source_network_identity(case)
            self._set_exact(resolved, "network_mode", network.get("network_mode"))
            if network.get("network_mode") == "inbound_listener":
                self._set_exact(resolved, "local_ip", network.get("local_ip"))
                self._set_exact(resolved, "local_port", network.get("local_port"))
            else:
                # Do NOT filter by local_port: multi-instance C2 implants may use
                # different ephemeral local ports to the same remote C2 endpoint.
                # Removing local_port ensures ALL connections to the C2 IP:port
                # are discovered, enabling sibling-process attribution.
                resolved.pop("local_ip", None)
                resolved.pop("local_port", None)
        elif tool in {"check_process", "check_process_tree"}:
            sibling_pid = int(node.metadata.get("sibling_pid") or 0) if node.metadata else 0
            sibling = next(
                (
                    item
                    for item in case.sibling_c2_processes()
                    if int(item.get("pid") or 0) == sibling_pid
                ),
                {},
            ) if sibling_pid else {}
            pid = sibling_pid or int(attributed.get("pid") or 0)
            name = str(sibling.get("process_name") or attributed.get("process_name") or "")
            if pid:
                self._set_exact(resolved, "pid", pid)
                resolved.pop("process_name", None)
            elif name:
                resolved.pop("pid", None)
                self._set_exact(resolved, "process_name", name)
            else:
                resolved.pop("pid", None)
                resolved.pop("process_name", None)
        elif tool == "check_file_metadata":
            self._set_exact(resolved, "file_path", effective_path)
        elif tool == "check_persistence_all":
            self._set_exact(resolved, "process_path", effective_path)
        elif tool == "check_powershell_history":
            self._set_exact(
                resolved,
                "pattern",
                attributed.get("process_path") or attributed.get("process_name") or alert.get("remote_ip"),
            )
        elif tool == "check_dns_cache":
            self._set_exact(resolved, "domain_filter", alert.get("remote_domain"))
        elif tool == "kill_process":
            # Sibling C2 process nodes carry their own pid in metadata.
            sibling_pid = int(node.metadata.get("sibling_pid") or 0) if node.metadata else 0
            if sibling_pid:
                self._set_exact(resolved, "pid", sibling_pid)
                resolved.pop("process_name", None)
                sibling_info = next(
                    (s for s in case.sibling_c2_processes() if int(s.get("pid") or 0) == sibling_pid),
                    {},
                )
                sname = str(sibling_info.get("process_name") or "")
                spath = str(sibling_info.get("process_path") or "")
                if sname:
                    self._set_exact(resolved, "process_name", sname.removesuffix(".exe"))
                if spath:
                    self._set_exact(resolved, "expected_path", spath)
            else:
                pid = int(attributed.get("pid") or 0)
                if pid:
                    self._set_exact(resolved, "pid", pid)
                else:
                    resolved.pop("pid", None)
                name = str(attributed.get("process_name") or "")
                if name:
                    self._set_exact(resolved, "process_name", name.removesuffix(".exe"))
                else:
                    resolved.pop("process_name", None)
                path = str(attributed.get("process_path") or "")
                if path:
                    self._set_exact(resolved, "expected_path", path)
                else:
                    resolved.pop("expected_path", None)
        elif tool == "remove_file":
            self._set_exact(resolved, "file_path", effective_path)
        elif tool == "remove_registry":
            persistence = case.latest_persistence("registry_run_keys")
            self._set_exact(resolved, "reg_path", persistence.get("path"))
            self._set_exact(resolved, "value_name", persistence.get("name"))
            self._set_exact(resolved, "expected_value", persistence.get("value"))
        elif tool == "remove_scheduled_task":
            persistence = case.latest_persistence("scheduled_tasks")
            self._set_exact(resolved, "task_name", persistence.get("name"))
            self._set_exact(resolved, "task_path", persistence.get("path"))
        elif tool == "remove_service":
            persistence = case.latest_persistence("services")
            self._set_exact(resolved, "service_name", persistence.get("name"))
        elif tool == "verify_cleanup":
            self._set_exact(resolved, "remote_ip", alert.get("remote_ip"))
            self._set_exact(resolved, "remote_port", alert.get("remote_port"))
            self._set_exact(resolved, "local_port", self._source_local_port(case))
            self._set_exact(resolved, "file_path", effective_path)
            self._set_exact(resolved, "pid", attributed.get("pid"))
            self._set_exact(resolved, "process_name", attributed.get("process_name"))
            response_actions = [
                {
                    "result_id": result.result_id,
                    "node_id": result.node_id,
                    "tool": result.tool,
                    "arguments": dict(result.arguments),
                }
                for result in case.action_results
                if result.tool in RESPONSE_TOOLS
                and result.success
                and not (isinstance(result.data, dict) and result.data.get("dry_run") is True)
            ]
            if response_actions:
                resolved["response_actions"] = response_actions
            else:
                resolved.pop("response_actions", None)
        allowed_keys = TOOL_ARGUMENT_KEYS.get(tool, frozenset())
        return {
            key: value
            for key, value in resolved.items()
            if key in allowed_keys
            and value not in ("", None)
            and (
                value != 0
                or (tool == "check_recent_files" and key == "max_depth")
            )
        }

    @staticmethod
    def _set_exact(target: dict[str, Any], key: str, value: Any) -> None:
        if value in ("", None, 0):
            target.pop(key, None)
        else:
            target[key] = value

    @staticmethod
    def _source_local_port(case: CaseFile) -> int:
        return int(WorkflowController._source_network_identity(case).get("local_port") or 0)

    @staticmethod
    def _source_network_identity(case: CaseFile) -> dict[str, Any]:
        victim_ip = str(case.source_alert.get("victim_ip") or "")
        remote_ip = str(case.source_alert.get("remote_ip") or "")
        for event in reversed(case.source_events):
            src_ip = str(event.get("src_ip") or "")
            dest_ip = str(event.get("dest_ip") or "")
            try:
                if src_ip == victim_ip and (not remote_ip or dest_ip == remote_ip):
                    return {
                        "network_mode": "outbound_active_flow",
                        "local_ip": victim_ip,
                        "local_port": int(event.get("src_port") or 0),
                    }
                if dest_ip == victim_ip and (not remote_ip or src_ip == remote_ip):
                    return {
                        "network_mode": "inbound_listener",
                        "local_ip": victim_ip,
                        "local_port": int(event.get("dest_port") or 0),
                    }
            except (TypeError, ValueError):
                continue
        return {}

    def _resolve_value(self, case: CaseFile, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        text = value.strip()
        alert = case.source_alert
        persistence = case.latest_persistence()
        category = str(persistence.get("category") or "")
        is_reg = category == "registry_run_keys"
        is_task = category == "scheduled_tasks"
        is_service = category == "services"
        placeholders = {
            "{{alert.remote_ip}}": alert.get("remote_ip", ""),
            "{{alert.remote_port}}": alert.get("remote_port", ""),
            "{{alert.remote_domain}}": alert.get("remote_domain", ""),
            "{{alert.remote_url}}": alert.get("remote_url", ""),
            "{{alert.victim_ip}}": alert.get("victim_ip", ""),
            "{{evidence.pid}}": case.latest_pid(),
            "{{evidence.process_name}}": case.latest_process_name(),
            "{{evidence.process_path}}": case.latest_process_path(),
            "{{evidence.file_path}}": case.latest_process_path(),
            "{{evidence.persistence.category}}": category,
            "{{evidence.persistence.name}}": persistence.get("name", ""),
            "{{evidence.persistence.path}}": persistence.get("path", ""),
            "{{evidence.persistence.reg_path}}": persistence.get("path", "") if is_reg else "",
            "{{evidence.persistence.value_name}}": persistence.get("name", "") if is_reg else "",
            "{{evidence.persistence.expected_value}}": persistence.get("value", "") if is_reg else "",
            "{{evidence.persistence.task_name}}": persistence.get("name", "") if is_task else "",
            "{{evidence.persistence.task_path}}": persistence.get("path", "") if is_task else "",
            "{{evidence.persistence.service_name}}": persistence.get("name", "") if is_service else "",
        }
        return placeholders.get(text, value)

    @staticmethod
    def _evidence_sufficient_for_response(case: CaseFile) -> bool:
        types = {f.finding_type for f in case.findings}
        has_network = bool(types & {"network_confirmed", "network_connection", "network_connected", "network_stale", "network_listening"})
        has_process = bool(types & {"c2_process_attributed", "process_detail", "process_tree"})
        has_artifact_context = bool(types & {"payload_file_verified", "suspicious_process_path", "persistence_summary", "persistence_linked_to_payload"})
        return has_network and has_process and has_artifact_context

    def _auto_kill_sibling_c2_processes(self, case: CaseFile) -> None:
        """Automatically kill sibling C2 processes found during investigation.

        When a multi-instance C2 implant (e.g. dual meterpreter) is discovered,
        the LLM-generated strategy tree only contains a single kill_process node
        for the primary network-attributed PID. This method discovers sibling
        C2 processes (same executable, different PID) and executes kill_process
        for each through the full audit + execute pipeline.

        Standalone StrategyNode objects are used (NOT added to the strategy
        tree) so that they are never prematurely replayed in the execute phase.
        """
        if case.strategy_tree is None:
            return
        killed_pids = {
            int(r.arguments.get("pid") or 0)
            for r in case.action_results
            if r.tool == "kill_process" and r.success
        }
        if not killed_pids:
            return
        siblings = case.sibling_c2_processes()
        if not siblings:
            return
        from c2trace.models import StrategyNode, NodeType, NodeStatus
        for i, sibling in enumerate(siblings):
            sibling_pid = int(sibling.get("pid") or 0)
            if sibling_pid <= 0 or sibling_pid in killed_pids:
                continue
            node_id = f"sibling-kill-{i+1}"
            already = any(
                int(r.arguments.get("pid") or 0) == sibling_pid
                for r in case.action_results
                if r.tool == "kill_process"
            )
            if already:
                continue
            identity_node = StrategyNode(
                node_id=f"sibling-identity-{i+1}",
                type=NodeType.INVESTIGATE,
                goal=f"Confirm sibling C2 process identity PID {sibling_pid}",
                tool="check_process",
                arguments={"pid": str(sibling_pid)},
                requires=[],
                on_success=[],
                on_failure=[],
                status=NodeStatus.READY,
                metadata={"sibling_c2_process": True, "sibling_pid": sibling_pid},
            )
            self._execute_node(case, identity_node)
            identity_result = next(
                (
                    result
                    for result in reversed(case.action_results)
                    if result.result_id == identity_node.result_id
                ),
                None,
            )
            process_rows = (
                identity_result.data.get("processes", [])
                if identity_result is not None and isinstance(identity_result.data, dict)
                else []
            )
            matching_rows: list[dict[str, Any]] = []
            for row in process_rows if isinstance(process_rows, list) else []:
                if not isinstance(row, dict):
                    continue
                try:
                    row_pid = int(row.get("pid") or row.get("process_id") or 0)
                except (TypeError, ValueError):
                    continue
                if row_pid == sibling_pid:
                    matching_rows.append(row)
            observed = matching_rows[0] if len(matching_rows) == 1 else {}
            expected_path = str(sibling.get("process_path") or "")
            observed_path = str(
                observed.get("process_path")
                or observed.get("path")
                or observed.get("executable_path")
                or ""
            )
            creation_time = str(
                observed.get("creation_time")
                or observed.get("creation_time_utc")
                or observed.get("creation_date")
                or observed.get("start_time")
                or ""
            )
            same_path = (
                bool(observed_path)
                and (
                    not expected_path
                    or observed_path.replace("/", "\\").casefold()
                    == expected_path.replace("/", "\\").casefold()
                )
            )
            if (
                identity_node.status != NodeStatus.SUCCEEDED
                or len(matching_rows) != 1
                or not creation_time
                or not same_path
            ):
                case.final_status = "target_identity_incomplete"
                case.record_error(
                    "sibling_identity_incomplete",
                    f"Refusing sibling response for PID {sibling_pid}: exact PID/path/creation_time identity was not confirmed",
                    {
                        "pid": sibling_pid,
                        "matching_process_rows": len(matching_rows),
                        "expected_path": expected_path,
                        "observed_path": observed_path,
                        "creation_time_present": bool(creation_time),
                    },
                )
                case.add_timeline(
                    "sibling_identity_blocked",
                    f"Sibling C2 process PID {sibling_pid} was not fully identified; response branch stopped",
                    "workflow",
                    [identity_node.node_id],
                )
                return
            case.add_timeline(
                "sibling_identity_confirmed",
                f"Sibling C2 process PID {sibling_pid} confirmed by check_process",
                "workflow",
                [identity_node.node_id],
                details={"pid": sibling_pid, "creation_time": creation_time, "path": observed_path},
            )
            node = StrategyNode(
                node_id=node_id,
                type=NodeType.RESPONSE,
                goal=f"Kill sibling C2 process PID {sibling_pid}",
                tool="kill_process",
                arguments={"pid": str(sibling_pid)},
                requires=[],
                on_success=[],
                on_failure=[],
                status=NodeStatus.READY,
                metadata={
                    "sibling_c2_process": True,
                    "sibling_pid": sibling_pid,
                    "sibling_process_name": sibling.get("process_name", ""),
                    "sibling_process_path": sibling.get("process_path", ""),
                },
            )
            case.add_timeline(
                "sibling_c2_discovered",
                f"Sibling C2 process PID {sibling_pid} discovered; killing via audit pipeline",
                "workflow",
                [node.node_id],
                details={"sibling_pid": sibling_pid},
            )
            self._audit_then_execute_response(case, node)
            killed_pids.add(sibling_pid)

    def _finalize_status(self, case: CaseFile) -> None:
        if case.final_status in {
            "planner_failed",
            "failed_max_steps",
            "baseline_triage_failed",
            "protected_target_blocked",
            "target_drift",
            "wrong_target",
            "infrastructure_invalid",
            "target_identity_incomplete",
        }:
            return
        response_failures = [result for result in case.action_results if result.tool in RESPONSE_TOOLS and not result.success]
        if response_failures:
            case.final_status = "response_failed"
            for result in response_failures:
                case.record_error(
                    "response_action_failed",
                    result.error or f"{result.tool} failed",
                    {"node_id": result.node_id, "tool": result.tool},
                )
            return
        response_results = [result for result in case.action_results if result.tool in RESPONSE_TOOLS]
        dry_run_results = [
            result
            for result in response_results
            if result.success and isinstance(result.data, dict) and result.data.get("dry_run") is True
        ]
        executed_results = [
            result
            for result in response_results
            if result.success and not (isinstance(result.data, dict) and result.data.get("dry_run") is True)
        ]
        if executed_results:
            last_response_index = max(case.action_results.index(result) for result in executed_results)
            verification_results = [
                result
                for result in case.action_results[last_response_index + 1:]
                if result.tool == "verify_cleanup"
            ]
            if not verification_results:
                case.final_status = "cleanup_verification_missing"
                case.record_error(
                    "cleanup_verification_missing",
                    "Response actions executed without a subsequent cleanup verification",
                )
                return
            if any(not result.success for result in verification_results):
                case.final_status = "verification_failed"
                case.record_error(
                    "cleanup_verification_failed",
                    "Cleanup verification tool failed after response execution",
                )
                return
            successful_verification_ids = {
                result.result_id for result in verification_results if result.success
            }
            verified_actions = [
                finding.details
                for finding in case.findings
                if finding.finding_type == "cleanup_action_verified"
                and isinstance(finding.details, dict)
                and str(finding.details.get("verification_result_id") or "") in successful_verification_ids
            ]
            missing_actions = [
                {
                    "result_id": result.result_id,
                    "node_id": result.node_id,
                    "tool": result.tool,
                    "arguments": result.arguments,
                }
                for result in executed_results
                if not any(
                    str(details.get("response_result_id") or "") == result.result_id
                    and str(details.get("tool") or "") == result.tool
                    and details.get("arguments") == result.arguments
                    for details in verified_actions
                )
            ]
            network_verified = any(
                finding.finding_type == "cleanup_network_verified"
                and isinstance(finding.details, dict)
                and str(finding.details.get("verification_result_id") or "") in successful_verification_ids
                for finding in case.findings
            )
            if missing_actions or not network_verified:
                case.final_status = "cleanup_incomplete"
                case.record_error(
                    "cleanup_incomplete",
                    "Cleanup verification did not confirm every executed response target and the final C2 network state",
                    {
                        "missing_response_actions": missing_actions,
                        "network_verification_missing": not network_verified,
                    },
                )
                return
            case.final_status = "completed"
            return
        if dry_run_results or any(f.finding_type == "response_action_dry_run" for f in case.findings):
            case.final_status = "completed_dry_run"
            return
        if self._evidence_sufficient_for_response(case):
            case.final_status = "response_not_executed"
            return
        case.final_status = "attribution_inconclusive"


# Migration compatibility only.  New production code and documentation use
# WorkflowController so this deterministic state machine is not personified as
# a fourth agent.
C2TraceOrchestrator = WorkflowController
