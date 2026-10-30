from __future__ import annotations

from typing import Any

from c2trace.authorization import ResponseAuthorizationIssuer
from c2trace.execution import PreparedToolCall, ResponseAuthorization
from c2trace.llm import DeepSeekClient, LLMError
from c2trace.models import AuditDecision, AuditVerdict, CaseFile, StrategyNode
from c2trace.agents.target_identity import TargetIdentityValidator


class AuditorAgent:
    role_name = "auditor"

    def __init__(
        self,
        *,
        llm_client: Any | None = None,
        target_validator: TargetIdentityValidator | None = None,
        authorization_issuer: ResponseAuthorizationIssuer | None = None,
        require_llm: bool = False,
    ) -> None:
        self.llm_client = llm_client or DeepSeekClient()
        self.target_validator = target_validator
        self.authorization_issuer = authorization_issuer or ResponseAuthorizationIssuer()
        self.require_llm = bool(require_llm)
        self._authorizations: dict[str, ResponseAuthorization] = {}

    @property
    def authorization_public_key_b64(self) -> str:
        return self.authorization_issuer.public_key_b64

    @property
    def authorization_public_key_fingerprint(self) -> str:
        return self.authorization_issuer.public_key_fingerprint

    def validate_case_input(self, case: CaseFile) -> None:
        if self.target_validator is not None:
            self.target_validator.validate_case_input(case)

    def authorization_for(self, decision_id: str) -> ResponseAuthorization | None:
        return self._authorizations.get(str(decision_id))

    def audit(
        self,
        case: CaseFile,
        node: StrategyNode,
        resolved_args: dict[str, Any] | PreparedToolCall,
    ) -> AuditDecision:
        prepared = (
            resolved_args
            if isinstance(resolved_args, PreparedToolCall)
            else PreparedToolCall.create(
                node_id=node.node_id,
                tool=node.tool,
                arguments=resolved_args,
            )
        )
        arguments = prepared.arguments
        supported, reason, missing, support = self._hard_rule(case, node.tool, arguments)
        if not supported:
            verdict = AuditVerdict.REJECTED if reason.startswith("reject:") else AuditVerdict.NEED_MORE_EVIDENCE
            clean_reason = reason.removeprefix("reject:").strip()
            decision = AuditDecision(
                node_id=node.node_id,
                verdict=verdict,
                reason=clean_reason,
                missing_evidence=missing,
                supporting_evidence=support,
            )
            case.add_audit_decision(decision)
            return decision
        target_lock: dict[str, Any] | None = None
        if self.target_validator is not None:
            target_lock = self.target_validator.lock_response(case, node, arguments)
        try:
            llm_reason = self._llm_reason(case, node, arguments, reason)
        except LLMError as exc:
            case.record_error(
                "auditor_llm_failed",
                str(exc),
                {"node_id": node.node_id, "tool": node.tool, "strict": True},
            )
            decision = AuditDecision(
                node_id=node.node_id,
                verdict=AuditVerdict.REJECTED,
                reason="Auditor semantic LLM review was unavailable; strict mode failed closed",
                missing_evidence=["successful Auditor semantic LLM review"],
                supporting_evidence=support,
            )
            case.add_audit_decision(decision)
            return decision
        decision = AuditDecision(
            node_id=node.node_id,
            verdict=AuditVerdict.APPROVED,
            reason=llm_reason or reason,
            supporting_evidence=support,
        )
        if target_lock is not None:
            authorization = self.authorization_issuer.issue(
                case_id=case.case_id,
                decision=decision,
                call=prepared,
                target_lock=target_lock,
            )
            self._authorizations[decision.decision_id] = authorization
            decision.authorization_receipt = authorization.public_receipt()
        case.add_audit_decision(decision)
        return decision

    def _llm_reason(self, case: CaseFile, node: StrategyNode, args: dict[str, Any], hard_reason: str) -> str:
        try:
            parsed = self.llm_client.chat_json(
                system_prompt=(
                    "You are Auditor. Explain whether an already hard-rule-approved response action is evidence-supported. "
                    "You cannot override hard safety rules. Return one JSON object only. "
                    'Example JSON output: {"reason":"The exact evidence-linked target is approved."}'
                ),
                user_payload={
                    "task": "Provide a concise audit reason for an approved C2 response node.",
                    "casefile": case.compact_summary(),
                    "node": node.to_dict(),
                    "resolved_args": args,
                    "hard_rule_result": hard_reason,
                    "output_schema": {"reason": "short reason"},
                },
                temperature=0.1,
                max_tokens=600,
            )
            return str(parsed.get("reason") or "").strip()
        except Exception as exc:
            if self.require_llm:
                if isinstance(exc, LLMError):
                    raise
                raise LLMError(f"Auditor semantic review failed: {type(exc).__name__}") from exc
            return hard_reason

    def _hard_rule(self, case: CaseFile, tool: str, args: dict[str, Any]) -> tuple[bool, str, list[str], list[str]]:
        if tool == "remove_file" and self._is_protected_path(str(args.get("file_path") or "")):
            return False, "reject: refusing to remove protected system path", [], []
        if not self._has_network_evidence(case):
            return False, "response requires C2 network evidence before dangerous action", ["network->pid evidence"], []
        if tool == "kill_process":
            attributed = case.attributed_process()
            pid = self._as_pid(args.get("pid"))
            process_name = self._normalize_name(args.get("process_name"))
            expected_path = self._normalize_path(args.get("expected_path"))
            attributed_pid = self._as_pid(attributed.get("pid"))
            attributed_name = self._normalize_name(attributed.get("process_name"))
            attributed_path = self._normalize_path(attributed.get("process_path"))
            if not (pid or process_name):
                return False, "kill_process requires PID or process_name", ["pid or process_name"], []
            # Check if this PID is a sibling C2 process (multi-instance implant).
            sibling_pids = {self._as_pid(s.get("pid")) for s in case.sibling_c2_processes()}
            is_sibling = pid and pid in sibling_pids
            if pid and not is_sibling and (not attributed_pid or pid != attributed_pid):
                return False, "process PID does not exactly match the C2 network owner", ["exact network owner PID"], []
            if process_name and (not attributed_name or process_name != attributed_name) and not is_sibling:
                return False, "process name does not exactly match the C2 network owner", ["exact network owner process name"], []
            if expected_path and (not attributed_path or expected_path != attributed_path):
                return False, "expected_path does not exactly match the attributed C2 process", ["exact process path evidence"], []
            if is_sibling:
                supporting = self._network_process_evidence_ids(case, pid)
                return True, f"kill_process approved for sibling C2 process PID {pid}", [], supporting
            supporting = self._network_process_evidence_ids(case, attributed_pid)
            return True, f"kill_process approved for exact C2 network owner PID {attributed_pid or process_name}", [], supporting

        if tool == "remove_file":
            path = self._normalize_path(args.get("file_path"))
            if not path:
                return False, "reject: remove_file requires file_path", [], []
            evidence_ids = self._exact_path_evidence_ids(case, path)
            if evidence_ids:
                return True, "remove_file approved because the exact file path is linked to C2 evidence", [], evidence_ids
            return False, "file path is not linked to C2 process or persistence evidence", ["process_path or persistence evidence"], []

        if tool == "remove_registry":
            reg_path = self._normalize_path(args.get("reg_path"))
            value_name = self._normalize_name(args.get("value_name"), strip_exe=False)
            if not (reg_path and value_name):
                return False, "reject: no registry persistence target resolved", [], []
            evidence_ids = self._persistence_evidence_ids(
                case, "registry_run_keys", path=reg_path, name=value_name
            )
            if evidence_ids:
                return True, "remove_registry approved for the exact evidence-linked registry value", [], evidence_ids
            return False, "registry value is not linked to attributed payload", ["registry persistence evidence"], []

        if tool == "remove_scheduled_task":
            task_name = self._normalize_name(args.get("task_name"), strip_exe=False)
            task_path = self._normalize_path(args.get("task_path"))
            if not task_name:
                return False, "reject: no scheduled task persistence target resolved", [], []
            evidence_ids = self._persistence_evidence_ids(
                case, "scheduled_tasks", path=task_path, name=task_name, path_optional=True
            )
            if evidence_ids:
                return True, "remove_scheduled_task approved for the exact evidence-linked task", [], evidence_ids
            return False, "scheduled task is not linked to attributed payload", ["scheduled task persistence evidence"], []

        if tool == "remove_service":
            service_name = self._normalize_name(args.get("service_name"), strip_exe=False)
            if not service_name:
                return False, "reject: no service persistence target resolved", [], []
            evidence_ids = self._persistence_evidence_ids(case, "services", name=service_name)
            if evidence_ids:
                return True, "remove_service approved for the exact evidence-linked service", [], evidence_ids
            return False, "service is not linked to attributed payload", ["service persistence evidence"], []

        return False, f"unsupported response tool {tool}", ["supported response tool"], []

    @staticmethod
    def _is_protected_path(path: str) -> bool:
        text = path.lower().replace("/", "\\")
        protected_prefixes = (
            "c:\\windows\\",
            "c:\\program files\\",
            "c:\\program files (x86)\\",
        )
        return any(text.startswith(prefix) for prefix in protected_prefixes)

    @staticmethod
    def _has_network_evidence(case: CaseFile) -> bool:
        remote_ip = str(case.source_alert.get("remote_ip") or "").strip().lower()
        if not remote_ip:
            return False
        remote_port = str(case.source_alert.get("remote_port") or "")
        local_port = str(AuditorAgent._source_local_port(case) or "")
        victim_ip = str(case.source_alert.get("victim_ip") or "").strip().lower()
        for finding in case.findings:
            if finding.finding_type not in {"network_confirmed", "network_connection"}:
                continue
            details = finding.details if isinstance(finding.details, dict) else {}
            candidates = [details]
            candidates.extend(
                item for item in details.get("connections", [])
                if isinstance(item, dict)
            )
            for item in candidates:
                observed_remote = str(item.get("remote_address") or "").strip().lower()
                observed_remote_port = str(item.get("remote_port") or "")
                observed_local_port = str(item.get("local_port") or "")
                if not observed_remote:
                    src_ip = str(item.get("src_ip") or "").strip().lower()
                    dest_ip = str(item.get("dest_ip") or "").strip().lower()
                    if src_ip == remote_ip and (not victim_ip or dest_ip == victim_ip):
                        observed_remote = src_ip
                        observed_remote_port = str(item.get("src_port") or "")
                        observed_local_port = str(item.get("dest_port") or "")
                    elif dest_ip == remote_ip and (not victim_ip or src_ip == victim_ip):
                        observed_remote = dest_ip
                        observed_remote_port = str(item.get("dest_port") or "")
                        observed_local_port = str(item.get("src_port") or "")
                network_mode = str(item.get("network_mode") or "")
                if network_mode == "inbound_listener":
                    listener = item.get("listener") if isinstance(item.get("listener"), dict) else {}
                    listener_lp = str(listener.get("local_port") or item.get("local_port") or "")
                    if listener_lp and remote_port and listener_lp == remote_port:
                        observed_remote = remote_ip
                        observed_remote_port = remote_port
                        observed_local_port = listener_lp
                if observed_remote != remote_ip:
                    continue
                if remote_port and observed_remote_port != remote_port:
                    continue
                if local_port and observed_local_port != local_port:
                    continue
                return True
        return False

    @staticmethod
    def _source_local_port(case: CaseFile) -> int:
        victim_ip = str(case.source_alert.get("victim_ip") or "")
        remote_ip = str(case.source_alert.get("remote_ip") or "")
        for event in reversed(case.source_events):
            try:
                if str(event.get("src_ip") or "") == victim_ip and str(event.get("dest_ip") or "") == remote_ip:
                    return int(event.get("src_port") or 0)
                if str(event.get("dest_ip") or "") == victim_ip and str(event.get("src_ip") or "") == remote_ip:
                    return int(event.get("dest_port") or 0)
            except (TypeError, ValueError):
                continue
        return 0

    @staticmethod
    def _as_pid(value: Any) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _normalize_path(value: Any) -> str:
        return str(value or "").strip().lower().replace("/", "\\").replace("\\\\", "\\")

    @staticmethod
    def _normalize_name(value: Any, *, strip_exe: bool = True) -> str:
        text = str(value or "").strip().lower()
        return text.removesuffix(".exe") if strip_exe else text

    @classmethod
    def _network_process_evidence_ids(cls, case: CaseFile, pid: int) -> list[str]:
        ids: list[str] = []
        for finding in case.findings:
            if finding.finding_type not in {"network_confirmed", "network_connection", "c2_process_attributed"}:
                continue
            details = finding.details if isinstance(finding.details, dict) else {}
            candidates = [details]
            candidates.extend(item for item in details.get("connections", []) if isinstance(item, dict))
            if any(cls._as_pid(item.get("pid") or item.get("owning_process")) == pid for item in candidates):
                ids.append(finding.finding_id)
        return ids

    @classmethod
    def _exact_path_evidence_ids(cls, case: CaseFile, path: str) -> list[str]:
        ids: list[str] = []
        for finding in case.findings:
            if finding.finding_type not in {
                "file_metadata",
                "payload_file_verified",
                "process_detail",
                "process_tree",
                "persistence_linked_to_payload",
            }:
                continue
            details = finding.details if isinstance(finding.details, dict) else {}
            candidates = [finding.value, details.get("path"), details.get("process_path"), details.get("executable_path")]
            root = details.get("root") if isinstance(details.get("root"), dict) else {}
            candidates.extend([root.get("path"), root.get("process_path")])
            if any(cls._normalize_path(item) == path for item in candidates if item):
                ids.append(finding.finding_id)
                continue
            # Check command_line fields for the payload path (interpreter-hosted payloads)
            command_line = cls._normalize_path(details.get("command_line") or "")
            if path and path in command_line:
                ids.append(finding.finding_id)
                continue
            root_cmd = cls._normalize_path(root.get("command_line") or "") if isinstance(root, dict) else ""
            if path and path in root_cmd:
                ids.append(finding.finding_id)
                continue
            chain = details.get("chain") if isinstance(details.get("chain"), list) else []
            for chain_item in chain:
                if isinstance(chain_item, dict):
                    chain_cmd = cls._normalize_path(chain_item.get("command_line") or "")
                    if path and path in chain_cmd:
                        ids.append(finding.finding_id)
                        break
        return ids

    @classmethod
    def _persistence_evidence_ids(
        cls,
        case: CaseFile,
        category: str,
        *,
        name: str,
        path: str = "",
        path_optional: bool = False,
    ) -> list[str]:
        ids: list[str] = []
        for finding in case.findings:
            if finding.finding_type != "persistence_linked_to_payload":
                continue
            details = finding.details if isinstance(finding.details, dict) else {}
            if details.get("category") != category:
                continue
            if cls._normalize_name(details.get("name"), strip_exe=False) != name:
                continue
            evidence_path = cls._normalize_path(details.get("path"))
            if path and evidence_path != path:
                continue
            if not path and not path_optional and category == "registry_run_keys":
                continue
            ids.append(finding.finding_id)
        return ids
