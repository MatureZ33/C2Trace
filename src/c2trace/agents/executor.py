from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from c2trace.execution import (
    ExecutionEnvelope,
    PreparedToolCall,
    ResponseAuthorization,
    TargetObservation,
    ToolClient,
)
from c2trace.models import (
    ActionResult,
    CaseFile,
    EvidenceLink,
    Finding,
    INTERPRETER_HOSTS,
    StrategyNode,
    extract_payload_from_command_line,
)
from c2trace.tools import READ_ONLY_TOOLS


class ExecutorAgent:
    role_name = "executor"

    def __init__(
        self,
        *,
        tool_client: ToolClient | Any | None = None,
        tool_runner: Any | None = None,
    ) -> None:
        if tool_client is not None and tool_runner is not None:
            raise ValueError("ExecutorAgent accepts tool_client or legacy tool_runner, not both")
        selected = tool_client if tool_client is not None else tool_runner
        if selected is None:
            raise ValueError("ExecutorAgent requires an explicit ToolClient")
        self.tool_client = selected
        # Compatibility for old tests/bench code.  Production run_case never
        # reads this alias and always injects StdioMcpToolClient.
        self.tool_runner = selected

    def list_tools(self) -> list[dict[str, Any]]:
        method = getattr(self.tool_client, "list_tools", None)
        if not callable(method):
            return []
        return list(method())

    @property
    def tool_catalog_hash(self) -> str:
        return str(getattr(self.tool_client, "catalog_hash", "") or "")

    @property
    def response_enabled(self) -> bool:
        """Whether the production transport accepts authorized response calls.

        Legacy injected runners have no transport mode and retain their own
        dry-run behavior.  The stdio MCP client always exposes this flag.
        """

        flag = getattr(self.tool_client, "response_enabled", None)
        return True if flag is None else bool(flag)

    def prepare(
        self,
        case: CaseFile,
        node: StrategyNode,
        resolved_args: dict[str, Any] | None = None,
    ) -> PreparedToolCall:
        arguments = dict(node.arguments if resolved_args is None else resolved_args)
        bindings = {
            key: str(value)
            for key, value in node.arguments.items()
            if isinstance(value, str) and value.strip().startswith("{{")
        }
        prepared = PreparedToolCall.create(
            node_id=node.node_id,
            tool=node.tool,
            arguments=arguments,
            evidence_bindings=bindings,
        )
        case.add_timeline(
            "tool_call_prepared",
            f"Executor prepared {node.tool} with evidence-bound arguments",
            self.role_name,
            refs=[node.node_id, prepared.call_id],
            details={
                "call_id": prepared.call_id,
                "arguments_sha256": prepared.arguments_sha256,
                "evidence_bindings": prepared.evidence_bindings,
            },
        )
        return prepared

    def observe_target(
        self,
        case: CaseFile,
        node: StrategyNode,
        tool: str,
        arguments: dict[str, Any],
    ) -> Any:
        """Collect one Auditor-requested target observation via read-only MCP."""

        if tool not in READ_ONLY_TOOLS:
            raise PermissionError(f"target observation cannot call response tool {tool}")
        raw = self.tool_client.run(tool, arguments)
        receipt = dict(getattr(raw, "receipt", {}) or {})
        observation = TargetObservation(
            tool=tool,
            arguments=dict(arguments),
            data=dict(raw.data) if raw.success and isinstance(raw.data, dict) else {},
            observed_at=datetime.now(timezone.utc).isoformat(),
            request_id=str(receipt.get("request_id") or ""),
        )
        case.add_target_observation(observation.to_dict())
        case.add_timeline(
            "target_observation_bound",
            f"Executor bound {tool} observation to response node {node.node_id}",
            self.role_name,
            refs=[node.node_id, observation.request_id],
            details={
                "tool": tool,
                "success": bool(raw.success),
                "error_type": str(receipt.get("error_type") or getattr(raw, "error_type", "")),
            },
        )
        return raw

    def execute(
        self,
        case: CaseFile,
        node: StrategyNode,
        resolved_args: dict[str, Any] | PreparedToolCall,
        *,
        authorization: ResponseAuthorization | None = None,
    ) -> ActionResult:
        prepared = (
            resolved_args
            if isinstance(resolved_args, PreparedToolCall)
            else self.prepare(case, node, resolved_args)
        )
        envelope = self.execute_prepared(prepared, authorization=authorization)
        raw = envelope.tool_result
        result = ActionResult(
            node_id=node.node_id,
            tool=node.tool,
            success=raw.success,
            data=raw.data,
            error=raw.error,
            elapsed_ms=raw.elapsed_ms,
            arguments=dict(prepared.arguments),
            audit_decision_id=node.audit_decision_id,
            transport_receipt=dict(getattr(raw, "receipt", {}) or {}),
        )
        case.add_result(result)
        if result.success and node.tool == "check_process":
            # Network attribution supplies the PID/path first; the read-only
            # process lookup supplies creation time. Correlate those facts
            # before adding the normal process_detail finding.
            self._enrich_c2_process_attributions(case, result.data)
        node.result_id = result.result_id
        for finding in self._derive_findings(case, node, result, prepared.arguments):
            added = case.add_finding(finding)
            case.add_evidence_link(EvidenceLink(
                source_id=result.result_id,
                target_id=added.finding_id,
                relation="derived_from_tool_result",
                confidence=added.confidence,
                details={"tool": node.tool, "node_id": node.node_id},
            ))
            node.evidence_refs.append(added.finding_id)
        return result

    @classmethod
    def _enrich_c2_process_attributions(
        cls, case: CaseFile, data: Any
    ) -> None:
        """Attach verified process identity fields to prior C2 attributions."""
        processes = cls._as_list(data.get("processes")) if isinstance(data, dict) else []
        by_pid: dict[int, dict[str, Any]] = {}
        for process in processes:
            try:
                pid = int(process.get("pid") or process.get("process_id") or 0)
            except (TypeError, ValueError):
                pid = 0
            if pid > 0:
                by_pid[pid] = process
        if not by_pid:
            return
        for finding in case.findings:
            if finding.finding_type != "c2_process_attributed":
                continue
            details = finding.details if isinstance(finding.details, dict) else {}
            try:
                pid = int(details.get("pid") or details.get("process_id") or 0)
            except (TypeError, ValueError):
                pid = 0
            process = by_pid.get(pid)
            if process is None:
                continue
            for key in ("creation_time", "creation_time_utc", "creation_date", "start_time"):
                value = process.get(key)
                if value and not details.get("creation_time"):
                    details["creation_time"] = value
                    break
            if not details.get("process_path") and not details.get("path"):
                path = process.get("process_path") or process.get("path") or process.get("executable_path")
                if path:
                    details["process_path"] = path
            if not details.get("process_name") and not details.get("name"):
                name = process.get("process_name") or process.get("name")
                if name:
                    details["process_name"] = name

    def execute_prepared(
        self,
        prepared: PreparedToolCall,
        *,
        authorization: ResponseAuthorization | None = None,
    ) -> ExecutionEnvelope:
        try:
            raw = self.tool_client.run(
                prepared.tool,
                prepared.arguments,
                authorization=authorization,
            )
        except TypeError:
            # Compatibility only for injected legacy/fake runners.  The MCP
            # production client always implements the authorization keyword.
            raw = self.tool_client.run(prepared.tool, prepared.arguments)
        return ExecutionEnvelope(
            prepared_call=prepared,
            tool_result=raw,
            authorization_receipt=(
                authorization.public_receipt() if authorization is not None else {}
            ),
        )

    def preview_response(
        self,
        case: CaseFile,
        node: StrategyNode,
        prepared: PreparedToolCall,
    ) -> ActionResult:
        """Record an audited dry-run without sending a response tool to MCP."""

        result = ActionResult(
            node_id=node.node_id,
            tool=node.tool,
            success=True,
            data={
                "dry_run": True,
                "tool": node.tool,
                "params": dict(prepared.arguments),
                "transport": "not_sent",
                "reason": "mcp_server_read_only",
            },
            arguments=dict(prepared.arguments),
            audit_decision_id=node.audit_decision_id,
        )
        case.add_result(result)
        node.result_id = result.result_id
        for finding in self._derive_findings(case, node, result, prepared.arguments):
            added = case.add_finding(finding)
            case.add_evidence_link(EvidenceLink(
                source_id=result.result_id,
                target_id=added.finding_id,
                relation="derived_from_response_preview",
                confidence=added.confidence,
                details={"tool": node.tool, "node_id": node.node_id},
            ))
            node.evidence_refs.append(added.finding_id)
        case.add_timeline(
            "response_preview_recorded",
            f"Executor did not send {node.tool}; MCP server is read-only",
            self.role_name,
            refs=[node.node_id, prepared.call_id, result.result_id],
            details={"arguments_sha256": prepared.arguments_sha256},
        )
        return result

    def close(self) -> None:
        method = getattr(self.tool_client, "close", None)
        if callable(method):
            method()

    def _derive_findings(
        self,
        case: CaseFile,
        node: StrategyNode,
        result: ActionResult,
        args: dict[str, Any],
    ) -> list[Finding]:
        if not result.success:
            return []
        data = result.data if isinstance(result.data, dict) else {}
        findings: list[Finding] = []
        if node.tool == "check_network":
            requested_ip = str(args.get("remote_ip") or args.get("target_ip") or "").strip().lower()
            requested_port = str(args.get("remote_port") or args.get("target_port") or "")
            requested_local_port = str(args.get("local_port") or "")
            network_mode = str(args.get("network_mode") or "outbound_active_flow").strip().lower()
            if network_mode == "inbound_listener":
                source_event = self._matching_inbound_source_event(
                    case,
                    remote_ip=requested_ip,
                    local_port=requested_local_port,
                )
                connections = []
                for conn in self._as_list(data.get("connections")):
                    state = str(conn.get("state") or "").strip().lower()
                    if (
                        not source_event
                        or not requested_ip
                        or state not in {"listen", "listening"}
                        or not int(conn.get("pid") or conn.get("owning_process") or 0)
                        or (
                            requested_local_port
                            and str(conn.get("local_port") or "") != requested_local_port
                        )
                    ):
                        continue
                    connections.append({
                        "network_mode": "inbound_listener",
                        "protocol": str(source_event.get("proto") or "tcp").lower(),
                        "src_ip": source_event.get("src_ip"),
                        "src_port": source_event.get("src_port"),
                        "dest_ip": source_event.get("dest_ip"),
                        "dest_port": source_event.get("dest_port"),
                        "pid": conn.get("pid") or conn.get("owning_process"),
                        "process_name": conn.get("process_name") or "",
                        "process_path": conn.get("process_path") or "",
                        "state": conn.get("state") or "",
                        "listener": dict(conn),
                    })
            else:
                connections = [
                    conn
                    for conn in self._as_list(data.get("connections"))
                    if requested_ip
                    and str(conn.get("remote_address") or "").strip().lower() == requested_ip
                    and (not requested_port or str(conn.get("remote_port") or "") == requested_port)
                    and (not requested_local_port or str(conn.get("local_port") or "") == requested_local_port)
                ]
            if not connections and network_mode != "inbound_listener" and (requested_port or requested_local_port):
                fallback_port = requested_local_port or requested_port
                fallback_result = self.tool_client.run("check_network", {
                    "network_mode": "inbound_listener",
                    "local_port": fallback_port,
                    "local_ip": str(case.source_alert.get("victim_ip") or ""),
                })
                fallback_data = fallback_result.data if isinstance(fallback_result.data, dict) else {}
                fallback_source_event = self._matching_inbound_source_event(
                    case,
                    remote_ip=requested_ip,
                    local_port=str(fallback_port),
                )
                for conn in self._as_list(fallback_data.get("connections")):
                    state = str(conn.get("state") or "").strip().lower()
                    if state not in {"listen", "listening"}:
                        continue
                    if not int(conn.get("pid") or conn.get("owning_process") or 0):
                        continue
                    connections.append({
                        "network_mode": "inbound_listener",
                        "protocol": str(fallback_source_event.get("proto") or "tcp").lower(),
                        "src_ip": fallback_source_event.get("src_ip"),
                        "src_port": fallback_source_event.get("src_port"),
                        "dest_ip": fallback_source_event.get("dest_ip"),
                        "dest_port": fallback_source_event.get("dest_port"),
                        "pid": conn.get("pid") or conn.get("owning_process"),
                        "process_name": conn.get("process_name") or "",
                        "process_path": conn.get("process_path") or "",
                        "state": conn.get("state") or "",
                        "listener": dict(conn),
                    })
            if connections:
                findings.append(Finding(
                    finding_type="network_confirmed",
                    value=str(args.get("remote_ip") or args.get("target_ip") or ""),
                    evidence=f"check_network returned {len(connections)} matching connection(s)",
                    source=self.role_name,
                    confidence=0.85,
                    details={"connections": connections},
                ))
                for conn in connections[:5]:
                    if network_mode == "inbound_listener":
                        connection_value = f"{conn.get('src_ip')}:{conn.get('src_port')} -> {conn.get('dest_ip')}:{conn.get('dest_port')}"
                    else:
                        connection_value = f"{conn.get('remote_address')}:{conn.get('remote_port')}"
                    findings.append(Finding(
                        finding_type="network_connection",
                        value=connection_value,
                        evidence="Network connection links C2 seed to local PID/process context",
                        source=self.role_name,
                        confidence=0.85,
                        details=conn,
                    ))
                    if conn.get("pid"):
                        findings.append(Finding(
                            finding_type="c2_process_attributed",
                            value=str(conn.get("process_name") or conn.get("pid")),
                            evidence="Owning PID/process observed on C2 network connection",
                            source=self.role_name,
                            confidence=0.8,
                            details=conn,
                        ))
        elif node.tool == "check_process":
            for proc in self._as_list(data.get("processes")):
                findings.extend(self._process_findings(proc))
                proc_name = str(proc.get("name") or proc.get("process_name") or "").lower()
                if proc_name in INTERPRETER_HOSTS:
                    command_line = str(proc.get("command_line") or "")
                    payload_path = extract_payload_from_command_line(
                        command_line, proc.get("name", "")
                    )
                    if payload_path:
                        findings.append(Finding(
                            finding_type="payload_file_verified",
                            value=payload_path,
                            evidence="Payload file path extracted from interpreter host process command line",
                            source=self.role_name,
                            confidence=0.85,
                            details={
                                "path": payload_path,
                                "command_line": command_line,
                                "host_process": proc.get("name", ""),
                                "pid": proc.get("pid") or proc.get("process_id"),
                            },
                        ))
        elif node.tool == "check_process_tree":
            for tree in self._as_list(data.get("trees")):
                chain = self._as_list(tree.get("chain"))
                root = tree.get("root") if isinstance(tree.get("root"), dict) else (chain[0] if chain else {})
                findings.append(Finding(
                    finding_type="process_tree",
                    value=str(root.get("name") or root.get("pid") or ""),
                    evidence=f"Collected parent process chain with {len(chain)} process node(s)",
                    source=self.role_name,
                    confidence=0.75,
                    details=tree,
                ))
                if isinstance(root, dict):
                    findings.extend(self._process_findings(root))
        elif node.tool == "check_file_metadata":
            file_info = data.get("file", {}) if isinstance(data.get("file"), dict) else {}
            path = str(file_info.get("path") or args.get("file_path") or "")
            exists = bool(file_info.get("exists"))
            findings.append(Finding(
                finding_type="file_metadata",
                value=path,
                evidence=f"File metadata collected; exists={exists}",
                source=self.role_name,
                confidence=0.8 if exists else 0.45,
                details=file_info,
            ))
            if exists:
                findings.append(Finding(
                    finding_type="payload_file_verified",
                    value=path,
                    evidence="Payload candidate file exists and metadata was collected",
                    source=self.role_name,
                    confidence=0.85,
                    details=file_info,
                ))
        elif node.tool == "check_recent_files":
            for file_info in self._as_list(data.get("files")):
                path = str(file_info.get("path") or "")
                if not path:
                    continue
                findings.append(Finding(
                    finding_type="file_metadata",
                    value=path,
                    evidence="File metadata collected by bounded recent-file discovery",
                    source=self.role_name,
                    confidence=0.8 if file_info.get("sha256") else 0.7,
                    details=file_info,
                ))
        elif node.tool == "check_persistence_all":
            payload_indicators = self._payload_indicators(case)
            count = 0
            for category in ("registry_run_keys", "scheduled_tasks", "services"):
                for item in self._as_list(data.get(category)):
                    count += 1
                    item_details = {"category": category, **item}
                    findings.append(Finding(
                        finding_type="persistence_candidate",
                        value=str(item.get("name") or item.get("path") or category),
                        evidence=f"Potential persistence item found in {category}",
                        source=self.role_name,
                        confidence=0.55,
                        details=item_details,
                    ))
                    if self._item_mentions_any_indicator(item, payload_indicators):
                        findings.append(Finding(
                            finding_type="persistence_linked_to_payload",
                            value=str(item.get("name") or item.get("path") or category),
                            evidence="Persistence item references the process or payload attributed to the C2 seed",
                            source=self.role_name,
                            confidence=0.88,
                            details=item_details,
                        ))
            findings.append(Finding(
                finding_type="persistence_summary",
                value=str(count),
                evidence=f"Persistence scan found {count} candidate item(s)",
                source=self.role_name,
                confidence=0.6,
                details=data,
            ))
        elif node.tool == "check_powershell_history":
            for entry in self._as_list(data.get("history"))[:8]:
                findings.append(Finding(
                    finding_type="powershell_history_hit",
                    value=str(entry.get("command") or ""),
                    evidence="PowerShell history contains command related to investigated artifact",
                    source=self.role_name,
                    confidence=0.65,
                    details=entry,
                ))
        elif node.tool == "check_dns_cache":
            entries = self._as_list(data.get("entries"))
            if entries:
                findings.append(Finding(
                    finding_type="dns_cache_confirmed",
                    value=str(args.get("domain_filter") or ""),
                    evidence=f"check_dns_cache returned {len(entries)} matching entrie(s)",
                    source=self.role_name,
                    confidence=0.75,
                    details={"entries": entries},
                ))
        elif node.tool == "verify_cleanup":
            network = data.get("network", {}) if isinstance(data.get("network"), dict) else {}
            connections = self._as_list(network.get("connections"))
            if "network_checked" in data:
                network_checked = data.get("network_checked") is True
            else:
                network_checked = (
                    bool(args.get("remote_ip"))
                    and "network" in data
                    and isinstance(network.get("connections"), list)
                )
            if "network_clean" in data:
                network_clean = data.get("network_clean") is True
            else:
                network_clean = network_checked and not connections
            verification_details = {
                "verification_result_id": result.result_id,
                "arguments": args,
                "result": data,
            }
            findings.append(Finding(
                finding_type="cleanup_verification",
                value=str(args),
                evidence="Cleanup verification executed",
                source=self.role_name,
                confidence=0.7,
                details=verification_details,
            ))
            if network_checked and network_clean:
                findings.append(Finding(
                    finding_type="cleanup_network_verified",
                    value=str(args.get("remote_ip") or ""),
                    evidence="No matching C2 network connection remained",
                    source=self.role_name,
                    confidence=0.85,
                    details={"verification_result_id": result.result_id, "network": network},
                ))
            for check in self._verified_response_actions(data, args):
                response_result_id = str(check.get("response_result_id") or "")
                tool = str(check.get("tool") or "")
                target_args = check.get("arguments") if isinstance(check.get("arguments"), dict) else {}
                detail = {
                    "response_result_id": response_result_id,
                    "verification_result_id": result.result_id,
                    "tool": tool,
                    "arguments": target_args,
                }
                findings.append(Finding(
                    finding_type="cleanup_action_verified",
                    value=response_result_id,
                    evidence=f"Post-response verification confirmed cleanup for {tool}",
                    source=self.role_name,
                    confidence=0.9,
                    details=detail,
                ))
                dimension = {
                    "kill_process": "cleanup_process_verified",
                    "remove_file": "cleanup_file_verified",
                    "remove_registry": "cleanup_persistence_verified",
                    "remove_scheduled_task": "cleanup_persistence_verified",
                    "remove_service": "cleanup_persistence_verified",
                }.get(tool)
                if dimension:
                    findings.append(Finding(
                        finding_type=dimension,
                        value=response_result_id,
                        evidence=f"Exact {tool} target was absent during cleanup verification",
                        source=self.role_name,
                        confidence=0.85,
                        details=detail,
                    ))
        elif node.tool.startswith(("kill_", "remove_")):
            dry_run = bool(data.get("dry_run"))
            findings.append(Finding(
                finding_type="response_action_dry_run" if dry_run else "response_action_executed",
                value=node.tool,
                evidence=f"{node.tool} {'dry-run completed' if dry_run else 'executed'}",
                source=self.role_name,
                confidence=0.75,
                details={"node": node.to_dict(), "args": args, "result": data},
            ))
        return findings

    @staticmethod
    def _matching_inbound_source_event(
        case: CaseFile,
        *,
        remote_ip: str,
        local_port: str,
    ) -> dict[str, Any]:
        victim_ip = str(case.source_alert.get("victim_ip") or "").strip().lower()
        for event in reversed(case.source_events):
            if (
                str(event.get("src_ip") or "").strip().lower() == remote_ip
                and str(event.get("dest_ip") or "").strip().lower() == victim_ip
                and (not local_port or str(event.get("dest_port") or "") == local_port)
            ):
                return dict(event)
        return {"proto": "tcp", "source": "alert_fallback", "src_ip": remote_ip, "dest_ip": victim_ip, "dest_port": local_port}

    def _process_findings(self, proc: dict[str, Any]) -> list[Finding]:
        name = str(proc.get("name") or proc.get("process_name") or proc.get("pid") or "")
        path = str(proc.get("path") or proc.get("process_path") or "")
        findings = [
            Finding(
                finding_type="process_detail",
                value=name,
                evidence=f"Process detail collected for {name}",
                source=self.role_name,
                confidence=0.75,
                details=proc,
            )
        ]
        if path and self._is_suspicious_path(path):
            findings.append(Finding(
                finding_type="suspicious_process_path",
                value=path,
                evidence="Process executable path is user-writable or staging-like",
                source=self.role_name,
                confidence=0.8,
                details={"path": path, "process_name": name, **proc},
            ))
        return findings

    @staticmethod
    def _as_list(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, list):
            return [v for v in value if isinstance(v, dict)]
        if isinstance(value, dict):
            return [value]
        return []

    @staticmethod
    def _is_suspicious_path(path: str) -> bool:
        text = path.lower()
        return any(hint in text for hint in ("\\users\\public\\", "\\appdata\\", "\\temp\\", "\\programdata\\"))

    @staticmethod
    def _payload_indicators(case: CaseFile) -> list[str]:
        indicators = []
        latest = case.latest_process_path()
        if latest:
            indicators.append(latest.lower().replace("\\\\", "\\"))
        attributed = case.attributed_process()
        payload_path = str(attributed.get("payload_path") or "")
        if payload_path:
            indicators.append(payload_path.lower().replace("\\\\", "\\"))
        for finding in case.findings:
            if finding.finding_type == "suspicious_process_path":
                value = str(finding.value or "")
                if value and "\\" in value:
                    indicators.append(value.lower().replace("\\\\", "\\"))
            if finding.finding_type in {"network_confirmed", "network_connection", "c2_process_attributed", "process_detail", "process_tree"}:
                indicators.extend(ExecutorAgent._process_name_indicators(finding.details))
        return list(dict.fromkeys(item for item in indicators if item))

    @staticmethod
    def _process_name_indicators(details: dict[str, Any]) -> list[str]:
        if not isinstance(details, dict):
            return []
        names: list[str] = []
        candidates: list[Any] = [
            details.get("process_name"),
            details.get("name"),
        ]
        root = details.get("root") if isinstance(details.get("root"), dict) else {}
        candidates.extend([root.get("process_name"), root.get("name")])
        connections = details.get("connections", []) if isinstance(details.get("connections"), list) else []
        candidates.extend(conn.get("process_name") for conn in connections if isinstance(conn, dict))
        chain = details.get("chain", []) if isinstance(details.get("chain"), list) else []
        if chain and isinstance(chain[0], dict):
            candidates.extend([chain[0].get("process_name"), chain[0].get("name")])
        for candidate in candidates:
            name = str(candidate or "").strip().lower()
            if not name:
                continue
            stem = name.removesuffix(".exe")
            if ExecutorAgent._is_specific_process_name(stem):
                names.extend([stem, f"{stem}.exe"])
        return names

    @staticmethod
    def _is_specific_process_name(name: str) -> bool:
        common = {
            "cmd",
            "conhost",
            "explorer",
            "lsass",
            "msedge",
            "onedrive",
            "powershell",
            "pwsh",
            "rundll32",
            "runtimebroker",
            "searchindexer",
            "securityhealthsystray",
            "services",
            "spoolsv",
            "svchost",
            "taskhostw",
            "vmtoolsd",
            "wmiprvse",
        }
        return len(name) >= 4 and name not in common

    @staticmethod
    def _item_mentions_any_indicator(item: dict[str, Any], indicators: list[str]) -> bool:
        blob = json.dumps(item, ensure_ascii=False).lower().replace("\\\\", "\\")
        for indicator in indicators:
            if not indicator:
                continue
            if "\\" in indicator and indicator in blob:
                return True
            if re.search(rf"(?<![a-z0-9_.-]){re.escape(indicator)}(?![a-z0-9_.-])", blob):
                return True
        return False

    @classmethod
    def _verified_response_actions(cls, data: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
        has_explicit_checks = isinstance(data.get("action_checks"), list)
        explicit = cls._as_list(data.get("action_checks"))
        explicit_by_id = {
            str(item.get("response_result_id") or ""): item
            for item in explicit
            if item.get("response_result_id")
        }
        actions = cls._as_list(args.get("response_actions"))
        verified: list[dict[str, Any]] = []
        for action in actions:
            response_result_id = str(action.get("result_id") or action.get("response_result_id") or "")
            tool = str(action.get("tool") or "")
            arguments = action.get("arguments") if isinstance(action.get("arguments"), dict) else {}
            explicit_check = explicit_by_id.get(response_result_id)
            if explicit_check is not None:
                is_clean = explicit_check.get("checked") is True and explicit_check.get("clean") is True
            elif has_explicit_checks:
                is_clean = False
            elif tool == "kill_process":
                is_clean = "processes" in data and isinstance(data.get("processes"), list) and not data["processes"]
            elif tool == "remove_file":
                is_clean = data.get("file_exists") is False
            elif tool in {"remove_registry", "remove_scheduled_task", "remove_service"}:
                persistence = data.get("persistence")
                is_clean = isinstance(persistence, dict) and not cls._persistence_target_present(
                    persistence, tool, arguments
                )
            else:
                is_clean = False
            if is_clean and response_result_id:
                verified.append({
                    "response_result_id": response_result_id,
                    "tool": tool,
                    "arguments": dict(arguments),
                })
        return verified

    @staticmethod
    def _normalize_text(value: Any) -> str:
        return str(value or "").strip().lower()

    @staticmethod
    def _normalize_path(value: Any) -> str:
        return str(value or "").strip().lower().replace("/", "\\").replace("\\\\", "\\")

    @classmethod
    def _persistence_target_present(cls, data: dict[str, Any], tool: str, arguments: dict[str, Any]) -> bool:
        if tool == "remove_registry":
            category = "registry_run_keys"
            name = cls._normalize_text(arguments.get("value_name"))
            path = cls._normalize_path(arguments.get("reg_path"))
        elif tool == "remove_scheduled_task":
            category = "scheduled_tasks"
            name = cls._normalize_text(arguments.get("task_name"))
            path = cls._normalize_path(arguments.get("task_path"))
        else:
            category = "services"
            name = cls._normalize_text(arguments.get("service_name"))
            path = ""
        for item in cls._as_list(data.get(category)):
            if cls._normalize_text(item.get("name")) != name:
                continue
            if path and cls._normalize_path(item.get("path")) != path:
                continue
            return True
        return False
