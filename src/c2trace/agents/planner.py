from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any
from uuid import uuid4

from c2trace.kb import C2KnowledgePack
from c2trace.llm import DeepSeekClient, LLMError
from c2trace.models import CaseFile, NodeStatus, NodeType, StrategyNode, StrategyTree, ValidationError
from c2trace.tools import READ_ONLY_TOOLS, RESPONSE_TOOLS
from c2trace.execution import canonical_sha256, tool_catalog_hash


class PlannerError(RuntimeError):
    pass


PROJECT_ROOT = Path(__file__).resolve().parents[3]
PROMPT_ROOT = PROJECT_ROOT / "prompts"
# ``check_recent_files`` is injected by the orchestrator as a deterministic
# baseline policy.  It is intentionally not left to LLM choice, which avoids
# duplicate file observations and keeps dry-run/execute scoring reproducible.
PLANNER_READ_ONLY_TOOLS = READ_ONLY_TOOLS - {"check_recent_files"}
DEPENDENCY_FIELDS = frozenset({"requires", "on_success", "on_failure"})
PLANNER_TEMPERATURE = 0.0


def _load_prompt(name: str, fallback: str) -> str:
    path = PROMPT_ROOT / name
    if path.exists():
        return path.read_text(encoding="utf-8")
    return fallback


class PlannerAgent:
    role_name = "planner"

    def __init__(
        self,
        *,
        llm_client: Any | None = None,
        knowledge_pack: C2KnowledgePack,
        experience_context: list[dict[str, Any]] | None = None,
        allowed_response_tools: set[str] | list[str] | tuple[str, ...] | None = None,
        strategy_tree_template: dict[str, Any] | None = None,
        tool_catalog: list[dict[str, Any]] | None = None,
    ) -> None:
        self.llm_client = llm_client or DeepSeekClient()
        self.knowledge_pack = knowledge_pack
        self.experience_context = experience_context or []
        self.tool_catalog = [dict(item) for item in (tool_catalog or [])]
        catalog_names = {
            str(item.get("name") or "")
            for item in self.tool_catalog
            if str(item.get("name") or "")
        }
        self.available_tools = frozenset(catalog_names or (READ_ONLY_TOOLS | RESPONSE_TOOLS))
        missing_required = (READ_ONLY_TOOLS | RESPONSE_TOOLS) - self.available_tools
        if self.tool_catalog and missing_required:
            raise ValueError(f"MCP tool catalog is missing required tools: {sorted(missing_required)}")
        self.tool_catalog_sha256 = tool_catalog_hash(self.tool_catalog) if self.tool_catalog else ""
        requested_tools = set(RESPONSE_TOOLS if allowed_response_tools is None else allowed_response_tools)
        unknown_tools = requested_tools - RESPONSE_TOOLS
        if unknown_tools:
            raise ValueError(
                f"unsupported response tool policy: {sorted(unknown_tools)}"
            )
        if not requested_tools:
            raise ValueError("response tool policy must allow at least one response tool")
        unavailable = requested_tools - self.available_tools
        if unavailable:
            raise ValueError(f"response tool policy is unavailable from MCP: {sorted(unavailable)}")
        self.allowed_response_tools = frozenset(requested_tools)
        self.strategy_tree_template = (
            deepcopy(strategy_tree_template)
            if isinstance(strategy_tree_template, dict)
            else None
        )

    def create_strategy_tree(self, case: CaseFile) -> StrategyTree:
        system_prompt = _load_prompt(
            "planner_initial_strategy.md",
            (
                "You are Planner, an LLM-driven C2 incident-response planning agent. "
                "Generate only safe structured StrategyTree JSON. Never execute tools."
            ),
        )
        payload = {
            "task": "Generate a machine-executable StrategyTree for C2 endpoint traceback and response.",
            "minimal_c2_seed_alert": case.source_alert,
            "casefile_summary": case.compact_summary(),
            "c2_kb": self.knowledge_pack.to_prompt_context(),
            "sanitized_experience_history": self.experience_context,
            "mcp_tool_catalog": [
                {
                    "name": item.get("name"),
                    "description": item.get("description", ""),
                    "input_schema": item.get("inputSchema", {}),
                    "c2trace_meta": (
                        item.get("_meta", {}).get("c2trace", {})
                        if isinstance(item.get("_meta"), dict)
                        else {}
                    ),
                }
                for item in self.tool_catalog
                if str(item.get("name") or "") in self.available_tools
            ],
            "allowed_tools": sorted(
                (PLANNER_READ_ONLY_TOOLS | set(self.allowed_response_tools))
                & set(self.available_tools)
            ),
            "allowed_response_tools": sorted(self.allowed_response_tools),
            "node_types": ["investigate", "decision", "response", "verify"],
            "constraints": [
                "Return JSON only.",
                "The JSON root must contain tree_id, root_objective, and nodes.",
                "Do not include PID, process path, payload path, registry value, Sandcat, Caldera operation result, or any host-side answer unless it is already in the alert.",
                "Use alert fields for remote_ip, remote_port, protocol, victim_ip.",
                "Sanitized experience history is reusable pattern memory only; do not treat it as current-case evidence.",
                "Never copy concrete PID, IP, process path, payload path, registry value, Run Key, Sandcat, or Caldera answers from experience history.",
                "Use placeholders for unknown evidence, such as {{evidence.pid}}, {{evidence.process_path}}, {{evidence.persistence.reg_path}}, {{evidence.persistence.value_name}}.",
                "investigate and verify nodes use allowed read-only tools.",
                "response nodes use allowed response tools and must depend on an evidence_sufficient_for_response decision node.",
                f"Response nodes may use only this run policy allowlist: {sorted(self.allowed_response_tools)}.",
                self._persistence_policy_constraint(),
                "Include at least one investigate node, one decision node, one response node, and one verify node.",
                "Use on_success/on_failure to express branches.",
            ],
            "required_output_shape": {
                "tree_id": "tree-id",
                "root_objective": "trace and respond to suspected C2 seed",
                "nodes": [
                    {
                        "node_id": "n1",
                        "type": "investigate",
                        "goal": "confirm active network connection",
                        "tool": "check_network",
                        "arguments": {"remote_ip": "{{alert.remote_ip}}", "remote_port": "{{alert.remote_port}}"},
                        "requires": [],
                        "on_success": ["n2"],
                        "on_failure": ["n3"]
                    }
                ]
            },
        }
        dependency_repair: dict[str, Any] | None = None
        initial_call: dict[str, Any] = {}
        try:
            planning_mode = "strategy_tree_replay" if self.strategy_tree_template else "llm"
            if self.strategy_tree_template:
                parsed = deepcopy(self.strategy_tree_template)
            else:
                parsed = self.llm_client.chat_json(
                    system_prompt=system_prompt,
                    user_payload=payload,
                    temperature=PLANNER_TEMPERATURE,
                    max_tokens=3200,
                )
                initial_call = self._latest_usage_record()
            parsed = self._ensure_evidence_gate(parsed)
            try:
                tree = StrategyTree.from_dict(parsed)
            except ValidationError as exc:
                if self.strategy_tree_template or not self._is_dependency_error(exc):
                    raise
                parsed, dependency_repair = self._repair_dependencies(
                    original=parsed,
                    validation_error=str(exc),
                    initial_call=initial_call,
                )
                parsed = self._ensure_evidence_gate(parsed)
                tree = StrategyTree.from_dict(parsed)
            unavailable_nodes = [
                node.node_id
                for node in tree.nodes
                if node.tool and node.tool not in self.available_tools
            ]
            if unavailable_nodes:
                raise ValidationError(
                    f"StrategyTree selects tools absent from MCP catalog: {unavailable_nodes}"
                )
            self._enforce_read_only_planning_policy(
                tree,
                replay=self.strategy_tree_template is not None,
            )
            if self.strategy_tree_template:
                tree.created_by = "planner_strategy_tree_replay"
            pruned_response_nodes = self._apply_response_tool_policy(
                tree, set(self.allowed_response_tools)
            )
            self._ensure_persistence_cleanup_coverage(
                tree, set(self.allowed_response_tools)
            )
            self._normalize_initial_status(tree)
            if planning_mode == "llm":
                tree.provenance = {
                    "source": "llm",
                    "llm_call_id": str(initial_call.get("call_id") or ""),
                    "llm_response_sha256": str(initial_call.get("parsed_response_sha256") or ""),
                    "strategy_tree_sha256": canonical_sha256({
                        "tree_id": tree.tree_id,
                        "root_objective": tree.root_objective,
                        "created_by": tree.created_by,
                        "nodes": [node.to_dict() for node in tree.nodes],
                    }),
                    "tool_catalog_sha256": self.tool_catalog_sha256,
                }
                if dependency_repair is not None:
                    tree.provenance["dependency_repair"] = dependency_repair
            else:
                tree.provenance = {
                    **dict(tree.provenance),
                    "source": "strategy_tree_replay",
                    "tool_catalog_sha256": self.tool_catalog_sha256,
                }
        except (LLMError, ValidationError, Exception) as exc:
            case.final_status = "planner_failed"
            case.record_error("planner_failed", str(exc), {"stage": "initial_strategy_tree"})
            raise PlannerError(str(exc)) from exc
        case.strategy_tree = tree
        case.add_timeline(
            "strategy_tree_created",
            f"Planner generated StrategyTree {tree.tree_id}",
            self.role_name,
            [tree.tree_id],
            details={
                "allowed_response_tools": sorted(self.allowed_response_tools),
                "pruned_response_nodes": pruned_response_nodes,
                "planning_mode": planning_mode,
                "tool_catalog_sha256": self.tool_catalog_sha256,
                "dependency_repair": deepcopy(dependency_repair),
            },
        )
        return tree

    @staticmethod
    def _ensure_evidence_gate(parsed: dict[str, Any]) -> dict[str, Any]:
        """Deterministically ensure every response node directly depends on an
        evidence_sufficient_for_response decision. If the LLM-generated tree is
        missing the gate, inject one. If the gate exists but some response nodes
        do not directly require it, add the dependency."""
        import copy as _copy
        nodes = parsed.get("nodes")
        if not isinstance(nodes, list) or not nodes:
            return parsed
        node_map: dict[str, dict[str, Any]] = {}
        for node in nodes:
            if isinstance(node, dict):
                nid = str(node.get("node_id") or "")
                if nid:
                    node_map[nid] = node

        def _is_evidence_sufficient(n: dict[str, Any]) -> bool:
            cond = str(n.get("condition") or "").lower()
            goal = str(n.get("goal") or "").lower()
            return n.get("type") == "decision" and "evidence_sufficient" in f"{cond} {goal}"

        gate_id: str | None = None
        for n in nodes:
            if isinstance(n, dict) and _is_evidence_sufficient(n):
                gate_id = str(n.get("node_id") or "")
                break

        response_nodes = [
            n for n in nodes
            if isinstance(n, dict) and n.get("type") == "response"
        ]
        if not response_nodes:
            return parsed

        if gate_id is None:
            gate_id = "n_evidence_gate"
            idx = 0
            while gate_id in node_map:
                idx += 1
                gate_id = f"n_evidence_gate_{idx}"
            investigation_ids = [
                str(n.get("node_id") or "")
                for n in nodes
                if isinstance(n, dict) and n.get("type") == "investigate"
            ]
            last_investigation = investigation_ids[-1] if investigation_ids else ""
            gate_node = {
                "node_id": gate_id,
                "type": "decision",
                "goal": "Evaluate if sufficient evidence collected for response",
                "tool": "",
                "arguments": {},
                "condition": "evidence_sufficient_for_response",
                "requires": [last_investigation] if last_investigation else [],
                "on_success": [],
                "on_failure": [],
            }
            for rn in response_nodes:
                rid = str(rn.get("node_id") or "")
                requires = rn.get("requires")
                if not isinstance(requires, list):
                    requires = []
                requires = [r for r in requires if r != gate_id]
                requires.append(gate_id)
                rn["requires"] = requires
                gate_node["on_success"].append(rid)
            verify_nodes = [
                str(n.get("node_id") or "")
                for n in nodes
                if isinstance(n, dict) and n.get("type") == "verify"
            ]
            if verify_nodes:
                gate_node["on_failure"] = [verify_nodes[-1]]
            gate_node["on_success"] = list(dict.fromkeys(gate_node["on_success"]))
            gate_node["on_failure"] = list(dict.fromkeys(gate_node["on_failure"]))
            nodes.append(gate_node)
            node_map[gate_id] = gate_node
        else:
            for rn in response_nodes:
                requires = rn.get("requires")
                if not isinstance(requires, list):
                    requires = []
                if gate_id not in requires:
                    requires.append(gate_id)
                    rn["requires"] = requires
        return parsed

    def _latest_usage_record(self) -> dict[str, Any]:
        usage_records = getattr(self.llm_client, "usage_records", [])
        if not isinstance(usage_records, list) or not usage_records:
            return {}
        latest = usage_records[-1]
        return dict(latest) if isinstance(latest, dict) else {}

    @staticmethod
    def _is_dependency_error(exc: ValidationError) -> bool:
        message = str(exc).lower()
        return (
            "unknown requirement" in message
            or "must directly depend on an evidence_sufficient_for_response decision"
            in message
        )

    def _repair_dependencies(
        self,
        *,
        original: dict[str, Any],
        validation_error: str,
        initial_call: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        system_prompt = _load_prompt(
            "planner_dependency_repair.md",
            (
                "You repair only StrategyTree dependency fields. Return JSON only. "
                "Never execute tools and never change nodes, tools, arguments, goals, "
                "conditions, or response scope."
            ),
        )
        payload = {
            "task": "Repair only invalid StrategyTree graph dependencies.",
            "validation_error": validation_error,
            "original_strategy_tree": deepcopy(original),
            "editable_node_fields": sorted(DEPENDENCY_FIELDS),
            "required_output_shape": {
                "dependency_updates": [
                    {
                        "node_id": "existing-node-id",
                        "requires": ["existing-node-id"],
                        "on_success": ["existing-node-id"],
                        "on_failure": ["existing-node-id"],
                    }
                ]
            },
            "constraints": [
                "Return an object containing only dependency_updates.",
                "Each update may contain only node_id plus requires, on_success, and on_failure arrays.",
                "Every response node must directly require a decision whose condition or goal contains evidence_sufficient.",
                "Reference only existing node IDs.",
                "Do not execute or describe tool execution.",
            ],
        }
        repair_response = self.llm_client.chat_json(
            system_prompt=system_prompt,
            user_payload=payload,
            temperature=PLANNER_TEMPERATURE,
            max_tokens=1200,
        )
        repair_call = self._latest_usage_record()
        repaired, changes = self._apply_dependency_patch(original, repair_response)
        return repaired, {
            "attempted": True,
            "max_attempts": 1,
            "validation_error": validation_error,
            "editable_fields": sorted(DEPENDENCY_FIELDS),
            "initial_call_id": str(initial_call.get("call_id") or ""),
            "initial_response_sha256": str(
                initial_call.get("parsed_response_sha256") or ""
            ),
            "repair_call_id": str(repair_call.get("call_id") or ""),
            "repaired_response_sha256": str(
                repair_call.get("parsed_response_sha256") or ""
            ),
            "changes": changes,
        }

    @staticmethod
    def _apply_dependency_patch(
        original: dict[str, Any], repair_response: dict[str, Any]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        if not isinstance(original, dict) or not isinstance(repair_response, dict):
            raise ValidationError("dependency repair requires JSON objects")
        if set(repair_response) != {"dependency_updates"}:
            raise ValidationError(
                "dependency repair response may contain only dependency_updates"
            )
        updates = repair_response.get("dependency_updates")
        if not isinstance(updates, list) or not updates:
            raise ValidationError("dependency repair returned no dependency updates")

        repaired = deepcopy(original)
        original_nodes = original.get("nodes")
        repaired_nodes = repaired.get("nodes")
        if not isinstance(original_nodes, list) or not isinstance(repaired_nodes, list):
            raise ValidationError("dependency repair requires an original nodes array")
        node_map: dict[str, dict[str, Any]] = {}
        for node in repaired_nodes:
            if not isinstance(node, dict):
                raise ValidationError("dependency repair found a non-object original node")
            node_id = str(node.get("node_id") or node.get("id") or "")
            if not node_id or node_id in node_map:
                raise ValidationError("dependency repair requires unique original node IDs")
            node_map[node_id] = node

        changes: list[dict[str, Any]] = []
        updated_nodes: set[str] = set()
        for update in updates:
            if not isinstance(update, dict):
                raise ValidationError("dependency update must be an object")
            unknown_fields = set(update) - ({"node_id"} | set(DEPENDENCY_FIELDS))
            if unknown_fields:
                raise ValidationError(
                    f"dependency update contains unsupported field(s): {sorted(unknown_fields)}"
                )
            node_id = str(update.get("node_id") or "")
            if node_id not in node_map:
                raise ValidationError(
                    f"dependency update references unknown node {node_id or '<empty>'}"
                )
            if node_id in updated_nodes:
                raise ValidationError(f"dependency repair updates node {node_id} more than once")
            updated_nodes.add(node_id)
            fields = set(update) & set(DEPENDENCY_FIELDS)
            if not fields:
                raise ValidationError(
                    f"dependency update for node {node_id} contains no editable fields"
                )
            node = node_map[node_id]
            for field in sorted(fields):
                before_edges = node.get(field, [])
                after_edges = update[field]
                if not isinstance(before_edges, list) or not isinstance(after_edges, list):
                    raise ValidationError(
                        f"dependency repair field {field} on node {node_id} must be an array"
                    )
                if any(not isinstance(value, str) or not value for value in after_edges):
                    raise ValidationError(
                        f"dependency repair field {field} on node {node_id} contains an invalid node ID"
                    )
                unknown_edges = [value for value in after_edges if value not in node_map]
                if unknown_edges:
                    raise ValidationError(
                        f"dependency repair field {field} on node {node_id} references unknown node(s): {unknown_edges}"
                    )
                if len(set(after_edges)) != len(after_edges):
                    raise ValidationError(
                        f"dependency repair field {field} on node {node_id} contains duplicates"
                    )
                if after_edges != before_edges:
                    changes.append(
                        {
                            "node_id": node_id,
                            "field": field,
                            "before": list(before_edges),
                            "after": list(after_edges),
                        }
                    )
                    node[field] = list(after_edges)
        if not changes:
            raise ValidationError("dependency repair made no dependency changes")
        return repaired, changes

    @staticmethod
    def _enforce_read_only_planning_policy(
        tree: StrategyTree,
        *,
        replay: bool,
    ) -> None:
        for node in tree.nodes:
            if node.type not in {NodeType.INVESTIGATE, NodeType.VERIFY}:
                continue
            if node.tool in PLANNER_READ_ONLY_TOOLS:
                continue
            is_reviewed_baseline = (
                replay
                and node.type == NodeType.INVESTIGATE
                and node.tool == "check_recent_files"
                and node.metadata.get("c2trace_policy")
                == "c2trace.baseline.recent_files.v1"
            )
            if not is_reviewed_baseline:
                raise ValidationError(
                    f"Planner may not select system-owned read-only tool {node.tool}"
                )

    def _persistence_policy_constraint(self) -> str:
        persistence_tools = {
            "remove_registry",
            "remove_scheduled_task",
            "remove_service",
        }
        allowed = sorted(persistence_tools & set(self.allowed_response_tools))
        if not allowed:
            return (
                "check_persistence_all is investigation-only for this run. Do not create "
                "Run Key, Scheduled Task, or Service response nodes."
            )
        return (
            "If check_persistence_all is in the plan, include placeholder persistence cleanup "
            f"nodes only for these allowed tools: {allowed}. Never add a persistence response "
            "tool outside the run policy allowlist."
        )

    def plan_more_evidence(self, case: CaseFile, blocked_node: StrategyNode, reason: str) -> list[StrategyNode]:
        system_prompt = _load_prompt(
            "planner_more_evidence.md",
            "You are Planner. Generate only read-only investigation nodes as JSON.",
        )
        payload = {
            "task": "Add read-only investigation nodes that collect missing evidence before a blocked response node can be audited again.",
            "casefile": case.compact_summary(),
            "blocked_response_node": blocked_node.to_dict(),
            "audit_feedback": reason,
            "c2_kb": self.knowledge_pack.to_prompt_context(),
            "sanitized_experience_history": self.experience_context,
            "allowed_read_only_tools": [
                "check_network",
                "check_process",
                "check_process_tree",
                "check_file_metadata",
                "check_persistence_all",
                "check_powershell_history",
                "check_dns_cache",
                "verify_cleanup",
            ],
            "constraints": [
                "Return JSON only.",
                "Return an object with a nodes array.",
                "Every node must be type investigate.",
                "Do not add response nodes.",
                "Do not invent host-side artifacts.",
                "Sanitized experience history is pattern memory only, not current-case evidence.",
                "Use placeholders for unknown evidence.",
            ],
        }
        try:
            parsed = self.llm_client.chat_json(
                system_prompt=system_prompt,
                user_payload=payload,
                temperature=PLANNER_TEMPERATURE,
                max_tokens=1600,
            )
            raw_nodes = parsed.get("nodes", [])
            if not isinstance(raw_nodes, list) or not raw_nodes:
                raise ValidationError("补证 planning returned no nodes")
            nodes = [StrategyNode.from_dict({**item, "type": "investigate"}) for item in raw_nodes if isinstance(item, dict)]
            if not nodes:
                raise ValidationError("补证 planning returned no valid node objects")
            known_ids = set(case.strategy_tree.node_map()) if case.strategy_tree else set()
            proposed_ids = {node.node_id for node in nodes}
            for node in nodes:
                unknown = [item for item in node.requires if item not in known_ids and item not in proposed_ids]
                if unknown:
                    raise ValidationError(
                        f"补证 node {node.node_id} has unknown requirement(s): {unknown}"
                    )
        except (LLMError, ValidationError, Exception) as exc:
            case.record_error("planner_failed", str(exc), {"stage": "more_evidence", "node_id": blocked_node.node_id})
            raise PlannerError(str(exc)) from exc
        existing_ids = set(case.strategy_tree.node_map()) if case.strategy_tree else set()
        for node in nodes:
            if node.node_id in existing_ids:
                node.node_id = f"evidence-{uuid4().hex[:8]}"
            node.status = NodeStatus.PENDING
            if not node.on_success:
                node.on_success = [blocked_node.node_id]
        return nodes

    @staticmethod
    def _normalize_initial_status(tree: StrategyTree) -> None:
        for node in tree.nodes:
            node.status = NodeStatus.READY if not node.requires else NodeStatus.PENDING
            node.assigned_to = None
            node.evidence_refs = []
            node.audit_decision_id = None
            node.result_id = None

    @staticmethod
    def _ensure_persistence_cleanup_coverage(
        tree: StrategyTree,
        allowed_response_tools: set[str] | None = None,
    ) -> None:
        if not any(node.tool == "check_persistence_all" for node in tree.nodes):
            return
        allowed_response_tools = set(
            RESPONSE_TOOLS if allowed_response_tools is None else allowed_response_tools
        )
        existing_tools = {node.tool for node in tree.nodes if node.type == NodeType.RESPONSE}
        specs = {
            "remove_registry": {
                "goal": "remove linked registry run key persistence",
                "arguments": {
                    "reg_path": "{{evidence.persistence.reg_path}}",
                    "value_name": "{{evidence.persistence.value_name}}",
                    "expected_value": "{{evidence.persistence.expected_value}}",
                },
            },
            "remove_scheduled_task": {
                "goal": "remove linked scheduled task persistence",
                "arguments": {
                    "task_name": "{{evidence.persistence.task_name}}",
                    "task_path": "{{evidence.persistence.task_path}}",
                },
            },
            "remove_service": {
                "goal": "remove linked service persistence",
                "arguments": {
                    "service_name": "{{evidence.persistence.service_name}}",
                },
            },
        }
        missing = [
            tool
            for tool in specs
            if tool in allowed_response_tools and tool not in existing_tools
        ]
        if not missing:
            return
        decision = next(
            (
                node
                for node in tree.nodes
                if node.type == NodeType.DECISION
                and "evidence_sufficient" in f"{node.condition} {node.goal}".lower()
            ),
            None,
        )
        persistence_nodes = [node for node in tree.nodes if node.tool == "check_persistence_all"]
        requires = [decision.node_id] if decision else [persistence_nodes[-1].node_id]
        existing_ids = {node.node_id for node in tree.nodes}
        new_nodes: list[StrategyNode] = []
        for tool in missing:
            node_id = PlannerAgent._unique_node_id(f"auto_{tool}", existing_ids)
            existing_ids.add(node_id)
            new_nodes.append(StrategyNode(
                node_id=node_id,
                type=NodeType.RESPONSE,
                goal=specs[tool]["goal"],
                tool=tool,
                arguments=specs[tool]["arguments"],
                requires=list(requires),
            ))
            if decision and node_id not in decision.on_success:
                decision.on_success.append(node_id)
        tree.add_nodes(new_nodes)
        new_node_ids = [node.node_id for node in new_nodes]
        response_ids = {
            node.node_id
            for node in tree.nodes
            if node.type == NodeType.RESPONSE
        }
        for verify_node in tree.nodes:
            if verify_node.type != NodeType.VERIFY:
                continue
            # Only response-cleanup verification branches should wait for the
            # normalized response nodes. A no-response verification branch
            # must remain runnable when the evidence gate fails.
            if not any(requirement in response_ids for requirement in verify_node.requires):
                continue
            verify_node.requires = list(dict.fromkeys([*verify_node.requires, *new_node_ids]))
        tree.validate()

    @staticmethod
    def _apply_response_tool_policy(
        tree: StrategyTree, allowed_response_tools: set[str]
    ) -> list[dict[str, str]]:
        removed = [
            node
            for node in tree.nodes
            if node.type == NodeType.RESPONSE
            and node.tool not in allowed_response_tools
        ]
        if not removed:
            return []

        removed_ids = {node.node_id for node in removed}
        kept = [node for node in tree.nodes if node.node_id not in removed_ids]
        remaining_response_ids = [
            node.node_id for node in kept if node.type == NodeType.RESPONSE
        ]
        if not remaining_response_ids:
            raise ValidationError(
                "response tool policy removed every response node from the StrategyTree"
            )

        for node in kept:
            removed_requirements = [
                requirement
                for requirement in node.requires
                if requirement in removed_ids
            ]
            node.requires = [
                requirement
                for requirement in node.requires
                if requirement not in removed_ids
            ]
            if removed_requirements:
                if node.type != NodeType.VERIFY:
                    raise ValidationError(
                        f"response policy cannot safely rewrite dependency for node {node.node_id}"
                    )
                node.requires = list(
                    dict.fromkeys([*node.requires, *remaining_response_ids])
                )
            node.on_success = [
                target for target in node.on_success if target not in removed_ids
            ]
            node.on_failure = [
                target for target in node.on_failure if target not in removed_ids
            ]

        tree.nodes = kept
        tree.validate()
        return [
            {"node_id": node.node_id, "tool": node.tool}
            for node in removed
        ]

    @staticmethod
    def _unique_node_id(prefix: str, existing_ids: set[str]) -> str:
        if prefix not in existing_ids:
            return prefix
        for index in range(2, 100):
            candidate = f"{prefix}_{index}"
            if candidate not in existing_ids:
                return candidate
        return f"{prefix}_{uuid4().hex[:8]}"
