from contextlib import contextmanager
import importlib
import sys

import pytest

from c2trace.agents import ExecutorAgent
from c2trace.authorization import ResponseAuthorizationIssuer, ResponseAuthorizationVerifier
from c2trace.execution import PreparedToolCall
from c2trace.mcp.client import McpTransportError, StdioMcpToolClient
from c2trace.models import AuditDecision, AuditVerdict, CaseFile, MinimalAlert, StrategyNode
from c2trace.tools import READ_ONLY_TOOLS, RESPONSE_TOOLS, ToolResult


def _alert() -> MinimalAlert:
    return MinimalAlert.from_dict({
        "case_id": "MCP-TEST-001",
        "alert_id": "MCP-TEST-001-A",
        "source": "unit_test",
        "alert_type": "c2_http_beacon",
        "victim_ip": "192.0.2.10",
        "remote_ip": "192.0.2.20",
        "remote_port": 443,
        "protocol": "tcp",
    })


def _client(*, response_enabled: bool = False) -> StdioMcpToolClient:
    issuer = ResponseAuthorizationIssuer()
    return StdioMcpToolClient(
        case_id="MCP-TEST-001",
        response_enabled=response_enabled,
        public_key_b64=issuer.public_key_b64,
        timeout_seconds=20,
    )


def test_stdio_mcp_catalog_declares_exactly_fourteen_tools():
    with _client() as client:
        names = {str(item.get("name") or "") for item in client.catalog}
        assert names == set(READ_ONLY_TOOLS | RESPONSE_TOOLS)
        assert len(names) == 14
        assert len(client.catalog_hash) == 64
        response = next(item for item in client.catalog if item["name"] == "kill_process")
        assert response["_meta"]["c2trace"]["response"] is True
        assert "pid" in response["inputSchema"]["properties"]


def test_stdio_mcp_close_cleans_worker_and_fails_closed_after_close():
    client = _client()
    worker = client._thread
    client.close()
    assert worker.is_alive() is False
    result = client.run("check_process", {"pid": 1})
    assert result.success is False
    assert result.error_type == "infrastructure_invalid"


def test_stdio_mcp_startup_crash_fails_as_infrastructure(monkeypatch):
    async def crash(_self):
        raise RuntimeError("synthetic MCP startup crash")

    monkeypatch.setattr(StdioMcpToolClient, "_session_main", crash)
    with pytest.raises(McpTransportError, match="startup crash"):
        _client()


def test_read_only_mcp_rejects_response_tool_with_receipt():
    with _client() as client:
        result = client.run(
            "remove_file",
            {"file_path": r"C:\Users\Public\must-not-be-deleted.txt"},
        )
        assert result.success is False
        assert result.error_type == "response_disabled"
        assert result.receipt["schema_version"] == "c2trace.mcp_tool_receipt.v1"
        assert result.receipt["tool"] == "remove_file"
        assert len(result.receipt["actual_args_sha256"]) == 64


def test_response_enabled_mcp_rejects_missing_auditor_authorization():
    with _client(response_enabled=True) as client:
        result = client.run(
            "remove_file",
            {"file_path": r"C:\Users\Public\must-not-be-deleted.txt"},
        )
        assert result.success is False
        assert result.error_type == "authorization_denied"
        assert "Auditor authorization" in (result.error or "")


def test_executor_freezes_prepared_call_and_preserves_mcp_receipt():
    case = CaseFile.from_alert(_alert())
    node = StrategyNode.from_dict({
        "node_id": "n-response",
        "type": "response",
        "goal": "dry-run exact file response",
        "tool": "remove_file",
        "arguments": {"file_path": "{{evidence.file_path}}"},
    })
    with _client() as client:
        executor = ExecutorAgent(tool_client=client)
        prepared = executor.prepare(
            case,
            node,
            {"file_path": r"C:\Users\Public\must-not-be-deleted.txt"},
        )
        result = executor.execute(case, node, prepared)
    assert prepared.arguments_sha256
    assert result.success is False
    assert result.transport_receipt["error_type"] == "response_disabled"
    assert result.transport_receipt["tool"] == "remove_file"


class _Meta:
    def __init__(self, payload):
        self.payload = payload

    def model_dump(self, **_kwargs):
        return self.payload


class _Context:
    request_id = "request-001"

    def __init__(self, authorization):
        self.request_context = type("RequestContext", (), {
            "meta": _Meta({"c2trace": {"authorization": authorization.to_wire()}}),
        })()


class _AuthorizedFakeBackend:
    def __init__(self):
        self.mutations = 0

    @contextmanager
    def mcp_authorized_response(self, **_kwargs):
        yield "fake-backend-capability"

    def run(self, tool, params):
        if tool == "check_file_metadata":
            return ToolResult(True, data={"file": {
                "exists": True,
                "path": r"C:\Users\Public\mcp-test.exe",
                "sha256": "c" * 64,
            }})
        if tool == "remove_file":
            self.mutations += 1
            return ToolResult(True, data={"removed": True, "file_path": params["file_path"]})
        raise AssertionError(tool)


def test_server_accepts_valid_authorization_once_and_rejects_replay(monkeypatch):
    issuer = ResponseAuthorizationIssuer()
    monkeypatch.setenv("C2TRACE_MCP_MODE", "response_enabled")
    monkeypatch.setenv("C2TRACE_MCP_CASE_ID", "MCP-TEST-001")
    monkeypatch.setenv("C2TRACE_MCP_PUBLIC_KEY", issuer.public_key_b64)
    sys.modules.pop("c2trace.mcp.server", None)
    server = importlib.import_module("c2trace.mcp.server")

    arguments = {"file_path": r"C:\Users\Public\mcp-test.exe"}
    call = PreparedToolCall.create(
        node_id="n-response",
        tool="remove_file",
        arguments=arguments,
    )
    decision = AuditDecision(
        node_id=call.node_id,
        verdict=AuditVerdict.APPROVED,
        reason="test",
    )
    lock = {
        "schema_version": "c2trace.response_target_lock.v2",
        "lock_id": "d" * 64,
        "case_id": "MCP-TEST-001",
        "process": {},
        "file": {
            "path": arguments["file_path"],
            "canonical_path": arguments["file_path"].lower(),
            "sha256": "c" * 64,
        },
        "persistence_targets": [],
    }
    authorization = issuer.issue(
        case_id="MCP-TEST-001",
        decision=decision,
        call=call,
        target_lock=lock,
    )
    backend = _AuthorizedFakeBackend()
    monkeypatch.setattr(server, "backend", backend)
    monkeypatch.setattr(server, "verifier", ResponseAuthorizationVerifier(issuer.public_key_b64))

    first = server._invoke("remove_file", arguments, _Context(authorization))
    second = server._invoke("remove_file", arguments, _Context(authorization))

    assert first["success"] is True
    assert first["authorization_receipt"]["nonce_consumed"] is True
    assert backend.mutations == 1
    assert second["success"] is False
    assert second["error_type"] == "authorization_denied"
    assert "consumed" in second["error"]
    sys.modules.pop("c2trace.mcp.server", None)
