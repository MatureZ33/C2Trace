from __future__ import annotations

"""Stable execution contracts shared by the three-agent workflow and MCP.

This module deliberately contains data and transport contracts only.  It does
not know about Planner, Auditor, Executor, PowerShell, or the workflow
controller, which keeps infrastructure from becoming a fourth agent.
"""

from dataclasses import dataclass, field
from hashlib import sha256
import json
from typing import Any, Mapping, Protocol, runtime_checkable
from uuid import uuid4


EXECUTION_SCHEMA_VERSION = "c2trace.execution.v1"
MCP_RECEIPT_SCHEMA_VERSION = "c2trace.mcp_tool_receipt.v1"
AUTHORIZATION_SCHEMA_VERSION = "c2trace.response_authorization.v1"


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def canonical_sha256(value: Any) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def canonical_arguments(arguments: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a JSON-stable copy without changing argument semantics."""
    payload = json.loads(canonical_json(dict(arguments or {})))
    if not isinstance(payload, dict):  # defensive; dict input should guarantee this
        raise TypeError("tool arguments must serialize to a JSON object")
    return payload


def effective_arguments(arguments: Mapping[str, Any] | None) -> dict[str, Any]:
    """Normalize omitted/default tool values for cross-transport fingerprints."""
    return {
        key: value
        for key, value in canonical_arguments(arguments).items()
        if value is not None and value != "" and value != 0 and value != [] and value != {}
    }


@dataclass(frozen=True, slots=True)
class PreparedToolCall:
    node_id: str
    tool: str
    arguments: dict[str, Any]
    evidence_bindings: dict[str, str] = field(default_factory=dict)
    call_id: str = field(default_factory=lambda: str(uuid4()))
    schema_version: str = EXECUTION_SCHEMA_VERSION

    @classmethod
    def create(
        cls,
        *,
        node_id: str,
        tool: str,
        arguments: Mapping[str, Any] | None,
        evidence_bindings: Mapping[str, str] | None = None,
    ) -> "PreparedToolCall":
        return cls(
            node_id=str(node_id),
            tool=str(tool),
            arguments=canonical_arguments(arguments),
            evidence_bindings=dict(evidence_bindings or {}),
        )

    @property
    def arguments_sha256(self) -> str:
        return canonical_sha256(effective_arguments(self.arguments))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "call_id": self.call_id,
            "node_id": self.node_id,
            "tool": self.tool,
            "arguments": dict(self.arguments),
            "arguments_sha256": self.arguments_sha256,
            "evidence_bindings": dict(self.evidence_bindings),
        }


@dataclass(frozen=True, slots=True)
class TargetObservation:
    tool: str
    arguments: dict[str, Any]
    data: dict[str, Any]
    observed_at: str
    request_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "arguments": dict(self.arguments),
            "data": dict(self.data),
            "observed_at": self.observed_at,
            "request_id": self.request_id,
        }


@dataclass(frozen=True, slots=True)
class TargetLock:
    payload: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "TargetLock":
        payload = canonical_arguments(value)
        if not payload.get("lock_id"):
            raise ValueError("target lock requires lock_id")
        return cls(payload=payload)

    @property
    def sha256(self) -> str:
        return canonical_sha256(self.payload)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.payload)


@dataclass(frozen=True, slots=True)
class ResponseAuthorization:
    claims: dict[str, Any]
    signature: str
    algorithm: str = "Ed25519"
    schema_version: str = AUTHORIZATION_SCHEMA_VERSION

    @property
    def token_sha256(self) -> str:
        return canonical_sha256(self.to_wire())

    def to_wire(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "algorithm": self.algorithm,
            "claims": dict(self.claims),
            "signature": self.signature,
        }

    def public_receipt(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "algorithm": self.algorithm,
            "token_sha256": self.token_sha256,
            "claims": dict(self.claims),
        }


@dataclass(slots=True)
class ToolResult:
    success: bool
    data: Any = None
    error: str | None = None
    elapsed_ms: float = 0.0
    receipt: dict[str, Any] = field(default_factory=dict)
    error_type: str = ""


@dataclass(slots=True)
class ExecutionEnvelope:
    prepared_call: PreparedToolCall
    tool_result: ToolResult
    authorization_receipt: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "prepared_call": self.prepared_call.to_dict(),
            "tool_result": {
                "success": self.tool_result.success,
                "data": self.tool_result.data,
                "error": self.tool_result.error,
                "error_type": self.tool_result.error_type,
                "elapsed_ms": self.tool_result.elapsed_ms,
                "receipt": dict(self.tool_result.receipt),
            },
            "authorization_receipt": dict(self.authorization_receipt),
        }


@dataclass(frozen=True, slots=True)
class LlmCallProvenance:
    call_id: str
    logical_call_id: str
    attempt: int
    role: str
    provider: str
    endpoint_host: str
    model: str
    api_key_sha256: str
    request_id: str
    prompt_sha256: str
    response_sha256: str
    parsed_response_sha256: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    success: bool
    error_type: str
    http_status: int
    provider_error_code: str
    retry_after_ms: int
    started_at: str
    finished_at: str

    @classmethod
    def from_record(cls, role: str, record: Mapping[str, Any]) -> "LlmCallProvenance":
        return cls(
            call_id=str(record.get("call_id") or ""),
            logical_call_id=str(record.get("logical_call_id") or record.get("call_id") or ""),
            attempt=int(record.get("attempt") or 1),
            role=str(role),
            provider=str(record.get("provider") or ""),
            endpoint_host=str(record.get("endpoint_host") or ""),
            model=str(record.get("model") or ""),
            api_key_sha256=str(record.get("api_key_sha256") or ""),
            request_id=str(record.get("request_id") or ""),
            prompt_sha256=str(record.get("prompt_sha256") or ""),
            response_sha256=str(record.get("response_sha256") or ""),
            parsed_response_sha256=str(record.get("parsed_response_sha256") or ""),
            prompt_tokens=int(record.get("prompt_tokens") or 0),
            completion_tokens=int(record.get("completion_tokens") or 0),
            total_tokens=int(record.get("total_tokens") or 0),
            success=record.get("success") is True,
            error_type=str(record.get("error_type") or ""),
            http_status=int(record.get("http_status") or 0),
            provider_error_code=str(record.get("provider_error_code") or ""),
            retry_after_ms=int(record.get("retry_after_ms") or 0),
            started_at=str(record.get("started_at") or ""),
            finished_at=str(record.get("finished_at") or ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_id": self.call_id,
            "logical_call_id": self.logical_call_id,
            "attempt": self.attempt,
            "role": self.role,
            "provider": self.provider,
            "endpoint_host": self.endpoint_host,
            "model": self.model,
            "api_key_sha256": self.api_key_sha256,
            "request_id": self.request_id,
            "prompt_sha256": self.prompt_sha256,
            "response_sha256": self.response_sha256,
            "parsed_response_sha256": self.parsed_response_sha256,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "success": self.success,
            "error_type": self.error_type,
            "http_status": self.http_status,
            "provider_error_code": self.provider_error_code,
            "retry_after_ms": self.retry_after_ms,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


@dataclass(frozen=True, slots=True)
class McpToolReceipt:
    request_id: str
    tool: str
    tool_version: str
    success: bool
    data: Any = None
    error: str | None = None
    error_type: str = ""
    elapsed_ms: float = 0.0
    actual_args_summary: dict[str, Any] = field(default_factory=dict)
    actual_args_sha256: str = ""
    authorization_receipt: dict[str, Any] | None = None
    target_revalidation: dict[str, Any] | None = None
    schema_version: str = MCP_RECEIPT_SCHEMA_VERSION

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "McpToolReceipt":
        if str(payload.get("schema_version") or "") != MCP_RECEIPT_SCHEMA_VERSION:
            raise ValueError("unsupported or missing MCP tool receipt schema_version")
        return cls(
            request_id=str(payload.get("request_id") or ""),
            tool=str(payload.get("tool") or ""),
            tool_version=str(payload.get("tool_version") or ""),
            success=payload.get("success") is True,
            data=payload.get("data"),
            error=str(payload.get("error")) if payload.get("error") is not None else None,
            error_type=str(payload.get("error_type") or ""),
            elapsed_ms=float(payload.get("elapsed_ms") or 0.0),
            actual_args_summary=dict(payload.get("actual_args_summary") or {}),
            actual_args_sha256=str(payload.get("actual_args_sha256") or ""),
            authorization_receipt=(
                dict(payload["authorization_receipt"])
                if isinstance(payload.get("authorization_receipt"), Mapping)
                else None
            ),
            target_revalidation=(
                dict(payload["target_revalidation"])
                if isinstance(payload.get("target_revalidation"), Mapping)
                else None
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "error_type": self.error_type,
            "elapsed_ms": round(float(self.elapsed_ms), 3),
            "actual_args_summary": dict(self.actual_args_summary),
            "actual_args_sha256": self.actual_args_sha256,
            "authorization_receipt": self.authorization_receipt,
            "target_revalidation": self.target_revalidation,
        }

    def to_tool_result(self) -> ToolResult:
        return ToolResult(
            success=self.success,
            data=self.data,
            error=self.error,
            elapsed_ms=self.elapsed_ms,
            receipt=self.to_dict(),
            error_type=self.error_type,
        )


@runtime_checkable
class ToolClient(Protocol):
    def list_tools(self) -> list[dict[str, Any]]: ...

    def run(
        self,
        tool: str,
        params: dict[str, Any] | None = None,
        *,
        authorization: ResponseAuthorization | None = None,
    ) -> ToolResult: ...

    def close(self) -> None: ...


def tool_catalog_hash(tools: list[dict[str, Any]]) -> str:
    normalized = sorted(
        [canonical_arguments(item) for item in tools],
        key=lambda item: str(item.get("name") or ""),
    )
    return canonical_sha256(normalized)
