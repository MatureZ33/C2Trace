from __future__ import annotations

"""Auditor-issued, server-verified one-shot response capabilities."""

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from threading import Lock
from typing import Any, Mapping
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from c2trace.execution import (
    AUTHORIZATION_SCHEMA_VERSION,
    PreparedToolCall,
    ResponseAuthorization,
    TargetLock,
    canonical_json,
)
from c2trace.models import AuditDecision, AuditVerdict


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_utc(value: Any) -> datetime:
    raw = str(value or "").strip().replace("Z", "+00:00").replace("z", "+00:00")
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class AuthorizationVerification:
    valid: bool
    reason: str
    claims: dict[str, Any]
    token_sha256: str

    def receipt(self, *, consumed: bool = False) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "token_sha256": self.token_sha256,
            "claims": dict(self.claims),
            "nonce_consumed": consumed,
        }


class ResponseAuthorizationIssuer:
    """Owned by AuditorAgent; only the public key is shared with MCP Server."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        self._private_key = private_key or Ed25519PrivateKey.generate()

    @property
    def public_key_b64(self) -> str:
        raw = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return _b64encode(raw)

    @property
    def public_key_fingerprint(self) -> str:
        return sha256(_b64decode(self.public_key_b64)).hexdigest()

    def issue(
        self,
        *,
        case_id: str,
        decision: AuditDecision,
        call: PreparedToolCall,
        target_lock: Mapping[str, Any],
        ttl_seconds: int = 60,
    ) -> ResponseAuthorization:
        if decision.verdict != AuditVerdict.APPROVED:
            raise PermissionError("response authorization requires an approved audit decision")
        if decision.node_id != call.node_id:
            raise PermissionError("audit decision is not bound to the prepared response call")
        lock = TargetLock.from_mapping(target_lock)
        issued_at = _utc_now()
        claims = {
            "case_id": str(case_id),
            "audit_decision_id": decision.decision_id,
            "strategy_node_id": call.node_id,
            "call_id": call.call_id,
            "tool": call.tool,
            "arguments_sha256": call.arguments_sha256,
            "target_lock": lock.to_dict(),
            "target_lock_sha256": lock.sha256,
            "issued_at": issued_at.isoformat(),
            "expires_at": (issued_at + timedelta(seconds=max(1, int(ttl_seconds)))).isoformat(),
            "nonce": uuid4().hex,
            "public_key_fingerprint": self.public_key_fingerprint,
        }
        signature = self._private_key.sign(canonical_json(claims).encode("utf-8"))
        return ResponseAuthorization(claims=claims, signature=_b64encode(signature))


class ResponseAuthorizationVerifier:
    def __init__(self, public_key_b64: str) -> None:
        raw = _b64decode(public_key_b64)
        self._public_key = Ed25519PublicKey.from_public_bytes(raw)
        self.public_key_fingerprint = sha256(raw).hexdigest()
        self._consumed_nonces: set[str] = set()
        self._lock = Lock()

    def verify(
        self,
        wire: Mapping[str, Any],
        *,
        case_id: str,
        call_id: str,
        node_id: str,
        tool: str,
        arguments_sha256: str,
        now: datetime | None = None,
    ) -> AuthorizationVerification:
        try:
            if str(wire.get("schema_version") or "") != AUTHORIZATION_SCHEMA_VERSION:
                raise ValueError("authorization schema mismatch")
            if str(wire.get("algorithm") or "") != "Ed25519":
                raise ValueError("authorization algorithm mismatch")
            claims = dict(wire.get("claims") or {})
            signature = _b64decode(str(wire.get("signature") or ""))
            self._public_key.verify(signature, canonical_json(claims).encode("utf-8"))
            expected = {
                "case_id": str(case_id),
                "call_id": str(call_id),
                "strategy_node_id": str(node_id),
                "tool": str(tool),
                "arguments_sha256": str(arguments_sha256),
                "public_key_fingerprint": self.public_key_fingerprint,
            }
            mismatches = [key for key, value in expected.items() if str(claims.get(key) or "") != value]
            if mismatches:
                raise ValueError(f"authorization claim mismatch: {', '.join(mismatches)}")
            lock = TargetLock.from_mapping(dict(claims.get("target_lock") or {}))
            if str(claims.get("target_lock_sha256") or "") != lock.sha256:
                raise ValueError("authorization target-lock hash mismatch")
            current = (now or _utc_now()).astimezone(timezone.utc)
            if current < _parse_utc(claims.get("issued_at")) - timedelta(seconds=5):
                raise ValueError("authorization is not yet valid")
            if current >= _parse_utc(claims.get("expires_at")):
                raise ValueError("authorization expired")
            nonce = str(claims.get("nonce") or "")
            if not nonce:
                raise ValueError("authorization nonce is missing")
            with self._lock:
                if nonce in self._consumed_nonces:
                    raise ValueError("authorization nonce was already consumed")
            token_sha256 = sha256(canonical_json(dict(wire)).encode("utf-8")).hexdigest()
            return AuthorizationVerification(True, "verified", claims, token_sha256)
        except (InvalidSignature, ValueError, TypeError, KeyError) as exc:
            token_sha256 = sha256(canonical_json(dict(wire)).encode("utf-8")).hexdigest()
            return AuthorizationVerification(False, str(exc) or "invalid signature", {}, token_sha256)

    def consume(self, verification: AuthorizationVerification) -> None:
        if not verification.valid:
            raise PermissionError("cannot consume invalid response authorization")
        nonce = str(verification.claims.get("nonce") or "")
        with self._lock:
            if nonce in self._consumed_nonces:
                raise PermissionError("authorization nonce was already consumed")
            self._consumed_nonces.add(nonce)

