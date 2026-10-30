from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from hashlib import sha256
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from dataclasses import dataclass, field
import time
from typing import Any
from uuid import uuid4

from c2trace.execution import canonical_json


class LLMError(RuntimeError):
    pass


DEFAULT_DEEPSEEK_MODEL = "deepseek-v4-pro"
TRANSIENT_HTTP_STATUSES = frozenset({429, 500, 503})


def _safe_provider_error_code(detail: str) -> str:
    """Extract only a short provider code; never persist the response body."""
    try:
        payload = json.loads(detail)
    except (TypeError, json.JSONDecodeError):
        return ""
    error = payload.get("error") if isinstance(payload, dict) else None
    raw = error.get("code") if isinstance(error, dict) else ""
    text = str(raw or "").strip()
    return text[:80] if re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", text) else ""


def _retry_after_ms(headers: Any) -> int:
    if headers is None:
        return 0
    raw = str(headers.get("Retry-After") or "").strip()
    if not raw:
        return 0
    try:
        return max(0, min(60_000, int(float(raw) * 1000)))
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(raw)
        except (TypeError, ValueError, OverflowError):
            return 0
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=timezone.utc)
        delta = (retry_at.astimezone(timezone.utc) - datetime.now(timezone.utc)).total_seconds()
        return max(0, min(60_000, int(delta * 1000)))


def parse_json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            raise LLMError("LLM response did not contain JSON object")
        parsed = json.loads(text[start:end + 1])
    if not isinstance(parsed, dict):
        raise LLMError("LLM response JSON root must be an object")
    return parsed


@dataclass(slots=True)
class DeepSeekClient:
    api_key: str | None = None
    base_url: str | None = None
    model: str | None = None
    timeout_s: int = 90
    max_transient_retries: int = 1
    usage_records: list[dict[str, Any]] = field(default_factory=list, init=False, repr=False)
    configuration_sources: dict[str, str] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        explicit_key = bool(self.api_key)
        explicit_url = bool(self.base_url)
        explicit_model = bool(self.model)
        self.api_key = self.api_key or os.environ.get("DEEPSEEK_API_KEY")
        self.base_url = (self.base_url or os.environ.get("DEEPSEEK_BASE_URL") or "https://api.deepseek.com").rstrip("/")
        self.model = self.model or os.environ.get("DEEPSEEK_MODEL") or DEFAULT_DEEPSEEK_MODEL
        if not 0 <= int(self.max_transient_retries) <= 1:
            raise ValueError("max_transient_retries must be 0 or 1")
        self.configuration_sources = {
            "api_key": "explicit" if explicit_key else ("environment" if os.environ.get("DEEPSEEK_API_KEY") else "missing"),
            "base_url": "explicit" if explicit_url else ("environment" if os.environ.get("DEEPSEEK_BASE_URL") else "default"),
            "model": "explicit" if explicit_model else ("environment" if os.environ.get("DEEPSEEK_MODEL") else "default"),
        }

    def require_ready(self) -> None:
        if not self.api_key:
            raise LLMError("DEEPSEEK_API_KEY is required for Planner or Auditor")

    def chat_json(
        self,
        *,
        system_prompt: str,
        user_payload: dict[str, Any],
        temperature: float = 0.2,
        max_tokens: int = 2600,
    ) -> dict[str, Any]:
        self.require_ready()
        logical_call_id = str(uuid4())
        prompt_sha256 = sha256(canonical_json({
            "system_prompt": system_prompt,
            "user_payload": user_payload,
        }).encode("utf-8")).hexdigest()
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }
        if str(self.model).startswith("deepseek-v4-"):
            # Structured control-plane calls do not benefit from hidden
            # reasoning and should behave like the former deepseek-chat alias.
            body["thinking"] = {"type": "disabled"}
        payload: dict[str, Any]
        response_request_id = ""
        call_id = ""
        started_at = ""
        started = 0.0
        for attempt in range(1, int(self.max_transient_retries) + 2):
            call_id = str(uuid4())
            started_at = datetime.now(timezone.utc).isoformat()
            started = time.perf_counter()
            request = urllib.request.Request(
                f"{self.base_url}/chat/completions",
                data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                    headers = getattr(response, "headers", None)
                    if headers is not None:
                        response_request_id = str(
                            headers.get("x-request-id")
                            or headers.get("request-id")
                            or ""
                        )
                    raw_response = response.read().decode("utf-8")
                try:
                    decoded = json.loads(raw_response)
                except json.JSONDecodeError as exc:
                    self._record_usage(
                        temperature=temperature,
                        max_tokens=max_tokens,
                        elapsed_ms=(time.perf_counter() - started) * 1000,
                        success=False,
                        call_id=call_id,
                        logical_call_id=logical_call_id,
                        attempt=attempt,
                        started_at=started_at,
                        prompt_sha256=prompt_sha256,
                        request_id=response_request_id,
                        response_sha256=sha256(raw_response.encode("utf-8")).hexdigest(),
                        error_type="response_decode_error",
                    )
                    raise LLMError("DeepSeek response was not valid transport JSON") from exc
                if not isinstance(decoded, dict):
                    raise LLMError("DeepSeek response root was not an object")
                payload = decoded
                break
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")
                headers = getattr(exc, "headers", None)
                status = int(exc.code or 0)
                retry_ms = _retry_after_ms(headers)
                self._record_usage(
                    temperature=temperature,
                    max_tokens=max_tokens,
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                    success=False,
                    call_id=call_id,
                    logical_call_id=logical_call_id,
                    attempt=attempt,
                    started_at=started_at,
                    prompt_sha256=prompt_sha256,
                    request_id=str(headers.get("x-request-id") or headers.get("request-id") or "") if headers else "",
                    error_type="http_error",
                    http_status=status,
                    provider_error_code=_safe_provider_error_code(detail),
                    retry_after_ms=retry_ms,
                )
                if status in TRANSIENT_HTTP_STATUSES and attempt <= int(self.max_transient_retries):
                    time.sleep((retry_ms or 250) / 1000)
                    continue
                provider_code = _safe_provider_error_code(detail)
                suffix = f" ({provider_code})" if provider_code else ""
                raise LLMError(f"DeepSeek HTTP {status}{suffix}") from exc
            except LLMError:
                raise
            except Exception as exc:
                self._record_usage(
                    temperature=temperature,
                    max_tokens=max_tokens,
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                    success=False,
                    call_id=call_id,
                    logical_call_id=logical_call_id,
                    attempt=attempt,
                    started_at=started_at,
                    prompt_sha256=prompt_sha256,
                    error_type="transport_error",
                )
                raise LLMError(f"DeepSeek request failed: {type(exc).__name__}") from exc
        else:  # pragma: no cover - the bounded loop always returns or raises
            raise LLMError("DeepSeek retry loop ended unexpectedly")
        try:
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            self._record_usage(
                temperature=temperature,
                max_tokens=max_tokens,
                elapsed_ms=(time.perf_counter() - started) * 1000,
                success=False,
                usage=payload.get("usage") if isinstance(payload, dict) else None,
                call_id=call_id,
                logical_call_id=logical_call_id,
                attempt=attempt,
                started_at=started_at,
                prompt_sha256=prompt_sha256,
                request_id=response_request_id or str(payload.get("id") or ""),
                response_model=str(payload.get("model") or ""),
                error_type="response_schema_error",
            )
            raise LLMError("DeepSeek response missing choices[0].message.content") from exc
        response_text = str(content)
        if not response_text.strip():
            self._record_usage(
                temperature=temperature,
                max_tokens=max_tokens,
                elapsed_ms=(time.perf_counter() - started) * 1000,
                success=False,
                usage=payload.get("usage"),
                call_id=call_id,
                logical_call_id=logical_call_id,
                attempt=attempt,
                started_at=started_at,
                prompt_sha256=prompt_sha256,
                request_id=response_request_id or str(payload.get("id") or ""),
                response_model=str(payload.get("model") or ""),
                response_sha256=sha256(response_text.encode("utf-8")).hexdigest(),
                error_type="response_empty_error",
            )
            raise LLMError("DeepSeek returned empty JSON content")
        try:
            parsed = parse_json_object(response_text)
        except Exception:
            self._record_usage(
                temperature=temperature,
                max_tokens=max_tokens,
                elapsed_ms=(time.perf_counter() - started) * 1000,
                success=False,
                usage=payload.get("usage") if isinstance(payload, dict) else None,
                call_id=call_id,
                logical_call_id=logical_call_id,
                attempt=attempt,
                started_at=started_at,
                prompt_sha256=prompt_sha256,
                request_id=response_request_id or str(payload.get("id") or ""),
                response_model=str(payload.get("model") or ""),
                response_sha256=sha256(response_text.encode("utf-8")).hexdigest(),
                error_type="response_json_error",
            )
            raise
        self._record_usage(
            temperature=temperature,
            max_tokens=max_tokens,
            elapsed_ms=(time.perf_counter() - started) * 1000,
            success=True,
            usage=payload.get("usage") if isinstance(payload, dict) else None,
            call_id=call_id,
            logical_call_id=logical_call_id,
            attempt=attempt,
            started_at=started_at,
            prompt_sha256=prompt_sha256,
            request_id=response_request_id or str(payload.get("id") or ""),
            response_model=str(payload.get("model") or ""),
            response_sha256=sha256(response_text.encode("utf-8")).hexdigest(),
            parsed_response_sha256=sha256(canonical_json(parsed).encode("utf-8")).hexdigest(),
        )
        return parsed

    def _record_usage(
        self,
        *,
        temperature: float,
        max_tokens: int,
        elapsed_ms: float,
        success: bool,
        usage: Any = None,
        call_id: str = "",
        logical_call_id: str = "",
        attempt: int = 1,
        started_at: str = "",
        prompt_sha256: str = "",
        request_id: str = "",
        response_model: str = "",
        response_sha256: str = "",
        parsed_response_sha256: str = "",
        error_type: str = "",
        http_status: int = 0,
        provider_error_code: str = "",
        retry_after_ms: int = 0,
    ) -> None:
        raw_usage = usage if isinstance(usage, dict) else {}
        counters: dict[str, int] = {}
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            try:
                counters[key] = max(0, int(raw_usage.get(key) or 0))
            except (TypeError, ValueError):
                counters[key] = 0
        self.usage_records.append(
            {
                "call_id": call_id,
                "logical_call_id": logical_call_id,
                "attempt": int(attempt),
                "provider": "deepseek",
                "endpoint_host": urlsplit(str(self.base_url or "")).netloc,
                "model": str(self.model or ""),
                "response_model": str(response_model or ""),
                "api_key_sha256": sha256(str(self.api_key or "").encode("utf-8")).hexdigest() if self.api_key else "",
                "configuration_sources": dict(self.configuration_sources),
                "request_id": request_id,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "prompt_sha256": prompt_sha256,
                "response_sha256": response_sha256,
                "parsed_response_sha256": parsed_response_sha256,
                "temperature": float(temperature),
                "max_tokens": int(max_tokens),
                "elapsed_ms": round(float(elapsed_ms), 3),
                "success": bool(success),
                "error_type": str(error_type),
                "http_status": int(http_status),
                "provider_error_code": str(provider_error_code),
                "retry_after_ms": int(retry_after_ms),
                **counters,
            }
        )
