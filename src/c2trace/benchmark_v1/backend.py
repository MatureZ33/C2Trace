from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from .models import ActionReceipt, AttackBackend, C2ScenarioIR, content_hash


class BackendError(RuntimeError):
    pass


@dataclass
class BackendRegistry:
    _backends: dict[str, AttackBackend] = field(default_factory=dict)

    def register(self, backend: AttackBackend) -> None:
        name = str(backend.name).strip()
        if not name:
            raise BackendError("backend name cannot be empty")
        if name in self._backends:
            raise BackendError(f"backend already registered: {name}")
        self._backends[name] = backend

    def get(self, name: str) -> AttackBackend:
        try:
            return self._backends[name]
        except KeyError as exc:
            raise BackendError(f"backend is not registered: {name}") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._backends))


class RecordingAttackBackend:
    """Deterministic test backend; never used for live benchmark admission."""

    name = "recording_fake"

    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, Any]]] = []

    def prepare(self, scenario: C2ScenarioIR, parameters: Mapping[str, Any]) -> Mapping[str, Any]:
        prepared = {
            "scenario_id": scenario.scenario_id,
            "scenario_sha256": content_hash(scenario),
            "parameters": dict(parameters),
        }
        self.calls.append(("prepare", prepared))
        return prepared

    def _receipt(self, action: str, payload: Mapping[str, Any]) -> ActionReceipt:
        now = datetime.now(timezone.utc).isoformat()
        return ActionReceipt(
            action_id=action,
            backend=self.name,
            started_at_utc=now,
            ended_at_utc=now,
            success=True,
            request_sha256=content_hash(payload),
            result={"recorded": True},
        )

    def execute(self, prepared: Mapping[str, Any]) -> Sequence[ActionReceipt]:
        self.calls.append(("execute", prepared))
        return (self._receipt("execute", prepared),)

    def query_state(self, prepared: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append(("query_state", prepared))
        return {"recorded": True, "source": "fake"}

    def cleanup(self, prepared: Mapping[str, Any]) -> Sequence[ActionReceipt]:
        self.calls.append(("cleanup", prepared))
        return (self._receipt("cleanup", prepared),)

