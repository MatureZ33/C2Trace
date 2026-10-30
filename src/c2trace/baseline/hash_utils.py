"""Deterministic hashes for baseline prompts and frozen input material."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from c2trace.baseline.public_task import DEFAULT_SPEC_ROOT, build_public_system_prompt
from c2trace.models import MinimalAlert


def _manifest_alert() -> dict:
    return MinimalAlert.from_dict(
        {
            "schema_version": "c2trace.alert.v1",
            "alert_id": "manifest-hash-alert",
            "case_id": "manifest-hash-case",
            "source": "suricata_eve",
            "alert_type": "c2_http_beacon",
            "victim_ip": "192.0.2.20",
            "remote_ip": "192.0.2.10",
            "remote_port": 443,
            "protocol": "tcp",
            "time_window": {
                "start": "2026-01-01T00:00:00Z",
                "end": "2026-01-01T00:00:00Z",
            },
            "confidence": 0.5,
            "description": "deterministic manifest input",
        }
    ).to_dict()


def compute_baseline_prompt_hashes(kb_root: str | Path) -> dict[str, str]:
    """Return separate public-task dry-run and execute prompt hashes.

    ``kb_root`` remains an argument for historical callers but is deliberately
    ignored. The independent baseline never loads the treatment knowledge base.
    """
    alert = _manifest_alert()
    return {
        "dry_run": hashlib.sha256(
            build_public_system_prompt(alert, spec_root=DEFAULT_SPEC_ROOT, execute_response=False).encode("utf-8")
        ).hexdigest(),
        "execute": hashlib.sha256(
            build_public_system_prompt(alert, spec_root=DEFAULT_SPEC_ROOT, execute_response=True).encode("utf-8")
        ).hexdigest(),
    }


def compute_kb_hash(kb_root: str | Path) -> str:
    """Compatibility name returning the public task contract hash.

    Formal ReAct runs must not hash or load the treatment knowledge base.
    Historical callers still pass ``kb_root``; the argument is ignored.
    """
    return compute_public_task_spec_hash(DEFAULT_SPEC_ROOT)


def _compute_legacy_tree_hash(kb_root: str | Path) -> str:
    root = Path(kb_root)
    digest = hashlib.sha256()
    for kbfile in sorted(root.rglob("*")):
        if kbfile.is_file():
            digest.update(str(kbfile.relative_to(root)).encode("utf-8"))
            digest.update(kbfile.read_bytes())
    return digest.hexdigest()


def compute_tool_schema_hash(tools: list) -> str:
    payload = [
        {
            "name": tool.name,
            "description": tool.description,
            "args_schema": str(getattr(tool, "args_schema", "")),
        }
        for tool in tools
    ]
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def compute_public_task_spec_hash(spec_root: str | Path = DEFAULT_SPEC_ROOT) -> str:
    """Hash the model-visible public contract, excluding transient caches."""
    root = Path(spec_root)
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "README.md":
            continue
        digest.update(str(path.relative_to(root)).replace("\\", "/").encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


__all__ = ["compute_baseline_prompt_hashes", "compute_kb_hash", "compute_tool_schema_hash", "compute_public_task_spec_hash"]
