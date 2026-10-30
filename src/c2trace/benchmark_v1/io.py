from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .models import (
    C2ScenarioIR,
    EpisodeTemplate,
    FidelityReceipt,
    QualificationReceipt,
    SourceRoot,
    TrialReceipt,
    VariantPolicy,
)


def read_json(path: str | Path) -> dict[str, Any]:
    requested = Path(path)
    try:
        value = json.loads(requested.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read JSON {requested}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {requested}")
    return value


def write_json(path: str | Path, value: Mapping[str, Any]) -> None:
    requested = Path(path)
    requested.parent.mkdir(parents=True, exist_ok=True)
    requested.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_source_root(path: str | Path) -> SourceRoot:
    return SourceRoot.from_dict(read_json(path))


def load_fidelity_receipt(path: str | Path) -> FidelityReceipt:
    return FidelityReceipt.from_dict(read_json(path))


def load_scenario_ir(path: str | Path) -> C2ScenarioIR:
    return C2ScenarioIR.from_dict(read_json(path))


def load_variant_policy(path: str | Path) -> VariantPolicy:
    return VariantPolicy.from_dict(read_json(path))


def load_episode_template(path: str | Path) -> EpisodeTemplate:
    return EpisodeTemplate.from_dict(read_json(path))


def load_qualification_receipt(path: str | Path) -> QualificationReceipt:
    return QualificationReceipt.from_dict(read_json(path))


def load_trial_receipt(path: str | Path) -> TrialReceipt:
    return TrialReceipt.from_dict(read_json(path))
