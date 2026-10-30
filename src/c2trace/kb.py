from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class C2KnowledgePack:
    template: str
    tool_catalog: str
    evidence_rules: str
    response_safety_rules: str

    def to_prompt_context(self) -> dict[str, str]:
        return {
            "generic_http_c2_windows": self.template,
            "windows_tool_catalog": self.tool_catalog,
            "evidence_rules": self.evidence_rules,
            "response_safety_rules": self.response_safety_rules,
        }


def load_c2kb(root: Path) -> C2KnowledgePack:
    def read(rel: str) -> str:
        path = root / rel
        return path.read_text(encoding="utf-8") if path.exists() else ""

    return C2KnowledgePack(
        template=read("templates/generic_http_c2_windows.md"),
        tool_catalog=read("tools/windows_tool_catalog.md"),
        evidence_rules=read("rules/evidence_rules.md"),
        response_safety_rules=read("rules/response_safety_rules.md"),
    )

