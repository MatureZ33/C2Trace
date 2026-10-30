from __future__ import annotations

"""Deterministic software lock for Bench v4 qualification/admission."""

import hashlib
from pathlib import Path
import platform
from typing import Any, Iterable


_SUFFIXES = {".json", ".md", ".ps1", ".py", ".rules", ".toml", ".yaml", ".yml"}


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_locked_files(project_root: str | Path) -> Iterable[Path]:
    root = Path(project_root).resolve()
    selected: set[Path] = set()
    for relative in ("run_case.py", "pyproject.toml"):
        path = (root / relative).resolve()
        if path.is_file():
            selected.add(path)
    for relative in ("src/c2trace", "prompts", "kb", "experiments/c2trace_bench_v4"):
        tree = (root / relative).resolve()
        if not tree.is_dir():
            continue
        for path in tree.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in _SUFFIXES:
                continue
            parts = path.relative_to(root).parts
            if "__pycache__" in parts or "admissions" in parts or "runs" in parts:
                continue
            selected.add(path.resolve())
    scripts = root / "scripts"
    for pattern in ("*c2trace_bench_v4*", "start_suricata_s002.ps1", "stop_suricata_s002.ps1"):
        for path in scripts.glob(pattern):
            if path.is_file() and path.suffix.lower() in _SUFFIXES:
                selected.add(path.resolve())
    yield from sorted(selected, key=lambda path: path.relative_to(root).as_posix())


def build_software_lock(
    project_root: str | Path,
    *,
    vm_snapshot_id: str,
    model: str = "deepseek-chat",
) -> dict[str, Any]:
    root = Path(project_root).resolve()
    rows: list[dict[str, Any]] = []
    tree = hashlib.sha256()
    for path in iter_locked_files(root):
        relative = path.relative_to(root).as_posix()
        digest = sha256_file(path)
        size = path.stat().st_size
        rows.append({"path": relative, "size": size, "sha256": digest})
        tree.update(relative.encode("utf-8") + b"\0")
        tree.update(digest.encode("ascii") + b"\0")
        tree.update(str(size).encode("ascii") + b"\n")
    return {
        "schema_version": "c2trace.bench.software_lock.v4",
        "project_root": str(root),
        "file_count": len(rows),
        "tree_sha256": tree.hexdigest(),
        "files": rows,
        "runtime": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
        },
        "experiment_configuration": {
            "model": model,
            "planner_temperature": 0.2,
            "auditor_temperature": 0.1,
            "experience_history": "frozen_empty",
            "vm_snapshot_id": str(vm_snapshot_id or "").strip(),
        },
        "environment_secrets_included": False,
        "environment_file_included": False,
    }


__all__ = ["build_software_lock", "iter_locked_files", "sha256_file"]
