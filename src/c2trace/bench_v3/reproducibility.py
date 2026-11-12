from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
from typing import Any, Iterable


_TOP_LEVEL_FILES = ("run_case.py", "pyproject.toml")
_LOCKED_TREES = (
    "src/c2trace",
    "prompts",
    "kb",
    "experiments/c2trace_bench_v3",
)
_LOCKED_SCRIPTS = (
    "aggregate_c2trace_bench_v3.py",
    "build_c2trace_bench_v3.py",
    "c2trace_bench_v3_screening.py",
    "cleanup_c2trace_bench_v3_trial.ps1",
    "collect_c2trace_bench_v3_snapshot.ps1",
    "fetch_attack_flow_corpus.ps1",
    "finalize_c2trace_bench_v3_qualification.py",
    "run_c2trace_bench_v3.py",
    "run_c2trace_bench_v3.ps1",
    "score_c2trace_bench_v3.py",
    "start_suricata_s002.ps1",
    "stop_suricata_s002.ps1",
    "validate_c2trace_bench_v3.py",
)
_ALLOWED_SUFFIXES = {
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".rules",
    ".toml",
    ".yaml",
    ".yml",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_locked_files(project_root: Path) -> Iterable[Path]:
    root = project_root.resolve()
    selected: set[Path] = set()
    for relative in _TOP_LEVEL_FILES:
        candidate = (root / relative).resolve()
        if candidate.is_file():
            selected.add(candidate)
    for tree in _LOCKED_TREES:
        tree_root = (root / tree).resolve()
        if not tree_root.is_dir():
            continue
        for candidate in tree_root.rglob("*"):
            if (
                candidate.is_file()
                and candidate.suffix.lower() in _ALLOWED_SUFFIXES
                and "__pycache__" not in candidate.parts
                and "runs" not in candidate.relative_to(root).parts
            ):
                selected.add(candidate.resolve())
    for name in _LOCKED_SCRIPTS:
        candidate = (root / "scripts" / name).resolve()
        if candidate.is_file():
            selected.add(candidate)
    yield from sorted(selected, key=lambda item: item.relative_to(root).as_posix())


def build_software_lock(
    project_root: str | Path,
    *,
    vm_snapshot_id: str = "",
    model: str | None = None,
) -> dict[str, Any]:
    root = Path(project_root).resolve()
    rows: list[dict[str, Any]] = []
    tree_digest = hashlib.sha256()
    for path in iter_locked_files(root):
        relative = path.relative_to(root).as_posix()
        digest = sha256_file(path)
        size = path.stat().st_size
        rows.append({"path": relative, "size": size, "sha256": digest})
        tree_digest.update(relative.encode("utf-8"))
        tree_digest.update(b"\0")
        tree_digest.update(digest.encode("ascii"))
        tree_digest.update(b"\0")
        tree_digest.update(str(size).encode("ascii"))
        tree_digest.update(b"\n")
    source_lock_path = root / "experiments" / "c2trace_bench_v3" / "source_lock.json"
    source_lock = json.loads(source_lock_path.read_text(encoding="utf-8-sig"))
    return {
        "schema_version": "c2trace.bench.software_lock.v3",
        "project_root": str(root),
        "file_count": len(rows),
        "tree_sha256": tree_digest.hexdigest(),
        "files": rows,
        "attack_flow": {
            "tag": source_lock.get("release_tag"),
            "commit": source_lock.get("commit"),
            "source_lock_sha256": sha256_file(source_lock_path),
        },
        "local_caldera_commit": _git_commit(root / "caldera"),
        "runtime": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
        },
        "experiment_configuration": {
            "model": model or os.environ.get("DEEPSEEK_MODEL") or "deepseek-chat",
            "planner_temperature": 0.2,
            "auditor_temperature": 0.1,
            "vm_snapshot_id": str(vm_snapshot_id or "").strip(),
        },
    }


def _git_commit(path: Path) -> str:
    if not (path / ".git").exists():
        return ""
    completed = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.stdout.strip().lower() if completed.returncode == 0 else ""
