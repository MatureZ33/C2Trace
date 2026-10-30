from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import re
import sys
from typing import Any, Iterable, Mapping, Sequence


_LOCKED_SUFFIXES = {
    ".cs",
    ".exe",
    ".js",
    ".json",
    ".md",
    ".pem",
    ".ps1",
    ".py",
    ".rules",
    ".toml",
    ".yaml",
    ".yml",
}
_EXCLUDED_PARTS = {"__pycache__", ".pytest_cache", "offline_test_runs", "sensor_test_runs", "locks"}
_PASSED_RE = re.compile(r"(?m)(\d+) passed(?:,| in)")


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _contained_file(root: Path, requested: str | Path) -> Path:
    candidate = Path(requested)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    resolved.relative_to(root)
    if not resolved.is_file():
        raise ValueError(f"locked file does not exist: {resolved}")
    return resolved


def iter_locked_files(project_root: str | Path) -> Iterable[Path]:
    root = Path(project_root).resolve()
    selected: set[Path] = set()

    for relative in ("pyproject.toml", "run_case.py"):
        path = root / relative
        if path.is_file():
            selected.add(path.resolve())

    for relative in (
        "src/c2trace",
        "prompts",
        "kb",
        "experiments/c2trace_benchmark_v1",
        "case_study/caldera",
        "case_study/scripts",
    ):
        tree = root / relative
        if not tree.is_dir():
            continue
        for path in tree.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in _LOCKED_SUFFIXES:
                continue
            parts = path.relative_to(root).parts
            if any(part in _EXCLUDED_PARTS for part in parts):
                continue
            selected.add(path.resolve())

    for relative in (
        "scripts/validate_c2trace_benchmark_v1.py",
        "scripts/generate_c2trace_benchmark_v1.py",
        "scripts/build_c2trace_benchmark_v1_lock.py",
        "scripts/build_c2trace_benchmark_v1_scenarios.py",
        "scripts/run_low_memory_pytest.ps1",
        "scripts/run_c2trace_benchmark_v1_qualification.py",
        "scripts/run_c2trace_benchmark_v1_qualification.ps1",
        "scripts/run_c2trace_benchmark_v1_maas_qualification.py",
        "scripts/run_c2trace_benchmark_v1_maas_qualification.ps1",
        "scripts/initialize_c2trace_evidence_root.ps1",
        "scripts/export_c2trace_benchmark_v1_bundle.py",
    ):
        path = root / relative
        if path.is_file():
            selected.add(path.resolve())

    tests = root / "tests"
    if tests.is_dir():
        selected.update(path.resolve() for path in tests.glob("test_*.py") if path.is_file())

    yield from sorted(selected, key=lambda path: path.relative_to(root).as_posix())


def summarize_pytest_receipts(
    project_root: str | Path,
    summary_paths: Sequence[str | Path],
) -> dict[str, Any]:
    root = Path(project_root).resolve()
    expected = {
        path.name for path in (root / "tests").glob("test_*.py") if path.is_file()
    }
    passed: dict[str, dict[str, Any]] = {}
    summaries: list[dict[str, Any]] = []

    for requested in summary_paths:
        summary_path = _contained_file(root, requested)
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid low-memory pytest summary {summary_path}: {exc}") from exc
        if summary.get("live_actions_performed") is not False:
            raise ValueError(f"pytest summary does not prove offline execution: {summary_path}")
        summaries.append(
            {
                "path": summary_path.relative_to(root).as_posix(),
                "sha256": sha256_file(summary_path),
                "run_id": str(summary.get("run_id") or ""),
                "minimum_observed_free_memory_mb": summary.get(
                    "minimum_observed_free_memory_mb"
                ),
            }
        )
        for row in summary.get("results") or []:
            test_file = str(row.get("test_file") or "")
            if test_file not in expected or row.get("status") != "passed":
                continue
            stdout_path = _contained_file(root, str(row.get("stdout") or ""))
            stderr_path = _contained_file(root, str(row.get("stderr") or ""))
            matches = _PASSED_RE.findall(stdout_path.read_text(encoding="utf-8-sig"))
            if len(matches) != 1:
                raise ValueError(f"cannot determine pytest count from {stdout_path}")
            passed[test_file] = {
                "test_file": test_file,
                "passed_test_count": int(matches[0]),
                "run_id": str(summary.get("run_id") or ""),
                "stdout": {
                    "path": stdout_path.relative_to(root).as_posix(),
                    "sha256": sha256_file(stdout_path),
                },
                "stderr": {
                    "path": stderr_path.relative_to(root).as_posix(),
                    "sha256": sha256_file(stderr_path),
                },
            }

    missing = sorted(expected - set(passed))
    if missing:
        raise ValueError(f"pytest receipts do not cover passing results for: {', '.join(missing)}")
    minimum_values = [
        int(row["minimum_observed_free_memory_mb"])
        for row in summaries
        if row["minimum_observed_free_memory_mb"] is not None
    ]
    results = [passed[name] for name in sorted(passed)]
    return {
        "execution_model": "one_test_file_per_python_process",
        "test_file_count": len(results),
        "passed_test_count": sum(row["passed_test_count"] for row in results),
        "all_test_files_passed": True,
        "minimum_observed_free_memory_mb": min(minimum_values) if minimum_values else None,
        "summary_receipts": summaries,
        "test_results": results,
        "live_actions_performed": False,
    }


def build_software_lock(
    project_root: str | Path,
    *,
    pytest_summary_paths: Sequence[str | Path],
    vm_snapshot_id: str,
    planned_kali_ip: str,
    planned_windows_ip: str,
    offline_validation: dict[str, Any],
    generation_check: dict[str, Any],
    captured_at_utc: str | None = None,
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

    if offline_validation.get("valid") is not True:
        raise ValueError("offline validation did not pass")
    if offline_validation.get("live_actions_performed") is not False:
        raise ValueError("offline validation crossed the live boundary")
    if generation_check.get("valid") is not True or generation_check.get("written") is not False:
        raise ValueError("generation check must be valid and read-only")

    captured = captured_at_utc or datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": "c2trace.benchmark.v1.software_lock",
        "benchmark_id": "c2trace_benchmark_v1",
        "captured_at_utc": captured,
        "project_root": str(root),
        "file_count": len(rows),
        "tree_sha256": tree.hexdigest(),
        "files": rows,
        "runtime": {
            "python_executable": sys.executable,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
        },
        "offline_regression": summarize_pytest_receipts(root, pytest_summary_paths),
        "offline_validation": offline_validation,
        "generation_check": generation_check,
        "planned_environment": {
            "vm_snapshot_id": vm_snapshot_id,
            "kali_ip": planned_kali_ip,
            "windows_ip": planned_windows_ip,
            "live_verified": False,
        },
        "release_state": {
            "admitted_root_count": int(offline_validation.get("admitted_root_count", 0)),
            "minimum_release_ready": False,
            "required_label": "pilot_evaluation",
            "live_authorized": False,
            "live_actions_performed": False,
        },
        "environment_secrets_included": False,
        "environment_file_included": False,
    }


def verify_software_lock(
    project_root: str | Path,
    lock: Mapping[str, Any],
) -> dict[str, Any]:
    root = Path(project_root).resolve()
    expected_rows = lock.get("files")
    if lock.get("schema_version") != "c2trace.benchmark.v1.software_lock":
        raise ValueError("software lock schema_version is invalid")
    if not isinstance(expected_rows, list):
        raise ValueError("software lock has no files array")
    expected = {
        str(row.get("path") or ""): dict(row)
        for row in expected_rows
        if isinstance(row, Mapping) and str(row.get("path") or "")
    }
    actual_paths = {
        path.relative_to(root).as_posix(): path for path in iter_locked_files(root)
    }
    missing = sorted(set(expected) - set(actual_paths))
    added = sorted(set(actual_paths) - set(expected))
    drifted: list[str] = []
    tree = hashlib.sha256()
    for relative, path in sorted(actual_paths.items()):
        digest = sha256_file(path)
        size = path.stat().st_size
        row = expected.get(relative)
        if row is not None and (
            str(row.get("sha256") or "") != digest or int(row.get("size") or -1) != size
        ):
            drifted.append(relative)
        tree.update(relative.encode("utf-8") + b"\0")
        tree.update(digest.encode("ascii") + b"\0")
        tree.update(str(size).encode("ascii") + b"\n")
    actual_tree = tree.hexdigest()
    expected_tree = str(lock.get("tree_sha256") or "")
    expected_runtime = lock.get("runtime")
    runtime_drift: list[str] = []
    if isinstance(expected_runtime, Mapping):
        actual_runtime = {
            "python_executable": sys.executable,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
        }
        runtime_drift = [
            key
            for key, value in actual_runtime.items()
            if str(expected_runtime.get(key) or "") != str(value)
        ]
    valid = (
        not missing
        and not added
        and not drifted
        and not runtime_drift
        and actual_tree == expected_tree
    )
    return {
        "schema_version": "c2trace.benchmark.v1.software_lock_verification",
        "valid": valid,
        "missing": missing,
        "added": added,
        "drifted": drifted,
        "runtime_drift": runtime_drift,
        "expected_tree_sha256": expected_tree,
        "actual_tree_sha256": actual_tree,
        "checked_file_count": len(actual_paths),
        "live_actions_performed": False,
    }


__all__ = [
    "build_software_lock",
    "iter_locked_files",
    "sha256_file",
    "summarize_pytest_receipts",
    "verify_software_lock",
]
