from __future__ import annotations

"""Evidence-backed software locks for the public-tool Benchmark v1.

The lock is a structural snapshot of one selected case package, its frozen
upstream source material, and the receipt set used to validate the offline-only
boundary.  It never certifies Live or admission.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import platform
import sys
from typing import Any, Iterable, Mapping, Sequence


LOCK_SCHEMA = "c2trace.public_tool_benchmark.v1.public_tool_software_lock"
VERIFY_SCHEMA = "c2trace.public_tool_benchmark.v1.public_tool_software_lock_verification"
ROOT_ID = "CTID-WEBSHELL-001"
_EXCLUDED_PARTS = {"__pycache__", ".pytest_cache", "locks", "offline_test_runs", "sensor_test_runs"}
_EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".tmp"}
_RECEIPT_NAME_MARKERS = ("receipt", "audit", "preparation")


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def _contained(root: Path, requested: str | Path) -> Path:
    candidate = Path(requested)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escaped project root: {requested}") from exc
    if not resolved.is_file():
        raise ValueError(f"required locked file is missing: {resolved}")
    return resolved


def _relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root).as_posix()


def _tree_sha256(rows: Sequence[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    for row in sorted(rows, key=lambda item: str(item.get("path") or "")):
        digest.update(str(row.get("path") or "").encode("utf-8") + b"\0")
        digest.update(str(row.get("sha256") or "").encode("ascii") + b"\0")
        digest.update(str(row.get("size") or "").encode("ascii") + b"\n")
    return digest.hexdigest()


def _validate_relative(value: str) -> str:
    if not value or "\\" in value:
        raise ValueError(f"invalid lock path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts or "." in path.parts:
        raise ValueError(f"invalid lock path: {value!r}")
    return path.as_posix()


def _walk_files(root: Path) -> list[Path]:
    if not root.is_dir():
        raise ValueError(f"locked package directory is missing: {root}")
    paths: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative_parts = path.relative_to(root).parts
        if any(part in _EXCLUDED_PARTS for part in relative_parts):
            continue
        if path.suffix.lower() in _EXCLUDED_SUFFIXES:
            continue
        paths.append(path.resolve())
    return sorted(paths, key=lambda item: item.relative_to(root).as_posix())


def _registry_case(benchmark_root: Path, root_id: str) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    registry = _load_json(benchmark_root / "registry.json")
    case_entry = next((row for row in registry.get("selected_cases", []) if row.get("root_id") == root_id), None)
    if not isinstance(case_entry, dict):
        raise ValueError(f"selected case is not registered: {root_id}")
    case_path = _contained(benchmark_root, str(case_entry.get("case_path") or ""))
    case_root = case_path.parent
    case = _load_json(case_path)
    if case.get("root_id") != root_id:
        raise ValueError("case Root ID does not match lock target")
    return case_root, case, case_entry


def _case_source_lock(project_root: Path, case: Mapping[str, Any]) -> Path | None:
    source_lock_relative = str(case.get("source", {}).get("source_lock_path") or "")
    if not source_lock_relative:
        return None
    return _contained(project_root, source_lock_relative)


def _source_artifact_paths(project_root: Path, case: Mapping[str, Any]) -> tuple[Path | None, dict[str, Any] | None, list[Path]]:
    source_lock = _case_source_lock(project_root, case)
    if source_lock is None:
        return None, None, []
    value = _load_json(source_lock)
    rows: list[Path] = [source_lock]
    schema = str(value.get("schema_version") or "")
    if schema == "c2trace.aurora_demos_source_lock.v1":
        local_root = Path(str(value.get("local", {}).get("root") or "")).resolve()
        for row in value.get("files", []):
            if not isinstance(row, Mapping):
                continue
            rows.append(_contained(local_root, str(row.get("path") or "")))
    else:
        artifacts = [row for row in value.get("artifacts", []) if isinstance(row, Mapping)]
        if not artifacts:
            raise ValueError(f"source lock has no artifacts: {source_lock}")
        source_root = source_lock.parent.parent if schema == "c2trace.bench.source_lock.v4" else source_lock.parent
        for row in artifacts:
            relative = str(row.get("path") or row.get("upstream_path") or "")
            if not relative:
                continue
            try:
                rows.append(_contained(source_root, relative))
            except ValueError:
                local_root = str(value.get("local", {}).get("root") or "")
                if not local_root:
                    raise
                rows.append(_contained(Path(local_root).resolve(), relative))
    return source_lock, value, rows


def _receipt_row(project_root: Path, requested: str | Path, *, kind: str, root_id: str) -> dict[str, Any]:
    path = _contained(project_root, requested)
    value = _load_json(path)
    if value.get("live_actions_performed") is not False:
        raise ValueError(f"{kind} crosses the live boundary: {path}")
    if isinstance(value.get("root_id"), str) and value["root_id"] != root_id:
        raise ValueError(f"{kind} receipt root_id drift: {path}")
    if kind == "offline_validation":
        if value.get("valid") is not True:
            raise ValueError("offline validation receipt lacks valid=true")
        if value.get("admitted_case_count") != 0:
            raise ValueError("offline validation receipt must reflect zero admission")
    if "executed" in value and value.get("executed") is not False:
        raise ValueError(f"{kind} receipt crosses the live boundary: {path}")
    if "frozen_source_modified" in value and value.get("frozen_source_modified") is not False:
        raise ValueError(f"{kind} receipt reports source drift: {path}")
    if "artifacts" in value:
        artifacts = value.get("artifacts")
        if not isinstance(artifacts, list):
            raise ValueError(f"{kind} receipt artifacts are malformed: {path}")
        for artifact in artifacts:
            if not isinstance(artifact, Mapping):
                raise ValueError(f"{kind} receipt artifact row is not an object: {path}")
            if artifact.get("executed") is not False:
                raise ValueError(f"{kind} receipt artifact was executed: {path}")
    return {
        "kind": kind,
        "path": _relative(project_root, path),
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def _case_relative(project: Path, benchmark: Path, path: Path) -> str:
    """Return a project-relative POSIX path, preserving the benchmark prefix."""
    return _relative(project, path)


def _controller_binding(project: Path, benchmark: Path, case_root: Path, runtime: Mapping[str, Any]) -> str | None:
    for key in ("controller", "offline_controller", "build_controller", "live_controller"):
        value = runtime.get(key)
        if isinstance(value, str) and value:
            normalized = value.replace("\\", "/")
            if normalized.startswith("cases/"):
                return _relative(project, benchmark / normalized)
            if normalized.startswith("experiments/"):
                return normalized
            return normalized
    offline_check = case_root / "runtime" / "offline_check.py"
    if offline_check.is_file():
        return _relative(project, offline_check)
    return None


def _runtime_controller(project: Path, benchmark: Path, case_root: Path, runtime: Mapping[str, Any]) -> str | None:
    return _controller_binding(project, benchmark, case_root, runtime)


def _inventory(project_root: Path, benchmark_root: Path, root_id: str) -> tuple[Path, list[dict[str, Any]], dict[str, Any], dict[str, Any], dict[str, Any]]:
    case_root, case, _ = _registry_case(benchmark_root, root_id)
    source_lock, source_lock_value, source_paths = _source_artifact_paths(project_root, case)
    source_relative_paths = {
        _relative(project_root, path)
        for path in source_paths
    }
    rows = []
    seen: set[str] = set()
    for path in [*_walk_files(case_root), *source_paths]:
        relative = _relative(project_root, path)
        if relative in seen:
            continue
        seen.add(relative)
        rows.append({"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)})
    if root_id == ROOT_ID:
        public_case = project_root / "asiaccs2027" / "公开资源目录" / "公开资源" / "ctid_micro" / "cases" / "MEP-WINDOWS-WEBSHELL-01"
        if public_case.is_dir():
            for path in _walk_files(public_case):
                relative = _relative(project_root, path)
                if relative in seen or relative in source_relative_paths:
                    continue
                seen.add(relative)
                rows.append({"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)})
    rows.sort(key=lambda row: row["path"])
    return case_root, rows, case, source_lock_value or {}, {"source_lock": source_lock}


def iter_public_tool_files(
    project_root: str | Path,
    benchmark_root: str | Path,
    root_id: str = ROOT_ID,
) -> Iterable[Path]:
    """Yield the deterministic file inventory for one public-tool case."""
    project = Path(project_root).resolve()
    benchmark = Path(benchmark_root).resolve()
    _, rows, _, _, _ = _inventory(project, benchmark, root_id)
    for row in rows:
        yield _contained(project, row["path"])


def _validate_case_state(case: Mapping[str, Any]) -> None:
    readiness = case.get("readiness")
    if not isinstance(readiness, Mapping):
        raise ValueError("case readiness is missing")
    if readiness.get("source_material_frozen") is not True:
        raise ValueError("case source is not frozen")
    if case.get("live_allowed") is not False:
        raise ValueError("case must remain offline-only")


def build_public_tool_lock(
    project_root: str | Path,
    benchmark_root: str | Path,
    *,
    root_id: str = ROOT_ID,
    offline_validation_path: str | Path,
    test_receipt_paths: Sequence[str | Path],
    output_path: str | Path | None = None,
    captured_at_utc: str | None = None,
) -> dict[str, Any]:
    """Build a lock from already-produced offline evidence.

    The lock snapshots the selected case package and the current offline-only
    runtime boundary.  It intentionally does not certify offline-ready or
    admitted status.
    """
    project = Path(project_root).resolve()
    benchmark = Path(benchmark_root).resolve()
    case_root, rows, case, source_lock_value, source_lock_meta = _inventory(project, benchmark, root_id)
    _validate_case_state(case)

    validation = _receipt_row(project, offline_validation_path, kind="offline_validation", root_id=root_id)
    validation_value = _load_json(_contained(project, offline_validation_path))
    if validation_value.get("valid") is not True:
        raise ValueError("offline validation receipt lacks valid=true")
    if validation_value.get("admitted_case_count") != 0:
        raise ValueError("offline validation receipt must reflect zero admission")

    receipts = [validation]
    for path in test_receipt_paths:
        receipts.append(_receipt_row(project, path, kind="test", root_id=root_id))
    if len(receipts) < 2:
        raise ValueError("at least one test receipt is required")

    inventory_paths = {row["path"] for row in rows}
    lock_relative = None
    if output_path:
        try:
            lock_relative = _relative(project, Path(output_path).resolve())
        except ValueError:
            lock_relative = None
    if lock_relative and lock_relative in inventory_paths:
        raise ValueError("software lock must not be included in its own inventory")
    if lock_relative and lock_relative in {row["path"] for row in receipts}:
        raise ValueError("software lock must not self-reference evidence receipts")

    runtime_path = case_root / "runtime" / "manifest.json"
    runtime = _load_json(runtime_path)
    if runtime.get("arbitrary_commands") is not False:
        raise ValueError("runtime permits arbitrary commands")
    if runtime.get("live_actions_performed") is not False:
        raise ValueError("runtime crosses the live boundary")

    source_lock = source_lock_meta.get("source_lock")
    source_lock_path = _case_source_lock(project, case)
    bindings = {
        "case_path": _relative(project, case_root / "case.json"),
        "controller": _controller_binding(project, benchmark, case_root, runtime),
        "runtime_manifest": _relative(project, runtime_path),
        "fidelity": _relative(project, case_root / "fidelity.json"),
        "orchestration_contract": _relative(project, case_root / "orchestration" / "contract.json"),
        "sensor_contract": _relative(project, case_root / "sensor" / "contract.json"),
        "oracle_contract": _relative(project, case_root / "oracle" / "contract.json"),
        "response_contract": _relative(project, case_root / "response" / "contract.json"),
        "source_lock": _relative(project, source_lock_path) if source_lock_path else None,
    }
    if root_id == ROOT_ID:
        source_rows = [row for row in (_load_json(source_lock_path).get("artifacts", []) if source_lock_path else []) if isinstance(row, Mapping)]
        if source_rows:
            payload_row = next((row for row in source_rows if str(row.get("path", "")).endswith("windows_webshell.zip")), None)
            if isinstance(payload_row, Mapping):
                payload_path = _contained(source_lock_path.parent.parent, str(payload_row.get("path") or ""))
                bindings["source_payload"] = _relative(project, payload_path)
                bindings["public_payload"] = bindings["source_payload"]
    if (benchmark / "builds" / root_id).exists():
        bindings["build_root"] = _relative(project, (benchmark / "builds" / root_id).resolve())

    captured = captured_at_utc or datetime.now(timezone.utc).isoformat()
    value = {
        "schema_version": LOCK_SCHEMA,
        "benchmark_id": "c2trace_public_tool_benchmark_v1",
        "root_id": root_id,
        "captured_at_utc": captured,
        "lock_path": lock_relative,
        "project_root": str(project),
        "file_count": len(rows),
        "tree_sha256": _tree_sha256(rows),
        "files": rows,
        "case": {
            "path": _relative(project, case_root / "case.json"),
            "root_id": root_id,
            "source_kind": str(case.get("source", {}).get("kind") or ""),
            "live_allowed": bool(case.get("live_allowed", True)),
            "readiness": dict(case.get("readiness") or {}),
        },
        "runtime": {
            "path": _relative(project, runtime_path),
            "controller": _controller_binding(project, benchmark, case_root, runtime),
            "arbitrary_commands": runtime.get("arbitrary_commands"),
            "live_actions_performed": runtime.get("live_actions_performed"),
            "status": runtime.get("status"),
        },
        "bindings": bindings,
        "receipts": {
            "offline_validation": validation,
            "tests": receipts[1:],
        },
        "source_lock": {
            "path": _relative(project, source_lock_path) if source_lock_path else None,
            "schema_version": source_lock_meta.get("schema_version") if isinstance(source_lock_meta, Mapping) else None,
        },
        "safety": {
            "live_allowed": False,
            "components_started": False,
            "handler_started": False,
            "implant_started": False,
            "caldera_operation_started": False,
            "suricata_live_started": False,
            "c2trace_live_executed": False,
            "response_executed": False,
            "reference_response_executed": False,
            "cleanup_executed": False,
            "live_actions_performed": False,
            "admitted": False,
        },
        "live_actions_performed": False,
        "runtime_environment": {
            "python_executable": sys.executable,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
        },
    }
    return value


def verify_public_tool_lock(
    project_root: str | Path,
    benchmark_root: str | Path,
    lock: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify a public-tool lock without starting any component."""
    project = Path(project_root).resolve()
    benchmark = Path(benchmark_root).resolve()
    errors: list[str] = []
    missing: list[str] = []
    added: list[str] = []
    drifted: list[str] = []
    actual_tree = ""
    actual_rows: dict[str, dict[str, Any]] = {}

    if lock.get("schema_version") != LOCK_SCHEMA:
        errors.append("invalid schema_version")
    root_id = str(lock.get("root_id") or "")
    if not root_id:
        errors.append("missing root_id")
        root_id = ROOT_ID

    try:
        case_root, rows, case, _, _ = _inventory(project, benchmark, root_id)
        actual_rows = {row["path"]: row for row in rows}
        expected_rows = lock.get("files")
        if not isinstance(expected_rows, list) or not expected_rows:
            raise ValueError("files array is missing or empty")
        expected: dict[str, dict[str, Any]] = {}
        duplicates: list[str] = []
        for raw in expected_rows:
            if not isinstance(raw, Mapping):
                errors.append("file row is not an object")
                continue
            try:
                path = _validate_relative(str(raw.get("path") or ""))
            except ValueError as exc:
                errors.append(str(exc))
                continue
            if path in expected:
                duplicates.append(path)
            expected[path] = dict(raw)
        if duplicates:
            errors.append("duplicate paths: " + ", ".join(sorted(set(duplicates))))

        lock_path = lock.get("lock_path")
        if lock_path:
            try:
                if _validate_relative(str(lock_path)) in expected:
                    errors.append("lock self-reference")
            except ValueError as exc:
                errors.append(str(exc))

        missing = sorted(set(expected) - set(actual_rows))
        added = sorted(set(actual_rows) - set(expected))
        for path in sorted(set(expected) & set(actual_rows)):
            if (
                str(expected[path].get("sha256") or "").lower() != actual_rows[path]["sha256"].lower()
                or int(expected[path].get("size", -1)) != actual_rows[path]["size"]
            ):
                drifted.append(path)
        expected_tree = str(lock.get("tree_sha256") or "")
        actual_tree = _tree_sha256(list(actual_rows.values()))
        if expected_tree != actual_tree:
            errors.append("tree hash drift")
        if int(lock.get("file_count", -1)) != len(actual_rows):
            errors.append("file_count drift")
        if missing:
            errors.append("missing files: " + ", ".join(missing))
        if added:
            errors.append("added files: " + ", ".join(added))
        if drifted:
            errors.append("changed files: " + ", ".join(drifted))

        bindings = lock.get("bindings")
        if not isinstance(bindings, Mapping):
            errors.append("missing bindings")
        else:
            expected_bindings = {
                "case_path": _relative(project, case_root / "case.json"),
                "runtime_manifest": _relative(project, case_root / "runtime" / "manifest.json"),
                "fidelity": _relative(project, case_root / "fidelity.json"),
                "orchestration_contract": _relative(project, case_root / "orchestration" / "contract.json"),
                "sensor_contract": _relative(project, case_root / "sensor" / "contract.json"),
                "oracle_contract": _relative(project, case_root / "oracle" / "contract.json"),
                "response_contract": _relative(project, case_root / "response" / "contract.json"),
            }
            source_lock_path = _case_source_lock(project, case)
            expected_bindings["source_lock"] = _relative(project, source_lock_path) if source_lock_path else None
            runtime_value = _load_json(case_root / "runtime" / "manifest.json")
            actual_controller = _controller_binding(project, benchmark, case_root, runtime_value)
            if bindings.get("controller") != actual_controller:
                errors.append("controller drift")
            for key, expected_value in expected_bindings.items():
                if bindings.get(key) != expected_value:
                    errors.append(f"binding drift: {key}")
                    break
            if root_id == ROOT_ID:
                source_lock_value = _load_json(source_lock_path) if source_lock_path else {}
                source_rows = [row for row in source_lock_value.get("artifacts", []) if isinstance(row, Mapping)]
                payload_row = next((row for row in source_rows if str(row.get("path", "")).endswith("windows_webshell.zip")), None)
                if isinstance(payload_row, Mapping):
                    payload_path = _contained(source_lock_path.parent.parent, str(payload_row.get("path") or "")) if source_lock_path else None
                    if payload_path is not None:
                        if bindings.get("source_payload") != _relative(project, payload_path):
                            errors.append("binding drift: source_payload")
                        if bindings.get("public_payload") != _relative(project, payload_path):
                            errors.append("binding drift: public_payload")

        receipts = lock.get("receipts")
        if not isinstance(receipts, Mapping):
            errors.append("missing receipts")
        else:
            def _check_receipt(row: Mapping[str, Any] | object, label: str) -> None:
                if not isinstance(row, Mapping):
                    errors.append(f"{label} receipt row is not an object")
                    return
                try:
                    path = _contained(project, str(row.get("path") or ""))
                except ValueError as exc:
                    errors.append(f"{label} receipt path error: {exc}")
                    return
                size = path.stat().st_size
                digest = sha256_file(path)
                if int(row.get("size", -1)) != size:
                    errors.append(f"{label} receipt size drift: {path.relative_to(project).as_posix()}")
                if str(row.get("sha256") or "").lower() != digest.lower():
                    errors.append(f"{label} receipt hash drift: {path.relative_to(project).as_posix()}")
                value = _load_json(path)
                if value.get("live_actions_performed") is not False:
                    errors.append(f"{label} receipt crosses the live boundary: {path.relative_to(project).as_posix()}")
                if isinstance(value.get("root_id"), str) and value["root_id"] != root_id:
                    errors.append(f"{label} receipt root_id drift: {path.relative_to(project).as_posix()}")
                if "executed" in value and value.get("executed") is not False:
                    errors.append(f"{label} receipt was executed: {path.relative_to(project).as_posix()}")
                if "artifacts" in value:
                    artifacts = value.get("artifacts")
                    if not isinstance(artifacts, list):
                        errors.append(f"{label} receipt artifacts are malformed: {path.relative_to(project).as_posix()}")
                        return
                    for artifact in artifacts:
                        if not isinstance(artifact, Mapping):
                            errors.append(f"{label} receipt artifact row is not an object: {path.relative_to(project).as_posix()}")
                            continue
                        if artifact.get("executed") is not False:
                            errors.append(f"{label} receipt artifact was executed: {path.relative_to(project).as_posix()}")

            _check_receipt(receipts.get("offline_validation"), "offline_validation")
            test_rows = receipts.get("tests")
            if not isinstance(test_rows, list) or not test_rows:
                errors.append("missing test receipts")
            else:
                for index, row in enumerate(test_rows, start=1):
                    _check_receipt(row, f"test#{index}")

        runtime = lock.get("runtime")
        if not isinstance(runtime, Mapping):
            errors.append("missing runtime")
        else:
            runtime_value = _load_json(case_root / "runtime" / "manifest.json")
            if runtime.get("arbitrary_commands") is not False or runtime_value.get("arbitrary_commands") is not False:
                errors.append("runtime permits arbitrary commands")
            if runtime.get("live_actions_performed") is not False or runtime_value.get("live_actions_performed") is not False:
                errors.append("runtime crosses the live boundary")
            if runtime.get("status") != runtime_value.get("status"):
                errors.append("runtime status drift")

        if lock.get("live_actions_performed") is not False:
            errors.append("lock is not offline-only")

        expected_safety = {
            "live_allowed": False,
            "components_started": False,
            "handler_started": False,
            "implant_started": False,
            "caldera_operation_started": False,
            "suricata_live_started": False,
            "c2trace_live_executed": False,
            "response_executed": False,
            "reference_response_executed": False,
            "cleanup_executed": False,
            "live_actions_performed": False,
            "admitted": False,
        }
        if dict(lock.get("safety") or {}) != expected_safety:
            errors.append("safety-state drift")

    except (OSError, TypeError, ValueError, KeyError) as exc:
        errors.append(str(exc))

    return {
        "schema_version": VERIFY_SCHEMA,
        "valid": not errors,
        "errors": errors,
        "missing": missing,
        "added": added,
        "drifted": drifted,
        "expected_tree_sha256": str(lock.get("tree_sha256") or ""),
        "actual_tree_sha256": actual_tree,
        "checked_file_count": len(actual_rows),
        "live_actions_performed": False,
    }


__all__ = [
    "LOCK_SCHEMA",
    "ROOT_ID",
    "build_public_tool_lock",
    "iter_public_tool_files",
    "sha256_file",
    "verify_public_tool_lock",
]
