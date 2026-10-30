from __future__ import annotations

"""Read-only replay of the two historical v5 target-drift batches."""

from hashlib import sha256
import json
import ntpath
from pathlib import Path
from typing import Any, Iterable, Mapping

from c2trace.time_identity import compare_creation_times, normalize_creation_time


def _load_json(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    payload = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return payload, sha256(raw).hexdigest()


def _walk(value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _path(value: Any) -> str:
    raw = str(value or "").strip().strip('"')
    return ntpath.normcase(ntpath.normpath(raw.replace("/", "\\"))) if raw else ""


def _pid(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _process_observation(snapshot: Mapping[str, Any], expected: Mapping[str, Any]) -> dict[str, Any]:
    expected_pid = _pid(expected.get("pid"))
    expected_path = _path(expected.get("path"))
    candidates: list[dict[str, Any]] = []
    for item in _walk(snapshot):
        if item.get("tool") != "check_process":
            continue
        data = item.get("data") if isinstance(item.get("data"), Mapping) else {}
        rows = data.get("processes") if isinstance(data.get("processes"), list) else []
        for row in rows:
            if not isinstance(row, Mapping) or _pid(row.get("pid") or row.get("process_id")) != expected_pid:
                continue
            candidates.append(dict(row))
    if not candidates:
        return {}
    exact_paths = [
        item for item in candidates
        if _path(item.get("path") or item.get("process_path") or item.get("executable_path")) == expected_path
    ]
    return dict((exact_paths or candidates)[-1])


def _file_observation(snapshot: Mapping[str, Any], expected: Mapping[str, Any]) -> dict[str, Any]:
    expected_path = _path(expected.get("path"))
    candidates: list[dict[str, Any]] = []
    for item in _walk(snapshot):
        if item.get("tool") != "check_file_metadata":
            continue
        data = item.get("data") if isinstance(item.get("data"), Mapping) else {}
        file_info = data.get("file") if isinstance(data.get("file"), Mapping) else None
        if isinstance(file_info, Mapping) and _path(file_info.get("path")) == expected_path:
            candidates.append(dict(file_info))
    return dict(candidates[-1]) if candidates else {}


def _historical_target_drift(casefile: Mapping[str, Any]) -> bool:
    if casefile.get("final_status") != "target_drift":
        return False
    for error in casefile.get("errors", []):
        if not isinstance(error, Mapping):
            continue
        details = error.get("details") if isinstance(error.get("details"), Mapping) else {}
        if "process.creation_time_utc" in list(details.get("differences") or []):
            return True
    return False


def analyze_trial(trial_root: str | Path) -> dict[str, Any]:
    root = Path(trial_root).resolve()
    manifest_path = root / "protected_processes.v2.json"
    snapshot_path = root / "evidence" / "before_response.json"
    casefile_path = root / "c2trace_dryrun" / "casefile.json"
    manifest, manifest_hash = _load_json(manifest_path)
    snapshot, snapshot_hash = _load_json(snapshot_path)
    casefile, casefile_hash = _load_json(casefile_path)
    expected = manifest.get("expected_target") if isinstance(manifest.get("expected_target"), Mapping) else {}
    observed_process = _process_observation(snapshot, expected)
    observed_file = _file_observation(snapshot, expected)
    expected_creation = str(expected.get("creation_time_utc") or "")
    observed_creation = str(
        observed_process.get("creation_time_utc")
        or observed_process.get("creation_date")
        or ""
    )
    time_comparison = compare_creation_times(expected_creation, observed_creation)
    identity = {
        "pid_matches": _pid(expected.get("pid")) == _pid(observed_process.get("pid")),
        "path_matches": _path(expected.get("path")) == _path(
            observed_process.get("path")
            or observed_process.get("process_path")
            or observed_process.get("executable_path")
        ),
        "sha256_matches": (
            str(expected.get("sha256") or "").strip().casefold()
            == str(observed_file.get("sha256") or "").strip().casefold()
        ),
    }
    other_identity_matches = all(identity.values())
    legacy_exact_match = (
        normalize_creation_time(expected_creation)
        == normalize_creation_time(observed_creation)
    )
    return {
        "trial_id": root.name,
        "case_id": str(manifest.get("case_id") or casefile.get("case_id") or ""),
        "source_files": {
            "protected_processes": {"path": str(manifest_path), "sha256": manifest_hash},
            "before_response": {"path": str(snapshot_path), "sha256": snapshot_hash},
            "casefile": {"path": str(casefile_path), "sha256": casefile_hash},
        },
        "historical_result": {
            "final_status": str(casefile.get("final_status") or ""),
            "creation_time_target_drift": _historical_target_drift(casefile),
        },
        "expected_process": {
            "pid": _pid(expected.get("pid")),
            "path": str(expected.get("path") or ""),
            "creation_time_utc": expected_creation,
            "sha256": str(expected.get("sha256") or "").lower(),
        },
        "observed_process": {
            "pid": _pid(observed_process.get("pid")),
            "path": str(observed_process.get("path") or observed_process.get("process_path") or ""),
            "creation_time_utc": observed_creation,
            "sha256": str(observed_file.get("sha256") or "").lower(),
        },
        "legacy_normalized_string_match": legacy_exact_match,
        "fixed_time_comparison": time_comparison.to_dict(),
        "other_identity": {**identity, "all_match": other_identity_matches},
        "candidate_fixed_gate_pass": bool(time_comparison.matches and other_identity_matches),
        "interpretation": (
            "historical false target_drift is explained by representation-sensitive exact comparison"
            if _historical_target_drift(casefile)
            and not legacy_exact_match
            and time_comparison.matches
            and other_identity_matches
            else "historical trial requires additional review"
        ),
    }


def analyze_batches(batch_roots: Iterable[str | Path]) -> dict[str, Any]:
    trials: list[dict[str, Any]] = []
    batches: list[str] = []
    for batch_root in batch_roots:
        root = Path(batch_root).resolve()
        batches.append(str(root))
        trial_dir = root / "trials"
        for child in sorted(trial_dir.iterdir()):
            if child.is_dir() and (child / "protected_processes.v2.json").exists():
                trials.append(analyze_trial(child))
    return {
        "schema_version": "c2trace.target_drift_replay.v1",
        "read_only_replay": True,
        "source_batches": batches,
        "summary": {
            "trial_count": len(trials),
            "historical_creation_time_target_drift_count": sum(
                item["historical_result"]["creation_time_target_drift"] is True
                for item in trials
            ),
            "legacy_exact_mismatch_count": sum(
                item["legacy_normalized_string_match"] is False for item in trials
            ),
            "fixed_time_match_count": sum(
                item["fixed_time_comparison"]["matches"] is True for item in trials
            ),
            "other_identity_match_count": sum(
                item["other_identity"]["all_match"] is True for item in trials
            ),
            "candidate_fixed_gate_pass_count": sum(
                item["candidate_fixed_gate_pass"] is True for item in trials
            ),
        },
        "trials": trials,
        "caveat": (
            "This is an offline replay of preserved observations. It does not reclassify historical trials "
            "and does not prove that a new live response will execute successfully."
        ),
    }


def render_markdown(report: Mapping[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), Mapping) else {}
    lines = [
        "# C2Trace v5 target-drift offline replay",
        "",
        "> Read-only diagnostic. Historical CaseFiles and classifications were not modified.",
        "",
        "## Summary",
        "",
        f"- Trials replayed: {summary.get('trial_count', 0)}",
        f"- Historical creation-time target drift: {summary.get('historical_creation_time_target_drift_count', 0)}",
        f"- Legacy normalized-string mismatches: {summary.get('legacy_exact_mismatch_count', 0)}",
        f"- Unified UTC comparator matches: {summary.get('fixed_time_match_count', 0)}",
        f"- PID/path/hash identity matches: {summary.get('other_identity_match_count', 0)}",
        f"- Candidate fixed gate passes: {summary.get('candidate_fixed_gate_pass_count', 0)}",
        "",
        "## Trials",
        "",
        "| Trial | Legacy exact | UTC delta (ms) | Other identity | Candidate gate |",
        "|---|---:|---:|---:|---:|",
    ]
    for item in report.get("trials", []):
        if not isinstance(item, Mapping):
            continue
        comparison = item.get("fixed_time_comparison") if isinstance(item.get("fixed_time_comparison"), Mapping) else {}
        identity = item.get("other_identity") if isinstance(item.get("other_identity"), Mapping) else {}
        lines.append(
            f"| {item.get('trial_id', '')} | {item.get('legacy_normalized_string_match')} | "
            f"{comparison.get('delta_ms')} | {identity.get('all_match')} | "
            f"{item.get('candidate_fixed_gate_pass')} |"
        )
    lines.extend(["", "## Caveat", "", str(report.get("caveat") or ""), ""])
    return "\n".join(lines)

