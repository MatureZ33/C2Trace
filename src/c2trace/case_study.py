from __future__ import annotations

"""Offline validation and evidence/report helpers for the WebShell Case Study.

This module never starts CALDERA, Suricata, a WebShell, or a response action.
Live orchestration remains in the frozen Bench v4 controller and is invoked
only by the explicit operator wrapper in ``case_study/scripts``.
"""

import csv
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any, Callable, Iterable, Mapping
import zipfile

from c2trace.llm import DeepSeekClient, LLMError


CASE_ID = "CS-MEP-WEBSHELL-001"
EXECUTION_CASE_ID = "MEP-WINDOWS-WEBSHELL-01"
SOURCE_COMMIT = "4467a6eed6e67d25009704130e1d27d1a8007f57"
ARCHIVE_SHA256 = "056bb041b34d619e31c90639af508a2e6428fd42ccdad28e2d97f0360c333540"
ARCHIVE_SIZE = 5_638_451
EXECUTABLE_MEMBER = "build/windows/shell/windowswebshell.exe"
EXECUTABLE_SHA256 = "e47143e88931d45d0b3b8d012783e52665a7f4b689728d6ba00d8f61bcd1ebea"
EXECUTABLE_SIZE = 4_590_080
DETECTION_SID = 9_204_005
EXPECTED_TRACE_IDS = (
    "trace.webshell.file",
    "trace.webshell.process",
    "trace.webshell.listener",
    "trace.webshell.groups.file",
    "trace.webshell.tasks.file",
)
EXPECTED_HOST_CAPTURES = (
    "bootstrap",
    "scenario_detection",
    "dry_run",
    "execute_verify",
)
PUBLIC_BEHAVIORS = {
    "7d8a50d4-9e38-50f4-bf5a-e34b7509e837": "T1505.003 WebShell start",
    "dc934e5a-3184-5b6f-8535-a78cc2adfac5": "T1069.001 Local groups discovery",
    "87bd9d84-f8b7-5810-9a53-ce0a9cdb589d": "T1057 Process discovery",
}
SUPPORT_ABILITY_ID = "03677b83-9e45-54e3-9d87-b10d6ba2c201"


class CaseStudyError(RuntimeError):
    """Raised when a Case Study contract or artifact is unsafe/incomplete."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_hash(value: Mapping[str, Any]) -> str:
    raw = json.dumps(
        dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return sha256(raw).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CaseStudyError(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise CaseStudyError(f"JSON root must be an object: {path}")
    return value


def read_yaml(path: Path) -> Any:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - PyYAML is present in the project venv
        raise CaseStudyError("PyYAML is required for Case Study validation") from exc
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise CaseStudyError(f"invalid YAML: {path}") from exc


def write_json_atomic(path: Path, value: Mapping[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(dict(value), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)
    return path


def _assert_contained(path: Path, root: Path, label: str) -> Path:
    resolved = path.resolve()
    allowed = root.resolve()
    try:
        resolved.relative_to(allowed)
    except ValueError as exc:
        raise CaseStudyError(f"{label} is outside {allowed}") from exc
    return resolved


def _single_yaml_object(path: Path) -> dict[str, Any]:
    value = read_yaml(path)
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], Mapping):
        return dict(value[0])
    if isinstance(value, Mapping):
        return dict(value)
    raise CaseStudyError(f"expected one YAML object: {path}")


def validate_case_study(case_root: Path, project_root: Path) -> dict[str, Any]:
    """Validate every frozen static input without network or host probes."""

    case_root = case_root.resolve()
    project_root = project_root.resolve()
    checks: list[dict[str, Any]] = []
    errors: list[str] = []

    def check(name: str, action: Callable[[], Mapping[str, Any] | None]) -> None:
        try:
            details = dict(action() or {})
            checks.append({"name": name, "passed": True, "details": details})
        except Exception as exc:
            message = f"{name}: {type(exc).__name__}: {exc}"
            errors.append(message)
            checks.append({"name": name, "passed": False, "error": message})

    manifest_path = case_root / "scenario" / "case_study_manifest.yaml"
    ground_truth_path = case_root / "scenario" / "ground_truth.yaml"
    detection_path = case_root / "scenario" / "detection_contract.yaml"
    cleanup_path = case_root / "scenario" / "cleanup_contract.yaml"
    payload_path = case_root / "assets" / "payload_manifest.json"
    archive_path = case_root / "assets" / "c2t_windows_webshell_056bb041.zip"
    source_lock_path = case_root / "sources" / "source_lock.json"
    install_manifest_path = case_root / "caldera" / "install_manifest.json"

    def validate_identity() -> Mapping[str, Any]:
        manifest = read_yaml(manifest_path)
        if not isinstance(manifest, Mapping):
            raise CaseStudyError("case_study_manifest root must be an object")
        if manifest.get("case_id") != CASE_ID:
            raise CaseStudyError("Case Study ID drifted")
        if manifest.get("execution_case_id") != EXECUTION_CASE_ID:
            raise CaseStudyError("execution Case ID drifted")
        source = manifest.get("source") if isinstance(manifest.get("source"), Mapping) else {}
        if source.get("commit") != SOURCE_COMMIT:
            raise CaseStudyError("source commit drifted")
        if source.get("license") != "Apache-2.0":
            raise CaseStudyError("source license drifted")
        lab = manifest.get("lab") if isinstance(manifest.get("lab"), Mapping) else {}
        if list(lab.get("webshell_port_range") or []) != [18080, 18979]:
            raise CaseStudyError("WebShell port range drifted")
        model = manifest.get("model") if isinstance(manifest.get("model"), Mapping) else {}
        if model.get("name") != "deepseek-v4-flash":
            raise CaseStudyError("formal Case Study model drifted")
        return {"case_id": CASE_ID, "execution_case_id": EXECUTION_CASE_ID}

    check("case_identity_and_manifest", validate_identity)

    def validate_source_lock() -> Mapping[str, Any]:
        lock = read_json(source_lock_path)
        revision = lock.get("revision") if isinstance(lock.get("revision"), Mapping) else {}
        license_row = lock.get("license") if isinstance(lock.get("license"), Mapping) else {}
        if revision.get("commit") != SOURCE_COMMIT:
            raise CaseStudyError("source_lock commit drifted")
        if license_row.get("spdx") != "Apache-2.0":
            raise CaseStudyError("source_lock license drifted")
        artifacts = [row for row in lock.get("artifacts", []) if isinstance(row, Mapping)]
        by_path = {str(row.get("path") or ""): row for row in artifacts}
        required = {
            "ctid_micro/raw/micro_emulation_plans/src/webshell/README.md": (
                case_root / "sources" / "upstream_webshell_plan.md"
            ),
            "ctid_micro/raw/micro_emulation_plans/src/webshell/README_windows_webshell.md": (
                case_root / "sources" / "upstream_windows_instructions.md"
            ),
            "ctid_micro/raw/micro_emulation_plans/src/webshell/windows_webshell.zip": archive_path,
        }
        for locked_path, local_path in required.items():
            row = by_path.get(locked_path)
            if row is None:
                raise CaseStudyError(f"source_lock lacks {locked_path}")
            if not local_path.is_file():
                raise CaseStudyError(f"materialized source is missing: {local_path}")
            if sha256_file(local_path) != str(row.get("sha256") or "").casefold():
                raise CaseStudyError(f"materialized source hash drifted: {local_path.name}")
            if local_path.stat().st_size != int(row.get("size") or -1):
                raise CaseStudyError(f"materialized source size drifted: {local_path.name}")
        return {"commit": SOURCE_COMMIT, "locked_artifact_count": len(artifacts)}

    check("source_lock_and_materialized_sources", validate_source_lock)

    def validate_payload() -> Mapping[str, Any]:
        manifest = read_json(payload_path)
        archive = manifest.get("archive") if isinstance(manifest.get("archive"), Mapping) else {}
        executable = manifest.get("executable") if isinstance(manifest.get("executable"), Mapping) else {}
        if manifest.get("case_id") != CASE_ID or manifest.get("execution_case_id") != EXECUTION_CASE_ID:
            raise CaseStudyError("payload manifest identity drifted")
        if archive.get("sha256") != ARCHIVE_SHA256:
            raise CaseStudyError("payload manifest archive hash drifted")
        if executable.get("zip_member") != EXECUTABLE_MEMBER:
            raise CaseStudyError("payload member path drifted")
        if executable.get("sha256") != EXECUTABLE_SHA256:
            raise CaseStudyError("payload executable hash drifted")
        if int(executable.get("size") or -1) != EXECUTABLE_SIZE:
            raise CaseStudyError("payload executable size drifted")
        if archive_path.stat().st_size != ARCHIVE_SIZE:
            raise CaseStudyError("payload archive size drifted")
        if sha256_file(archive_path) != ARCHIVE_SHA256:
            raise CaseStudyError("payload archive hash drifted")
        with zipfile.ZipFile(archive_path, "r") as archive_file:
            names = archive_file.namelist()
            if names.count(EXECUTABLE_MEMBER) != 1:
                raise CaseStudyError("archive does not contain exactly one pinned executable")
            if any(
                name.startswith(("/", "\\")) or ".." in Path(name).parts
                for name in names
            ):
                raise CaseStudyError("archive contains an unsafe member path")
            info = archive_file.getinfo(EXECUTABLE_MEMBER)
            if info.file_size != EXECUTABLE_SIZE:
                raise CaseStudyError("embedded executable size drifted")
            digest = sha256()
            with archive_file.open(info, "r") as member:
                for chunk in iter(lambda: member.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest() != EXECUTABLE_SHA256:
                raise CaseStudyError("embedded executable hash drifted")
        return {
            "archive_sha256": ARCHIVE_SHA256,
            "archive_size": ARCHIVE_SIZE,
            "executable_sha256": EXECUTABLE_SHA256,
            "executable_size": EXECUTABLE_SIZE,
        }

    check("payload_archive_and_embedded_executable", validate_payload)

    def validate_caldera_assets() -> Mapping[str, Any]:
        install = read_json(install_manifest_path)
        if install.get("case_id") != EXECUTION_CASE_ID:
            raise CaseStudyError("CALDERA install manifest case drifted")
        expected_abilities = {
            "03677b83-9e45-54e3-9d87-b10d6ba2c201": "T1105",
            "7d8a50d4-9e38-50f4-bf5a-e34b7509e837": "T1505.003",
            "dc934e5a-3184-5b6f-8535-a78cc2adfac5": "T1069.001",
            "87bd9d84-f8b7-5810-9a53-ce0a9cdb589d": "T1057",
        }
        rows = [row for row in install.get("abilities", []) if isinstance(row, Mapping)]
        if {str(row.get("id") or "") for row in rows} != set(expected_abilities):
            raise CaseStudyError("CALDERA ability set drifted")
        for row in rows:
            ability_id = str(row["id"])
            path = case_root / "caldera" / "abilities" / f"{ability_id}.yml"
            if sha256_file(path) != str(row.get("sha256") or "").casefold():
                raise CaseStudyError(f"ability hash drifted: {ability_id}")
            ability = _single_yaml_object(path)
            technique = ability.get("technique") if isinstance(ability.get("technique"), Mapping) else {}
            if technique.get("attack_id") != expected_abilities[ability_id]:
                raise CaseStudyError(f"ability technique drifted: {ability_id}")
        adversary_rows = [
            row for row in install.get("adversaries", []) if isinstance(row, Mapping)
        ]
        if len(adversary_rows) != 2:
            raise CaseStudyError("expected two CALDERA adversaries")
        all_ability_ids = set(expected_abilities)
        observed_order: list[str] = []
        for row in adversary_rows:
            adversary_id = str(row.get("id") or "")
            path = case_root / "caldera" / "adversaries" / f"{adversary_id}.yml"
            if sha256_file(path) != str(row.get("sha256") or "").casefold():
                raise CaseStudyError(f"adversary hash drifted: {adversary_id}")
            adversary = _single_yaml_object(path)
            ordering = [str(value) for value in adversary.get("atomic_ordering", [])]
            if not ordering or not set(ordering).issubset(all_ability_ids):
                raise CaseStudyError(f"adversary ordering drifted: {adversary_id}")
            observed_order.extend(ordering)
        if observed_order != [
            "dc934e5a-3184-5b6f-8535-a78cc2adfac5",
            "87bd9d84-f8b7-5810-9a53-ce0a9cdb589d",
            "03677b83-9e45-54e3-9d87-b10d6ba2c201",
            "7d8a50d4-9e38-50f4-bf5a-e34b7509e837",
        ]:
            # The install manifest sorts adversary IDs, so the two operations
            # are validated individually below rather than relying on file order.
            order_sets = {tuple(_single_yaml_object(case_root / "caldera" / "adversaries" / f"{row['id']}.yml").get("atomic_ordering", [])) for row in adversary_rows}
            wanted_sets = {
                (
                    "03677b83-9e45-54e3-9d87-b10d6ba2c201",
                    "7d8a50d4-9e38-50f4-bf5a-e34b7509e837",
                ),
                (
                    "dc934e5a-3184-5b6f-8535-a78cc2adfac5",
                    "87bd9d84-f8b7-5810-9a53-ce0a9cdb589d",
                ),
            }
            if order_sets != wanted_sets:
                raise CaseStudyError("CALDERA adversary operation ordering drifted")
        return {"ability_count": 4, "adversary_count": 2}

    check("caldera_assets_and_attack_mapping", validate_caldera_assets)

    def validate_contracts() -> Mapping[str, Any]:
        ground_truth = read_yaml(ground_truth_path)
        detection = read_yaml(detection_path)
        cleanup = read_yaml(cleanup_path)
        if not all(isinstance(value, Mapping) for value in (ground_truth, detection, cleanup)):
            raise CaseStudyError("scenario contract root must be an object")
        if ground_truth.get("planner_visible") is not False:
            raise CaseStudyError("Ground Truth must be hidden from Planner")
        facts = [row for row in ground_truth.get("facts", []) if isinstance(row, Mapping)]
        if tuple(str(row.get("id") or "") for row in facts) != EXPECTED_TRACE_IDS:
            raise CaseStudyError("five-trace Ground Truth order/set drifted")
        response = [row for row in ground_truth.get("expected_response", []) if isinstance(row, Mapping)]
        if [row.get("tool") for row in response] != ["kill_process", "remove_file"]:
            raise CaseStudyError("response tool contract drifted")
        if any(row.get("exact_once") is not True for row in response):
            raise CaseStudyError("response actions must be exact-once")
        if int(detection.get("signature_id") or 0) != DETECTION_SID:
            raise CaseStudyError("Suricata SID drifted")
        selector = detection.get("selector") if isinstance(detection.get("selector"), Mapping) else {}
        if selector.get("src_ip") != "192.168.21.132" or selector.get("dest_ip") != "192.168.21.145":
            raise CaseStudyError("Suricata direction drifted")
        if list(selector.get("dest_port_range") or []) != [18080, 18979]:
            raise CaseStudyError("Suricata port range drifted")
        if cleanup.get("phase") != "after_scoring_and_capture":
            raise CaseStudyError("cleanup phase drifted")
        if cleanup.get("automatic_retry") is not False:
            raise CaseStudyError("automatic live retry must remain disabled")
        return {"trace_count": 5, "response_action_count": 2, "sid": DETECTION_SID}

    check("ground_truth_detection_and_cleanup_contracts", validate_contracts)

    def validate_frozen_runtime() -> Mapping[str, Any]:
        runtime_root = (
            project_root
            / "experiments"
            / "c2trace_bench_v4"
            / "ctid_micro"
            / "cases"
            / EXECUTION_CASE_ID
        )
        if not (runtime_root / "case.json").is_file():
            raise CaseStudyError("frozen Bench v4 WebShell runtime is missing")
        for category in ("abilities", "adversaries", "sources"):
            case_files = sorted((case_root / "caldera" / category).glob("*.yml"))
            runtime_files = sorted((runtime_root / "caldera" / category).glob("*.yml"))
            if [path.name for path in case_files] != [path.name for path in runtime_files]:
                raise CaseStudyError(f"runtime {category} file set drifted")
            for local, frozen in zip(case_files, runtime_files, strict=True):
                if sha256_file(local) != sha256_file(frozen):
                    raise CaseStudyError(f"runtime copy drifted: {local.name}")
        frozen_archive = (
            runtime_root
            / "caldera"
            / "payloads"
            / "c2t_v4_windows_webshell_056bb041.zip"
        )
        if sha256_file(frozen_archive) != ARCHIVE_SHA256:
            raise CaseStudyError("frozen runtime payload drifted")
        return {"runtime_root": str(runtime_root), "payload_sha256": ARCHIVE_SHA256}

    check("frozen_bench_v4_runtime_binding", validate_frozen_runtime)

    report = {
        "schema_version": "c2trace.case_study.offline_validation.v1",
        "case_id": CASE_ID,
        "execution_case_id": EXECUTION_CASE_ID,
        "validated_at_utc": utc_now(),
        "offline_only": True,
        "passed": not errors,
        "check_count": len(checks),
        "checks": checks,
        "errors": errors,
    }
    return report


def run_llm_role_preflight(
    *,
    model: str = "deepseek-v4-flash",
    client_factory: Callable[..., Any] = DeepSeekClient,
) -> dict[str, Any]:
    """Run two low-token structured calls and return a sanitized receipt."""

    if model != "deepseek-v4-flash":
        raise CaseStudyError("formal Case Study LLM preflight requires deepseek-v4-flash")
    client = client_factory(model=model, max_transient_retries=1)
    roles: list[dict[str, Any]] = []
    specifications = (
        (
            "planner",
            "Return only a JSON object proving the Planner JSON control path is ready.",
            {
                "task": "C2Trace Case Study Planner preflight; do not plan a real incident.",
                "output_schema": {
                    "role": "planner",
                    "ready": True,
                    "nodes": [
                        {
                            "node_id": "preflight-readonly",
                            "type": "investigate",
                            "tool": "check_network",
                        }
                    ],
                },
            },
        ),
        (
            "auditor",
            "Return only a JSON object proving the Auditor semantic JSON control path is ready.",
            {
                "task": "C2Trace Case Study Auditor preflight; do not authorize any action.",
                "output_schema": {
                    "role": "auditor",
                    "ready": True,
                    "reason": "short readiness statement",
                },
            },
        ),
    )
    for role, system_prompt, payload in specifications:
        first_record = len(getattr(client, "usage_records", []))
        try:
            parsed = client.chat_json(
                system_prompt=system_prompt,
                user_payload=payload,
                temperature=0.0,
                max_tokens=220,
            )
            if str(parsed.get("role") or "").casefold() != role:
                raise CaseStudyError(f"{role} preflight role field drifted")
            if parsed.get("ready") is not True:
                raise CaseStudyError(f"{role} preflight did not return ready=true")
            if role == "planner":
                nodes = parsed.get("nodes")
                if not isinstance(nodes, list) or not nodes:
                    raise CaseStudyError("Planner preflight returned no nodes")
                node = nodes[0] if isinstance(nodes[0], Mapping) else {}
                if node.get("type") != "investigate" or node.get("tool") != "check_network":
                    raise CaseStudyError("Planner preflight node schema drifted")
            else:
                if not str(parsed.get("reason") or "").strip():
                    raise CaseStudyError("Auditor preflight returned no reason")
            records = [dict(row) for row in client.usage_records[first_record:]]
            successful = [row for row in records if row.get("success") is True]
            total_tokens = sum(int(row.get("total_tokens") or 0) for row in successful)
            if not successful or total_tokens <= 0:
                raise CaseStudyError(f"{role} preflight token usage is missing")
            roles.append(
                {
                    "role": role,
                    "passed": True,
                    "total_tokens": total_tokens,
                    "calls": records,
                }
            )
        except Exception as exc:
            records = [dict(row) for row in client.usage_records[first_record:]]
            roles.append(
                {
                    "role": role,
                    "passed": False,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "calls": records,
                }
            )
            break
    passed = len(roles) == 2 and all(row.get("passed") is True for row in roles)
    return {
        "schema_version": "c2trace.case_study.llm_preflight.v1",
        "case_id": CASE_ID,
        "captured_at_utc": utc_now(),
        "model": model,
        "passed": passed,
        "roles": roles,
        "secret_material_persisted": False,
    }


def _copy_verified(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise CaseStudyError(f"source artifact is missing: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if not destination.is_file() or sha256_file(source) != sha256_file(destination):
            raise CaseStudyError(f"refusing to overwrite drifted artifact: {destination}")
        return
    shutil.copy2(source, destination)


def materialize_bench_artifacts(
    *,
    run_root: Path,
    bench_batch_root: Path,
    project_root: Path,
) -> dict[str, Any]:
    """Copy immutable evidence from a single Bench v4 batch into the Case Study run."""

    run_root = _assert_contained(
        run_root, project_root / "case_study" / "runs", "Case Study run root"
    )
    bench_batch_root = _assert_contained(
        bench_batch_root,
        project_root / "results" / "c2trace_bench_v4",
        "Bench v4 batch root",
    )
    if not bench_batch_root.is_dir():
        raise CaseStudyError(f"Bench v4 batch root is missing: {bench_batch_root}")
    copied: list[str] = []
    trials_root = bench_batch_root / "trials"
    trial_dirs = sorted(path for path in trials_root.glob("*") if path.is_dir())
    if len(trial_dirs) > 1:
        raise CaseStudyError("Case Study Bench v4 batch contains more than one trial")

    mappings: list[tuple[Path, Path]] = []
    for name in ("batch_context.json", "batch_plan.json", "preflight.json", "software_lock.json"):
        source = bench_batch_root / name
        if source.is_file():
            mappings.append((source, run_root / "raw" / "bench_v4" / name))
    for source in sorted((bench_batch_root / "suricata").glob("*")):
        if source.is_file():
            mappings.append((source, run_root / "suricata" / source.name))
    for name in ("suricata_start.txt", "suricata_stop.txt"):
        source = bench_batch_root / name
        if source.is_file():
            mappings.append((source, run_root / "suricata" / name))

    if trial_dirs:
        trial = trial_dirs[0]
        for source in sorted(trial.rglob("*")):
            if not source.is_file():
                continue
            relative = source.relative_to(trial)
            text = relative.as_posix()
            if text.startswith("c2trace_dryrun/") or text.startswith("c2trace_execute/"):
                destination = run_root / "c2trace" / relative
            elif source.name.startswith("caldera_"):
                destination = run_root / "caldera" / source.name
            elif text.startswith("evidence/") or source.name in {
                "after_dryrun_gate.json",
                "baseline_gate.json",
                "dry_run_gate.json",
                "post_response_validation.json",
                "protected_processes.v2.json",
                "target_identity.json",
                "target_identity.pre_scenario.json",
            }:
                destination = run_root / "host_state" / relative
            elif source.name == "external_cleanup.json":
                destination = run_root / "cleanup" / source.name
            else:
                destination = run_root / "raw" / "trial" / relative
            mappings.append((source, destination))
    for source, destination in mappings:
        _copy_verified(source, destination)
        copied.append(destination.relative_to(run_root).as_posix())
    return {
        "schema_version": "c2trace.case_study.materialization.v1",
        "case_id": CASE_ID,
        "execution_case_id": EXECUTION_CASE_ID,
        "materialized_at_utc": utc_now(),
        "bench_batch_root": str(bench_batch_root),
        "trial_count": len(trial_dirs),
        "artifact_count": len(copied),
        "artifacts": copied,
    }


def _classify_artifact(relative: str) -> tuple[str, str]:
    folded = relative.casefold()
    if "checkpoints/" in folded:
        return "operator_checkpoint", "checkpoint"
    if folded.startswith("caldera/") or "caldera_" in folded:
        return "caldera", "attack_emulation"
    if folded.startswith("suricata/") or "suricata" in folded:
        return "suricata", "detection"
    if folded.startswith("c2trace/"):
        if "execute" in folded:
            return "c2trace", "response_verify"
        return "c2trace", "investigation_dry_run"
    if folded.startswith("host_state/"):
        return "windows_host", "host_state"
    if folded.startswith("cleanup/"):
        return "bench_harness", "external_cleanup"
    if folded.startswith("report/") or folded.startswith("manual/"):
        return "case_study", "reporting"
    return "case_study", "raw"


def build_evidence_index(run_root: Path) -> dict[str, Any]:
    run_root = run_root.resolve()
    if not run_root.is_dir():
        raise CaseStudyError(f"run root is missing: {run_root}")
    excluded = {
        "evidence_index.json",
        "finalization_receipt.json",
        "case_study_report.md",
        "case_study_report.html",
        "case_study_report.pdf",
        "case_study_report_preview.png",
        "render_receipt.json",
    }
    paths = sorted(
        path
        for path in run_root.rglob("*")
        if path.is_file()
        and path.name not in excluded
        and not path.name.endswith(".tmp")
    )
    entries: list[dict[str, Any]] = []
    for index, path in enumerate(paths, start=1):
        relative = path.relative_to(run_root).as_posix()
        source, phase = _classify_artifact(relative)
        entries.append(
            {
                "evidence_id": f"E{index:04d}",
                "path": relative,
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
                "phase": phase,
                "data_source": source,
                "casefile_reference": (
                    relative if path.name in {"casefile.json", "scoring_casefile.json"} else ""
                ),
            }
        )
    by_path = {row["path"]: row for row in entries}
    capture_rows = []
    for label, stage in enumerate(EXPECTED_HOST_CAPTURES, start=1):
        relative = f"raw/checkpoints/{stage}.json"
        evidence = by_path.get(relative)
        receipt: dict[str, Any] = {}
        if evidence is not None:
            try:
                receipt = read_json(run_root / relative)
            except CaseStudyError:
                receipt = {}
        protocol_valid = (
            receipt.get("capture_mode") == "external_host"
            and receipt.get("in_guest_file_required") is False
            and receipt.get("machine_verifiable") is False
            and receipt.get("host_capture_label") == label
        )
        capture_rows.append(
            {
                "host_capture_label": label,
                "checkpoint": stage,
                "capture_mode": "external_host",
                "in_guest_file_required": False,
                "machine_verifiable": False,
                "checkpoint_receipt_present": evidence is not None,
                "checkpoint_protocol_valid": protocol_valid,
                "checkpoint_receipt_evidence_id": (
                    evidence.get("evidence_id", "") if evidence else ""
                ),
            }
        )
    batch_plan_paths = [path for path in paths if path.name == "batch_plan.json"]
    trial_result_paths = [path for path in paths if path.name == "trial_result.json"]
    bench_batch_id = ""
    execution_run_id = ""
    if len(batch_plan_paths) == 1:
        try:
            bench_batch_id = str(read_json(batch_plan_paths[0]).get("batch_id") or "")
        except CaseStudyError:
            bench_batch_id = ""
    if len(trial_result_paths) == 1:
        try:
            execution_run_id = str(read_json(trial_result_paths[0]).get("run_id") or "")
        except CaseStudyError:
            execution_run_id = ""
    return {
        "schema_version": "c2trace.case_study.evidence_index.v1",
        "case_id": CASE_ID,
        "execution_case_id": EXECUTION_CASE_ID,
        "run_id": run_root.name,
        "identity_binding": {
            "case_study_id": CASE_ID,
            "case_study_run_id": run_root.name,
            "bench_batch_id": bench_batch_id,
            "execution_case_id": EXECUTION_CASE_ID,
            "execution_run_id": execution_run_id,
        },
        "generated_at_utc": utc_now(),
        "artifact_count": len(entries),
        "entries": entries,
        "external_host_capture": {
            "capture_mode": "external_host",
            "expected_checkpoint_opportunities": len(EXPECTED_HOST_CAPTURES),
            "recorded_checkpoint_opportunities": sum(
                1 for row in capture_rows if row["checkpoint_receipt_present"]
            ),
            "checkpoint_protocol_complete": all(
                row["checkpoint_protocol_valid"] for row in capture_rows
            ),
            "in_guest_file_required": False,
            "machine_verifiable": False,
            "operator_capture_status": "not_machine_verifiable",
            "captures": capture_rows,
        },
    }


def _find_entry(index: Mapping[str, Any], suffix: str) -> dict[str, Any] | None:
    matches = [
        dict(row)
        for row in index.get("entries", [])
        if isinstance(row, Mapping) and str(row.get("path") or "").endswith(suffix)
    ]
    return matches[0] if len(matches) == 1 else None


def _evidence_citation(index: Mapping[str, Any], suffix: str) -> str:
    row = _find_entry(index, suffix)
    if row is None:
        return "未发现对应工件"
    return f"[{row['evidence_id']}] `{row['path']}`（SHA-256 `{row['sha256']}`）"


def _load_indexed_json(run_root: Path, index: Mapping[str, Any], suffix: str) -> dict[str, Any]:
    row = _find_entry(index, suffix)
    if row is None:
        return {}
    try:
        return read_json(run_root / str(row["path"]))
    except CaseStudyError:
        return {}


def _llm_calls(metadata: Mapping[str, Any]) -> list[dict[str, Any]]:
    usage = metadata.get("llm_usage")
    if isinstance(usage, Mapping):
        rows = usage.get("calls", [])
    elif isinstance(usage, list):
        rows = usage
    else:
        rows = []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _metric_block(score: Mapping[str, Any], name: str) -> dict[str, Any]:
    direct = score.get(name)
    if isinstance(direct, Mapping):
        return dict(direct)
    legacy_metrics = score.get("metrics") if isinstance(score.get("metrics"), Mapping) else {}
    legacy_counts = score.get("counts") if isinstance(score.get("counts"), Mapping) else {}
    prefix = "trace" if name == "trace_metrics" else "response_action"
    return {
        "precision": legacy_metrics.get(f"{prefix}_precision"),
        "recall": legacy_metrics.get(f"{prefix}_recall"),
        "f1": legacy_metrics.get(f"{prefix}_f1"),
        "tp": legacy_counts.get(f"{prefix}_tp"),
        "fp": legacy_counts.get(f"{prefix}_fp"),
        "fn": legacy_counts.get(f"{prefix}_fn"),
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None or precision + recall == 0:
        return None
    return 2 * precision * recall / (precision + recall)


def _classification_metrics(*, tp: int, fp: int, fn: int) -> dict[str, Any]:
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": _f1(precision, recall),
    }


def build_case_study_acceptance(
    run_root: Path, index: Mapping[str, Any]
) -> dict[str, Any]:
    """Evaluate the Case Study overlay without changing the frozen v4 score."""

    trial = _load_indexed_json(run_root, index, "trial_result.json")
    score = _load_indexed_json(run_root, index, "score.json")
    dry_meta = _load_indexed_json(run_root, index, "c2trace_dryrun/run_metadata.json")
    execute_meta = _load_indexed_json(run_root, index, "c2trace_execute/run_metadata.json")
    execute_case = _load_indexed_json(run_root, index, "c2trace_execute/casefile.json")
    post = _load_indexed_json(run_root, index, "post_response_validation.json")
    cleanup = _load_indexed_json(run_root, index, "external_cleanup.json")
    payload_cleanup = _load_indexed_json(run_root, index, "payload_cleanup.json")
    driver_retirement = _load_indexed_json(run_root, index, "driver_retirement.json")
    windows_preflight = _load_indexed_json(
        run_root, index, "windows_host_preflight.json"
    )

    matching = score.get("trace_matching") if isinstance(score.get("trace_matching"), Mapping) else {}
    matched_ids = {
        str(row.get("trace_id") or "")
        for row in matching.get("matches", [])
        if isinstance(row, Mapping)
    }
    trace_rows = [
        {"trace_id": trace_id, "matched": trace_id in matched_ids}
        for trace_id in EXPECTED_TRACE_IDS
    ]
    trace_matched = sum(1 for row in trace_rows if row["matched"])
    trace_fp = len(
        [
            row
            for row in matching.get("unmatched_observations", [])
            if isinstance(row, Mapping)
        ]
    )
    case_trace_metrics = _classification_metrics(
        tp=trace_matched,
        fp=trace_fp,
        fn=len(EXPECTED_TRACE_IDS) - trace_matched,
    )

    per_ability = {
        str(row.get("ability_id") or ""): dict(row)
        for row in score.get("per_ability", [])
        if isinstance(row, Mapping)
    }
    behavior_rows = []
    for ability_id, label in PUBLIC_BEHAVIORS.items():
        row = per_ability.get(ability_id, {})
        behavior_rows.append(
            {
                "ability_id": ability_id,
                "behavior": label,
                "strict_hit": row.get("strict_hit") is True,
                "coverage": row.get("coverage"),
            }
        )
    behavior_matched = sum(1 for row in behavior_rows if row["strict_hit"])
    behavior_recall = _ratio(behavior_matched, len(PUBLIC_BEHAVIORS))
    behavior_metrics = {
        "tp": behavior_matched,
        "fp": None,
        "fn": len(PUBLIC_BEHAVIORS) - behavior_matched,
        "precision": None,
        "recall": behavior_recall,
        "f1": None,
        "precision_status": (
            "not_applicable: C2Trace does not independently predict CALDERA ability IDs"
        ),
    }

    response_matching = (
        score.get("response_action_matching")
        if isinstance(score.get("response_action_matching"), Mapping)
        else {}
    )
    response_match_tools = [
        str(row.get("observed", {}).get("tool") or "")
        for row in response_matching.get("matches", [])
        if isinstance(row, Mapping) and isinstance(row.get("observed"), Mapping)
    ]
    unmatched_response_rows = [
        row
        for row in response_matching.get("unmatched_observed", [])
        if isinstance(row, Mapping)
    ]
    response_tp = sum(
        1 for tool in response_match_tools if tool in {"kill_process", "remove_file"}
    )
    case_response_metrics = _classification_metrics(
        tp=response_tp,
        fp=len(unmatched_response_rows),
        fn=2 - response_tp,
    )
    executed_response_tools = [
        str(row.get("tool") or "")
        for row in execute_case.get("action_results", [])
        if isinstance(row, Mapping)
        and row.get("success") is True
        and str(row.get("tool") or "") in {"kill_process", "remove_file"}
        and not (
            isinstance(row.get("data"), Mapping)
            and row.get("data", {}).get("dry_run") is True
        )
    ]
    exact_once = all(
        response_match_tools.count(tool) == 1 and executed_response_tools.count(tool) == 1
        for tool in ("kill_process", "remove_file")
    ) and len(response_match_tools) == 2 and len(executed_response_tools) == 2

    calls = _llm_calls(dry_meta) + _llm_calls(execute_meta)
    planners = [row for row in calls if str(row.get("role") or "").casefold() == "planner"]
    auditors = [row for row in calls if str(row.get("role") or "").casefold() == "auditor"]
    planner_ok = bool(planners) and all(
        row.get("success") is True
        and int(row.get("total_tokens") or 0) > 0
        and row.get("model") == "deepseek-v4-flash"
        for row in planners
    )
    auditor_ok = bool(auditors) and all(
        row.get("success") is True
        and int(row.get("total_tokens") or 0) > 0
        and row.get("model") == "deepseek-v4-flash"
        for row in auditors
    )

    post_ok = post.get("passed") is True and all(
        post.get(key) is True
        for key in (
            "target_network_absent",
            "target_process_absent",
            "target_file_absent",
            "control_sandcat_alive",
            "driver_agent_alive",
        )
    )
    cleanup_ok = cleanup.get("completed") is True or trial.get("cleanup_completed") is True
    payload_cleanup_ok = (
        payload_cleanup.get("status") in {"removed", "already_absent"}
        and str(payload_cleanup.get("expected_sha256") or "").casefold()
        == ARCHIVE_SHA256
        and bool(payload_cleanup.get("staging_receipt_sha256"))
    )
    frozen_driver = (
        windows_preflight.get("driver")
        if isinstance(windows_preflight.get("driver"), Mapping)
        else {}
    )
    try:
        retired_driver_pid = int(driver_retirement.get("frozen_pid") or 0)
        preflight_driver_pid = int(frozen_driver.get("pid") or 0)
    except (TypeError, ValueError):
        retired_driver_pid = 0
        preflight_driver_pid = -1
    driver_retirement_ok = (
        driver_retirement.get("schema_version")
        == "c2trace.case_study.driver_retirement.v1"
        and driver_retirement.get("case_id") == CASE_ID
        and driver_retirement.get("run_id") == run_root.name
        and driver_retirement.get("status") == "retired"
        and driver_retirement.get("operator_verified_identity") is True
        and retired_driver_pid == preflight_driver_pid
        and retired_driver_pid > 0
        and str(driver_retirement.get("frozen_paw") or "")
        == str(frozen_driver.get("paw") or "")
        and re.fullmatch(
            r"[0-9a-f]{64}",
            str(driver_retirement.get("remote_log_sha256") or "").casefold(),
        )
        is not None
    )
    identity = index.get("identity_binding") if isinstance(index.get("identity_binding"), Mapping) else {}
    identity_ok = (
        identity.get("case_study_id") == CASE_ID
        and identity.get("case_study_run_id") == run_root.name
        and identity.get("bench_batch_id") == run_root.name
        and identity.get("execution_case_id") == EXECUTION_CASE_ID
        and str(identity.get("execution_run_id") or "").startswith(
            f"{run_root.name}-{EXECUTION_CASE_ID.lower()}-r"
        )
    )
    technical_checks = {
        "identity_binding_complete": identity_ok,
        "trial_evaluation_valid_pass": trial.get("trial_class") == "evaluation_valid_pass",
        "five_trace_metrics_perfect": case_trace_metrics
        == {
            "tp": 5,
            "fp": 0,
            "fn": 0,
            "precision": 1.0,
            "recall": 1.0,
            "f1": 1.0,
        },
        "three_public_behaviors_strict_hit": behavior_matched == len(PUBLIC_BEHAVIORS),
        "planner_llm_strict": planner_ok,
        "every_auditor_llm_strict": auditor_ok,
        "response_metrics_perfect_and_exact_once": (
            case_response_metrics
            == {
                "tp": 2,
                "fp": 0,
                "fn": 0,
                "precision": 1.0,
                "recall": 1.0,
                "f1": 1.0,
            }
            and exact_once
        ),
        "post_response_verify": post_ok,
        "windows_external_cleanup": cleanup_ok,
        "kali_payload_cleanup_recorded": payload_cleanup_ok,
        "frozen_driver_retirement_recorded": driver_retirement_ok,
    }
    external_capture = index.get("external_host_capture", {})
    return {
        "schema_version": "c2trace.case_study.acceptance.v1",
        "case_id": CASE_ID,
        "execution_case_id": EXECUTION_CASE_ID,
        "run_id": run_root.name,
        "generated_at_utc": utc_now(),
        "identity_binding": dict(index.get("identity_binding") or {}),
        "frozen_v4_metrics": {
            "trace": _metric_block(score, "trace_metrics"),
            "response_action": _metric_block(score, "response_action_metrics"),
            "support_ability_in_original_denominator": SUPPORT_ABILITY_ID,
            "source_score_sha256": (_find_entry(index, "score.json") or {}).get("sha256", ""),
        },
        "case_study_metrics": {
            "public_behavior_denominator": len(PUBLIC_BEHAVIORS),
            "public_behavior_strict_hits": behavior_matched,
            "public_behavior_recall": behavior_recall,
            "public_behavior_metrics": behavior_metrics,
            "behaviors": behavior_rows,
            "trace_denominator": len(EXPECTED_TRACE_IDS),
            "trace_matches": trace_matched,
            "trace_recall": case_trace_metrics["recall"],
            "trace_metrics": case_trace_metrics,
            "traces": trace_rows,
            "support_step_excluded_from_behavior_denominator": True,
        },
        "llm": {
            "planner_call_count": len(planners),
            "auditor_call_count": len(auditors),
            "planner_passed": planner_ok,
            "every_auditor_passed": auditor_ok,
            "total_tokens": sum(int(row.get("total_tokens") or 0) for row in calls),
        },
        "response": {
            "matched_tools": response_match_tools,
            "executed_tools": executed_response_tools,
            "exact_once": exact_once,
            "metrics": case_response_metrics,
        },
        "cleanup": {
            "windows_external_cleanup": cleanup_ok,
            "kali_payload_cleanup_recorded": payload_cleanup_ok,
            "payload_cleanup_status": payload_cleanup.get("status"),
            "driver_retirement_recorded": driver_retirement_ok,
            "driver_retirement_status": driver_retirement.get("status"),
        },
        "technical_checks": technical_checks,
        "technical_acceptance_passed": all(technical_checks.values()),
        "documentation_complete": None,
        "external_host_capture": dict(external_capture),
        "technical_classification_unchanged_by_external_capture": True,
    }


def write_timeline_csv(run_root: Path, index: Mapping[str, Any]) -> Path:
    events: list[dict[str, str]] = []
    state_entry = _find_entry(index, "state.jsonl")
    if state_entry is not None:
        state_path = run_root / str(state_entry["path"])
        for line in state_path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, Mapping):
                events.append(
                    {
                        "timestamp_utc": str(row.get("timestamp") or ""),
                        "stage": str(row.get("stage") or ""),
                        "actor": "WorkflowController",
                        "event": str(row.get("status") or "stage event"),
                        "evidence_ref": str(state_entry["evidence_id"]),
                    }
                )
    for row in index.get("entries", []):
        if not isinstance(row, Mapping) or "raw/checkpoints/" not in str(row.get("path") or ""):
            continue
        receipt = _load_indexed_json(run_root, index, str(row["path"]))
        events.append(
            {
                "timestamp_utc": str(receipt.get("confirmed_at_utc") or ""),
                "stage": str(receipt.get("checkpoint") or "checkpoint"),
                "actor": "Operator",
                "event": "accepted" if receipt.get("accepted") is True else "rejected",
                "evidence_ref": str(row.get("evidence_id") or ""),
            }
        )
    events.sort(key=lambda row: (row["timestamp_utc"], row["stage"]))
    path = run_root / "report" / "timeline.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=("timestamp_utc", "stage", "actor", "event", "evidence_ref"),
        )
        writer.writeheader()
        writer.writerows(events)
    return path


def write_external_capture_log(run_root: Path, index: Mapping[str, Any]) -> Path:
    path = run_root / "report" / "external_capture_log.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = index.get("external_host_capture", {}).get("captures", [])
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "host_capture_label",
                "checkpoint",
                "capture_mode",
                "in_guest_file_required",
                "machine_verifiable",
                "checkpoint_receipt_present",
                "checkpoint_protocol_valid",
                "checkpoint_receipt_evidence_id",
            ),
        )
        writer.writeheader()
        writer.writerows(rows)
    return path


def write_agent_activity_csv(run_root: Path, index: Mapping[str, Any]) -> Path:
    rows = [
        {
            "actor": "Planner",
            "responsibility": "从最小 Suricata 告警与 MCP 工具目录生成 StrategyTree",
            "evidence_ref": (_find_entry(index, "c2trace_dryrun/run_metadata.json") or {}).get("evidence_id", ""),
        },
        {
            "actor": "Executor",
            "responsibility": "经 stdio MCP 调查、执行 exact-once 响应并重新 Verify",
            "evidence_ref": (_find_entry(index, "c2trace_execute/run_metadata.json") or {}).get("evidence_id", ""),
        },
        {
            "actor": "Auditor",
            "responsibility": "语义审查、确定性 target lock 与一次性响应授权",
            "evidence_ref": (_find_entry(index, "c2trace_execute/casefile.json") or {}).get("evidence_id", ""),
        },
    ]
    path = run_root / "report" / "agent_activity_table.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=("actor", "responsibility", "evidence_ref")
        )
        writer.writeheader()
        writer.writerows(rows)
    return path


def render_teacher_report(run_root: Path, index: Mapping[str, Any]) -> str:
    trial = _load_indexed_json(run_root, index, "trial_result.json")
    score = _load_indexed_json(run_root, index, "score.json")
    dry_meta = _load_indexed_json(run_root, index, "c2trace_dryrun/run_metadata.json")
    execute_meta = _load_indexed_json(run_root, index, "c2trace_execute/run_metadata.json")
    cleanup = _load_indexed_json(run_root, index, "external_cleanup.json")
    post = _load_indexed_json(run_root, index, "post_response_validation.json")
    acceptance = _load_indexed_json(run_root, index, "case_study_acceptance.json")
    trace_metrics = _metric_block(score, "trace_metrics")
    response_metrics = _metric_block(score, "response_action_metrics")

    llm_rows: list[dict[str, Any]] = []
    for metadata in (dry_meta, execute_meta):
        usage = metadata.get("llm_usage") if isinstance(metadata.get("llm_usage"), Mapping) else {}
        llm_rows.extend(
            dict(row) for row in usage.get("calls", []) if isinstance(row, Mapping)
        )
    planner_ok = acceptance.get("llm", {}).get("planner_passed") is True
    auditor_ok = acceptance.get("llm", {}).get("every_auditor_passed") is True
    total_tokens = sum(int(row.get("total_tokens") or 0) for row in llm_rows)

    technical_status = str(trial.get("trial_class") or "尚无完整 trial_result")
    capture_status = index.get("external_host_capture", {})
    cleanup_complete = cleanup.get("completed") is True or trial.get("cleanup_completed") is True
    lines = [
        "# C2Trace Windows WebShell Case Study 报告",
        "",
        f"- Case Study ID：`{CASE_ID}`",
        f"- 底层执行 ID：`{EXECUTION_CASE_ID}`",
        f"- RunId：`{run_root.name}`",
        f"- 技术分类：`{technical_status}`",
        f"- Case Study 技术验收：`{str(acceptance.get('technical_acceptance_passed') is True).lower()}`",
        "- Host screenshots: external WeChat capture; no in-guest file required and not machine-verifiable",
        f"- Recorded checkpoint opportunities: {capture_status.get('recorded_checkpoint_opportunities', 0)}/{capture_status.get('expected_checkpoint_opportunities', len(EXPECTED_HOST_CAPTURES))}",
        "",
        "> 本案例复现的是 CTID 官方 Windows WebShell 安全微仿真，不是真实恶意软件事件或某个威胁组织的完整入侵。",
        "",
        "## 1. 案例边界与公开来源",
        "",
        f"公开来源固定在 CTID adversary_emulation_library 提交 `{SOURCE_COMMIT}`。CALDERA payload 交付仅为实验支撑，不作为额外公开攻击行为计分。源锁和 payload 合同见 {_evidence_citation(index, 'source_lock.json')}。",
        "",
        "## 2. 攻击链实际做了什么",
        "",
        "| 顺序 | 执行位置 | 行为 | ATT&CK | 预期主机痕迹 |",
        "|---:|---|---|---|---|",
        "| 1 | Windows control | 校验并启动运行专属 WebShell | T1505.003 | 可执行文件、进程、入站监听 |",
        "| 2 | Kali driver | HTTP POST 执行 `whoami /groups` | T1069.001 | groups 输出文件 |",
        "| 3 | Kali driver | HTTP POST 执行 `tasklist` | T1057 | tasks 输出文件 |",
        "",
        f"Bootstrap 原始证据：{_evidence_citation(index, 'caldera_bootstrap_operation.json')}；Scenario 原始证据：{_evidence_citation(index, 'caldera_scenario_operation.json')}。",
        "",
        "## 3. 检测起点",
        "",
        f"Suricata SID `{DETECTION_SID}` 只接受 `192.168.21.132 -> 192.168.21.140:18080-18979` 的新鲜 HTTP POST。C2Trace 收到的是最小告警及物理 EVE 定位，不读取 Ground Truth。告警证据：{_evidence_citation(index, 'suricata_event.json')}。",
        "",
        "## 4. C2Trace 三智能体活动",
        "",
        f"- Planner：依据最小告警、C2-KB 和 MCP 工具目录生成 StrategyTree。Planner 调用完整成功：`{str(planner_ok).lower()}`。证据：{_evidence_citation(index, 'c2trace_dryrun/run_metadata.json')}。",
        f"- Executor：经 stdio MCP 调查网络、进程、文件和相关输出；在授权后 exact-once 执行响应，并重新查询真实状态。证据：{_evidence_citation(index, 'c2trace_execute/run_metadata.json')}。",
        f"- Auditor：LLM 给出语义理由，确定性内核锁定 PID、路径、创建时间、端口和哈希，再签发一次性授权。Auditor 调用全部成功：`{str(auditor_ok).lower()}`。证据：{_evidence_citation(index, 'c2trace_execute/casefile.json')}。",
        f"- 本次全部 LLM usage 记录的 token 合计：`{total_tokens}`。",
        "",
        "## 5. 响应与 Verify",
        "",
        "| 口径 | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
        f"| 冻结 v4 响应动作 | {response_metrics.get('tp', 'N/A')} | {response_metrics.get('fp', 'N/A')} | {response_metrics.get('fn', 'N/A')} | {response_metrics.get('precision', 'N/A')} | {response_metrics.get('recall', 'N/A')} | {response_metrics.get('f1', 'N/A')} |",
        f"| Case Study 两项响应 | {acceptance.get('response', {}).get('metrics', {}).get('tp', 'N/A')} | {acceptance.get('response', {}).get('metrics', {}).get('fp', 'N/A')} | {acceptance.get('response', {}).get('metrics', {}).get('fn', 'N/A')} | {acceptance.get('response', {}).get('metrics', {}).get('precision', 'N/A')} | {acceptance.get('response', {}).get('metrics', {}).get('recall', 'N/A')} | {acceptance.get('response', {}).get('metrics', {}).get('f1', 'N/A')} |",
        "",
        f"Case Study exact-once 验收：`{str(acceptance.get('response', {}).get('exact_once') is True).lower()}`。",
        f"Verify 与保护对象证据：{_evidence_citation(index, 'post_response_validation.json')}。post-response gate 通过：`{str(post.get('passed') is True).lower()}`。",
        "",
        "## 6. 五项痕迹与评分",
        "",
        "| 口径 | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
        f"| 冻结 v4 痕迹 | {trace_metrics.get('tp', 'N/A')} | {trace_metrics.get('fp', 'N/A')} | {trace_metrics.get('fn', 'N/A')} | {trace_metrics.get('precision', 'N/A')} | {trace_metrics.get('recall', 'N/A')} | {trace_metrics.get('f1', 'N/A')} |",
        f"| Case Study 五项痕迹 | {acceptance.get('case_study_metrics', {}).get('trace_metrics', {}).get('tp', 'N/A')} | {acceptance.get('case_study_metrics', {}).get('trace_metrics', {}).get('fp', 'N/A')} | {acceptance.get('case_study_metrics', {}).get('trace_metrics', {}).get('fn', 'N/A')} | {acceptance.get('case_study_metrics', {}).get('trace_metrics', {}).get('precision', 'N/A')} | {acceptance.get('case_study_metrics', {}).get('trace_metrics', {}).get('recall', 'N/A')} | {acceptance.get('case_study_metrics', {}).get('trace_metrics', {}).get('f1', 'N/A')} |",
        "",
        f"Case Study 论文口径单独报告：公开行为严格命中 `{acceptance.get('case_study_metrics', {}).get('public_behavior_strict_hits', 0)}/3`（TP `{acceptance.get('case_study_metrics', {}).get('public_behavior_metrics', {}).get('tp', 0)}`、FN `{acceptance.get('case_study_metrics', {}).get('public_behavior_metrics', {}).get('fn', 0)}`、Recall `{acceptance.get('case_study_metrics', {}).get('public_behavior_metrics', {}).get('recall', 'N/A')}`），五项痕迹匹配 `{acceptance.get('case_study_metrics', {}).get('trace_matches', 0)}/5`。行为级 Precision/FP/F1 为 N/A，因为 C2Trace 不独立预测 CALDERA ability ID；这三个值不能通过把 support step 排除后人为置零。T1105 仅为 support step，不进入三项公开行为分母；其产生的 WebShell 文件仍是五项可观测痕迹之一。",
        "",
        "## 7. 外部 Cleanup 边界",
        "",
        f"C2Trace 响应只包含终止目标进程和删除目标可执行文件；命令输出、压缩包、解压目录、CALDERA payload 和临时 driver 属于实验 harness cleanup。Windows cleanup 完成：`{str(cleanup_complete).lower()}`；Kali payload cleanup：`{str(acceptance.get('cleanup', {}).get('kali_payload_cleanup_recorded') is True).lower()}`；冻结 driver 退役记录：`{str(acceptance.get('cleanup', {}).get('driver_retirement_recorded') is True).lower()}`。Windows cleanup 证据：{_evidence_citation(index, 'external_cleanup.json')}，payload 证据：{_evidence_citation(index, 'payload_cleanup.json')}，driver 证据：{_evidence_citation(index, 'driver_retirement.json')}。",
        "",
        "## 8. 端到端证据与材料完整性",
        "",
        f"EvidenceIndex 共收录 `{index.get('artifact_count', 0)}` 个工件。四个检查点协议记录：`{capture_status.get('recorded_checkpoint_opportunities', 0)}/{capture_status.get('expected_checkpoint_opportunities', len(EXPECTED_HOST_CAPTURES))}`。主机微信截图不写入虚拟机，也不由系统声称已机器验证；这不改变技术 trial 分类。",
        "",
        "## 9. 局限性",
        "",
        "该案例只证明在冻结的单台 Windows 受害机、Kali/CALDERA 和固定 WebShell 微链上的端到端可行性；它不构成真实 actor 归因、完整入侵重建或生产网络泛化结论。",
        "",
    ]
    return "\n".join(lines)


def _inline_markdown(text: str) -> str:
    rendered = escape(text)
    rendered = re.sub(r"`([^`]+)`", r"<code>\1</code>", rendered)
    rendered = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", rendered)
    return rendered


def render_report_html(markdown: str, *, title: str) -> str:
    """Render the report's constrained Markdown subset without extra dependencies."""

    lines = markdown.splitlines()
    body: list[str] = []
    index = 0
    in_list = False
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if in_list and not stripped.startswith("- "):
            body.append("</ul>")
            in_list = False
        if not stripped:
            index += 1
            continue
        if stripped.startswith("|") and index + 1 < len(lines):
            separator = lines[index + 1].strip()
            if re.fullmatch(r"\|?[\s:|-]+\|?", separator) and "---" in separator:
                headers = [cell.strip() for cell in stripped.strip("|").split("|")]
                body.append("<table><thead><tr>")
                body.extend(f"<th>{_inline_markdown(cell)}</th>" for cell in headers)
                body.append("</tr></thead><tbody>")
                index += 2
                while index < len(lines) and lines[index].strip().startswith("|"):
                    cells = [cell.strip() for cell in lines[index].strip().strip("|").split("|")]
                    body.append("<tr>")
                    body.extend(f"<td>{_inline_markdown(cell)}</td>" for cell in cells)
                    body.append("</tr>")
                    index += 1
                body.append("</tbody></table>")
                continue
        heading = re.match(r"^(#{1,3})\s+(.+)$", stripped)
        if heading:
            level = len(heading.group(1))
            body.append(f"<h{level}>{_inline_markdown(heading.group(2))}</h{level}>")
        elif stripped.startswith("> "):
            body.append(f"<blockquote>{_inline_markdown(stripped[2:])}</blockquote>")
        elif stripped.startswith("- "):
            if not in_list:
                body.append("<ul>")
                in_list = True
            body.append(f"<li>{_inline_markdown(stripped[2:])}</li>")
        else:
            body.append(f"<p>{_inline_markdown(stripped)}</p>")
        index += 1
    if in_list:
        body.append("</ul>")
    css = """
@page { size: A4; margin: 14mm 15mm 16mm; }
* { box-sizing: border-box; }
body { color: #17202a; font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
       font-size: 10.5pt; line-height: 1.55; margin: 0 auto; max-width: 190mm; }
h1 { color: #123b5d; border-bottom: 2px solid #2d6f8e; font-size: 22pt; margin: 0 0 16px; }
h2 { color: #123b5d; border-bottom: 1px solid #b8cad5; font-size: 15pt;
     margin: 22px 0 9px; page-break-after: avoid; }
h3 { color: #2f4858; font-size: 12pt; page-break-after: avoid; }
p, li { orphans: 3; widows: 3; }
blockquote { background: #eef4f6; border-left: 4px solid #2d6f8e; margin: 12px 0;
             padding: 8px 12px; }
code { background: #edf1f3; border-radius: 3px; font-family: Consolas, monospace;
       font-size: 0.92em; padding: 1px 4px; overflow-wrap: anywhere; }
table { border-collapse: collapse; font-size: 9pt; margin: 10px 0 16px; width: 100%;
        page-break-inside: avoid; }
th { background: #dce8ed; color: #123b5d; text-align: left; }
th, td { border: 1px solid #9eb3be; padding: 5px 6px; vertical-align: top; }
tr:nth-child(even) td { background: #f7f9fa; }
""".strip()
    return (
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
        f"<title>{escape(title)}</title><style>{css}</style></head><body>"
        + "\n".join(body)
        + "</body></html>\n"
    )


def _edge_executable(explicit: Path | None = None) -> Path:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit)
    for name in ("msedge.exe", "msedge"):
        located = shutil.which(name)
        if located:
            candidates.append(Path(located))
    candidates.extend(
        [
            Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
            Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
        ]
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise CaseStudyError("Microsoft Edge executable was not found for PDF rendering")


def _validate_pdf(path: Path) -> dict[str, Any]:
    try:
        from pypdf import PdfReader
    except ImportError as exc:  # pragma: no cover - present in the experiment venv
        raise CaseStudyError("pypdf is required to validate the rendered report") from exc
    try:
        reader = PdfReader(str(path))
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
    except Exception as exc:
        raise CaseStudyError("rendered PDF could not be parsed by pypdf") from exc
    if not reader.pages or "C2Trace" not in text or CASE_ID not in text:
        raise CaseStudyError("rendered PDF is missing pages or expected report text")
    return {"page_count": len(reader.pages), "text_check_passed": True}


def _png_dimensions(path: Path) -> tuple[int, int]:
    try:
        header = path.read_bytes()[:24]
    except OSError as exc:
        raise CaseStudyError("report preview PNG was not created") from exc
    if len(header) != 24 or header[:8] != b"\x89PNG\r\n\x1a\n":
        raise CaseStudyError("report preview is not a valid PNG")
    return int.from_bytes(header[16:20], "big"), int.from_bytes(header[20:24], "big")


def write_report_outputs(
    run_root: Path,
    markdown: str,
    *,
    generate_pdf: bool,
    edge_executable: Path | None = None,
) -> dict[str, Any]:
    report_dir = run_root / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    markdown_path = report_dir / "case_study_report.md"
    html_path = report_dir / "case_study_report.html"
    markdown_path.write_text(markdown, encoding="utf-8")
    html_path.write_text(
        render_report_html(markdown, title=f"C2Trace Case Study {CASE_ID}"),
        encoding="utf-8",
    )
    receipt: dict[str, Any] = {
        "schema_version": "c2trace.case_study.render_receipt.v1",
        "case_id": CASE_ID,
        "run_id": run_root.name,
        "rendered_at_utc": utc_now(),
        "html": {
            "path": str(html_path),
            "sha256": sha256_file(html_path),
            "size_bytes": html_path.stat().st_size,
        },
        "pdf_requested": generate_pdf,
        "secret_material_persisted": False,
    }
    if generate_pdf:
        edge = _edge_executable(edge_executable)
        pdf_path = report_dir / "case_study_report.pdf"
        preview_path = report_dir / "case_study_report_preview.png"
        with tempfile.TemporaryDirectory(prefix="c2trace-edge-") as profile:
            common = [
                str(edge),
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                f"--user-data-dir={profile}",
            ]
            pdf_process = subprocess.run(
                [
                    *common,
                    "--no-pdf-header-footer",
                    f"--print-to-pdf={pdf_path}",
                    html_path.resolve().as_uri(),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=120,
            )
            if pdf_process.returncode != 0 or not pdf_path.is_file():
                raise CaseStudyError(
                    f"Edge PDF render failed with exit {pdf_process.returncode}"
                )
            preview_process = subprocess.run(
                [
                    *common,
                    "--hide-scrollbars",
                    "--window-size=1440,2000",
                    f"--screenshot={preview_path}",
                    html_path.resolve().as_uri(),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=120,
            )
            if preview_process.returncode != 0 or not preview_path.is_file():
                raise CaseStudyError(
                    f"Edge report preview failed with exit {preview_process.returncode}"
                )
        pdf_validation = _validate_pdf(pdf_path)
        preview_width, preview_height = _png_dimensions(preview_path)
        receipt.update(
            {
                "renderer": "Microsoft Edge headless",
                "pdf": {
                    "path": str(pdf_path),
                    "sha256": sha256_file(pdf_path),
                    "size_bytes": pdf_path.stat().st_size,
                    **pdf_validation,
                },
                "preview": {
                    "path": str(preview_path),
                    "sha256": sha256_file(preview_path),
                    "size_bytes": preview_path.stat().st_size,
                    "width": preview_width,
                    "height": preview_height,
                },
            }
        )
    write_json_atomic(report_dir / "render_receipt.json", receipt)
    return receipt


def finalize_case_study_run(
    *,
    run_root: Path,
    project_root: Path,
    bench_batch_root: Path | None = None,
    generate_pdf: bool = False,
    edge_executable: Path | None = None,
) -> dict[str, Any]:
    run_root = _assert_contained(
        run_root, project_root / "case_study" / "runs", "Case Study run root"
    )
    run_root.mkdir(parents=True, exist_ok=True)
    for directory in (
        "raw",
        "c2trace",
        "caldera",
        "suricata",
        "host_state",
        "cleanup",
        "report",
    ):
        (run_root / directory).mkdir(parents=True, exist_ok=True)
    static_contracts = {
        project_root / "case_study" / "sources" / "source_lock.json": (
            run_root / "raw" / "contracts" / "source_lock.json"
        ),
        project_root / "case_study" / "assets" / "payload_manifest.json": (
            run_root / "raw" / "contracts" / "payload_manifest.json"
        ),
        project_root / "case_study" / "scenario" / "case_study_manifest.yaml": (
            run_root / "raw" / "contracts" / "case_study_manifest.yaml"
        ),
        project_root / "case_study" / "scenario" / "ground_truth.yaml": (
            run_root / "raw" / "contracts" / "ground_truth.yaml"
        ),
        project_root / "case_study" / "scenario" / "detection_contract.yaml": (
            run_root / "raw" / "contracts" / "detection_contract.yaml"
        ),
        project_root / "case_study" / "scenario" / "cleanup_contract.yaml": (
            run_root / "raw" / "contracts" / "cleanup_contract.yaml"
        ),
    }
    for source, destination in static_contracts.items():
        _copy_verified(source, destination)
    materialization: dict[str, Any] | None = None
    if bench_batch_root is not None:
        materialization = materialize_bench_artifacts(
            run_root=run_root,
            bench_batch_root=bench_batch_root,
            project_root=project_root,
        )
        write_json_atomic(run_root / "raw" / "materialization_receipt.json", materialization)
    index = build_evidence_index(run_root)
    acceptance = build_case_study_acceptance(run_root, index)
    write_json_atomic(run_root / "report" / "case_study_acceptance.json", acceptance)
    index = build_evidence_index(run_root)
    write_timeline_csv(run_root, index)
    write_agent_activity_csv(run_root, index)
    write_external_capture_log(run_root, index)
    # Stabilize evidence IDs after all indexed paths exist, then rewrite CSV
    # references once. The path set no longer changes, so the IDs remain stable.
    index = build_evidence_index(run_root)
    write_timeline_csv(run_root, index)
    write_agent_activity_csv(run_root, index)
    write_external_capture_log(run_root, index)
    index = build_evidence_index(run_root)
    write_json_atomic(run_root / "evidence_index.json", index)
    report_text = render_teacher_report(run_root, index)
    render_receipt = write_report_outputs(
        run_root,
        report_text,
        generate_pdf=generate_pdf,
        edge_executable=edge_executable,
    )
    report_path = run_root / "report" / "case_study_report.md"
    return {
        "schema_version": "c2trace.case_study.finalization.v1",
        "case_id": CASE_ID,
        "execution_case_id": EXECUTION_CASE_ID,
        "run_id": run_root.name,
        "finalized_at_utc": utc_now(),
        "materialization": materialization,
        "evidence_index": str(run_root / "evidence_index.json"),
        "acceptance": str(run_root / "report" / "case_study_acceptance.json"),
        "technical_acceptance_passed": acceptance["technical_acceptance_passed"],
        "report_markdown": str(report_path),
        "report_html": render_receipt["html"]["path"],
        "report_pdf": render_receipt.get("pdf", {}).get("path"),
        "render_receipt": str(run_root / "report" / "render_receipt.json"),
        "artifact_count": index["artifact_count"],
        "external_host_capture_machine_verifiable": False,
        "external_host_capture_protocol_complete": index["external_host_capture"][
            "checkpoint_protocol_complete"
        ],
    }


__all__ = [
    "ARCHIVE_SHA256",
    "CASE_ID",
    "CaseStudyError",
    "EXECUTION_CASE_ID",
    "EXPECTED_HOST_CAPTURES",
    "build_case_study_acceptance",
    "build_evidence_index",
    "canonical_json_hash",
    "finalize_case_study_run",
    "materialize_bench_artifacts",
    "read_json",
    "render_report_html",
    "render_teacher_report",
    "run_llm_role_preflight",
    "sha256_file",
    "utc_now",
    "validate_case_study",
    "write_json_atomic",
    "write_report_outputs",
]
