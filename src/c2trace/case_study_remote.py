from __future__ import annotations

"""Fail-closed remote preparation helpers for the WebShell Case Study."""

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import urlparse
from uuid import uuid4

from c2trace.bench_v3.caldera_client import (
    CalderaClient,
    _ability_equivalent,
    _adversary_equivalent,
    load_ability_payload,
    load_adversary_payload,
)
from c2trace.bench_v4.runtime import (
    RuntimeCase,
    discover_case_paths,
    load_runtime_case,
    verify_deployment_manifest,
)
from c2trace.case_study import (
    ARCHIVE_SHA256,
    CASE_ID,
    EXECUTION_CASE_ID,
    CaseStudyError,
    canonical_json_hash,
    sha256_file,
    utc_now,
)


LOCAL_PAYLOAD_NAME = "c2t_windows_webshell_056bb041.zip"
PAYLOAD_NAME = "c2t_v4_windows_webshell_056bb041.zip"
DEFAULT_KALI_IP = "192.168.21.132"
DEFAULT_KALI_USER = "kali"
DEFAULT_CALDERA_ROOT = "/home/kali/to/caldera"
_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,31}$")
_PAYLOAD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,255}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_REMOTE_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")


class RemotePreparationError(CaseStudyError):
    """Raised when remote state is missing, ambiguous, or unsafe to change."""


@dataclass(frozen=True, slots=True)
class RemoteTarget:
    host: str
    user: str
    caldera_root: str

    @property
    def login(self) -> str:
        return f"{self.user}@{self.host}"

    @property
    def payload_dir(self) -> str:
        return f"{self.caldera_root}/data/payloads"

    @property
    def payload_path(self) -> str:
        return f"{self.payload_dir}/{PAYLOAD_NAME}"


class SshTransport(Protocol):
    def run_script(self, script: str, args: Sequence[str]) -> subprocess.CompletedProcess[str]: ...

    def copy_file(self, source: Path, destination: str) -> subprocess.CompletedProcess[str]: ...


class OpenSshTransport:
    def __init__(self, target: RemoteTarget, *, connect_timeout: int = 10):
        self.target = target
        self.connect_timeout = connect_timeout
        self.ssh = shutil.which("ssh")
        self.scp = shutil.which("scp")
        if not self.ssh or not self.scp:
            raise RemotePreparationError("OpenSSH ssh/scp executables are required")

    def run_script(
        self, script: str, args: Sequence[str]
    ) -> subprocess.CompletedProcess[str]:
        command = [
            self.ssh,
            "-o",
            f"ConnectTimeout={self.connect_timeout}",
            self.target.login,
            "sh",
            "-s",
            "--",
            *args,
        ]
        process = subprocess.run(
            command,
            input=script.replace("\r\n", "\n").encode("utf-8"),
            capture_output=True,
            check=False,
        )
        return subprocess.CompletedProcess(
            args=process.args,
            returncode=process.returncode,
            stdout=bytes(process.stdout or b"").decode("utf-8", errors="replace"),
            stderr=bytes(process.stderr or b"").decode("utf-8", errors="replace"),
        )

    def copy_file(self, source: Path, destination: str) -> subprocess.CompletedProcess[str]:
        command = [
            self.scp,
            "-o",
            f"ConnectTimeout={self.connect_timeout}",
            str(source),
            f"{self.target.login}:{destination}",
        ]
        return subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )


def validate_remote_target(
    *, host: str, user: str, caldera_root: str
) -> RemoteTarget:
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise RemotePreparationError("Kali host must be a literal RFC1918 IPv4 address") from exc
    private_v4 = isinstance(address, ipaddress.IPv4Address) and any(
        address in network
        for network in (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
    )
    if not private_v4:
        raise RemotePreparationError("Kali host must be an RFC1918 IPv4 address")
    if not _USER_RE.fullmatch(user):
        raise RemotePreparationError("Kali user contains unsupported characters")
    root = str(PurePosixPath(caldera_root))
    if (
        root == "/"
        or not _SAFE_REMOTE_PATH_RE.fullmatch(root)
        or ".." in PurePosixPath(root).parts
    ):
        raise RemotePreparationError("CALDERA root must be a safe absolute POSIX path")
    return RemoteTarget(host=str(address), user=user, caldera_root=root)


def validate_caldera_server(value: str, *, target: RemoteTarget) -> str:
    parsed = urlparse(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise RemotePreparationError("CALDERA server contains an invalid port") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != target.host
        or port != 8888
        or parsed.path not in {"", "/"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise RemotePreparationError(
            "CALDERA server must be the target Kali host at http://<host>:8888"
        )
    return value.rstrip("/")


def load_webshell_runtime(project_root: Path) -> RuntimeCase:
    bench_root = project_root / "experiments" / "c2trace_bench_v4"
    paths = discover_case_paths(bench_root, case_id=EXECUTION_CASE_ID)
    if len(paths) != 1:
        raise RemotePreparationError(
            f"expected one frozen {EXECUTION_CASE_ID} runtime, found {len(paths)}"
        )
    return load_runtime_case(bench_root, paths[0])


def validate_local_payload(project_root: Path) -> tuple[Path, RuntimeCase, str]:
    archive = project_root / "case_study" / "assets" / LOCAL_PAYLOAD_NAME
    if not archive.is_file() or sha256_file(archive) != ARCHIVE_SHA256:
        raise RemotePreparationError("local Case Study payload hash is invalid")
    runtime = load_webshell_runtime(project_root)
    deployment = verify_deployment_manifest(runtime)
    payloads = list(deployment.payloads_require_manual_staging)
    if len(payloads) != 1:
        raise RemotePreparationError("frozen runtime does not declare exactly one payload")
    payload = payloads[0]
    if (
        payload.get("caldera_name") != PAYLOAD_NAME
        or str(payload.get("sha256") or "").casefold() != ARCHIVE_SHA256
    ):
        raise RemotePreparationError("frozen runtime payload contract drifted")
    return archive, runtime, deployment.manifest_sha256


_PROBE_SCRIPT = r"""
set -eu
root=$1
name=$2
[ -f "$root/server.py" ] || { echo 'error=server_py_missing'; exit 20; }
[ -d "$root/data/payloads" ] || { echo 'error=payload_dir_missing'; exit 21; }
target="$root/data/payloads/$name"
echo "caldera_root=$root"
echo "payload_path=$target"
if [ -L "$target" ]; then
  echo 'error=payload_is_symlink'
  exit 22
fi
if [ -e "$target" ]; then
  [ -f "$target" ] || { echo 'error=payload_not_regular'; exit 23; }
  digest=$(sha256sum -- "$target" | awk '{print $1}')
  echo 'status=present'
  echo "observed_sha256=$digest"
else
  echo 'status=missing'
  echo 'observed_sha256='
fi
"""

_FINALIZE_STAGE_SCRIPT = r"""
set -eu
root=$1
name=$2
temp_name=$3
expected=$4
dir="$root/data/payloads"
temp="$dir/$temp_name"
target="$dir/$name"
[ -f "$root/server.py" ] || { echo 'error=server_py_missing'; exit 30; }
[ -d "$dir" ] || { echo 'error=payload_dir_missing'; exit 31; }
[ ! -L "$temp" ] || { echo 'error=temp_is_symlink'; exit 32; }
[ -f "$temp" ] || { echo 'error=temp_missing'; exit 32; }
temp_hash=$(sha256sum -- "$temp" | awk '{print $1}')
if [ "$temp_hash" != "$expected" ]; then
  rm -f -- "$temp"
  echo 'error=temp_hash_mismatch'
  exit 33
fi
if [ -L "$target" ]; then
  rm -f -- "$temp"
  echo 'error=payload_is_symlink'
  exit 34
fi
if [ -e "$target" ]; then
  [ -f "$target" ] || { rm -f -- "$temp"; echo 'error=payload_not_regular'; exit 35; }
  current=$(sha256sum -- "$target" | awk '{print $1}')
  rm -f -- "$temp"
  [ "$current" = "$expected" ] || { echo 'error=refusing_overwrite'; exit 36; }
  echo 'status=reused'
  echo "observed_sha256=$current"
  exit 0
fi
ln -- "$temp" "$target" || { rm -f -- "$temp"; echo 'error=atomic_create_failed'; exit 37; }
rm -f -- "$temp"
current=$(sha256sum -- "$target" | awk '{print $1}')
[ "$current" = "$expected" ] || { echo 'error=readback_hash_mismatch'; exit 38; }
echo 'status=created'
echo "observed_sha256=$current"
"""

_REMOVE_TEMP_SCRIPT = r"""
set -eu
root=$1
temp_name=$2
dir="$root/data/payloads"
temp="$dir/$temp_name"
case "$temp_name" in .c2trace-*.tmp) ;; *) echo 'error=invalid_temp_name'; exit 39;; esac
[ -d "$dir" ] || { echo 'error=payload_dir_missing'; exit 31; }
if [ -L "$temp" ]; then echo 'error=temp_is_symlink'; exit 32; fi
if [ -e "$temp" ]; then
  [ -f "$temp" ] || { echo 'error=temp_not_regular'; exit 33; }
  rm -- "$temp"
fi
echo 'status=removed_or_absent'
"""

_CLEANUP_SCRIPT = r"""
set -eu
root=$1
name=$2
expected=$3
target="$root/data/payloads/$name"
[ -f "$root/server.py" ] || { echo 'error=server_py_missing'; exit 40; }
if [ -L "$target" ]; then echo 'error=payload_is_symlink'; exit 41; fi
if [ ! -e "$target" ]; then
  echo 'status=already_absent'
  echo 'observed_sha256='
  exit 0
fi
[ -f "$target" ] || { echo 'error=payload_not_regular'; exit 42; }
current=$(sha256sum -- "$target" | awk '{print $1}')
[ "$current" = "$expected" ] || { echo 'error=cleanup_hash_mismatch'; exit 43; }
rm -- "$target"
[ ! -e "$target" ] || { echo 'error=cleanup_remove_failed'; exit 44; }
echo 'status=removed'
echo "observed_sha256=$current"
"""


def _parse_remote_output(process: subprocess.CompletedProcess[str], label: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in str(process.stdout or "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if re.fullmatch(r"[a-z][a-z0-9_]*", key):
            values[key] = value
    if process.returncode != 0:
        code = values.get("error") or f"exit_{process.returncode}"
        raise RemotePreparationError(f"{label} failed: {code}")
    return values


def probe_remote_payload(
    target: RemoteTarget, transport: SshTransport
) -> dict[str, Any]:
    values = _parse_remote_output(
        transport.run_script(_PROBE_SCRIPT, [target.caldera_root, PAYLOAD_NAME]),
        "remote payload probe",
    )
    status = values.get("status")
    observed = values.get("observed_sha256", "").casefold()
    if status not in {"present", "missing"}:
        raise RemotePreparationError("remote payload probe returned an invalid status")
    if status == "present" and not _SHA256_RE.fullmatch(observed):
        raise RemotePreparationError("remote payload probe returned an invalid SHA-256")
    return {
        "status": status,
        "observed_sha256": observed,
        "payload_path": target.payload_path,
    }


def _staging_receipt(
    *, deployment_sha256: str, caldera_server: str, observed_sha256: str
) -> dict[str, Any]:
    return {
        "schema_version": "c2trace.bench.payload_staging_receipt.v4",
        "receipt_id": str(uuid4()),
        "case_id": EXECUTION_CASE_ID,
        "deployment_manifest_sha256": deployment_sha256,
        "caldera_server": caldera_server.rstrip("/"),
        "payload_name": PAYLOAD_NAME,
        "expected_sha256": ARCHIVE_SHA256,
        "observed_sha256": observed_sha256,
        "verified_at_utc": utc_now(),
        "verification_method": "server_filesystem_sha256",
    }


def stage_payload(
    *,
    project_root: Path,
    target: RemoteTarget,
    caldera_server: str,
    transport: SshTransport,
    allow_create: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    caldera_server = validate_caldera_server(caldera_server, target=target)
    archive, _runtime, deployment_sha256 = validate_local_payload(project_root)
    before = probe_remote_payload(target, transport)
    if before["status"] == "present" and before["observed_sha256"] != ARCHIVE_SHA256:
        raise RemotePreparationError("remote payload differs; refusing to overwrite")
    action = "reused"
    if before["status"] == "missing":
        if not allow_create:
            raise RemotePreparationError("remote payload is missing")
        receipt_id = uuid4().hex
        temp_name = f".c2trace-{receipt_id}.tmp"
        temp_path = f"{target.payload_dir}/{temp_name}"
        copied = transport.copy_file(archive, temp_path)
        if copied.returncode != 0:
            cleanup = transport.run_script(
                _REMOVE_TEMP_SCRIPT, [target.caldera_root, temp_name]
            )
            if cleanup.returncode != 0:
                raise RemotePreparationError(
                    "SCP payload transfer failed and its temporary file requires manual review"
                )
            raise RemotePreparationError(
                f"SCP payload transfer failed with exit {copied.returncode}"
            )
        values = _parse_remote_output(
            transport.run_script(
                _FINALIZE_STAGE_SCRIPT,
                [target.caldera_root, PAYLOAD_NAME, temp_name, ARCHIVE_SHA256],
            ),
            "remote payload finalize",
        )
        action = values.get("status", "")
        if action not in {"created", "reused"}:
            raise RemotePreparationError("remote payload finalize returned invalid status")
    after = probe_remote_payload(target, transport)
    if after["status"] != "present" or after["observed_sha256"] != ARCHIVE_SHA256:
        raise RemotePreparationError("remote payload read-back verification failed")
    receipt = _staging_receipt(
        deployment_sha256=deployment_sha256,
        caldera_server=caldera_server,
        observed_sha256=after["observed_sha256"],
    )
    audit = {
        "schema_version": "c2trace.case_study.payload_staging_audit.v1",
        "case_id": CASE_ID,
        "execution_case_id": EXECUTION_CASE_ID,
        "captured_at_utc": utc_now(),
        "remote": {
            "host": target.host,
            "user": target.user,
            "caldera_root": target.caldera_root,
            "payload_path": target.payload_path,
        },
        "action": action,
        "local_sha256": ARCHIVE_SHA256,
        "observed_sha256": after["observed_sha256"],
        "staging_receipt_sha256": canonical_json_hash(receipt),
        "secret_material_persisted": False,
    }
    return receipt, audit


def cleanup_payload(
    *, target: RemoteTarget, transport: SshTransport, staging_receipt: Mapping[str, Any]
) -> dict[str, Any]:
    if (
        staging_receipt.get("schema_version")
        != "c2trace.bench.payload_staging_receipt.v4"
        or staging_receipt.get("case_id") != EXECUTION_CASE_ID
        or staging_receipt.get("payload_name") != PAYLOAD_NAME
        or str(staging_receipt.get("expected_sha256") or "").casefold()
        != ARCHIVE_SHA256
        or str(staging_receipt.get("observed_sha256") or "").casefold()
        != ARCHIVE_SHA256
        or str(staging_receipt.get("verification_method") or "")
        != "server_filesystem_sha256"
    ):
        raise RemotePreparationError("cleanup requires the matching verified staging receipt")
    validate_caldera_server(
        str(staging_receipt.get("caldera_server") or ""), target=target
    )
    values = _parse_remote_output(
        transport.run_script(
            _CLEANUP_SCRIPT,
            [target.caldera_root, PAYLOAD_NAME, ARCHIVE_SHA256],
        ),
        "remote payload cleanup",
    )
    status = values.get("status")
    if status not in {"removed", "already_absent"}:
        raise RemotePreparationError("remote payload cleanup returned invalid status")
    return {
        "schema_version": "c2trace.case_study.payload_cleanup.v1",
        "case_id": CASE_ID,
        "execution_case_id": EXECUTION_CASE_ID,
        "cleaned_at_utc": utc_now(),
        "remote_host": target.host,
        "payload_path": target.payload_path,
        "expected_sha256": ARCHIVE_SHA256,
        "observed_sha256_before_removal": values.get("observed_sha256", ""),
        "status": status,
        "staging_receipt_sha256": canonical_json_hash(staging_receipt),
        "secret_material_persisted": False,
    }


def _list_api(value: Any, label: str) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [dict(row) for row in value if isinstance(row, Mapping)]
    if isinstance(value, Mapping):
        for key in (label, "items", "data"):
            rows = value.get(key)
            if isinstance(rows, list):
                return [dict(row) for row in rows if isinstance(row, Mapping)]
    raise RemotePreparationError(f"CALDERA response contains no {label} list")


def inspect_caldera_definitions(
    client: CalderaClient, *, case_root: Path
) -> dict[str, Any]:
    ability_payloads = [
        load_ability_payload(path, case_id=EXECUTION_CASE_ID)
        for path in sorted((case_root / "caldera" / "abilities").glob("*.yml"))
    ]
    adversary_payloads = [
        load_adversary_payload(path, case_id=EXECUTION_CASE_ID)
        for path in sorted((case_root / "caldera" / "adversaries").glob("*.yml"))
    ]
    remote_abilities = _list_api(client.request("/api/v2/abilities"), "abilities")
    remote_adversaries = _list_api(
        client.request("/api/v2/adversaries"), "adversaries"
    )

    def classify(
        payloads: Sequence[Mapping[str, Any]],
        remote: Sequence[Mapping[str, Any]],
        *,
        identifier: str,
        equivalent: Any,
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for payload in payloads:
            object_id = str(payload[identifier])
            matches = [
                row
                for row in remote
                if str(row.get(identifier) or row.get("id") or "") == object_id
            ]
            if not matches:
                state = "missing"
            elif len(matches) > 1:
                state = "duplicate"
            elif equivalent(matches[0], payload):
                state = "equivalent"
            else:
                state = "drift"
            rows.append({"id": object_id, "state": state, "remote_count": len(matches)})
        return rows

    abilities = classify(
        ability_payloads,
        remote_abilities,
        identifier="ability_id",
        equivalent=_ability_equivalent,
    )
    adversaries = classify(
        adversary_payloads,
        remote_adversaries,
        identifier="adversary_id",
        equivalent=_adversary_equivalent,
    )
    rows = abilities + adversaries
    counts = {
        state: sum(1 for row in rows if row["state"] == state)
        for state in ("missing", "equivalent", "drift", "duplicate")
    }
    return {
        "schema_version": "c2trace.case_study.caldera_definition_audit.v1",
        "case_id": CASE_ID,
        "execution_case_id": EXECUTION_CASE_ID,
        "captured_at_utc": utc_now(),
        "abilities": abilities,
        "adversaries": adversaries,
        "counts": counts,
        "safe_to_install": counts["drift"] == 0 and counts["duplicate"] == 0,
        "ready": counts == {
            "missing": 0,
            "equivalent": len(rows),
            "drift": 0,
            "duplicate": 0,
        },
        "operation_created": False,
        "secret_material_persisted": False,
    }


__all__ = [
    "DEFAULT_CALDERA_ROOT",
    "DEFAULT_KALI_IP",
    "DEFAULT_KALI_USER",
    "OpenSshTransport",
    "PAYLOAD_NAME",
    "RemotePreparationError",
    "RemoteTarget",
    "cleanup_payload",
    "inspect_caldera_definitions",
    "load_webshell_runtime",
    "probe_remote_payload",
    "stage_payload",
    "validate_local_payload",
    "validate_caldera_server",
    "validate_remote_target",
]
