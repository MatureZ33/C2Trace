import json
import subprocess
from unittest.mock import patch

import pytest

from c2trace.models import CaseFile, MinimalAlert, StrategyTree
from c2trace.target_safety import (
    PROTECTED_PROCESSES_SCHEMA_V2,
    TARGET_LOCK_SCHEMA_V1,
    TARGET_LOCK_SCHEMA_V2,
    TargetSafetyError,
    TargetSafetyGuard,
    load_protected_processes,
    load_reviewed_target,
)
from c2trace.tools import SystemToolRunner, ToolResult


VICTIM = "192.168.21.138"
KALI = "192.168.21.132"
SANDCAT_PATH = r"C:\Users\Public\c2t_target_sandcat.exe"
CONTROL_PATH = r"C:\Users\Public\control_sandcat.exe"
SANDCAT_HASH = "a" * 64
SANDCAT_CREATED = "2026-07-15t01:00:00+00:00"
CONTROL_CREATED = "2026-07-15t00:00:00+00:00"
HTTPD_PATH = r"C:\Apache24\bin\httpd.exe"
HTTPD_HASH = "b" * 64
WEBSHELL_PATH = r"C:\Apache24\htdocs\c2t_webshell.php"
WEBSHELL_HASH = "c" * 64


def _response_node(tool: str):
    return StrategyTree.from_dict(
        {
            "root_objective": "v2 safety test",
            "nodes": [
                {
                    "node_id": "investigate",
                    "type": "investigate",
                    "goal": "investigate",
                    "tool": "check_network",
                },
                {
                    "node_id": "decision",
                    "type": "decision",
                    "goal": "decide",
                    "condition": "evidence_sufficient_for_response",
                    "requires": ["investigate"],
                },
                {
                    "node_id": "response",
                    "type": "response",
                    "goal": "respond",
                    "tool": tool,
                    "requires": ["decision"],
                },
                {
                    "node_id": "verify",
                    "type": "verify",
                    "goal": "verify",
                    "tool": "verify_cleanup",
                    "requires": ["response"],
                },
            ],
        }
    ).node_map()["response"]


def _case(*, listener: bool = False, timestamp: str = "2026-07-15T01:01:00+00:00"):
    if listener:
        src_ip, src_port, dest_ip, dest_port, remote_port = KALI, 54321, VICTIM, 8080, 54321
        alert_type = "webshell_http_request"
        signature_id = 9204101
    else:
        src_ip, src_port, dest_ip, dest_port, remote_port = VICTIM, 51001, KALI, 8888, 8888
        alert_type = "c2_http_beacon"
        signature_id = 9204002
    alert = MinimalAlert.from_dict(
        {
            "case_id": "MEP-TARGET-SAFETY-V2",
            "alert_id": "MEP-TARGET-SAFETY-V2-alert",
            "source": "suricata",
            "alert_type": alert_type,
            "victim_ip": VICTIM,
            "remote_ip": KALI,
            "remote_port": remote_port,
            "protocol": "tcp",
        }
    )
    return CaseFile.from_alert(
        alert,
        source_events=[
            {
                "timestamp": timestamp,
                "event_type": "alert",
                "src_ip": src_ip,
                "src_port": src_port,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "proto": "TCP",
                "signature_id": signature_id,
                "flow_id": "v2-flow-1",
            }
        ],
        source_artifacts=[{"event_sha256": "d" * 64}],
    )


def _sandcat_expected(**overrides):
    value = {
        "target_type": "sandcat_http_client",
        "network_mode": "outbound_active_flow",
        "paw": "target-paw",
        "pid": 4242,
        "creation_time_utc": SANDCAT_CREATED,
        "path": SANDCAT_PATH,
        "sha256": SANDCAT_HASH,
        "group": "c2t-run-target",
        "host": "WIN10",
        "contact": "http",
        "network_identity": {
            "protocol": "tcp",
            "local_ip": VICTIM,
            "local_port": 51001,
            "remote_ip": KALI,
            "remote_port": 8888,
            "direction": "victim_to_remote",
            "signature_id": 9204002,
        },
        "source_not_before_utc": "2026-07-15T01:00:30+00:00",
    }
    value.update(overrides)
    return value


class SandcatRunner:
    def __init__(self, *, pid=4242, creation=SANDCAT_CREATED, path=SANDCAT_PATH, conflicts=1):
        self.pid = pid
        self.creation = creation
        self.path = path
        self.conflicts = conflicts
        self.calls = []

    def run(self, tool, params=None):
        params = dict(params or {})
        self.calls.append((tool, params))
        if tool == "check_network":
            rows = [
                {
                    "local_address": VICTIM,
                    "local_port": 51001,
                    "remote_address": KALI,
                    "remote_port": 8888,
                    "state": "Established",
                    "pid": self.pid + index,
                    "process_path": self.path,
                }
                for index in range(self.conflicts)
            ]
            return ToolResult(True, data={"connections": rows})
        if tool == "check_process":
            return ToolResult(
                True,
                data={
                    "processes": [
                        {
                            "pid": self.pid,
                            "name": "sandcat.exe",
                            "path": self.path,
                            "creation_time_utc": self.creation,
                        }
                    ]
                },
            )
        if tool == "check_file_metadata":
            return ToolResult(
                True,
                data={
                    "file": {
                        "exists": True,
                        "path": self.path,
                        "sha256": SANDCAT_HASH,
                    }
                },
            )
        return ToolResult(True, data={})


class ListenerRunner:
    def __init__(self, *, listener_count=1):
        self.listener_count = listener_count
        self.calls = []

    def run(self, tool, params=None):
        params = dict(params or {})
        self.calls.append((tool, params))
        if tool == "check_network":
            rows = [
                {
                    "local_address": "0.0.0.0",
                    "local_port": 8080,
                    "remote_address": "0.0.0.0",
                    "remote_port": 0,
                    "state": "Listen",
                    "pid": 7000 + index,
                    "process_path": HTTPD_PATH,
                }
                for index in range(self.listener_count)
            ]
            return ToolResult(True, data={"connections": rows})
        if tool == "check_process":
            return ToolResult(
                True,
                data={
                    "processes": [
                        {
                            "pid": 7000,
                            "name": "httpd.exe",
                            "path": HTTPD_PATH,
                            "creation_time_utc": SANDCAT_CREATED,
                        }
                    ]
                },
            )
        if tool == "check_file_metadata":
            path = params["file_path"]
            digest = HTTPD_HASH if path.lower() == HTTPD_PATH.lower() else WEBSHELL_HASH
            return ToolResult(True, data={"file": {"exists": True, "path": path, "sha256": digest}})
        return ToolResult(True, data={})


def _webshell_expected():
    return {
        "target_type": "windows_webshell_http_listener",
        "network_mode": "inbound_listener",
        "listener_owner": {
            "pid": 7000,
            "created_at": SANDCAT_CREATED,
            "path": HTTPD_PATH,
            "sha256": HTTPD_HASH,
            "host": "WIN10",
        },
        "host": "WIN10",
        "payload_artifacts": [
            {
                "path": WEBSHELL_PATH,
                "sha256": WEBSHELL_HASH,
                "artifact_role": "webshell_payload",
            }
        ],
        "network_identity": {
            "protocol": "tcp",
            "local_ip": VICTIM,
            "local_port": 8080,
            "remote_ip": KALI,
            "remote_port": 54321,
            "direction": "remote_to_victim",
            "signature_id": 9204101,
        },
        "source_not_before_utc": "2026-07-15T01:00:30+00:00",
        "response_policy": {
            "allow_process_termination": False,
            "allow_file_removal": True,
        },
    }


def test_v2_target_sandcat_uses_exact_local_port_and_does_not_confuse_shared_hash():
    runner = SandcatRunner()
    guard = TargetSafetyGuard(
        tool_runner=runner,
        run_id="run-v2-sandcat",
        expected_target=_sandcat_expected(),
        target_lock_schema_version=TARGET_LOCK_SCHEMA_V2,
        protected_processes=[
            {
                "label": "control-sandcat",
                "pid": 1111,
                "creation_time_utc": CONTROL_CREATED,
                "path": CONTROL_PATH,
                "canonical_path": CONTROL_PATH.lower(),
                "sha256": SANDCAT_HASH,
            }
        ],
    )
    case = _case()
    guard.validate_case_input(case)

    lock = guard.prepare_response(
        case,
        _response_node("kill_process"),
        {"pid": 4242, "expected_path": SANDCAT_PATH},
    )

    assert lock["schema_version"] == TARGET_LOCK_SCHEMA_V2
    assert lock["target_type"] == "sandcat_http_client"
    assert lock["target_paw"] == "target-paw"
    assert lock["network"]["local_port"] == 51001
    assert ("check_network", {"remote_ip": KALI, "remote_port": 8888, "local_port": 51001}) in runner.calls


def test_v2_still_blocks_the_exact_control_sandcat_on_shared_8888():
    runner = SandcatRunner(pid=1111, creation=CONTROL_CREATED, path=CONTROL_PATH)
    guard = TargetSafetyGuard(
        tool_runner=runner,
        run_id="run-v2-control",
        expected_target=_sandcat_expected(pid=1111, creation_time_utc=CONTROL_CREATED, path=CONTROL_PATH),
        target_lock_schema_version=TARGET_LOCK_SCHEMA_V2,
        protected_processes=[
            {
                "label": "control-sandcat",
                "pid": 1111,
                "creation_time_utc": CONTROL_CREATED,
                "path": CONTROL_PATH,
                "canonical_path": CONTROL_PATH.lower(),
                "sha256": SANDCAT_HASH,
            }
        ],
    )

    with pytest.raises(TargetSafetyError) as caught:
        guard.prepare_response(
            _case(),
            _response_node("kill_process"),
            {"pid": 1111, "expected_path": CONTROL_PATH},
        )
    assert caught.value.status == "protected_target_blocked"
    assert "pid_creation_time" in caught.value.details["matched_by"]


def test_v2_detects_pid_reuse_by_creation_time():
    guard = TargetSafetyGuard(
        tool_runner=SandcatRunner(creation="2026-07-15t02:00:00+00:00"),
        run_id="run-v2-pid-reuse",
        expected_target=_sandcat_expected(),
        target_lock_schema_version=TARGET_LOCK_SCHEMA_V2,
    )

    with pytest.raises(TargetSafetyError) as caught:
        guard.prepare_response(
            _case(),
            _response_node("kill_process"),
            {"pid": 4242, "expected_path": SANDCAT_PATH},
        )
    assert caught.value.status == "target_drift"
    assert "process.creation_time_utc" in caught.value.details["differences"]


def test_v2_rejects_source_event_older_than_target_instance():
    guard = TargetSafetyGuard(
        tool_runner=SandcatRunner(),
        run_id="run-v2-stale",
        expected_target=_sandcat_expected(),
        target_lock_schema_version=TARGET_LOCK_SCHEMA_V2,
    )

    with pytest.raises(TargetSafetyError, match="predates"):
        guard.validate_case_input(_case(timestamp="2026-07-15T00:59:00+00:00"))


def test_v2_listener_lock_separates_host_process_from_webshell_payload():
    runner = ListenerRunner()
    guard = TargetSafetyGuard(
        tool_runner=runner,
        run_id="run-v2-webshell",
        expected_target=_webshell_expected(),
        target_lock_schema_version=TARGET_LOCK_SCHEMA_V2,
    )
    case = _case(listener=True)
    guard.validate_case_input(case)

    lock = guard.prepare_response(
        case,
        _response_node("remove_file"),
        {"file_path": WEBSHELL_PATH},
    )

    assert lock["network_mode"] == "inbound_listener"
    assert lock["network"]["listener_address"] == "0.0.0.0"
    assert lock["process"]["canonical_path"].endswith(r"apache24\bin\httpd.exe")
    assert lock["file"]["canonical_path"].endswith(r"apache24\htdocs\c2t_webshell.php")
    assert lock["file"]["artifact_role"] == "webshell_payload"
    assert runner.calls[0] == (
        "check_network",
        {"network_mode": "inbound_listener", "local_ip": VICTIM, "local_port": 8080},
    )

    with pytest.raises(TargetSafetyError) as caught:
        guard.prepare_response(
            case,
            _response_node("kill_process"),
            {"pid": 7000, "expected_path": HTTPD_PATH},
        )
    assert caught.value.status == "protected_target_blocked"


def test_v2_listener_port_conflict_fails_closed():
    guard = TargetSafetyGuard(
        tool_runner=ListenerRunner(listener_count=2),
        run_id="run-v2-listener-conflict",
        expected_target=_webshell_expected(),
        target_lock_schema_version=TARGET_LOCK_SCHEMA_V2,
    )

    with pytest.raises(TargetSafetyError) as caught:
        guard.prepare_response(
            _case(listener=True),
            _response_node("remove_file"),
            {"file_path": WEBSHELL_PATH},
        )
    assert caught.value.status == "target_drift"
    assert caught.value.details["matching_connections"] == 2


def test_v2_manifest_and_reviewed_lock_load_while_v1_remains_supported(tmp_path):
    manifest = tmp_path / "protected-v2.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": PROTECTED_PROCESSES_SCHEMA_V2,
                "run_id": "run-v2-load",
                "processes": [
                    {
                        "label": "control-sandcat",
                        "pid": 1111,
                        "creation_time_utc": CONTROL_CREATED,
                        "path": CONTROL_PATH,
                        "sha256": SANDCAT_HASH,
                    }
                ],
                "expected_target": _sandcat_expected(),
            }
        ),
        encoding="utf-8",
    )
    loaded = load_protected_processes(manifest)
    assert loaded.payload["target_lock_schema_version"] == TARGET_LOCK_SCHEMA_V2

    guard = TargetSafetyGuard(
        tool_runner=SandcatRunner(),
        run_id="run-v2-load",
        expected_target=loaded.payload["expected_target"],
        target_lock_schema_version=loaded.payload["target_lock_schema_version"],
    )
    case = _case()
    guard.validate_case_input(case)
    lock = guard.prepare_response(
        case,
        _response_node("kill_process"),
        {"pid": 4242, "expected_path": SANDCAT_PATH},
    )
    lock_path = tmp_path / "lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    assert load_reviewed_target(lock_path).payload["schema_version"] == TARGET_LOCK_SCHEMA_V2
    assert TARGET_LOCK_SCHEMA_V1 == "c2trace.response_target_lock.v1"


def test_system_network_probe_can_bind_an_inbound_listener_without_remote_ip():
    completed = subprocess.CompletedProcess(
        args=["powershell"], returncode=0, stdout='{"connections":[]}', stderr=""
    )
    runner = SystemToolRunner()
    with patch("c2trace.tools.system.platform.system", return_value="Windows"):
        with patch("c2trace.tools.system.subprocess.run", return_value=completed) as run:
            result = runner.check_network(
                network_mode="inbound_listener",
                local_ip=VICTIM,
                local_port=8080,
            )

    command = run.call_args.args[0][-1]
    assert result.success is True
    assert "$_.LocalPort -eq 8080" in command
    assert "$_.State -eq 'Listen'" in command
    # Listener discovery may return the remote columns for evidence, but it
    # must not filter on a remote endpoint because a listening socket has no
    # established peer yet.
    assert "$_.RemoteAddress -eq" not in command
