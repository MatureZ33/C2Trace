import subprocess
import hashlib
import os
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from c2trace.agents import ExecutorAgent
from c2trace.models import AuditDecision, AuditVerdict, CaseFile, MinimalAlert, NodeType, StrategyNode
from c2trace.tools import SystemToolRunner, ToolResult


def test_run_ps_json_decodes_utf8_non_ascii_output():
    completed = subprocess.CompletedProcess(
        args=["powershell"],
        returncode=0,
        stdout='{"items":[{"name":"测试任务"}]}',
        stderr="",
    )
    with patch("c2trace.tools.system.platform.system", return_value="Windows"):
        with patch("c2trace.tools.system.subprocess.run", return_value=completed) as run:
            result = SystemToolRunner()._run_ps_json("ConvertTo-Json @{}", default={})

    assert result.success is True
    assert result.data == {"items": [{"name": "测试任务"}]}
    assert run.call_args.kwargs["encoding"] == "utf-8"
    assert run.call_args.kwargs["errors"] == "replace"


def test_kill_process_uses_pid_and_expected_path_guard():
    completed = subprocess.CompletedProcess(
        args=["powershell"],
        returncode=0,
        stdout='{"killed":true,"pid":4321}',
        stderr="",
    )
    runner = SystemToolRunner(execute_response=True)
    node = StrategyNode(
        node_id="response-1",
        type=NodeType.RESPONSE,
        goal="kill attributed process",
        tool="kill_process",
    )
    decision = AuditDecision(
        node_id=node.node_id,
        verdict=AuditVerdict.APPROVED,
        reason="target is evidence-linked",
    )
    node.audit_decision_id = decision.decision_id
    params = {
        "pid": 4321,
        "process_name": "payload",
        "expected_path": "C:\\Users\\Public\\payload.exe",
    }
    with patch("c2trace.tools.system.platform.system", return_value="Windows"):
        with patch("c2trace.tools.system.subprocess.run", return_value=completed) as run:
            with runner.audited_response(decision=decision, node=node, params=params):
                result = runner.run("kill_process", params)

    command = run.call_args.args[0][-1]
    assert result.success is True
    assert "$pidValue = 4321" in command
    assert "expectedPath" in command
    assert "Stop-Process -Id $target.ProcessId" in command


def test_real_destructive_run_requires_audit_authorization():
    runner = SystemToolRunner(execute_response=True)

    with patch("c2trace.tools.system.subprocess.run") as run:
        result = runner.run("remove_file", {"file_path": "C:\\Users\\Public\\payload.exe"})

    assert result.success is False
    assert "audit authorization" in (result.error or "")
    run.assert_not_called()


def test_direct_destructive_method_cannot_bypass_dry_run_boundary():
    runner = SystemToolRunner(execute_response=False)

    with patch("c2trace.tools.system.subprocess.run") as run:
        result = runner.remove_file("C:\\Users\\Public\\payload.exe")

    assert result.success is False
    assert "direct destructive invocation" in (result.error or "")
    run.assert_not_called()


def test_response_run_still_supports_explicit_dry_run_without_powershell():
    runner = SystemToolRunner(execute_response=False)

    with patch("c2trace.tools.system.subprocess.run") as run:
        result = runner.run("remove_file", {"file_path": "C:\\Users\\Public\\payload.exe"})

    assert result.success is True
    assert result.data["dry_run"] is True
    run.assert_not_called()


def test_audit_authorization_is_bound_to_exact_arguments_and_one_shot():
    runner = SystemToolRunner(execute_response=True)
    node = StrategyNode(
        node_id="response-1",
        type=NodeType.RESPONSE,
        goal="remove attributed file",
        tool="remove_file",
    )
    decision = AuditDecision(
        node_id=node.node_id,
        verdict=AuditVerdict.APPROVED,
        reason="target is evidence-linked",
    )
    node.audit_decision_id = decision.decision_id
    approved_params = {"file_path": "C:\\Users\\Public\\payload.exe"}

    with patch("c2trace.tools.system.subprocess.run") as run:
        with runner.audited_response(decision=decision, node=node, params=approved_params):
            mismatch = runner.remove_file("C:\\Users\\Public\\different.exe")
            replay = runner.remove_file(approved_params["file_path"])

    assert mismatch.success is False
    assert "argument mismatch" in (mismatch.error or "")
    assert replay.success is False
    assert "audit authorization" in (replay.error or "")
    run.assert_not_called()


def test_verify_cleanup_propagates_failed_subcheck():
    runner = SystemToolRunner()

    with patch.object(runner, "check_network", return_value=ToolResult(False, error="access denied")):
        with patch.object(runner, "check_persistence_all", return_value=ToolResult(True, data={})):
            result = runner.verify_cleanup(remote_ip="192.0.2.10")

    assert result.success is False
    assert "network verification failed" in (result.error or "")


def test_check_network_refuses_port_only_or_domain_only_attribution():
    runner = SystemToolRunner()

    with patch("c2trace.tools.system.platform.system", return_value="Windows"):
        with patch("c2trace.tools.system.subprocess.run") as run:
            result = runner.check_network(remote_port=443)

    assert result.success is False
    assert "remote_ip is required" in (result.error or "")
    run.assert_not_called()


def test_check_network_binds_remote_and_suricata_local_port():
    completed = subprocess.CompletedProcess(
        args=["powershell"], returncode=0, stdout='{"connections":[]}', stderr=""
    )
    runner = SystemToolRunner()

    with patch("c2trace.tools.system.platform.system", return_value="Windows"):
        with patch("c2trace.tools.system.subprocess.run", return_value=completed) as run:
            result = runner.check_network(
                remote_ip="192.0.2.10",
                remote_port=8888,
                local_port=50123,
            )

    command = run.call_args.args[0][-1]
    assert result.success is True
    assert "$_.RemoteAddress -eq '192.0.2.10'" in command
    assert "$_.RemotePort -eq 8888" in command
    assert "$_.LocalPort -eq 50123" in command
    assert "$_.State -eq 'Established'" in command
    assert "$_.OwningProcess -gt 0" in command


def test_check_process_places_llm_process_name_inside_single_quoted_powershell_literal():
    completed = subprocess.CompletedProcess(
        args=["powershell"], returncode=0, stdout='{"processes":[]}', stderr=""
    )
    runner = SystemToolRunner()

    with patch("c2trace.tools.system.platform.system", return_value="Windows"):
        with patch("c2trace.tools.system.subprocess.run", return_value=completed) as run:
            result = runner.check_process(process_name="$(Write-Output injected)")

    command = run.call_args.args[0][-1]
    assert result.success is True
    assert '-Filter "Name =' not in command
    assert "-Filter 'Name = ''$(Write-Output injected)''" in command


def test_check_persistence_all_includes_run_and_runonce_locations():
    completed = subprocess.CompletedProcess(
        args=["powershell"],
        returncode=0,
        stdout=(
            '{"registry_run_keys":[],"scheduled_tasks":[],"services":[],'
            '"registry_values":[],"targeted_tasks":[],"targeted_services":[]}'
        ),
        stderr="",
    )
    runner = SystemToolRunner()

    with patch("c2trace.tools.system.platform.system", return_value="Windows"):
        with patch("c2trace.tools.system.subprocess.run", return_value=completed) as run:
            result = runner.check_persistence_all()

    command = run.call_args.args[0][-1]
    assert result.success is True
    assert 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"' in command
    assert 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"' in command
    assert 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"' in command
    assert 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"' in command


@pytest.mark.parametrize(
    "completed",
    [
        subprocess.CompletedProcess(["powershell"], 1, '{"partial":true}', "failed"),
        subprocess.CompletedProcess(["powershell"], 0, "warning\nnot-json", ""),
        subprocess.CompletedProcess(["powershell"], 0, "", ""),
    ],
)
def test_run_ps_json_fails_closed_on_nonzero_malformed_or_empty_output(completed):
    with patch("c2trace.tools.system.platform.system", return_value="Windows"):
        with patch("c2trace.tools.system.subprocess.run", return_value=completed):
            result = SystemToolRunner()._run_ps_json("ConvertTo-Json @{}", default={})

    assert result.success is False


def test_verify_cleanup_without_exact_network_target_fails_closed():
    runner = SystemToolRunner()

    with patch("c2trace.tools.system.platform.system", return_value="Windows"):
        with patch("c2trace.tools.system.subprocess.run") as run:
            result = runner.verify_cleanup()

    assert result.success is False
    assert "exact remote_ip" in (result.error or "")
    assert result.data["network_checked"] is False
    run.assert_not_called()


def test_remove_service_checks_sc_exit_code_before_reporting_success():
    completed = subprocess.CompletedProcess(
        args=["powershell"], returncode=0, stdout='{"removed":true}', stderr=""
    )
    runner = SystemToolRunner(execute_response=True)
    node = StrategyNode("response-service", NodeType.RESPONSE, "remove service", "remove_service")
    decision = AuditDecision(node.node_id, AuditVerdict.APPROVED, "exact service evidence")
    node.audit_decision_id = decision.decision_id
    params = {"service_name": "EvidenceLinkedService"}

    with patch("c2trace.tools.system.platform.system", return_value="Windows"):
        with patch("c2trace.tools.system.subprocess.run", return_value=completed) as run:
            with runner.audited_response(decision=decision, node=node, params=params):
                result = runner.run(node.tool, params)

    assert result.success is True
    assert "$LASTEXITCODE -ne 0" in run.call_args.args[0][-1]


def test_check_recent_files_collects_only_windowed_files_from_fixed_roots(tmp_path):
    public = tmp_path / "Public"
    appdata = tmp_path / "AppData" / "Roaming"
    public.mkdir()
    appdata.mkdir(parents=True)
    public_file = public / "public.log"
    appdata_file = appdata / "target.wmic.log"
    old_file = appdata / "old.log"
    public_file.write_bytes(b"public trace")
    appdata_file.write_bytes(b"wmic trace")
    old_file.write_bytes(b"old trace")
    now = datetime.now(UTC)
    os.utime(public_file, (now.timestamp() - 10, now.timestamp() - 10))
    os.utime(appdata_file, (now.timestamp() - 5, now.timestamp() - 5))
    os.utime(old_file, (now.timestamp() - 3600, now.timestamp() - 3600))
    runner = SystemToolRunner()

    roots = {"users_public": public, "appdata": appdata}
    with patch("c2trace.tools.system.platform.system", return_value="Windows"):
        with patch.object(runner, "_recent_file_allowed_roots", return_value=roots):
            with patch("c2trace.tools.system.subprocess.run") as powershell:
                result = runner.check_recent_files(
                    since_utc=(now - timedelta(minutes=2)).isoformat(),
                    until_utc=(now + timedelta(seconds=1)).isoformat(),
                )

    assert result.success is True
    assert [item["name"] for item in result.data["files"]] == [
        "target.wmic.log",
        "public.log",
    ]
    by_name = {item["name"]: item for item in result.data["files"]}
    assert by_name["target.wmic.log"]["sha256"] == hashlib.sha256(b"wmic trace").hexdigest()
    assert by_name["target.wmic.log"]["size"] == len(b"wmic trace")
    assert by_name["target.wmic.log"]["exists"] is True
    assert by_name["target.wmic.log"]["sha256_status"] == "hashed"
    assert result.data["scan"]["matching_file_count"] == 2
    assert result.data["scan"]["truncated"] is False
    powershell.assert_not_called()


def test_check_recent_files_rejects_arbitrary_root_or_unbounded_limits():
    runner = SystemToolRunner()

    with patch("c2trace.tools.system.platform.system", return_value="Windows"):
        arbitrary = runner.check_recent_files(root_aliases=[r"C:\Windows"])
        excessive_depth = runner.check_recent_files(max_depth=99)
        excessive_size = runner.check_recent_files(max_file_size=32 * 1024 * 1024)

    assert arbitrary.success is False
    assert "unsupported recent-file root alias" in (arbitrary.error or "")
    assert excessive_depth.success is False
    assert "max_depth must be between" in (excessive_depth.error or "")
    assert excessive_size.success is False
    assert "max_file_size must be between" in (excessive_size.error or "")


def test_check_recent_files_requires_bounded_utc_window():
    runner = SystemToolRunner()
    now = datetime.now(UTC)

    with patch("c2trace.tools.system.platform.system", return_value="Windows"):
        non_utc = runner.check_recent_files(
            since_utc=(now - timedelta(minutes=1)).astimezone().replace(tzinfo=None).isoformat(),
            until_utc=now.isoformat(),
        )
        too_wide = runner.check_recent_files(
            since_utc=(now - timedelta(hours=3)).isoformat(),
            until_utc=now.isoformat(),
        )

    assert non_utc.success is False
    assert "must include the UTC offset" in (non_utc.error or "")
    assert too_wide.success is False
    assert "cannot exceed 2 hours" in (too_wide.error or "")


def test_check_recent_files_does_not_hash_file_over_size_limit(tmp_path):
    public = tmp_path / "Public"
    appdata = tmp_path / "AppData" / "Roaming"
    public.mkdir()
    appdata.mkdir(parents=True)
    oversized = appdata / "large.log"
    oversized.write_bytes(b"x" * 64)
    runner = SystemToolRunner()
    now = datetime.now(UTC)

    with patch("c2trace.tools.system.platform.system", return_value="Windows"):
        with patch.object(
            runner,
            "_recent_file_allowed_roots",
            return_value={"users_public": public, "appdata": appdata},
        ):
            result = runner.check_recent_files(
                since_utc=(now - timedelta(minutes=1)).isoformat(),
                until_utc=(now + timedelta(seconds=1)).isoformat(),
                max_file_size=32,
            )

    assert result.success is True
    assert result.data["files"][0]["sha256"] == ""
    assert result.data["files"][0]["sha256_status"] == "skipped_size_limit"


def test_check_recent_files_depth_zero_keeps_newest_root_files_in_stable_order(tmp_path):
    public = tmp_path / "Public"
    appdata = tmp_path / "AppData" / "Roaming"
    nested = appdata / "nested"
    public.mkdir()
    nested.mkdir(parents=True)
    now = datetime.now(UTC)
    timestamps = {
        appdata / "second.log": now.timestamp() - 2,
        appdata / "first.log": now.timestamp() - 1,
        appdata / "third.log": now.timestamp() - 3,
        nested / "newest-but-nested.log": now.timestamp(),
    }
    for path, timestamp in timestamps.items():
        path.write_text(path.name, encoding="utf-8")
        os.utime(path, (timestamp, timestamp))
    runner = SystemToolRunner()

    with patch("c2trace.tools.system.platform.system", return_value="Windows"):
        with patch.object(
            runner,
            "_recent_file_allowed_roots",
            return_value={"users_public": public, "appdata": appdata},
        ):
            result = runner.check_recent_files(max_depth=0, max_results=2)

    assert result.success is True
    assert [item["name"] for item in result.data["files"]] == ["first.log", "second.log"]
    assert "newest-but-nested.log" not in {item["name"] for item in result.data["files"]}
    assert result.data["scan"]["matching_file_count"] == 3
    assert result.data["scan"]["truncated"] is True
    assert "result_limit" in result.data["scan"]["truncated_reasons"]


def test_check_recent_files_fails_if_any_selected_fixed_root_is_unavailable(tmp_path):
    public = tmp_path / "missing-public"
    appdata = tmp_path / "AppData" / "Roaming"
    appdata.mkdir(parents=True)
    runner = SystemToolRunner()

    with patch("c2trace.tools.system.platform.system", return_value="Windows"):
        with patch.object(
            runner,
            "_recent_file_allowed_roots",
            return_value={"users_public": public, "appdata": appdata},
        ):
            result = runner.check_recent_files()

    assert result.success is False
    assert "selected recent-file roots is unavailable" in (result.error or "")
    assert result.data["unavailable_root_aliases"] == ["users_public"]


def test_recent_file_tool_is_read_only_and_emits_file_metadata_findings():
    class RecentFileRunner:
        def run(self, tool, params=None):
            assert tool == "check_recent_files"
            return ToolResult(True, data={"files": [
                {
                    "path": r"C:\Users\tester\AppData\Roaming\trial.wmic.log",
                    "size": 12,
                    "creation_time_utc": "2026-07-15T09:00:00Z",
                    "last_write_time_utc": "2026-07-15T09:00:01Z",
                    "sha256": "a" * 64,
                },
                {
                    "path": r"C:\Users\tester\AppData\Roaming\trial.tasklist.log",
                    "size": 13,
                    "creation_time_utc": "2026-07-15T09:00:00Z",
                    "last_write_time_utc": "2026-07-15T09:00:02Z",
                    "sha256": "b" * 64,
                },
            ]})

    alert = MinimalAlert.from_dict({
        "case_id": "recent-files",
        "alert_id": "recent-files-alert",
        "source": "suricata",
        "alert_type": "c2_tcp_beacon",
        "victim_ip": "192.0.2.20",
        "remote_ip": "192.0.2.10",
        "remote_port": 7010,
        "protocol": "tcp",
        "confidence": 0.8,
    })
    case = CaseFile.from_alert(alert)
    node = StrategyNode(
        node_id="recent-files-node",
        type=NodeType.INVESTIGATE,
        goal="discover recent host artifacts",
        tool="check_recent_files",
    )
    node.validate_tool_policy()

    result = ExecutorAgent(tool_runner=RecentFileRunner()).execute(case, node, {})

    assert result.success is True
    file_findings = [item for item in case.findings if item.finding_type == "file_metadata"]
    assert len(file_findings) == 2
    assert {item.details["sha256"] for item in file_findings} == {"a" * 64, "b" * 64}
    assert all(item.source == "executor" for item in file_findings)
