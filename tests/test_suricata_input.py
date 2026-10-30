import hashlib
import json

import pytest

from c2trace.models import FORBIDDEN_ALERT_FIELDS
from c2trace.suricata import (
    SuricataAlertError,
    SuricataFilters,
    SuricataSelection,
    event_to_minimal_alert,
    load_eve_records_with_artifacts,
    sanitize_source_event,
    select_suricata_alert,
    select_suricata_alert_with_artifact,
)


def _eve_alert(**overrides):
    event = {
        "timestamp": "2026-07-04T15:40:00.000000+0800",
        "flow_id": 12345,
        "event_type": "alert",
        "src_ip": "192.168.21.138",
        "src_port": 50555,
        "dest_ip": "192.168.21.132",
        "dest_port": 8888,
        "proto": "TCP",
        "app_proto": "http",
        "alert": {
            "signature": "C2TRACE Possible HTTP C2 Beacon",
            "signature_id": 9000001,
            "category": "Potential C2",
            "severity": 2,
        },
        "payload": "forbidden raw payload",
    }
    event.update(overrides)
    return event


def test_suricata_alert_converts_to_minimal_alert():
    alert, source_event = event_to_minimal_alert(_eve_alert(), case_id="S002", victim_ip="192.168.21.138")

    payload = alert.to_dict()
    assert payload["source"] == "suricata_eve"
    assert payload["alert_type"] == "c2_http_beacon"
    assert payload["victim_ip"] == "192.168.21.138"
    assert payload["remote_ip"] == "192.168.21.132"
    assert payload["remote_port"] == 8888
    assert payload["protocol"] == "http"
    assert not (set(payload) & FORBIDDEN_ALERT_FIELDS)
    assert "payload" not in source_event
    assert source_event["signature_id"] == 9000001


def test_suricata_jsonl_filters_signature_port_and_app_proto(tmp_path):
    eve_path = tmp_path / "eve.json"
    events = [
        {"event_type": "dns", "src_ip": "1.1.1.1"},
        _eve_alert(alert={"signature": "Other alert", "signature_id": 42, "severity": 3}),
        _eve_alert(src_port=44444, flow_id=777),
    ]
    eve_path.write_text("\n".join(json.dumps(item) for item in events), encoding="utf-8")

    alert, source_event = select_suricata_alert(
        eve_path,
        case_id="S002",
        victim_ip="192.168.21.138",
        filters=SuricataFilters(
            signature_contains="HTTP C2",
            signature_id="9000001",
            app_proto="http",
            dest_port=8888,
        ),
    )

    assert alert.to_dict()["remote_ip"] == "192.168.21.132"
    assert source_event["flow_id"] == 777


def test_suricata_selection_returns_raw_artifact_reference(tmp_path):
    eve_path = tmp_path / "eve.json"
    events = [
        {"event_type": "dns", "src_ip": "1.1.1.1"},
        _eve_alert(flow_id=888),
    ]
    eve_path.write_text("\n".join(json.dumps(item) for item in events), encoding="utf-8")

    _, source_event, artifact = select_suricata_alert_with_artifact(
        eve_path,
        case_id="S002",
        victim_ip="192.168.21.138",
        filters=SuricataFilters(signature_id="9000001"),
    )

    assert source_event["flow_id"] == 888
    assert artifact["artifact_type"] == "suricata_eve"
    assert artifact["path"].endswith("eve.json")
    assert artifact["line_number"] == 2
    assert len(artifact["file_sha256"]) == 64
    assert len(artifact["event_sha256"]) == 64
    assert len(artifact["raw_record_sha256"]) == 64
    assert artifact["file_sha256"] == hashlib.sha256(eve_path.read_bytes()).hexdigest()
    assert artifact["raw_record_sha256"] == hashlib.sha256(eve_path.read_bytes().splitlines()[1]).hexdigest()
    assert artifact["selection"] == {
        "policy": "latest",
        "match_count": 1,
        "selected_match_number": 1,
        "ordering": "eve_source_order",
    }


def test_suricata_selection_defaults_to_latest_matching_record(tmp_path):
    eve_path = tmp_path / "eve.json"
    events = [
        _eve_alert(timestamp="2026-07-04T15:40:00+08:00", flow_id=111, src_port=50001),
        _eve_alert(timestamp="2026-07-04T15:41:00+08:00", flow_id=222, src_port=50002),
    ]
    eve_path.write_text("\n".join(json.dumps(item) for item in events), encoding="utf-8")

    _, source_event, artifact = select_suricata_alert_with_artifact(
        eve_path,
        case_id="S002",
        victim_ip="192.168.21.138",
        filters=SuricataFilters(signature_id="9000001"),
    )

    assert source_event["flow_id"] == 222
    assert artifact["line_number"] == 2
    assert artifact["selection"]["policy"] == "latest"
    assert artifact["selection"]["match_count"] == 2
    assert artifact["selection"]["selected_match_number"] == 2


def test_suricata_selection_can_request_first_or_a_flow_id(tmp_path):
    eve_path = tmp_path / "eve.json"
    events = [_eve_alert(flow_id=111), _eve_alert(flow_id=222), _eve_alert(flow_id=222, src_port=50003)]
    eve_path.write_text("\n".join(json.dumps(item) for item in events), encoding="utf-8")

    _, first_event, first_artifact = select_suricata_alert_with_artifact(
        eve_path,
        case_id="S002",
        victim_ip="192.168.21.138",
        selection=SuricataSelection(policy="first"),
    )
    _, flow_event, flow_artifact = select_suricata_alert_with_artifact(
        eve_path,
        case_id="S002",
        victim_ip="192.168.21.138",
        selection=SuricataSelection(flow_id="222"),
    )

    assert first_event["flow_id"] == 111
    assert first_artifact["line_number"] == 1
    assert flow_event["src_port"] == 50003
    assert flow_artifact["line_number"] == 3
    assert flow_artifact["selection"]["flow_id"] == "222"
    assert flow_artifact["selection"]["match_count"] == 2


def test_suricata_selection_can_freeze_exact_line_and_event_hash(tmp_path):
    eve_path = tmp_path / "eve.json"
    # A leading blank line verifies that the frozen line number refers to the
    # physical EVE file and is not shifted by whitespace trimming.
    events = [_eve_alert(flow_id=111), _eve_alert(flow_id=222)]
    eve_path.write_text("\n\n" + "\n".join(json.dumps(item) for item in events), encoding="utf-8")
    records = load_eve_records_with_artifacts(eve_path)
    selected_hash = records[0][1]["event_sha256"]

    _, source_event, artifact = select_suricata_alert_with_artifact(
        eve_path,
        case_id="S002",
        victim_ip="192.168.21.138",
        selection=SuricataSelection(line_number=3, event_sha256=selected_hash),
    )

    assert source_event["flow_id"] == 111
    assert artifact["line_number"] == 3
    assert artifact["event_sha256"] == selected_hash
    assert artifact["raw_record_sha256"]


def test_suricata_selection_rejects_selector_mismatch(tmp_path):
    eve_path = tmp_path / "eve.json"
    eve_path.write_text(json.dumps([_eve_alert(flow_id=111)]), encoding="utf-8")

    with pytest.raises(SuricataAlertError, match="no matching Suricata alert"):
        select_suricata_alert_with_artifact(
            eve_path,
            case_id="S002",
            victim_ip="192.168.21.138",
            selection=SuricataSelection(flow_id="222"),
        )


def test_suricata_direction_when_victim_is_destination():
    event = _eve_alert(
        src_ip="192.168.21.132",
        src_port=8888,
        dest_ip="192.168.21.138",
        dest_port=50555,
    )

    alert, _ = event_to_minimal_alert(event, case_id="S002", victim_ip="192.168.21.138")

    assert alert.to_dict()["victim_ip"] == "192.168.21.138"
    assert alert.to_dict()["remote_ip"] == "192.168.21.132"
    assert alert.to_dict()["remote_port"] == 8888


def test_sanitized_source_event_uses_only_allowed_metadata():
    event = _eve_alert(
        pid=5252,
        process_path="C:\\Users\\Public\\sandcat_s002.exe",
        payload_path="C:\\Users\\Public\\sandcat_s002.exe",
        run_key="S002Sandcat",
    )

    source_event = sanitize_source_event(event)

    assert "pid" not in source_event
    assert "process_path" not in source_event
    assert "payload_path" not in source_event
    assert "run_key" not in source_event
