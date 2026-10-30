from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from c2trace.models import MinimalAlert, ValidationError


class SuricataAlertError(ValueError):
    pass


SOURCE_EVENT_FIELDS = {
    "timestamp",
    "event_type",
    "src_ip",
    "src_port",
    "dest_ip",
    "dest_port",
    "proto",
    "app_proto",
    "signature",
    "signature_id",
    "category",
    "severity",
    "flow_id",
}


@dataclass(slots=True)
class SuricataFilters:
    signature_contains: str = ""
    signature_id: str = ""
    app_proto: str = ""
    dest_port: int | None = None


@dataclass(slots=True)
class SuricataSelection:
    """Select one reproducible event after the ordinary alert filters run.

    ``latest`` means the last matching record in EVE source order. Suricata
    appends EVE JSONL records in observation order, so this is the useful
    default for a just-triggered experiment.  The location/hash selectors are
    optional exact selectors and may be combined with ``flow_id`` as a
    consistency check.
    """

    policy: str = "latest"
    flow_id: str = ""
    line_number: int | None = None
    record_index: int | None = None
    event_sha256: str = ""

    def normalized(self) -> "SuricataSelection":
        policy = str(self.policy or "latest").lower()
        if policy not in {"first", "latest"}:
            raise SuricataAlertError("Suricata selection policy must be 'first' or 'latest'")
        if self.line_number is not None and self.line_number < 1:
            raise SuricataAlertError("Suricata EVE line number must be >= 1")
        if self.record_index is not None and self.record_index < 1:
            raise SuricataAlertError("Suricata EVE record index must be >= 1")
        if self.line_number is not None and self.record_index is not None:
            raise SuricataAlertError("select by either EVE line number or record index, not both")
        event_sha256 = str(self.event_sha256 or "").lower()
        if event_sha256 and (len(event_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in event_sha256)):
            raise SuricataAlertError("Suricata event_sha256 must be a 64-character hexadecimal digest")
        return SuricataSelection(
            policy=policy,
            flow_id=str(self.flow_id or ""),
            line_number=self.line_number,
            record_index=self.record_index,
            event_sha256=event_sha256,
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"policy": self.policy}
        if self.flow_id:
            payload["flow_id"] = self.flow_id
        if self.line_number is not None:
            payload["line_number"] = self.line_number
        if self.record_index is not None:
            payload["record_index"] = self.record_index
        if self.event_sha256:
            payload["event_sha256"] = self.event_sha256
        return payload


def load_eve_records(path: str | Path) -> list[dict[str, Any]]:
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        records: list[dict[str, Any]] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SuricataAlertError(f"invalid JSONL at line {line_no}: {exc}") from exc
            if isinstance(item, dict):
                records.append(item)
        return records
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    raise SuricataAlertError("Suricata EVE input must be a JSON object, JSON array, or JSONL")


def load_eve_records_with_artifacts(path: str | Path) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    input_path = Path(path)
    raw_bytes = input_path.read_bytes()
    file_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    text = raw_bytes.decode("utf-8-sig")
    if not text.strip():
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        records: list[tuple[dict[str, Any], dict[str, Any]]] = []
        raw_lines = raw_bytes.splitlines()
        for line_no, raw_line_bytes in enumerate(raw_lines, start=1):
            # utf-8-sig removes a BOM only from the first record while retaining
            # the original bytes for an exact raw-record digest.
            line = raw_line_bytes.decode("utf-8-sig" if line_no == 1 else "utf-8")
            stripped_line = line.strip()
            if not stripped_line:
                continue
            try:
                item = json.loads(stripped_line)
            except json.JSONDecodeError as exc:
                raise SuricataAlertError(f"invalid JSONL at line {line_no}: {exc}") from exc
            if isinstance(item, dict):
                records.append((
                    item,
                    _source_artifact(
                        input_path,
                        file_sha256,
                        item,
                        file_size_bytes=len(raw_bytes),
                        line_number=line_no,
                        raw_record=raw_line_bytes,
                    ),
                ))
        return records
    if isinstance(parsed, dict):
        return [(
            parsed,
            _source_artifact(
                input_path,
                file_sha256,
                parsed,
                file_size_bytes=len(raw_bytes),
                record_index=1,
                raw_record=raw_bytes,
            ),
        )]
    if isinstance(parsed, list):
        records = []
        for index, item in enumerate(parsed, start=1):
            if isinstance(item, dict):
                records.append((
                    item,
                    _source_artifact(
                        input_path,
                        file_sha256,
                        item,
                        file_size_bytes=len(raw_bytes),
                        record_index=index,
                    ),
                ))
        return records
    raise SuricataAlertError("Suricata EVE input must be a JSON object, JSON array, or JSONL")


def select_suricata_alert(
    path: str | Path,
    *,
    case_id: str,
    victim_ip: str,
    filters: SuricataFilters | None = None,
    selection: SuricataSelection | None = None,
) -> tuple[MinimalAlert, dict[str, Any]]:
    alert, source_event, _ = select_suricata_alert_with_artifact(
        path,
        case_id=case_id,
        victim_ip=victim_ip,
        filters=filters,
        selection=selection,
    )
    return alert, source_event


def select_suricata_alert_with_artifact(
    path: str | Path,
    *,
    case_id: str,
    victim_ip: str,
    filters: SuricataFilters | None = None,
    selection: SuricataSelection | None = None,
) -> tuple[MinimalAlert, dict[str, Any], dict[str, Any]]:
    records = load_eve_records_with_artifacts(path)
    filters = filters or SuricataFilters()
    selection = (selection or SuricataSelection()).normalized()
    matches: list[tuple[MinimalAlert, dict[str, Any], dict[str, Any]]] = []
    for event, artifact in records:
        if not _matches_filters(event, filters):
            continue
        if not _matches_selection(event, artifact, selection):
            continue
        try:
            alert, source_event = event_to_minimal_alert(event, case_id=case_id, victim_ip=victim_ip)
            matches.append((alert, source_event, artifact))
        except SuricataAlertError:
            continue
    if not matches:
        selector_text = json.dumps(selection.to_dict(), ensure_ascii=False, sort_keys=True)
        raise SuricataAlertError(
            "no matching Suricata alert event was found for the victim/filter/selection criteria "
            f"(selection={selector_text})"
        )

    selected_index = 0 if selection.policy == "first" else len(matches) - 1
    alert, source_event, selected_artifact = matches[selected_index]
    artifact = dict(selected_artifact)
    artifact["selection"] = {
        **selection.to_dict(),
        "match_count": len(matches),
        "selected_match_number": selected_index + 1,
        "ordering": "eve_source_order",
    }
    return alert, source_event, artifact


def event_to_minimal_alert(
    event: dict[str, Any],
    *,
    case_id: str,
    victim_ip: str,
) -> tuple[MinimalAlert, dict[str, Any]]:
    if event.get("event_type") != "alert":
        raise SuricataAlertError("EVE event is not event_type=alert")

    src_ip = str(event.get("src_ip") or "")
    dest_ip = str(event.get("dest_ip") or "")
    src_port = _as_int(event.get("src_port"))
    dest_port = _as_int(event.get("dest_port"))
    if src_ip == victim_ip:
        remote_ip = dest_ip
        remote_port = dest_port
    elif dest_ip == victim_ip:
        remote_ip = src_ip
        remote_port = src_port
    else:
        raise SuricataAlertError("alert does not include the configured victim_ip")
    if not remote_ip:
        raise SuricataAlertError("alert does not contain a usable remote IP")

    protocol = _normalize_protocol(event)
    timestamp = str(event.get("timestamp") or datetime.now(timezone.utc).isoformat())
    source_event = sanitize_source_event(event)
    payload = {
        "schema_version": "c2trace.alert.v1",
        "alert_id": f"{case_id}-SURICATA-A001",
        "case_id": case_id,
        "source": "suricata_eve",
        "alert_type": _normalize_alert_type(event, protocol),
        "victim_ip": victim_ip,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "protocol": protocol,
        "time_window": {"start": timestamp, "end": timestamp},
        "confidence": _confidence_from_severity(source_event.get("severity")),
        "description": "Minimal C2 seed alert converted from a Suricata EVE alert.",
    }
    if remote_port is None:
        payload.pop("remote_port")
    try:
        return MinimalAlert.from_dict(payload), source_event
    except ValidationError as exc:
        raise SuricataAlertError(str(exc)) from exc


def sanitize_source_event(event: dict[str, Any]) -> dict[str, Any]:
    alert = event.get("alert") if isinstance(event.get("alert"), dict) else {}
    sanitized = {
        "timestamp": event.get("timestamp"),
        "event_type": event.get("event_type"),
        "src_ip": event.get("src_ip"),
        "src_port": _as_int(event.get("src_port")),
        "dest_ip": event.get("dest_ip"),
        "dest_port": _as_int(event.get("dest_port")),
        "proto": _lower_or_empty(event.get("proto")),
        "app_proto": _lower_or_empty(event.get("app_proto")),
        "signature": alert.get("signature"),
        "signature_id": alert.get("signature_id"),
        "category": alert.get("category"),
        "severity": _as_int(alert.get("severity")),
        "flow_id": event.get("flow_id"),
    }
    return {key: value for key, value in sanitized.items() if key in SOURCE_EVENT_FIELDS and value not in (None, "")}


def _matches_filters(event: dict[str, Any], filters: SuricataFilters) -> bool:
    if event.get("event_type") != "alert":
        return False
    alert = event.get("alert") if isinstance(event.get("alert"), dict) else {}
    signature = str(alert.get("signature") or "")
    if filters.signature_contains and filters.signature_contains.lower() not in signature.lower():
        return False
    if filters.signature_id and str(alert.get("signature_id") or "") != str(filters.signature_id):
        return False
    if filters.app_proto and str(event.get("app_proto") or "").lower() != filters.app_proto.lower():
        return False
    if filters.dest_port is not None and _as_int(event.get("dest_port")) != filters.dest_port:
        return False
    return True


def _matches_selection(
    event: dict[str, Any],
    artifact: dict[str, Any],
    selection: SuricataSelection,
) -> bool:
    if selection.flow_id and str(event.get("flow_id") or "") != selection.flow_id:
        return False
    if selection.line_number is not None and artifact.get("line_number") != selection.line_number:
        return False
    if selection.record_index is not None and artifact.get("record_index") != selection.record_index:
        return False
    if selection.event_sha256 and artifact.get("event_sha256") != selection.event_sha256:
        return False
    return True


def _normalize_protocol(event: dict[str, Any]) -> str:
    app_proto = _lower_or_empty(event.get("app_proto"))
    if app_proto and app_proto not in {"failed", "unknown"}:
        return app_proto
    proto = _lower_or_empty(event.get("proto"))
    if proto:
        return proto
    return "tcp"


def _normalize_alert_type(event: dict[str, Any], protocol: str) -> str:
    alert = event.get("alert") if isinstance(event.get("alert"), dict) else {}
    signature = str(alert.get("signature") or "").lower()
    if protocol == "http" or "http" in signature:
        return "c2_http_beacon"
    if protocol == "dns" or "dns" in signature:
        return "c2_dns_beacon"
    if "beacon" in signature or "c2" in signature:
        return f"c2_{protocol}_beacon"
    return f"c2_{protocol}_seed"


def _confidence_from_severity(value: Any) -> float:
    severity = _as_int(value)
    if severity is None:
        return 0.6
    if severity <= 1:
        return 0.9
    if severity == 2:
        return 0.75
    if severity == 3:
        return 0.6
    return 0.5


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _lower_or_empty(value: Any) -> str:
    return str(value or "").lower()


def _source_artifact(
    path: Path,
    file_sha256: str,
    event: dict[str, Any],
    *,
    file_size_bytes: int,
    line_number: int | None = None,
    record_index: int | None = None,
    raw_record: bytes | None = None,
) -> dict[str, Any]:
    canonical = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    artifact = {
        "artifact_type": "suricata_eve",
        "path": str(path.resolve()),
        "file_sha256": file_sha256,
        "file_size_bytes": file_size_bytes,
        "event_sha256": hashlib.sha256(canonical).hexdigest(),
    }
    if line_number is not None:
        artifact["line_number"] = line_number
    if record_index is not None:
        artifact["record_index"] = record_index
    if raw_record is not None:
        artifact["raw_record_sha256"] = hashlib.sha256(raw_record).hexdigest()
    return artifact
