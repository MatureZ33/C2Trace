from __future__ import annotations

"""Pre-registered, read-only evidence collection for Bench v4."""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from c2trace.suricata import (
    SuricataAlertError,
    event_to_minimal_alert,
    load_eve_records_with_artifacts,
)

from .runtime import BenchV4RuntimeError, RuntimeCase, RuntimeValues, render_runtime_value


READ_ONLY_TOOLS = frozenset(
    {
        "check_network",
        "check_process",
        "check_process_tree",
        "check_file_metadata",
        "check_persistence_all",
        "check_powershell_history",
        "check_dns_cache",
    }
)


class EvidenceCaptureError(BenchV4RuntimeError):
    """A required, pre-registered evidence capture failed."""


class ReadOnlyProbe(Protocol):
    def run(self, tool: str, params: dict[str, Any] | None = None) -> Any: ...


def _parse_time(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        result = datetime.fromisoformat(text)
    except ValueError:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


class PlanDrivenEvidenceCollector:
    def __init__(
        self,
        *,
        runtime: RuntimeCase,
        values: RuntimeValues,
        probe: ReadOnlyProbe,
        target_identity: Mapping[str, Any] | None = None,
        suricata_eve: str | Path | None = None,
        source_not_before_utc: str = "",
        supplied: Mapping[str, Any] | None = None,
        custom_collectors: Mapping[
            str, Callable[[Mapping[str, Any]], Mapping[str, Any]]
        ]
        | None = None,
    ) -> None:
        self.runtime = runtime
        self.values = values
        self.probe = probe
        self.target_identity = dict(target_identity or {})
        self.suricata_eve = Path(suricata_eve).resolve() if suricata_eve else None
        self.source_not_before_utc = source_not_before_utc
        self.supplied = dict(supplied or {})
        self.custom_collectors = dict(custom_collectors or {})
        self._cache: dict[tuple[str, str], dict[str, Any]] = {}
        self._traces = {
            str(trace.get("trace_id") or ""): dict(trace)
            for ability in runtime.ground_truth.get("ability_instances", [])
            if isinstance(ability, Mapping)
            for trace in ability.get("trace_facts", [])
            if isinstance(trace, Mapping) and trace.get("trace_id")
        }

    def _render(self, value: Any) -> Any:
        facts = {
            "run_id": self.values.run_id,
            "victim_ip": self.values.victim_ip,
            "kali_ip": self.values.kali_ip,
            "webshell_port": self.values.webshell_port or "",
            **self.values.facts,
            # APPDATA is a host-resolved runtime value rather than a
            # target-profile runtime_fact.  Include it explicitly so both
            # #{c2trace.appdata} and the legacy %APPDATA% trace notation are
            # rendered by render_runtime_value.  An empty value is left
            # unresolved there and therefore still fails closed.
            "c2trace.appdata": self.values.appdata,
        }
        return render_runtime_value(value, facts)

    def _probe(self, tool: str, params: Mapping[str, Any]) -> dict[str, Any]:
        if tool not in READ_ONLY_TOOLS:
            raise EvidenceCaptureError(f"collector attempted a non-read-only tool: {tool}")
        key = (tool, json.dumps(dict(params), sort_keys=True, default=str))
        if key in self._cache:
            return dict(self._cache[key])
        result = self.probe.run(tool, dict(params))
        success = bool(getattr(result, "success", False))
        data = getattr(result, "data", None)
        error = getattr(result, "error", None)
        if not success or not isinstance(data, Mapping):
            raise EvidenceCaptureError(
                f"read-only probe {tool} failed: {error or 'malformed result'}"
            )
        record = {"tool": tool, "params": dict(params), "data": dict(data)}
        self._cache[key] = record
        return dict(record)

    def _network_params(self) -> dict[str, Any]:
        target = self.runtime.target
        contact = target["contact"]
        mode = str(target["network_mode"])
        if mode == "inbound_listener":
            return {
                "network_mode": mode,
                "local_ip": self.values.victim_ip,
                "local_port": int(self.values.webshell_port or contact["listener_port"]),
            }
        params: dict[str, Any] = {
            "network_mode": mode,
            "remote_ip": self.values.kali_ip,
            "remote_port": int(contact["listener_port"]),
        }
        local_port = int(
            self.target_identity.get("local_port")
            or self.target_identity.get("network", {}).get("local_port", 0)
            or 0
        )
        if local_port:
            params["local_port"] = local_port
        elif target.get("target_type") == "sandcat_http_client":
            raise EvidenceCaptureError(
                "shared HTTP/8888 capture requires the target Sandcat's exact local port"
            )
        return params

    def _host_trace(self, trace: Mapping[str, Any]) -> dict[str, Any]:
        trace_type = str(trace.get("trace_type") or "")
        expected = self._render(trace.get("expected_value") or {})
        if trace_type == "network_connection":
            params = self._network_params()
            if str(expected.get("pid") or "") == "FILL_FROM_TARGET_SECONDARY":
                params.pop("local_port", None)
            return self._probe("check_network", params)
        if trace_type == "process":
            if str(expected.get("pid") or "") == "FILL_FROM_TARGET_SECONDARY":
                pid = int(self.target_identity.get("secondary_pid") or 0)
            else:
                pid = int(self.target_identity.get("pid") or 0)
            name = str(expected.get("name") or "") if isinstance(expected, Mapping) else ""
            return self._probe("check_process", {"pid": pid, "process_name": name})
        if trace_type == "process_parent_edge":
            pid = int(self.target_identity.get("pid") or 0)
            name = str(expected.get("child_name") or "") if isinstance(expected, Mapping) else ""
            return self._probe("check_process_tree", {"pid": pid, "process_name": name})
        if trace_type == "file":
            path = str(expected.get("path") or "") if isinstance(expected, Mapping) else ""
            return self._probe("check_file_metadata", {"file_path": path})
        if trace_type in {"registry_value", "registry_run_key"}:
            target = dict(expected) if isinstance(expected, Mapping) else {}
            return self._probe(
                "check_persistence_all",
                {
                    "registry_targets": [target],
                },
            )
        if trace_type == "scheduled_task":
            target = dict(expected) if isinstance(expected, Mapping) else {}
            if "task_name" not in target and target.get("name"):
                target["task_name"] = target["name"]
            return self._probe(
                "check_persistence_all",
                {
                    "task_targets": [target],
                },
            )
        if trace_type == "service":
            target = dict(expected) if isinstance(expected, Mapping) else {}
            if "service_name" not in target and target.get("name"):
                target["service_name"] = target["name"]
            return self._probe(
                "check_persistence_all",
                {
                    "service_targets": [target],
                },
            )
        if trace_type == "powershell_history":
            pattern = str(expected.get("command") or expected.get("pattern") or "")
            return self._probe("check_powershell_history", {"pattern": pattern})
        if trace_type == "dns_cache":
            domain = str(expected.get("domain") or expected.get("name") or "")
            return self._probe("check_dns_cache", {"domain_filter": domain})
        raise EvidenceCaptureError(f"unsupported Ground Truth trace type: {trace_type}")

    def _host_snapshot(self, capture: Mapping[str, Any]) -> dict[str, Any]:
        stage = str(capture.get("stage") or "")
        trace_ids = [str(value) for value in capture.get("trace_fact_ids", [])]
        if stage == "baseline":
            # A target does not exist yet.  Only pre-registered static
            # artifacts can be checked for residue; querying a shared 8888
            # endpoint here could accidentally bind the protected controller.
            trace_ids = [
                trace_id
                for trace_id, trace in self._traces.items()
                if str(trace.get("trace_type") or "")
                in {"file", "registry_value", "registry_run_key", "scheduled_task", "service"}
            ]
        elif not trace_ids:
            # Dry-run and post-response stages use the same pre-registered
            # selectors as the before-response capture.  This makes semantic
            # comparison independent of capture IDs and prevents a broad host
            # query from silently replacing the frozen selectors.
            trace_ids = list(self._traces)
        traces: dict[str, Any] = {}
        for trace_id in trace_ids:
            trace = self._traces.get(trace_id)
            if trace is None:
                raise EvidenceCaptureError(
                    f"capture {capture.get('capture_id')} references unknown trace {trace_id}"
                )
            traces[trace_id] = self._host_trace(trace)

        # The runtime target path itself is also a pre-registered selector in
        # every evidence plan.  At baseline it proves the unique path is clean;
        # later it tracks target-file presence without making it a source trace.
        traces["target.file"] = self._probe(
            "check_file_metadata", {"file_path": self.values.target_path}
        )

        if stage != "baseline":
            # These target observations are safety/response facts, not public
            # source trace facts, and therefore use reserved target.* keys.
            pid = int(self.target_identity.get("pid") or 0)
            if pid:
                traces["target.process"] = self._probe(
                    "check_process", {"pid": pid, "process_name": ""}
                )
            # Fail closed if an established target exists but its exact
            # endpoint is unavailable.  In particular, never query shared
            # Sandcat HTTP/8888 without the target's local ephemeral port.
            if pid or self.runtime.target.get("network_mode") == "inbound_listener":
                traces["target.network"] = self._probe(
                    "check_network", self._network_params()
                )
        return {
            "selection_policy": "pre_registered_trace_selectors",
            "trace_observations": traces,
        }

    def _suricata(self, capture: Mapping[str, Any]) -> dict[str, Any]:
        if self.suricata_eve is None:
            raise EvidenceCaptureError("Suricata capture requires a frozen EVE path")
        selector = capture.get("selector") if isinstance(capture.get("selector"), Mapping) else {}
        sid = int(selector.get("signature_id") or 0)
        not_before = _parse_time(self.source_not_before_utc)
        if not_before is None:
            raise EvidenceCaptureError(
                "Suricata capture requires a valid source_not_before_utc freshness boundary"
            )
        target = self.runtime.target
        mode = str(selector.get("network_mode") or target["network_mode"])
        expected_port = (
            int(self.values.webshell_port or 0)
            if mode == "inbound_listener"
            else int(target["contact"]["listener_port"])
        )
        exact_local_port = int(
            self.target_identity.get("local_port")
            or self.target_identity.get("network", {}).get("local_port", 0)
            or 0
        )
        exact_remote_port = int(
            self.target_identity.get("remote_port")
            or self.target_identity.get("network", {}).get("remote_port", 0)
            or 0
        )
        selector_flow = str(selector.get("flow_id") or "")
        selector_hash = str(selector.get("event_sha256") or "").lower()
        selector_line = int(selector.get("line_number") or 0)
        selector_record = int(selector.get("record_index") or 0)
        candidates: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
        try:
            records = load_eve_records_with_artifacts(self.suricata_eve)
        except (OSError, UnicodeError, SuricataAlertError) as exc:
            raise EvidenceCaptureError(f"unable to read Suricata evidence: {exc}") from exc
        for event, artifact in records:
            alert = event.get("alert") if isinstance(event.get("alert"), Mapping) else {}
            if int(alert.get("signature_id") or event.get("signature_id") or 0) != sid:
                continue
            protocol = str(event.get("proto") or "tcp").strip().lower()
            if protocol not in {"tcp", "tcp6"}:
                continue
            timestamp = _parse_time(event.get("timestamp"))
            if timestamp is None or timestamp < not_before:
                continue
            if mode == "inbound_listener":
                if str(event.get("src_ip") or "") != self.values.kali_ip:
                    continue
                if str(event.get("dest_ip") or "") != self.values.victim_ip:
                    continue
                if int(event.get("dest_port") or 0) != expected_port:
                    continue
                if exact_remote_port and int(event.get("src_port") or 0) != exact_remote_port:
                    continue
            else:
                if str(event.get("src_ip") or "") != self.values.victim_ip:
                    continue
                if str(event.get("dest_ip") or "") != self.values.kali_ip:
                    continue
                if int(event.get("dest_port") or 0) != expected_port:
                    continue
                if not exact_local_port:
                    raise EvidenceCaptureError(
                        "outbound Suricata selection requires the target's exact local port"
                    )
                if int(event.get("src_port") or 0) != exact_local_port:
                    continue
            if not int(event.get("src_port") or 0) or not int(event.get("dest_port") or 0):
                continue
            if selector_flow and str(event.get("flow_id") or "") != selector_flow:
                continue
            if selector_hash and str(artifact.get("event_sha256") or "").lower() != selector_hash:
                continue
            if selector_line and int(artifact.get("line_number") or 0) != selector_line:
                continue
            if selector_record and int(artifact.get("record_index") or 0) != selector_record:
                continue
            try:
                _, source_event = event_to_minimal_alert(
                    dict(event), case_id=self.runtime.case_id, victim_ip=self.values.victim_ip
                )
            except SuricataAlertError:
                continue
            candidates.append((dict(event), dict(source_event), dict(artifact)))
        if not candidates:
            raise EvidenceCaptureError(
                "no fresh TCP Suricata event matched the exact target five-tuple"
            )
        selected, source_event, artifact = candidates[-1]
        return {
            "selection_policy": "latest_exact_fresh_tcp_flow_in_eve_source_order",
            "candidate_count": len(candidates),
            "selected_event": selected,
            "source_event": source_event,
            "source_artifact": artifact,
            "selected_event_sha256": artifact["event_sha256"],
        }

    def _collect_one(self, capture: Mapping[str, Any]) -> dict[str, Any]:
        collector = str(capture.get("collector") or "")
        if collector == "host_snapshot":
            return self._host_snapshot(capture)
        if collector == "suricata":
            return self._suricata(capture)
        if collector in {"caldera_report", "powershell_history", "dns_cache"}:
            if collector in self.supplied:
                value = self.supplied[collector]
                if not isinstance(value, Mapping):
                    raise EvidenceCaptureError(f"supplied {collector} evidence is malformed")
                return dict(value)
            if collector == "powershell_history":
                return self._probe("check_powershell_history", {})
            if collector == "dns_cache":
                return self._probe("check_dns_cache", {})
            raise EvidenceCaptureError("CALDERA report must be supplied by the API controller")
        if collector == "custom_read_only":
            capture_id = str(capture.get("capture_id") or "")
            callback = self.custom_collectors.get(capture_id)
            if callback is None:
                raise EvidenceCaptureError(
                    f"custom read-only collector is not registered: {capture_id}"
                )
            value = callback(capture)
            if not isinstance(value, Mapping):
                raise EvidenceCaptureError("custom read-only collector returned malformed data")
            return dict(value)
        raise EvidenceCaptureError(f"unsupported evidence collector: {collector}")

    def capture_stage(self, stage: str) -> dict[str, Any]:
        # Evidence must reflect the requested point in time.  Reusing cached
        # pre-response probe data after a dry-run or response would turn the
        # transaction checks into a tautology.
        self._cache.clear()
        rows = [
            dict(row)
            for row in self.runtime.evidence_plan.get("captures", [])
            if isinstance(row, Mapping) and str(row.get("stage") or "") == stage
        ]
        if not rows:
            raise EvidenceCaptureError(f"evidence plan has no captures for stage {stage}")
        captures: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for row in rows:
            try:
                result = self._collect_one(row)
            except EvidenceCaptureError as exc:
                error = {
                    "capture_id": row.get("capture_id"),
                    "required": row.get("required") is True,
                    "error": str(exc),
                }
                errors.append(error)
                if row.get("required") is True:
                    raise EvidenceCaptureError(
                        f"required capture {row.get('capture_id')} failed: {exc}"
                    ) from exc
            else:
                captures.append(
                    {
                        "capture_id": row.get("capture_id"),
                        "collector": row.get("collector"),
                        "trace_fact_ids": list(row.get("trace_fact_ids") or []),
                        "required": row.get("required") is True,
                        "result": result,
                    }
                )
        return {
            "schema_version": "c2trace.bench.evidence_capture.v4",
            "case_id": self.runtime.case_id,
            "run_id": self.values.run_id,
            "stage": stage,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "read_only": True,
            "captures": captures,
            "non_required_errors": errors,
        }
