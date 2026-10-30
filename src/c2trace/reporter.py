from __future__ import annotations

from c2trace.models import CaseFile, FinalReport


class Reporter:
    def build(self, case: CaseFile) -> FinalReport:
        findings = [
            f"{f.finding_type}: {f.value} - {f.evidence}"
            for f in case.findings
        ]
        actions = [
            f"{r.tool} node={r.node_id} success={r.success} error={r.error or ''}"
            for r in case.action_results
        ]
        audit_summary = [
            f"{d.verdict.value}: node={d.node_id} {d.reason}"
            for d in case.audit_decisions
        ]
        verification = [
            f"{f.finding_type}: {f.evidence}"
            for f in case.findings
            if f.finding_type.startswith("cleanup_")
        ]
        evidence_chain = self._build_evidence_chain(case)
        response_count = sum(1 for f in case.findings if f.finding_type == "response_action_executed")
        dry_run_count = sum(1 for f in case.findings if f.finding_type == "response_action_dry_run")
        rejected_count = sum(1 for d in case.audit_decisions if d.verdict.value == "rejected")
        summary = (
            f"Case {case.case_id} finished with status={case.final_status}. "
            f"Findings={len(case.findings)}, actions={len(case.action_results)}, "
            f"audit_decisions={len(case.audit_decisions)}, real_response={response_count}, dry_run_response={dry_run_count}."
        )
        if rejected_count:
            summary += f" {rejected_count} response branch(es) were closed due to insufficient evidence."
        report = FinalReport(
            title=f"C2Trace Report - {case.case_id}",
            executive_summary=summary,
            findings=findings,
            actions=actions,
            audit_summary=audit_summary,
            verification=verification,
            evidence_chain=evidence_chain,
        )
        case.final_report = report
        case.add_timeline("report_generated", f"Report generated for {case.case_id}", "reporter", [report.report_id])
        return report

    @staticmethod
    def _build_evidence_chain(case: CaseFile) -> list[str]:
        chain: list[str] = []
        for event in case.source_events:
            alert = event.get("signature") or f"sid={event.get('signature_id')}"
            src = f"{event.get('src_ip', '')}:{event.get('src_port', '')}".strip(":")
            dst = f"{event.get('dest_ip', '')}:{event.get('dest_port', '')}".strip(":")
            proto = event.get("app_proto") or event.get("proto") or "network"
            chain.append(f"Suricata seed alert: {alert} ({proto} {src} -> {dst})")
        for artifact in getattr(case, "source_artifacts", []):
            event_hash = str(artifact.get("event_sha256") or "")
            file_hash = str(artifact.get("file_sha256") or "")
            location = f"line {artifact.get('line_number')}" if artifact.get("line_number") else f"record {artifact.get('record_index')}"
            chain.append(
                "Source artifact: "
                f"{artifact.get('artifact_type', 'source')} {artifact.get('path', '')} "
                f"{location}; event_sha256={event_hash[:16]}; file_sha256={file_hash[:16]}"
            )

        alert = case.source_alert
        remote = alert.get("remote_ip") or alert.get("remote_domain") or alert.get("remote_url") or "unknown remote"
        port = alert.get("remote_port")
        if port:
            remote = f"{remote}:{port}"
        chain.append(f"Minimal C2 seed alert: {alert.get('alert_type', 'c2_seed')} {alert.get('protocol', '')} {remote}".strip())

        ordered_types = [
            ("network_confirmed", "Network connection"),
            ("network_connection", "Network connection"),
            ("c2_process_attributed", "PID/process attribution"),
            ("process_detail", "PID/process attribution"),
            ("process_tree", "Process lineage"),
            ("suspicious_process_path", "Payload file candidate"),
            ("file_metadata", "Payload file metadata"),
            ("payload_file_verified", "Payload file verification"),
            ("persistence_summary", "Persistence scan"),
            ("persistence_linked_to_payload", "Persistence item"),
            ("response_action_dry_run", "Response dry-run"),
            ("response_action_executed", "Response action"),
        ]
        seen: set[str] = set()
        for finding_type, label in ordered_types:
            for finding in case.findings:
                if finding.finding_type != finding_type or finding.finding_id in seen:
                    continue
                chain.append(f"{label}: {finding.value} - {finding.evidence}")
                seen.add(finding.finding_id)
                break

        for decision in case.audit_decisions:
            chain.append(f"Audit decision: {decision.verdict.value} for {decision.node_id} - {decision.reason}")

        for finding in case.findings:
            if finding.finding_type.startswith("cleanup_"):
                chain.append(f"Cleanup verification: {finding.finding_type} - {finding.evidence}")

        return chain

    @staticmethod
    def to_markdown(report: FinalReport) -> str:
        lines = [
            f"# {report.title}",
            "",
            "## Executive Summary",
            report.executive_summary,
            "",
            "## Evidence Chain",
            *[f"- {item}" for item in (report.evidence_chain or ["No structured evidence chain recorded."])],
            "",
            "## Findings",
            *[f"- {item}" for item in report.findings],
            "",
            "## Actions",
            *[f"- {item}" for item in report.actions],
            "",
            "## Audit Summary",
            *[f"- {item}" for item in report.audit_summary],
            "",
            "## Verification",
            *[f"- {item}" for item in report.verification],
            "",
        ]
        return "\n".join(lines)
