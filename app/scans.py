"""Scan orchestration, result persistence and lifecycle management."""

from __future__ import annotations

import traceback
from typing import Any

from .database import (
    get_db,
    json_dump,
    json_load,
    log_event,
    scan_cancelled,
    update_scan,
    utcnow,
)
from .discovery import record_scan_inventory, track_historical_findings
from .scanners.ad import process_ad_report, scan_ad_report
from .scanners.agent import process_agent_payload
from .scanners.base import ScanCancelled, ScanContext, ScanResult
from .scanners.kev import enrich_finding
from .scanners.network import process_agent_network_payload, scan as scan_network
from .scanners.osv import kev_lookup
from .scanners.repository import scan_repository
from .scanners.subdomains import scan_subdomains
from .scanners.web import scan as scan_web
from .utils import risk_label, risk_score, severity_summary, truncate


def _fetch_scan(scan_id: int) -> dict[str, Any] | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return dict(row) if row else None


def _save_findings(scan: dict[str, Any], findings: list[dict[str, Any]]) -> int:
    scan_id = int(scan["id"])
    customer_id = scan.get("customer_id")
    asset_id = scan.get("asset_id")
    now_value = utcnow()
    previous: dict[str, dict[str, Any]] = {}
    if asset_id:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT fingerprint, status, first_seen FROM findings "
                "WHERE asset_id = ? ORDER BY id DESC",
                (asset_id,),
            ).fetchall()
        for row in rows:
            previous.setdefault(row["fingerprint"], dict(row))
    with get_db() as conn:
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        for finding in findings:
            fp = finding.get("fingerprint")
            old = previous.get(fp) if fp else None
            conn.execute(
                "INSERT INTO findings("
                "scan_id, customer_id, asset_id, severity, category, title, description, "
                "evidence, remediation, cve, cwe, cvss, location, resource, fingerprint, "
                "status, first_seen, last_seen, raw"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    customer_id,
                    asset_id,
                    finding["severity"],
                    finding["category"],
                    finding["title"],
                    finding["description"],
                    finding["evidence"],
                    finding["remediation"],
                    finding["cve"],
                    finding["cwe"],
                    finding["cvss"],
                    finding["location"],
                    finding["resource"],
                    fp,
                    old["status"] if old else "open",
                    old["first_seen"] if old else now_value,
                    now_value,
                    json_dump(finding.get("raw") or {}),
                ),
            )
        conn.commit()
    return len(findings)


def _enrich_with_kev(findings: list[dict[str, Any]]) -> None:
    cves = set()
    for finding in findings:
        for cve in (finding.get("cve") or "").split(","):
            cve = cve.strip()
            if cve.startswith("CVE-"):
                cves.add(cve)
    if not cves:
        return
    try:
        known = kev_lookup(cves)
        for finding in findings:
            enrich_finding(finding, known)
    except Exception:
        # Enrichment must never fail a scan.
        pass


def persist_result(scan_id: int, result: ScanResult) -> dict[str, Any]:
    scan = _fetch_scan(scan_id)
    if not scan:
        raise RuntimeError("Scan record disappeared")
    findings = result.normalized()
    _enrich_with_kev(findings)
    # Recalculate because enrichment can add metadata but not findings.
    summary = severity_summary(findings)
    score = risk_score(summary)
    summary["risk_score"] = score
    summary["risk_label"] = risk_label(score)
    summary["metadata"] = result.metadata
    _save_findings(scan, findings)
    # Inventory and trend tracking are valuable but must never turn a
    # successful scan into a failed one.
    try:
        host_assets = record_scan_inventory(scan, findings, result.metadata)
    except Exception:
        host_assets = {}
    summary["inventory_entries"] = len(host_assets)
    try:
        scan_asset_id = scan.get("asset_id")
        if scan_asset_id:
            track_historical_findings(scan_id, int(scan_asset_id), findings)
        else:
            for host, asset_id in host_assets.items():
                subset = [
                    finding
                    for finding in findings
                    if host in str(finding.get("location") or "")
                    or host in str(finding.get("resource") or "")
                ]
                if subset:
                    track_historical_findings(scan_id, asset_id, subset)
    except Exception:
        pass
    return summary


def _dispatch(scan: dict[str, Any], ctx: ScanContext, runtime_options: dict[str, Any]) -> ScanResult:
    scan_type = scan["scan_type"]
    if scan_type == "web":
        return scan_web(ctx)
    if scan_type == "network":
        return scan_network(ctx)
    if scan_type in {"repo", "github"}:
        token = runtime_options.get("_github_token") or None
        return scan_repository(ctx, scan["target"], token)
    if scan_type == "domain":
        return scan_subdomains(ctx)
    if scan_type == "ad":
        return scan_ad_report(ctx, scan["target"])
    raise ValueError(f"Unsupported scan type: {scan_type}")


def _notify_schedule(
    runtime_options: dict[str, Any], scan_id: int, status: str, message: str
) -> None:
    schedule_id = runtime_options.get("_schedule_id")
    if not schedule_id:
        return
    try:
        from .scheduler import notify_scheduled_scan

        notify_scheduled_scan(scan_id, int(schedule_id), status, message)
    except Exception:
        # Notification failure must not change the scan result.
        pass


def execute_scan(scan_id: int, runtime_options: dict[str, Any] | None = None) -> None:
    runtime_options = runtime_options or {}
    scan = _fetch_scan(scan_id)
    if not scan or scan["status"] not in {"queued"}:
        return
    if scan_cancelled(scan_id):
        update_scan(scan_id, status="cancelled", stage="Cancelled", completed_at=utcnow())
        _notify_schedule(runtime_options, scan_id, "cancelled", "Scan cancelled before execution")
        return
    options = json_load(scan.get("options"), {})
    ctx = ScanContext(scan_id, scan["target"], options)
    started = utcnow()
    update_scan(scan_id, status="running", progress=1, stage="Starting", started_at=started)
    log_event(scan_id, f"Starting {scan['scan_type']} scan against {scan['target']}")
    try:
        from .tool_policy import enforce_scan_policy

        for warning in enforce_scan_policy(scan["scan_type"], options):
            log_event(scan_id, f"Tool version policy: {warning}", "warning")
            ctx.log(f"Tool version policy: {warning}", "warning")
        result = _dispatch(scan, ctx, runtime_options)
        if ctx.cancelled() or scan_cancelled(scan_id):
            summary = persist_result(scan_id, result)
            update_scan(
                scan_id,
                status="cancelled",
                progress=100,
                stage="Cancelled",
                completed_at=utcnow(),
                summary=summary,
                error="Scan cancelled by user",
            )
            log_event(scan_id, "Scan cancelled; partial findings were saved", "warning")
            _notify_schedule(
                runtime_options,
                scan_id,
                "cancelled",
                f"Scan cancelled with {summary.get('total', 0)} partial finding(s).",
            )
            return
        ctx.progress(98, "Saving findings")
        summary = persist_result(scan_id, result)
        update_scan(
            scan_id,
            status="completed",
            progress=100,
            stage="Completed",
            completed_at=utcnow(),
            summary=summary,
        )
        log_event(
            scan_id,
            f"Scan completed with {summary.get('total', 0)} finding(s) "
            f"(risk score {summary.get('risk_score', 0)})",
        )
        _notify_schedule(
            runtime_options,
            scan_id,
            "completed",
            f"Scan completed with {summary.get('total', 0)} finding(s); "
            f"risk score {summary.get('risk_score', 0)}.",
        )
    except ScanCancelled:
        update_scan(
            scan_id,
            status="cancelled",
            progress=100,
            stage="Cancelled",
            completed_at=utcnow(),
            error="Scan cancelled by user",
        )
        log_event(scan_id, "Scan cancelled", "warning")
        _notify_schedule(runtime_options, scan_id, "cancelled", "Scan cancelled by user.")
    except Exception as exc:
        message = truncate(f"{exc.__class__.__name__}: {exc}", 1500)
        update_scan(
            scan_id,
            status="failed",
            progress=100,
            stage="Failed",
            completed_at=utcnow(),
            error=message,
        )
        log_event(scan_id, f"Scan failed: {message}", "error")
        log_event(scan_id, truncate(traceback.format_exc(), 4000), "debug")
        _notify_schedule(runtime_options, scan_id, "failed", message)


def execute_ad_import(scan_id: int, report: dict[str, Any]) -> None:
    scan = _fetch_scan(scan_id)
    if not scan or scan["status"] not in {"queued", "running"}:
        return
    options = json_load(scan.get("options"), {})
    ctx = ScanContext(scan_id, scan["target"], options)
    update_scan(
        scan_id,
        status="running",
        progress=10,
        stage="Evaluating Active Directory report",
        started_at=utcnow(),
    )
    log_event(scan_id, "Active Directory report import started")
    try:
        result = process_ad_report(report)
        ctx.progress(90, "Saving Active Directory findings")
        summary = persist_result(scan_id, result)
        update_scan(
            scan_id,
            status="completed",
            progress=100,
            stage="Completed",
            completed_at=utcnow(),
            summary=summary,
        )
        log_event(
            scan_id,
            f"AD report imported with {summary.get('total', 0)} finding(s) "
            f"(risk score {summary.get('risk_score', 0)})",
        )
    except Exception as exc:
        message = truncate(f"{exc.__class__.__name__}: {exc}", 1500)
        update_scan(
            scan_id,
            status="failed",
            progress=100,
            stage="Failed",
            completed_at=utcnow(),
            error=message,
        )
        log_event(scan_id, f"AD import failed: {message}", "error")


def execute_agent_result(
    scan_id: int,
    payload: dict[str, Any],
    job_id: str | None = None,
) -> None:
    scan = _fetch_scan(scan_id)
    if not scan:
        return
    if scan["status"] in {"completed", "failed", "cancelled"}:
        return
    options = json_load(scan.get("options"), {})
    ctx = ScanContext(scan_id, scan["target"], options)
    update_scan(
        scan_id,
        status="running",
        progress=10,
        stage="Processing agent report",
        started_at=scan.get("started_at") or utcnow(),
    )
    log_event(scan_id, "Agent report received")
    try:
        if scan["scan_type"] == "network":
            result = process_agent_network_payload(ctx, payload)
        else:
            result = process_agent_payload(ctx, payload)
        if ctx.cancelled() or scan_cancelled(scan_id):
            update_scan(
                scan_id,
                status="cancelled",
                progress=100,
                stage="Cancelled",
                completed_at=utcnow(),
                error="Scan cancelled by user",
            )
            log_event(scan_id, "Agent report discarded because the scan was cancelled", "warning")
            if job_id:
                with get_db() as conn:
                    conn.execute(
                        "UPDATE agent_jobs SET status = 'cancelled', completed_at = ? WHERE id = ?",
                        (utcnow(), job_id),
                    )
                    conn.commit()
            return
        ctx.progress(98, "Saving findings")
        summary = persist_result(scan_id, result)
        update_scan(
            scan_id,
            status="completed",
            progress=100,
            stage="Completed",
            completed_at=utcnow(),
            summary=summary,
        )
        log_event(
            scan_id,
            f"Agent scan completed with {summary.get('total', 0)} finding(s) "
            f"(risk score {summary.get('risk_score', 0)})",
        )
        if job_id:
            with get_db() as conn:
                conn.execute(
                    "UPDATE agent_jobs SET status = 'completed', completed_at = ? WHERE id = ?",
                    (utcnow(), job_id),
                )
                conn.commit()
    except Exception as exc:
        message = truncate(f"{exc.__class__.__name__}: {exc}", 1500)
        update_scan(
            scan_id,
            status="failed",
            progress=100,
            stage="Failed",
            completed_at=utcnow(),
            error=message,
        )
        log_event(scan_id, f"Could not process agent report: {message}", "error")
        if job_id:
            with get_db() as conn:
                conn.execute(
                    "UPDATE agent_jobs SET status = 'failed', completed_at = ?, error = ? WHERE id = ?",
                    (utcnow(), message, job_id),
                )
                conn.commit()


def recover_interrupted_scans() -> None:
    """Mark scans that were running when the server stopped as failed."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id FROM scans WHERE status IN ('queued', 'running')"
        ).fetchall()
        for row in rows:
            conn.execute(
                "UPDATE scans SET status = 'failed', progress = 100, stage = 'Interrupted', "
                "completed_at = ?, error = 'Server restarted before this scan finished. Start a new scan.' "
                "WHERE id = ?",
                (utcnow(), row["id"]),
            )
            conn.execute(
                "INSERT INTO scan_events(scan_id, created_at, level, message) VALUES (?, ?, 'warning', ?)",
                (
                    row["id"],
                    utcnow(),
                    "Scan interrupted by server restart; start a new scan.",
                ),
            )
        conn.commit()


def scan_counts() -> dict[str, int]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running, "
            "SUM(CASE WHEN status = 'waiting_agent' THEN 1 ELSE 0 END) AS waiting "
            "FROM scans"
        ).fetchone()
    return {
        "total": int(row["total"] or 0),
        "running": int(row["running"] or 0),
        "waiting_agent": int(row["waiting"] or 0),
    }
