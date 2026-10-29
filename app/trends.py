"""Scan/asset trend comparison: did we get better from last scan?"""

from __future__ import annotations

from typing import Any

from .database import get_db


def compare_scans(scan_id_older: int, scan_id_newer: int) -> dict[str, Any]:
    """Compare two scans of the same asset/customer and return delta."""
    with get_db() as conn:
        old = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id_older,)).fetchone()
        new = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id_newer,)).fetchone()
    if not old or not new:
        return {"error": "One or both scans not found"}
    if old["asset_id"] and new["asset_id"] and old["asset_id"] != new["asset_id"]:
        return {"error": "Scans belong to different assets and cannot be compared"}

    old_findings = _get_findings(scan_id_older)
    new_findings = _get_findings(scan_id_newer)

    old_by_fp = {f.get("fingerprint"): f for f in old_findings if f.get("fingerprint")}
    new_by_fp = {f.get("fingerprint"): f for f in new_findings if f.get("fingerprint")}

    # New findings
    new_findings = [new_by_fp[f] for f in new_by_fp if f not in old_by_fp]
    # Fixed findings (present in old, not in new)
    fixed_findings = [old_by_fp[f] for f in old_by_fp if f not in new_by_fp]
    # Unchanged
    unchanged = [f for f in old_by_fp if f in new_by_fp]

    # Severity changes (same fingerprint, different severity)
    severity_changes = []
    for fp in unchanged:
        old_sev = old_by_fp[fp].get("severity")
        new_sev = new_by_fp[fp].get("severity")
        if old_sev != new_sev:
            severity_changes.append({
                "fingerprint": fp,
                "title": old_by_fp[fp].get("title"),
                "old_severity": old_sev,
                "new_severity": new_sev,
            })

    old_sum = _summary(old)
    new_sum = _summary(new)

    return {
        "older_scan_id": scan_id_older,
        "newer_scan_id": scan_id_newer,
        "older_target": old["target"],
        "newer_target": new["target"],
        "older_summary": old_sum,
        "newer_summary": new_sum,
        "new_findings": len(new_findings),
        "fixed_findings": len(fixed_findings),
        "unchanged": len(unchanged),
        "severity_changed": len(severity_changes),
        "new_findings_list": [{"title": f.get("title"), "severity": f.get("severity")} for f in new_findings[:20]],
        "fixed_findings_list": [{"title": f.get("title"), "severity": f.get("severity")} for f in fixed_findings[:20]],
        "severity_changes": severity_changes[:20],
        "improved": new_sum.get("total", 9999) < old_sum.get("total", 0),
    }


def asset_trend(asset_id: int, limit: int = 10) -> dict[str, Any]:
    limit = max(1, min(int(limit or 10), 100))
    with get_db() as conn:
        scans = conn.execute(
            "SELECT id, scan_type, target, status, summary, created_at, completed_at FROM scans WHERE asset_id = ? AND status = 'completed' ORDER BY created_at DESC LIMIT ?",
            (asset_id, limit),
        ).fetchall()
    if not scans:
        return {"asset_id": asset_id, "scans": [], "trend": "no data"}

    results = []
    for row in scans:
        s = dict(row)
        summary_obj = s.get("summary") or {}
        if isinstance(summary_obj, str):
            from .database import json_load

            summary_obj = json_load(summary_obj, {})
        s["summary"] = summary_obj
        s["findings"] = _get_findings(s["id"])
        results.append(s)

    # Calculate improvement from newest to oldest
    total_first = results[0].get("summary", {}).get("total", 0)
    total_last = results[-1].get("summary", {}).get("total", 0) if len(results) > 1 else total_first
    risk_first = results[0].get("summary", {}).get("risk_score", 0)
    risk_last = results[-1].get("summary", {}).get("risk_score", 0) if len(results) > 1 else risk_first

    improved = total_first < total_last or (total_first == total_last and risk_first <= risk_last)

    trend = "improving" if improved else ("worse" if total_first > total_last else "stable")

    return {
        "asset_id": asset_id,
        "scan_count": len(results),
        "scans": [
            {"id": s["id"], "type": s["scan_type"], "target": s["target"],
             "status": s["status"], "completed_at": s["completed_at"],
             "total_findings": s.get("summary", {}).get("total", 0),
             "risk_score": s.get("summary", {}).get("risk_score", 0),
             "critical": s.get("summary", {}).get("critical", 0),
             "high": s.get("summary", {}).get("high", 0)}
            for s in results
        ],
        "trend": trend,
        "improved": improved,
        "latest_findings": results[0].get("findings", [])[:5],
    }


def _get_findings(scan_id: int) -> list[dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT severity, title, fingerprint, status FROM findings WHERE scan_id = ? "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id",
            (scan_id,),
        ).fetchall()
    return [
        {
            "severity": r["severity"],
            "title": r["title"],
            "fingerprint": r["fingerprint"],
            "status": r["status"],
        }
        for r in rows
    ]


def _summary(scan_row: Any) -> dict[str, Any]:
    from .database import json_load

    value = scan_row["summary"] or {}
    return value if isinstance(value, dict) else json_load(value, {})
