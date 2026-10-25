"""JSON, CSV and standalone HTML report generation."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from .utils import SEVERITY_COLORS, escape, format_duration

REPORT_CSS = """
:root{color-scheme:light;--ink:#162033;--muted:#64748b;--line:#e2e8f0;--bg:#f5f7fb}
*{box-sizing:border-box}body{margin:0;font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--ink);background:var(--bg)}
.wrap{max-width:1100px;margin:0 auto;padding:38px 28px 80px}
header{display:flex;justify-content:space-between;gap:24px;align-items:flex-start;border-bottom:3px solid #0f172a;padding-bottom:22px}
.brand{font-size:12px;letter-spacing:.16em;text-transform:uppercase;color:#0891b2;font-weight:800}
h1{font-size:30px;margin:7px 0 4px;letter-spacing:-.02em}.meta{color:var(--muted);font-size:13px}
.badge{display:inline-block;padding:4px 10px;border-radius:999px;color:#fff;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.06em}
.cards{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:26px 0}
.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:14px}.card b{display:block;font-size:24px}.card span{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.07em}
.summary{background:#fff;border:1px solid var(--line);border-radius:14px;padding:20px;margin:18px 0}
h2{font-size:19px;margin:30px 0 12px}h3{font-size:15px;margin:0 0 8px}
.finding{background:#fff;border:1px solid var(--line);border-left:5px solid #64748b;border-radius:11px;padding:18px;margin:12px 0;break-inside:avoid}
.fhead{display:flex;gap:10px;align-items:center;justify-content:space-between}.fmeta{color:var(--muted);font-size:12px;margin:4px 0 10px}
pre{white-space:pre-wrap;word-break:break-word;background:#0f172a;color:#e2e8f0;border-radius:8px;padding:12px;font-size:12px;overflow:auto}
.lbl{font-size:10px;letter-spacing:.09em;text-transform:uppercase;color:#0891b2;font-weight:800;margin:12px 0 4px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:14px}.two>div{background:#f8fafc;border:1px solid var(--line);border-radius:9px;padding:12px}
.kev{background:#7c2d12;color:#fff;border-radius:5px;padding:2px 7px;font-size:10px;font-weight:700;margin-left:6px}
footer{margin-top:40px;color:var(--muted);font-size:11px;border-top:1px solid var(--line);padding-top:16px}
@media print{body{background:#fff}.wrap{max-width:none;padding:0}.finding{break-inside:avoid}a{color:inherit;text-decoration:none}}
@media(max-width:800px){.cards{grid-template-columns:repeat(3,1fr)}.two{grid-template-columns:1fr}}
"""


def build_json(scan: dict[str, Any], findings: list[dict[str, Any]], context: dict[str, Any]) -> str:
    payload = {
        "report_version": 1,
        "generated_at": context.get("generated_at"),
        "product": "VulnScanner",
        "customer": context.get("customer"),
        "group": context.get("group"),
        "asset": context.get("asset"),
        "scan": scan,
        "summary": context.get("summary"),
        "findings": findings,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


def build_csv(scan: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "scan_id", "severity", "category", "title", "cve", "cwe", "cvss",
            "location", "resource", "status", "first_seen", "last_seen",
            "description", "evidence", "remediation",
        ]
    )
    for finding in findings:
        writer.writerow(
            [
                scan.get("id"),
                finding.get("severity"),
                finding.get("category"),
                finding.get("title"),
                finding.get("cve"),
                finding.get("cwe"),
                finding.get("cvss"),
                finding.get("location"),
                finding.get("resource"),
                finding.get("status"),
                finding.get("first_seen"),
                finding.get("last_seen"),
                finding.get("description"),
                finding.get("evidence"),
                finding.get("remediation"),
            ]
        )
    return output.getvalue()


def build_html(scan: dict[str, Any], findings: list[dict[str, Any]], context: dict[str, Any]) -> str:
    customer = context.get("customer") or {}
    group = context.get("group") or {}
    asset = context.get("asset") or {}
    summary = context.get("summary") or {}
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(findings, key=lambda item: severity_order.get(item.get("severity", "info"), 9))
    cards = "".join(
        f'<div class="card"><b>{summary.get(name, 0)}</b><span>{name}</span></div>'
        for name in ("critical", "high", "medium", "low", "info", "total")
    )
    finding_html = []
    for finding in findings:
        severity = finding.get("severity", "info")
        color = SEVERITY_COLORS.get(severity, "#64748b")
        raw = finding.get("raw") or {}
        kev = '<span class="kev">CISA KEV</span>' if raw.get("kev") else ""
        references = ""
        refs = raw.get("references") or []
        if refs:
            links = " ".join(
                f'<a href="{escape(url)}" rel="noreferrer">{escape(url)}</a>'
                for url in refs[:8]
            )
            references = f'<div class="lbl">References</div><div class="meta">{links}</div>'
        finding_html.append(
            f"""
<section class="finding" style="border-left-color:{color}">
  <div class="fhead"><h3>{escape(finding.get('title'))}{kev}</h3>
  <span class="badge" style="background:{color}">{escape(severity)}</span></div>
  <div class="fmeta">
    {escape(finding.get('category') or '')}
    {(' · ' + escape(finding.get('location'))) if finding.get('location') else ''}
    {(' · CVSS ' + str(finding.get('cvss'))) if finding.get('cvss') else ''}
    {(' · ' + escape(finding.get('cve'))) if finding.get('cve') else ''}
    {(' · ' + escape(finding.get('cwe'))) if finding.get('cwe') else ''}
    · status: {escape(finding.get('status') or 'open')}
  </div>
  {('<div class="lbl">Description</div><div>' + escape(finding.get('description', '')).replace(chr(10), '<br>') + '</div>') if finding.get('description') else ''}
  {('<div class="lbl">Evidence</div><pre>' + escape(finding.get('evidence', '')) + '</pre>') if finding.get('evidence') else ''}
  {('<div class="lbl">Remediation</div><div>' + escape(finding.get('remediation', '')).replace(chr(10), '<br>') + '</div>') if finding.get('remediation') else ''}
  {references}
</section>"""
        )
    duration = format_duration(scan.get("started_at"), scan.get("completed_at"))
    generated = escape(context.get("generated_at", ""))
    title = f"{customer.get('name', 'Customer')} — {scan.get('scan_type', 'scan').upper()} report"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title><style>{REPORT_CSS}</style></head>
<body><div class="wrap">
<header>
  <div><div class="brand">VulnScanner · Security Assessment</div>
  <h1>{escape(title)}</h1>
  <div class="meta">Target: <b>{escape(scan.get('target'))}</b> · Scan #{scan.get('id')} · {escape(scan.get('completed_at') or scan.get('created_at') or '')}</div></div>
  <div class="badge" style="background:#0f172a">Risk {escape(summary.get('risk_label', 'None'))} · {escape(summary.get('risk_score', 0))}/100</div>
</header>
<div class="cards">{cards}</div>
<div class="summary">
  <div class="two">
    <div><div class="lbl">Customer</div><b>{escape(customer.get('name', '—'))}</b><br><span class="meta">{escape(group.get('name', '—'))} / {escape(asset.get('name', '—'))}</span></div>
    <div><div class="lbl">Scan details</div><span class="meta">Type: {escape(scan.get('scan_type'))}<br>Status: {escape(scan.get('status'))}<br>Duration: {escape(duration)}<br>Started: {escape(scan.get('started_at') or '—')}</span></div>
  </div>
</div>
<h2>Findings ({len(findings)})</h2>
{''.join(finding_html) if finding_html else '<div class="summary">No findings were recorded for this scan.</div>'}
<footer>Generated {generated} by VulnScanner. This report reflects the state at scan time. Only scan systems for which you have explicit authorization. Evidence may contain sensitive information; handle this report accordingly.</footer>
</div></body></html>"""
