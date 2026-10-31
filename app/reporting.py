"""JSON, CSV, standalone HTML and PDF report generation."""

from __future__ import annotations

import csv
import io
import json
from typing import Any
from urllib.parse import urlparse

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas

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


def _csv_cell(value: Any) -> Any:
    """Neutralise spreadsheet formula injection in exported cells."""
    if value is None:
        return ""
    text = str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r", "\n")):
        return "'" + text
    return text


def _safe_reference_url(value: Any) -> str | None:
    """Return a reference URL only when it uses a safe web scheme."""
    text = str(value or "").strip()
    try:
        parsed = urlparse(text)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None
    return text


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
                _csv_cell(scan.get("id")),
                _csv_cell(finding.get("severity")),
                _csv_cell(finding.get("category")),
                _csv_cell(finding.get("title")),
                _csv_cell(finding.get("cve")),
                _csv_cell(finding.get("cwe")),
                _csv_cell(finding.get("cvss")),
                _csv_cell(finding.get("location")),
                _csv_cell(finding.get("resource")),
                _csv_cell(finding.get("status")),
                _csv_cell(finding.get("first_seen")),
                _csv_cell(finding.get("last_seen")),
                _csv_cell(finding.get("description")),
                _csv_cell(finding.get("evidence")),
                _csv_cell(finding.get("remediation")),
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
        safe_refs = [
            safe
            for safe in (_safe_reference_url(url) for url in refs[:8])
            if safe
        ]
        if safe_refs:
            links = " ".join(
                f'<a href="{escape(url)}" rel="noreferrer">{escape(url)}</a>'
                for url in safe_refs
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


# ---------------------------------------------------------------------------
# PDF Report Generation
# ---------------------------------------------------------------------------

def build_pdf(
    scan: dict[str, Any],
    findings: list[dict[str, Any]],
    context: dict[str, Any],
    report_type: str = "technical",
) -> bytes:
    """Generate PDF report (technical or executive summary)."""
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)

    # Styles
    styles = getSampleStyleSheet()
    styles["Heading1"].fontSize = 18
    styles["Heading1"].spaceAfter = 10
    styles["Heading2"].fontSize = 14
    styles["Heading2"].spaceAfter = 8
    styles["Heading3"].fontSize = 12
    styles["Heading3"].spaceAfter = 6
    styles["Normal"].fontSize = 10
    styles["Normal"].spaceAfter = 4

    # Header
    p.setFont("Helvetica-Bold", 16)
    p.drawString(20 * mm, 290 * mm, "VulnScanner Security Assessment")
    p.setFont("Helvetica", 10)
    p.drawString(20 * mm, 280 * mm, f"Report Type: {report_type.capitalize()}")
    p.drawString(20 * mm, 270 * mm, f"Generated: {context.get('generated_at', '')}")
    customer = context.get("customer") or {}
    p.drawString(20 * mm, 260 * mm, f"Customer: {customer.get('name', '—')}")
    p.drawString(20 * mm, 250 * mm, f"Scan ID: {scan.get('id')}")
    p.drawString(20 * mm, 240 * mm, f"Target: {scan.get('target')}")

    # Summary section
    y = 220 * mm
    p.setFont("Helvetica-Bold", 14)
    p.drawString(20 * mm, y, "Summary")
    y -= 8 * mm
    p.setFont("Helvetica", 10)

    if report_type == "technical":
        y = _draw_technical_summary_pdf(p, scan, context, findings, y)
    else:
        y = _draw_executive_summary_pdf(p, scan, context, findings, y)

    # Footer
    p.setFont("Helvetica", 8)
    p.drawString(20 * mm, 20 * mm, "Page 1 of 1")
    p.drawString(170 * mm, 20 * mm, "Generated by VulnScanner")

    p.showPage()
    p.save()

    return buffer.getvalue()


def _wrap_text_pdf(text: str, max_chars: int) -> list[str]:
    """Simple text wrapping for PDF."""
    if not text:
        return []
    words = text.split()
    lines: list[str] = []
    current_line = []
    current_length = 0

    for word in words:
        if current_length + len(word) + (1 if current_line else 0) <= max_chars:
            current_line.append(word)
            current_length += len(word) + 1
        else:
            lines.append(" ".join(current_line))
            current_line = [word]
            current_length = len(word)

    if current_line:
        lines.append(" ".join(current_line))

    return lines


def _draw_technical_summary_pdf(
    p,
    scan: dict[str, Any],
    context: dict[str, Any],
    findings: list[dict[str, Any]],
    y: float,
) -> float:
    """Draw technical details: findings, evidence, remediation."""
    summary = context.get("summary", {})

    # Risk score bar
    p.setFont("Helvetica-Bold", 12)
    p.drawString(20 * mm, y, "Risk Summary")
    y -= 8 * mm
    p.setFont("Helvetica", 10)

    risk_score = summary.get("risk_score", 0)
    risk_label = summary.get("risk_label", "Low")

    p.setFillColor(colors.grey)
    p.rect(20 * mm, y - 4 * mm, 160 * mm, 4 * mm)
    bar_width = (risk_score / 100) * 160 * mm
    p.setFillColor(_risk_color_pdf(risk_score))
    p.rect(20 * mm, y - 4 * mm, bar_width, 4 * mm)

    p.setFillColor(colors.black)
    p.drawString(20 * mm, y, f"Risk Score: {risk_score}/100")
    p.drawString(120 * mm, y, f"Risk Level: {risk_label}")
    y -= 20 * mm

    # Finding breakdown
    p.setFont("Helvetica-Bold", 12)
    p.drawString(20 * mm, y, "Finding Breakdown")
    y -= 8 * mm
    p.setFont("Helvetica", 10)

    for sev in ("critical", "high", "medium", "low"):
        count = summary.get(sev, 0)
        if count:
            p.drawString(30 * mm, y, f"• {sev.capitalize()}: {count}")
            y -= 5 * mm

    y -= 10 * mm

    # Detailed findings
    p.setFont("Helvetica-Bold", 12)
    p.drawString(20 * mm, y, "Detailed Findings")
    y -= 8 * mm

    p.setFont("Helvetica", 9)
    finding_index = 0
    for finding in findings:
        if finding_index >= 5:
            break

        severity = finding.get("severity", "info")
        p.setFillColor(_severity_color_pdf(severity))
        p.drawString(30 * mm, y, f"{severity.upper()}: {finding.get('title', '')}")
        p.setFillColor(colors.black)
        y -= 4 * mm

        p.drawString(
            40 * mm,
            y,
            f"Location: {finding.get('location') or ''} CVSS: {finding.get('cvss') or ''} CWE: {finding.get('cwe') or ''}",
        )
        y -= 4 * mm

        if finding.get("remediation"):
            p.setFont("Helvetica-Bold", 9)
            p.drawString(30 * mm, y, "Remediation:")
            p.setFont("Helvetica", 8)
            remediation = finding["remediation"]
            if isinstance(remediation, str):
                lines = _wrap_text_pdf(remediation, 160)
                for line in lines[:2]:
                    y -= 4 * mm
                    p.drawString(40 * mm, y, line)

        y -= 8 * mm
        finding_index += 1

    return y


def _draw_executive_summary_pdf(
    p,
    scan: dict[str, Any],
    context: dict[str, Any],
    findings: list[dict[str, Any]],
    y: float,
) -> float:
    """Draw executive summary: high-level risk, top concerns, recommendations."""
    summary = context.get("summary", {})

    p.setFont("Helvetica-Bold", 12)
    p.drawString(20 * mm, y, "Executive Summary")
    y -= 8 * mm

    p.setFont("Helvetica", 10)
    p.drawString(30 * mm, y, f"Target: {scan.get('target')}")
    y -= 5 * mm
    p.drawString(
        30 * mm,
        y,
        f"Scan Period: {scan.get('started_at', '')} to {scan.get('completed_at', '')}",
    )
    y -= 5 * mm
    p.drawString(30 * mm, y, f"Total Findings: {summary.get('total', 0)}")
    p.drawString(
        30 * mm,
        y - 5 * mm,
        f"Critical/High: {summary.get('critical', 0) + summary.get('high', 0)}",
    )
    y -= 10 * mm

    p.setFont("Helvetica-Bold", 12)
    p.drawString(20 * mm, y, "Top Risks")
    y -= 8 * mm

    sorted_findings = sorted(
        findings,
        key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                f.get("severity", "info"), 99
            )
        ),
    )

    p.setFont("Helvetica", 9)
    for finding in sorted_findings[:5]:
        severity = finding.get("severity", "info")
        p.setFillColor(_severity_color_pdf(severity))
        p.drawString(40 * mm, y, f"● {severity.upper()}: {finding.get('title', '')}")
        p.setFillColor(colors.black)
        y -= 8 * mm

    y -= 4 * mm
    p.setFont("Helvetica-Bold", 12)
    p.drawString(20 * mm, y, "Key Recommendations")
    y -= 8 * mm

    p.setFont("Helvetica", 9)
    recommendations = [
        "Immediately address critical findings that could lead to data breach or system compromise.",
        "Implement security controls for high-severity findings that could be exploited.",
        "Review medium-severity findings during routine maintenance cycles.",
        "Document current security posture for compliance reporting.",
        "Establish continuous monitoring to detect new vulnerabilities.",
    ]

    for i, rec in enumerate(recommendations):
        p.drawString(30 * mm, y, f"{i + 1}. {rec}")
        y -= 10 * mm

    y -= 5 * mm
    p.setFont("Helvetica", 8)
    p.drawString(
        20 * mm,
        y,
        "Note: See technical report for detailed evidence and remediation steps.",
    )

    return y


def _risk_color_pdf(score: float) -> colors.HexColor:
    if score >= 80:
        return colors.red
    elif score >= 60:
        return colors.orange
    elif score >= 40:
        return colors.yellow
    else:
        return colors.green


def _severity_color_pdf(severity: str) -> colors.HexColor:
    return SEVERITY_COLORS.get(severity, colors.grey)
