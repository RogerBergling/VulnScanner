import csv
import io
import json

from app.reporting import build_csv, build_html, build_json

SCAN = {
    "id": 7,
    "scan_type": "web",
    "target": "https://example.test/?q=<script>",
    "status": "completed",
    "created_at": "2026-01-01T00:00:00+00:00",
    "started_at": "2026-01-01T00:00:01+00:00",
    "completed_at": "2026-01-01T00:00:31+00:00",
}
FINDINGS = [
    {
        "severity": "high",
        "category": "web",
        "title": "<script>alert(1)</script>",
        "description": "Description with <b>markup</b>",
        "evidence": "line1\nline2",
        "remediation": "Fix & verify",
        "cve": "CVE-2026-0001",
        "cwe": "CWE-79",
        "cvss": 8.1,
        "location": "https://example.test/?q=<x>",
        "resource": "",
        "status": "open",
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-01-01T00:00:00+00:00",
        "raw": {"kev": {"cve_id": "CVE-2026-0001"}, "references": ["https://example.test/a?x=1&y=2"]},
    },
    {
        "severity": "low",
        "category": "info",
        "title": "Low finding",
        "description": "",
        "evidence": "",
        "remediation": "",
        "cve": "",
        "cwe": "",
        "cvss": None,
        "location": "",
        "resource": "",
        "status": "acknowledged",
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-01-01T00:00:00+00:00",
        "raw": {},
    },
]
CONTEXT = {
    "generated_at": "2026-01-02T00:00:00+00:00",
    "customer": {"name": "Acme & Sons"},
    "group": {"name": "Web"},
    "asset": {"name": "site"},
    "summary": {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 1,
        "info": 0,
        "total": 2,
        "risk_score": 9,
        "risk_label": "Low",
    },
}


def test_json_report_round_trip():
    payload = json.loads(build_json(SCAN, FINDINGS, CONTEXT))
    assert payload["product"] == "VulnScanner"
    assert payload["customer"]["name"] == "Acme & Sons"
    assert payload["scan"]["id"] == 7
    assert len(payload["findings"]) == 2


def test_csv_report_has_header_and_rows():
    rows = list(csv.reader(io.StringIO(build_csv(SCAN, FINDINGS))))
    assert rows[0][0] == "scan_id"
    assert len(rows) == 3
    assert rows[1][1] == "high"
    assert rows[1][3] == "<script>alert(1)</script>"


def test_html_report_escapes_content_and_marks_kev():
    html = build_html(SCAN, FINDINGS, CONTEXT)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert "CISA KEV" in html
    assert "https://example.test/a?x=1&amp;y=2" in html
    assert "Acme &amp; Sons" in html
    assert "30s" in html
    assert "Findings (2)" in html


def test_html_report_without_findings():
    html = build_html({**SCAN, "status": "completed"}, [], {**CONTEXT, "summary": {"total": 0}})
    assert "No findings were recorded" in html


def test_csv_neutralises_formula_injection():
    finding = dict(FINDINGS[0])
    finding["title"] = "=cmd|' /C calc'!A0"
    finding["evidence"] = "@SUM(1+1)"
    text = build_csv(SCAN, [finding])
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[1][3] == "'=cmd|' /C calc'!A0"
    assert rows[1][13] == "'@SUM(1+1)"


def test_html_report_drops_unsafe_reference_schemes():
    finding = dict(FINDINGS[0])
    finding["raw"] = {"references": ["javascript:alert(1)", "https://example.test/advisory"]}
    html = build_html(SCAN, [finding], {"customer": {}, "group": {}, "asset": {}, "summary": {}})
    assert "javascript:" not in html
    assert "https://example.test/advisory" in html
