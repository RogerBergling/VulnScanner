"""Optional testssl.sh integration for deep TLS inspection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..database import get_setting
from ..utils import truncate
from .base import Finding, ScanContext, ScanResult
from .tools import run_tool, tool_path

MAX_TESTSSL_FINDINGS = 500
SKIP_IDS = {"service", "HTTP_status_code", "HTTP_clock_skew", "HTTP_headerTime"}


def _join(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return ",".join(str(item) for item in value if item)
    return str(value or "")


def _severity(value: Any) -> str | None:
    raw = str(value or "").strip().upper()
    mapping = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "WARN": "medium",
        "WARNING": "medium",
        "LOW": "low",
        "FATAL": "high",
    }
    return mapping.get(raw)


def _remediation(identifier: str) -> str:
    lower = identifier.lower()
    if "cert" in lower or "chain" in lower:
        return (
            "Install a complete, trusted certificate chain that matches the hostname, "
            "and automate renewal before expiry."
        )
    if "protocol" in lower or "cipher" in lower or "forward_secrecy" in lower:
        return (
            "Disable obsolete protocols and weak cipher suites; require TLS 1.2/1.3 "
            "with forward-secret ciphers in the server configuration."
        )
    if "hsts" in lower:
        return "Send a strict Strict-Transport-Security policy after verifying HTTPS coverage."
    return "Review the testssl.sh result and the server's TLS configuration, then retest."


def _entries(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []
    for key in ("scanResult", "scanResults", "results", "findings"):
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return [data]


def parse_testssl_json(data: Any, host: str, port: int) -> list[dict[str, Any]]:
    """Convert testssl.sh's JSON report into finding dictionaries.

    Older and newer testssl.sh releases both expose a ``scanResult`` array, but
    report roots have differed over time. Unknown or informational records are
    ignored rather than failing the integration.
    """
    findings: list[dict[str, Any]] = []
    location = f"{host}:{port}"
    for item in _entries(data):
        identifier = str(item.get("id") or item.get("test") or item.get("title") or "").strip()
        if not identifier or identifier in SKIP_IDS:
            continue
        severity = _severity(item.get("severity"))
        if not severity:
            continue
        finding_text = str(
            item.get("finding") or item.get("message") or item.get("result") or ""
        ).strip()
        cve = _join(item.get("cve") or item.get("cves"))
        cwe = _join(item.get("cwe") or item.get("cwes"))
        title = str(item.get("name") or identifier).strip()
        if not title.lower().startswith("tls"):
            title = f"TLS configuration issue: {title}"
        findings.append(
            {
                "severity": severity,
                "title": truncate(title, 250),
                "category": "tls",
                "description": truncate(finding_text, 4000)
                or "testssl.sh reported a TLS configuration issue.",
                "evidence": truncate(
                    f"Test: {identifier}\nTarget: {location}\n"
                    f"Finding: {finding_text or '(no details)'}",
                    3000,
                ),
                "remediation": _remediation(identifier),
                "cve": cve[:300],
                "cwe": cwe[:300],
                "location": location,
                "resource": f"testssl:{identifier}",
                "key": f"testssl:{identifier}",
                "raw": {
                    "test": identifier,
                    "severity": str(item.get("severity") or ""),
                    "detected_by": "testssl.sh",
                },
            }
        )
        if len(findings) >= MAX_TESTSSL_FINDINGS:
            break
    return findings


def _read_report(directory: Path) -> Any:
    candidates = sorted(directory.glob("*.json"))
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if data:
            return data
    return None


def run_testssl(result: ScanResult, host: str, port: int, ctx: ScanContext) -> int:
    """Run testssl.sh against an HTTPS endpoint when it is enabled."""
    if not ctx.option_bool("external_tools", False) or not ctx.option_bool("testssl", False):
        return 0
    if get_setting("testssl_enabled", "true") != "true":
        return 0
    path = tool_path("testssl")
    if not path:
        ctx.log("testssl.sh not installed; using built-in TLS checks only", "warning")
        return 0

    import tempfile

    ctx.log(f"Running testssl.sh against {host}:{port}")
    with tempfile.TemporaryDirectory(prefix="vs-testssl-") as temp_dir:
        report = Path(temp_dir) / "testssl.json"
        command = [
            path,
            "--jsonfile",
            str(report),
            "--color",
            "0",
            "--quiet",
            f"{host}:{port}",
        ]
        try:
            proc = run_tool(command, timeout=600)
        except Exception as exc:
            ctx.log(f"testssl.sh failed to run: {exc}", "warning")
            return 0
        if proc.returncode not in (0, 1):
            ctx.log(
                f"testssl.sh exited with code {proc.returncode}: "
                f"{truncate(proc.stderr or proc.stdout, 300)}",
                "warning",
            )
        data = _read_report(Path(temp_dir))
        if data is None:
            ctx.log("testssl.sh did not produce a usable JSON report", "warning")
            return 0
        findings = parse_testssl_json(data, host, port)
        for item in findings:
            result.add(Finding(**item))
        ctx.log(f"testssl.sh reported {len(findings)} TLS finding(s)")
        return len(findings)
