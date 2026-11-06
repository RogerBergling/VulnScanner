"""sqlmap integration (dangerous, double-gated).

sqlmap sends real SQL injection attack payloads. It is the only scanner that
requires **two** independent switches before it runs:

1. Settings → **Dangerous tools** (`dangerous_tools_enabled`, default off).
2. The per-scan **sqlmap** option (default off).

sqlmap is GPL-2.0 licensed and is invoked as a separate process; it is never
linked or bundled. It is pre-installed on Kali Linux; on other systems the
operator installs it from https://sqlmap.org and points `VS_SQLMAP_PATH` at it.
"""

from __future__ import annotations

import re
from typing import Any

from ..database import setting_or_default
from ..utils import redact_url
from .base import Finding, ScanContext, ScanResult
from .tools import run_tool, tool_path

# sqlmap prints one of these blocks per injectable parameter:
#   Parameter: id (GET)
#       Type: boolean-based blind
#       Title: AND boolean-based blind - WHERE or HAVING clause
#       Payload: id=1 AND 1=1
PARAM_RE = re.compile(r"^\s*Parameter:\s+(\S+)\s+\(([A-Z]+)\)", re.M)
TYPE_RE = re.compile(r"^\s*Type:\s+(.+)$", re.M)
PAYLOAD_RE = re.compile(r"^\s*Payload:\s+(.+)$", re.M)
VULNERABLE_RE = re.compile(
    r"(sqlmap identified the following injection point|is vulnerable|"
    r"the back-end DBMS is)",
    re.I,
)

MAX_TARGETS = 20


def run_sqlmap(result: ScanResult, param_urls: list[str], ctx: ScanContext) -> int:
    """Run sqlmap against discovered parameter URLs (double-gated)."""
    if not param_urls:
        return 0
    if not ctx.option_bool("sqlmap", False):
        return 0
    if setting_or_default("dangerous_tools_enabled", "false") != "true":
        ctx.log(
            "sqlmap skipped: the global dangerous-tools switch is disabled in Settings",
            "warning",
        )
        return 0
    path = tool_path("sqlmap")
    if not path:
        ctx.log("sqlmap not installed; skipping deep SQL injection testing", "warning")
        return 0
    try:
        max_targets = int(ctx.option("max_sqlmap_targets", 5))
    except (TypeError, ValueError):
        max_targets = 5
    max_targets = max(1, min(MAX_TARGETS, max_targets))
    found = 0
    for url in param_urls[:max_targets]:
        ctx.check_cancel()
        ctx.log(f"sqlmap: testing {redact_url(url)}")
        command = [
            path,
            "-u",
            url,
            "--batch",
            "--smart",
            "--level",
            "2",
            "--risk",
            "2",
            "--threads",
            "4",
            "--timeout",
            "15",
            "--retries",
            "1",
            "--disable-coloring",
        ]
        try:
            proc = run_tool(command, timeout=900)
        except Exception as exc:
            ctx.log(f"sqlmap failed on {redact_url(url)}: {exc}", "warning")
            continue
        output = proc.stdout or ""
        added = _parse_sqlmap_output(result, url, output)
        if added:
            found += added
        if proc.returncode != 0:
            ctx.log(f"sqlmap exited with code {proc.returncode} on {redact_url(url)}", "warning")
    ctx.log(f"sqlmap confirmed {found} injectable parameter(s)")
    return found


def _parse_sqlmap_output(result: ScanResult, url: str, output: str) -> int:
    """Turn sqlmap console output into findings. Pure for tests."""
    if not VULNERABLE_RE.search(output):
        return 0
    added = 0
    parameters: dict[str, dict[str, Any]] = {}
    current: str | None = None
    for line in output.splitlines():
        match = PARAM_RE.search(line)
        if match:
            current = match.group(1)
            method = match.group(2)
            parameters.setdefault(
                current, {"method": method, "types": [], "payloads": []}
            )
            continue
        if current is None:
            continue
        type_match = TYPE_RE.search(line)
        if type_match:
            parameters[current]["types"].append(type_match.group(1).strip())
            continue
        payload_match = PAYLOAD_RE.search(line)
        if payload_match:
            parameters[current]["payloads"].append(payload_match.group(1).strip()[:300])
    for name, data in parameters.items():
        if not data["types"]:
            continue
        evidence = [
            f"URL: {redact_url(url)}",
            f"Parameter: {name} ({data['method']})",
            "Injection types: " + ", ".join(data["types"]),
        ]
        if data["payloads"]:
            evidence.append("Payload sample: " + data["payloads"][0])
        result.add(
            Finding(
                severity="critical",
                title=f"SQL injection confirmed by sqlmap in parameter '{name}'",
                category="web",
                description=(
                    f"sqlmap confirmed that the '{name}' parameter of {redact_url(url)} "
                    "is injectable using the following technique(s): "
                    + ", ".join(data["types"])
                    + ". An attacker can read or modify database contents through this parameter."
                ),
                evidence="\n".join(evidence),
                remediation=(
                    "Use parameterized queries or prepared statements for every database "
                    "access, validate input, apply least-privilege database accounts and "
                    "enable a Web Application Firewall while the code is fixed."
                ),
                cwe="CWE-89",
                location=redact_url(url),
                resource=f"sqlmap:{name}",
                key=f"sqlmap:{name}",
                raw={
                    "parameter": name,
                    "method": data["method"],
                    "types": data["types"],
                    "engine": "sqlmap",
                },
            )
        )
        added += 1
    return added
