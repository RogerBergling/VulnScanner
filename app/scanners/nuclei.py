"""Nuclei signature engine integration.

Nuclei is the primary vulnerability-signature engine for web targets and for
the HTTP services discovered during network scans. Unlike the other optional
CLI tools it is on by default: a scan opts out with ``nuclei=false``. The
template database is updated automatically on a schedule and on demand from
Settings; updates respect the external-API master switch and the Nuclei
integration toggle.
"""

from __future__ import annotations

import json
import threading
from typing import Any

from ..config import ENABLE_EXTERNAL_APIS
from ..database import set_setting, setting_or_default, utcnow
from ..utils import truncate
from .base import Finding, ScanContext, ScanResult
from .tools import run_tool, tool_path

DEFAULT_TAGS = "cve,misconfiguration,exposure"
SEVERITIES = "critical,high,medium"
TAG_RE = r"^[a-zA-Z0-9,\-]{0,200}$"

_update_lock = threading.Lock()


def resolve_tags(ctx: ScanContext | None) -> str:
    """Return the tag filter for a scan (option overrides the default)."""
    import re

    raw = ""
    if ctx is not None:
        raw = str(ctx.option("nuclei_tags", "") or "").strip()
    if not raw:
        raw = setting_or_default("nuclei_default_tags", DEFAULT_TAGS)
    raw = raw.strip()
    if not raw or raw.lower() in {"all", "*"}:
        return ""
    if not re.match(TAG_RE, raw):
        return ""
    return raw


def run_nuclei(result: ScanResult, url: str, ctx: ScanContext) -> None:
    """Run Nuclei templates against a target URL (default on per scan)."""
    if not ctx.option_bool("nuclei", True):
        return
    if setting_or_default("nuclei_enabled", "true") != "true":
        return
    path = tool_path("nuclei")
    if not path:
        ctx.log("Nuclei not installed; using built-in checks only", "warning")
        return
    tags = resolve_tags(ctx)
    ctx.log(
        "Running Nuclei signature engine "
        f"(severities {SEVERITIES}" + (f", tags {tags}" if tags else ", all tags") + ")"
    )
    command = [
        path,
        "-u",
        url,
        "-jsonl",
        "-silent",
        "-no-interactsh",
        "-disable-update-check",
        "-severity",
        SEVERITIES,
        "-timeout",
        "10",
        "-retries",
        "1",
    ]
    if tags:
        command += ["-tags", tags]
    try:
        proc = run_tool(command, timeout=900)
    except Exception as exc:
        ctx.log(f"Nuclei failed to run: {exc}", "warning")
        return
    if proc.returncode not in (0, 1):
        ctx.log(f"Nuclei exited with code {proc.returncode}", "warning")
    count = 0
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        info = item.get("info") or {}
        classification = info.get("classification") or {}
        cve = classification.get("cve-id") or ""
        cwe = classification.get("cwe-id") or ""
        if isinstance(cve, list):
            cve = ",".join(str(x) for x in cve)
        if isinstance(cwe, list):
            cwe = ",".join(str(x) for x in cwe)
        matched = item.get("matched-at") or item.get("host") or url
        template_id = str(item.get("template-id") or "")
        tags_list = info.get("tags") or []
        if isinstance(tags_list, str):
            tags_list = [tags_list]
        result.add(
            Finding(
                severity=str(info.get("severity") or "medium"),
                title=str(info.get("name") or template_id or "Nuclei finding"),
                category="web",
                description=str(info.get("description") or "") + (
                    f"\n\nTags: {', '.join(str(t) for t in tags_list)}" if tags_list else ""
                ),
                evidence=f"Template: {template_id}\nMatcher: {item.get('matcher-name', '')}\nMatched at: {matched}",
                remediation=str(info.get("remediation") or "Review the Nuclei template and vendor guidance."),
                cve=str(cve),
                cwe=str(cwe),
                cvss=classification.get("cvss-score"),
                location=matched,
                resource=f"nuclei:{template_id}",
                key=f"nuclei:{template_id}:{item.get('matcher-name', '')}",
                raw={
                    "template_id": template_id,
                    "tags": [str(t) for t in tags_list],
                    "engine": "nuclei",
                },
            )
        )
        count += 1
    ctx.log(f"Nuclei reported {count} finding(s)")


def update_templates() -> dict[str, Any]:
    """Run ``nuclei -update-templates`` once; returns status for the GUI."""
    with _update_lock:
        if setting_or_default("nuclei_enabled", "true") != "true":
            return {"status": "disabled", "detail": "Nuclei integration is disabled in Settings"}
        if not ENABLE_EXTERNAL_APIS or setting_or_default("allow_external_apis", "true") != "true":
            return {
                "status": "blocked",
                "detail": "External APIs are disabled; enable them before updating templates",
            }
        path = tool_path("nuclei")
        if not path:
            return {"status": "missing", "detail": "Nuclei is not installed"}
        try:
            proc = run_tool([path, "-update-templates", "-disable-update-check"], timeout=1800)
        except Exception as exc:
            return {"status": "failed", "detail": truncate(str(exc), 300)}
        output = (proc.stdout or "").strip() or (proc.stderr or "").strip()
        status = "ok" if proc.returncode == 0 else "failed"
        set_setting("nuclei_templates_updated_at", utcnow())
        set_setting("nuclei_templates_status", status)
        set_setting("nuclei_templates_detail", truncate(output, 600))
        return {
            "status": status,
            "detail": truncate(output, 600),
            "returncode": proc.returncode,
        }
