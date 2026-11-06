"""Greenbone/OpenVAS integration (optional external engine).

Runs the Greenbone Vulnerability Management daemon through ``gvm-cli`` for an
additional feed-based scan engine. The integration is deliberately optional
and off by default: it requires a working GVM stack (PostgreSQL, gvmd,
ospd-openvas and the community feed) and credentials that reach the daemon
socket.

Security notes:

- Credentials are stored encrypted (same Fernet key as SMTP/target
  credentials) and are never returned by the API.
- ``gvm-cli`` is invoked as a separate process with an argument array and a
  minimal environment; its GPL license does not affect this MIT project.
- Per-scan result caps and the scan's cancellation flag are respected.
"""

from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from typing import Any

from ..credentials import decrypt_secret
from ..database import setting_or_default
from ..utils import safe_xml_fromstring, truncate
from .base import ScanCancelled, ScanContext, ScanResult
from .tools import run_tool, tool_path

MAX_RESULTS = 200


def severity_from_gmp(value: str) -> str:
    """Map a GMP severity string (e.g. '9.8') onto VulnScanner severities."""
    try:
        score = float(value or 0)
    except (TypeError, ValueError):
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _credentials(ctx: ScanContext | None = None) -> tuple[str, str, str]:
    """Return (socket_path, username, password) for gvm-cli."""
    socket_path = setting_or_default("gvm_socket_path", "/run/gvmd/gvmd.sock")
    username = setting_or_default("gvm_username", "admin")
    encrypted = setting_or_default("gvm_password", "")
    password = ""
    if encrypted:
        try:
            password = decrypt_secret(encrypted)
        except Exception:
            password = ""
    return socket_path, username, password


def _gmp(cli: str, socket_path: str, username: str, password: str,
         xml: str, ctx: ScanContext | None = None) -> str | None:
    command = [
        cli,
        "--gmp-username", username,
        "--gmp-password", password,
        "socket",
        "--socketpath", socket_path,
        "--xml", xml,
    ]
    if ctx:
        ctx.check_cancel()
    try:
        proc = run_tool(command, timeout=600)
    except Exception as exc:
        if ctx:
            ctx.log(f"gvm-cli failed: {exc}", "warning")
        return None
    if proc.returncode != 0:
        if ctx:
            ctx.log(f"gvm-cli exited with code {proc.returncode}: {truncate(proc.stderr, 300)}", "warning")
        return None
    return proc.stdout or ""


def _response_ok(xml_text: str) -> bool:
    try:
        root = safe_xml_fromstring(xml_text)
    except (ET.ParseError, ValueError):
        return False
    return root.get("status") == "200"


def _extract_id(xml_text: str, tag: str, status: str | None = None) -> str | None:
    try:
        root = safe_xml_fromstring(xml_text)
    except (ET.ParseError, ValueError):
        return None
    if status is not None and root.get("status") != status:
        return None
    return root.get("id")


def create_target(cli: str, socket_path: str, username: str, password: str,
                  host: str, ctx: ScanContext) -> str | None:
    xml = (
        f'<create_target><name>vs-{host}-{int(time.time())}</name>'
        f"<hosts>{host}</hosts></create_target>"
    )
    response = _gmp(cli, socket_path, username, password, xml, ctx)
    return _extract_id(response or "", "create_target", "201") if response else None


def create_task(cli: str, socket_path: str, username: str, password: str,
                target_id: str, ctx: ScanContext) -> str | None:
    xml = (
        "<create_task>"
        f"<name>vs-scan-{int(time.time())}</name>"
        "<comment>VulnScanner external engine</comment>"
        f"<config id=\"daba56c8-73ec-11df-a475-002264764cea\"/>"  # Full and fast
        f"<target id=\"{target_id}\"/>"
        "<scanner id=\"08b69003-5fc2-4037-a479-93b440211c73\"/>"  # OpenVAS Default
        "</create_task>"
    )
    response = _gmp(cli, socket_path, username, password, xml, ctx)
    return _extract_id(response or "", "create_task", "201") if response else None


def start_task(cli: str, socket_path: str, username: str, password: str,
               task_id: str, ctx: ScanContext) -> str | None:
    response = _gmp(
        cli, socket_path, username, password,
        f'<start_task task_id="{task_id}"/>', ctx,
    )
    return _extract_id(response or "", "start_task", "202") if response else None


def wait_for_task(cli: str, socket_path: str, username: str, password: str,
                  task_id: str, ctx: ScanContext, max_wait: int = 1800) -> str | None:
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        ctx.check_cancel()
        response = _gmp(
            cli, socket_path, username, password,
            f'<get_tasks task_id="{task_id}"/>', ctx,
        )
        if response:
            try:
                root = safe_xml_fromstring(response)
            except (ET.ParseError, ValueError):
                root = None
            if root is not None and root.get("status") == "200":
                task = root.find(".//task")
                if task is not None:
                    status = task.findtext("status")
                    if status in {"Done", "Stopped", "Interrupted"}:
                        report = task.find('.//last_report/report')
                        if report is not None:
                            return report.get("id")
                        return "done-no-report"
        time.sleep(15)
    return None


def fetch_report(cli: str, socket_path: str, username: str, password: str,
                 report_id: str, ctx: ScanContext) -> str | None:
    return _gmp(
        cli, socket_path, username, password,
        f'<get_reports report_id="{report_id}"/>', ctx,
    )


def parse_report(report_xml: str) -> list[dict[str, Any]]:
    """Parse a GMP report into finding dicts. Pure for tests."""
    findings: list[dict[str, Any]] = []
    try:
        root = safe_xml_fromstring(report_xml)
    except (ET.ParseError, ValueError):
        return findings
    for result in root.findall(".//result")[:MAX_RESULTS]:
        name = result.findtext("name") or "Unnamed result"
        severity = severity_from_gmp(result.findtext("severity") or "0")
        nvt = result.find("nvt") if result.find("nvt") is not None else None
        nvt_oid = nvt.get("oid") if nvt is not None else ""
        host_text = result.findtext("host") or ""
        port_text = result.findtext("port") or ""
        description = (result.findtext("description") or "")[:2000]
        findings.append({
            "severity": severity,
            "title": truncate(name, 300),
            "category": "network",
            "description": description,
            "evidence": f"OpenVAS NVT: {nvt_oid}\nHost: {host_text}\nPort: {port_text}",
            "remediation": "Review the OpenVAS result and apply the vendor remediation guidance.",
            "location": f"{host_text}:{port_text}",
            "key": f"openvas:{nvt_oid}:{host_text}:{port_text}",
            "raw": {
                "engine": "openvas",
                "nvt": nvt_oid,
                "host": host_text,
                "port": port_text,
            },
        })
    return findings


def run_openvas(result: ScanResult, host: str, ctx: ScanContext) -> int:
    """Run a full OpenVAS task for one host (double-gated optional engine)."""
    if not ctx.option_bool("external_tools", False) or not ctx.option_bool("openvas", False):
        return 0
    if setting_or_default("openvas_enabled", "false") != "true":
        ctx.log("OpenVAS skipped: the integration is disabled in Settings", "warning")
        return 0
    cli = tool_path("gvm-cli")
    if not cli:
        ctx.log("gvm-cli not installed; skipping the OpenVAS engine", "warning")
        return 0
    socket_path, username, password = _credentials(ctx)
    if not password:
        ctx.log("OpenVAS credentials are not configured in Settings", "warning")
        return 0
    ctx.log(f"Starting OpenVAS task for {host}")
    try:
        target_id = create_target(cli, socket_path, username, password, host, ctx)
        if not target_id:
            ctx.log("OpenVAS: could not create target", "warning")
            return 0
        task_id = create_task(cli, socket_path, username, password, target_id, ctx)
        if not task_id:
            ctx.log("OpenVAS: could not create task", "warning")
            return 0
        if not start_task(cli, socket_path, username, password, task_id, ctx):
            ctx.log("OpenVAS: could not start task", "warning")
            return 0
        report_id = wait_for_task(cli, socket_path, username, password, task_id, ctx)
        if not report_id:
            ctx.log("OpenVAS: task did not finish in time", "warning")
            return 0
        if report_id == "done-no-report":
            ctx.log("OpenVAS task finished without a report")
            return 0
        report_xml = fetch_report(cli, socket_path, username, password, report_id, ctx)
        if not report_xml:
            ctx.log("OpenVAS: could not fetch the report", "warning")
            return 0
    except ScanCancelled:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        ctx.log(f"OpenVAS engine failed: {exc}", "warning")
        return 0
    parsed = parse_report(report_xml)
    for item in parsed:
        result.add(item)
    ctx.log(f"OpenVAS reported {len(parsed)} result(s) for {host}")
    return len(parsed)
