"""Nuclei signature engine integration.

Nuclei is the primary vulnerability-signature engine for web targets and for
the HTTP services discovered during network scans. Unlike the other optional
CLI tools it is on by default: a scan opts out with ``nuclei=false``. The
template database is updated automatically on a schedule and on demand from
Settings; updates respect the external-API master switch and the Nuclei
integration toggle.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import threading
from typing import Any

from ..config import ENABLE_EXTERNAL_APIS, interactsh_server, interactsh_token
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


def _oast_args(ctx: ScanContext) -> list[str]:
    if not ctx.option_bool("oast", False):
        return ["-no-interactsh"]
    server = interactsh_server()
    if not server:
        return ["-no-interactsh"]
    args = ["-interactsh-server", server]
    token = interactsh_token()
    if token:
        args += ["-interactsh-token", token]
    return args


def _auth_config(ctx: ScanContext) -> tuple[str, list[str]]:
    """Write authenticated web headers to a private temporary Nuclei config.

    Passing bearer tokens/cookies through ``-H`` would expose them in the
    process list. Nuclei's ``-config`` file keeps them out of argv and the file
    is removed after the run.
    """
    web_auth = ctx.option("_web_auth") or None
    if not web_auth:
        return "", []
    headers: list[str] = []
    auth_type = str(web_auth.get("auth_type") or "").lower()
    if auth_type == "basic":
        username = str(web_auth.get("username") or "")
        password = str(web_auth.get("password") or "")
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers.append(f"Authorization: Basic {token}")
    elif auth_type == "bearer":
        headers.append(f"Authorization: Bearer {web_auth.get('token') or ''}")
    elif auth_type == "cookie":
        headers.append(f"Cookie: {web_auth.get('cookie') or ''}")
    for key, value in (web_auth.get("headers") or {}).items():
        if str(key).strip():
            headers.append(f"{key}: {value}")
    headers = [header for header in headers if "\r" not in header and "\n" not in header]
    if not headers:
        return "", []
    content = "header:\n" + "\n".join(
        "  - " + json.dumps(header) for header in headers
    ) + "\n"
    fd, path = tempfile.mkstemp(prefix="vulnscanner-nuclei-", suffix=".yaml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path, ["-config", path]


def _parse_nuclei_output(
    result: ScanResult,
    ctx: ScanContext,
    stdout: str,
    fallback: str,
    *,
    category: str = "web",
) -> int:
    count = 0
    for line in (stdout or "").splitlines():
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
        matched = item.get("matched-at") or item.get("host") or fallback
        template_id = str(item.get("template-id") or "")
        tags_list = info.get("tags") or []
        if isinstance(tags_list, str):
            tags_list = [tags_list]
        result.add(
            Finding(
                severity=str(info.get("severity") or "medium"),
                title=str(info.get("name") or template_id or "Nuclei finding"),
                category=category,
                description=str(info.get("description") or "") + (
                    f"\n\nTags: {', '.join(str(t) for t in tags_list)}" if tags_list else ""
                ),
                evidence=(
                    f"Template: {template_id}\n"
                    f"Matcher: {item.get('matcher-name', '')}\n"
                    f"Matched at: {matched}"
                ),
                remediation=str(
                    info.get("remediation") or "Review the Nuclei template and vendor guidance."
                ),
                cve=str(cve),
                cwe=str(cwe),
                cvss=classification.get("cvss-score"),
                location=matched,
                resource=f"nuclei:{template_id}",
                key=f"nuclei:{category}:{template_id}:{item.get('matcher-name', '')}",
                raw={
                    "template_id": template_id,
                    "tags": [str(t) for t in tags_list],
                    "engine": "nuclei",
                },
            )
        )
        count += 1
    return count


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
        *_oast_args(ctx),
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
    config_path, config_args = ("", [])
    try:
        config_path, config_args = _auth_config(ctx)
        if config_args:
            command += config_args
        proc = run_tool(command, timeout=900)
    except Exception as exc:
        ctx.log(f"Nuclei failed to run: {exc}", "warning")
        return
    finally:
        if config_path:
            try:
                os.unlink(config_path)
            except OSError:
                pass
    if proc.returncode not in (0, 1):
        ctx.log(f"Nuclei exited with code {proc.returncode}", "warning")
    count = _parse_nuclei_output(result, ctx, proc.stdout or "", url, category="web")
    ctx.log(f"Nuclei reported {count} finding(s)")


def run_nuclei_network(
    result: ScanResult,
    targets: list[str],
    ctx: ScanContext,
) -> None:
    """Run Nuclei's network-protocol templates against ``host:port`` targets.

    Web Nuclei already covers HTTP services. This stage adds signature coverage
    for SMB, RDP, SSH, databases, mail and other non-HTTP services using the
    same MIT-licensed template repository.
    """
    if not ctx.option_bool("nuclei", True) or not ctx.option_bool("nuclei_network", True):
        return
    if setting_or_default("nuclei_enabled", "true") != "true":
        return
    path = tool_path("nuclei")
    if not path:
        ctx.log("Nuclei is not installed; network signature templates are skipped", "warning")
        return
    unique: list[str] = []
    seen: set[str] = set()
    for target in targets:
        value = str(target or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        unique.append(value)
    try:
        default_targets = int(
            setting_or_default("max_nuclei_network_targets", "200")
        )
    except (TypeError, ValueError):
        default_targets = 200
    try:
        max_targets = int(ctx.option("max_nuclei_network_targets", default_targets))
    except (TypeError, ValueError):
        max_targets = default_targets
    max_targets = max(1, min(max_targets, 2000))
    if len(unique) > max_targets:
        ctx.log(
            f"Nuclei network templates limited to {max_targets} of {len(unique)} open service(s)",
            "warning",
        )
        unique = unique[:max_targets]
    if not unique:
        return
    raw_tags = str(ctx.option("nuclei_tags", "") or "").strip()
    extra_tags: list[str] = []
    if raw_tags and raw_tags.lower() not in {"all", "*"}:
        import re

        if re.match(TAG_RE, raw_tags):
            extra_tags = ["-tags", raw_tags]
    temp_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix="-nuclei-targets.txt", delete=False, encoding="utf-8"
        ) as handle:
            handle.write("\n".join(unique))
            temp_path = handle.name
        command = [
            path,
            "-l",
            temp_path,
            "-pt",
            "tcp",
            "-jsonl",
            "-silent",
            *_oast_args(ctx),
            "-disable-update-check",
            "-severity",
            SEVERITIES,
            "-timeout",
            "10",
            "-retries",
            "1",
            *extra_tags,
        ]
        ctx.log(f"Running Nuclei network templates against {len(unique)} service(s)")
        proc = run_tool(command, timeout=900)
        if proc.returncode not in (0, 1):
            ctx.log(f"Nuclei network templates exited with code {proc.returncode}", "warning")
        count = _parse_nuclei_output(
            result, ctx, proc.stdout or "", unique[0], category="network"
        )
        ctx.log(f"Nuclei network templates reported {count} finding(s)")
    except Exception as exc:
        ctx.log(f"Nuclei network template run failed: {exc}", "warning")
    finally:
        if temp_path:
            try:
                import os

                os.unlink(temp_path)
            except OSError:
                pass


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
