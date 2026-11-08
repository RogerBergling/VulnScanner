"""Scan-depth diagnostics.

A scan that only produces open-port findings is often not broken: a signature
engine is missing, external APIs are offline, a TLS handshake failed, or the
selected executor only performs discovery. These helpers make that visible
before and after a scan instead of leaving the operator to read logs.
"""

from __future__ import annotations

import os
from typing import Any

from .config import ENABLE_EXTERNAL_APIS, interactsh_server, tls_ca_bundle
from .database import get_db, get_setting, setting_or_default
from .scanners.tools import tool_path

TOOL_LABELS = {
    "nuclei": "Nuclei signature engine",
    "nmap": "Nmap service detection",
    "testssl": "testssl.sh",
    "gvm-cli": "OpenVAS / gvm-cli",
    "sqlmap": "sqlmap (dangerous)",
}


def _tool_check(tool: str, enabled: bool, detail_when_missing: str) -> dict[str, Any]:
    try:
        from .tools_manager import tool_mode

        source_disabled = tool_mode(tool) == "disabled"
    except Exception:
        source_disabled = False
    if not enabled or source_disabled:
        return {
            "id": f"tool:{tool}",
            "label": TOOL_LABELS.get(tool, tool),
            "status": "disabled",
            "detail": (
                "Disabled in Settings → Optional command-line tools."
                if source_disabled
                else "Disabled by the selected scan options or Settings."
            ),
        }
    path = tool_path(tool)
    if path:
        return {
            "id": f"tool:{tool}",
            "label": TOOL_LABELS.get(tool, tool),
            "status": "ready",
            "detail": path,
        }
    return {
        "id": f"tool:{tool}",
        "label": TOOL_LABELS.get(tool, tool),
        "status": "missing",
        "detail": detail_when_missing,
    }


def _cache_counts() -> dict[str, int]:
    counts = {"nvd": 0, "epss": 0, "kev": 0, "osv": 0}
    try:
        with get_db() as conn:
            counts["nvd"] = int(
                conn.execute(
                    "SELECT COUNT(*) FROM nvd_cache WHERE cache_key LIKE 'nvd:%'"
                ).fetchone()[0]
            )
            counts["epss"] = int(
                conn.execute("SELECT COUNT(*) FROM epss_cache").fetchone()[0]
            )
            counts["kev"] = int(
                conn.execute("SELECT COUNT(*) FROM kev_catalog").fetchone()[0]
            )
            counts["osv"] = int(
                conn.execute("SELECT COUNT(*) FROM osv_cache").fetchone()[0]
            )
    except Exception:
        pass
    return counts


def _nvd_key_configured() -> bool:
    if os.getenv("VS_NVD_API_KEY", "").strip():
        return True
    try:
        return bool(get_setting("nvd_api_key", "").strip())
    except Exception:
        return False


def build_scan_diagnostics(
    scan_type: str,
    options: dict[str, Any] | None = None,
    *,
    target: str = "",
    executor: str = "",
    agent: dict[str, Any] | None = None,
    satellite: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a compact readiness report for a planned or completed scan."""
    options = options or {}
    checks: list[dict[str, Any]] = []
    warnings: list[str] = []

    external = bool(ENABLE_EXTERNAL_APIS) and setting_or_default(
        "allow_external_apis", "true"
    ) == "true"
    counts = _cache_counts()
    if external:
        checks.append(
            {
                "id": "external-apis",
                "label": "Vulnerability APIs",
                "status": "ready",
                "detail": "NVD, OSV, EPSS and KEV lookups are allowed.",
            }
        )
    else:
        checks.append(
            {
                "id": "external-apis",
                "label": "Vulnerability APIs",
                "status": "disabled",
                "detail": (
                    "External APIs are disabled. CVE/OSV lookups only use local "
                    f"caches (NVD records: {counts['nvd']}, OSV records: {counts['osv']})."
                ),
            }
        )
        warnings.append(
            "External APIs are disabled; only previously cached vulnerability data can be used."
        )

    if counts["nvd"] or counts["epss"] or counts["kev"]:
        checks.append(
            {
                "id": "vulnerability-cache",
                "label": "Local vulnerability data",
                "status": "ready" if counts["nvd"] or counts["kev"] else "warning",
                "detail": (
                    f"NVD cache entries: {counts['nvd']} · EPSS scores: {counts['epss']} · "
                    f"KEV entries: {counts['kev']} · OSV cache entries: {counts['osv']}"
                ),
            }
        )
    else:
        checks.append(
            {
                "id": "vulnerability-cache",
                "label": "Local vulnerability data",
                "status": "warning",
                "detail": "No vulnerability cache is populated. Run Settings → Vulnerability data → Sync.",
            }
        )

    checks.append(
        {
            "id": "nvd-key",
            "label": "NVD API key",
            "status": "ready" if _nvd_key_configured() else "warning",
            "detail": (
                "Configured (higher NVD rate limit)."
                if _nvd_key_configured()
                else "Not configured; NVD is limited to 5 requests per 30 seconds."
            ),
        }
    )

    nuclei_enabled = bool(options.get("nuclei", True)) and setting_or_default(
        "nuclei_enabled", "true"
    ) == "true"
    if scan_type in {"web", "network"}:
        checks.append(
            _tool_check(
                "nuclei",
                nuclei_enabled,
                "Not installed. The main web/network signature engine will be skipped.",
            )
        )
        try:
            from .tools_manager import tool_mode

            nuclei_source_disabled = tool_mode("nuclei") == "disabled"
        except Exception:
            nuclei_source_disabled = False
        if nuclei_enabled and not tool_path("nuclei") and not nuclei_source_disabled:
            warnings.append(
                "Nuclei is enabled but not installed; the scan will use built-in checks only."
            )

    if scan_type in {"web", "network"} and options.get("sqlmap"):
        checks.append(
            _tool_check(
                "sqlmap",
                True,
                "Not installed; the dangerous sqlmap stage will be skipped.",
            )
        )
        if setting_or_default("dangerous_tools_enabled", "false") != "true":
            warnings.append(
                "sqlmap is enabled for this scan but the global dangerous-tools switch is off."
            )

    if scan_type == "network":
        if not bool(options.get("nuclei_network", True)):
            warnings.append(
                "Nuclei network templates are disabled; non-web services only get built-in probes and CVE matching."
            )
        nmap_enabled = bool(options.get("external_tools", False)) and setting_or_default(
            "nmap_enabled", "true"
        ) == "true"
        checks.append(
            _tool_check(
                "nmap",
                nmap_enabled,
                "Not installed; service versions are inferred from banners only.",
            )
        )
        if nmap_enabled and not tool_path("nmap"):
            warnings.append(
                "Nmap is enabled but not installed; only banner-based service fingerprinting will run."
            )
        testssl_enabled = bool(options.get("external_tools", False)) and bool(
            options.get("testssl", False)
        )
        checks.append(
            _tool_check(
                "testssl",
                testssl_enabled,
                "Not installed; only built-in TLS observations will be produced.",
            )
        )
        if testssl_enabled and not tool_path("testssl"):
            warnings.append(
                "testssl.sh is enabled but not installed; TLS depth is limited to built-in checks."
            )
        openvas_enabled = bool(options.get("openvas", False)) and setting_or_default(
            "openvas_enabled", "false"
        ) == "true"
        checks.append(
            _tool_check(
                "gvm-cli",
                openvas_enabled,
                "Not installed or GVM is not configured; OpenVAS coverage is skipped.",
            )
        )
        if openvas_enabled and not tool_path("gvm-cli"):
            warnings.append(
                "OpenVAS is enabled but gvm-cli is not installed or configured."
            )
        if not bool(options.get("web_checks", True)):
            warnings.append(
                "Web vulnerability checks are disabled; discovered HTTP/HTTPS services will only be fingerprinted."
            )
        if not bool(options.get("cve_lookup", True)):
            warnings.append(
                "CVE matching is disabled by the scan options; only port/service findings will be produced."
            )
        if not bool(options.get("service_probes", True)):
            warnings.append(
                "Service security probes are disabled; SMB/SNMP/Redis/MongoDB/RDP/VNC checks will be skipped."
            )
    elif scan_type == "web":
        testssl_enabled = bool(options.get("external_tools", False)) and bool(
            options.get("testssl", False)
        )
        checks.append(
            _tool_check(
                "testssl",
                testssl_enabled,
                "Not installed; only built-in TLS observations will be produced.",
            )
        )
        if not bool(options.get("cve_lookup", True)):
            warnings.append("CVE matching is disabled by the scan options.")
        if not bool(options.get("active", True)):
            warnings.append("Active checks are disabled; the scan is passive.")

    ca_bundle = tls_ca_bundle()
    checks.append(
        {
            "id": "tls",
            "label": "TLS verification",
            "status": "ready",
            "detail": (
                f"Certificate verification is on with custom CA bundle: {ca_bundle}"
                if ca_bundle
                else "Certificate verification is on. Private/self-signed HTTPS targets need a CA bundle or the per-scan ignore-TLS option."
            ),
        }
    )
    if ca_bundle and not os.path.isfile(ca_bundle):
        checks[-1]["status"] = "warning"
        checks[-1]["detail"] = f"Configured CA bundle does not exist: {ca_bundle}"
        warnings.append(f"The configured TLS CA bundle does not exist: {ca_bundle}")

    if options.get("oast"):
        server = interactsh_server()
        checks.append(
            {
                "id": "oast",
                "label": "OAST collaborator",
                "status": "ready" if server else "warning",
                "detail": (
                    f"Interactsh server: {server}"
                    if server
                    else "OAST is enabled for the scan but no Interactsh server is configured in Settings."
                ),
            }
        )
        if not server:
            warnings.append(
                "OAST is enabled but no Interactsh server is configured; blind callbacks will not be detected."
            )

    if agent:
        checks.append(
            {
                "id": "executor",
                "label": "Executor: endpoint agent",
                "status": "warning",
                "detail": (
                    "The agent performs TCP discovery from its network position and "
                    "returns open ports/banners. Web checks and Nuclei do not run on "
                    "the agent; the server can still enrich banners with CVE data."
                ),
            }
        )
        warnings.append(
            "Agent-delegated network scans are unauthenticated and do not run the full web/signature engine."
        )
    elif satellite:
        online = bool(satellite.get("online"))
        checks.append(
            {
                "id": "executor",
                "label": "Executor: satellite",
                "status": "ready" if online else "warning",
                "detail": (
                    f"Satellite {satellite.get('name') or satellite.get('id')} runs the full "
                    "web/network engines from its network position."
                    if online
                    else "The selected satellite is offline; the scan waits until it reconnects."
                ),
            }
        )
        if not online:
            warnings.append("The selected satellite is offline.")
    else:
        checks.append(
            {
                "id": "executor",
                "label": "Executor: local server",
                "status": "ready",
                "detail": "The scan runs on this VulnScanner server.",
            }
        )

    return {
        "scan_type": scan_type,
        "target": target,
        "executor": executor or ("agent" if agent else "satellite" if satellite else "server"),
        "checks": checks,
        "warnings": warnings,
        "ready": not any(item["status"] == "missing" for item in checks),
    }
