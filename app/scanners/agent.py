"""Normalize results uploaded by the Linux/Windows endpoint agent."""

from __future__ import annotations

import ipaddress
import re

from typing import Any

from ..config import DANGEROUS_PORTS, SERVICE_NAMES
from ..utils import truncate
from .ad import process_ad_report
from .base import Finding, ScanContext, ScanResult, normalize_finding
from .dependencies import PackageRef, enrich_packages


def _address_exposed(address: str) -> bool:
    address = (address or "").strip().strip("[]")
    if not address or address.lower() in {"localhost", "::1"}:
        return False
    if address.startswith("127."):
        return False
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        return not ip.is_loopback
    except ValueError:
        return True


def _add_ports(result: ScanResult, payload: dict[str, Any]) -> None:
    ports = payload.get("listening_ports") or []
    if not isinstance(ports, list):
        return
    for item in ports[:2000]:
        if not isinstance(item, dict):
            continue
        try:
            port = int(item.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if not port:
            continue
        address = str(item.get("address") or "")
        protocol = str(item.get("protocol") or "tcp").lower()
        service = str(item.get("service") or SERVICE_NAMES.get(port, "unknown"))
        process = str(item.get("process") or "")
        exposed = _address_exposed(address)
        dangerous = DANGEROUS_PORTS.get(port)
        if dangerous and exposed and protocol == "tcp":
            _, severity, remediation = dangerous
            result.add(
                Finding(
                    severity=severity,
                    title=f"Risky service listening on all interfaces: {dangerous[0]} (port {port})",
                    category="host",
                    description=(
                        f"The agent found {dangerous[0]} listening on {address}:{port}. "
                        "A service bound to a non-loopback address can be reached from the network."
                    ),
                    evidence=(
                        f"Address: {address}:{port}/{protocol}\nService: {service}\n"
                        f"Process: {process or 'unknown'}"
                    ),
                    remediation=remediation,
                    location=f"{address}:{port}",
                    key=f"agent-risky-port:{port}",
                    raw={"address": address, "port": port, "process": process},
                )
            )
        else:
            result.add(
                Finding(
                    severity="info",
                    title=f"Listening service on {address}:{port} ({service})",
                    category="host",
                    description=(
                        "The endpoint has a listening service. Exposure depends on the bind address and host firewall."
                    ),
                    evidence=(
                        f"Address: {address}:{port}/{protocol}\nService: {service}\n"
                        f"Process: {process or 'unknown'}"
                    ),
                    remediation="Stop unused services and bind management services to loopback or a protected interface.",
                    location=f"{address}:{port}",
                    key=f"agent-open-port:{address}:{port}:{protocol}",
                    raw={"address": address, "port": port},
                )
            )


def _add_checks(result: ScanResult, payload: dict[str, Any]) -> None:
    checks = payload.get("checks") or []
    if not isinstance(checks, list):
        return
    for item in checks[:1000]:
        if not isinstance(item, dict):
            continue
        finding = normalize_finding(item)
        finding["category"] = finding.get("category") or "host"
        finding["key"] = finding.get("key") or f"agent-check:{finding.get('title', '')}"
        result.findings.append(finding)


WINDOWS_SOFTWARE_EOL = [
    (r"internet explorer", "Internet Explorer", "critical",
     "Remove Internet Explorer and use a supported browser."),
    (r"adobe flash", "Adobe Flash", "critical",
     "Uninstall Adobe Flash; it is end-of-life and unsupported."),
    (r"microsoft silverlight", "Microsoft Silverlight", "high",
     "Remove Silverlight or upgrade to a supported platform."),
    (r"python 2(\.|$)", "Python 2", "high",
     "Upgrade Python 2 applications to Python 3."),
    (r"apache tomcat (6|7)(\.|$)", "Apache Tomcat 6/7", "high",
     "Upgrade Apache Tomcat to a supported release."),
    (r"openssl 1\.0", "OpenSSL 1.0", "high",
     "Upgrade software that bundles OpenSSL 1.0."),
    (r"microsoft sql server (2008|2012|2014)", "SQL Server 2008/2012/2014", "high",
     "Upgrade SQL Server to a supported version."),
]


def _add_windows_software_eol(result: ScanResult, packages: list[dict[str, Any]]) -> None:
    for item in packages[:6000]:
        if str(item.get("source") or "") != "windows-registry":
            continue
        label = f"{item.get('name', '')} {item.get('version', '')}".strip()
        lowered = label.lower()
        for pattern, product, severity, remediation in WINDOWS_SOFTWARE_EOL:
            if not re.search(pattern, lowered):
                continue
            result.add(
                Finding(
                    severity=severity,
                    title=f"Unsupported software on the endpoint: {product}",
                    category="host",
                    description=(
                        f"The endpoint reports {label}, which is no longer supported "
                        "or no longer receives security updates."
                    ),
                    evidence=f"Software: {label}\nPublisher: {item.get('publisher', '')}",
                    remediation=remediation,
                    location=str(item.get("name") or "endpoint"),
                    key=f"agent-software-eol:{product.lower().replace(' ', '-')}",
                    cwe="CWE-1104",
                    raw={"name": item.get("name"), "version": item.get("version")},
                )
            )
            break


def _add_secrets(result: ScanResult, payload: dict[str, Any], category: str = "secret") -> None:
    items = payload.get("secrets") or payload.get("source") or []
    if not isinstance(items, list):
        return
    for item in items[:500]:
        if not isinstance(item, dict):
            continue
        finding = normalize_finding(item)
        finding["category"] = category
        finding["key"] = finding.get("key") or f"{category}:{finding.get('location', '')}"
        result.findings.append(finding)


def process_agent_payload(ctx: ScanContext, payload: dict[str, Any]) -> ScanResult:
    result = ScanResult()
    system = payload.get("system") or {}
    if not isinstance(system, dict):
        system = {}
    result.metadata["system"] = {
        key: truncate(str(value), 300)
        for key, value in system.items()
        if isinstance(value, (str, int, float, bool)) and value not in (None, "")
    }
    ctx.log(
        f"Agent report from {system.get('hostname', 'unknown host')} "
        f"({system.get('os', system.get('platform', 'unknown OS'))})"
    )

    _add_checks(result, payload)
    ctx.progress(35, "Processing endpoint services")
    _add_ports(result, payload)
    _add_secrets(result, payload, category="secret")
    if payload.get("source_findings"):
        _add_secrets(result, {"secrets": payload.get("source_findings")}, category="source")

    ad_report = payload.get("ad")
    if isinstance(ad_report, dict) and ad_report:
        ctx.progress(55, "Evaluating Active Directory findings")
        ad_result = process_ad_report(ad_report)
        result.findings.extend(ad_result.findings)
        result.metadata["ad"] = ad_result.metadata

    packages = payload.get("packages") or []
    package_refs: list[PackageRef] = []
    if isinstance(packages, list):
        for item in packages[:6000]:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            version = str(item.get("version") or "").strip()
            ecosystem = str(item.get("ecosystem") or "").strip()
            if not name or not version or not ecosystem:
                continue
            package_refs.append(
                PackageRef(
                    name,
                    version,
                    ecosystem,
                    str(item.get("source") or "agent inventory"),
                    bool(item.get("dev")),
                )
            )
    _add_windows_software_eol(result, packages)
    result.metadata["inventory_packages"] = len(package_refs)
    if package_refs:
        ctx.progress(65, "Matching installed packages against OSV")
        ctx.log(f"Checking {len(package_refs)} installed package version(s) against OSV.dev")
        try:
            enrich_packages(package_refs, ctx, result)
        except Exception as exc:
            ctx.log(f"Package vulnerability lookup failed: {exc}", "warning")
            result.metadata["osv_error"] = truncate(str(exc), 300)

    # Agent-provided custom findings (for future modules and third-party tools).
    for item in payload.get("findings") or []:
        if isinstance(item, dict):
            finding = normalize_finding(item)
            finding["key"] = finding.get("key") or f"agent:{finding.get('title', '')}"
            result.findings.append(finding)

    ctx.progress(94, "Finalizing endpoint results")
    normalized = result.normalized()
    result.metadata["finding_count"] = len(normalized)
    result.metadata["modules"] = payload.get("modules") or []
    return result
