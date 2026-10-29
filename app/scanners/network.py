"""TCP service and network exposure scanner."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import requests
from requests.packages import urllib3

from ..config import DANGEROUS_PORTS, MAX_CIDR_HOSTS, SERVICE_NAMES, get_limit
from ..database import get_setting
from ..utils import parse_ports, safe_xml_fromstring, truncate, validate_host_target
from .authenticated import authenticated_scan
from .base import Finding, ScanContext, ScanResult
from .testssl import run_testssl
from .tools import run_tool, tool_path
from .web import (
    _add_header_findings,
    _exposed_files,
    _get as safe_get,
    _injection_checks,
    _run_nuclei,
    _session as web_session,
    _title,
    _tls_findings,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER_PORTS = {
    21, 22, 23, 25, 110, 143, 389, 587, 993, 995, 1433, 1521, 3306, 5432,
    5900, 6379, 9200, 11211, 27017,
}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
HTTP_PORTS = {
    80, 443, 591, 3000, 5000, 5601, 7001, 8000, 8008, 8080, 8081,
    8443, 8888, 9000, 9090, 9443,
}
TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443}


@dataclass
class PortResult:
    host: str
    port: int
    banner: str = ""
    elapsed: float = 0.0


def _expand_hosts(target: str) -> list[str]:
    kind, value = validate_host_target(target)
    if kind == "cidr":
        network = ipaddress.ip_network(value, strict=False)
        limit = get_limit("max_cidr_hosts", MAX_CIDR_HOSTS)
        if network.num_addresses > limit:
            raise ValueError(
                f"Network contains {network.num_addresses} addresses; limit is {limit}. "
                "Scan smaller ranges."
            )
        if network.num_addresses == 1:
            return [str(network.network_address)]
        return [str(host) for host in network.hosts()]
    try:
        socket.getaddrinfo(value, None)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve host {value}: {exc}") from exc
    return [value]


def _probe_port(host: str, port: int, timeout: float) -> PortResult | None:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(min(timeout, 0.8))
            banner = b""
            if port in BANNER_PORTS:
                try:
                    banner = sock.recv(512)
                except (socket.timeout, OSError):
                    banner = b""
            cleaned = banner.decode("utf-8", errors="replace")
            cleaned = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", cleaned)
            return PortResult(host, port, truncate(cleaned, 500), time.monotonic() - started)
    except (OSError, socket.timeout):
        return None


def _bounded_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, parsed))


def _probe_ports(
    hosts: list[str],
    ports: list[int],
    timeout: float,
    workers: int,
    ctx: ScanContext,
) -> list[PortResult]:
    """Probe hosts/ports with a bounded in-flight window.

    Submitting every host×port pair at once can consume gigabytes for a large
    CIDR and a broad port range. Keep at most a few multiples of the worker
    count in flight, matching the agent-side implementation.
    """
    results: list[PortResult] = []
    total = max(1, len(hosts) * len(ports))
    finished = 0
    window = max(workers * 4, 32)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        pending: set[concurrent.futures.Future] = set()
        for host in hosts:
            for port in ports:
                if ctx.cancelled():
                    for future in pending:
                        future.cancel()
                    return results
                pending.add(executor.submit(_probe_port, host, port, timeout))
                if len(pending) < window:
                    continue
                done, pending = concurrent.futures.wait(
                    pending, return_when=concurrent.futures.FIRST_COMPLETED
                )
                for future in done:
                    finished += 1
                    try:
                        item = future.result()
                    except Exception:
                        continue
                    if item:
                        results.append(item)
                ctx.progress(5 + int(finished / total * 70), "Probing TCP ports")
        for future in concurrent.futures.as_completed(pending):
            finished += 1
            try:
                item = future.result()
            except Exception:
                continue
            if item:
                results.append(item)
            if finished % max(1, total // 100) == 0 or finished == total:
                ctx.progress(5 + int(finished / total * 70), "Probing TCP ports")
    return results


def _http_service(
    result: ScanResult, host: str, port: int, open_ports: list[int], ctx: ScanContext
) -> tuple[str, requests.Response, str] | None:
    schemes = ["https", "http"] if port in TLS_PORTS else ["http", "https"]
    response = None
    used_scheme = schemes[0]
    session = web_session()
    try:
        for scheme in schemes:
            try:
                response = safe_get(session, f"{scheme}://{host}:{port}/", timeout=6)
                used_scheme = scheme
                break
            except requests.RequestException:
                continue
    finally:
        session.close()
    if response is None:
        return None
    body = (response.content or b"")[:200_000].decode(response.encoding or "utf-8", errors="replace")
    title = _title(body)
    result.add(
        Finding(
            severity="info",
            title=f"Web server detected on port {port}",
            category="network",
            description=(
                "An HTTP/HTTPS web service was discovered. Header, exposed-file and "
                "injection checks run when web checks are enabled for this scan."
            ),
            evidence=(
                f"URL: {used_scheme}://{host}:{port}/\n"
                f"HTTP {response.status_code}\nTitle: {title or '(none)'}\n"
                f"Server: {truncate(response.headers.get('server', ''), 150)}"
            ),
            remediation="Review all web findings below. Patch web server software, remove exposed admin interfaces, and restrict access with a WAF or reverse proxy.",
            location=f"{host}:{port}",
            key=f"http-service:{host}:{port}",
            raw={"status": response.status_code, "title": title, "scan_type": "web"},
        )
    )
    result.metadata.setdefault("web_services", []).append(
        {"host": host, "port": port, "url": f"{used_scheme}://{host}:{port}/", "title": title}
    )
    if used_scheme == "https" or port in TLS_PORTS:
        _tls_findings(result, host, port, ctx)
    return f"{used_scheme}://{host}:{port}/", response, body


def _web_vulnerability_checks(
    result: ScanResult,
    ctx: ScanContext,
    url: str,
    response: requests.Response,
    body: str,
) -> None:
    """Run the reusable web checks against a discovered HTTP service."""
    session = web_session()
    try:
        _add_header_findings(result, url, response, body, ctx)
        try:
            _exposed_files(result, session, url, ctx)
        except requests.RequestException as exc:
            ctx.log(f"Exposed-file checks stopped on {url}: {exc}", "warning")
        try:
            _injection_checks(result, session, url, response, body, ctx)
        except requests.RequestException as exc:
            ctx.log(f"Injection probes stopped on {url}: {exc}", "warning")
        _run_nuclei(result, url, ctx)
        # Add a summary finding showing the deep web scan was executed and results were added.
        web_findings = []
        for f in result.findings:
            cat = f.category if hasattr(f, "category") else f.get("category")
            loc = f.location if hasattr(f, "location") else f.get("location", "")
            if cat in ("web", "network") and url in (loc or ""):
                web_findings.append(f)
        result.add(
            Finding(
                severity="info",
                title=f"Deep web vulnerability assessment completed on {url}",
                category="web",
                description=f"A deep web scan (headers, exposed files, injection probes, Nuclei CVE templates) was executed against the discovered web server. {len(web_findings)} web/network findings produced.",
                evidence=f"Target URL: {url}\nWeb findings generated: {len(web_findings)}",
                remediation="Review all related findings. Address critical/high web vulnerabilities before exposing this service externally.",
                location=url,
                key=f"deep-web-summary:{url}",
                raw={"url": url, "findings": len(web_findings)},
            )
        )
    finally:
        session.close()


def _add_port_findings(
    result: ScanResult, ports: list[PortResult], ctx: ScanContext
) -> None:
    for item in ports:
        service = SERVICE_NAMES.get(item.port, "unknown")
        dangerous = DANGEROUS_PORTS.get(item.port)
        evidence = f"Target: {item.host}:{item.port}/tcp\nService: {service}"
        if item.banner:
            evidence += f"\nBanner: {item.banner}"
        if dangerous:
            _, severity, remediation = dangerous
            result.add(
                Finding(
                    severity=severity,
                    title=f"Risky service exposed: {dangerous[0]} on port {item.port}",
                    category="network",
                    description=f"A {dangerous[0]} service is reachable from the scanner. Exposed management or data services are common attack paths.",
                    evidence=evidence,
                    remediation=remediation,
                    location=f"{item.host}:{item.port}",
                    key=f"risky-port:{item.port}",
                )
            )
        else:
            result.add(
                Finding(
                    severity="info",
                    title=f"Open TCP port {item.port} ({service})",
                    category="network",
                    description="The port accepted a TCP connection. Confirm that the service is required and restricted.",
                    evidence=evidence,
                    remediation="Close unused ports and restrict required services with a firewall or security group.",
                    location=f"{item.host}:{item.port}",
                    key=f"open-port:{item.port}",
                    raw={"port": item.port, "service": service, "banner": item.banner},
                )
            )
        if item.banner and re.search(r"\d+\.\d+", item.banner) and not dangerous:
            result.add(
                Finding(
                    severity="low",
                    title=f"Service version disclosed on port {item.port}",
                    category="network",
                    description="The service banner reveals version information that can help attackers choose an exploit.",
                    evidence=f"Banner: {truncate(item.banner, 300)}",
                    remediation="Reduce banner detail where the protocol permits it and keep the service patched.",
                    cwe="CWE-200",
                    location=f"{item.host}:{item.port}",
                    key=f"banner-version:{item.port}",
                )
            )


def parse_nmap_xml(xml_text: str) -> list[dict[str, Any]]:
    """Parse service and script/CVE data from nmap -oX output."""
    findings: list[dict[str, Any]] = []
    try:
        root = safe_xml_fromstring(xml_text)
    except (ET.ParseError, ValueError):
        return findings
    for host in root.findall("host"):
        address = ""
        address_node = host.find("address")
        if address_node is not None:
            address = address_node.attrib.get("addr", "")
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            try:
                port_id = int(port.attrib.get("portid", "0"))
            except (TypeError, ValueError):
                continue
            service = port.find("service")
            name = service.attrib.get("name", "unknown") if service is not None else "unknown"
            product = service.attrib.get("product", "") if service is not None else ""
            version = service.attrib.get("version", "") if service is not None else ""
            extra = service.attrib.get("extrainfo", "") if service is not None else ""
            version_text = " ".join(x for x in (product, version, extra) if x)
            findings.append(
                {
                    "severity": "info",
                    "title": f"Nmap service: {name} on port {port_id}",
                    "category": "network",
                    "description": "Service fingerprint reported by Nmap.",
                    "evidence": f"{address}:{port_id} {name} {version_text}".strip(),
                    "remediation": "Confirm the service version is supported and patched.",
                    "cve": "",
                    "location": f"{address}:{port_id}",
                    "key": f"nmap-service:{port_id}",
                    "raw": {"service": name, "product": product, "version": version},
                }
            )
            for script in port.findall("script"):
                output = script.attrib.get("output", "")
                script_id = script.attrib.get("id", "")
                cves = sorted(set(cve.upper() for cve in CVE_RE.findall(output)))
                if cves:
                    findings.append(
                        {
                            "severity": "high",
                            "title": f"Nmap script reported {', '.join(cves[:3])} on port {port_id}",
                            "category": "network",
                            "description": f"Nmap NSE script '{script_id}' associated known vulnerabilities with this service.",
                            "evidence": truncate(output, 1500),
                            "remediation": "Update the service to a supported version and follow the CVE advisories.",
                            "cve": ",".join(cves),
                            "location": f"{address}:{port_id}",
                            "key": f"nmap-cve:{script_id}:{','.join(cves)}",
                            "raw": {"script": script_id},
                        }
                    )
            # Host/port script CVEs (some scripts attach at host level).
        for script in host.findall("./hostscript/script"):
            output = script.attrib.get("output", "")
            cves = sorted(set(cve.upper() for cve in CVE_RE.findall(output)))
            if cves:
                findings.append(
                    {
                        "severity": "high",
                        "title": f"Host-level Nmap script reported {', '.join(cves[:3])}",
                        "category": "network",
                        "description": "An Nmap host script reported known vulnerabilities.",
                        "evidence": truncate(output, 1500),
                        "remediation": "Review the associated CVEs and update affected software.",
                        "cve": ",".join(cves),
                        "location": address,
                        "key": f"nmap-host-cve:{script.attrib.get('id', '')}:{','.join(cves)}",
                    }
                )
    return findings


def _run_nmap(
    result: ScanResult,
    host: str,
    open_ports: list[int],
    ctx: ScanContext,
) -> None:
    if not ctx.option_bool("external_tools", False) or not open_ports:
        return
    if get_setting("nmap_enabled", "true") != "true":
        return
    path = tool_path("nmap")
    if not path:
        ctx.log("Nmap is not installed; using built-in TCP service detection", "warning")
        return
    port_arg = ",".join(str(port) for port in open_ports[:500])
    command = [path, "-Pn", "-sV", "--version-light", "-T4", "-p", port_arg, "-oX", "-"]
    if ctx.option_bool("nmap_vulners", False):
        command[1:1] = ["--script", "vulners"]
    command.append(host)
    ctx.log(f"Running Nmap service detection against {host}")
    try:
        proc = run_tool(command, timeout=600)
    except Exception as exc:
        ctx.log(f"Nmap failed: {exc}", "warning")
        return
    if proc.returncode != 0 and not proc.stdout:
        ctx.log(f"Nmap exited with code {proc.returncode}: {truncate(proc.stderr, 300)}", "warning")
        return
    parsed = parse_nmap_xml(proc.stdout or "")
    for item in parsed:
        result.add(item)
    ctx.log(f"Nmap returned {len(parsed)} service/CVE record(s)")


def scan(ctx: ScanContext) -> ScanResult:
    result = ScanResult()
    ports = parse_ports(ctx.option("ports"), ctx.option("profile", "common"))
    hosts = _expand_hosts(ctx.target)
    timeout = float(ctx.option("connect_timeout", 0.45))
    timeout = max(0.1, min(timeout, 3.0))
    workers = _bounded_int(
        ctx.option("workers", get_limit("workers", 300)), 300, 10, 600
    )
    ctx.log(
        f"Scanning {len(hosts)} host(s) across {len(ports)} TCP port(s) "
        f"with a {timeout:.2f}s connect timeout"
    )
    ctx.progress(3, "Resolving target")
    open_by_host: dict[str, list[PortResult]] = {host: [] for host in hosts}
    started = time.monotonic()

    for item in _probe_ports(hosts, ports, timeout, workers, ctx):
        open_by_host.setdefault(item.host, []).append(item)
    if ctx.cancelled():
        ctx.log("Port scan cancelled", "warning")

    all_open = [item for items in open_by_host.values() for item in items]
    ctx.log(f"Found {len(all_open)} open TCP port(s) in {time.monotonic() - started:.1f}s")
    ctx.progress(78, "Identifying services")
    result.metadata = {
        "hosts": hosts[:500],
        "host_count": len(hosts),
        "ports_scanned": len(ports),
        "open_ports": [
            {
                "host": item.host,
                "port": item.port,
                "service": SERVICE_NAMES.get(item.port, "unknown"),
            }
            for item in all_open[:1000]
        ],
    }
    _add_port_findings(result, all_open, ctx)

    # Web/TLS checks for likely HTTP ports.
    web_checks = ctx.option_bool("web_checks", True)
    web_budget = _bounded_int(
        ctx.option("max_web_hosts", get_limit("max_web_hosts", 20)), 20, 1, 10_000
    )
    testssl_budget = _bounded_int(ctx.option("max_testssl_hosts", 5), 5, 0, 50)
    testssl_enabled = (
        ctx.option_bool("external_tools", False) and ctx.option_bool("testssl", False)
    )
    web_checked = 0
    testssl_checked = 0
    testssl_cap_logged = False
    for item in all_open:
        if item.port in HTTP_PORTS:
            ctx.check_cancel()
            try:
                service = _http_service(
                    result, item.host, item.port, [p.port for p in open_by_host[item.host]], ctx
                )
            except Exception as exc:
                ctx.log(f"HTTP probe failed on {item.host}:{item.port}: {exc}", "warning")
                continue
            if not service or not web_checks:
                continue
            if web_checked >= web_budget:
                ctx.log(
                    f"Deep web checks limited to {web_budget} service(s); "
                    "remaining web ports were fingerprinted only",
                    "warning",
                )
                break
            web_checked += 1
            url, response, body = service
            try:
                _web_vulnerability_checks(result, ctx, url, response, body)
            except Exception as exc:
                ctx.log(f"Web vulnerability checks failed on {url}: {exc}", "warning")
            parsed_url = urlparse(url)
            if parsed_url.scheme == "https" and testssl_enabled:
                if testssl_checked < testssl_budget:
                    testssl_checked += 1
                    try:
                        run_testssl(
                            result,
                            parsed_url.hostname or item.host,
                            parsed_url.port or 443,
                            ctx,
                        )
                    except Exception as exc:
                        ctx.log(f"testssl.sh integration failed on {url}: {exc}", "warning")
                elif testssl_budget and not testssl_cap_logged:
                    testssl_cap_logged = True
                    ctx.log(
                        f"testssl.sh limited to {testssl_budget} HTTPS service(s)",
                        "warning",
                    )

    # Nmap is optional and only used to enrich hosts with open services.
    if ctx.option_bool("external_tools", False):
        for host, items in open_by_host.items():
            if items and not ctx.cancelled():
                _run_nmap(result, host, sorted({p.port for p in items}), ctx)

    # Authenticated inventory/CVE checks use one credential per target OS.
    if ctx.option_bool("authenticated", False):
        ctx.progress(88, "Running authenticated host checks")
        authenticated_scan(result, ctx, open_by_host)

    ctx.progress(96, "Finalizing network results")
    return result


def _payload_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def process_agent_network_payload(ctx: ScanContext, payload: dict[str, Any]) -> ScanResult:
    """Turn a delegated TCP probe report from an endpoint agent into findings."""
    result = ScanResult()
    if not isinstance(payload.get("network"), dict) and payload.get("error"):
        raise ValueError(str(payload["error"]))
    network = payload.get("network")
    if not isinstance(network, dict):
        network = payload
    raw_ports = network.get("open_ports") or []
    ports: list[PortResult] = []
    if isinstance(raw_ports, list):
        for item in raw_ports[:5000]:
            if not isinstance(item, dict):
                continue
            host = str(item.get("host") or "").strip()[:255]
            if not host:
                continue
            try:
                port = int(item.get("port") or 0)
            except (TypeError, ValueError):
                continue
            if port < 1 or port > 65535:
                continue
            ports.append(
                PortResult(host, port, truncate(str(item.get("banner") or ""), 500))
            )
    ctx.log(f"Agent network report contains {len(ports)} open TCP port(s)")
    warnings = payload.get("warnings") or []
    if isinstance(warnings, list):
        for warning in warnings[:20]:
            ctx.log(truncate(str(warning), 400), "warning")
    ctx.progress(60, "Evaluating agent network results")
    _add_port_findings(result, ports, ctx)
    raw_hosts = network.get("hosts")
    hosts = raw_hosts[:500] if isinstance(raw_hosts, list) else []
    result.metadata = {
        "execution": "agent",
        "target": ctx.target,
        "hosts": [str(host)[:255] for host in hosts],
        "host_count": _payload_int(network.get("host_count")),
        "ports_scanned": _payload_int(network.get("ports_scanned")),
        "open_ports": [
            {
                "host": item.host,
                "port": item.port,
                "service": SERVICE_NAMES.get(item.port, "unknown"),
            }
            for item in ports[:1000]
        ],
        "agent_reported_at": truncate(str(network.get("finished_at") or ""), 80),
    }
    ctx.progress(94, "Finalizing delegated network results")
    return result
