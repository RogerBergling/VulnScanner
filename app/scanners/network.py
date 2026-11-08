"""TCP service and network exposure scanner."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import requests
from requests.packages import urllib3

from ..config import DANGEROUS_PORTS, MAX_CIDR_HOSTS, SERVICE_NAMES, get_limit, tls_ca_bundle
from ..database import setting_or_default
from ..utils import (
    parse_ports,
    parse_target_list,
    safe_xml_fromstring,
    truncate,
    validate_host_target,
)
from .authenticated import authenticated_scan
from .base import Finding, ScanCancelled, ScanContext, ScanResult
from .cpe import add_cve_findings, fingerprint_text, lookup_cves, lookup_epss
from .services import run_service_probes
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
    crawl_same_origin,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER_PORTS = {
    21, 22, 23, 25, 110, 143, 389, 587, 993, 995, 1433, 1521, 3306, 5432,
    5900, 6379, 9200, 11211, 27017,
}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
HTTP_PORTS = {
    80, 443, 591, 3000, 4443, 5000, 5601, 5984, 6443, 7001, 8000, 8008,
    8080, 8081, 8443, 8888, 9000, 9090, 9443, 10000,
}
TLS_PORTS = {443, 465, 636, 993, 995, 4443, 6443, 8443, 9443}
WEB_SERVICE_NAMES = {
    "http",
    "https",
    "http-proxy",
    "https-alt",
    "kibana",
    "couchdb",
    "weblogic",
    "webmin",
    "kubernetes",
    "elasticsearch",
}
MAX_AUTO_WEB_PORTS = 20


@dataclass
class PortResult:
    host: str
    port: int
    banner: str = ""
    elapsed: float = 0.0


def _expand_hosts(target: str) -> list[str]:
    entries = parse_target_list(target)
    if not entries:
        raise ValueError("A network target is required")
    limit = get_limit("max_cidr_hosts", MAX_CIDR_HOSTS)
    hosts: list[str] = []
    seen: set[str] = set()

    def add(host: str) -> None:
        key = host.lower()
        if key not in seen:
            seen.add(key)
            hosts.append(host)

    total = 0
    for entry in entries:
        kind, value = validate_host_target(entry)
        if kind == "cidr":
            network = ipaddress.ip_network(value, strict=False)
            if network.num_addresses > limit:
                raise ValueError(
                    f"Network {value} contains {network.num_addresses} addresses; "
                    f"limit is {limit}. Scan smaller ranges."
                )
            total += network.num_addresses
            if total > limit:
                raise ValueError(
                    f"Target list expands to more than {limit} hosts. "
                    "Reduce the number of targets or scan smaller ranges."
                )
            if network.num_addresses == 1:
                add(str(network.network_address))
            else:
                for host in network.hosts():
                    add(str(host))
            continue

        total += 1
        if total > limit:
            raise ValueError(
                f"Target list expands to more than {limit} hosts. "
                "Reduce the number of targets or scan smaller ranges."
            )
        try:
            socket.getaddrinfo(value, None)
        except socket.gaierror as exc:
            raise ValueError(f"Could not resolve host {value}: {exc}") from exc
        add(value)
    return hosts


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


def _ping_host(host: str, timeout: float = 1.0) -> bool | None:
    """Return True/False for an ICMP echo result, or None if ICMP is unusable.

    The built-in scanner normally scans every target with TCP connect probes and
    does not require ICMP. When the operator explicitly disables the
    "scan unresponsive hosts" option, this cheap system-ping pre-check filters
    silent addresses before the more expensive port scan.
    """
    if not re.fullmatch(r"[A-Za-z0-9._:%\[\]-]+", host) or host.startswith("-"):
        return None
    ping = shutil.which("ping")
    if not ping:
        return None
    if os.name == "nt":
        command = [ping, "-n", "1", "-w", str(max(250, int(timeout * 1000))), host]
    elif sys.platform == "darwin":
        command = [ping, "-n", "-c", "1", "-W", str(max(1, int(timeout * 1000))), host]
    else:
        command = [ping, "-n", "-c", "1", "-W", str(max(1, int(round(timeout)))), host]
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            timeout=max(2.0, timeout + 2.0),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False
    except OSError:
        return None
    if proc.returncode == 0:
        return True
    error = (proc.stderr or b"").decode("utf-8", errors="replace").lower()
    if any(
        token in error
        for token in (
            "permission",
            "not permitted",
            "operation not permitted",
            "unknown option",
            "invalid option",
            "usage:",
        )
    ):
        return None
    return False


def _filter_responsive_hosts(hosts: list[str], ctx: ScanContext) -> list[str]:
    """Keep hosts that answer ICMP; scan all hosts when ICMP is unavailable."""
    if not hosts:
        return hosts
    states: dict[str, bool | None] = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, min(32, len(hosts)))
    ) as executor:
        future_to_host = {executor.submit(_ping_host, host): host for host in hosts}
        for future in concurrent.futures.as_completed(future_to_host):
            host = future_to_host[future]
            try:
                states[host] = future.result()
            except Exception:
                states[host] = None
    unresolved = sum(1 for host in hosts if states.get(host) is None)
    responsive = [host for host in hosts if states.get(host) is not False]
    if unresolved == len(hosts):
        ctx.log(
            "ICMP ping is unavailable or not permitted; scanning all hosts anyway",
            "warning",
        )
    skipped = len(hosts) - len(responsive)
    if skipped:
        ctx.log(
            f"ICMP pre-check skipped {skipped} host(s) that did not respond; "
            "enable 'Scan hosts even if they do not answer ping' to include them",
            "warning",
        )
    return responsive


def _is_web_candidate(item: PortResult) -> bool:
    if item.port in HTTP_PORTS:
        return True
    if SERVICE_NAMES.get(item.port, "") in WEB_SERVICE_NAMES:
        return True
    banner = (item.banner or "").lower()
    return "http/" in banner or "server:" in banner or "<html" in banner


def _select_web_candidates(
    all_open: list[PortResult], include_unknown: bool = True
) -> list[PortResult]:
    """Return known web services plus a bounded set of unknown ports to probe."""
    candidates = [item for item in all_open if _is_web_candidate(item)]
    selected = {(item.host, item.port) for item in candidates}
    if not include_unknown:
        return candidates
    unknown: list[PortResult] = []
    for item in all_open:
        if (item.host, item.port) in selected:
            continue
        if SERVICE_NAMES.get(item.port) in (None, "unknown") and len(unknown) < MAX_AUTO_WEB_PORTS:
            unknown.append(item)
    return candidates + unknown


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
    result: ScanResult,
    host: str,
    port: int,
    open_ports: list[int],
    ctx: ScanContext,
    probe_timeout: float = 6.0,
) -> tuple[str, requests.Response, str] | None:
    schemes = ["https", "http"] if port in TLS_PORTS else ["http", "https"]
    response = None
    used_scheme = schemes[0]
    verify_tls = not ctx.option_bool("ignore_tls_errors", False)
    session = web_session(
        verify_tls=verify_tls,
        ca_bundle=tls_ca_bundle(),
        web_auth=ctx.option("_web_auth") or None,
    )
    errors: list[str] = []
    try:
        for scheme in schemes:
            try:
                response = safe_get(session, f"{scheme}://{host}:{port}/", timeout=probe_timeout)
                used_scheme = scheme
                break
            except requests.RequestException as exc:
                errors.append(f"{scheme}: {exc}")
                continue
    finally:
        session.close()
    if response is None:
        detail = "; ".join(errors[-2:]) or "no HTTP/HTTPS response"
        ctx.log(f"HTTP probe failed on {host}:{port}: {detail}", "warning")
        tls_like_error = any(
            token in detail.lower()
            for token in ("certificate", "ssl", "tls", "handshake")
        )
        if port in HTTP_PORTS or port in TLS_PORTS or tls_like_error:
            result.add(
                Finding(
                    severity="low" if port in TLS_PORTS or tls_like_error else "info",
                    title=f"Web service on port {port} could not be inspected",
                    category="network",
                    description=(
                        "The port is a likely HTTP/HTTPS service, but the scanner "
                        "could not complete a web request. Common causes are a "
                        "self-signed/private-CA certificate, a hostname mismatch "
                        "when scanning by IP, or a service that expects another "
                        "protocol."
                    ),
                    evidence=(
                        f"Target: {host}:{port}\n"
                        f"TLS verification: {'on' if verify_tls else 'off'}\n"
                        f"CA bundle: {tls_ca_bundle() or '(system trust store)'}\n"
                        f"Errors: {truncate(detail, 800)}"
                    ),
                    remediation=(
                        "Use the target hostname instead of an IP, add the private "
                        "CA to VS_TLS_CA_BUNDLE/Settings, or enable 'Ignore TLS "
                        "certificate errors' only for an authorised lab target."
                    ),
                    location=f"{host}:{port}",
                    key=f"web-probe-failed:{host}:{port}",
                )
            )
        return None
    body = (response.content or b"")[:200_000].decode(response.encoding or "utf-8", errors="replace")
    title = _title(body)
    result.add(
        Finding(
            severity="info",
            title=f"Web server detected on port {port}",
            category="network",
            description=(
                "An HTTP/HTTPS web service was discovered. Header, exposed-file, "
                "same-origin crawl and injection checks run when web checks are enabled "
                "for this scan."
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
        {
            "host": host,
            "port": port,
            "url": f"{used_scheme}://{host}:{port}/",
            "title": title,
            "server": truncate(response.headers.get("server", ""), 200),
            "powered_by": truncate(response.headers.get("x-powered-by", ""), 200),
        }
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
) -> int:
    """Run the reusable web checks against a discovered HTTP service."""
    session = web_session(
        verify_tls=not ctx.option_bool("ignore_tls_errors", False),
        ca_bundle=tls_ca_bundle(),
        web_auth=ctx.option("_web_auth") or None,
    )
    pages_crawled = 0
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
        try:
            pages = crawl_same_origin(session, url, body, ctx)
            pages_crawled = len(pages)
            for page_url, page_response, page_body in pages:
                try:
                    _injection_checks(result, session, page_url, page_response, page_body, ctx)
                except requests.RequestException as exc:
                    ctx.log(f"Injection probes stopped on {page_url}: {exc}", "warning")
        except ScanCancelled:
            raise
        except Exception as exc:
            ctx.log(f"Same-origin crawl stopped on {url}: {exc}", "warning")
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
                description=(
                    "A deep web scan (header review, exposed files, same-origin crawl, "
                    "injection probes and Nuclei CVE templates) was executed against the "
                    f"discovered web server. {len(web_findings)} web/network findings produced."
                ),
                evidence=(
                    f"Target URL: {url}\nPages crawled: {pages_crawled}\n"
                    f"Web findings generated: {len(web_findings)}"
                ),
                remediation="Review all related findings. Address critical/high web vulnerabilities before exposing this service externally.",
                location=url,
                key=f"deep-web-summary:{url}",
                raw={"url": url, "findings": len(web_findings), "pages_crawled": pages_crawled},
            )
        )
    finally:
        session.close()
    return pages_crawled


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
) -> list[dict[str, Any]]:
    if not ctx.option_bool("external_tools", False) or not open_ports:
        return []
    if setting_or_default("nmap_enabled", "true") != "true":
        return []
    path = tool_path("nmap")
    if not path:
        ctx.log("Nmap is not installed; using built-in TCP service detection", "warning")
        return []
    port_arg = ",".join(str(port) for port in open_ports[:500])
    command = [path, "-sV", "--version-light", "-T4", "-p", port_arg, "-oX", "-"]
    if ctx.option_bool("scan_unresponsive_hosts", True):
        command.insert(1, "-Pn")
    if ctx.option_bool("nmap_vulners", False):
        command[1:1] = ["--script", "vulners"]
    command.append(host)
    ctx.log(f"Running Nmap service detection against {host}")
    try:
        proc = run_tool(command, timeout=600)
    except Exception as exc:
        ctx.log(f"Nmap failed: {exc}", "warning")
        return []
    if proc.returncode != 0 and not proc.stdout:
        ctx.log(f"Nmap exited with code {proc.returncode}: {truncate(proc.stderr, 300)}", "warning")
        return []
    parsed = parse_nmap_xml(proc.stdout or "")
    for item in parsed:
        result.add(item)
    ctx.log(f"Nmap returned {len(parsed)} service/CVE record(s)")
    return parsed


def _run_cve_matching(
    result: ScanResult,
    ctx: ScanContext,
    all_open: list[PortResult],
    web_headers: dict[tuple[str, int], dict[str, str]],
    nmap_hints: list[tuple[str, str]],
    extra_banners: dict[tuple[str, int], str] | None = None,
) -> int:
    """Fingerprint detected services and match their versions against NVD CVEs."""
    max_lookups = _bounded_int(
        ctx.option("max_cve_lookups", get_limit("max_cve_lookups", 25)), 25, 0, 200
    )
    if max_lookups == 0:
        return 0
    max_per_service = _bounded_int(
        ctx.option("max_cves_per_service", get_limit("max_cves_per_service", 50)), 50, 1, 500
    )
    max_per_scan = _bounded_int(
        ctx.option("max_cves_per_scan", get_limit("max_cves_per_scan", 500)), 500, 1, 5_000
    )

    candidates: list[tuple[Any, str, str]] = []
    seen: set[tuple[str, str]] = set()
    extra_banners = extra_banners or {}
    for item in all_open:
        location = f"{item.host}:{item.port}"
        texts: list[tuple[str, str]] = []
        if item.banner:
            texts.append((item.banner, "banner"))
        probe_banner = extra_banners.get((item.host, item.port))
        if probe_banner:
            texts.append((probe_banner, "active-probe"))
        headers = web_headers.get((item.host, item.port)) or {}
        if headers.get("server"):
            texts.append((headers["server"], "http-server-header"))
        if headers.get("powered_by"):
            texts.append((headers["powered_by"], "http-x-powered-by"))
        for text, source in texts:
            for match in fingerprint_text(text, source):
                key = (location, match.cpe)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append((match, location, "network"))
    for location, text in nmap_hints:
        for match in fingerprint_text(text, "nmap"):
            key = (location, match.cpe)
            if key in seen:
                continue
            seen.add(key)
            candidates.append((match, location, "network"))

    if not candidates:
        ctx.log("CVE matching: no service versions could be fingerprinted", "info")
        return 0

    total_added = 0
    for match, location, category in candidates[:max_lookups]:
        ctx.check_cancel()
        cves = lookup_cves(match, ctx.log)
        if not cves:
            continue
        ctx.log(
            f"CVE matching: {match.product} {match.version} on {location} "
            f"matches {len(cves)} known CVE(s)"
        )
        cve_ids = [record["id"] for record in cves if record.get("id")]
        epss = lookup_epss(cve_ids, ctx.log)
        total_added += add_cve_findings(
            result,
            match,
            location,
            cves,
            category,
            epss=epss,
            max_findings=min(max_per_service, max_per_scan - total_added),
        )
        if total_added >= max_per_scan:
            ctx.log(
                f"CVE matching stopped at the per-scan cap of {max_per_scan} finding(s)",
                "warning",
            )
            break
    ctx.log(f"CVE matching produced {total_added} finding(s)")
    return total_added


def _expand_wildcards(
    ctx: ScanContext, entries: list[str]
) -> tuple[list[str], list[str], dict[str, list[str]]]:
    """Split wildcard targets (``*.example.com``) from plain targets.

    Wildcards are expanded with subdomain discovery (Subfinder + wordlist) and
    the discovered hostnames are returned to be scanned in the same job.
    """
    plain: list[str] = []
    discovered: list[str] = []
    metadata: dict[str, list[str]] = {}
    wildcard_domains = [entry[2:] for entry in entries if entry.startswith("*.")]
    for entry in entries:
        if not entry.startswith("*."):
            plain.append(entry)
    if not wildcard_domains:
        return plain, discovered, metadata
    from .subdomains import discover_subdomains, normalize_domain

    try:
        max_hosts = int(ctx.option("max_wildcard_hosts", 1000))
    except (TypeError, ValueError):
        max_hosts = 1000
    max_hosts = max(1, min(10_000, max_hosts))
    for domain in wildcard_domains:
        try:
            domain = normalize_domain(domain)
        except ValueError as exc:
            raise ValueError(f"Invalid wildcard target: {exc}") from exc
        ctx.log(
            f"Wildcard target *.{domain}: running subdomain discovery "
            f"(Subfinder passive + wordlist), then scanning discovered hosts"
        )
        hosts = discover_subdomains(ctx, domain, max_hosts=max_hosts)
        ctx.log(f"Wildcard *.{domain} resolved to {len(hosts)} host(s)")
        discovered.extend(sorted(hosts))
        metadata[domain] = sorted(hosts)[:200]
    return plain, discovered, metadata


def scan(ctx: ScanContext) -> ScanResult:
    result = ScanResult()
    ports = parse_ports(ctx.option("ports"), ctx.option("profile", "common"))
    entries = parse_target_list(ctx.target)
    wildcard_entries = [entry for entry in entries if entry.startswith("*.")]
    plain_entries, discovered_hosts, wildcard_meta = _expand_wildcards(ctx, entries)
    if not plain_entries and not discovered_hosts and wildcard_entries:
        # Discovery found nothing. Do not try to resolve the wildcard string
        # itself (``*.example.com``); finish with an explanatory finding.
        result.metadata = {
            "hosts": [],
            "host_count": 0,
            "ports_scanned": len(ports),
            "wildcard_expansion": wildcard_meta,
            "no_hosts_discovered": wildcard_entries,
        }
        result.add(
            Finding(
                severity="info",
                title="No hosts discovered for wildcard target",
                category="network",
                description=(
                    "Subdomain discovery found no hosts for the wildcard target. "
                    "Check the domain, the Subfinder integration, the subdomain "
                    "wordlist and the external-API setting. The scan did not fall "
                    "back to resolving the literal wildcard name."
                ),
                evidence=(
                    "Wildcard target(s): " + ", ".join(wildcard_entries)
                    + "\nSubfinder: " + ("enabled" if ctx.option_bool("subfinder", True) else "disabled")
                    + "\nWordlist discovery: " + ("enabled" if ctx.option_bool("bruteforce", True) else "disabled")
                ),
                remediation=(
                    "Load the SecLists wordlist under Settings, install Subfinder, "
                    "or use an explicit host/CIDR target instead."
                ),
                location=", ".join(wildcard_entries),
                key="wildcard-no-hosts:" + ",".join(wildcard_entries),
                raw={"wildcards": wildcard_entries, "expansion": wildcard_meta},
            )
        )
        ctx.progress(100, "No wildcard hosts discovered")
        return result
    if discovered_hosts:
        target = "\n".join(plain_entries + discovered_hosts)
    else:
        target = ctx.target
    hosts = _expand_hosts(target)
    default_timeout = 0.45
    try:
        default_timeout = float(setting_or_default("network_connect_timeout", "0.45"))
    except (TypeError, ValueError):
        pass
    timeout = float(ctx.option("connect_timeout", default_timeout))
    timeout = max(0.1, min(timeout, 3.0))
    workers = _bounded_int(
        ctx.option("workers", get_limit("workers", 300)), 300, 10, 600
    )
    ctx.progress(3, "Resolving target")
    if not ctx.option_bool("scan_unresponsive_hosts", True):
        ctx.progress(4, "Checking ICMP reachability")
        ctx.log(f"Running an ICMP pre-check against {len(hosts)} host(s)")
        hosts = _filter_responsive_hosts(hosts, ctx)
    ctx.log(
        f"Scanning {len(hosts)} host(s) across {len(ports)} TCP port(s) "
        f"with a {timeout:.2f}s connect timeout"
    )
    open_by_host: dict[str, list[PortResult]] = {host: [] for host in hosts}
    started = time.monotonic()

    for item in _probe_ports(hosts, ports, timeout, workers, ctx):
        open_by_host.setdefault(item.host, []).append(item)
    if ctx.cancelled():
        ctx.log("Port scan cancelled", "warning")

    all_open = [item for items in open_by_host.values() for item in items]
    all_open.sort(key=lambda item: (item.host, item.port))
    ctx.log(f"Found {len(all_open)} open TCP port(s) in {time.monotonic() - started:.1f}s")
    ctx.progress(78, "Identifying services")
    result.metadata = {
        "hosts": hosts[:500],
        "host_count": len(hosts),
        "ports_scanned": len(ports),
        "scan_unresponsive_hosts": ctx.option_bool("scan_unresponsive_hosts", True),
        "open_ports": [
            {
                "host": item.host,
                "port": item.port,
                "service": SERVICE_NAMES.get(item.port, "unknown"),
            }
            for item in all_open[:1000]
        ],
    }
    if wildcard_meta:
        result.metadata["wildcard_expansion"] = wildcard_meta
    _add_port_findings(result, all_open, ctx)

    # Active service security probes: SMB signing, unauthenticated
    # Redis/MongoDB/Elasticsearch/Docker/Memcached/Kibana, default SNMP
    # communities, RDP NLA and VNC authentication.
    service_banners: dict[tuple[str, int], str] = {}
    if ctx.option_bool("service_probes", True):
        ctx.progress(80, "Running service security probes")
        try:
            service_banners = run_service_probes(result, ctx, open_by_host)
        except ScanCancelled:
            raise
        except Exception as exc:
            ctx.log(f"Service probes failed: {exc}", "warning")

    # Web/TLS checks for detected and likely HTTP/HTTPS services.
    web_checks = ctx.option_bool("web_checks", True)
    web_budget = _bounded_int(
        ctx.option("max_web_hosts", get_limit("max_web_hosts", 20)), 20, 1, 10_000
    )
    try:
        default_testssl_budget = int(setting_or_default("max_testssl_hosts", "5"))
    except (TypeError, ValueError):
        default_testssl_budget = 5
    testssl_budget = _bounded_int(
        ctx.option("max_testssl_hosts", default_testssl_budget),
        default_testssl_budget,
        0,
        50,
    )
    testssl_enabled = (
        ctx.option_bool("external_tools", False) and ctx.option_bool("testssl", False)
    )
    web_checked = 0
    testssl_checked = 0
    testssl_cap_logged = False
    web_cap_logged = False
    web_candidates = _select_web_candidates(all_open, include_unknown=web_checks)
    for item in web_candidates:
        ctx.check_cancel()
        known_web_port = _is_web_candidate(item)
        try:
            service = _http_service(
                result,
                item.host,
                item.port,
                [p.port for p in open_by_host[item.host]],
                ctx,
                probe_timeout=6.0 if known_web_port else 2.0,
            )
        except Exception as exc:
            ctx.log(f"HTTP probe failed on {item.host}:{item.port}: {exc}", "warning")
            continue
        if not service or not web_checks:
            continue
        if web_checked >= web_budget:
            if not web_cap_logged:
                web_cap_logged = True
                ctx.log(
                    f"Deep web checks limited to {web_budget} service(s); "
                    "remaining web ports were fingerprinted only",
                    "warning",
                )
            continue
        web_checked += 1
        url, response, body = service
        try:
            pages_crawled = _web_vulnerability_checks(result, ctx, url, response, body)
            for service_meta in result.metadata.get("web_services", []):
                if service_meta.get("url") == url:
                    service_meta["pages_crawled"] = pages_crawled
                    break
        except ScanCancelled:
            raise
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

    # Nuclei network-protocol templates add signature coverage for SMB, RDP,
    # SSH, databases and similar non-HTTP services.
    if all_open and ctx.option_bool("nuclei_network", True):
        ctx.progress(84, "Running Nuclei network templates")
        try:
            from .nuclei import run_nuclei_network

            run_nuclei_network(
                result,
                [f"{item.host}:{item.port}" for item in all_open],
                ctx,
            )
        except ScanCancelled:
            raise
        except Exception as exc:
            ctx.log(f"Nuclei network templates failed: {exc}", "warning")

    # Nmap is optional and only used to enrich hosts with open services.
    nmap_hints: list[tuple[str, str]] = []
    if ctx.option_bool("external_tools", False):
        for host, items in open_by_host.items():
            if items and not ctx.cancelled():
                parsed = _run_nmap(result, host, sorted({p.port for p in items}), ctx)
                for item in parsed:
                    raw = item.get("raw") or {}
                    product = str(raw.get("product") or "").strip()
                    version = str(raw.get("version") or "").strip()
                    if product or version:
                        nmap_hints.append((item.get("location") or host, f"{product} {version}".strip()))

    # CVE matching: fingerprint detected services and compare versions with
    # the NVD database. This is what turns a port scan into a vulnerability
    # scan for unauthenticated network targets.
    web_headers: dict[tuple[str, int], dict[str, str]] = {}
    for service_meta in result.metadata.get("web_services", []):
        key = (str(service_meta.get("host") or ""), int(service_meta.get("port") or 0))
        web_headers[key] = {
            "server": str(service_meta.get("server") or ""),
            "powered_by": str(service_meta.get("powered_by") or ""),
        }
    if ctx.option_bool("cve_lookup", True):
        ctx.progress(86, "Matching service versions against CVE data")
        try:
            _run_cve_matching(
                result, ctx, all_open, web_headers, nmap_hints, service_banners
            )
        except ScanCancelled:
            raise
        except Exception as exc:
            ctx.log(f"CVE matching failed: {exc}", "warning")

    if ctx.option_bool("sqlmap", False):
        ctx.progress(87, "Running sqlmap (dangerous tools)")
        try:
            from .sqlmap import run_sqlmap

            run_sqlmap(result, result.metadata.get("param_urls", []), ctx)
        except ScanCancelled:
            raise
        except Exception as exc:
            ctx.log(f"sqlmap stage failed: {exc}", "warning")

    # Greenbone/OpenVAS: optional external feed-based engine.
    if ctx.option_bool("openvas", False):
        ctx.progress(88, "Running OpenVAS engine (optional)")
        try:
            default_openvas_budget = int(setting_or_default("max_openvas_hosts", "5"))
        except (TypeError, ValueError):
            default_openvas_budget = 5
        openvas_budget = _bounded_int(
            ctx.option("max_openvas_hosts", default_openvas_budget),
            default_openvas_budget,
            1,
            50,
        )
        openvas_checked = 0
        from .openvas import run_openvas

        for host, items in open_by_host.items():
            if not items or ctx.cancelled():
                continue
            if openvas_checked >= openvas_budget:
                ctx.log(f"OpenVAS limited to {openvas_budget} host(s)", "warning")
                break
            openvas_checked += 1
            try:
                run_openvas(result, host, ctx)
            except ScanCancelled:
                raise
            except Exception as exc:
                ctx.log(f"OpenVAS engine failed on {host}: {exc}", "warning")

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
    if ctx.option_bool("cve_lookup", True) and ports:
        ctx.progress(70, "Matching agent service banners against CVE data")
        try:
            _run_cve_matching(result, ctx, ports, {}, [], {})
        except ScanCancelled:
            raise
        except Exception as exc:
            ctx.log(f"Agent CVE matching failed: {exc}", "warning")
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
