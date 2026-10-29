"""Host auto-discovery via TCP probes and continuous inventory tracking."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import logging
import re
import socket
import time
from typing import Any

from .config import MAX_CIDR_HOSTS, get_limit
from .database import json_dump, transaction, utcnow

logger = logging.getLogger("discovery")

PORT_INDICATORS = [22, 80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443]
VERSION_SNIFFERS = [
    ("SSH", ["SSH-2.0-"]),
    ("OpenSSH", ["SSH-"]),
    ("Redis", ["redis_"]),
    ("MySQL", ["mysql"]),
    ("PostgreSQL", ["postgresql"]),
    ("Kubernetes", ["Kubernetes"]),
    ("Docker", ["Docker"]),
    ("iSCSI", ["iSCSI"]),
    ("LDAP", ["2696"]),
    ("SMTP", ["SMTP"]),
    ("HTTPS", []),
    ("HTTP", []),
]

OS_SIGNATURES = {
    "linux": ["Linux"],
    "windows": ["Windows"],
    "mac": ["Darwin"],
    "ios": ["iPhone", "iPad"],
    "android": ["Android"],
}

DEVICE_TYPE_MAP = {
    "windows": "Windows",
    "linux": "Linux Server",
    "mac": "MacOS",
    "ios": "iOS",
    "android": "Android",
}


def discover_hosts(
    subnet: str | None = None,
    custom_ports: str | None = None,
    timeout: float = 1.5,
    workers: int = 100,
) -> list[dict[str, Any]]:
    """Auto-discover hosts on a subnet by probing well-known ports.

    Returns a list of discovered host/service records. This is a discovery
    helper; callers decide whether to persist them with
    :func:`create_inventory_entry`.
    """
    if not subnet:
        raise ValueError("A subnet is required")

    probes: list[tuple[int, int]] = []
    if custom_ports:
        for item in custom_ports.split(","):
            item = item.strip()
            if not item:
                continue
            try:
                port = int(item)
            except ValueError:
                continue
            if 1 <= port <= 65535:
                probes.append((port, port))
    if not probes:
        probes = [(port, port) for port in PORT_INDICATORS]

    host_list = _expand_subnet(subnet, get_limit("max_cidr_hosts", MAX_CIDR_HOSTS))
    if not host_list:
        return []

    total_probes = len(host_list) * len(probes)
    if total_probes <= 0:
        return []
    discovered: list[dict[str, Any]] = []
    max_workers = max(1, min(int(workers or 100), total_probes, 512))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {
            executor.submit(_probe_one, host, port, timeout): host
            for host in host_list
            for _port, port in probes
        }
        for future in concurrent.futures.as_completed(future_to_host):
            try:
                result = future.result()
            except Exception as exc:
                logger.warning("Probe failed for %s: %s", future_to_host[future], exc)
                continue
            if result:
                discovered.append(result)

    logger.info(
        "Discovered %d service(s) across %d host(s) on subnet %s",
        len(discovered),
        len(host_list),
        subnet,
    )
    return discovered


def _expand_subnet(subnet: str, max_hosts: int) -> list[str]:
    """Expand a CIDR subnet to individual IPs."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid subnet: {subnet}") from exc
    if net.num_addresses > max_hosts:
        raise ValueError(f"Subnet {subnet} has too many hosts ({net.num_addresses})")
    if net.num_addresses == 1:
        return [str(net.network_address)]
    return [str(ip) for ip in net.hosts()]


def _probe_one(host: str, port: int, timeout: float) -> dict[str, Any] | None:
    """Probe one host:port and detect open service version."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            banner = _fetch_banner(sock, port, timeout)
            service = _match_service(port, banner)
        return {"host": host, "port": port, "service": service, "banner": banner}
    except (OSError, socket.timeout):
        return None


def _fetch_banner(sock: socket.socket, port: int, timeout: float) -> str:
    try:
        if port in {25, 110, 143, 587}:
            sock.sendall(b"\r\n\r\n")
        time.sleep(0.05)
        data = sock.recv(1024).decode("utf-8", errors="replace").strip()
        return data[:256]
    except Exception:
        return ""


def _match_service(port: int, banner: str) -> dict[str, Any]:
    """Detect service name and OS from banner text."""
    services: list[str] = []
    lowered = banner.lower()

    for name, patterns in VERSION_SNIFFERS:
        for pattern in patterns:
            if pattern.lower() in lowered:
                services.append(name)
                break

    os_guess = ""
    for os_type, patterns in OS_SIGNATURES.items():
        if any(pattern.lower() in lowered for pattern in patterns):
            os_guess = os_type.upper()
            break

    return {"services": services, "os": os_guess}


def _default_group(conn: Any, customer_id: int) -> int:
    row = conn.execute(
        "SELECT id FROM asset_groups WHERE customer_id = ? ORDER BY id LIMIT 1",
        (customer_id,),
    ).fetchone()
    if row:
        return int(row["id"])
    return int(
        conn.execute(
            "INSERT INTO asset_groups(customer_id, name, description, created_at) "
            "VALUES (?, 'General', 'Default asset group', ?)",
            (customer_id, utcnow()),
        ).lastrowid
    )


def create_inventory_entry(
    scan_id: int,
    customer_id: int | None,
    asset_id: int | None,
    host: str,
    port: int,
    service: dict[str, Any],
) -> dict[str, Any]:
    """Insert or update an asset inventory entry from a discovered host."""
    host = (host or "").strip()
    if not host:
        raise ValueError("A discovered host is required")
    service = service if isinstance(service, dict) else {}
    now_str = utcnow()

    with transaction() as conn:
        row = conn.execute(
            "SELECT * FROM asset_inventory WHERE ip_address = ? AND scan_id = ?",
            (host, scan_id),
        ).fetchone()

        if row:
            ports = []
            try:
                ports = json.loads(row["ports"] or "[]")
            except (TypeError, ValueError):
                ports = []
            if port not in ports:
                ports.append(port)
            conn.execute(
                "UPDATE asset_inventory SET last_seen = ?, status = 'active', "
                "ports = ?, hostname = COALESCE(NULLIF(hostname, ''), ?), "
                "asset_id = COALESCE(asset_id, ?) WHERE id = ?",
                (now_str, json_dump(ports), host, asset_id, row["id"]),
            )
            return _build_result({**dict(row), "ports": ports}, port)

        hostname = host
        device_type = DEVICE_TYPE_MAP.get(
            _guess_os_from_service(service.get("os", "")), "Unknown Device"
        )
        mac_guess = _guess_mac_from_service(service)
        new_asset_id = asset_id

        if new_asset_id is None and customer_id is not None:
            existing = conn.execute(
                "SELECT id FROM assets WHERE customer_id = ? "
                "AND (identifier = ? OR name = ?) LIMIT 1",
                (customer_id, host, host),
            ).fetchone()
            if existing:
                new_asset_id = int(existing["id"])
            else:
                group_id = _default_group(conn, customer_id)
                new_asset_id = int(
                    conn.execute(
                        "INSERT INTO assets("
                        "customer_id, group_id, name, kind, identifier, description, "
                        "metadata, created_at"
                        ") VALUES (?, ?, ?, 'network', ?, '', '{}', ?)",
                        (customer_id, group_id, host, host, now_str),
                    ).lastrowid
                )

        conn.execute(
            "INSERT INTO asset_inventory("
            "scan_id, asset_id, customer_id, ip_address, hostname, mac_address, "
            "device_type, ports, os_guess, first_seen, last_seen, status"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')",
            (
                scan_id,
                new_asset_id,
                customer_id,
                host,
                hostname,
                mac_guess,
                device_type,
                json_dump([port]),
                service.get("os", ""),
                now_str,
                now_str,
            ),
        )
        return _build_result({"asset_id": new_asset_id, "ip_address": host, "hostname": hostname}, port)


def _guess_os_from_service(os_str: str) -> str:
    for os_type in ("linux", "windows", "mac"):
        if os_type.upper() in (os_str or "").upper():
            return os_type
    return "unknown"


def _guess_mac_from_service(service: dict[str, Any]) -> str:
    mac = ""
    banner = service.get("banner", "") or ""
    mac_match = re.search(
        r"(?:MAC|Address)\s*:\s*([0-9a-fA-F:]{17})", banner, re.IGNORECASE
    )
    if mac_match:
        mac = mac_match.group(1).upper().replace("-", ":")
    else:
        mac_match = re.search(
            r"[0-9a-fA-F]{8}:[0-9a-fA-F]{4}:[0-9a-fA-F]{4}:[0-9a-fA-F]{12}",
            banner,
        )
        if mac_match:
            mac = mac_match.group(0).upper().replace(":", "-")
    return mac


def _build_result(row: dict[str, Any], port: int) -> dict[str, Any]:
    return {
        "ip": row.get("ip_address", ""),
        "hostname": row.get("hostname", ""),
        "device_type": row.get("device_type", "Unknown"),
        "os_guess": row.get("os_guess", ""),
        "port": port,
    }


def track_historical_findings(
    scan_id: int,
    asset_id: int | None,
    findings: list[dict[str, Any]],
) -> None:
    """Save finding history rows for trend analysis across scans of same asset."""
    if not findings or not asset_id:
        return

    with transaction() as conn:
        for finding in findings:
            fingerprint = finding.get("fingerprint") or (
                f"{finding.get('category', '')}:{finding.get('title', '')}"
            )
            severity = finding.get("severity", "info")
            first_seen = str(finding.get("first_seen") or utcnow())
            last_seen = str(finding.get("last_seen") or first_seen)
            row = conn.execute(
                "SELECT id, count FROM finding_history WHERE asset_id = ? AND fingerprint = ?",
                (asset_id, fingerprint),
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE finding_history SET last_seen = ?, last_seen_scan_id = ?, "
                    "severity_at_last = ?, status_at_last = ?, count = ? WHERE id = ?",
                    (
                        last_seen,
                        scan_id,
                        severity,
                        finding.get("status", "open"),
                        int(row["count"]) + 1,
                        row["id"],
                    ),
                )
            else:
                conn.execute(
                    "INSERT INTO finding_history("
                    "asset_id, fingerprint, first_seen_scan_id, last_seen_scan_id, "
                    "severity_at_first, severity_at_last, status_at_first, status_at_last, "
                    "first_seen, last_seen, count"
                    ") VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, 1)",
                    (
                        asset_id,
                        fingerprint,
                        scan_id,
                        scan_id,
                        severity,
                        severity,
                        finding.get("status", "open"),
                        first_seen,
                        last_seen,
                    ),
                )
