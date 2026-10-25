"""Host auto-discovery via TCP probes and continuous inventory tracking."""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
from datetime import datetime
from typing import Any

from .database import get_db, json_dump, utcnow
from .scanners.base import PortResult

logger = logging.getLogger("discovery")

PORT_INDICATORS = [22, 80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443]
VERSION_SNIFFERS = [
    ("SSH", ["SSH-2.0-"]),
    ("OpenSSH", ["SSH-" + "-"]),  # e.g. SSH-2.0-OpenSSH_8.9
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

# OS signature patterns for typing devices
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

    Returns a list of new inventory entries (with discovered host info).
    Uses standard library only — no external dependencies.
    """
    import concurrent.futures
    from .config import MAX_CIDR_HOSTS

    probes: list[tuple[int, int]] = []
    if custom_ports:
        for p in custom_ports.split(","):
            p = p.strip()
            if not p:
                continue
            try:
                probes.append((port := int(p), port))
            except ValueError:
                pass

    host_list = _expand_subnet(subnet, MAX_CIDR_HOSTS)
    discovered: list[dict[str, Any]] = []

    total_probes = len(host_list) * len(probes)
    succeeded = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, total_probes)) as executor:
        future_to_host = {}
        for host in host_list:
            for port in probes:
                future_to_host[executor.submit(_probe_one, host, port, timeout)] = host

        for future in concurrent.futures.as_completed(future_to_host):
            try:
                result = future.result()
                if result:
                    succeeded += 1
                    discovered.append(result)
            except Exception as exc:
                logger.warning("Probe failed for %s: %s", future_to_host[future], exc)

    logger.info("Discovered %d/%d hosts on subnet %s", succeeded, len(host_list), subnet or "?")
    return discovered


def _expand_subnet(subnet: str, max_hosts: int) -> list[str]:
    """Expand a CIDR subnet to individual IPs."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        if net.num_addresses > max_hosts:
            raise ValueError(f"Subnet {subnet} has too many hosts ({net.num_addresses})")
        ips = list(net.hosts()) if net.num_addresses <= max_hosts else list(net)[1:]
        return [str(ip) for ip in ips]
    except ValueError as exc:
        raise ValueError(str(exc)) from exc


def _probe_one(host: str, port: int, timeout: float) -> dict[str, Any] | None:
    """Probe one host:port and detect open service version."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.connect((host, port))
            banner = _fetch_banner(sock, port, timeout)
            service = _match_service(port, banner)
        return {"host": host, "port": port, "service": service, "banner": banner}
    except (OSError, socket.timeout, ConnectionRefusedError):
        return None


def _fetch_banner(sock: socket.socket, port: int, timeout: float) -> str:
    try:
        sock.sendall(b"\r\n\r\n")  # SMTP triggers server greeting; most just ignore
        time.sleep(0.1)
        data = sock.recv(1024).decode("utf-8", errors="replace").strip()
        return data[:256]
    except Exception:
        return ""


def _match_service(port: int, banner: str) -> str:
    """Detect service name and OS from banner text."""
    services = []
    lowered = banner.lower()

    for name, patterns in VERSION_SNIFFERS:
        for pat in patterns:
            if lowered.find(pat.lower()) >= 0:
                if pat == "SSH-2.0-":
                    services.append("SSH-2.0")
                else:
                    services.append(name)
                break

    os_guess = ""
    for os_type, patterns in OS_SIGNATURES.items():
        for pattern in patterns:
            if pattern.lower() in lowered:
                os_guess = os_type.upper()
                break

    hostname = _resolve_hostname(None)

    return {"services": services, "os": os_guess}


def _resolve_hostname(_unused: None) -> str:
    """Placeholder host resolution (not needed on localhost scans)."""
    import socket as s
    try:
        return s.gethostname() or "localhost"
    except Exception:
        return "unknown"


def create_inventory_entry(
    scan_id: int,
    customer_id: int | None,
    asset_id: int | None,
    host: str,
    port: int,
    service: dict[str, Any],
) -> dict[str, Any]:
    """Insert or update an asset inventory entry from a discovered host."""
    ip = f"{host}.{port}" if "." in host else host
    now_str = utcnow()

    with get_db() as conn:
        # Check if this IP already exists in inventory
        row = conn.execute(
            "SELECT * FROM asset_inventory WHERE ip_address = ? AND scan_id = ?",
            (ip, scan_id),
        ).fetchone()

        if row:
            update_fields = {"last_seen": now_str, "status": "active"}
            if row["hostname"]:
                update_fields["hostname"] = row["hostname"]
            conn.execute(
                f"UPDATE asset_inventory SET {', '.join(k + ' = ' + repr(v) for k, v in update_fields.items())}, "
                f"last_seen = ? WHERE id = ?",
                (now_str, row["id"]),
            )
            asset = conn.execute(
                "SELECT id FROM asset_inventory WHERE id = ?", (row["id"],)
            ).fetchone()
            return _build_result(dict(row), port)
        else:
            hostname = host
            mac = ""
            device_type = DEVICE_TYPE_MAP.get(_guess_os_from_service(service.get("os", "")), "Unknown Device")
            mac_guess = _guess_mac_from_service(service)
            conn.execute(
                "INSERT INTO asset_inventory("
                "scan_id, asset_id, customer_id, ip_address, hostname, mac_address, device_type, ports, os_guess, first_seen, last_seen, status"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    asset_id,
                    customer_id,
                    ip,
                    hostname,
                    mac_guess,
                    device_type,
                    json_dump([port]),
                    service.get("os", ""),
                    now_str,
                    now_str,
                    "active",
                ),
            )

            # Check if an asset with this identifier already exists
            existing_asset = None
            if host:
                existing_asset = conn.execute(
                    "SELECT * FROM assets WHERE identifier LIKE ? OR name LIKE ? LIMIT 1",
                    (f"%{host}%", f"%{host}%"),
                ).fetchone()

            new_asset_id = existing_asset["id"] if existing_asset else None
            if new_asset_id is None and customer_id is not None and asset_id is None:
                # Auto-create asset entry (no group match — orphaned but tracked)
                with transaction() as conn2:
                    cur = conn2.execute(
                        "INSERT INTO assets(customer_id, group_id, name, kind, identifier, description, metadata, created_at) VALUES (?, ?, ?, 'network', ?, '', '', ?)",
                        (customer_id, 0, host, now_str),
                    )
                    new_asset_id = cur.lastrowid
                    conn2.commit()

            return _build_result({"asset_id": new_asset_id}, port)


def _guess_os_from_service(os_str: str) -> str:
    for os_type in ("linux", "windows", "mac"):
        if os_type.upper() in (os_str or "").upper():
            return os_type
    return "unknown"


def _guess_mac_from_service(service: dict[str, Any]) -> str:
    mac = ""
    parts = service.get("banner", "") or ""
    mac_match = __import__("re").search(r"(?:MAC|Address)\s*:\s*([0-9a-fA-F:]{17})", parts, re.IGNORECASE)
    if mac_match:
        mac = mac_match.group(1).upper().replace("-", ":")
    elif parts:
        # Try NVIDIA MAC pattern
        mac_match2 = __import__("re").search(r"[0-9a-fA-F]{8}:[0-9a-fA-F]{4}:[0-9a-fA-F]{4}\:[0-9a-fA-F]{12}", parts)
        if mac_match2:
            mac = mac_match2.group(0).upper().replace(":", "-")
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
    if not findings:
        return

    with get_db() as conn:
        for finding in findings:
            fp = finding.get("fingerprint") or f"{finding.get('category', '')}:{finding.get('title', '')}"
            sev = finding.get("severity", "info")

            row = conn.execute(
                "SELECT * FROM finding_history WHERE fingerprint = ?", (fp,)
            ).fetchone()

            if row:
                updates = {
                    "last_seen": str(finding.get("first_seen", "")) or row["last_seen"],
                    "status_at_last": finding.get("status", row["status_at_last"]),
                    "severity_at_last": sev,
                    "count": row["count"] + 1,
                }
                if finding.get("scan_id"):
                    updates["last_seen_scan_id"] = finding["scan_id"]
                conn.execute(
                    "UPDATE finding_history SET ? WHERE fingerprint = ?",
                    (updates, fp),
                )
            else:
                conn.execute(
                    "INSERT INTO finding_history("
                    "asset_id, fingerprint, severity_at_first, severity_at_last, status_at_first, status_at_last, count, first_seen, last_seen"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        asset_id, fp, sev, sev, "open", "open", 1,
                        str(finding.get("first_seen", "")),
                        str(finding.get("first_seen", "")),
                    ),
                )
                if asset_id:
                    conn.execute(
                        "INSERT INTO assets(customer_id, group_id, name, kind, identifier, description, metadata, created_at) "
                        "VALUES (NULL, NULL, ?, 'host', ?, '', '{}', ?)",
                        (f"{fp}", str(finding.get("location", "")), str(finding.get("first_seen", ""))),
                    )
        conn.commit()
