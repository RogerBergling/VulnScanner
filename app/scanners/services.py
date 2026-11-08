"""Built-in network service security probes.

Active but non-destructive checks for common insecure service configurations:
unauthenticated Redis/MongoDB/Elasticsearch/Docker/Memcached, default SNMP
communities, SMB signing/SMBv1, RDP NLA support and VNC authentication. Every
probe only reads; no write command is ever sent.

Pure parsers are separated from the socket code so tests can exercise the
protocol logic offline.
"""

from __future__ import annotations

import concurrent.futures
import re
import socket
import struct
from typing import Any

import requests

from ..config import tls_ca_bundle
from ..utils import truncate
from .base import Finding, ScanContext, ScanResult

PROBE_TIMEOUT = 3.0

# ---------------------------------------------------------------------------
# Pure parsers and builders
# ---------------------------------------------------------------------------


def parse_redis_info(data: bytes) -> dict[str, str]:
    """Parse a Redis INFO response into a key/value mapping."""
    info: dict[str, str] = {}
    text = data.decode("utf-8", errors="replace")
    if not text.strip().startswith("#") and "redis_version" not in text:
        return info
    for line in text.splitlines():
        if ":" in line and not line.strip().startswith("#"):
            key, _, value = line.partition(":")
            info[key.strip()] = value.strip()
    return info


def parse_memcached_version(data: bytes) -> str:
    for line in data.decode("utf-8", errors="replace").splitlines():
        if line.upper().startswith("STAT VERSION "):
            return line.split(" ", 2)[-1].strip()
    return ""


def parse_mongo_is_master(data: bytes) -> dict[str, Any]:
    """Parse a minimal isMaster reply. The last bytes are the BSON document."""
    if len(data) < 36:
        return {}
    try:
        message_length = struct.unpack_from("<I", data, 0)[0]
    except struct.error:
        return {}
    if message_length <= 0 or message_length > len(data) + 4:
        return {}
    payload = data[:message_length]
    if len(payload) < 36:
        return {}
    # OP_REPLY header: length(4) requestId(4) responseTo(4) opcode(4)
    # flags(4) cursorId(8) startingFrom(4) numberReturned(4) = 36 bytes,
    # followed by the BSON documents.
    document = payload[36:]
    # The reply document for isMaster is text-searchable for version fields.
    text = document.decode("utf-8", errors="replace")
    info: dict[str, Any] = {}
    version = re.search(r'"version"\s*:\s*"([^"]+)"', text)
    if version:
        info["version"] = version.group(1)
    for key in ("maxWireVersion", "ok", "ismaster", "isWritablePrimary"):
        match = re.search(rf'"{key}"\s*:\s*([0-9.]+)', text)
        if match:
            try:
                info[key] = float(match.group(1))
            except ValueError:
                info[key] = match.group(1)
    info["_text"] = truncate(text, 300)
    return info


def build_snmp_get(community: str, oid: str = "1.3.6.1.2.1.1.1.0") -> bytes:
    """Build an SNMPv1/v2c GET request for the given OID."""
    oid_bytes = _encode_oid(oid)
    # version 0x01, community, PDU GetRequest (0xA0)
    version = b"\x02\x01\x01"
    community_field = b"\x04" + bytes([len(community)]) + community.encode()
    request_id = b"\x02\x01\x01"
    error_status = b"\x02\x01\x00"
    error_index = b"\x02\x01\x00"
    varbind = b"\x30" + bytes([len(oid_bytes) + 2]) + b"\x06" + bytes([len(oid_bytes)]) + oid_bytes + b"\x05\x00"
    varbind_list = b"\x30" + bytes([len(varbind)]) + varbind
    pdu = b"\xa0" + bytes([len(request_id + error_status + error_index + varbind_list)]) + request_id + error_status + error_index + varbind_list
    body = version + community_field + pdu
    return b"\x30" + bytes([len(body)]) + body


def _encode_oid(oid: str) -> bytes:
    parts = [int(part) for part in oid.split(".")]
    encoded = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        while part >= 0x80:
            part >>= 7
            chunk.append(0x80 | (part & 0x7F))
        encoded += bytes(reversed(chunk))
    return encoded


def _read_length(data: bytes, index: int) -> tuple[int, int]:
    """Read a BER length starting at ``index``; return (length, next_index)."""
    if index >= len(data):
        raise ValueError("truncated BER length")
    first = data[index]
    if first < 0x80:
        return first, index + 1
    count = first & 0x7F
    if count == 0 or index + 1 + count > len(data):
        raise ValueError("invalid BER length")
    value = int.from_bytes(data[index + 1:index + 1 + count], "big")
    return value, index + 1 + count


def _walk_tlvs(data: bytes, start: int, end: int) -> str | None:
    """Depth-first TLV walk; return the first octet-string payload."""
    index = start
    constructed = {0x24, 0x30, 0x80, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}
    while index + 2 <= end:
        tag = data[index]
        length, next_index = _read_length(data, index + 1)
        if next_index + length > end:
            return None
        if tag == 0x04:
            value = data[next_index:next_index + length]
            try:
                text = value.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                text = value.decode("latin-1", errors="replace")
            return truncate(text, 400) if text.strip() else None
        if tag in constructed:
            found = _walk_tlvs(data, next_index, next_index + length)
            if found is not None:
                return found
        index = next_index + length
    return None


def parse_snmp_response(data: bytes) -> str | None:
    """Extract the first varbind value (sysDescr) from an SNMPv1/v2 response."""
    try:
        index = 0
        if not data or data[index] != 0x30:
            return None
        _length, index = _read_length(data, index + 1)
        if index >= len(data) or data[index] != 0x02:  # version
            return None
        _length, index = _read_length(data, index + 1)
        index += _length
        if index >= len(data) or data[index] != 0x04:  # community
            return None
        length, index = _read_length(data, index + 1)
        index += length
        if index >= len(data) or data[index] not in (0xA2, 0xA4):  # response PDU
            return None
        _length, index = _read_length(data, index + 1)
        return _walk_tlvs(data, index, min(index + _length, len(data)))
    except (ValueError, IndexError):
        return None


def build_smb2_negotiate() -> bytes:
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    body = (
        struct.pack("<HHI", 36, len(dialects), 1)  # StructureSize, DialectCount, SecurityMode(signing enabled)
        + b"\x00" * 16  # Reserved(2) + Capabilities(4) + ClientGuid first 10 of 16
        + b"\x00" * 6  # rest of ClientGuid
        + b"\x00" * 8  # ClientStartTime
        + b"".join(struct.pack("<H", dialect) for dialect in dialects)
    )
    header = (
        b"\xfeSMB"
        + struct.pack("<H", 64)  # StructureSize
        + struct.pack("<H", 0)  # CreditCharge
        + struct.pack("<I", 0)  # Status
        + struct.pack("<H", 0)  # Command: NEGOTIATE
        + struct.pack("<H", 0)  # Credits requested
        + struct.pack("<I", 0)  # Flags
        + struct.pack("<I", 0)  # NextCommand
        + struct.pack("<Q", 1)  # MessageId
        + struct.pack("<I", 0)  # Reserved
        + struct.pack("<I", 0)  # TreeId
        + struct.pack("<Q", 0)  # SessionId
        + b"\x00" * 16  # Signature
    )
    packet = header + body
    return struct.pack(">I", len(packet)) + packet


def parse_smb2_negotiate_response(data: bytes) -> dict[str, Any] | None:
    """Return signing/SMB1 info from an SMB2 NEGOTIATE response."""
    if len(data) < 4 + 64 + 4:
        return None
    # Skip the 4-byte netbios length, then the 64-byte SMB2 header.
    header = data[4:4 + 64]
    if header[:4] != b"\xfeSMB":
        return None
    status = struct.unpack_from("<I", header, 8)[0]
    body = data[4 + 64:]
    structure_size = struct.unpack_from("<H", body, 0)[0]
    if structure_size < 9:
        return None
    security_mode = struct.unpack_from("<H", body, 2)[0]
    return {
        "status": status,
        "signing_enabled": bool(security_mode & 0x01),
        "signing_required": bool(security_mode & 0x02),
        "security_mode": security_mode,
    }


def parse_vnc_security_types(data: bytes) -> list[int]:
    """Parse the VNC server security-type list: count byte + types."""
    if not data:
        return []
    count = data[0]
    types = list(data[1:1 + count])
    return types


VNC_AUTH_NAMES = {
    1: "None (no authentication)",
    2: "VNC password",
    16: "Tight",
    17: "Ultra",
    18: "TLS",
    19: "VeNCrypt",
    30: "Apple Remote Desktop",
}


def parse_rdp_negotiation(data: bytes) -> dict[str, Any] | None:
    """Parse an RDP Negotiation Response/Failure embedded in an X.224 CC TPDU.

    Returns the selected protocol (2 = TLS/NLA hybrid, 1 = SSL, 0 = RDP) or a
    failure record. Returns None when the server sent plain RDP security or
    the payload is not recognisable.
    """
    # The probe passes the raw TPKT frame; skip its 4-byte header.
    if len(data) >= 4 and data[0] == 0x03:
        data = data[4:]
    if len(data) < 8 or data[1] != 0xD0:  # CC TPDU type byte
        return None
    # Layout after the X.224 length byte:
    #   [0] len indicator, [1] type 0xD0, [2:4] dst ref, [4:6] src ref,
    #   [6] class, [7] negotiation structure type.
    neg_type = data[7]
    if neg_type == 0x02 and len(data) >= 12:  # Negotiation Response
        flags = data[8]
        selected = struct.unpack_from("<I", data, 11)[0]
        return {"failure": False, "selected_protocol": selected, "flags": flags}
    if neg_type == 0x03 and len(data) >= 12:  # Negotiation Failure
        failure_code = struct.unpack_from("<I", data, 11)[0]
        return {"failure": True, "failure_code": failure_code}
    return None


RDP_PROTOCOL_NAMES = {0: "RDP", 1: "SSL/TLS", 2: "CredSSP/NLA (hybrid)"}

# ---------------------------------------------------------------------------
# Socket probes
# ---------------------------------------------------------------------------


def _tcp_exchange(host: str, port: int, payload: bytes | None, read_bytes: int,
                  timeout: float) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        if payload is not None:
            sock.sendall(payload)
        chunks = []
        try:
            chunk = sock.recv(min(read_bytes, 8192))
            if chunk:
                chunks.append(chunk)
                # One short follow-up read to catch multi-packet replies.
                try:
                    sock.settimeout(min(timeout, 0.6))
                    tail = sock.recv(min(max(0, read_bytes - len(chunk)), 8192))
                    if tail:
                        chunks.append(tail)
                except socket.timeout:
                    pass
        except socket.timeout:
            pass
        return b"".join(chunks)


def probe_redis(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> dict[str, Any] | None:
    data = _tcp_exchange(host, port, b"INFO\r\n", 4096, timeout)
    info = parse_redis_info(data)
    if not info:
        return None
    return {
        "version": info.get("redis_version", ""),
        "unauthenticated": True,
        "banner": f"redis_version:{info.get('redis_version', '')}",
        "info": info,
    }


def probe_memcached(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> dict[str, Any] | None:
    data = _tcp_exchange(host, port, b"stats\r\n", 4096, timeout)
    version = parse_memcached_version(data)
    if not data.strip():
        return None
    return {
        "version": version,
        "unauthenticated": True,
        "banner": f"STAT version {version}".strip(),
    }


def probe_mongodb(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> dict[str, Any] | None:
    # OP_QUERY isMaster on admin.$cmd (legacy handshake still answered by
    # modern servers that accept it).
    query = (
        b"\x10\x00\x00\x00"  # message length placeholder (16)
        b"\x00\x00\x00\x00"  # request id
        b"\x00\x00\x00\x00"  # response to
        b"\xd4\x07\x00\x00"  # OP_QUERY
        b"\x00\x00\x00\x00"  # flags
        b"admin.$cmd\x00"
        b"\x00\x00\x00\x00"  # skip
        b"\xff\xff\xff\xff"  # return
        b'\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00'
    )
    data = _tcp_exchange(host, port, query, 2048, timeout)
    info = parse_mongo_is_master(data)
    if not info or "_text" not in info:
        return None
    if "version" not in info and "ok" not in info and "ismaster" not in info and "isWritablePrimary" not in info:
        return None
    return {
        "version": info.get("version", ""),
        "unauthenticated": True,
        "banner": f'"version":"{info.get("version", "")}"',
        "info": info,
    }


def _http_get_json(host: str, port: int, path: str, timeout: float,
                   https: bool = False, verify: bool | str = True) -> dict[str, Any] | None:
    scheme = "https" if https else "http"
    try:
        response = requests.get(
            f"{scheme}://{host}:{port}{path}",
            timeout=timeout,
            verify=verify,
            headers={"User-Agent": "VulnScanner/1.0 (service probe)"},
        )
    except requests.RequestException:
        return None
    if response.status_code != 200:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def probe_elasticsearch(host: str, port: int, timeout: float = PROBE_TIMEOUT,
                        verify: bool | str = True) -> dict[str, Any] | None:
    data = _http_get_json(host, port, "/", timeout, verify=verify)
    if not isinstance(data, dict) or "version" not in data:
        return None
    version = data.get("version", {})
    number = version.get("number", "") if isinstance(version, dict) else str(version)
    if not number and "tagline" not in data:
        return None
    return {
        "version": number,
        "unauthenticated": True,
        "banner": f'"number":"{number}"',
        "info": data,
    }


def probe_kibana(host: str, port: int, timeout: float = PROBE_TIMEOUT,
                 verify: bool | str = True) -> dict[str, Any] | None:
    data = _http_get_json(host, port, "/api/status", timeout, verify=verify)
    if not isinstance(data, dict) or "name" not in data:
        return None
    version = data.get("version", {})
    number = version.get("number", "") if isinstance(version, dict) else ""
    return {
        "version": number,
        "unauthenticated": True,
        "banner": f'"name":"{data.get("name", "kibana")}" "number":"{number}"',
        "info": data,
    }


def probe_docker(host: str, port: int, timeout: float = PROBE_TIMEOUT,
                 https: bool = False, verify: bool | str = True) -> dict[str, Any] | None:
    data = _http_get_json(host, port, "/version", timeout, https=https, verify=verify)
    if not isinstance(data, dict) or "Version" not in data:
        return None
    return {
        "version": str(data.get("Version") or ""),
        "unauthenticated": True,
        "banner": f'"Version":"{data.get("Version", "")}"',
        "info": data,
    }


def probe_snmp(host: str, port: int, community: str, timeout: float = 1.5) -> str | None:
    request = build_snmp_get(community)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(request, (host, port))
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                return None
    except OSError:
        return None
    return parse_snmp_response(data)


def probe_smb_signing(host: str, port: int = 445, timeout: float = PROBE_TIMEOUT) -> dict[str, Any] | None:
    request = build_smb2_negotiate()
    data = _tcp_exchange(host, port, request, 8192, timeout)
    return parse_smb2_negotiate_response(data)


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining > 0:
        chunk = sock.recv(min(remaining, 8192))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def probe_vnc(host: str, port: int = 5900, timeout: float = PROBE_TIMEOUT) -> dict[str, Any] | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            version_data = _recv_exact(sock, 12)
            if len(version_data) < 12 or not version_data.startswith(b"RFB "):
                return None
            version = version_data[:12].decode("ascii", errors="replace").strip()
            sock.sendall(version_data[:12])
            count_byte = _recv_exact(sock, 1)
            if not count_byte:
                return None
            count = count_byte[0]
            types_data = _recv_exact(sock, count)
    except (OSError, socket.timeout):
        return None
    security_types = list(types_data)
    return {
        "version": version,
        "security_types": security_types,
        "no_authentication": 1 in security_types,
        "type_names": [VNC_AUTH_NAMES.get(t, f"type {t}") for t in security_types],
    }


def probe_rdp_nla(host: str, port: int = 3389, timeout: float = PROBE_TIMEOUT) -> dict[str, Any] | None:
    # X.224 Connection Request with RDP Negotiation Request (SSL+NLA hybrid).
    payload = bytes.fromhex(
        "0300002b"  # TPKT
        "25"        # X.224 length
        "e0"        # CR TPDU
        "0000" "0000" "00"  # dst ref, src ref, class
        "01"        # RDP negotiation request
        "00"        # flags
        "0800"      # length
        "03000000"  # requested protocols: SSL | NLA hybrid
    )
    data = _tcp_exchange(host, port, payload, 1024, timeout)
    if not data:
        return None
    negotiation = parse_rdp_negotiation(data)
    if negotiation:
        return negotiation
    # Fall back: report that the server used legacy RDP security (no NLA).
    return {"failure": False, "selected_protocol": 0, "legacy": True}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

PROBE_TARGETS: dict[int, tuple[str, Any]] = {
    6379: ("probe_redis", {}),
    11211: ("probe_memcached", {}),
    27017: ("probe_mongodb", {}),
    9200: ("probe_elasticsearch", {}),
    5601: ("probe_kibana", {}),
    2375: ("probe_docker", {"https": False}),
    2376: ("probe_docker", {"https": True}),
    445: ("probe_smb", {}),
    5900: ("probe_vnc", {}),
    3389: ("probe_rdp", {}),
}

MAX_SNMP_HOSTS = 64


def _snmp_pass(result: ScanResult, hosts: list[str]) -> None:
    """Probe UDP 161 for default communities. TCP scans cannot see UDP."""
    hosts = hosts[:MAX_SNMP_HOSTS]
    if not hosts:
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        futures = {
            executor.submit(probe_snmp, host, 161, "public"): ("public", host)
            for host in hosts
        }
        futures.update({
            executor.submit(probe_snmp, host, 161, "private"): ("private", host)
            for host in hosts
        })
        for future in concurrent.futures.as_completed(futures):
            community, host = futures[future]
            try:
                descr = future.result()
            except Exception:
                continue
            if not descr:
                continue
            if community == "public":
                _add_finding(
                    result,
                    "medium",
                    f"SNMP responds to the default community 'public' on {host}:161",
                    f"snmp-public:{host}:161",
                    "The default read community string 'public' exposes system information to anyone who can reach the service.",
                    f"SysDescr: {descr}",
                    "Remove or restrict SNMP, use SNMPv3 with authentication, and change community strings.",
                    "CWE-200",
                    f"{host}:161",
                )
            else:
                _add_finding(
                    result,
                    "high",
                    f"SNMP responds to the default community 'private' on {host}:161",
                    f"snmp-private:{host}:161",
                    "The default read-write community string 'private' is in use, which often grants full write access to device configuration.",
                    f"SysDescr: {descr}",
                    "Change the community string immediately, restrict access, or move to SNMPv3.",
                    "CWE-798",
                    f"{host}:161",
                )


def run_service_probes(
    result: ScanResult,
    ctx: ScanContext,
    open_by_host: dict[str, list[Any]],
) -> dict[tuple[str, int], str]:
    """Run active service probes for known insecure-service ports.

    Returns {（host, port): banner_text} so the CVE stage can fingerprint the
    actively collected versions as well.
    """
    extra_banners: dict[tuple[str, int], str] = {}
    total = sum(len(items) for items in open_by_host.values())
    done = 0
    verify: bool | str = False if ctx.option_bool("ignore_tls_errors", False) else (
        tls_ca_bundle() or True
    )
    http_probes = {"probe_elasticsearch", "probe_kibana", "probe_docker"}
    for host, items in open_by_host.items():
        for item in items:
            done += 1
            ctx.check_cancel()
            ctx.progress(60 + int(done / max(1, total) * 16), "Probing services")
            handler = PROBE_TARGETS.get(item.port)
            if not handler:
                continue
            name, kwargs = handler
            call_kwargs = dict(kwargs)
            if name in http_probes:
                call_kwargs["verify"] = verify
            try:
                probe = globals()[name]
                data = probe(host, item.port, **call_kwargs)
            except (OSError, requests.RequestException, socket.timeout):
                continue
            if not data:
                continue
            if data.get("banner"):
                extra_banners[(host, item.port)] = str(data["banner"])
            _findings_for_probe(result, name, host, item.port, data)
    ctx.log("Probing SNMP over UDP 161 for default communities")
    try:
        _snmp_pass(result, list(open_by_host.keys()))
    except Exception as exc:  # pragma: no cover - defensive
        ctx.log(f"SNMP probe pass failed: {exc}", "warning")
    return extra_banners


def _add_finding(
    result: ScanResult,
    severity: str,
    title: str,
    key: str,
    description: str,
    evidence: str,
    remediation: str,
    cwe: str,
    location: str,
) -> None:
    result.add(
        Finding(
            severity=severity,
            title=title,
            category="network",
            description=description,
            evidence=evidence,
            remediation=remediation,
            cwe=cwe,
            location=location,
            key=key,
        )
    )


def _findings_for_probe(result: ScanResult, name: str, host: str, port: int,
                        data: dict[str, Any]) -> None:
    location = f"{host}:{port}"
    if name == "probe_redis":
        _add_finding(
            result,
            "critical",
            f"Redis requires no authentication on {location}",
            f"redis-unauth:{location}",
            "The Redis server accepts commands without a password. Attackers can read and overwrite arbitrary data, and use Redis for further attacks.",
            f"Redis version: {data.get('version') or 'unknown'}",
            "Bind Redis to trusted interfaces, set requirepass, and disable dangerous commands.",
            "CWE-306",
            location,
        )
    elif name == "probe_memcached":
        _add_finding(
            result,
            "medium",
            f"Memcached accepts anonymous connections on {location}",
            f"memcached-open:{location}",
            "Memcached has no authentication by design; an exposed instance leaks cached data and can be abused for reflection attacks.",
            f"Memcached version: {data.get('version') or 'unknown'}",
            "Restrict Memcached to trusted networks and keep it off public interfaces.",
            "CWE-306",
            location,
        )
    elif name == "probe_mongodb":
        _add_finding(
            result,
            "critical",
            f"MongoDB requires no authentication on {location}",
            f"mongo-unauth:{location}",
            "The MongoDB instance answers isMaster without credentials. Attackers can read and modify every database.",
            f"MongoDB version: {data.get('version') or 'unknown'}",
            "Enable authentication, bind to trusted interfaces, and enable TLS.",
            "CWE-306",
            location,
        )
    elif name == "probe_elasticsearch":
        _add_finding(
            result,
            "critical",
            f"Elasticsearch requires no authentication on {location}",
            f"elastic-unauth:{location}",
            "The Elasticsearch API responds without credentials, exposing indices and cluster information and allowing data modification.",
            f"Elasticsearch version: {data.get('version') or 'unknown'}",
            "Enable Elasticsearch security (xpack.security), authentication and TLS, and restrict network access.",
            "CWE-306",
            location,
        )
    elif name == "probe_kibana":
        _add_finding(
            result,
            "medium",
            f"Kibana status is readable without authentication on {location}",
            f"kibana-open:{location}",
            "Kibana answers /api/status without credentials, exposing the Kibana/Elasticsearch version.",
            f"Kibana version: {data.get('version') or 'unknown'}",
            "Require authentication on Kibana and restrict access to trusted networks.",
            "CWE-200",
            location,
        )
    elif name == "probe_docker":
        _add_finding(
            result,
            "critical",
            f"Docker Engine API requires no authentication on {location}",
            f"docker-unauth:{location}",
            "The Docker API responds without authentication. Anyone who can reach it can create privileged containers and take over the host.",
            f"Docker version: {data.get('version') or 'unknown'}",
            "Never expose the Docker socket/API without TLS and client authentication.",
            "CWE-306",
            location,
        )
    elif name == "probe_smb":
        if not data.get("signing_enabled"):
            _add_finding(
                result,
                "high",
                f"SMB signing is disabled on {location}",
                f"smb-signing-disabled:{location}",
                "The SMB server has signing disabled entirely, so sessions are vulnerable to relay and tampering attacks.",
                f"SMB2 security mode: enabled={data.get('signing_enabled')}, required={data.get('signing_required')}",
                "Enable and require SMB signing on the server and all clients.",
                "CWE-319",
                location,
            )
        elif not data.get("signing_required"):
            _add_finding(
                result,
                "medium",
                f"SMB signing is optional on {location}",
                f"smb-signing-optional:{location}",
                "The SMB server supports signing but does not require it, enabling downgrade-based relay attacks.",
                f"SMB2 security mode: enabled={data.get('signing_enabled')}, required={data.get('signing_required')}",
                "Require SMB signing on the server and all clients.",
                "CWE-319",
                location,
            )
    elif name == "probe_vnc":
        if data.get("no_authentication"):
            _add_finding(
                result,
                "high",
                f"VNC offers connections without authentication on {location}",
                f"vnc-noauth:{location}",
                "The VNC server advertises the 'None' security type, so anyone can view or control the desktop without credentials.",
                f"VNC version: {data.get('version')}; offered types: {', '.join(data.get('type_names') or [])}",
                "Configure VNC to require a password or TLS authentication and restrict network access.",
                "CWE-306",
                location,
            )
        else:
            _add_finding(
                result,
                "info",
                f"VNC service detected on {location}",
                f"vnc-detected:{location}",
                "A VNC service was detected. Review who may connect to it.",
                f"VNC version: {data.get('version')}; offered types: {', '.join(data.get('type_names') or [])}",
                "Restrict VNC to trusted networks and require strong authentication.",
                "CWE-200",
                location,
            )
    elif name == "probe_rdp":
        if data.get("failure"):
            _add_finding(
                result,
                "medium",
                f"RDP on {location} does not support NLA (CredSSP)",
                f"rdp-no-nla:{location}",
                "The RDP server did not negotiate CredSSP/NLA, so credentials are exchanged before server authentication. This enables credential theft and downgrade attacks.",
                f"Negotiation failure code: {data.get('failure_code')}",
                "Require Network Level Authentication on the RDP server (System Properties → Remote → 'Allow connections only from computers running Remote Desktop with NLA').",
                "CWE-287",
                location,
            )
        elif data.get("selected_protocol", 0) != 2:
            _add_finding(
                result,
                "low",
                f"RDP on {location} negotiates legacy security (no NLA)",
                f"rdp-legacy:{location}",
                "The RDP server negotiated a legacy security protocol instead of CredSSP/NLA.",
                f"Selected protocol: {RDP_PROTOCOL_NAMES.get(data.get('selected_protocol', 0), 'unknown')}",
                "Require Network Level Authentication on the RDP server.",
                "CWE-287",
                location,
            )
