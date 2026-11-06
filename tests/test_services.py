"""Tests for the built-in network service probe parsers (offline)."""

import socket
import struct
import threading

from app.scanners.services import (
    build_smb2_negotiate,
    build_snmp_get,
    parse_memcached_version,
    parse_mongo_is_master,
    parse_rdp_negotiation,
    parse_redis_info,
    parse_smb2_negotiate_response,
    parse_snmp_response,
    parse_vnc_security_types,
    probe_redis,
    probe_vnc,
)


def test_parse_redis_info():
    data = b"# Server\r\nredis_version:6.2.6\r\nredis_mode:standalone\r\n"
    info = parse_redis_info(data)
    assert info["redis_version"] == "6.2.6"
    assert info["redis_mode"] == "standalone"


def test_parse_redis_info_empty():
    assert parse_redis_info(b"-ERR unknown command\r\n") == {}


def test_parse_memcached_version():
    data = b"STAT pid 123\r\nSTAT version 1.5.22\r\nEND\r\n"
    assert parse_memcached_version(data) == "1.5.22"


def test_parse_mongo_is_master():
    doc = b'"version":"4.4.6","maxWireVersion":9.0,"ok":1.0'
    reply = (
        struct.pack("<I", 36 + len(doc))
        + b"\x00" * 8  # requestId + responseTo
        + struct.pack("<I", 1)  # OP_REPLY
        + b"\x00" * 20  # flags, cursor, startingFrom, numberReturned
        + doc
    )
    info = parse_mongo_is_master(reply)
    assert info["version"] == "4.4.6"
    assert info["ok"] == 1.0


def test_parse_mongo_short_reply():
    assert parse_mongo_is_master(b"short") == {}


def test_build_snmp_get_structure():
    request = build_snmp_get("public")
    assert request[:1] == b"\x30"  # SEQUENCE
    assert b"\x04\x06public" in request
    assert b"\xa0" in request  # GetRequest PDU
    assert b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00" in request  # sysDescr OID


def _snmp_response(sysdescr: bytes) -> bytes:
    def tlv(tag: int, value: bytes) -> bytes:
        if len(value) < 0x80:
            return bytes([tag, len(value)]) + value
        return bytes([tag, 0x81, len(value)]) + value

    varbind = tlv(0x30, tlv(0x06, bytes.fromhex("2b06010201010100")) + tlv(0x04, sysdescr))
    pdu = tlv(0xA2, tlv(0x02, b"\x01") + tlv(0x02, b"\x00") + tlv(0x02, b"\x00") + tlv(0x30, varbind))
    body = tlv(0x02, b"\x01") + tlv(0x04, b"public") + pdu
    return tlv(0x30, body)


def test_parse_snmp_response():
    response = _snmp_response(b"Linux router")
    assert parse_snmp_response(response) == "Linux router"


def test_parse_snmp_response_none():
    assert parse_snmp_response(b"\x30\x00") is None
    assert parse_snmp_response(b"garbage") is None


def _smb2_reply(security_mode: int) -> bytes:
    body = struct.pack("<HHHHI", 65, security_mode, 0x0311, 0, 0)
    header = (
        b"\xfeSMB"
        + struct.pack("<H", 64)
        + struct.pack("<H", 0)
        + struct.pack("<I", 0)  # STATUS_SUCCESS
        + struct.pack("<H", 0)
        + struct.pack("<H", 1)
        + struct.pack("<I", 1)  # server response flag
        + struct.pack("<I", 0)
        + struct.pack("<Q", 1)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + struct.pack("<Q", 0)
        + b"\x00" * 16
    )
    packet = header + body
    return struct.pack(">I", len(packet)) + packet


def test_parse_smb2_response_signing():
    required = parse_smb2_negotiate_response(_smb2_reply(0x03))
    assert required["signing_enabled"] is True
    assert required["signing_required"] is True
    optional = parse_smb2_negotiate_response(_smb2_reply(0x01))
    assert optional["signing_enabled"] is True
    assert optional["signing_required"] is False
    disabled = parse_smb2_negotiate_response(_smb2_reply(0x00))
    assert disabled["signing_enabled"] is False
    assert disabled["signing_required"] is False


def test_build_smb2_negotiate_shape():
    packet = build_smb2_negotiate()
    length = struct.unpack(">I", packet[:4])[0]
    assert length == len(packet) - 4
    assert packet[4:8] == b"\xfeSMB"


def test_parse_smb2_garbage():
    assert parse_smb2_negotiate_response(b"") is None
    assert parse_smb2_negotiate_response(b"not smb at all") is None


def test_parse_vnc_security_types():
    assert parse_vnc_security_types(b"\x01\x01") == [1]
    assert parse_vnc_security_types(b"\x02\x01\x02") == [1, 2]
    assert parse_vnc_security_types(b"") == []


def _rdp_cc(neg_struct: str) -> bytes:
    # TPKT header + X.224 CC TPDU containing the RDP negotiation structure.
    tpkt = bytes.fromhex("0300000b")
    cc = bytes.fromhex("0ad0" "0000" "0000" "00") + bytes.fromhex(neg_struct)
    return tpkt + cc


def test_parse_rdp_negotiation_response():
    data = _rdp_cc("02" "00" "0800" "02000000")
    result = parse_rdp_negotiation(data)
    assert result is not None
    assert result["failure"] is False
    assert result["selected_protocol"] == 2


def test_parse_rdp_negotiation_failure():
    data = _rdp_cc("03" "00" "0800" "05000000")
    result = parse_rdp_negotiation(data)
    assert result is not None
    assert result["failure"] is True
    assert result["failure_code"] == 5


def test_parse_rdp_plain_response():
    assert parse_rdp_negotiation(bytes.fromhex("030000050ad0")) is None
    assert parse_rdp_negotiation(b"") is None


class _ScriptedServer:
    """Serve a fixed byte response on a loopback port for one connection."""

    def __init__(self, respond: bytes):
        self._respond = respond
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
            with conn:
                conn.recv(4096)
                conn.sendall(self._respond)
        except OSError:
            pass

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc_info):
        self._sock.close()


def test_probe_redis_against_scripted_server():
    response = b"# Server\r\nredis_version:6.2.6\r\n"
    with _ScriptedServer(response) as server:
        result = probe_redis("127.0.0.1", server.port, timeout=2.0)
    assert result is not None
    assert result["unauthenticated"] is True
    assert result["version"] == "6.2.6"


class _VncServer:
    """Scripted RFB server: version first, then the security-type list."""

    def __init__(self, version: bytes, security_types: bytes):
        self._version = version
        self._types = security_types
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
            with conn:
                conn.sendall(self._version)
                conn.recv(32)  # client echoes its version
                conn.sendall(self._types)
        except OSError:
            pass

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc_info):
        self._sock.close()


def test_probe_vnc_against_scripted_server():
    with _VncServer(b"RFB 003.008\n", b"\x02\x01\x02") as server:
        result = probe_vnc("127.0.0.1", server.port, timeout=2.0)
    assert result is not None
    assert result["no_authentication"] is True
    assert 1 in result["security_types"]


def test_probe_vnc_requires_auth():
    with _VncServer(b"RFB 003.008\n", b"\x01\x02") as server:
        result = probe_vnc("127.0.0.1", server.port, timeout=2.0)
    assert result is not None
    assert result["no_authentication"] is False
