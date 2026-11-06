"""Distributed scanning: satellite VulnScanner servers.

A satellite is a second VulnScanner installation that polls this (master)
server over outbound HTTPS, exactly like an endpoint agent. The satellite
executes scan jobs from its own network position — typically a DMZ — and
uploads the findings; the master owns all data and shows everything in one
GUI.

Pairing flow:

1. The operator creates a one-time pairing code in the GUI.
2. The satellite enrolls with that code over HTTPS. The master issues a
   client certificate signed by the internal CA plus a long-lived bearer
   token, and stores the token hash and certificate fingerprint.
3. From then on the satellite polls with the bearer token (mandatory) and
   presents its client certificate (transport-level mTLS when the listener
   is configured with ``VS_SSL_CLIENT_CA``; otherwise the token plus the
   pinned fingerprint on every pairing is the authentication boundary).
"""

from __future__ import annotations

import hashlib
import ipaddress
import secrets
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .database import get_db, json_dump, json_load, utcnow
from .security import constant_time_equal, hash_token, new_agent_token

PAIRING_TTL_SECONDS = 3600
_pairings: dict[str, dict[str, Any]] = {}
_pairings_lock = threading.Lock()


def create_pairing(hours: int = 1) -> dict[str, Any]:
    """Create a one-time pairing code; return {code, expires_at}."""
    code = f"vs_pair_{secrets.token_urlsafe(24)}"
    expires = (datetime.now(timezone.utc) + timedelta(hours=max(1, min(hours, 24)))).isoformat()
    with _pairings_lock:
        now = time.monotonic()
        for key in [k for k, item in _pairings.items() if item["deadline"] < now]:
            _pairings.pop(key, None)
        _pairings[code] = {"deadline": time.monotonic() + PAIRING_TTL_SECONDS * max(1, min(hours, 24))}
    return {"code": code, "expires_at": expires}


def _consume_pairing(code: str) -> bool:
    with _pairings_lock:
        item = _pairings.pop(code, None)
        if item is None:
            return False
        return item["deadline"] >= time.monotonic()


def _cert_fingerprint(cert_pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem)
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _issue_satellite_certificate(satellite_id: str) -> tuple[bytes, bytes]:
    """Sign a satellite client certificate with the internal CA."""
    from .certs import (
        INTERNAL_CERT_FILE,
        INTERNAL_CA_KEY,
        _generate_internal_ca,
    )

    if not INTERNAL_CERT_FILE.is_file() or not INTERNAL_CA_KEY.is_file():
        _generate_internal_ca()
    ca_cert = x509.load_pem_x509_certificate(INTERNAL_CERT_FILE.read_bytes())
    ca_key = serialization.load_pem_private_key(INTERNAL_CA_KEY.read_bytes(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VulnScanner"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"satellite-{satellite_id[:12]}"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def register_satellite(pairing_code: str, name: str, hostname: str,
                       platform: str = "", version: str = "",
                       subnets: list[str] | None = None) -> dict[str, Any] | None:
    """Consume a pairing code and enroll a satellite. Returns None on failure."""
    if not _consume_pairing(pairing_code):
        return None
    satellite_id = f"sat_{uuid.uuid4().hex[:24]}"
    token = new_agent_token()
    cert_pem, key_pem = _issue_satellite_certificate(satellite_id)
    from .certs import INTERNAL_CERT_FILE, _generate_internal_ca

    if not INTERNAL_CERT_FILE.is_file():
        _generate_internal_ca()
    now = utcnow()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO satellites"
            "(id, name, hostname, platform, version, token_hash, cert_fingerprint, "
            "subnets, status, online, last_seen, enrolled_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 0, '', ?, ?)",
            (
                satellite_id,
                name or "",
                hostname or "",
                platform or "",
                version or "",
                hash_token(token),
                _cert_fingerprint(cert_pem),
                json_dump(subnets or []),
                now,
                now,
            ),
        )
        conn.commit()
    return {
        "satellite_id": satellite_id,
        "token": token,
        "client_cert": cert_pem.decode(),
        "client_key": key_pem.decode(),
        "ca_cert": INTERNAL_CERT_FILE.read_text(encoding="utf-8"),
    }


def authenticate_satellite(token: str) -> dict[str, Any] | None:
    """Resolve a satellite from its bearer token (hash-compared)."""
    if not token:
        return None
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM satellites WHERE status = 'active'"
        ).fetchall()
    for row in rows:
        if constant_time_equal(row["token_hash"], hash_token(token)):
            return dict(row)
    return None


def _public(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "hostname": row["hostname"],
        "platform": row["platform"],
        "version": row["version"],
        "subnets": json_load(row.get("subnets"), []),
        "status": row["status"],
        "online": bool(row["online"]),
        "last_seen": row["last_seen"],
        "enrolled_at": row["enrolled_at"],
    }


def list_satellites() -> list[dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM satellites WHERE status != 'revoked' ORDER BY name, hostname"
        ).fetchall()
    return [_public(dict(row)) for row in rows]


def get_satellite(satellite_id: str) -> dict[str, Any] | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM satellites WHERE id = ? AND status != 'revoked'",
            (satellite_id,),
        ).fetchone()
    return _public(dict(row)) if row else None


def update_satellite(satellite_id: str, *, name: str | None = None,
                     subnets: list[str] | None = None) -> dict[str, Any] | None:
    fields: list[str] = []
    values: list[Any] = []
    if name is not None:
        fields.append("name = ?")
        values.append(name.strip()[:160])
    if subnets is not None:
        cleaned = [str(item).strip() for item in subnets if str(item).strip()]
        fields.append("subnets = ?")
        values.append(json_dump(cleaned[:64]))
    if not fields:
        return get_satellite(satellite_id)
    fields.append("updated_at = ?")
    values.append(utcnow())
    values.append(satellite_id)
    with get_db() as conn:
        conn.execute(
            f"UPDATE satellites SET {', '.join(fields)} WHERE id = ?", values
        )
        conn.commit()
    return get_satellite(satellite_id)


def heartbeat(satellite_id: str, platform: str, version: str,
              subnets: list[str] | None = None) -> None:
    now = utcnow()
    fields = ["platform = ?", "version = ?", "online = 1", "last_seen = ?", "updated_at = ?"]
    values: list[Any] = [platform or "", version or "", now, now]
    if subnets is not None:
        fields.append("subnets = ?")
        values.append(json_dump([str(item).strip() for item in subnets if str(item).strip()][:64]))
    values.append(satellite_id)
    with get_db() as conn:
        conn.execute(f"UPDATE satellites SET {', '.join(fields)} WHERE id = ?", values)
        conn.commit()


def revoke_satellite(satellite_id: str) -> bool:
    now = utcnow()
    with get_db() as conn:
        conn.execute(
            "UPDATE satellites SET status = 'revoked', online = 0, updated_at = ? WHERE id = ?",
            (now, satellite_id),
        )
        conn.execute(
            "UPDATE satellite_jobs SET status = 'cancelled' WHERE satellite_id = ? "
            "AND status IN ('queued', 'running')",
            (satellite_id,),
        )
        rows = conn.execute(
            "SELECT scan_id FROM satellite_jobs WHERE satellite_id = ? "
            "AND status = 'cancelled'",
            (satellite_id,),
        ).fetchall()
        conn.commit()
    for row in rows:
        try:
            from .database import update_scan

            update_scan(
                int(row["scan_id"]),
                status="cancelled",
                stage="Cancelled (satellite revoked)",
                completed_at=utcnow(),
                error="The executing satellite was revoked",
            )
        except Exception:
            pass
    return True


def expire_stale_satellite_jobs(timeout_seconds: int) -> None:
    """Mark running satellite jobs whose satellite went silent as failed."""
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=timeout_seconds)).isoformat()
    with get_db() as conn:
        rows = conn.execute(
            "SELECT j.id, j.scan_id FROM satellite_jobs j "
            "WHERE j.status = 'running' AND j.claimed_at < ?",
            (cutoff,),
        ).fetchall()
        for row in rows:
            conn.execute(
                "UPDATE satellite_jobs SET status = 'failed', error = ?, completed_at = ? "
                "WHERE id = ?",
                ("Satellite timed out before uploading a result", utcnow(), row["id"]),
            )
        conn.commit()
    for row in rows:
        try:
            from .database import update_scan

            update_scan(
                int(row["scan_id"]),
                status="failed",
                progress=100,
                stage="Failed",
                completed_at=utcnow(),
                error="Satellite timed out before uploading a result",
            )
        except Exception:
            pass


def queue_satellite_job(satellite_id: str, scan_id: int, payload: dict[str, Any]) -> str:
    job_id = f"satjob_{uuid.uuid4().hex[:24]}"
    with get_db() as conn:
        conn.execute(
            "INSERT INTO satellite_jobs"
            "(id, satellite_id, scan_id, status, payload, created_at) "
            "VALUES (?, ?, ?, 'queued', ?, ?)",
            (job_id, satellite_id, scan_id, json_dump(payload), utcnow()),
        )
        conn.commit()
    return job_id


def claim_next_job(satellite_id: str) -> dict[str, Any] | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM satellite_jobs WHERE satellite_id = ? AND status = 'queued' "
            "ORDER BY created_at LIMIT 1",
            (satellite_id,),
        ).fetchone()
        if not row:
            return None
        conn.execute(
            "UPDATE satellite_jobs SET status = 'running', claimed_at = ? WHERE id = ?",
            (utcnow(), row["id"]),
        )
        conn.commit()
        job = dict(row)
        job["status"] = "running"
    payload = json_load(job.get("payload"), {})
    return {"job_id": job["id"], "scan_id": job["scan_id"], **payload}


def complete_job(job_id: str, status: str = "completed", error: str = "") -> bool:
    with get_db() as conn:
        cursor = conn.execute(
            "UPDATE satellite_jobs SET status = ?, error = ?, completed_at = ? "
            "WHERE id = ? AND status != 'completed'",
            (status, error, utcnow(), job_id),
        )
        conn.commit()
    return cursor.rowcount > 0


def _cidrs_overlap(subnets: list[str], target_cidrs: list[str]) -> bool:
    try:
        networks = [ipaddress.ip_network(item, strict=False) for item in subnets]
        targets = [ipaddress.ip_network(item, strict=False) for item in target_cidrs]
    except ValueError:
        return False
    return any(any(target.overlaps(network) for network in networks) for target in targets)


def matching_satellite(target: str) -> str | None:
    """Find an online satellite whose advertised subnets overlap the target."""
    entries = [line.strip() for line in target.replace(",", "\n").splitlines() if line.strip()]
    target_cidrs = []
    for entry in entries:
        if "/" in entry and not entry.startswith("*."):
            target_cidrs.append(entry)
    if not target_cidrs:
        return None
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM satellites WHERE status = 'active' AND online = 1"
        ).fetchall()
    for row in rows:
        subnets = json_load(row["subnets"], [])
        if subnets and _cidrs_overlap(subnets, target_cidrs):
            return row["id"]
    return None
