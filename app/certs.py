"""Self-signed SSL certificate generation and management."""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERT_DIR = Path(__file__).resolve().parent.parent / "data" / "certs"
CERT_FILE = CERT_DIR / "server.crt"
KEY_FILE = CERT_DIR / "server.key"


def _generate_self_signed() -> tuple[str, str]:
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Enterprise"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VulnScanner"),
        x509.NameAttribute(NameOID.COMMON_NAME, "vulnscanner.local"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("vulnscanner.local")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path = str(KEY_FILE)
    cert_path = str(CERT_FILE)
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def get_cert_paths() -> tuple[str | None, str | None]:
    """Return (cert_path, key_path) if they exist; else generate and return."""
    if CERT_FILE.exists() and KEY_FILE.exists():
        return str(CERT_FILE), str(KEY_FILE)
    cert_path, key_path = _generate_self_signed()
    return cert_path, key_path
