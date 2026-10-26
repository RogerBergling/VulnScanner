"""Self-signed SSL certificate generation and management."""

from __future__ import annotations

import hmac
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERT_DIR = Path(__file__).resolve().parent.parent / "data" / "certs"
CERT_FILE = CERT_DIR / "server.crt"
KEY_FILE = CERT_DIR / "server.key"

WEB_CERT_FILE = CERT_FILE
WEB_KEY_FILE = KEY_FILE

INTERNAL_DIR = CERT_DIR / "internal"
INTERNAL_CERT_FILE = INTERNAL_DIR / "ca.crt"
INTERNAL_SERVER_CERT = INTERNAL_DIR / "server.crt"
INTERNAL_SERVER_KEY = INTERNAL_DIR / "server.key"
INTERNAL_CA_KEY = INTERNAL_DIR / "ca.key"

# Certificate uploads are small text files. Cap them well below agent result
# uploads so a request cannot exhaust memory or disk.
MAX_CERT_BYTES = 1024 * 1024


class CertificateError(ValueError):
    """Raised when an uploaded certificate or key is invalid."""


def _write_file(path: Path, data: bytes, mode: int) -> None:
    """Write ``data`` atomically and enforce file permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp_name, mode)
        except OSError:
            pass
        os.replace(temp_name, path)
        try:
            os.chmod(path, mode)
        except OSError:
            pass
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def _ensure_private_key(path: Path) -> None:
    """Tighten permissions on an existing private key (best effort)."""
    if path.exists():
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def validate_certificate_and_key(cert_data: bytes, key_data: bytes) -> None:
    """Validate PEM data and confirm that the key matches the certificate."""
    try:
        cert = x509.load_pem_x509_certificate(cert_data)
    except Exception as exc:  # cryptography raises several exception types
        raise CertificateError("Certificate must be a valid PEM-encoded X.509 certificate") from exc

    try:
        key = serialization.load_pem_private_key(key_data, password=None)
    except TypeError as exc:
        raise CertificateError(
            "Encrypted private keys are not supported; upload an unencrypted PEM key"
        ) from exc
    except Exception as exc:
        raise CertificateError("Private key must be a valid unencrypted PEM private key") from exc

    cert_public = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_public = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if not hmac.compare_digest(cert_public, key_public):
        raise CertificateError("Certificate and private key do not match")


def save_certificate(cert_path: Path, key_path: Path, cert_data: bytes, key_data: bytes) -> None:
    """Validate and atomically install a certificate/key pair."""
    validate_certificate_and_key(cert_data, key_data)
    _write_file(cert_path, cert_data, 0o644)
    _write_file(key_path, key_data, 0o600)


def _generate_self_signed(cert_path: str | None = None, key_path: str | None = None, cn: str = "vulnscanner.local") -> tuple[str, str]:
    target_cert = Path(cert_path or CERT_FILE)
    target_key = Path(key_path or KEY_FILE)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Enterprise"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VulnScanner"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    _write_file(
        target_key,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
        0o600,
    )
    _write_file(target_cert, cert.public_bytes(serialization.Encoding.PEM), 0o644)
    return str(target_cert), str(target_key)


def get_cert_paths() -> tuple[str, str]:
    """Return (cert_path, key_path) if they exist; else generate and return."""
    if CERT_FILE.exists() and KEY_FILE.exists():
        _ensure_private_key(KEY_FILE)
        return str(CERT_FILE), str(KEY_FILE)
    cert_path, key_path = _generate_self_signed()
    return cert_path, key_path


def get_web_cert_paths() -> tuple[str, str]:
    _ensure_private_key(WEB_KEY_FILE)
    return str(WEB_CERT_FILE), str(WEB_KEY_FILE)


def get_internal_cert_paths() -> tuple[str, str, str]:
    _ensure_private_key(INTERNAL_SERVER_KEY)
    _ensure_private_key(INTERNAL_CA_KEY)
    return str(INTERNAL_CERT_FILE), str(INTERNAL_SERVER_CERT), str(INTERNAL_SERVER_KEY)


def _generate_internal_ca() -> None:
    INTERNAL_DIR.mkdir(parents=True, exist_ok=True)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VulnScanner Internal CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "VulnScanner Internal CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    _write_file(INTERNAL_CERT_FILE, ca_cert.public_bytes(serialization.Encoding.PEM), 0o644)
    _write_file(
        INTERNAL_CA_KEY,
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
        0o600,
    )
    # Server cert signed by CA
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VulnScanner"),
        x509.NameAttribute(NameOID.COMMON_NAME, "vulnscanner.local"),
    ])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("vulnscanner.local")]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    _write_file(INTERNAL_SERVER_CERT, server_cert.public_bytes(serialization.Encoding.PEM), 0o644)
    _write_file(
        INTERNAL_SERVER_KEY,
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
        0o600,
    )
