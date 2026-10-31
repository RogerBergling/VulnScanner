"""RFC 6238 TOTP and recovery-code helpers.

Implemented locally so authenticator support does not add a runtime
dependency.  The default is SHA-1/6 digits/30 seconds, which is what common
authenticator apps expect.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

DIGITS = 6
PERIOD = 30
WINDOW = 1
ISSUER = "VulnScanner"


def generate_secret() -> str:
    """Return a 160-bit base32 secret without padding."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def normalize_secret(secret: str) -> str:
    text = "".join((secret or "").split()).upper().replace(" ", "")
    padding = (-len(text)) % 8
    return text + ("=" * padding)


def _counter_bytes(counter: int) -> bytes:
    return struct.pack(">Q", int(counter))


def hotp(secret: str, counter: int, digits: int = DIGITS) -> str:
    key = base64.b32decode(normalize_secret(secret), casefold=True)
    digest = hmac.new(key, _counter_bytes(counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def current_step(now: float | None = None) -> int:
    return int((now if now is not None else time.time()) // PERIOD)


def verify_totp(
    secret: str,
    code: str,
    *,
    window: int = WINDOW,
    last_step: int | None = None,
    now: float | None = None,
) -> int | None:
    """Return the matched timestep, or None.

    ``last_step`` prevents replay of a previously accepted code.  A small
    window tolerates clock drift between the server and the authenticator.
    """
    cleaned = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(cleaned) != DIGITS:
        return None
    step = current_step(now)
    for offset in range(-window, window + 1):
        candidate = step + offset
        if last_step is not None and candidate <= int(last_step):
            continue
        if hmac.compare_digest(hotp(secret, candidate), cleaned):
            return candidate
    return None


def provisioning_uri(secret: str, account: str, issuer: str = ISSUER) -> str:
    label = quote(f"{issuer}:{account}", safe="")
    params = {
        "secret": normalize_secret(secret).rstrip("="),
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": str(DIGITS),
        "period": str(PERIOD),
    }
    query = "&".join(f"{key}={quote(value, safe='')}" for key, value in params.items())
    return f"otpauth://totp/{label}?{query}"


def generate_recovery_codes(count: int = 10) -> list[str]:
    """Return human-friendly one-time recovery codes."""
    codes: list[str] = []
    for _ in range(count):
        raw = secrets.token_hex(5).upper()
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def normalize_recovery_code(code: str) -> str:
    return "".join(ch for ch in str(code or "").upper() if ch.isalnum())


def hash_recovery_code(code: str) -> str:
    normalized = normalize_recovery_code(code)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def verify_recovery_code(code: str, hashes: list[str]) -> str | None:
    """Return the matching hash for a recovery code, or None."""
    digest = hash_recovery_code(code)
    for stored in hashes:
        if hmac.compare_digest(digest, str(stored)):
            return str(stored)
    return None
