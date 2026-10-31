"""Token handling for agents and enrollment."""

from __future__ import annotations

import base64
import calendar
import hashlib
import hmac
import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone

from .config import BASE_DIR, env_file_path
from .database import get_db, get_setting, set_setting, transaction, utcnow
from .envfile import env_entries, remove_env_entries
from .totp import (
    generate_recovery_codes,
    generate_secret,
    hash_recovery_code,
    provisioning_uri,
    verify_recovery_code,
    verify_totp,
)

logger = logging.getLogger("vulnscanner.security")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_agent_token() -> str:
    return f"vs_agent_{secrets.token_urlsafe(32)}"


def new_enrollment_token() -> str:
    return f"vs_enroll_{secrets.token_urlsafe(28)}"


def token_hint(token: str) -> str:
    return token[:16] + "…"


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


PASSWORD_SCHEME = "pbkdf2_sha256"
PASSWORD_ITERATIONS = 260_000


def hash_password(password: str) -> str:
    """Return a salted PBKDF2 hash suitable for storage in SQLite."""
    if not password:
        return ""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return "{}${}${}${}".format(
        PASSWORD_SCHEME,
        PASSWORD_ITERATIONS,
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    if not password or not encoded:
        return False
    try:
        scheme, iterations, salt_text, digest_text = encoded.split("$", 3)
        if scheme != PASSWORD_SCHEME:
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(iterations)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def admin_user() -> str:
    return os.getenv("VS_ADMIN_USER") or get_setting("admin_user", "admin")


def admin_password_hash() -> str:
    return get_setting("admin_password_hash", "")


def admin_auth_enabled() -> bool:
    return bool(admin_password_hash() or os.getenv("VS_ADMIN_PASSWORD", ""))


def verify_admin(username: str, password: str) -> bool:
    """Validate dashboard Basic-auth credentials.

    The database hash is authoritative when present. The environment variable is
    kept as a fallback for installations that have not yet saved a password
    through the Settings page.
    """
    expected_user = admin_user()
    if not constant_time_equal(username, expected_user):
        return False
    stored_hash = admin_password_hash()
    if stored_hash:
        return verify_password(password, stored_hash)
    expected_password = os.getenv("VS_ADMIN_PASSWORD", "")
    return bool(expected_password) and constant_time_equal(password, expected_password)


def migrate_env_admin_password() -> None:
    """Move a legacy VS_ADMIN_PASSWORD value into the database and scrub it.

    The plaintext value is removed from ``VS_ENV_FILE`` (and any commented
    duplicate) after the hash is stored.  An explicit process environment
    variable cannot be rewritten by the application; in that case a warning
    tells the operator to remove it from the service definition.
    """
    legacy = os.getenv("VS_ADMIN_PASSWORD", "")
    try:
        if legacy and not admin_password_hash():
            set_setting("admin_password_hash", hash_password(legacy))
            set_setting("legacy_password_migrated_at", utcnow())
    except Exception:
        # A read-only or temporarily locked database must not prevent startup;
        # the environment fallback still works.
        return

    # The database hash is authoritative. Scrub the file even when a hash
    # already existed so an old plaintext secret does not linger. Tests set
    # VS_SKIP_DOTENV without an explicit VS_ENV_FILE; do not touch the
    # developer's checkout in that mode.
    if not (os.getenv("VS_SKIP_DOTENV") == "1" and not os.getenv("VS_ENV_FILE")):
        try:
            removed = remove_env_entries(
                env_file_path(BASE_DIR), {"VS_ADMIN_PASSWORD"}
            )
            if removed:
                logger.info(
                    "Removed legacy plaintext VS_ADMIN_PASSWORD from the environment file"
                )
        except OSError as exc:
            logger.warning(
                "Could not remove legacy VS_ADMIN_PASSWORD from the environment file: %s",
                exc,
            )
    if legacy:
        logger.warning(
            "VS_ADMIN_PASSWORD is still present in the process environment. "
            "Remove it from the service definition; the database hash is authoritative."
        )


def legacy_password_in_env_file() -> bool:
    """Return True when the environment file still contains a plaintext secret."""
    try:
        return bool(
            env_entries(env_file_path(BASE_DIR)).get("VS_ADMIN_PASSWORD", "")
        )
    except OSError:
        return False


def cleanup_legacy_password() -> dict[str, bool]:
    """Remove a plaintext VS_ADMIN_PASSWORD from the file and process."""
    removed = remove_env_entries(env_file_path(BASE_DIR), {"VS_ADMIN_PASSWORD"})
    os.environ.pop("VS_ADMIN_PASSWORD", None)
    return {"removed": bool(removed), "process_cleared": True}


# ---------------------------------------------------------------------------
# TOTP MFA
# ---------------------------------------------------------------------------

MFA_ISSUER = "VulnScanner"


def mfa_enabled() -> bool:
    """Return True only when MFA is enabled *and* a secret is present.

    This prevents a restored or partially-written settings row from locking the
    administrator out with an MFA challenge that can never be satisfied.
    """
    enabled = get_setting("mfa_enabled", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    return enabled and bool(get_setting("mfa_secret", ""))


def _decrypt_setting(key: str) -> str:
    value = get_setting(key, "")
    if not value:
        return ""
    try:
        from .credentials import decrypt_secret

        return decrypt_secret(value)
    except Exception:
        logger.error("Could not decrypt %s; MFA may need to be re-enrolled", key)
        return ""


def _encrypt_setting(value: str) -> str:
    if not value:
        return ""
    from .credentials import encrypt_secret

    return encrypt_secret(value)


def _recovery_hashes() -> list[str]:
    try:
        parsed = json.loads(get_setting("mfa_recovery_hashes", "[]"))
    except (TypeError, ValueError):
        return []
    return [str(item) for item in parsed if item] if isinstance(parsed, list) else []


def mfa_status() -> dict:
    hashes = _recovery_hashes()
    return {
        "enabled": mfa_enabled(),
        "recovery_codes_remaining": len(hashes),
        "pending": bool(get_setting("mfa_pending_secret", "")),
        "issuer": MFA_ISSUER,
    }


def mfa_setup(username: str) -> dict:
    """Create a pending TOTP secret and return the manual/otpauth values."""
    if mfa_enabled():
        raise ValueError("MFA is already enabled; disable it before enrolling again")
    secret = generate_secret()
    set_setting("mfa_pending_secret", _encrypt_setting(secret))
    return {
        "secret": secret,
        "otpauth_uri": provisioning_uri(secret, username, MFA_ISSUER),
        "issuer": MFA_ISSUER,
        "account": username,
        "digits": 6,
        "period": 30,
        "algorithm": "SHA1",
    }


def mfa_enable(code: str) -> list[str]:
    """Verify the pending secret and enable MFA. Returns recovery codes once."""
    pending = _decrypt_setting("mfa_pending_secret")
    if not pending:
        raise ValueError("Start MFA setup first")
    step = verify_totp(pending, code)
    if step is None:
        raise ValueError("The authenticator code is invalid or has expired")
    codes = generate_recovery_codes()
    hashes = [hash_recovery_code(item) for item in codes]
    set_setting("mfa_secret", _encrypt_setting(pending))
    set_setting("mfa_enabled", "true")
    set_setting("mfa_last_step", str(step))
    set_setting("mfa_recovery_hashes", json.dumps(hashes, separators=(",", ":")))
    set_setting("mfa_pending_secret", "")
    return codes


def mfa_disable() -> None:
    for key in (
        "mfa_enabled",
        "mfa_secret",
        "mfa_pending_secret",
        "mfa_recovery_hashes",
        "mfa_last_step",
    ):
        set_setting(key, "" if key not in {"mfa_enabled"} else "false")


def regenerate_recovery_codes() -> list[str]:
    if not mfa_enabled():
        raise ValueError("MFA is not enabled")
    codes = generate_recovery_codes()
    hashes = [hash_recovery_code(item) for item in codes]
    set_setting("mfa_recovery_hashes", json.dumps(hashes, separators=(",", ":")))
    return codes


def verify_mfa_code(code: str, *, recovery: bool = False) -> bool:
    """Verify a TOTP or one-time recovery code and prevent TOTP replay."""
    if not mfa_enabled():
        return False
    if recovery:
        hashes = _recovery_hashes()
        matched = verify_recovery_code(code, hashes)
        if not matched:
            return False
        hashes = [item for item in hashes if item != matched]
        set_setting("mfa_recovery_hashes", json.dumps(hashes, separators=(",", ":")))
        return True
    secret = _decrypt_setting("mfa_secret")
    if not secret:
        return False
    try:
        last_step = int(get_setting("mfa_last_step", "0") or 0)
    except ValueError:
        last_step = 0
    step = verify_totp(secret, code, last_step=last_step)
    if step is None:
        return False
    set_setting("mfa_last_step", str(step))
    return True


def _add_months(moment: datetime, months: int) -> datetime:
    """Add calendar months without the dateutil dependency.

    ``timedelta`` cannot represent months or years. Clamp the day to the last
    valid day of the target month (for example 31 January + 1 month = 28/29
    February).
    """
    months = int(months)
    month_index = moment.month - 1 + months
    year = moment.year + month_index // 12
    month = month_index % 12 + 1
    day = min(moment.day, calendar.monthrange(year, month)[1])
    return moment.replace(year=year, month=month, day=day)


def create_enrollment_token(
    customer_id: int,
    group_id: int,
    agent_name: str = "",
    hours: int = 24,
    days: int = 0,
    months: int = 0,
    years: int = 0,
) -> tuple[str, dict]:
    token = new_enrollment_token()
    token_id = secrets.token_hex(12)
    now = datetime.now(timezone.utc)
    # Calculate expiration: default is max(1, min(hours, 168)) for hourly mode.
    # If any of days/months/years provided, use calendar-aware arithmetic.
    if days or months or years:
        expires = now + timedelta(days=max(0, int(days or 0)))
        expires = _add_months(expires, max(0, int(months or 0)) + max(0, int(years or 0)) * 12)
    else:
        expires = now + timedelta(hours=max(1, min(hours, 168)))
    with get_db() as conn:
        conn.execute(
            "INSERT INTO enrollment_tokens"
            "(id, token_hash, token_prefix, customer_id, group_id, agent_name, expires_at, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                token_id,
                hash_token(token),
                token_hint(token),
                customer_id,
                group_id,
                agent_name.strip(),
                expires.replace(microsecond=0).isoformat(),
                utcnow(),
            ),
        )
        conn.commit()
    return token, {
        "id": token_id,
        "prefix": token_hint(token),
        "expires_at": expires.replace(microsecond=0).isoformat(),
    }


def consume_enrollment_token(token: str) -> dict | None:
    token_hash = hash_token(token)
    now = utcnow()
    with transaction() as conn:
        row = conn.execute(
            "SELECT * FROM enrollment_tokens WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if not row or row["used_at"] or row["expires_at"] < now:
            return None
        updated = conn.execute(
            "UPDATE enrollment_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL",
            (now, row["id"]),
        )
        if updated.rowcount != 1:
            return None
        return dict(row)


def authenticate_agent(token: str | None) -> dict | None:
    if not token:
        return None
    token_hash = hash_token(token)
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM agents WHERE token_hash = ? AND status != 'revoked'",
            (token_hash,),
        ).fetchone()
    return dict(row) if row else None
