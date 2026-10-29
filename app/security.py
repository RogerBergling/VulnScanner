"""Token handling for agents and enrollment."""

from __future__ import annotations

import base64
import calendar
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from .database import get_db, get_setting, transaction, utcnow


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
    """Move a legacy VS_ADMIN_PASSWORD value into the database as a hash."""
    from .database import set_setting

    try:
        if admin_password_hash():
            return
        legacy = os.getenv("VS_ADMIN_PASSWORD", "")
        if legacy:
            set_setting("admin_password_hash", hash_password(legacy))
    except Exception:
        # A read-only or temporarily locked database must not prevent startup;
        # the environment fallback still works.
        return


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
