"""Token handling for agents and enrollment."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from .database import get_db, transaction, utcnow


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


def create_enrollment_token(
    customer_id: int,
    group_id: int,
    agent_name: str = "",
    hours: int = 24,
) -> tuple[str, dict]:
    token = new_enrollment_token()
    token_id = secrets.token_hex(12)
    now = datetime.now(timezone.utc)
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
