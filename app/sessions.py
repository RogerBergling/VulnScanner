"""Session-based dashboard authentication.

HTTP Basic auth is retained for API clients, but browsers need a session so
the login flow can prompt for an authenticator code.  Sessions are random
256-bit tokens stored as SHA-256 hashes, with an absolute lifetime and an
idle timeout.  A per-session CSRF token protects cookie-authenticated
state-changing requests.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .database import get_db, utcnow
from .security import (
    admin_auth_enabled,
    admin_user,
    mfa_enabled,
    verify_admin,
    verify_mfa_code,
)

SESSION_COOKIE = "vs_session"
CSRF_COOKIE = "vs_csrf"
CSRF_HEADER = "x-csrf-token"
MFA_HEADER = "x-vs-mfa"
RECOVERY_HEADER = "x-vs-recovery-code"


def _env_int(name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(low, min(high, value))


def session_ttl_seconds() -> int:
    return _env_int("VS_SESSION_TTL_HOURS", 12, 1, 168) * 3600


def session_idle_seconds() -> int:
    return _env_int("VS_SESSION_IDLE_MINUTES", 30, 5, 1440) * 60


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _parse(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def request_is_secure(request) -> bool:
    if request.url.scheme == "https":
        return True
    if os.getenv("VS_TRUST_PROXY", "").strip().lower() in {"1", "true", "yes", "on"}:
        return request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip() == "https"
    return False


def _client_ip(request) -> str:
    from .rate_limit import client_ip

    return client_ip(request)


def create_session(username: str, request) -> dict[str, Any]:
    """Create a session and return the raw token plus metadata."""
    token = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    expires = now + timedelta(seconds=session_ttl_seconds())
    session_id = secrets.token_hex(16)
    with get_db() as conn:
        conn.execute("DELETE FROM auth_sessions WHERE expires_at <= ?", (now.isoformat(),))
        conn.execute(
            "INSERT INTO auth_sessions("
            "id, token_hash, csrf_token, username, created_at, last_seen, "
            "expires_at, ip, user_agent"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                session_id,
                _hash_token(token),
                csrf,
                username,
                now.isoformat(),
                now.isoformat(),
                expires.isoformat(),
                _client_ip(request),
                request.headers.get("user-agent", "")[:300],
            ),
        )
        conn.commit()
    return {
        "token": token,
        "csrf_token": csrf,
        "session_id": session_id,
        "expires_at": expires.isoformat(),
    }


def resolve_session(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    token_hash = _hash_token(token)
    now = datetime.now(timezone.utc)
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM auth_sessions WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        if not row:
            return None
        expires = _parse(row["expires_at"])
        last_seen = _parse(row["last_seen"])
        if expires is None or expires <= now:
            conn.execute("DELETE FROM auth_sessions WHERE id = ?", (row["id"],))
            conn.commit()
            return None
        if last_seen is None or (now - last_seen).total_seconds() > session_idle_seconds():
            conn.execute("DELETE FROM auth_sessions WHERE id = ?", (row["id"],))
            conn.commit()
            return None
        if last_seen is None or (now - last_seen).total_seconds() > 60:
            conn.execute(
                "UPDATE auth_sessions SET last_seen = ? WHERE id = ?",
                (now.replace(microsecond=0).isoformat(), row["id"]),
            )
            conn.commit()
    return dict(row)


def delete_session(token: str | None) -> None:
    if not token:
        return
    with get_db() as conn:
        conn.execute(
            "DELETE FROM auth_sessions WHERE token_hash = ?", (_hash_token(token),)
        )
        conn.commit()


def cleanup_sessions() -> int:
    now = utcnow()
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM auth_sessions WHERE expires_at <= ?", (now,))
        conn.commit()
        return int(cursor.rowcount or 0)


def set_auth_cookies(response, session: dict[str, Any], request) -> None:
    secure = request_is_secure(request)
    max_age = session_ttl_seconds()
    response.set_cookie(
        SESSION_COOKIE,
        session["token"],
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE,
        session["csrf_token"],
        max_age=max_age,
        httponly=False,
        secure=secure,
        samesite="strict",
        path="/",
    )


def clear_auth_cookies(response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


@dataclass
class AuthContext:
    authenticated: bool = False
    actor: str = "anonymous"
    method: str = "none"
    session: dict[str, Any] | None = None
    csrf_token: str = ""
    mfa_verified: bool = False
    detail: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


def authenticate_request(request) -> AuthContext:
    """Resolve a session cookie or HTTP Basic credentials."""
    if not admin_auth_enabled():
        return AuthContext(
            authenticated=True,
            actor="local",
            method="disabled",
            mfa_verified=False,
            detail="authentication disabled",
        )

    token = request.cookies.get(SESSION_COOKIE)
    session = resolve_session(token)
    if session:
        return AuthContext(
            authenticated=True,
            actor=str(session.get("username") or admin_user()),
            method="session",
            session=session,
            csrf_token=str(session.get("csrf_token") or ""),
            mfa_verified=True,
        )

    header = request.headers.get("authorization", "")
    if header.lower().startswith("basic "):
        import base64

        try:
            decoded = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
            username, password = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            return AuthContext(detail="Malformed Basic authorization header")
        if not verify_admin(username, password):
            return AuthContext(detail="Invalid username or password")
        if mfa_enabled():
            code = request.headers.get(MFA_HEADER, "")
            recovery = request.headers.get(RECOVERY_HEADER, "")
            if not code and not recovery:
                return AuthContext(
                    detail="MFA code required",
                    metadata={"mfa_required": True},
                )
            if not verify_mfa_code(recovery or code, recovery=bool(recovery)):
                return AuthContext(detail="Invalid MFA code")
        return AuthContext(
            authenticated=True,
            actor=username,
            method="basic",
            mfa_verified=mfa_enabled(),
        )
    return AuthContext(detail="Authentication required")
