"""Session login, logout and TOTP MFA endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from ..audit import record_request
from ..database import get_db
from ..rate_limit import client_ip, login_limiter
from ..schemas import (
    LoginRequest,
    MfaDisableRequest,
    MfaEnableRequest,
    RecoveryCodesRequest,
)
from ..security import (
    admin_auth_enabled,
    admin_user,
    legacy_password_in_env_file,
    mfa_disable,
    mfa_enable,
    mfa_enabled,
    mfa_setup,
    mfa_status,
    regenerate_recovery_codes,
    verify_admin,
    verify_mfa_code,
)
from ..sessions import (
    SESSION_COOKIE,
    clear_auth_cookies,
    create_session,
    delete_session,
    set_auth_cookies,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

LOGIN_IP_LIMIT = 20
LOGIN_USER_LIMIT = 5
LOGIN_WINDOW = 300


def _too_many(retry_after: int) -> JSONResponse:
    return JSONResponse(
        {"detail": "Too many login attempts. Try again later.", "retry_after": retry_after},
        status_code=429,
        headers={"Retry-After": str(retry_after)},
    )


@router.get("/status")
def auth_status(request: Request) -> dict:
    auth = getattr(request.state, "auth", None)
    authenticated = bool(auth and auth.authenticated)
    session = auth.session if auth else None
    return {
        "auth_enabled": admin_auth_enabled(),
        "mfa_enabled": mfa_enabled(),
        "authenticated": authenticated,
        "username": auth.actor if authenticated else "",
        "method": auth.method if auth else "none",
        "csrf_token": (session or {}).get("csrf_token", "") if session else "",
        "legacy_password_present": legacy_password_in_env_file(),
    }


@router.post("/login")
def login(payload: LoginRequest, request: Request) -> JSONResponse:
    if not admin_auth_enabled():
        return JSONResponse({"ok": True, "auth_required": False})

    ip = client_ip(request)
    username = payload.username.strip()
    retry = login_limiter.hit(f"login:ip:{ip}", LOGIN_IP_LIMIT, LOGIN_WINDOW)
    if not retry:
        retry = login_limiter.hit(
            f"login:user:{username.lower()}", LOGIN_USER_LIMIT, LOGIN_WINDOW
        )
    if retry:
        record_request(
            request,
            "auth.login.rate_limited",
            category="auth",
            actor=username or "anonymous",
            outcome="failure",
            detail=f"Retry after {retry}s",
        )
        return _too_many(retry)

    if not username or not payload.password or not verify_admin(username, payload.password):
        record_request(
            request,
            "auth.login.failed",
            category="auth",
            actor=username or "anonymous",
            outcome="failure",
            detail="Invalid username or password",
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if mfa_enabled():
        if not payload.code and not payload.recovery_code:
            record_request(
                request,
                "auth.login.mfa_required",
                category="auth",
                actor=username,
                outcome="failure",
                detail="Password accepted; authenticator code required",
            )
            return JSONResponse(
                {
                    "detail": "Authenticator code required",
                    "mfa_required": True,
                },
                status_code=401,
            )
        if not verify_mfa_code(
            payload.recovery_code or payload.code,
            recovery=bool(payload.recovery_code),
        ):
            record_request(
                request,
                "auth.login.mfa_failed",
                category="auth",
                actor=username,
                outcome="failure",
                detail="Invalid MFA or recovery code",
            )
            raise HTTPException(status_code=401, detail="Invalid authenticator or recovery code")

    session = create_session(username, request)
    login_limiter.reset(f"login:user:{username.lower()}")
    response = JSONResponse(
        {
            "ok": True,
            "username": username,
            "csrf_token": session["csrf_token"],
            "expires_at": session["expires_at"],
            "mfa_enabled": mfa_enabled(),
        }
    )
    set_auth_cookies(response, session, request)
    record_request(
        request,
        "auth.login.succeeded",
        category="auth",
        actor=username,
        detail="MFA verified" if mfa_enabled() else "Password verified",
    )
    return response


@router.post("/logout")
def logout(request: Request) -> JSONResponse:
    token = request.cookies.get(SESSION_COOKIE)
    delete_session(token)
    response = JSONResponse({"ok": True})
    clear_auth_cookies(response)
    record_request(request, "auth.logout", category="auth")
    return response


@router.get("/mfa")
def mfa_state() -> dict:
    return mfa_status()


@router.post("/mfa/setup")
def mfa_start(request: Request) -> dict:
    if not admin_auth_enabled():
        raise HTTPException(
            status_code=400,
            detail="Set a dashboard password before enrolling authenticator MFA",
        )
    try:
        result = mfa_setup(admin_user())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_request(request, "auth.mfa.setup_started", category="auth")
    return result


@router.post("/mfa/enable")
def mfa_activate(payload: MfaEnableRequest, request: Request) -> dict:
    if not admin_auth_enabled():
        raise HTTPException(
            status_code=400,
            detail="Set a dashboard password before enrolling authenticator MFA",
        )
    try:
        codes = mfa_enable(payload.code)
    except ValueError as exc:
        record_request(
            request,
            "auth.mfa.enable_failed",
            category="auth",
            outcome="failure",
            detail=str(exc),
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    auth = getattr(request.state, "auth", None)
    current_id = (auth.session or {}).get("id") if auth else None
    with get_db() as conn:
        if current_id:
            conn.execute("DELETE FROM auth_sessions WHERE id != ?", (current_id,))
        else:
            conn.execute("DELETE FROM auth_sessions")
        conn.commit()
    record_request(request, "auth.mfa.enabled", category="auth")
    return {"ok": True, "recovery_codes": codes, "mfa": mfa_status()}


@router.post("/mfa/disable")
def mfa_deactivate(payload: MfaDisableRequest, request: Request) -> dict:
    if not verify_admin(admin_user(), payload.password):
        raise HTTPException(status_code=403, detail="Current password is incorrect")
    if mfa_enabled() and not verify_mfa_code(
        payload.recovery_code or payload.code,
        recovery=bool(payload.recovery_code),
    ):
        raise HTTPException(status_code=403, detail="Authenticator or recovery code is incorrect")
    mfa_disable()
    with get_db() as conn:
        conn.execute("DELETE FROM auth_sessions")
        conn.commit()
    record_request(request, "auth.mfa.disabled", category="auth")
    response = JSONResponse({"ok": True, "mfa": mfa_status()})
    clear_auth_cookies(response)
    return response


@router.post("/mfa/recovery-codes")
def mfa_new_recovery_codes(payload: RecoveryCodesRequest, request: Request) -> dict:
    if not verify_admin(admin_user(), payload.password):
        raise HTTPException(status_code=403, detail="Current password is incorrect")
    if not verify_mfa_code(
        payload.recovery_code or payload.code,
        recovery=bool(payload.recovery_code),
    ):
        raise HTTPException(status_code=403, detail="Authenticator or recovery code is incorrect")
    try:
        codes = regenerate_recovery_codes()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_request(request, "auth.mfa.recovery_codes_regenerated", category="auth")
    return {"ok": True, "recovery_codes": codes, "mfa": mfa_status()}


@router.post("/step-up")
def step_up(request: Request) -> dict:
    """Confirm that the current session is still authenticated and MFA-backed."""
    auth = getattr(request.state, "auth", None)
    if not auth or not auth.authenticated:
        raise HTTPException(status_code=401, detail="Authentication required")
    return {"ok": True, "mfa_verified": auth.mfa_verified, "method": auth.method}
