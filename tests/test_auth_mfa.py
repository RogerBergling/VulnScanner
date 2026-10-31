"""Session login, CSRF, TOTP MFA and login rate limiting."""

from __future__ import annotations

import base64

from app import totp


def _set_password(client, password: str = "correct-horse-battery-1") -> None:
    response = client.post(
        "/api/settings/admin-password", json={"password": password}
    )
    assert response.status_code == 200, response.text


def _login(client, password: str, **extra):
    return client.post(
        "/api/auth/login",
        json={"username": "admin", "password": password, **extra},
    )


def test_session_login_csrf_and_logout(client):
    _set_password(client)
    response = _login(client, "correct-horse-battery-1")
    assert response.status_code == 200, response.text
    assert response.json()["ok"] is True
    assert "vs_session" in client.cookies

    status = client.get("/api/auth/status").json()
    assert status["authenticated"] is True
    assert status["csrf_token"]

    # Cookie-authenticated unsafe requests require the CSRF token.
    denied = client.post("/api/customers", json={"name": "No CSRF"})
    assert denied.status_code == 403
    created = client.post(
        "/api/customers",
        json={"name": "With CSRF"},
        headers={"X-CSRF-Token": status["csrf_token"]},
    )
    assert created.status_code == 201, created.text

    logged_out = client.post(
        "/api/auth/logout", headers={"X-CSRF-Token": status["csrf_token"]}
    )
    assert logged_out.status_code == 200
    assert client.get("/api/customers").status_code == 401


def test_login_rate_limit(client):
    _set_password(client)
    for _ in range(5):
        assert _login(client, "wrong-password").status_code == 401
    limited = _login(client, "wrong-password")
    assert limited.status_code == 429
    assert limited.headers["retry-after"]


def test_totp_mfa_login_and_recovery_codes(client, monkeypatch):
    _set_password(client)
    login = _login(client, "correct-horse-battery-1")
    assert login.status_code == 200
    csrf = login.json()["csrf_token"]
    setup = client.post(
        "/api/auth/mfa/setup", json={}, headers={"X-CSRF-Token": csrf}
    )
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    assert setup.json()["otpauth_uri"].startswith("otpauth://totp/")

    step = totp.current_step()
    enabled = client.post(
        "/api/auth/mfa/enable",
        json={"code": totp.hotp(secret, step)},
        headers={"X-CSRF-Token": csrf},
    )
    assert enabled.status_code == 200, enabled.text
    codes = enabled.json()["recovery_codes"]
    assert len(codes) == 10

    status = client.get("/api/auth/status").json()
    client.post("/api/auth/logout", headers={"X-CSRF-Token": status["csrf_token"]})

    missing = _login(client, "correct-horse-battery-1")
    assert missing.status_code == 401
    assert missing.json()["mfa_required"] is True

    # The enrollment code was consumed; use the next time step.
    monkeypatch.setattr(totp.time, "time", lambda: (step + 1) * 30)
    verified = _login(
        client, "correct-horse-battery-1", code=totp.hotp(secret, step + 1)
    )
    assert verified.status_code == 200, verified.text

    # Basic auth needs an explicit MFA header when MFA is enabled.
    status = client.get("/api/auth/status").json()
    client.post("/api/auth/logout", headers={"X-CSRF-Token": status["csrf_token"]})
    basic = base64.b64encode(b"admin:correct-horse-battery-1").decode("ascii")
    no_code = client.get(
        "/api/customers", headers={"Authorization": "Basic " + basic}
    )
    assert no_code.status_code == 401
    monkeypatch.setattr(totp.time, "time", lambda: (step + 2) * 30)
    basic_ok = client.get(
        "/api/customers",
        headers={
            "Authorization": "Basic " + basic,
            "X-VS-MFA": totp.hotp(secret, step + 2),
        },
    )
    assert basic_ok.status_code == 200, basic_ok.text

    # Recovery codes are single use.
    recovery = _login(
        client, "correct-horse-battery-1", recovery_code=codes[0]
    )
    assert recovery.status_code == 200, recovery.text
    status = client.get("/api/auth/status").json()
    client.post("/api/auth/logout", headers={"X-CSRF-Token": status["csrf_token"]})
    reused = _login(
        client, "correct-horse-battery-1", recovery_code=codes[0]
    )
    assert reused.status_code == 401
