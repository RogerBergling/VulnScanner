"""HTTP Basic authentication and public endpoint tests."""

from __future__ import annotations


def test_dashboard_requires_basic_auth_when_configured(client, monkeypatch):
    monkeypatch.setenv("VS_ADMIN_PASSWORD", "s3cret")
    monkeypatch.setenv("VS_ADMIN_USER", "admin")

    unauthorized = client.get("/api/customers")
    assert unauthorized.status_code == 401
    assert unauthorized.headers["www-authenticate"].startswith("Basic")

    wrong = client.get("/api/customers", auth=("admin", "wrong"))
    assert wrong.status_code == 401

    wrong_user = client.get("/api/customers", auth=("other", "s3cret"))
    assert wrong_user.status_code == 401

    authorized = client.get("/api/customers", auth=("admin", "s3cret"))
    assert authorized.status_code == 200
    assert authorized.headers["x-content-type-options"] == "nosniff"

    assert client.get("/", auth=("admin", "s3cret")).status_code == 200
    assert client.get("/").status_code == 401
    assert client.get("/login").status_code == 200
    redirect = client.get(
        "/", headers={"Accept": "text/html"}, follow_redirects=False
    )
    assert redirect.status_code == 303
    assert redirect.headers["location"].startswith("/login")


def test_public_endpoints_bypass_dashboard_auth(client, monkeypatch):
    monkeypatch.setenv("VS_ADMIN_PASSWORD", "s3cret")

    assert client.get("/api/health").status_code == 200
    assert client.get("/api/openapi.json").status_code == 200
    assert client.get("/api/docs").status_code == 200
    assert client.get("/static/styles.css").status_code == 200
    assert client.get("/agent/download/vulnscanner_agent.py").status_code == 200

    # Agent enrollment is authenticated by its one-time token, not Basic auth.
    enrollment = client.post(
        "/api/agent/enroll",
        json={"enrollment_token": "not-a-real-token", "name": "x"},
    )
    assert enrollment.status_code == 401
    assert "invalid" in enrollment.json()["detail"].lower()

    # The agent API rejects missing bearer tokens rather than asking for Basic.
    heartbeat = client.post("/api/agent/heartbeat", json={})
    assert heartbeat.status_code == 401


def test_custom_admin_username_and_csp_on_401(client, monkeypatch):
    monkeypatch.setenv("VS_ADMIN_PASSWORD", "hunter2")
    monkeypatch.setenv("VS_ADMIN_USER", "auditor")

    assert client.get("/api/customers", auth=("admin", "hunter2")).status_code == 401
    assert client.get("/api/customers", auth=("auditor", "hunter2")).status_code == 200

    response = client.get("/")
    assert response.status_code == 401
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_manual_and_agent_scripts_are_served(client):
    manual = client.get("/manual")
    assert manual.status_code == 200
    assert "# VulnScanner" in manual.text

    for filename in (
        "vulnscanner_agent.py",
        "install-linux.sh",
        "install-windows.ps1",
        "ad_audit.ps1",
    ):
        response = client.get(f"/agent/download/{filename}")
        assert response.status_code == 200, filename
        assert filename in response.headers["content-disposition"]

    assert client.get("/agent/download/../../etc/passwd").status_code == 404


def test_satellite_endpoints_are_public_only_with_their_own_token(client, monkeypatch):
    monkeypatch.setenv("VS_ADMIN_PASSWORD", "s3cret")

    pairing = client.post(
        "/api/satellites/pairing", auth=("admin", "s3cret")
    )
    assert pairing.status_code == 200
    code = pairing.json()["code"]

    enrolled = client.post(
        "/api/satellite/pair",
        json={
            "pairing_code": code,
            "name": "dmz",
            "hostname": "dmz.example",
            "platform": "linux",
            "version": "1.3.0",
            "subnets": ["10.30.0.0/16"],
        },
    )
    assert enrolled.status_code == 200, enrolled.text

    # Missing satellite token is rejected by the endpoint, not redirected to
    # dashboard Basic auth.
    heartbeat = client.post("/api/satellite/heartbeat", json={})
    assert heartbeat.status_code == 401
