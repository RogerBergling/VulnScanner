"""Regression tests for the security fixes applied in this release."""

from __future__ import annotations

import importlib
import stat
import subprocess
import threading
import time
from pathlib import Path

import pytest
from starlette.requests import Request

from app.envfile import upsert_env_entries
from app.rate_limit import client_ip
from app.reporting import build_html
from app.scanners.base import Finding, normalize_finding
from tests.helpers import DummyContext

MALICIOUS_CVSS = '\"><script>alert(1)</script>'


def _base_finding(**overrides):
    finding = {
        "severity": "high",
        "category": "web",
        "title": "Test finding",
        "description": "",
        "evidence": "",
        "remediation": "",
        "cve": "",
        "cwe": "",
        "cvss": None,
        "location": "",
        "resource": "",
        "status": "open",
        "fingerprint": "regression-test-fingerprint",
        "raw": {},
    }
    finding.update(overrides)
    return finding


def _request_with_forwarded_for(value: str, peer: str = "10.0.0.5") -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": [(b"x-forwarded-for", value.encode("ascii"))],
            "client": (peer, 12345),
            "server": ("testserver", 80),
            "http_version": "1.1",
        }
    )


# ---------------------------------------------------------------------------
# CVSS injection / report headers
# ---------------------------------------------------------------------------


def test_normalize_finding_coerces_cvss_to_a_number_or_none():
    assert normalize_finding({"title": "bad", "cvss": MALICIOUS_CVSS})["cvss"] is None
    assert normalize_finding({"title": "bad", "cvss": "8.1"})["cvss"] == 8.1
    assert normalize_finding({"title": "bad", "cvss": 99})["cvss"] is None
    assert normalize_finding({"title": "bad", "cvss": "not-a-number"})["cvss"] is None
    assert Finding(
        severity="high", title="bad", category="web", cvss=MALICIOUS_CVSS
    ).to_dict()["cvss"] is None


def test_html_report_never_renders_malicious_cvss():
    html = build_html(
        {"id": 1, "scan_type": "web", "target": "https://example.test"},
        [_base_finding(cvss=MALICIOUS_CVSS)],
        {"customer": {}, "group": {}, "asset": {}, "summary": {"total": 1}},
    )
    assert "<script>alert(1)</script>" not in html
    assert "\"><script" not in html
    assert "CVSS" not in html


def test_html_export_uses_restrictive_headers_and_escaped_cvss(api_client, customer):
    from app.scans import _fetch_scan, _save_findings

    created = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "scan_type": "web",
            "target": "https://example.test",
        },
    )
    assert created.status_code == 201, created.text
    scan_id = created.json()["id"]
    _save_findings(_fetch_scan(scan_id), [_base_finding(cvss=MALICIOUS_CVSS)])

    response = api_client.get(f"/api/scans/{scan_id}/export")
    assert response.status_code == 200, response.text
    assert "<script>alert(1)</script>" not in response.text
    assert "CVSS" not in response.text
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-security-policy"] == (
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
        "base-uri 'none'; form-action 'none'"
    )


# ---------------------------------------------------------------------------
# Wordlist file disclosure
# ---------------------------------------------------------------------------


def test_external_wordlist_is_metadata_only(api_client, data_dir, monkeypatch, tmp_path):
    from app.scanners import subdomains

    external = tmp_path / "outside" / "secrets.txt"
    external.parent.mkdir()
    external.write_text("www\nTOP-SECRET-CONTENT\n", encoding="utf-8")
    monkeypatch.setenv("VS_SUBFINDER_WORDLIST", str(external))

    info = subdomains.wordlist_info()
    assert info["external"] is True
    assert info["editable"] is False
    assert info["content"] == ""
    assert info["line_count"] == 0
    assert "TOP-SECRET-CONTENT" not in repr(info)

    response = api_client.get("/api/settings/wordlist")
    assert response.status_code == 200
    payload = response.json()
    assert payload["external"] is True
    assert payload["editable"] is False
    assert payload["content"] == ""
    assert "TOP-SECRET-CONTENT" not in response.text


def test_wordlist_inside_data_dir_remains_editable(api_client, data_dir):
    from app.scanners import subdomains

    saved = subdomains.save_wordlist("www\nmail\n")
    assert saved["external"] is False
    assert saved["editable"] is True
    assert "www" in saved["content"]


# ---------------------------------------------------------------------------
# .env injection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "/tmp/data\nVS_SSL=false",
        "/tmp/data\rVS_SSL=false",
        "/tmp/data\x00",
        "/tmp/data\x01",
    ],
)
def test_storage_validation_rejects_control_characters(api_client, value):
    response = api_client.post(
        "/api/server/storage/validate", json={"data_dir": value}
    )
    assert response.status_code == 400


def test_upsert_env_entries_rejects_control_characters(tmp_path):
    path = tmp_path / ".env"
    path.write_text("VS_HOST=127.0.0.1\n", encoding="utf-8")
    with pytest.raises(ValueError):
        upsert_env_entries(path, {"VS_DATA_DIR": "/tmp/data\nVS_SSL=false"})
    assert "VS_SSL=false" not in path.read_text(encoding="utf-8")

    with pytest.raises(ValueError):
        upsert_env_entries(path, {"VS_DATA_DIR": "/tmp/data\x00"})
    with pytest.raises(ValueError):
        upsert_env_entries(path, {"VS_DATA_DIR": "/tmp/data\x01"})


def test_sync_env_from_settings_rejects_unsafe_values(
    data_dir, monkeypatch, tmp_path
):
    from app import runtime_settings
    from app.database import set_setting

    env_file = tmp_path / "service.env"
    monkeypatch.setenv("VS_ENV_FILE", str(env_file))
    monkeypatch.setattr(runtime_settings, "BASE_DIR", tmp_path)
    set_setting("bind_host", "127.0.0.1\nINJECTED=1")
    with pytest.raises(ValueError):
        runtime_settings.sync_env_from_settings()
    assert not env_file.exists() or "INJECTED" not in env_file.read_text(
        encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Basic-auth rate limiting and audit
# ---------------------------------------------------------------------------


def test_basic_auth_failures_are_rate_limited_and_audited(client, monkeypatch):
    from app.audit import list_entries

    monkeypatch.setenv("VS_ADMIN_USER", "admin")
    monkeypatch.setenv("VS_ADMIN_PASSWORD", "s3cret")
    for _ in range(5):
        response = client.get("/api/customers", auth=("admin", "wrong"))
        assert response.status_code == 401

    limited = client.get("/api/customers", auth=("admin", "wrong"))
    assert limited.status_code == 429
    assert limited.headers["retry-after"]

    entries = list_entries(limit=50)["entries"]
    actions = {entry["action"] for entry in entries}
    assert "auth.basic.failed" in actions
    assert "auth.basic.rate_limited" in actions


def test_basic_auth_mfa_failures_are_rate_limited(client, data_dir):
    from app import security, totp
    from app.audit import list_entries
    from app.database import set_setting

    set_setting("admin_password_hash", security.hash_password("s3cret"))
    setup = security.mfa_setup("admin")
    security.mfa_enable(totp.hotp(setup["secret"], totp.current_step()))

    for _ in range(5):
        response = client.get("/api/customers", auth=("admin", "s3cret"))
        assert response.status_code == 401
        assert response.json()["mfa_required"] is True

    limited = client.get("/api/customers", auth=("admin", "s3cret"))
    assert limited.status_code == 429

    entries = list_entries(limit=50)["entries"]
    actions = {entry["action"] for entry in entries}
    assert "auth.basic.mfa_required" in actions
    assert "auth.basic.rate_limited" in actions


# ---------------------------------------------------------------------------
# Forwarded-for parsing
# ---------------------------------------------------------------------------


def test_client_ip_uses_the_rightmost_trusted_hop(monkeypatch):
    monkeypatch.setenv("VS_TRUST_PROXY", "true")
    monkeypatch.delenv("VS_TRUSTED_PROXY_HOPS", raising=False)
    assert (
        client_ip(_request_with_forwarded_for("198.51.100.1, 203.0.113.9"))
        == "203.0.113.9"
    )

    monkeypatch.setenv("VS_TRUSTED_PROXY_HOPS", "2")
    assert (
        client_ip(_request_with_forwarded_for("198.51.100.1, 203.0.113.9"))
        == "198.51.100.1"
    )
    monkeypatch.setenv("VS_TRUSTED_PROXY_HOPS", "1")
    assert (
        client_ip(_request_with_forwarded_for("not-an-ip, 203.0.113.9"))
        == "203.0.113.9"
    )
    assert client_ip(_request_with_forwarded_for("garbage")) == "10.0.0.5"


def test_origin_must_match_scheme_host_and_port(api_client):
    for origin in (
        "http://testserver:8080",
        "https://testserver",
        "https://testserver:443",
    ):
        response = api_client.post(
            "/api/customers",
            json={"name": "Cross origin"},
            headers={"Origin": origin},
        )
        assert response.status_code == 403, origin

    accepted = api_client.post(
        "/api/customers",
        json={"name": "Same origin"},
        headers={"Origin": "http://testserver:80"},
    )
    assert accepted.status_code == 201, accepted.text


# ---------------------------------------------------------------------------
# Service probe redirects
# ---------------------------------------------------------------------------


def test_http_service_probe_does_not_follow_redirects(monkeypatch):
    from app.scanners import services

    captured: dict[str, object] = {}

    class Redirect:
        status_code = 302

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return Redirect()

    monkeypatch.setattr(services.requests, "get", fake_get)
    assert services._http_get_json("127.0.0.1", 9200, "/", 1.0) is None
    assert captured["allow_redirects"] is False


# ---------------------------------------------------------------------------
# Satellite listener startup
# ---------------------------------------------------------------------------


def test_lifespan_starts_satellite_listener_once(data_dir, monkeypatch):
    import app.main as main

    calls = []
    monkeypatch.setattr(main, "SATELLITE_PORT", 18443)
    monkeypatch.setattr(
        main,
        "_start_satellite_listener",
        lambda *args: calls.append(args),
    )

    from fastapi.testclient import TestClient

    with TestClient(main.app) as client:
        assert client.get("/api/health").status_code == 200
    assert len(calls) == 1


def test_satellite_listener_start_is_idempotent(data_dir, monkeypatch):
    import uvicorn

    import app.certs as certs
    import app.main as main

    class FakeServer:
        instances: list["FakeServer"] = []

        def __init__(self, _config):
            self.should_exit = False
            self.started = threading.Event()
            FakeServer.instances.append(self)

        def run(self):
            self.started.set()
            while not self.should_exit:
                time.sleep(0.01)

    monkeypatch.setattr(main, "SATELLITE_PORT", 18444)
    monkeypatch.setattr(uvicorn, "Config", lambda *args, **kwargs: object())
    monkeypatch.setattr(uvicorn, "Server", FakeServer)
    monkeypatch.setattr(certs, "satellite_client_ca_path", lambda: "ca.pem")
    main._satellite_thread = None
    main._satellite_server = None
    try:
        first = main._start_satellite_listener("cert.pem", "key.pem", "info")
        assert first is not None
        assert first.is_alive()
        second = main._start_satellite_listener("cert.pem", "key.pem", "info")
        assert second is first
        assert len(FakeServer.instances) == 1
    finally:
        main._stop_satellite_listener()


# ---------------------------------------------------------------------------
# Low-severity hardening
# ---------------------------------------------------------------------------


def test_tool_status_uses_the_sanitised_environment(monkeypatch):
    from app.scanners import tools

    captured = {}
    monkeypatch.setattr(
        tools, "tool_path", lambda name: "/bin/true" if name == "nmap" else None
    )
    monkeypatch.setenv("VS_CREDENTIAL_KEY", "do-not-leak")

    def fake_run(args, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(args, 0, "Nmap version 7.95\n", "")

    monkeypatch.setattr(tools.subprocess, "run", fake_run)
    status = tools.tool_status()
    assert status["nmap"]["available"] is True
    assert "VS_CREDENTIAL_KEY" not in captured["env"]


def test_github_token_is_only_sent_to_approved_hosts(monkeypatch, data_dir):
    from app.scanners import repository

    captured: list[dict[str, str]] = []
    monkeypatch.setattr(repository, "tool_path", lambda name: "/usr/bin/git")
    monkeypatch.setattr(repository, "clone_dir", lambda: data_dir / "clones")
    monkeypatch.setattr(repository, "_directory_size", lambda path: 0)

    def fake_run(command, timeout=0, env=None):
        captured.append(dict(env or {}))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(repository, "run_tool", fake_run)
    ctx = DummyContext()

    repository._clone_github(ctx, "https://github.com/acme/repo.git", "token-123")
    assert "GIT_CONFIG_VALUE_0" in captured[-1]

    repository._clone_github(
        ctx, "https://git.example.test/acme/repo.git", "token-123"
    )
    assert "GIT_CONFIG_VALUE_0" not in captured[-1]
    assert "GIT_CONFIG_COUNT" not in captured[-1]


def test_recovery_codes_have_at_least_128_bits_of_entropy():
    from app.totp import generate_recovery_codes, normalize_recovery_code

    for code in generate_recovery_codes():
        assert len(normalize_recovery_code(code)) >= 32


def test_login_next_url_is_origin_validated():
    text = (Path(__file__).resolve().parents[1] / "app" / "static" / "login.js").read_text(
        encoding="utf-8"
    )
    assert "new URL(next, location.origin)" in text
    assert "target.origin !== location.origin" in text


def test_agent_pending_result_is_private(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    agent = importlib.import_module("agent.vulnscanner_agent")
    agent.save_pending("job-1", {"ok": True}, "completed", "")
    path = tmp_path / "vulnscanner" / "pending-result.json"
    assert path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_new_password_hashes_use_the_stronger_pbkdf2_work_factor():
    from app.security import PASSWORD_ITERATIONS, hash_password

    assert PASSWORD_ITERATIONS >= 600_000
    assert f"${PASSWORD_ITERATIONS}$" in hash_password("a-test-password")
