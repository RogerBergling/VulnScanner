"""Security-header, host, origin and request-body hardening tests."""

from __future__ import annotations


def test_security_headers_and_host_allowlist(api_client):
    response = api_client.get("/api/health")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cross-origin-opener-policy"] == "same-origin"

    shell = api_client.get("/")
    assert shell.status_code == 200
    assert "object-src 'none'" in shell.headers["content-security-policy"]
    assert shell.headers["cache-control"] == "no-store"

    rejected = api_client.get(
        "/api/health", headers={"Host": "attacker.example"}
    )
    assert rejected.status_code == 400


def test_hsts_is_set_for_secure_proxy_requests(api_client, monkeypatch):
    monkeypatch.setenv("VS_TRUST_PROXY", "true")
    response = api_client.get(
        "/api/health", headers={"X-Forwarded-Proto": "https"}
    )
    assert response.status_code == 200
    assert response.headers["strict-transport-security"] == "max-age=31536000"


def test_cross_origin_state_changes_are_rejected(api_client):
    rejected = api_client.post(
        "/api/customers",
        json={"name": "Cross origin"},
        headers={"Origin": "https://attacker.example"},
    )
    assert rejected.status_code == 403
    assert "cross-origin" in rejected.json()["detail"].lower()

    accepted = api_client.post(
        "/api/customers",
        json={"name": "Same origin"},
        headers={"Origin": "http://testserver"},
    )
    assert accepted.status_code == 201, accepted.text


def test_oversized_request_body_is_rejected_before_parsing(api_client, monkeypatch):
    limit = 1024 * 1024
    monkeypatch.setenv("VS_MAX_REQUEST_BYTES", str(limit))
    response = api_client.post(
        "/api/customers",
        json={"name": "Too large", "description": "x" * (limit + 1024)},
    )
    assert response.status_code == 413
    assert response.json()["limit_bytes"] == limit
    assert response.headers["cache-control"] == "no-store"
