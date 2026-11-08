"""Tests for per-scan authenticated web sessions."""

import pytest

from app.credentials import resolve_scan_web_auth
from app.scanners.web import _session


def test_session_applies_basic_auth_and_headers():
    session = _session(
        web_auth={
            "auth_type": "basic",
            "username": "alice",
            "password": "secret",
            "headers": {"X-Tenant": "acme"},
        }
    )
    try:
        assert session.auth == ("alice", "secret")
        assert session.headers["X-Tenant"] == "acme"
    finally:
        session.close()


def test_session_applies_bearer_and_cookie():
    bearer = _session(web_auth={"auth_type": "bearer", "token": "abc"})
    try:
        assert bearer.headers["Authorization"] == "Bearer abc"
    finally:
        bearer.close()
    cookie = _session(web_auth={"auth_type": "cookie", "cookie": "a=b"})
    try:
        assert cookie.headers["Cookie"] == "a=b"
    finally:
        cookie.close()


def test_web_auth_api_stores_encrypted_secret(api_client, customer):
    response = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "scan_type": "web",
            "target": "https://example.com",
            "web_auth": {
                "auth_type": "bearer",
                "token": "test-token",
                "headers": {"X-Tenant": "acme"},
            },
        },
    )
    assert response.status_code == 201, response.text
    scan_id = response.json()["id"]
    stored = resolve_scan_web_auth(scan_id)
    assert stored["token"] == "test-token"
    assert stored["headers"] == {"X-Tenant": "acme"}


def test_web_auth_rejected_for_network_scan(api_client, customer):
    response = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "scan_type": "network",
            "target": "127.0.0.1",
            "web_auth": {"auth_type": "bearer", "token": "x"},
        },
    )
    assert response.status_code == 422


def test_store_web_auth_requires_fields(data_dir):
    from app.credentials import CredentialError, store_scan_web_auth
    from app.database import get_db, utcnow

    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO scans(scan_type,target,status,options,created_at) VALUES ('web','x','queued','{}',?)",
            (utcnow(),),
        )
        scan_id = int(cursor.lastrowid)
        conn.commit()
    with pytest.raises(CredentialError):
        store_scan_web_auth(scan_id, {"auth_type": "bearer", "token": ""})
