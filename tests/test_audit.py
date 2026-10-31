"""Audit trail recording, filtering and CSV export."""

from __future__ import annotations


def test_mutating_requests_are_audited(api_client):
    response = api_client.patch("/api/settings", json={"max_scan_files": 1234})
    assert response.status_code == 200, response.text

    listing = api_client.get("/api/audit", params={"category": "api", "q": "settings"})
    assert listing.status_code == 200, listing.text
    data = listing.json()
    assert data["total"] >= 1
    assert any("patch /api/settings" in entry["action"] for entry in data["entries"])

    summary = api_client.get("/api/audit/summary").json()
    assert summary["total"] >= 1

    exported = api_client.get("/api/audit/export", params={"category": "api"})
    assert exported.status_code == 200
    assert "text/csv" in exported.headers["content-type"]
    assert "patch /api/settings" in exported.text


def test_login_events_are_audited(client):
    client.post("/api/settings/admin-password", json={"password": "audit-password-123"})
    client.post(
        "/api/auth/login", json={"username": "admin", "password": "wrong"}
    )
    entries = client.get(
        "/api/audit",
        params={"category": "auth", "q": "login"},
        auth=("admin", "audit-password-123"),
    ).json()["entries"]
    assert any(entry["action"] == "auth.login.failed" for entry in entries)
