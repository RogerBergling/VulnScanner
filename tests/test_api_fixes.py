"""Regression tests for API and data-safety fixes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.config import get_limit
from app.database import get_db, utcnow


def _asset(api_client, customer, name="www01"):
    response = api_client.post(
        f"/api/groups/{customer['group_id']}/assets",
        json={
            "name": name,
            "kind": "web",
            "identifier": "https://example.test",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_blank_target_uses_asset_identifier(api_client, customer):
    asset = _asset(api_client, customer)
    response = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "asset_id": asset["id"],
            "scan_type": "web",
            "target": "",
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["target"] == "https://example.test"


def test_pdf_report_and_duration(api_client, customer):
    response = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "scan_type": "web",
            "target": "https://example.test",
        },
    )
    scan_id = response.json()["id"]
    with get_db() as conn:
        conn.execute(
            "UPDATE scans SET status = 'completed', progress = 100, stage = 'Completed', "
            "started_at = ?, completed_at = ? WHERE id = ?",
            (utcnow(), utcnow(), scan_id),
        )
        conn.execute(
            "INSERT INTO findings("
            "scan_id, customer_id, asset_id, severity, category, title, description, "
            "evidence, remediation, cve, cwe, cvss, location, resource, fingerprint, "
            "status, first_seen, last_seen, raw"
            ") VALUES (?, ?, NULL, 'high', 'web', 'Test', '', '', '', '', '', NULL, "
            "'', '', 'pdf-fp', 'open', ?, ?, '{}')",
            (scan_id, customer["id"], utcnow(), utcnow()),
        )
        conn.commit()

    pdf = api_client.get(f"/api/scans/{scan_id}/report/pdf")
    assert pdf.status_code == 200, pdf.text
    assert pdf.headers["content-type"].startswith("application/pdf")
    assert pdf.content.startswith(b"%PDF")

    invalid = api_client.get(f"/api/scans/{scan_id}/report/pdf?report_type=../../x")
    assert invalid.status_code == 400

    detail = api_client.get(f"/api/scans/{scan_id}").json()
    assert detail["duration_seconds"] is not None
    assert detail["duration_seconds"] >= 0


def test_enrollment_token_with_months(api_client, customer):
    response = api_client.post(
        "/api/agents/enrollment-tokens",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "agent_name": "long-lived",
            "hours": 24,
            "months": 1,
        },
    )
    assert response.status_code == 201, response.text
    expires = datetime.fromisoformat(response.json()["expires_at"])
    assert expires > datetime.now(timezone.utc)


def test_enrollment_token_with_days(api_client, customer):
    response = api_client.post(
        "/api/agents/enrollment-tokens",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "agent_name": "short-lived",
            "days": 2,
        },
    )
    assert response.status_code == 201, response.text
    expires = datetime.fromisoformat(response.json()["expires_at"])
    assert expires > datetime.now(timezone.utc) + timedelta(days=1)


def test_settings_guardrail_is_applied(api_client):
    response = api_client.patch("/api/settings", json={"max_scan_files": 1234})
    assert response.status_code == 200
    assert get_limit("max_scan_files", 20000) == 1234


def test_smtp_password_is_encrypted_at_rest(api_client):
    response = api_client.patch("/api/settings", json={"smtp_password": "smtp-secret"})
    assert response.status_code == 200
    with get_db() as conn:
        stored = conn.execute(
            "SELECT value FROM settings WHERE key = 'smtp_password'"
        ).fetchone()["value"]
    assert stored != "smtp-secret"
    from app.scheduler import _smtp_password

    assert _smtp_password() == "smtp-secret"
