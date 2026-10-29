"""Scheduled scan CRUD, cron calculation and queueing tests."""

from __future__ import annotations

from datetime import datetime

from app.database import get_db
from app.scheduler import _job_target


def _asset(api_client, customer):
    response = api_client.post(
        f"/api/groups/{customer['group_id']}/assets",
        json={
            "name": "www01",
            "kind": "web",
            "identifier": "https://example.test",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_schedule_crud_and_cron(api_client, customer):
    asset = _asset(api_client, customer)
    response = api_client.post(
        "/api/schedules",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "asset_id": asset["id"],
            "scan_type": "web",
            "target": "",
            "cron_expression": "0 2 * * *",
            "enabled": True,
        },
    )
    assert response.status_code == 201, response.text
    schedule = response.json()
    assert schedule["target"] == "https://example.test"
    assert schedule["next_run"].endswith("T02:00:00+00:00")
    assert datetime.fromisoformat(schedule["next_run"]).tzinfo is not None

    fetched = api_client.get(f"/api/schedules/{schedule['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["cron_expression"] == "0 2 * * *"

    updated = api_client.patch(
        f"/api/schedules/{schedule['id']}", json={"enabled": False}
    )
    assert updated.status_code == 200
    assert updated.json()["enabled"] is False

    # A blank target on PATCH resolves the asset identifier again.
    resolved = api_client.patch(
        f"/api/schedules/{schedule['id']}", json={"target": ""}
    )
    assert resolved.status_code == 200
    assert resolved.json()["target"] == "https://example.test"

    deleted = api_client.delete(f"/api/schedules/{schedule['id']}")
    assert deleted.status_code == 200
    assert api_client.get(f"/api/schedules/{schedule['id']}").status_code == 404


def test_schedule_rejects_invalid_cron(api_client, customer):
    response = api_client.post(
        "/api/schedules",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "scan_type": "web",
            "target": "https://example.test",
            "cron_expression": "not a cron",
            "enabled": True,
        },
    )
    assert response.status_code == 400


def test_schedule_queues_a_scan(api_client, customer, monkeypatch):
    asset = _asset(api_client, customer)
    response = api_client.post(
        "/api/schedules",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "asset_id": asset["id"],
            "scan_type": "web",
            "target": "https://example.test",
            "cron_expression": "*/15 * * * *",
            "enabled": True,
        },
    )
    schedule = response.json()

    submitted: list[int] = []
    monkeypatch.setattr("app.jobs.submit_scan", lambda scan_id, _options=None: submitted.append(scan_id))

    _job_target(schedule["id"])

    assert submitted
    with get_db() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (submitted[0],)).fetchone()
        updated = conn.execute(
            "SELECT * FROM scan_schedules WHERE id = ?", (schedule["id"],)
        ).fetchone()
    assert scan["status"] == "queued"
    assert scan["requested_by"] == "schedule"
    assert updated["last_run"]
    assert updated["next_run"]
