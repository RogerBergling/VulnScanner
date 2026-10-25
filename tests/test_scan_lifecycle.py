"""Scan execution, persistence and finding lifecycle tests."""

from __future__ import annotations

import app.scans as scans
from app.database import get_db, utcnow
from app.scanners.base import Finding, ScanResult


def _make_scan(
    customer: dict,
    *,
    scan_type: str = "network",
    target: str = "192.0.2.30",
    asset_id: int | None = None,
) -> int:
    with get_db() as conn:
        scan_id = conn.execute(
            "INSERT INTO scans(customer_id, group_id, asset_id, scan_type, target, status, progress, stage, created_at) "
            "VALUES (?, ?, ?, ?, ?, 'queued', 0, 'Queued', ?)",
            (
                customer["id"],
                customer["group_id"],
                asset_id,
                scan_type,
                target,
                utcnow(),
            ),
        ).lastrowid
        conn.commit()
    return int(scan_id)


def _result(*, cve: str = "CVE-2026-0001") -> ScanResult:
    return ScanResult(
        findings=[
            Finding(
                severity="high",
                title="Exposed Redis service",
                category="network",
                description="A Redis service is reachable.",
                evidence="192.0.2.30:6379",
                remediation="Restrict access.",
                cve=cve,
                location="192.0.2.30:6379",
                key="risky-port:6379",
            )
        ],
        metadata={"source": "test"},
    )


def test_execute_scan_persists_findings_and_summary(api_client, customer, monkeypatch):
    scan_id = _make_scan(customer)
    monkeypatch.setattr(scans, "_dispatch", lambda scan, ctx, runtime: _result())

    scans.execute_scan(scan_id)

    detail = api_client.get(f"/api/scans/{scan_id}").json()
    assert detail["status"] == "completed"
    assert detail["progress"] == 100
    assert detail["finding_count"] == 1
    assert detail["summary"]["high"] == 1
    assert detail["summary"]["total"] == 1
    assert detail["summary"]["risk_score"] > 0
    assert detail["summary"]["metadata"] == {"source": "test"}
    assert detail["started_at"] and detail["completed_at"]
    assert detail["findings"][0]["cve"] == "CVE-2026-0001"
    assert detail["findings"][0]["fingerprint"]

    events = [event["message"] for event in detail["events"]]
    assert any("Starting network scan" in message for message in events)
    assert any("Scan completed with 1 finding" in message for message in events)

    dashboard = api_client.get("/api/dashboard").json()
    assert dashboard["counts"]["scans"] == 1
    assert dashboard["counts"]["assessed_assets"] == 1
    assert dashboard["severity"]["high"] == 1
    assert dashboard["top_findings"][0]["title"] == "Exposed Redis service"


def test_finding_status_survives_rescan(api_client, customer, monkeypatch):
    asset = api_client.post(
        f"/api/groups/{customer['group_id']}/assets",
        json={"name": "web01", "kind": "host", "identifier": "192.0.2.30"},
    ).json()
    first_scan = _make_scan(customer, asset_id=asset["id"])
    monkeypatch.setattr(scans, "_dispatch", lambda scan, ctx, runtime: _result())
    scans.execute_scan(first_scan)

    findings = api_client.get(f"/api/scans/{first_scan}/findings").json()
    assert len(findings) == 1
    finding = findings[0]
    first_seen = finding["first_seen"]

    updated = api_client.patch(f"/api/findings/{finding['id']}", json={"status": "acknowledged"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "acknowledged"

    second_scan = _make_scan(customer, asset_id=asset["id"])
    scans.execute_scan(second_scan)
    repeated = api_client.get(f"/api/scans/{second_scan}/findings").json()
    assert len(repeated) == 1
    assert repeated[0]["id"] != finding["id"]
    assert repeated[0]["status"] == "acknowledged"
    assert repeated[0]["first_seen"] == first_seen
    assert repeated[0]["last_seen"] >= first_seen

    events = api_client.get(f"/api/scans/{first_scan}").json()["events"]
    assert any("status changed from open to acknowledged" in event["message"] for event in events)

    filtered = api_client.get(f"/api/scans/{second_scan}/findings?status=acknowledged").json()
    assert len(filtered) == 1
    assert api_client.get(
        f"/api/scans/{second_scan}/findings?severity=critical"
    ).json() == []
    assert api_client.get(f"/api/scans/{second_scan}/findings?category=network").json()
    assert api_client.patch("/api/findings/99999", json={"status": "open"}).status_code == 404
    assert api_client.patch(
        f"/api/findings/{finding['id']}", json={"status": "not-a-status"}
    ).status_code == 422


def test_execute_scan_failure_is_recorded(api_client, customer, monkeypatch):
    scan_id = _make_scan(customer)

    def fail(_scan, _ctx, _runtime):
        raise RuntimeError("engine crashed")

    monkeypatch.setattr(scans, "_dispatch", fail)
    scans.execute_scan(scan_id)

    detail = api_client.get(f"/api/scans/{scan_id}").json()
    assert detail["status"] == "failed"
    assert detail["progress"] == 100
    assert "engine crashed" in detail["error"]
    assert any(
        event["level"] == "error" and "engine crashed" in event["message"]
        for event in detail["events"]
    )


def test_queued_scan_can_be_cancelled_before_execution(api_client, customer):
    scan_id = _make_scan(customer)
    response = api_client.post(f"/api/scans/{scan_id}/cancel")
    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"

    scans.execute_scan(scan_id)
    detail = api_client.get(f"/api/scans/{scan_id}").json()
    assert detail["status"] == "cancelled"


def test_recover_interrupted_scans(data_dir):
    with get_db() as conn:
        customer_id = conn.execute(
            "INSERT INTO customers(name, description, created_at) VALUES ('Acme', '', ?)",
            (utcnow(),),
        ).lastrowid
        queued = conn.execute(
            "INSERT INTO scans(customer_id, scan_type, target, status, created_at) "
            "VALUES (?, 'web', 'https://example.test', 'queued', ?)",
            (customer_id, utcnow()),
        ).lastrowid
        running = conn.execute(
            "INSERT INTO scans(customer_id, scan_type, target, status, created_at) "
            "VALUES (?, 'network', '192.0.2.1', 'running', ?)",
            (customer_id, utcnow()),
        ).lastrowid
        completed = conn.execute(
            "INSERT INTO scans(customer_id, scan_type, target, status, created_at) "
            "VALUES (?, 'web', 'https://done.test', 'completed', ?)",
            (customer_id, utcnow()),
        ).lastrowid
        conn.commit()

    scans.recover_interrupted_scans()

    with get_db() as conn:
        rows = {
            row["id"]: dict(row)
            for row in conn.execute(
                "SELECT id, status, progress, stage, error FROM scans"
            ).fetchall()
        }
        events = conn.execute(
            "SELECT scan_id, message FROM scan_events WHERE scan_id IN (?, ?)",
            (queued, running),
        ).fetchall()
    assert rows[queued]["status"] == "failed"
    assert rows[running]["status"] == "failed"
    assert rows[queued]["progress"] == 100
    assert rows[queued]["stage"] == "Interrupted"
    assert "Server restarted" in rows[queued]["error"]
    assert rows[completed]["status"] == "completed"
    assert {event["scan_id"] for event in events} == {queued, running}


def test_exports_json_csv_and_html(api_client, customer, monkeypatch):
    scan_id = _make_scan(customer)
    monkeypatch.setattr(scans, "_dispatch", lambda scan, ctx, runtime: _result())
    scans.execute_scan(scan_id)

    json_response = api_client.get(f"/api/scans/{scan_id}/export?format=json")
    assert json_response.status_code == 200
    assert json_response.headers["content-type"].startswith("application/json")
    payload = json_response.json()
    assert payload["scan"]["id"] == scan_id
    assert len(payload["findings"]) == 1

    csv_response = api_client.get(f"/api/scans/{scan_id}/export?format=csv")
    assert csv_response.status_code == 200
    assert "text/csv" in csv_response.headers["content-type"]
    assert "Exposed Redis service" in csv_response.text
    assert "CVE-2026-0001" in csv_response.text

    html_response = api_client.get(f"/api/scans/{scan_id}/export")
    assert html_response.status_code == 200
    assert "text/html" in html_response.headers["content-type"]
    assert "Exposed Redis service" in html_response.text
    assert "attachment" not in html_response.headers["content-disposition"].lower()

    assert api_client.get(f"/api/scans/{scan_id}/export?format=pdf").status_code == 400
    assert api_client.get("/api/scans/99999/export").status_code == 404


def test_ad_import_execution(api_client, customer):
    report = {
        "domain": {"name": "corp.example"},
        "guest_enabled": True,
        "password_policy": {"min_length": 6, "complexity": False},
        "krbtgt_password_age_days": 400,
        "unconstrained_delegation": {"count": 1, "accounts": ["DC01$"]},
        "findings": [{"severity": "high", "title": "Imported issue", "key": "imported"}],
    }
    created = api_client.post(
        "/api/ad/import",
        json={"customer_id": customer["id"], "report": report},
    )
    assert created.status_code == 201
    scan_id = created.json()["id"]

    scans.execute_ad_import(scan_id, report)

    detail = api_client.get(f"/api/scans/{scan_id}").json()
    assert detail["status"] == "completed"
    assert detail["summary"]["metadata"]["domain"] == "corp.example"
    titles = {finding["title"] for finding in detail["findings"]}
    assert "Active Directory Guest account is enabled" in titles
    assert "Imported issue" in titles
    assert detail["summary"]["critical"] >= 1

    duplicate_run = scans._fetch_scan(scan_id)
    assert duplicate_run["status"] == "completed"


def test_agent_result_execution_completes_job(api_client, customer):
    token_response = api_client.post(
        "/api/agents/enrollment-tokens",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "agent_name": "web01",
        },
    )
    assert token_response.status_code == 201
    enrollment_token = token_response.json()["token"]
    enrolled = api_client.post(
        "/api/agent/enroll",
        json={
            "enrollment_token": enrollment_token,
            "platform": "Linux",
            "version": "1.0",
            "hostname": "web01",
            "capabilities": ["system"],
        },
    )
    assert enrolled.status_code == 201, enrolled.text
    agent = enrolled.json()

    scan_response = api_client.post(
        f"/api/agents/{agent['agent_id']}/scan",
        json={"modules": ["system", "ports"], "paths": []},
    )
    assert scan_response.status_code == 201, scan_response.text
    scan_id = scan_response.json()["scan_id"]

    job_response = api_client.post(
        "/api/agent/jobs/next",
        headers={"X-Agent-Token": agent["token"]},
    )
    assert job_response.status_code == 200
    job = job_response.json()["job"]
    assert job["scan_id"] == scan_id

    scans.execute_agent_result(
        scan_id,
        {
            "system": {"hostname": "web01", "os": "Linux"},
            "listening_ports": [{"address": "0.0.0.0", "port": 6379, "service": "redis"}],
            "packages": [],
        },
        job["id"],
    )

    detail = api_client.get(f"/api/scans/{scan_id}").json()
    assert detail["status"] == "completed"
    assert detail["summary"]["metadata"]["system"]["hostname"] == "web01"
    assert any(finding["category"] == "host" for finding in detail["findings"])

    with get_db() as conn:
        job_row = conn.execute(
            "SELECT status FROM agent_jobs WHERE id = ?", (job["id"],)
        ).fetchone()
    assert job_row["status"] == "completed"
