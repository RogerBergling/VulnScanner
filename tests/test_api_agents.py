"""Agent enrollment, authentication and job API tests."""

from __future__ import annotations

from app.database import get_db


def _enrollment_token(api_client, customer, name="web01", group_id=None):
    response = api_client.post(
        "/api/agents/enrollment-tokens",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"] if group_id is None else group_id,
            "agent_name": name,
            "hours": 2,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _enroll(api_client, token, *, name="", platform="Linux", hostname="web01", capabilities=None):
    return api_client.post(
        "/api/agent/enroll",
        json={
            "enrollment_token": token,
            "name": name,
            "platform": platform,
            "version": "1.2.3",
            "hostname": hostname,
            "capabilities": capabilities if capabilities is not None else ["system", "packages", "ports"],
        },
    )


def test_enrollment_token_commands_and_single_use(api_client, customer):
    result = _enrollment_token(api_client, customer)
    assert result["token"].startswith("vs_enroll_")
    assert result["token_prefix"].endswith("…")
    assert "vulnscanner_agent.py enroll" in result["linux_command"]
    assert "vulnscanner_agent.py enroll" in result["windows_command"]
    assert result["agent_url"].endswith("/agent/vulnscanner_agent.py")
    assert "install-windows-agent.ps1" in result["windows_installer_command"]
    assert result["windows_installer_url"].endswith("/agent/install-windows-agent.ps1")
    assert result["windows_agent_url"].endswith("/agent/VulnScannerAgent.ps1")
    assert "once" in result["note"]

    enrolled = _enroll(api_client, result["token"])
    assert enrolled.status_code == 201, enrolled.text
    agent = enrolled.json()
    assert agent["name"] == "web01"
    assert agent["token"].startswith("vs_agent_")
    assert agent["customer_id"] == customer["id"]
    assert agent["group_id"] == customer["group_id"]
    assert agent["poll_interval"] == 30

    repeated = _enroll(api_client, result["token"])
    assert repeated.status_code == 401
    assert "invalid" in repeated.json()["detail"].lower()


def test_enrollment_rejects_invalid_and_mismatched_requests(api_client, customer):
    invalid = _enroll(api_client, "vs_enroll_definitely-not-valid")
    assert invalid.status_code == 401

    with get_db() as conn:
        other = conn.execute(
            "INSERT INTO customers(name, description, created_at) VALUES ('Other', '', '2026-01-01T00:00:00+00:00')"
        ).lastrowid
        conn.commit()

    mismatch = api_client.post(
        "/api/agents/enrollment-tokens",
        json={"customer_id": other, "group_id": customer["group_id"]},
    )
    assert mismatch.status_code == 400

    missing = api_client.post(
        "/api/agents/enrollment-tokens",
        json={"customer_id": 99999, "group_id": 99999},
    )
    assert missing.status_code == 404


def test_agent_lifecycle_heartbeat_jobs_and_revocation(api_client, customer):
    token = _enrollment_token(api_client, customer)["token"]
    agent = _enroll(api_client, token).json()
    agent_id = agent["agent_id"]
    headers = {"X-Agent-Token": agent["token"]}

    listed = api_client.get("/api/agents")
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    entry = listed.json()[0]
    assert entry["id"] == agent_id
    assert entry["online"] is True
    assert "token_hash" not in entry
    assert entry["last_seen_human"]

    heartbeat = api_client.post(
        "/api/agent/heartbeat",
        headers=headers,
        json={
            "platform": "Linux",
            "version": "1.2.4",
            "hostname": "web01-updated",
            "capabilities": ["system"],
        },
    )
    assert heartbeat.status_code == 200
    assert heartbeat.json()["ok"] is True
    assert heartbeat.json()["next_poll"] == 30

    bearer = api_client.post(
        "/api/agent/heartbeat",
        headers={"Authorization": f"Bearer {agent['token']}"},
        json={"hostname": "web01"},
    )
    assert bearer.status_code == 200

    assert api_client.post(
        "/api/agent/heartbeat", headers={"X-Agent-Token": "bad"}, json={}
    ).status_code == 401

    scan = api_client.post(
        f"/api/agents/{agent_id}/scan",
        json={"modules": ["system", "packages", "ports"], "paths": []},
    )
    assert scan.status_code == 201, scan.text
    scan_payload = scan.json()
    assert scan_payload["agent_online"] is True
    scan_id = scan_payload["scan_id"]
    assert scan_payload["scan"]["status"] == "waiting_agent"

    no_job = api_client.post("/api/agent/jobs/next", headers=headers)
    assert no_job.status_code == 200
    job = no_job.json()["job"]
    assert job["scan_id"] == scan_id
    assert job["status"] == "running"
    assert job["payload"]["modules"] == ["system", "packages", "ports"]

    empty = api_client.post("/api/agent/jobs/next", headers=headers)
    assert empty.json()["job"] is None
    assert empty.json()["next_poll"] == 30

    accepted = api_client.post(
        f"/api/agent/jobs/{job['id']}/result",
        headers=headers,
        json={"status": "completed", "results": {"system": {"hostname": "web01"}}},
    )
    assert accepted.status_code == 200
    assert accepted.json()["accepted"] is True

    duplicate = api_client.post(
        f"/api/agent/jobs/{job['id']}/result",
        headers=headers,
        json={"status": "completed", "results": {}},
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True

    with get_db() as conn:
        row = conn.execute(
            "SELECT status FROM agent_jobs WHERE id = ?", (job["id"],)
        ).fetchone()
    assert row["status"] == "processing"

    assert api_client.delete(f"/api/agents/{agent_id}").status_code == 200
    assert api_client.get("/api/agents").json() == []
    assert api_client.post(
        "/api/agent/heartbeat", headers=headers, json={}
    ).status_code == 401
    assert api_client.post(
        "/api/agent/jobs/next", headers=headers
    ).status_code == 401


def test_agent_scan_module_validation(api_client, customer):
    token = _enrollment_token(api_client, customer)["token"]
    agent = _enroll(api_client, token, platform="Linux").json()

    secrets_without_path = api_client.post(
        f"/api/agents/{agent['agent_id']}/scan",
        json={"modules": ["secrets"], "paths": []},
    )
    assert secrets_without_path.status_code == 400

    ad_on_linux = api_client.post(
        f"/api/agents/{agent['agent_id']}/scan",
        json={"modules": ["ad"], "paths": []},
    )
    assert ad_on_linux.status_code == 400

    with_path = api_client.post(
        f"/api/agents/{agent['agent_id']}/scan",
        json={"modules": ["secrets", "system"], "paths": ["/srv/app"]},
    )
    assert with_path.status_code == 201

    assert api_client.post(
        "/api/agents/not-an-agent/scan", json={"modules": ["system"]}
    ).status_code == 404


def test_network_scan_can_be_delegated_to_agent(api_client, customer, monkeypatch):
    import app.api as api
    from app.scans import execute_agent_result

    submitted = []
    monkeypatch.setattr(api, "submit_scan", lambda *args, **kwargs: submitted.append(args))

    token = _enrollment_token(api_client, customer)["token"]
    agent = _enroll(
        api_client,
        token,
        platform="Windows",
        hostname="jump01",
        capabilities=["system", "ports", "network"],
    ).json()
    headers = {"X-Agent-Token": agent["token"]}

    response = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "scan_type": "network",
            "target": "10.0.0.0/30",
            "agent_id": agent["agent_id"],
            "options": {"profile": "web", "ports": "22,80,443"},
        },
    )
    assert response.status_code == 201, response.text
    scan = response.json()
    assert scan["scan_type"] == "network"
    assert scan["status"] == "waiting_agent"
    assert scan["agent_id"] == agent["agent_id"]
    assert submitted == []

    with get_db() as conn:
        job_row = conn.execute(
            "SELECT * FROM agent_jobs WHERE scan_id = ?", (scan["id"],)
        ).fetchone()
    assert job_row is not None
    payload = __import__("json").loads(job_row["payload"])
    assert payload["modules"] == ["network"]
    assert payload["target"] == "10.0.0.0/30"
    assert payload["options"]["profile"] == "web"

    claimed = api_client.post("/api/agent/jobs/next", headers=headers).json()["job"]
    assert claimed["scan_id"] == scan["id"]
    assert claimed["payload"]["modules"] == ["network"]

    report = {
        "network": {
            "hosts": ["10.0.0.1", "10.0.0.2"],
            "host_count": 2,
            "ports_scanned": 3,
            "open_ports": [
                {"host": "10.0.0.1", "port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH_9.0"},
                {"host": "10.0.0.2", "port": 6379, "service": "redis", "banner": "- NOAUTH required"},
            ],
            "finished_at": "2026-01-01T00:00:00+00:00",
        }
    }
    duplicate = api_client.post(
        f"/api/agent/jobs/{claimed['id']}/result",
        headers=headers,
        json={"status": "completed", "results": report},
    )
    assert duplicate.status_code == 200, duplicate.text
    assert duplicate.json()["accepted"] is True

    execute_agent_result(scan["id"], report, claimed["id"])
    detail = api_client.get(f"/api/scans/{scan['id']}").json()
    assert detail["status"] == "completed"
    assert detail["summary"]["total"] >= 2
    by_key = {finding["location"]: finding for finding in detail["findings"]}
    assert "10.0.0.1:22" in by_key
    assert by_key["10.0.0.2:6379"]["severity"] == "critical"
    assert detail["summary"]["metadata"]["execution"] == "agent"
    with get_db() as conn:
        job_status = conn.execute(
            "SELECT status FROM agent_jobs WHERE id = ?", (claimed["id"],)
        ).fetchone()["status"]
    assert job_status == "completed"


def test_agent_network_scan_module_and_validation(api_client, customer):
    token = _enrollment_token(api_client, customer)["token"]
    agent = _enroll(
        api_client, token, platform="Linux", capabilities=["system", "network"]
    ).json()

    missing_target = api_client.post(
        f"/api/agents/{agent['agent_id']}/scan",
        json={"modules": ["network"], "target": ""},
    )
    assert missing_target.status_code == 400

    mixed = api_client.post(
        f"/api/agents/{agent['agent_id']}/scan",
        json={"modules": ["network", "system"], "target": "10.0.0.1"},
    )
    assert mixed.status_code == 400

    created = api_client.post(
        f"/api/agents/{agent['agent_id']}/scan",
        json={
            "modules": ["network"],
            "target": "10.0.0.1",
            "options": {"profile": "common"},
        },
    )
    assert created.status_code == 201, created.text
    payload = created.json()
    assert payload["scan"]["scan_type"] == "network"
    assert payload["scan"]["status"] == "waiting_agent"

    with get_db() as conn:
        row = conn.execute(
            "SELECT scan_type FROM scans WHERE id = ?", (payload["scan_id"],)
        ).fetchone()
    assert row["scan_type"] == "network"

    legacy = _enroll(
        api_client,
        _enrollment_token(api_client, customer, name="legacy")["token"],
        name="legacy",
        capabilities=["system"],
    ).json()
    rejected = api_client.post(
        f"/api/agents/{legacy['agent_id']}/scan",
        json={"modules": ["network"], "target": "10.0.0.1"},
    )
    assert rejected.status_code == 400
    assert "network" in rejected.json()["detail"]

    wrong_customer = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "scan_type": "network",
            "target": "10.0.0.1",
            "agent_id": "not-an-agent",
        },
    )
    assert wrong_customer.status_code == 404

    non_network = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "scan_type": "web",
            "target": "https://example.test",
            "agent_id": agent["agent_id"],
        },
    )
    assert non_network.status_code == 400


def test_delegated_network_scan_requires_capability_and_bounded_cidr(api_client, customer):
    no_caps = _enroll(
        api_client,
        _enrollment_token(api_client, customer, name="no-caps")["token"],
        name="no-caps",
        capabilities=[],
    ).json()
    empty_capabilities = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "scan_type": "network",
            "target": "10.0.0.1",
            "agent_id": no_caps["agent_id"],
        },
    )
    assert empty_capabilities.status_code == 400
    assert "network" in empty_capabilities.json()["detail"]

    capable = _enroll(
        api_client,
        _enrollment_token(api_client, customer, name="neter")["token"],
        name="neter",
        capabilities=["system", "network"],
    ).json()
    oversized = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "scan_type": "network",
            "target": "10.0.0.0/8",
            "agent_id": capable["agent_id"],
        },
    )
    assert oversized.status_code == 400
    assert "limit is 256" in oversized.json()["detail"]

    via_agent = api_client.post(
        f"/api/agents/{capable['agent_id']}/scan",
        json={"modules": ["network"], "target": "10.0.0.0/8"},
    )
    assert via_agent.status_code == 400
    assert "limit is 256" in via_agent.json()["detail"]


def test_delegated_network_scan_uses_agent_group(api_client, customer):
    group = api_client.post(
        f"/api/customers/{customer['id']}/groups", json={"name": "Jump hosts"}
    ).json()
    agent = _enroll(
        api_client,
        _enrollment_token(api_client, customer, name="jump", group_id=group["id"])["token"],
        name="jump",
        capabilities=["network"],
    ).json()

    created = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "scan_type": "network",
            "target": "10.0.0.1",
            "agent_id": agent["agent_id"],
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["group_id"] == group["id"]

    cross_group = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "scan_type": "network",
            "target": "10.0.0.1",
            "agent_id": agent["agent_id"],
        },
    )
    assert cross_group.status_code == 400


def test_agent_job_result_failure_marks_scan_failed(api_client, customer):
    token = _enrollment_token(api_client, customer)["token"]
    agent = _enroll(api_client, token).json()
    headers = {"X-Agent-Token": agent["token"]}
    scan_id = api_client.post(
        f"/api/agents/{agent['agent_id']}/scan",
        json={"modules": ["system"]},
    ).json()["scan_id"]
    job = api_client.post("/api/agent/jobs/next", headers=headers).json()["job"]

    failed = api_client.post(
        f"/api/agent/jobs/{job['id']}/result",
        headers=headers,
        json={"status": "failed", "results": {}, "error": "collector crashed"},
    )
    assert failed.status_code == 200
    assert failed.json()["accepted"] is False

    detail = api_client.get(f"/api/scans/{scan_id}").json()
    assert detail["status"] == "failed"
    assert "collector crashed" in detail["error"]

    duplicate = api_client.post(
        f"/api/agent/jobs/{job['id']}/result",
        headers=headers,
        json={"status": "completed", "results": {}},
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True


def test_revoked_agent_cannot_start_jobs(api_client, customer):
    token = _enrollment_token(api_client, customer)["token"]
    agent = _enroll(api_client, token).json()
    api_client.delete(f"/api/agents/{agent['agent_id']}")

    response = api_client.post(
        f"/api/agents/{agent['agent_id']}/scan", json={"modules": ["system"]}
    )
    assert response.status_code == 409


def test_agent_detail_configuration_and_token_rotation(api_client, customer):
    token = _enrollment_token(api_client, customer)["token"]
    agent = _enroll(api_client, token).json()
    agent_id = agent["agent_id"]
    headers = {"X-Agent-Token": agent["token"]}

    scan = api_client.post(
        f"/api/agents/{agent_id}/scan", json={"modules": ["system"]}
    ).json()
    detail = api_client.get(f"/api/agents/{agent_id}")
    assert detail.status_code == 200, detail.text
    data = detail.json()
    assert data["name"] == "web01"
    assert data["customer_name"] == "Acme"
    assert data["stats"]["scans"] == 1
    assert data["stats"]["jobs"] == 1
    assert data["stats"]["queued_jobs"] == 1
    assert data["jobs"][0]["scan_id"] == scan["scan_id"]
    assert data["jobs"][0]["modules"] == ["system"]
    assert data["scans"][0]["id"] == scan["scan_id"]
    assert data["created_human"]
    assert "token_hash" not in data

    renamed = api_client.patch(
        f"/api/agents/{agent_id}", json={"name": "web01-renamed"}
    )
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["agent"]["name"] == "web01-renamed"
    assert renamed.json()["agent"]["asset_name"] == "web01-renamed"

    other = api_client.post("/api/customers", json={"name": "Other"}).json()
    other_detail = api_client.get(f"/api/customers/{other['id']}").json()
    other_group = other_detail["groups"][0]["id"]
    moved = api_client.patch(
        f"/api/agents/{agent_id}",
        json={
            "name": "web01-renamed",
            "customer_id": other["id"],
            "group_id": other_group,
        },
    )
    assert moved.status_code == 200, moved.text
    assert moved.json()["agent"]["customer_id"] == other["id"]
    assert moved.json()["agent"]["group_name"] == other_detail["groups"][0]["name"]
    with get_db() as conn:
        asset = conn.execute(
            "SELECT customer_id, group_id, name FROM assets WHERE id = ?",
            (agent["asset_id"],),
        ).fetchone()
    assert asset["customer_id"] == other["id"]
    assert asset["group_id"] == other_group

    mismatch = api_client.patch(
        f"/api/agents/{agent_id}",
        json={"customer_id": customer["id"], "group_id": other_group},
    )
    assert mismatch.status_code == 400
    assert api_client.patch(
        "/api/agents/not-an-agent", json={"name": "x"}
    ).status_code == 404
    assert api_client.get("/api/agents/not-an-agent").status_code == 404

    rotated = api_client.post(f"/api/agents/{agent_id}/rotate-token", json={})
    assert rotated.status_code == 200, rotated.text
    payload = rotated.json()
    assert payload["token"].startswith("vs_agent_")
    assert "update-token" in payload["linux_command"]
    assert "sudo -u vulnscanner /opt/vulnscanner-agent" in payload["linux_command"]
    assert "update-token" in payload["windows_command"]
    assert "VulnScannerAgent.ps1" in payload["windows_agent_command"]
    assert "-Action Configure" in payload["windows_agent_command"]
    assert api_client.post(
        "/api/agent/heartbeat", headers=headers, json={}
    ).status_code == 401
    assert api_client.post(
        "/api/agent/heartbeat",
        headers={"X-Agent-Token": payload["token"]},
        json={},
    ).status_code == 200

    api_client.delete(f"/api/agents/{agent_id}")
    assert api_client.patch(
        f"/api/agents/{agent_id}", json={"name": "after-revoke"}
    ).status_code == 409
    assert api_client.post(
        f"/api/agents/{agent_id}/rotate-token", json={}
    ).status_code == 409

