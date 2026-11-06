"""Tests for satellite pairing, jobs, routing and the satellite runner."""

import pytest

from app.satellites import (
    authenticate_satellite,
    claim_next_job,
    complete_job,
    create_pairing,
    expire_stale_satellite_jobs,
    get_satellite,
    matching_satellite,
    queue_satellite_job,
    register_satellite,
    revoke_satellite,
    update_satellite,
)
from app.satellite import SatelliteContext, load_config, save_config


def _register(data_dir, code, subnets=None):
    registration = register_satellite(
        code,
        "dmz-1",
        "dmz1.example.com",
        platform="linux",
        version="1.1.3",
        subnets=subnets or ["10.30.0.0/16"],
    )
    assert registration is not None
    assert registration["client_cert"].startswith("-----BEGIN CERTIFICATE-----")
    assert registration["client_key"].startswith("-----BEGIN")
    assert registration["ca_cert"].startswith("-----BEGIN CERTIFICATE-----")
    return registration


def test_pairing_and_registration(data_dir):
    pairing = create_pairing()
    registration = _register(data_dir, pairing["code"])
    assert get_satellite(registration["satellite_id"]) is not None


def test_pairing_code_is_one_time(data_dir):
    pairing = create_pairing()
    _register(data_dir, pairing["code"])
    assert register_satellite(pairing["code"], "again", "host") is None


def test_invalid_pairing_code(data_dir):
    assert register_satellite("vs_pair_nope", "x", "host") is None


def test_authenticate_satellite(data_dir):
    pairing = create_pairing()
    registration = _register(data_dir, pairing["code"])
    satellite = authenticate_satellite(registration["token"])
    assert satellite is not None
    assert satellite["id"] == registration["satellite_id"]
    assert authenticate_satellite("wrong-token") is None
    assert authenticate_satellite("") is None


def test_satellite_update_and_revoke(data_dir):
    pairing = create_pairing()
    registration = _register(data_dir, pairing["code"])
    satellite_id = registration["satellite_id"]
    updated = update_satellite(
        satellite_id, name="dmz-renamed", subnets=["10.30.0.0/16", "192.168.5.0/24"]
    )
    assert updated["name"] == "dmz-renamed"
    assert updated["subnets"] == ["10.30.0.0/16", "192.168.5.0/24"]

    assert revoke_satellite(satellite_id) is True
    assert get_satellite(satellite_id) is None
    assert authenticate_satellite(registration["token"]) is None


def test_job_claim_and_complete(data_dir):
    pairing = create_pairing()
    registration = _register(data_dir, pairing["code"])
    satellite_id = registration["satellite_id"]
    job_id = queue_satellite_job(
        satellite_id, None, {"scan_type": "network", "target": "10.30.0.5", "options": {}}
    )
    assert claim_next_job("other-satellite") is None
    job = claim_next_job(satellite_id)
    assert job is not None
    assert job["job_id"] == job_id
    assert job["scan_type"] == "network"
    assert claim_next_job(satellite_id) is None  # claimed already
    assert complete_job(job_id, "completed") is True
    assert claim_next_job(satellite_id) is None
    assert complete_job(job_id, "completed") is False  # idempotent


def test_subnet_matching(data_dir):
    pairing = create_pairing()
    registration = _register(data_dir, pairing["code"], subnets=["10.30.0.0/16"])
    from app.satellites import heartbeat

    heartbeat(registration["satellite_id"], "linux", "1.1.3")
    assert matching_satellite("10.30.5.0/24") is not None
    assert matching_satellite("10.31.0.0/24") is None
    assert matching_satellite("host.example.com") is None  # no CIDR -> no auto-match
    assert matching_satellite("10.30.0.5") is None  # single host -> no auto-match


def test_stale_satellite_job_expiry(data_dir):
    pairing = create_pairing()
    registration = _register(data_dir, pairing["code"])
    job_id = queue_satellite_job(
        registration["satellite_id"], None,
        {"scan_type": "network", "target": "10.30.0.5", "options": {}},
    )
    claim_next_job(registration["satellite_id"])
    from app.database import get_db

    with get_db() as conn:
        conn.execute(
            "UPDATE satellite_jobs SET claimed_at = '2000-01-01T00:00:00' WHERE id = ?",
            (job_id,),
        )
        conn.commit()
    expire_stale_satellite_jobs(3600)
    with get_db() as conn:
        row = conn.execute(
            "SELECT status, error FROM satellite_jobs WHERE id = ?", (job_id,)
        ).fetchone()
        assert row["status"] == "failed"
        assert "timed out" in row["error"]


def test_satellite_context():
    ctx = SatelliteContext("10.0.0.1", {"nuclei": "true"})
    ctx.log("hello", "warning")
    ctx.progress(50, "stage")
    assert ctx.option_bool("nuclei") is True
    assert ctx.option_bool("missing") is False
    assert ctx.cancelled() is False
    ctx.check_cancel()
    assert ctx.logs == [("warning", "hello")]


def test_satellite_config_roundtrip(tmp_path):
    config_path = tmp_path / "satellite.json"
    config = {
        "server": "https://master.example.com",
        "satellite_id": "sat_abc",
        "token": "secret-token",
        "name": "dmz-1",
        "cert_path": "",
        "key_path": "",
        "ca_path": "",
        "verify_tls": True,
        "poll_interval": 30,
        "subnets": ["10.30.0.0/16"],
    }
    save_config(config_path, config)
    loaded = load_config(config_path)
    assert loaded["token"] == "secret-token"
    assert loaded["subnets"] == ["10.30.0.0/16"]


def test_satellite_execute_rejects_unknown_type():
    from app.satellite import execute_job

    with pytest.raises(ValueError):
        execute_job({"scan_type": "ad", "target": "x"})


def test_satellites_api(api_client):
    pairing = api_client.post("/api/satellites/pairing")
    assert pairing.status_code == 200
    code = pairing.json()["code"]

    enrolled = api_client.post(
        "/api/satellite/pair",
        json={
            "pairing_code": code,
            "name": "dmz-1",
            "hostname": "dmz1.example.com",
            "platform": "linux",
            "version": "1.1.3",
            "subnets": ["10.30.0.0/16"],
        },
    )
    assert enrolled.status_code == 200, enrolled.text
    registration = enrolled.json()
    token = registration["token"]

    listed = api_client.get("/api/satellites")
    assert listed.status_code == 200
    assert any(item["id"] == registration["satellite_id"] for item in listed.json())

    headers = {"Authorization": f"Bearer {token}"}
    beat = api_client.post(
        "/api/satellite/heartbeat",
        json={"platform": "linux", "version": "1.1.3", "subnets": ["10.30.0.0/16"]},
        headers=headers,
    )
    assert beat.status_code == 200

    # A scan whose CIDR overlaps the satellite subnets is routed to it.
    customer = api_client.post("/api/customers", json={"name": "Satellite Customer"}).json()
    created = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "scan_type": "network",
            "target": "10.30.5.0/24",
            "executor": "auto",
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["status"] == "waiting_satellite"

    next_job = api_client.post("/api/satellite/jobs/next", json={}, headers=headers)
    assert next_job.status_code == 200
    job = next_job.json()["job"]
    assert job is not None
    assert job["scan_type"] == "network"

    result = api_client.post(
        f"/api/satellite/jobs/{job['job_id']}/result",
        json={"status": "completed", "results": {"findings": [], "metadata": {}}},
        headers=headers,
    )
    assert result.status_code == 200, result.text

    # Wrong satellite cannot claim another's job.
    wrong = api_client.post("/api/satellites/pairing").json()
    other = api_client.post(
        "/api/satellite/pair",
        json={"pairing_code": wrong["code"], "name": "other", "hostname": "x", "subnets": []},
    ).json()
    stolen = api_client.post(
        f"/api/satellite/jobs/{job['job_id']}/result",
        json={"status": "completed", "results": {}},
        headers={"Authorization": f"Bearer {other['token']}"},
    )
    assert stolen.status_code == 403

    revoked = api_client.delete(f"/api/satellites/{registration['satellite_id']}")
    assert revoked.status_code == 200
    assert api_client.post(
        "/api/satellite/heartbeat", json={}, headers=headers
    ).status_code == 401


def test_scan_rejects_satellite_for_other_types(api_client):
    pairing = api_client.post("/api/satellites/pairing").json()
    api_client.post(
        "/api/satellite/pair",
        json={"pairing_code": pairing["code"], "name": "s1", "hostname": "h", "subnets": []},
    )
    customer = api_client.post("/api/customers", json={"name": "Sat Types"}).json()
    created = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "scan_type": "domain",
            "target": "example.com",
            "executor": "sat_fake",
        },
    )
    assert created.status_code == 400
