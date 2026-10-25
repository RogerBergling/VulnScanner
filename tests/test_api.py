"""End-to-end tests for the HTTP API and SPA entry points."""

from __future__ import annotations

from pathlib import Path


def test_health_meta_and_dashboard(client):
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.json()["product"] == "VulnScanner"
    assert health.headers["x-content-type-options"] == "nosniff"

    meta = client.get("/api/meta").json()
    assert {item["id"] for item in meta["scan_types"]} == {
        "web",
        "network",
        "repo",
        "github",
        "ad",
    }
    assert "system" in {item["id"] for item in meta["agent_modules"]}

    dashboard = client.get("/api/dashboard")
    assert dashboard.status_code == 200
    data = dashboard.json()
    assert data["counts"]["customers"] == 0
    assert data["severity"]["total"] == 0
    assert data["recent_scans"] == []
    assert data["trend"] == []


def test_spa_index_manual_and_security_headers(client):
    index = client.get("/")
    assert index.status_code == 200
    assert "VulnScanner" in index.text
    assert "script-src 'self'" in index.headers["content-security-policy"]
    assert index.headers["x-frame-options"] == "DENY"

    manual = client.get("/manual")
    assert manual.status_code == 200
    assert "VulnScanner" in manual.text
    assert manual.headers["content-type"].startswith("text/markdown")

    assert client.get("/favicon.ico").status_code == 204


def test_agent_downloads_are_allow_listed(client):
    allowed = client.get("/agent/download/install-linux.sh")
    assert allowed.status_code == 200
    assert "attachment" in allowed.headers["content-disposition"]

    assert client.get("/agent/download/../app/main.py").status_code == 404
    assert client.get("/agent/download/unknown.txt").status_code == 404


def test_customer_group_and_asset_crud(api_client):
    created = api_client.post("/api/customers", json={"name": "Globex", "description": "Unit test"})
    assert created.status_code == 201, created.text
    customer = created.json()
    customer_id = customer["id"]
    assert customer["name"] == "Globex"
    assert customer["severity"]["total"] == 0

    duplicate = api_client.post("/api/customers", json={"name": "globex"})
    assert duplicate.status_code == 409

    listing = api_client.get("/api/customers").json()
    assert [item["name"] for item in listing] == ["Globex"]

    detail = api_client.get(f"/api/customers/{customer_id}").json()
    assert len(detail["groups"]) == 1
    default_group = detail["groups"][0]
    assert default_group["name"] == "General"
    assert detail["scan_count"] == 0

    group = api_client.post(
        f"/api/customers/{customer_id}/groups",
        json={"name": "webserver", "description": "Internet-facing"},
    )
    assert group.status_code == 201, group.text
    group_id = group.json()["id"]
    assert api_client.post(
        f"/api/customers/{customer_id}/groups", json={"name": "WebServer"}
    ).status_code == 409

    patched_group = api_client.patch(
        f"/api/groups/{group_id}", json={"description": "DMZ"}
    )
    assert patched_group.status_code == 200
    assert patched_group.json()["description"] == "DMZ"

    asset = api_client.post(
        f"/api/groups/{group_id}/assets",
        json={
            "name": "www01",
            "kind": "web",
            "identifier": "https://www.example.test",
            "metadata": {"owner": "web"},
        },
    )
    assert asset.status_code == 201, asset.text
    asset_id = asset.json()["id"]
    assert asset.json()["metadata"] == {"owner": "web"}
    assert api_client.post(
        f"/api/groups/{group_id}/assets", json={"name": "www01"}
    ).status_code == 409

    patched_asset = api_client.patch(
        f"/api/assets/{asset_id}", json={"description": "Primary", "metadata": {"tier": 1}}
    )
    assert patched_asset.status_code == 200
    assert patched_asset.json()["metadata"] == {"tier": 1}

    asset_detail = api_client.get(f"/api/assets/{asset_id}").json()
    assert asset_detail["group"]["id"] == group_id
    assert asset_detail["customer"]["id"] == customer_id
    assert asset_detail["latest_findings"] == []

    renamed = api_client.patch(f"/api/customers/{customer_id}", json={"name": "Globex Corp"})
    assert renamed.status_code == 200
    assert renamed.json()["name"] == "Globex Corp"

    assert api_client.get("/api/customers/99999").status_code == 404
    assert api_client.get("/api/assets/99999").status_code == 404
    assert api_client.patch("/api/groups/99999", json={"name": "x"}).status_code == 404

    deleted_asset = api_client.delete(f"/api/assets/{asset_id}")
    assert deleted_asset.status_code == 200
    assert api_client.get(f"/api/assets/{asset_id}").status_code == 404

    deleted_group = api_client.delete(f"/api/groups/{group_id}")
    assert deleted_group.status_code == 200
    assert api_client.get(f"/api/groups/{group_id}").status_code == 404

    deleted_customer = api_client.delete(f"/api/customers/{customer_id}")
    assert deleted_customer.status_code == 200
    assert api_client.get(f"/api/customers/{customer_id}").status_code == 404


def test_scan_creation_validation_and_listing(api_client, customer):
    customer_id = customer["id"]
    group_id = customer["group_id"]

    missing_target = api_client.post(
        "/api/scans", json={"customer_id": customer_id, "scan_type": "web", "target": ""}
    )
    assert missing_target.status_code == 422

    bad_url = api_client.post(
        "/api/scans",
        json={"customer_id": customer_id, "scan_type": "web", "target": "not a url"},
    )
    assert bad_url.status_code == 400

    bad_host = api_client.post(
        "/api/scans",
        json={"customer_id": customer_id, "scan_type": "network", "target": "bad host"},
    )
    assert bad_host.status_code == 400

    bad_profile = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer_id,
            "scan_type": "network",
            "target": "192.0.2.10",
            "options": {"profile": "every-port"},
        },
    )
    assert bad_profile.status_code == 400

    scan = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer_id,
            "group_id": group_id,
            "scan_type": "network",
            "target": "192.0.2.10",
            "options": {"ports": "22,80", "profile": "web", "connect_timeout": 0.25},
        },
    )
    assert scan.status_code == 201, scan.text
    data = scan.json()
    assert data["status"] == "queued"
    assert data["target"] == "192.0.2.10"
    assert data["options"]["ports"] == "22,80"
    assert data["customer_name"] == "Acme"
    assert data["group_name"] == "General"
    assert data["events"][0]["message"].startswith("network scan queued")

    web_scan = api_client.post(
        "/api/scans",
        json={"customer_id": customer_id, "scan_type": "web", "target": "example.test"},
    )
    assert web_scan.status_code == 201
    assert web_scan.json()["target"] == "https://example.test"

    ad_missing = api_client.post(
        "/api/scans",
        json={"customer_id": customer_id, "scan_type": "ad", "target": "/missing/report.json"},
    )
    assert ad_missing.status_code == 400

    listing = api_client.get(f"/api/scans?customer_id={customer_id}")
    assert listing.status_code == 200
    assert listing.json()["total"] == 2
    assert listing.json()["limit"] == 50

    filtered = api_client.get(f"/api/scans?customer_id={customer_id}&scan_type=web")
    assert filtered.json()["total"] == 1
    assert filtered.json()["items"][0]["scan_type"] == "web"

    search = api_client.get(f"/api/scans?q=example.test")
    assert search.json()["total"] == 1

    active = api_client.get(f"/api/scans?customer_id={customer_id}&active=true")
    assert active.json()["total"] == 2

    assert api_client.get("/api/scans/99999").status_code == 404

    queued_delete = api_client.delete(f"/api/scans/{data['id']}")
    assert queued_delete.status_code == 409


def test_scan_cancel_rescan_and_delete(api_client, customer):
    customer_id = customer["id"]
    scan = api_client.post(
        "/api/scans",
        json={"customer_id": customer_id, "scan_type": "network", "target": "192.0.2.20"},
    ).json()

    cancelled = api_client.post(f"/api/scans/{scan['id']}/cancel")
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    assert cancelled.json()["progress"] == 100
    assert cancelled.json()["cancelled"] == 1

    again = api_client.post(f"/api/scans/{scan['id']}/cancel")
    assert again.status_code == 409

    rescan = api_client.post(f"/api/scans/{scan['id']}/rescan")
    assert rescan.status_code == 201, rescan.text
    new_scan = rescan.json()
    assert new_scan["id"] != scan["id"]
    assert new_scan["status"] == "queued"
    assert new_scan["target"] == "192.0.2.20"

    deleted = api_client.delete(f"/api/scans/{new_scan['id']}")
    assert deleted.status_code == 409
    api_client.post(f"/api/scans/{new_scan['id']}/cancel")
    assert api_client.delete(f"/api/scans/{new_scan['id']}").status_code == 200

    assert api_client.post("/api/scans/99999/cancel").status_code == 404
    assert api_client.delete("/api/scans/99999").status_code == 404


def test_ad_import_endpoint(api_client, customer):
    report = {
        "domain": {"name": "corp.example"},
        "guest_enabled": True,
        "password_policy": {"min_length": 6},
        "findings": [{"severity": "high", "title": "Imported issue", "key": "imported"}],
    }
    response = api_client.post(
        "/api/ad/import",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "report": report,
        },
    )
    assert response.status_code == 201, response.text
    scan = response.json()
    assert scan["scan_type"] == "ad"
    assert scan["status"] == "queued"
    assert scan["target"] == "AD audit: corp.example"
    assert scan["requested_by"] == "ad-import"

    mismatched = api_client.post(
        "/api/ad/import",
        json={"customer_id": customer["id"], "group_id": 99999, "report": report},
    )
    assert mismatched.status_code == 404


def test_settings_get_and_update(api_client):
    settings = api_client.get("/api/settings")
    assert settings.status_code == 200
    data = settings.json()
    assert data["product"] == "VulnScanner"
    assert data["database_path"].endswith("vulnscanner.db")
    assert "tools" in data
    assert data["limits"]["top_ports"] == 58

    updated = api_client.patch(
        "/api/settings",
        json={"allow_external_apis": False, "nuclei_enabled": False},
    )
    assert updated.status_code == 200
    data = updated.json()
    assert data["allow_external_apis"] is False
    assert data["nuclei_enabled"] is False
    assert data["nmap_enabled"] is True

    # External APIs are disabled in the test environment, so KEV sync must be
    # refused instead of making an outbound request.
    assert api_client.post("/api/settings/kev/sync").status_code == 400

    enabled = api_client.patch("/api/settings", json={"nuclei_enabled": True})
    assert enabled.json()["nuclei_enabled"] is True


def test_openapi_document_lists_all_major_routes(client):
    document = client.get("/api/openapi.json")
    assert document.status_code == 200
    paths = document.json()["paths"]
    for path in (
        "/api/customers",
        "/api/scans",
        "/api/findings/{finding_id}",
        "/api/agents",
        "/api/agents/{agent_id}",
        "/api/agents/{agent_id}/rotate-token",
        "/api/agent/enroll",
        "/api/ad/import",
        "/api/settings",
        "/api/server/status",
        "/api/server/database/backup",
        "/api/server/database/vacuum",
    ):
        assert path in paths


def test_server_status_backup_and_vacuum(api_client, customer, data_dir):
    status = api_client.get("/api/server/status")
    assert status.status_code == 200, status.text
    data = status.json()
    assert data["product"] == "VulnScanner"
    assert data["status"] == "ok"
    assert data["database"]["integrity"] == "ok"
    assert data["database"]["path"].endswith("vulnscanner.db")
    assert data["database"]["schema_version"] >= 1
    assert data["counts"]["customers"] == 1
    assert data["counts"]["agents"] == 0
    assert "checks" in data and data["checks"]
    assert {check["id"] for check in data["checks"]} >= {
        "database", "data", "reports", "auth", "external_apis", "workers"
    }
    assert data["process"]["port"] > 0
    assert data["uptime_seconds"] >= 0
    assert "tools" in data
    assert data["settings"]["allow_external_apis"] is True

    backup = api_client.post("/api/server/database/backup")
    assert backup.status_code == 201, backup.text
    payload = backup.json()
    assert payload["ok"] is True
    assert payload["size"] > 0
    backup_path = payload["path"]
    assert backup_path.startswith(str(data_dir))
    import sqlite3
    from pathlib import Path

    assert Path(backup_path).exists()
    with sqlite3.connect(backup_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0] == 1

    vacuum = api_client.post("/api/server/database/vacuum")
    assert vacuum.status_code == 200, vacuum.text
    assert vacuum.json()["after"] >= 0
    refreshed = api_client.get("/api/server/status").json()
    assert refreshed["last_backup_at"]
    assert refreshed["last_backup_path"] == backup_path

