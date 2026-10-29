"""Database backup destination and selective restore tests."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from app.database import get_db, get_setting, utcnow


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


def _scan(api_client, customer, target="https://example.test"):
    asset = _asset(api_client, customer)
    response = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "asset_id": asset["id"],
            "scan_type": "web",
            "target": target,
        },
    )
    assert response.status_code == 201, response.text
    scan_id = response.json()["id"]
    with get_db() as conn:
        conn.execute(
            "UPDATE scans SET status = 'completed', progress = 100, "
            "stage = 'Completed', started_at = ?, completed_at = ? WHERE id = ?",
            (utcnow(), utcnow(), scan_id),
        )
        conn.execute(
            "INSERT INTO findings("
            "scan_id, customer_id, asset_id, severity, category, title, description, "
            "evidence, remediation, cve, cwe, cvss, location, resource, fingerprint, "
            "status, first_seen, last_seen, raw"
            ") VALUES (?, ?, ?, 'high', 'web', 'Restore test', '', '', '', '', '', NULL, "
            "'', '', ?, 'open', ?, ?, '{}')",
            (scan_id, customer["id"], asset["id"], f"fp-{scan_id}", utcnow(), utcnow()),
        )
        conn.commit()
    return scan_id, asset


def _backup(api_client, destination):
    response = api_client.post(
        "/api/server/database/backup", json={"destination": str(destination)}
    )
    assert response.status_code == 201, response.text
    return response.json()


def _backup_with_auth(api_client, destination, auth):
    response = api_client.post(
        "/api/server/database/backup",
        json={"destination": str(destination)},
        auth=auth,
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_backup_destination_and_settings_are_in_database(
    api_client, customer, monkeypatch, tmp_path
):
    import app.api as api
    from app.config import TOOL_PATHS

    monkeypatch.setattr(api, "BASE_DIR", tmp_path)
    original_paths = dict(TOOL_PATHS)
    original_env = dict(os.environ)
    try:
        fake_nmap = tmp_path / "nmap"
        fake_nmap.write_text("#!/bin/sh\necho 'Nmap version 9.9'\n", encoding="utf-8")
        fake_nmap.chmod(0o755)

        assert api_client.patch("/api/settings", json={"max_scan_files": 4321}).status_code == 200
        assert api_client.post(
            "/api/settings/tools", json={"paths": {"nmap": str(fake_nmap)}}
        ).status_code == 200
        assert api_client.post(
            "/api/settings/network",
            json={"bind_host": "127.0.0.1", "bind_port": 9443, "ssl_enabled": False},
        ).status_code == 200

        with get_db() as conn:
            values = {
                row["key"]: row["value"]
                for row in conn.execute(
                    "SELECT key, value FROM settings WHERE key IN "
                    "('max_scan_files', 'tool_paths', 'bind_host', 'bind_port', 'ssl_enabled')"
                )
            }
        assert values["max_scan_files"] == "4321"
        assert str(fake_nmap) in values["tool_paths"]
        assert values["bind_host"] == "127.0.0.1"
        assert values["bind_port"] == "9443"
        assert values["ssl_enabled"] == "false"

        destination = tmp_path / "chosen-backups"
        payload = _backup(api_client, destination)
        backup_path = Path(payload["path"])
        assert backup_path.parent == destination
        assert backup_path.exists()
        assert payload["size"] > 0

        with sqlite3.connect(backup_path) as conn:
            keys = {
                row[0]
                for row in conn.execute(
                    "SELECT key FROM settings WHERE key IN "
                    "('max_scan_files', 'tool_paths', 'bind_host', 'bind_port', 'ssl_enabled')"
                )
            }
        assert keys == {
            "max_scan_files",
            "tool_paths",
            "bind_host",
            "bind_port",
            "ssl_enabled",
        }

        listed = api_client.get(
            "/api/server/database/backups", params={"directory": str(destination)}
        )
        assert listed.status_code == 200, listed.text
        assert any(item["path"] == str(backup_path) for item in listed.json()["backups"])
    finally:
        TOOL_PATHS.clear()
        TOOL_PATHS.update(original_paths)
        os.environ.clear()
        os.environ.update(original_env)


def test_restore_all_restores_scans_and_settings(api_client, customer, monkeypatch, tmp_path):
    import app.api as api

    monkeypatch.setattr(api, "BASE_DIR", tmp_path)
    original_env = dict(os.environ)
    try:
        scan_id, _asset_row = _scan(api_client, customer)
        api_client.patch("/api/settings", json={"max_scan_files": 1111})
        backup = _backup(api_client, tmp_path / "all.db")

        api_client.patch("/api/settings", json={"max_scan_files": 2222})
        extra = api_client.post("/api/customers", json={"name": "Extra"}).json()
        with get_db() as conn:
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()

        response = api_client.post(
            "/api/server/database/restore",
            json={"path": backup["path"], "mode": "all"},
        )
        assert response.status_code == 200, response.text
        result = response.json()
        assert result["mode"] == "all"
        assert Path(result["safety_backup"]).exists()
        assert result["counts"]["scans"] == 1
        assert result["counts"]["findings"] == 1

        assert get_setting("max_scan_files", "") == "1111"
        customers = api_client.get("/api/customers").json()
        assert {item["name"] for item in customers} == {"Acme"}
        assert api_client.get(f"/api/scans/{scan_id}").status_code == 200
        assert api_client.get(f"/api/customers/{extra['id']}").status_code == 404
        status = api_client.get("/api/server/status").json()
        assert status["last_restore_mode"] == "all"
        assert status["last_restore_source"] == backup["path"]
        assert status["last_restore_safety_backup"] == result["safety_backup"]
    finally:
        os.environ.clear()
        os.environ.update(original_env)


def test_restore_all_restores_admin_password_and_tool_paths(
    api_client, monkeypatch, tmp_path
):
    import app.api as api
    from app.config import TOOL_PATHS

    monkeypatch.setattr(api, "BASE_DIR", tmp_path)
    original_paths = dict(TOOL_PATHS)
    original_env = dict(os.environ)
    try:
        fake_nmap = tmp_path / "nmap"
        fake_nmap.write_text("#!/bin/sh\necho 'Nmap version 9.9'\n", encoding="utf-8")
        fake_nmap.chmod(0o755)
        assert api_client.post(
            "/api/settings/tools", json={"paths": {"nmap": str(fake_nmap)}}
        ).status_code == 200
        assert api_client.post(
            "/api/settings/admin-password",
            json={"password": "first-password-123"},
        ).status_code == 200
        backup = _backup_with_auth(
            api_client, tmp_path / "settings-all.db", ("admin", "first-password-123")
        )

        changed = api_client.post(
            "/api/settings/admin-password",
            json={"password": "second-password-456"},
            auth=("admin", "first-password-123"),
        )
        assert changed.status_code == 200, changed.text
        assert api_client.post(
            "/api/settings/tools", json={"paths": {"nmap": ""}},
            auth=("admin", "second-password-456"),
        ).status_code == 200

        restored = api_client.post(
            "/api/server/database/restore",
            json={"path": backup["path"], "mode": "all"},
            auth=("admin", "second-password-456"),
        )
        assert restored.status_code == 200, restored.text
        assert api_client.get(
            "/api/settings", auth=("admin", "first-password-123")
        ).status_code == 200
        assert api_client.get(
            "/api/settings", auth=("admin", "second-password-456")
        ).status_code == 401
        assert TOOL_PATHS["nmap"] == str(fake_nmap)
    finally:
        TOOL_PATHS.clear()
        TOOL_PATHS.update(original_paths)
        os.environ.clear()
        os.environ.update(original_env)


def test_restore_scans_only_preserves_settings_and_current_customers(
    api_client, customer, monkeypatch, tmp_path
):
    import app.api as api

    monkeypatch.setattr(api, "BASE_DIR", tmp_path)
    original_env = dict(os.environ)
    try:
        _scan(api_client, customer)
        backup = _backup(api_client, tmp_path / "scans.db")
        api_client.patch("/api/settings", json={"max_scan_files": 3333})
        extra = api_client.post("/api/customers", json={"name": "Keep Me"}).json()

        response = api_client.post(
            "/api/server/database/restore",
            json={"path": backup["path"], "mode": "scans"},
        )
        assert response.status_code == 200, response.text
        assert get_setting("max_scan_files", "") == "3333"
        customers = api_client.get("/api/customers").json()
        assert {"Acme", "Keep Me"} <= {item["name"] for item in customers}
        assert api_client.get(f"/api/customers/{extra['id']}").status_code == 200
        scans = api_client.get("/api/scans").json()
        assert scans["total"] == 1
        assert scans["items"][0]["target"] == "https://example.test"
        detail = api_client.get(f"/api/scans/{scans['items'][0]['id']}").json()
        assert detail["finding_count"] == 1
    finally:
        os.environ.clear()
        os.environ.update(original_env)


def test_restore_settings_only_keeps_current_scans(api_client, customer, monkeypatch, tmp_path):
    import app.api as api

    monkeypatch.setattr(api, "BASE_DIR", tmp_path)
    original_env = dict(os.environ)
    try:
        scan_id, _asset_row = _scan(api_client, customer)
        api_client.patch("/api/settings", json={"max_scan_files": 4444})
        backup = _backup(api_client, tmp_path / "settings.db")
        api_client.patch("/api/settings", json={"max_scan_files": 5555})

        response = api_client.post(
            "/api/server/database/restore",
            json={"path": backup["path"], "mode": "settings"},
        )
        assert response.status_code == 200, response.text
        assert get_setting("max_scan_files", "") == "4444"
        assert api_client.get(f"/api/scans/{scan_id}").status_code == 200
    finally:
        os.environ.clear()
        os.environ.update(original_env)


def test_restore_scan_data_rejects_active_scans(
    api_client, customer, monkeypatch, tmp_path
):
    import app.api as api

    monkeypatch.setattr(api, "BASE_DIR", tmp_path)
    backup = _backup(api_client, tmp_path / "active.db")
    response = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "scan_type": "web",
            "target": "https://example.test",
        },
    )
    assert response.status_code == 201, response.text

    restore = api_client.post(
        "/api/server/database/restore",
        json={"path": backup["path"], "mode": "scans"},
    )
    assert restore.status_code == 400
    assert "active scans" in restore.json()["detail"]


def test_restore_rejects_invalid_and_newer_backups(api_client, data_dir, tmp_path):
    invalid = tmp_path / "invalid.db"
    invalid.write_text("not a database", encoding="utf-8")
    response = api_client.post(
        "/api/server/database/restore", json={"path": str(invalid), "mode": "all"}
    )
    assert response.status_code == 400

    newer = tmp_path / "newer.db"
    with sqlite3.connect(newer) as conn:
        conn.execute("CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("PRAGMA user_version = 999")
    response = api_client.post(
        "/api/server/database/restore", json={"path": str(newer), "mode": "all"}
    )
    assert response.status_code == 400
    assert "newer" in response.json()["detail"]


def test_backup_refuses_to_overwrite_without_confirmation(api_client, tmp_path):
    target = tmp_path / "fixed.db"
    target.write_bytes(b"existing")
    response = api_client.post(
        "/api/server/database/backup",
        json={"destination": str(target), "overwrite": False},
    )
    assert response.status_code == 409

    response = api_client.post(
        "/api/server/database/backup",
        json={"destination": str(target), "overwrite": True},
    )
    assert response.status_code == 201, response.text
    with sqlite3.connect(target) as conn:
        assert conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0] > 0
