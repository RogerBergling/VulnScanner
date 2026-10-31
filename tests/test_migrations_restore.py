"""Migration ledger and compatibility with older backups."""

from __future__ import annotations

import sqlite3

from app.database import SCHEMA, get_db, init_db


def test_fresh_database_has_migration_ledger(data_dir):
    with get_db() as conn:
        versions = [
            row[0] for row in conn.execute("SELECT version FROM schema_migrations")
        ]
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 5
    assert versions == [1, 2, 3, 4, 5]


def test_existing_v3_database_is_adopted(tmp_path, monkeypatch):
    database = tmp_path / "legacy.db"
    conn = sqlite3.connect(database)
    conn.executescript(SCHEMA)
    conn.execute("PRAGMA user_version = 3")
    conn.commit()
    conn.close()

    monkeypatch.setenv("VS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VS_DATABASE", str(database))
    init_db()
    with sqlite3.connect(database) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == 5
        tables = {
            row[0]
            for row in check.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert {"schema_migrations", "auth_sessions", "audit_log"} <= tables


def test_restore_upgrades_older_backup(api_client, monkeypatch, tmp_path):
    import app.api as api

    monkeypatch.setattr(api, "BASE_DIR", tmp_path)
    backup = api_client.post(
        "/api/server/database/backup",
        json={"destination": str(tmp_path / "older.db")},
    )
    assert backup.status_code == 201, backup.text
    path = backup.json()["path"]

    # Simulate a pre-migration-ledger backup that also lacks the tables added
    # in migrations 4 and 5.
    with sqlite3.connect(path) as conn:
        conn.execute("DROP TABLE IF EXISTS audit_log")
        conn.execute("DROP TABLE IF EXISTS notification_log")
        conn.execute("DROP TABLE IF EXISTS schema_migrations")
        conn.execute("PRAGMA user_version = 4")
        conn.commit()

    inspected = api_client.get(
        "/api/server/database/inspect", params={"path": path, "mode": "all"}
    )
    assert inspected.status_code == 200, inspected.text
    assert inspected.json()["upgrade_required"] is True
    assert "audit_log" in inspected.json()["missing_optional"]

    restored = api_client.post(
        "/api/server/database/restore", json={"path": path, "mode": "all"}
    )
    assert restored.status_code == 200, restored.text
    assert restored.json()["upgraded"] is True
    with get_db() as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert {"audit_log", "notification_log", "schema_migrations"} <= tables
