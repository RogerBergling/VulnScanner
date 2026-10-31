"""GUI database-location validation and relocation."""

from __future__ import annotations

import sqlite3

from app.config import data_dir, database_path


def test_storage_validation_rejects_unsafe_paths(api_client, tmp_path):
    relative = api_client.post(
        "/api/server/storage/validate", json={"data_dir": "relative/path"}
    )
    assert relative.status_code == 400

    root = api_client.post(
        "/api/server/storage/validate", json={"data_dir": "/"}
    )
    assert root.status_code == 400

    bad_suffix = api_client.post(
        "/api/server/storage/validate",
        json={"data_dir": str(tmp_path), "database_path": str(tmp_path / "x.txt")},
    )
    assert bad_suffix.status_code == 400


def test_relocate_database_and_data_directory(api_client, monkeypatch, tmp_path):
    import app.api as api

    env_file = tmp_path / "service.env"
    monkeypatch.setenv("VS_ENV_FILE", str(env_file))
    monkeypatch.setattr(api, "BASE_DIR", tmp_path)
    old_data = data_dir().resolve()
    old_db = database_path().resolve()
    new_data = tmp_path / "relocated-data"
    new_db = new_data / "vulnscanner.db"

    response = api_client.post(
        "/api/server/storage/relocate",
        json={
            "data_dir": str(new_data),
            "database_path": str(new_db),
            "copy_supporting_files": True,
            "overwrite": False,
            "force": False,
            "confirmation": "RELOCATE",
        },
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["database_path"] == str(new_db)
    assert result["restart_required"] is True
    assert new_db.is_file()
    assert old_db.is_file()
    assert env_file.is_file()
    env_text = env_file.read_text(encoding="utf-8")
    assert f"VS_DATA_DIR={new_data}" in env_text
    assert f"VS_DATABASE={new_db}" in env_text

    with sqlite3.connect(new_db) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0] > 0
    assert database_path().resolve() == new_db.resolve()
    assert data_dir().resolve() == new_data.resolve()

    status = api_client.get("/api/server/storage").json()
    assert status["database_path"] == str(new_db)
    assert status["data_dir"] == str(new_data)
    assert status["active_scans"] == 0

    # Restoring the environment for the rest of this test process is handled by
    # monkeypatch teardown; the old files are intentionally retained.
    assert old_data.is_dir()
