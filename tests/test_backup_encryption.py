"""API tests for encrypted backup creation and inspection."""

def test_encrypted_backup_and_inspect(api_client, data_dir):
    response = api_client.post(
        "/api/server/database/backup",
        json={"passphrase": "backup-passphrase"},
    )
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["encrypted"] is True
    assert result["path"].endswith(".vsenc")

    inspected = api_client.get(
        "/api/server/database/inspect",
        params={"path": result["path"], "mode": "settings"},
        headers={"X-Backup-Passphrase": "backup-passphrase"},
    )
    assert inspected.status_code == 200, inspected.text
    assert inspected.json()["encrypted"] is True


def test_encrypted_backup_requires_passphrase_to_inspect(api_client, data_dir):
    response = api_client.post(
        "/api/server/database/backup",
        json={"passphrase": "backup-passphrase"},
    )
    path = response.json()["path"]
    inspected = api_client.get(
        "/api/server/database/inspect", params={"path": path, "mode": "settings"}
    )
    assert inspected.status_code == 400
    assert "passphrase" in inspected.text.lower()


def test_encrypted_backup_can_be_restored(api_client, data_dir):
    backup = api_client.post(
        "/api/server/database/backup",
        json={"passphrase": "backup-passphrase"},
    ).json()
    restored = api_client.post(
        "/api/server/database/restore",
        json={
            "path": backup["path"],
            "mode": "settings",
            "passphrase": "backup-passphrase",
        },
    )
    assert restored.status_code == 200, restored.text
    assert restored.json()["source"] == backup["path"]
    assert api_client.get("/api/health").status_code == 200
