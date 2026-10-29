"""Tests for editing the listener bind address from the GUI/API."""

from __future__ import annotations

import os
import stat

import pytest

from app.config import HOST, PORT


def _use_temp_env(monkeypatch, tmp_path):
    """Redirect .env writes to a temporary directory and pin the active config."""
    import app.api as api

    monkeypatch.setattr(api, "BASE_DIR", tmp_path)
    monkeypatch.setenv("VS_HOST", HOST)
    monkeypatch.setenv("VS_PORT", str(PORT))
    return tmp_path / ".env"


def test_save_bind_address_writes_env_and_requires_restart(api_client, monkeypatch, tmp_path):
    env_path = _use_temp_env(monkeypatch, tmp_path)
    env_path.write_text(
        "VS_SSL=true\n"
        "VS_HOST=127.0.0.1\n"
        "VS_PORT=8765\n"
        "# keep this comment\n"
        "VS_ADMIN_PASSWORD=secret-value-123\n",
        encoding="utf-8",
    )
    new_host = "0.0.0.0" if HOST != "0.0.0.0" else "::"
    new_port = 9000 if PORT != 9000 else 9001

    response = api_client.post(
        "/api/settings/network",
        json={"bind_host": new_host, "bind_port": new_port},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["bind_host"] == new_host
    assert data["bind_port"] == new_port
    assert data["active_bind_host"] == HOST
    assert data["active_bind_port"] == PORT
    assert data["restart_required"] is True

    text = env_path.read_text(encoding="utf-8")
    assert f"VS_HOST={new_host}" in text
    assert f"VS_PORT={new_port}" in text
    assert "VS_SSL=true" in text
    assert "# keep this comment" in text
    assert "VS_ADMIN_PASSWORD=secret-value-123" in text
    assert text.count("VS_HOST=") == 1
    assert text.count("VS_PORT=") == 1
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600

    # The UI reads these values back before the restart, so they must reflect
    # the saved configuration while the active bind still shows the running one.
    settings = api_client.get("/api/settings").json()
    assert settings["bind_host"] == new_host
    assert settings["bind_port"] == new_port
    assert settings["active_bind_host"] == HOST
    assert settings["active_bind_port"] == PORT
    assert settings["bind_restart_required"] is True
    assert os.environ["VS_HOST"] == new_host
    assert os.environ["VS_PORT"] == str(new_port)


def test_save_bind_address_creates_env_when_missing(api_client, monkeypatch, tmp_path):
    env_path = _use_temp_env(monkeypatch, tmp_path)
    assert not env_path.exists()

    response = api_client.post(
        "/api/settings/network",
        json={"bind_host": "::1", "bind_port": 9443},
    )
    assert response.status_code == 200, response.text
    assert response.json()["bind_host"] == "::1"

    text = env_path.read_text(encoding="utf-8")
    assert "VS_HOST=::1" in text
    assert "VS_PORT=9443" in text
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "payload",
    [
        {"bind_host": "localhost", "bind_port": 8765},
        {"bind_host": "127.0.0.1; touch /tmp/owned", "bind_port": 8765},
        {"bind_host": "127.0.0.1\nVS_SSL=false", "bind_port": 8765},
        {"bind_host": "", "bind_port": 8765},
        {"bind_host": "127.0.0.1", "bind_port": 0},
        {"bind_host": "127.0.0.1", "bind_port": 65_536},
        {"bind_host": "127.0.0.1"},
    ],
)
def test_rejects_invalid_bind_address(api_client, monkeypatch, tmp_path, payload):
    env_path = _use_temp_env(monkeypatch, tmp_path)

    response = api_client.post("/api/settings/network", json=payload)
    assert response.status_code == 422
    assert not env_path.exists()


def test_admin_password_update_still_preserves_other_env_entries(api_client, monkeypatch, tmp_path):
    env_path = _use_temp_env(monkeypatch, tmp_path)
    monkeypatch.setenv("VS_ADMIN_PASSWORD", "old-value-1234")
    env_path.write_text(
        "VS_HOST=127.0.0.1\nVS_ADMIN_PASSWORD=old-value-1234\n",
        encoding="utf-8",
    )

    response = api_client.post(
        "/api/settings/admin-password",
        json={"password": "a-new-password-123"},
        auth=("admin", "old-value-1234"),
    )
    assert response.status_code == 200, response.text

    text = env_path.read_text(encoding="utf-8")
    assert "VS_ADMIN_PASSWORD=\n" in text or text.endswith("VS_ADMIN_PASSWORD=")
    assert text.count("VS_ADMIN_PASSWORD=") == 1
    assert "VS_HOST=127.0.0.1" in text
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600

    from app.database import get_setting

    stored = get_setting("admin_password_hash", "")
    assert stored.startswith("pbkdf2_sha256$")
    assert "a-new-password-123" not in stored
    assert "VS_ADMIN_PASSWORD" not in os.environ
    assert api_client.get(
        "/api/customers", auth=("admin", "a-new-password-123")
    ).status_code == 200
