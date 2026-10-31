"""Shared test fixtures.

Tests are local and offline by default.  The environment is configured before
application modules are imported so that no test can accidentally call OSV.dev,
CISA or GitHub.
"""

from __future__ import annotations

import os

os.environ["VS_ENABLE_EXTERNAL_APIS"] = "false"
os.environ["VS_LOG_LEVEL"] = "CRITICAL"
os.environ["VS_SKIP_DOTENV"] = "1"
os.environ.pop("VS_ADMIN_PASSWORD", None)

import pytest


@pytest.fixture(scope="session", autouse=True)
def _preserve_repo_env_file():
    """Never let the test suite modify or leave a developer's real .env file."""
    from pathlib import Path

    path = Path(__file__).resolve().parent.parent / ".env"
    original = path.read_bytes() if path.is_file() else None
    yield
    if original is None:
        path.unlink(missing_ok=True)
    else:
        path.write_bytes(original)
        try:
            path.chmod(0o600)
        except OSError:
            pass


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    from app.rate_limit import reset_rate_limits

    reset_rate_limits()
    yield
    reset_rate_limits()


@pytest.fixture()
def data_dir(tmp_path, monkeypatch):
    directory = tmp_path / "data"
    directory.mkdir()
    monkeypatch.setenv("VS_DATA_DIR", str(directory))
    monkeypatch.setenv("VS_DATABASE", str(directory / "vulnscanner.db"))
    monkeypatch.delenv("VS_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("VS_ADMIN_USER", raising=False)
    from app.database import init_db

    init_db()
    return directory


@pytest.fixture()
def client(data_dir):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def api_client(client, monkeypatch):
    """Test client with background scan submission disabled.

    Tests call the executor functions directly when they need a completed scan,
    which keeps assertions deterministic and avoids worker races.
    """
    import app.api as api

    monkeypatch.setattr(api, "submit_scan", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(api, "submit_agent_result", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(api, "submit_ad_import", lambda *_args, **_kwargs: None)
    return client


@pytest.fixture()
def customer(api_client):
    response = api_client.post("/api/customers", json={"name": "Acme", "description": "Test customer"})
    assert response.status_code == 201, response.text
    data = response.json()
    detail = api_client.get(f"/api/customers/{data['id']}").json()
    return {
        "id": data["id"],
        "group_id": detail["groups"][0]["id"],
        "customer": data,
    }
