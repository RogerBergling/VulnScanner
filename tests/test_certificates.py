"""Certificate management API tests."""

from __future__ import annotations

import stat

import pytest


def _configure_cert_dir(monkeypatch, tmp_path):
    """Point app.certs at a temporary directory for the duration of a test."""
    import app.certs as certs

    root = tmp_path / "certs"
    internal = root / "internal"
    paths = {
        "CERT_DIR": root,
        "CERT_FILE": root / "server.crt",
        "KEY_FILE": root / "server.key",
        "WEB_CERT_FILE": root / "server.crt",
        "WEB_KEY_FILE": root / "server.key",
        "INTERNAL_DIR": internal,
        "INTERNAL_CERT_FILE": internal / "ca.crt",
        "INTERNAL_SERVER_CERT": internal / "server.crt",
        "INTERNAL_SERVER_KEY": internal / "server.key",
        "INTERNAL_CA_KEY": internal / "ca.key",
    }
    for name, value in paths.items():
        monkeypatch.setattr(certs, name, value)
    return paths


def test_regenerate_internal_accepts_json_body(client, monkeypatch, tmp_path):
    paths = _configure_cert_dir(monkeypatch, tmp_path)

    response = client.post("/api/certs/regenerate", json={"mode": "internal"})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["mode"] == "internal"
    assert data["targets"] == ["internal"]

    assert paths["INTERNAL_CERT_FILE"].is_file()
    assert paths["INTERNAL_SERVER_CERT"].is_file()
    assert paths["INTERNAL_SERVER_KEY"].is_file()
    assert paths["INTERNAL_CA_KEY"].is_file()
    assert not paths["WEB_CERT_FILE"].exists()

    assert stat.S_IMODE(paths["INTERNAL_CA_KEY"].stat().st_mode) == 0o600
    assert stat.S_IMODE(paths["INTERNAL_SERVER_KEY"].stat().st_mode) == 0o600
    assert stat.S_IMODE(paths["INTERNAL_CERT_FILE"].stat().st_mode) == 0o644

    status = client.get("/api/certs/status").json()
    assert status["internal"]["exists"] is True
    assert status["internal"]["ca_path"] == str(paths["INTERNAL_CERT_FILE"])


def test_regenerate_query_mode_all_creates_both_sets(client, monkeypatch, tmp_path):
    paths = _configure_cert_dir(monkeypatch, tmp_path)

    response = client.post("/api/certs/regenerate?mode=all")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["mode"] == "all"
    assert data["targets"] == ["web", "internal"]
    assert set(data) >= {"web", "internal"}

    assert paths["WEB_CERT_FILE"].is_file()
    assert paths["WEB_KEY_FILE"].is_file()
    assert paths["INTERNAL_SERVER_CERT"].is_file()
    assert paths["INTERNAL_CA_KEY"].is_file()
    assert stat.S_IMODE(paths["WEB_KEY_FILE"].stat().st_mode) == 0o600


def test_regenerate_rejects_unknown_mode(client, monkeypatch, tmp_path):
    _configure_cert_dir(monkeypatch, tmp_path)

    assert client.post("/api/certs/regenerate?mode=bogus").status_code == 400
    assert client.post("/api/certs/regenerate", json={"mode": "bogus"}).status_code == 400


def test_upload_internal_uses_multipart_mode(client, monkeypatch, tmp_path):
    import app.certs as certs

    paths = _configure_cert_dir(monkeypatch, tmp_path)
    certs._generate_self_signed(paths["WEB_CERT_FILE"], paths["WEB_KEY_FILE"])
    certs._generate_internal_ca()

    web_cert_before = paths["WEB_CERT_FILE"].read_bytes()
    internal_cert_before = paths["INTERNAL_SERVER_CERT"].read_bytes()
    internal_key_before = paths["INTERNAL_SERVER_KEY"].read_bytes()

    response = client.post(
        "/api/certs/upload",
        data={"mode": "internal"},
        files={
            "cert_file": ("server.crt", internal_cert_before, "application/x-pem-file"),
            "key_file": ("server.key", internal_key_before, "application/x-pem-file"),
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["mode"] == "internal"
    assert paths["INTERNAL_SERVER_CERT"].read_bytes() == internal_cert_before
    assert paths["INTERNAL_SERVER_KEY"].read_bytes() == internal_key_before
    assert paths["WEB_CERT_FILE"].read_bytes() == web_cert_before
    assert stat.S_IMODE(paths["INTERNAL_SERVER_KEY"].stat().st_mode) == 0o600


def test_upload_rejects_unknown_mode(client, monkeypatch, tmp_path):
    import app.certs as certs

    paths = _configure_cert_dir(monkeypatch, tmp_path)
    certs._generate_internal_ca()

    response = client.post(
        "/api/certs/upload",
        data={"mode": "bogus"},
        files={
            "cert_file": ("server.crt", paths["INTERNAL_SERVER_CERT"].read_bytes(), "application/x-pem-file"),
            "key_file": ("server.key", paths["INTERNAL_SERVER_KEY"].read_bytes(), "application/x-pem-file"),
        },
    )
    assert response.status_code == 400


@pytest.mark.parametrize("mode", ["web", "internal", "all"])
def test_regenerate_modes_create_expected_files(client, monkeypatch, tmp_path, mode):
    paths = _configure_cert_dir(monkeypatch, tmp_path)

    response = client.post(f"/api/certs/regenerate?mode={mode}")
    assert response.status_code == 200, response.text
    assert response.json()["targets"] == (["web", "internal"] if mode == "all" else [mode])

    assert paths["WEB_CERT_FILE"].exists() is (mode in {"web", "all"})
    assert paths["INTERNAL_SERVER_CERT"].exists() is (mode in {"internal", "all"})
