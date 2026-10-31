"""Settings GUI/API coverage for notifications, guardrails and runtime options."""

from __future__ import annotations

import os

from app.config import get_limit
from app.database import get_setting


def test_settings_expose_gui_configuration(api_client):
    settings = api_client.get("/api/settings").json()
    for key in (
        "data_dir",
        "env_file_path",
        "credential_key_configured",
        "credential_key_path",
        "scan_workers",
        "scan_workers_saved",
        "external_api_master",
        "external_api_master_saved",
        "ssh_known_hosts",
        "seclists_download_url",
        "smtp",
        "notify_default",
        "max_repo_bytes",
        "max_source_file_bytes",
        "max_scan_files",
        "max_cidr_hosts",
        "agent_job_timeout",
    ):
        assert key in settings
    assert {"host", "port", "user", "from"} <= set(settings["smtp"])
    assert {"email", "webhook"} <= set(settings["notify_default"])
    assert {"max_web_hosts", "workers"} <= set(settings["limits"])


def test_update_notifications_and_guardrails(api_client):
    response = api_client.patch(
        "/api/settings",
        json={
            "smtp_host": "smtp.example.test",
            "smtp_port": "2525",
            "smtp_user": "scanner@example.test",
            "smtp_password": "smtp-password-123",
            "smtp_from": "scanner@example.test",
            "notify_email_default": "soc@example.test",
            "notify_webhook_default": "https://hooks.example.test/vulnscanner",
            "max_web_hosts": 123,
            "workers": 45,
            "max_repo_bytes": 2 * 1024 * 1024,
            "max_source_file_bytes": 2048,
            "max_scan_files": 999,
            "max_cidr_hosts": 128,
            "agent_job_timeout": 300,
        },
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["smtp"]["host"] == "smtp.example.test"
    assert data["smtp"]["port"] == "2525"
    assert data["notify_default"]["email"] == "soc@example.test"
    assert data["limits"]["max_web_hosts"] == 123
    assert data["limits"]["workers"] == 45
    assert data["max_repo_bytes"] == 2 * 1024 * 1024
    assert data["max_scan_files"] == 999
    assert data["max_cidr_hosts"] == 128
    assert data["agent_job_timeout"] == 300
    assert get_limit("max_scan_files", 20000) == 999
    assert get_setting("smtp_password", "") != "smtp-password-123"
    assert get_setting("notify_webhook_default", "") == "https://hooks.example.test/vulnscanner"


def test_admin_username_is_editable(api_client, monkeypatch, tmp_path):
    import app.api as api

    monkeypatch.setattr(api, "BASE_DIR", tmp_path)
    original = os.environ.get("VS_ADMIN_USER")
    try:
        response = api_client.post(
            "/api/settings/admin-user", json={"username": "auditor"}
        )
        assert response.status_code == 200, response.text
        assert response.json()["admin_user"] == "auditor"
        assert api_client.get("/api/settings").json()["admin_user"] == "auditor"
        assert os.environ["VS_ADMIN_USER"] == "auditor"
    finally:
        if original is None:
            os.environ.pop("VS_ADMIN_USER", None)
        else:
            os.environ["VS_ADMIN_USER"] = original


def test_runtime_settings_write_env_and_apply(api_client, data_dir, monkeypatch, tmp_path):
    import app.api as api

    monkeypatch.setattr(api, "BASE_DIR", tmp_path)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("example.test ssh-ed25519 AAAA\n", encoding="utf-8")
    wordlist = data_dir / "wordlists" / "custom.txt"
    original = {
        key: os.environ.get(key)
        for key in (
            "VS_SCAN_WORKERS",
            "VS_ENABLE_EXTERNAL_APIS",
            "VS_SSH_KNOWN_HOSTS",
            "VS_SUBFINDER_WORDLIST",
            "VS_SECLISTS_SUBDOMAIN_URL",
        )
    }
    try:
        response = api_client.post(
            "/api/settings/runtime",
            json={
                "scan_workers": 6,
                "external_api_master": False,
                "ssh_known_hosts": str(known_hosts),
                "wordlist_path": str(wordlist),
                "seclists_subdomain_url": "https://example.test/subdomains.txt",
            },
        )
        assert response.status_code == 200, response.text
        result = response.json()
        assert result["restart_required"] is True
        assert result["settings"]["scan_workers_saved"] == 6
        assert result["settings"]["external_api_master_saved"] is False
        assert result["settings"]["ssh_known_hosts"] == str(known_hosts)
        assert result["settings"]["wordlist_path"] == str(wordlist)
        assert (
            result["settings"]["seclists_download_url"]
            == "https://example.test/subdomains.txt"
        )
        env_text = (tmp_path / ".env").read_text(encoding="utf-8")
        assert "VS_SCAN_WORKERS=6" in env_text
        assert "VS_ENABLE_EXTERNAL_APIS=false" in env_text
        assert f"VS_SSH_KNOWN_HOSTS={known_hosts}" in env_text
        assert f"VS_SUBFINDER_WORDLIST={wordlist}" in env_text
        assert "VS_SECLISTS_SUBDOMAIN_URL=https://example.test/subdomains.txt" in env_text
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_gui_writes_custom_vs_env_file(api_client, monkeypatch, tmp_path):
    import app.api as api

    env_file = tmp_path / "service.env"
    monkeypatch.setenv("VS_ENV_FILE", str(env_file))
    monkeypatch.setenv("VS_ADMIN_USER", "admin")
    monkeypatch.setattr(api, "BASE_DIR", tmp_path / "repo")
    response = api_client.post(
        "/api/settings/admin-user", json={"username": "serviceadmin"}
    )
    assert response.status_code == 200, response.text
    assert env_file.exists()
    assert "VS_ADMIN_USER=serviceadmin" in env_file.read_text(encoding="utf-8")


def test_runtime_settings_reject_unsafe_paths(api_client, monkeypatch, tmp_path):
    import app.api as api

    monkeypatch.setattr(api, "BASE_DIR", tmp_path)
    missing_known_hosts = api_client.post(
        "/api/settings/runtime",
        json={"ssh_known_hosts": str(tmp_path / "missing-known-hosts")},
    )
    assert missing_known_hosts.status_code == 400

    relative_wordlist = api_client.post(
        "/api/settings/runtime", json={"wordlist_path": "relative/list.txt"}
    )
    assert relative_wordlist.status_code == 400

    bad_url = api_client.post(
        "/api/settings/runtime", json={"seclists_subdomain_url": "file:///tmp/list"}
    )
    assert bad_url.status_code == 422
