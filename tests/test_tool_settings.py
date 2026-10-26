"""API coverage for tool paths, wordlist editing and domain scans."""

from __future__ import annotations


def test_settings_expose_and_update_new_integrations(api_client):
    settings = api_client.get("/api/settings").json()
    for key in ("testssl_enabled", "trivy_enabled", "subfinder_enabled"):
        assert key in settings
    assert "tool_paths" in settings
    assert settings["wordlist_path"].endswith("wordlists/subdomains.txt")
    assert "SecLists" in settings["seclists_url"]

    updated = api_client.patch(
        "/api/settings",
        json={
            "testssl_enabled": False,
            "trivy_enabled": False,
            "subfinder_enabled": False,
        },
    )
    assert updated.status_code == 200, updated.text
    data = updated.json()
    assert data["testssl_enabled"] is False
    assert data["trivy_enabled"] is False
    assert data["subfinder_enabled"] is False

    restored = api_client.patch("/api/settings", json={"subfinder_enabled": True})
    assert restored.json()["subfinder_enabled"] is True
    assert restored.json()["testssl_enabled"] is False
    api_client.patch("/api/settings", json={"testssl_enabled": True, "trivy_enabled": True})


def test_tool_path_settings_write_env_and_apply(api_client, monkeypatch, tmp_path):
    import app.api as api
    from app.config import TOOL_PATHS
    from app.scanners import tools

    monkeypatch.setattr(api, "BASE_DIR", tmp_path)
    monkeypatch.setenv("VS_NMAP_PATH", "")
    original = dict(TOOL_PATHS)
    try:
        fake = tmp_path / "nmap"
        fake.write_text("#!/bin/sh\necho 'Nmap version 9.9'\n", encoding="utf-8")
        fake.chmod(0o755)

        response = api_client.post(
            "/api/settings/tools",
            json={"paths": {"nmap": str(fake), "trivy": ""}},
        )
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["tool_paths"]["nmap"] == str(fake)
        assert data["tools"]["nmap"]["path"] == str(fake)
        assert data["tools"]["nmap"]["available"] is True
        assert TOOL_PATHS["nmap"] == str(fake)
        assert tools.tool_status()["nmap"]["path"] == str(fake)

        env_content = (tmp_path / ".env").read_text(encoding="utf-8")
        assert f"VS_NMAP_PATH={fake}" in env_content
        assert "VS_TRIVY_PATH=" in env_content

        cleared = api_client.post("/api/settings/tools", json={"paths": {"nmap": ""}})
        assert cleared.status_code == 200
        assert cleared.json()["tool_paths"]["nmap"] == ""
        assert TOOL_PATHS["nmap"] == ""
    finally:
        TOOL_PATHS.clear()
        TOOL_PATHS.update(original)


def test_tool_path_settings_validate(api_client, monkeypatch, tmp_path):
    import app.api as api

    monkeypatch.setattr(api, "BASE_DIR", tmp_path)
    relative = api_client.post("/api/settings/tools", json={"paths": {"nmap": "bin/nmap"}})
    assert relative.status_code == 400

    missing = api_client.post(
        "/api/settings/tools", json={"paths": {"nmap": str(tmp_path / "missing")}}
    )
    assert missing.status_code == 400

    unknown = api_client.post("/api/settings/tools", json={"paths": {"nope": "/bin/true"}})
    assert unknown.status_code == 422

    unsafe = api_client.post(
        "/api/settings/tools", json={"paths": {"nmap": "/bin/nmap;rm -rf /"}}
    )
    assert unsafe.status_code == 422


def test_wordlist_api_and_seclists_gate(api_client, data_dir, monkeypatch, tmp_path):
    saved = api_client.post(
        "/api/settings/wordlist",
        json={"content": "# comment\nwww\nmail\n"},
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["line_count"] == 2

    loaded = api_client.get("/api/settings/wordlist").json()
    assert loaded["exists"] is True
    assert loaded["editable"] is True
    assert loaded["line_count"] == 2
    assert "www\nmail" in loaded["content"]
    assert "SecLists" in loaded["source"]
    assert loaded["path"].endswith("wordlists/subdomains.txt")

    null_bytes = api_client.post("/api/settings/wordlist", json={"content": "www\x00"})
    assert null_bytes.status_code == 422

    outside = tmp_path / "outside.txt"
    monkeypatch.setenv("VS_SUBFINDER_WORDLIST", str(outside))
    info = api_client.get("/api/settings/wordlist").json()
    assert info["editable"] is False
    rejected = api_client.post("/api/settings/wordlist", json={"content": "www\n"})
    assert rejected.status_code == 400
    assert not outside.exists()

    # The test environment disables external APIs, so the download is gated.
    monkeypatch.delenv("VS_SUBFINDER_WORDLIST", raising=False)
    download = api_client.post("/api/settings/wordlist/seclists", json={})
    assert download.status_code == 400
    assert "External APIs are disabled" in download.json()["detail"]


def test_testssl_and_trivy_scan_options_are_sanitized(api_client, customer, tmp_path):
    customer_id = customer["id"]
    network = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer_id,
            "scan_type": "network",
            "target": "192.0.2.10",
            "options": {
                "external_tools": True,
                "testssl": True,
                "max_testssl_hosts": 999,
                "trivy": True,
                "unknown": "ignored",
            },
        },
    )
    assert network.status_code == 201, network.text
    assert network.json()["options"] == {
        "external_tools": True,
        "testssl": True,
        "max_testssl_hosts": 50,
    }

    repository = tmp_path / "repo"
    repository.mkdir()
    repo = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer_id,
            "scan_type": "repo",
            "target": str(repository),
            "options": {"external_tools": True, "trivy": True, "testssl": True},
        },
    )
    assert repo.status_code == 201, repo.text
    assert repo.json()["options"] == {"external_tools": True, "trivy": True}


def test_domain_scan_creation_validation_and_rescan(api_client, customer):
    customer_id = customer["id"]
    created = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer_id,
            "scan_type": "domain",
            "target": "https://Sub.Example.com/path",
            "options": {
                "subfinder": False,
                "bruteforce": True,
                "max_words": 999999,
                "workers": 0,
                "max_subdomains": 999999,
                "unknown": "ignored",
            },
        },
    )
    assert created.status_code == 201, created.text
    scan = created.json()
    assert scan["scan_type"] == "domain"
    assert scan["target"] == "sub.example.com"
    assert scan["options"] == {
        "subfinder": False,
        "bruteforce": True,
        "max_words": 50000,
        "workers": 1,
        "max_subdomains": 5000,
    }

    for target in ("192.0.2.10", "*.example.com", "example.com:8443"):
        response = api_client.post(
            "/api/scans",
            json={"customer_id": customer_id, "scan_type": "domain", "target": target},
        )
        assert response.status_code == 400, target

    rescan = api_client.post(f"/api/scans/{scan['id']}/rescan")
    assert rescan.status_code == 201, rescan.text
    assert rescan.json()["target"] == "sub.example.com"
    assert rescan.json()["scan_type"] == "domain"
