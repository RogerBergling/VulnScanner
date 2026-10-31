"""SSRF validation and optional tool version policy."""

from __future__ import annotations

import pytest

from app.net_guard import UnsafeURLError, validate_outbound_url
from app.tool_policy import compare_versions, enforce_scan_policy, evaluate, set_policy


def test_ssrf_guard_blocks_private_and_non_http_urls():
    with pytest.raises(UnsafeURLError):
        validate_outbound_url("http://127.0.0.1/admin")
    with pytest.raises(UnsafeURLError):
        validate_outbound_url("http://10.0.0.5/hook")
    with pytest.raises(UnsafeURLError):
        validate_outbound_url("file:///etc/passwd")
    with pytest.raises(UnsafeURLError):
        validate_outbound_url("https://user:pass@example.com/hook")
    assert validate_outbound_url("http://127.0.0.1/admin", allow_private=True)
    assert validate_outbound_url("https://example.com/hook", resolve=False)


def test_notification_test_rejects_private_webhook(api_client):
    response = api_client.post(
        "/api/settings/notifications/test",
        json={"channel": "webhook", "webhook": "http://127.0.0.1:8080/hook"},
    )
    assert response.status_code == 400
    assert "private" in response.json()["detail"].lower()


def test_tool_version_policy(api_client, monkeypatch):
    assert compare_versions("7.94", "7.80") == 1
    assert compare_versions("3.1.0", "3.0.0") == 1
    assert compare_versions("2.0", "3.0") == -1
    assert evaluate("nmap", "7.70", {"minimums": {"nmap": "7.80"}})["outdated_warning"]

    response = api_client.post(
        "/api/settings/tool-policy",
        json={
            "enabled": True,
            "warn_only": False,
            "minimums": {"nmap": "7.80"},
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["policy"]["enabled"] is True

    monkeypatch.setattr(
        "app.tool_policy.get_policy",
        lambda: {"enabled": True, "warn_only": False, "minimums": {"nmap": "7.80"}},
    )
    with pytest.raises(ValueError):
        enforce_scan_policy(
            "network",
            {},
            tool_status={
                "nmap": {"available": True, "version": "7.70"},
                "testssl": {"available": False, "version": ""},
            },
        )
    set_policy(enabled=False)
