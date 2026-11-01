"""Release/build metadata exposed to the UI and API."""

from __future__ import annotations

from datetime import datetime

from app import build_info as build_module


def test_build_info_uses_release_environment(monkeypatch):
    build_module.build_info.cache_clear()
    monkeypatch.setenv("VS_BUILD_NUMBER", "42")
    monkeypatch.setenv("VS_BUILD_COMMIT", "abc1234")
    monkeypatch.setenv("VS_BUILD_TIME", "2026-11-01T11:14:00+00:00")
    try:
        info = build_module.build_info()
        expected = datetime.fromisoformat("2026-11-01T11:14:00+00:00").astimezone()
        assert info["version"] == build_module.__version__
        assert info["number"] == "42"
        assert info["commit"] == "abc1234"
        assert info["time"] == "2026-11-01T11:14:00+00:00"
        assert info["date"] == expected.strftime("%Y-%m-%d")
        assert info["hour"] == expected.strftime("%H:%M")
        assert info["timezone"] == (expected.tzname() or "local")
        assert "build #42" in info["display"]
    finally:
        build_module.build_info.cache_clear()


def test_health_dashboard_and_meta_expose_build(api_client):
    health = api_client.get("/api/health")
    assert health.status_code == 200
    build = health.json()["build"]
    assert {"version", "number", "commit", "time", "date", "hour", "timezone"} <= set(build)
    assert build["version"] == health.json()["version"]

    dashboard = api_client.get("/api/dashboard")
    assert dashboard.status_code == 200
    assert dashboard.json()["build"]["version"] == build["version"]

    meta = api_client.get("/api/meta")
    assert meta.status_code == 200
    assert meta.json()["build"]["version"] == build["version"]
