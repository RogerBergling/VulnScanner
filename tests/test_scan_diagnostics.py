"""Tests for scan-depth readiness diagnostics."""

from app.scan_diagnostics import build_scan_diagnostics


def test_diagnostics_warn_when_external_apis_disabled(data_dir, monkeypatch):
    monkeypatch.setattr("app.scan_diagnostics.ENABLE_EXTERNAL_APIS", False)
    report = build_scan_diagnostics(
        "network",
        {"web_checks": False, "cve_lookup": False, "service_probes": False, "nuclei": True},
        target="10.0.0.0/24",
    )
    assert report["scan_type"] == "network"
    assert any(item["id"] == "external-apis" for item in report["checks"])
    assert any("External APIs are disabled" in warning for warning in report["warnings"])
    assert any("CVE matching is disabled" in warning for warning in report["warnings"])
    assert any("Web vulnerability checks are disabled" in warning for warning in report["warnings"])


def test_diagnostics_agent_warns_about_discovery_only(data_dir):
    report = build_scan_diagnostics(
        "network",
        {"cve_lookup": True, "nuclei": True},
        agent={"id": "agent-1", "name": "endpoint"},
    )
    assert report["executor"] == "agent"
    assert any("do not run the full web/signature engine" in warning for warning in report["warnings"])


def test_diagnostics_api(api_client, customer):
    response = api_client.post(
        "/api/scan-diagnostics",
        json={
            "scan_type": "network",
            "target": "127.0.0.1",
            "options": {"cve_lookup": False, "nuclei": False},
        },
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["scan_type"] == "network"
    assert any(item["id"] == "vulnerability-cache" for item in data["checks"])
