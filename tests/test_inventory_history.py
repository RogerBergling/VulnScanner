"""Network scan inventory persistence and finding history."""

from __future__ import annotations

from app.scanners.base import Finding, ScanResult
from app.scans import persist_result


def test_network_scan_populates_inventory_and_history(api_client, customer):
    created = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "scan_type": "network",
            "target": "192.0.2.10",
        },
    )
    assert created.status_code == 201, created.text
    scan_id = created.json()["id"]

    result = ScanResult(
        findings=[
            Finding(
                severity="medium",
                title="Open HTTP service",
                category="network",
                location="http://192.0.2.10",
                resource="tcp/80",
                key="open-http",
            )
        ],
        metadata={
            "hosts": ["192.0.2.10"],
            "open_ports": [
                {"host": "192.0.2.10", "port": 80, "service": "http"},
                {"host": "192.0.2.10", "port": 443, "service": "https"},
            ],
        },
    )
    summary = persist_result(scan_id, result)
    assert summary["inventory_entries"] == 1

    inventory = api_client.get(
        "/api/inventory", params={"customer_id": customer["id"]}
    )
    assert inventory.status_code == 200, inventory.text
    entries = inventory.json()["entries"]
    assert len(entries) == 1
    assert entries[0]["ip_address"] == "192.0.2.10"
    assert 80 in entries[0]["ports"]
    assert 443 in entries[0]["ports"]
    asset_id = entries[0]["asset_id"]
    assert asset_id

    history = api_client.get(f"/api/assets/{asset_id}/history")
    assert history.status_code == 200, history.text
    assert history.json()["history"]
    assert history.json()["history"][0]["fingerprint"]
