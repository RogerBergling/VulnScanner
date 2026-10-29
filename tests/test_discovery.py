"""Discovery helpers and inventory persistence tests."""

from __future__ import annotations

from app.database import get_db, utcnow
from app.discovery import (
    _expand_subnet,
    create_inventory_entry,
    discover_hosts,
    track_historical_findings,
)


def _scan_id(api_client, customer) -> int:
    response = api_client.post(
        "/api/scans",
        json={
            "customer_id": customer["id"],
            "group_id": customer["group_id"],
            "scan_type": "network",
            "target": "192.0.2.0/30",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_expand_subnet_and_discovery_without_custom_ports(monkeypatch):
    assert _expand_subnet("192.0.2.0/30", 256) == ["192.0.2.1", "192.0.2.2"]
    monkeypatch.setattr(
        "app.discovery._probe_one",
        lambda host, port, timeout: {
            "host": host,
            "port": port,
            "service": {"services": ["SSH"], "os": ""},
            "banner": "SSH-2.0-OpenSSH_9.0",
        },
    )
    found = discover_hosts("192.0.2.0/30")
    assert len(found) == 22
    assert 22 in {item["port"] for item in found}


def test_inventory_entry_creates_valid_asset_and_history(api_client, customer):
    scan_id = _scan_id(api_client, customer)
    result = create_inventory_entry(
        scan_id,
        customer["id"],
        None,
        "192.0.2.10",
        22,
        {"os": "Linux", "banner": "SSH-2.0-OpenSSH_9.0"},
    )
    assert result["ip"] == "192.0.2.10"

    with get_db() as conn:
        inventory = conn.execute(
            "SELECT * FROM asset_inventory WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        asset = conn.execute(
            "SELECT * FROM assets WHERE id = ?", (inventory["asset_id"],)
        ).fetchone()
    assert asset is not None
    assert asset["group_id"] == customer["group_id"]

    finding = {
        "fingerprint": "fp-1",
        "severity": "high",
        "title": "Test finding",
        "status": "open",
        "first_seen": utcnow(),
        "last_seen": utcnow(),
    }
    track_historical_findings(scan_id, int(asset["id"]), [finding])
    track_historical_findings(scan_id, int(asset["id"]), [finding])
    with get_db() as conn:
        history = conn.execute(
            "SELECT * FROM finding_history WHERE asset_id = ? AND fingerprint = 'fp-1'",
            (asset["id"],),
        ).fetchone()
    assert history["count"] == 2
    assert history["last_seen_scan_id"] == scan_id
