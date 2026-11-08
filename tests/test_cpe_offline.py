"""Tests for the offline NVD product cache."""

import json

from app.database import get_db, utcnow
from app.scanners import cpe


def _cve_record():
    return {
        "id": "CVE-2026-9999",
        "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
        "weaknesses": [{"description": [{"value": "CWE-79"}]}],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "8.0",
                                "versionEndIncluding": "8.9",
                            }
                        ]
                    }
                ]
            }
        ],
    }


def test_product_cache_serves_offline_lookup(data_dir, monkeypatch):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO nvd_cache(cache_key, response, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (
                "nvd:product:openbsd:openssh",
                json.dumps({"vulnerabilities": [{"cve": _cve_record()}]}),
                utcnow(),
                "2099-01-01T00:00:00+00:00",
            ),
        )
        conn.commit()
    monkeypatch.setattr(cpe, "ENABLE_EXTERNAL_APIS", False)
    records = cpe.lookup_cves(
        cpe.ProductMatch("openbsd", "openssh", "8.2p1", "ssh", "test")
    )
    assert [record["id"] for record in records] == ["CVE-2026-9999"]


def test_product_sync_stores_full_records(data_dir, monkeypatch):
    monkeypatch.setattr(
        cpe,
        "_fetch_nvd_pages",
        lambda params, log, max_pages=20: [_cve_record()],
    )
    count = cpe.sync_product_cves("openbsd", "openssh")
    assert count == 1
    with get_db() as conn:
        row = conn.execute(
            "SELECT response FROM nvd_cache WHERE cache_key = 'nvd:product:openbsd:openssh'"
        ).fetchone()
    assert row is not None
    assert json.loads(row["response"])["vendor"] == "openbsd"
