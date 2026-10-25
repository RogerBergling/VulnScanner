from app.database import get_db, get_setting
from app.scanners import kev, osv
from app.scanners.kev import KevSyncError, enrich_finding, sync_kev


class FakeResponse:
    def __init__(self, payload=None, status_code=200, error=None):
        self._payload = payload
        self.status_code = status_code
        self._error = error

    def raise_for_status(self):
        if self._error:
            raise self._error
        if self.status_code >= 400:
            import requests

            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


def test_kev_sync_upserts_catalog(data_dir, monkeypatch):
    payload = {
        "catalogVersion": "2026.01.01",
        "dateReleased": "2026-01-01T00:00:00Z",
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "Acme",
                "product": "Widget",
                "vulnerabilityName": "Acme Widget RCE",
                "dateAdded": "2026-01-01",
                "dueDate": "2026-01-22",
                "knownRansomwareCampaignUse": "Known",
                "requiredAction": "Apply updates.",
            },
            {"cveID": "not-a-cve", "vendorProject": "Ignored"},
        ],
    }
    monkeypatch.setattr(kev.requests, "get", lambda *_args, **_kwargs: FakeResponse(payload))
    result = sync_kev()
    assert result["count"] == 1
    assert result["catalog_version"] == "2026.01.01"
    assert get_setting("kev_last_sync")
    with get_db() as conn:
        row = conn.execute("SELECT * FROM kev_catalog WHERE cve_id = 'CVE-2026-0001'").fetchone()
    assert row["product"] == "Widget"
    assert row["known_ransomware"] == "Known"


def test_kev_sync_errors_are_wrapped(data_dir, monkeypatch):
    import requests

    monkeypatch.setattr(
        kev.requests,
        "get",
        lambda *_args, **_kwargs: FakeResponse(error=requests.ConnectionError("offline")),
    )
    try:
        sync_kev()
    except KevSyncError as exc:
        assert "Could not download" in str(exc)
    else:
        raise AssertionError("expected KevSyncError")

    monkeypatch.setattr(kev.requests, "get", lambda *_args, **_kwargs: FakeResponse({"vulnerabilities": "bad"}))
    try:
        sync_kev()
    except KevSyncError as exc:
        assert "Unexpected KEV catalog format" in str(exc)
    else:
        raise AssertionError("expected KevSyncError")


def test_enrich_finding_adds_kev_metadata():
    finding = {
        "severity": "critical",
        "title": "Vulnerable dependency",
        "description": "Details.",
        "cve": "CVE-2026-0001, CVE-2026-0002",
    }
    enrich_finding(
        finding,
        {
            "CVE-2026-0001": {
                "cve_id": "CVE-2026-0001",
                "name": "Acme Widget RCE",
                "date_added": "2026-01-01",
                "due_date": "2026-01-22",
                "known_ransomware": "Known",
                "required_action": "Apply updates.",
            }
        },
    )
    assert finding["title"].endswith("(CISA KEV)")
    assert finding["raw"]["kev"]["cve_id"] == "CVE-2026-0001"
    assert "Required action: Apply updates." in finding["description"]
    assert "Known ransomware campaign use: yes." in finding["description"]


def test_enrich_finding_ignores_unknown_cve():
    finding = {"title": "No KEV", "cve": "CVE-2026-9999", "description": ""}
    enrich_finding(finding, {})
    assert finding == {"title": "No KEV", "cve": "CVE-2026-9999", "description": ""}


def test_kev_lookup_returns_catalog_rows(data_dir):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO kev_catalog(cve_id, vendor_project, product, name, date_added, "
            "due_date, known_ransomware, required_action, synced_at) "
            "VALUES ('CVE-2026-0001', 'Acme', 'Widget', 'RCE', '2026-01-01', "
            "'2026-01-22', 'Known', 'Patch', '2026-01-01')"
        )
        conn.commit()
    rows = osv.kev_lookup({"CVE-2026-0001", "CVE-2026-0002"})
    assert list(rows) == ["CVE-2026-0001"]
    assert osv.kev_lookup(set()) == {}


def test_osv_querybatch_retries_server_errors(monkeypatch):
    calls = {"count": 0}

    def fake_post(*_args, **_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return FakeResponse({"results": []}, status_code=503)
        return FakeResponse({"results": []})

    monkeypatch.setattr(osv.requests, "post", fake_post)
    monkeypatch.setattr(osv.time, "sleep", lambda _seconds: None)
    assert osv._post_batch({"queries": []}) == {"results": []}
    assert calls["count"] == 2
