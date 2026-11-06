"""Tests for the PingCastle Healthcheck XML parser."""

from pathlib import Path

import pytest

from app.scanners.pingcastle import (
    _points_severity,
    parse_pingcastle_xml,
    scan_pingcastle_report,
)
from tests.helpers import DummyContext

FIXTURE = Path(__file__).parent / "fixtures" / "pingcastle.xml"


@pytest.fixture()
def xml_text():
    return FIXTURE.read_text(encoding="utf-8")


def _by_key(result, key):
    for finding in result.normalized():
        if finding.get("key") == key:
            return finding
    return None


def test_parse_extracts_domain_metadata(xml_text):
    result = parse_pingcastle_xml(xml_text)
    assert result.metadata["domain"] == "mastec.local"
    assert result.metadata["forest"] == "mastec.local"
    assert result.metadata["collector"] == "PingCastle 2.9.2.0"
    assert result.metadata["collected_at"].startswith("2021-04-23")
    assert result.metadata["pingcastle_scores"]["global"] == "100"


def test_known_risk_rules_become_findings(xml_text):
    result = parse_pingcastle_xml(xml_text)
    krbtgt = _by_key(result, "ad:pingcastle:A-Krbtgt")
    assert krbtgt is not None
    assert krbtgt["severity"] == "critical"
    assert krbtgt["cwe"] == "CWE-263"
    assert "6677 day(s) ago" in krbtgt["evidence"]
    delegated = _by_key(result, "ad:pingcastle:P-Delegated")
    assert delegated is not None and delegated["severity"] == "high"
    kerb = _by_key(result, "ad:pingcastle:P-Kerberoasting")
    assert kerb is not None and kerb["severity"] == "high"
    laps = _by_key(result, "ad:pingcastle:A-LAPS-Not-Installed")
    assert laps is not None and laps["severity"] == "medium"


def test_unknown_risk_rules_fall_back(xml_text):
    result = parse_pingcastle_xml(xml_text)
    future = _by_key(result, "ad:pingcastle:X-FutureRule")
    assert future is not None
    # 15 points -> medium fallback.
    assert future["severity"] == "medium"
    assert "not yet modelled" in future["description"]


def test_structural_findings(xml_text):
    result = parse_pingcastle_xml(xml_text)
    findings = {item.get("key") for item in result.normalized()}
    assert "ad:pingcastle:prewin2000-anonymous" in findings
    assert "ad:pingcastle:recycle-bin" in findings
    assert "ad:pingcastle:ntfrs-sysvol" in findings
    assert "ad:pingcastle:functional-level" in findings  # level 2 = 2008
    assert "ad:pingcastle:no-preauth" in findings
    assert "ad:pingcastle:user-unconstrained-delegation" in findings


def test_domain_controller_findings(xml_text):
    result = parse_pingcastle_xml(xml_text)
    findings = {item.get("key") for item in result.normalized()}
    assert "ad:pingcastle:dc-spooler:DC01" in findings
    assert "ad:pingcastle:dc-spooler:DC02" not in findings
    # DC01 requires SMB signing; DC02 does not.
    assert "ad:pingcastle:smb-signing:DC01" not in findings
    assert "ad:pingcastle:smb-signing:DC02" in findings
    assert "ad:pingcastle:smb1:DC01" in findings
    assert "ad:pingcastle:smb1:DC02" not in findings
    # DC01 offers only legacy TLS for LDAPS; DC02 offers TLS 1.2.
    assert "ad:pingcastle:ldaps-protocols:DC01" in findings
    assert "ad:pingcastle:ldaps-protocols:DC02" not in findings


def test_metadata_carries_dcs_sites_os(xml_text):
    result = parse_pingcastle_xml(xml_text)
    metadata = result.metadata
    assert len(metadata["domain_controllers"]) == 2
    assert metadata["domain_controllers"][0]["name"] == "DC01"
    assert metadata["sites"] == ["Default"]
    assert metadata["os_distribution"] == {"Windows 7": 68, "Windows 10": 118}
    assert metadata["risk_score"] > 0
    assert metadata["risk_label"]


def test_points_severity_fallback():
    assert _points_severity(50) == "critical"
    assert _points_severity(30) == "high"
    assert _points_severity(20) == "high"
    assert _points_severity(15) == "medium"
    assert _points_severity(10) == "medium"
    assert _points_severity(5) == "low"
    assert _points_severity(1) == "info"


def test_rejects_non_pingcastle_xml():
    with pytest.raises(ValueError):
        parse_pingcastle_xml("<root><not>pingcastle</not></root>")


def test_scan_pingcastle_report(tmp_path):
    ctx = DummyContext()
    result = scan_pingcastle_report(ctx, str(FIXTURE))
    assert result.findings
    assert result.metadata["domain"] == "mastec.local"


def test_scan_pingcastle_report_missing_file(tmp_path):
    ctx = DummyContext()
    with pytest.raises(ValueError):
        scan_pingcastle_report(ctx, str(tmp_path / "missing.xml"))
