"""Tests for the optional Greenbone/OpenVAS engine (offline)."""

from app.scanners.base import ScanResult
from app.scanners.openvas import (
    parse_report,
    run_openvas,
    severity_from_gmp,
    _extract_id,
    _response_ok,
)
from tests.helpers import DummyContext

REPORT_XML = """<?xml version="1.0"?>
<get_reports_response status="200" status_text="OK">
  <report id="r1">
    <report>
      <results start="1" max="2">
        <result id="res1">
          <name>OpenSSH before 9.3p2 agent forwarding</name>
          <severity>9.8</severity>
          <nvt oid="1.3.6.1.4.1.25623.1.0.140022"/>
          <host>192.0.2.10</host>
          <port>22/tcp</port>
          <description>The PKCS#11 feature in ssh-agent ... insufficiently protected.</description>
        </result>
        <result id="res2">
          <name>Deprecated TLS protocol detected</name>
          <severity>5.5</severity>
          <nvt oid="1.3.6.1.4.1.25623.1.0.105021"/>
          <host>192.0.2.10</host>
          <port>443/tcp</port>
          <description>TLS 1.0 is deprecated.</description>
        </result>
      </results>
    </report>
  </report>
</get_reports_response>
"""


def test_parse_report_extracts_findings():
    findings = parse_report(REPORT_XML)
    assert len(findings) == 2
    critical = findings[0]
    assert critical["severity"] == "critical"
    assert critical["key"].startswith("openvas:1.3.6.1.4.1.25623.1.0.140022")
    assert critical["location"] == "192.0.2.10:22/tcp"
    assert findings[1]["severity"] == "medium"
    assert findings[0]["raw"]["engine"] == "openvas"


def test_parse_report_garbage():
    assert parse_report("not xml") == []
    assert parse_report("<other/>") == []


def test_severity_from_gmp():
    assert severity_from_gmp("10.0") == "critical"
    assert severity_from_gmp("9.8") == "critical"
    assert severity_from_gmp("7.5") == "high"
    assert severity_from_gmp("5.5") == "medium"
    assert severity_from_gmp("2.0") == "low"
    assert severity_from_gmp("0.0") == "info"
    assert severity_from_gmp("garbage") == "info"


def test_extract_id_and_ok():
    assert _extract_id('<create_target_response status="201" id="t1"/>', "create_target") == "t1"
    assert _extract_id('<create_target_response status="400"/>', "create_target") is None
    assert _response_ok('<get_tasks_response status="200"/>') is True
    assert _response_ok('junk') is False


def test_run_openvas_requires_settings_gate(monkeypatch):
    from app.scanners import openvas

    monkeypatch.setattr(openvas, "setting_or_default", lambda *a, **k: "false")
    result = ScanResult()
    ctx = DummyContext({"external_tools": True, "openvas": True})
    assert run_openvas(result, "192.0.2.10", ctx) == 0
    assert any("disabled in Settings" in message for _level, message in ctx.logs)


def test_run_openvas_requires_scan_option(monkeypatch):
    from app.scanners import openvas

    monkeypatch.setattr(openvas, "setting_or_default", lambda *a, **k: "true")
    result = ScanResult()
    ctx = DummyContext({"external_tools": False, "openvas": True})
    assert run_openvas(result, "192.0.2.10", ctx) == 0
    ctx = DummyContext({"external_tools": True, "openvas": False})
    assert run_openvas(result, "192.0.2.10", ctx) == 0


def test_run_openvas_skips_without_binary(monkeypatch):
    from app.scanners import openvas

    monkeypatch.setattr(openvas, "setting_or_default", lambda *a, **k: "true")
    result = ScanResult()
    ctx = DummyContext({"external_tools": True, "openvas": True})
    assert run_openvas(result, "192.0.2.10", ctx) == 0
    assert any("not installed" in message for _level, message in ctx.logs)
