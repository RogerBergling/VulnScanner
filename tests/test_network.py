import pytest

from app.scanners.network import (
    PortResult,
    _add_port_findings,
    _expand_hosts,
    parse_nmap_xml,
)
from tests.helpers import DummyContext

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="6379">
        <state state="open"/>
        <service name="redis" product="Redis" version="7.0.0"/>
        <script id="vulners" output="CVE-2026-1234&#10;CVE-2026-5678"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
    </ports>
    <hostscript>
      <script id="smb-vuln" output="CVE-2020-1472 is present"/>
    </hostscript>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml_services_and_cves():
    findings = parse_nmap_xml(NMAP_XML)
    service_findings = [f for f in findings if "Nmap service" in f["title"]]
    assert len(service_findings) == 2
    assert {f["location"] for f in service_findings} == {"192.0.2.10:22", "192.0.2.10:6379"}
    assert any(f["cve"] == "CVE-2026-1234,CVE-2026-5678" for f in findings)
    assert any(f["key"].startswith("nmap-host-cve") and f["cve"] == "CVE-2020-1472" for f in findings)
    assert all(f["location"] != "192.0.2.10:80" for f in findings)


def test_parse_nmap_xml_invalid_input():
    assert parse_nmap_xml("not xml") == []
    assert parse_nmap_xml("<nmaprun/>") == []


def test_expand_hosts_for_single_and_cidr():
    assert _expand_hosts("192.0.2.10") == ["192.0.2.10"]
    assert _expand_hosts("192.0.2.0/30") == ["192.0.2.1", "192.0.2.2"]
    assert _expand_hosts("192.0.2.10/32") == ["192.0.2.10"]
    with pytest.raises(ValueError, match="limit is 256"):
        _expand_hosts("10.0.0.0/23")


def test_add_port_findings_severities_and_banner():
    result_ports = [
        PortResult("192.0.2.5", 6379, banner="- NOAUTH Authentication required"),
        PortResult("192.0.2.5", 22, banner="SSH-2.0-OpenSSH_8.9p1"),
        PortResult("192.0.2.5", 8080, banner=""),
    ]
    from app.scanners.base import ScanResult

    result = ScanResult()
    _add_port_findings(result, result_ports, DummyContext())
    findings = result.normalized()
    by_port = {finding["key"]: finding for finding in findings}
    assert by_port["risky-port:6379"]["severity"] == "critical"
    assert by_port["open-port:22"]["severity"] == "info"
    assert by_port["banner-version:22"]["severity"] == "low"
    assert by_port["open-port:8080"]["severity"] == "info"
    assert "Banner: SSH-2.0-OpenSSH_8.9p1" in by_port["open-port:22"]["evidence"]
