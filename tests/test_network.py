import pytest

from app.scanners.network import (
    PortResult,
    _add_port_findings,
    _expand_hosts,
    parse_nmap_xml,
    process_agent_network_payload,
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


def test_process_agent_network_payload():
    payload = {
        "network": {
            "hosts": ["10.0.0.1", "10.0.0.2"],
            "host_count": 2,
            "ports_scanned": 3,
            "open_ports": [
                {"host": "10.0.0.1", "port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH_9.0"},
                {"host": "10.0.0.2", "port": 6379, "service": "redis", "banner": "- NOAUTH required"},
                {"host": "", "port": 80, "banner": "ignored"},
                {"host": "10.0.0.2", "port": "not-a-port"},
            ],
            "finished_at": "2026-01-01T00:00:00+00:00",
        },
        "warnings": ["one probe timed out"],
    }
    ctx = DummyContext(target="10.0.0.0/30")
    result = process_agent_network_payload(ctx, payload)
    findings = {finding["key"]: finding for finding in result.normalized()}
    assert "open-port:22" in findings
    assert findings["risky-port:6379"]["severity"] == "critical"
    assert result.metadata["execution"] == "agent"
    assert result.metadata["host_count"] == 2
    assert result.metadata["ports_scanned"] == 3
    assert {item["host"] for item in result.metadata["open_ports"]} == {"10.0.0.1", "10.0.0.2"}
    assert any("one probe timed out" in message for _level, message in ctx.logs)


def test_process_agent_network_payload_network_only_failure():
    ctx = DummyContext(target="10.0.0.0/30")
    with pytest.raises(ValueError, match="probe failed"):
        process_agent_network_payload(ctx, {"error": "probe failed"})


def test_scan_runs_authenticated_checks(monkeypatch):
    import app.scanners.network as network

    calls: list[list[str]] = []

    def fake_probe(host, port, timeout):
        return PortResult(host, port)

    def fake_auth(result, ctx, open_by_host):
        calls.append(sorted(open_by_host))
        result.metadata["authenticated_checked"] = True

    monkeypatch.setattr(network, "_probe_port", fake_probe)
    monkeypatch.setattr(network, "authenticated_scan", fake_auth)
    result = network.scan(
        DummyContext({"ports": "22", "authenticated": True}, target="127.0.0.1")
    )
    assert calls == [["127.0.0.1"]]
    assert result.metadata["authenticated_checked"] is True


def test_scan_runs_web_checks_on_http_ports(monkeypatch):
    import app.scanners.network as network

    checked: list[str] = []

    def fake_probe(host, port, timeout):
        return PortResult(host, port)

    def fake_http(result, host, port, open_ports, ctx):
        return f"http://{host}:{port}/", object(), "<html>ok</html>"

    def fake_web(result, ctx, url, response, body):
        checked.append(url)

    monkeypatch.setattr(network, "_probe_port", fake_probe)
    monkeypatch.setattr(network, "_http_service", fake_http)
    monkeypatch.setattr(network, "_web_vulnerability_checks", fake_web)
    network.scan(
        DummyContext({"ports": "80", "web_checks": True}, target="127.0.0.1")
    )
    assert checked == ["http://127.0.0.1:80/"]


def test_scan_tolerates_invalid_workers_option(monkeypatch):
    import app.scanners.network as network

    monkeypatch.setattr(network, "_probe_port", lambda host, port, timeout: None)
    result = network.scan(
        DummyContext({"ports": "80", "workers": "not-a-number"}, target="127.0.0.1")
    )
    assert result.findings == []
