from app.scanners import agent as agent_scanner
from app.scanners.agent import _address_exposed, process_agent_payload
from tests.helpers import DummyContext


def _payload():
    return {
        "system": {"hostname": "web01", "os": "Linux", "kernel": "6.8"},
        "modules": ["system", "ports", "secrets"],
        "checks": [
            {
                "severity": "high",
                "title": "SSH root login is enabled",
                "category": "host",
                "location": "/etc/ssh/sshd_config",
            }
        ],
        "listening_ports": [
            {"address": "0.0.0.0", "port": 23, "protocol": "tcp", "service": "telnet", "process": "telnetd"},
            {"address": "127.0.0.1", "port": 6379, "protocol": "tcp", "service": "redis", "process": "redis-server"},
            {"address": "0.0.0.0", "port": 22, "protocol": "tcp", "service": "ssh", "process": "sshd"},
            {"address": "::", "port": 80, "protocol": "tcp", "service": "http", "process": "nginx/1.25"},
            {"address": "bad", "port": "not-a-port"},
            {"port": 0},
            "not-a-dict",
        ],
        "secrets": [
            {
                "severity": "critical",
                "title": "Private key on host",
                "category": "secret",
                "location": "/home/app/.ssh/id_rsa",
            }
        ],
        "source_findings": [
            {
                "severity": "medium",
                "title": "Debug enabled",
                "category": "source",
                "location": "/srv/app/settings.py:4",
            }
        ],
        "findings": [
            {
                "severity": "low",
                "title": "Third-party check",
                "description": "Imported check",
            }
        ],
        "ad": {"domain": {"name": "corp.example"}, "guest_enabled": True},
    }


def test_address_exposure_detection():
    assert _address_exposed("0.0.0.0")
    assert _address_exposed("::")
    assert _address_exposed("[::]")
    assert _address_exposed("10.0.0.5")
    assert _address_exposed("hostname.local")
    assert not _address_exposed("127.0.0.1")
    assert not _address_exposed("127.1.2.3")
    assert not _address_exposed("::1")
    assert not _address_exposed("localhost")
    assert not _address_exposed("")
    assert _address_exposed("fe80::1%eth0")


def test_process_agent_payload_normalizes_ports_and_findings():
    result = process_agent_payload(DummyContext(), _payload())
    findings = result.normalized()
    titles = {finding["title"] for finding in findings}
    assert "Risky service listening on all interfaces: Telnet (port 23)" in titles
    assert "Risky service listening on all interfaces: SSH (port 22)" not in titles
    assert "Listening service on 127.0.0.1:6379 (redis)" in titles
    assert "Service version disclosed on port 22" not in titles
    assert "SSH root login is enabled" in titles
    assert "Private key on host" in titles
    assert "Debug enabled" in titles
    assert "Third-party check" in titles
    assert result.metadata["system"]["hostname"] == "web01"
    assert result.metadata["ad"]["domain"] == "corp.example"
    assert result.metadata["modules"] == ["system", "ports", "secrets"]
    assert result.metadata["finding_count"] == len(findings)
    telnet = next(f for f in findings if "Telnet" in f["title"])
    assert telnet["severity"] == "high"
    redis = next(f for f in findings if "6379" in f["title"])
    assert redis["severity"] == "info"


def test_process_agent_payload_queries_packages(monkeypatch):
    captured = {}

    def fake_enrich(packages, ctx, result):
        captured["packages"] = packages
        return 0

    monkeypatch.setattr(agent_scanner, "enrich_packages", fake_enrich)
    payload = {
        "system": {"hostname": "pkg-host"},
        "modules": ["packages"],
        "packages": [
            {"name": "openssl", "version": "3.0.1", "ecosystem": "Debian", "source": "dpkg"},
            {"name": "", "version": "1.0", "ecosystem": "PyPI"},
            {"name": "pip", "version": "", "ecosystem": "PyPI"},
            {"name": "requests", "version": "2.31.0", "ecosystem": "", },
        ],
    }
    ctx = DummyContext()
    result = process_agent_payload(ctx, payload)
    assert len(captured["packages"]) == 1
    assert captured["packages"][0].name == "openssl"
    assert result.metadata["inventory_packages"] == 1
    assert any("Checking 1 installed package" in message for _level, message in ctx.logs)


def test_process_agent_payload_survives_package_lookup_failure(monkeypatch):
    monkeypatch.setattr(
        agent_scanner,
        "enrich_packages",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("network down")),
    )
    result = process_agent_payload(
        DummyContext(),
        {
            "system": {"hostname": "pkg-host"},
            "packages": [{"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"}],
        },
    )
    assert result.metadata["osv_error"] == "network down"
    assert result.metadata["inventory_packages"] == 1


def test_process_agent_payload_ignores_bad_shapes():
    result = process_agent_payload(
        DummyContext(),
        {"system": "not-a-dict", "checks": "nope", "listening_ports": {}, "secrets": 1},
    )
    assert result.findings == []
    assert result.metadata["finding_count"] == 0
