"""Tests for wildcard (*.domain) expansion in network scans."""

import pytest

from app.scanners import network
from tests.helpers import DummyContext


def test_no_wildcards_passes_through():
    ctx = DummyContext({"max_wildcard_hosts": 100})
    plain, discovered, metadata = network._expand_wildcards(
        ctx, ["192.0.2.10", "web.example.com"]
    )
    assert plain == ["192.0.2.10", "web.example.com"]
    assert discovered == []
    assert metadata == {}


def test_wildcard_expands_discovered_hosts(monkeypatch):
    def fake_discover(ctx, domain, **kwargs):
        return {"www." + domain, "api." + domain, "mail." + domain}

    monkeypatch.setattr(
        "app.scanners.subdomains.discover_subdomains", fake_discover
    )
    monkeypatch.setattr(
        "app.scanners.subdomains.normalize_domain", lambda value: value.strip()
    )
    ctx = DummyContext({"max_wildcard_hosts": 100})
    plain, discovered, metadata = network._expand_wildcards(
        ctx, ["*.bergling.net", "10.0.0.5"]
    )
    assert plain == ["10.0.0.5"]
    assert sorted(discovered) == [
        "api.bergling.net",
        "mail.bergling.net",
        "www.bergling.net",
    ]
    assert metadata["bergling.net"] == sorted(discovered)
    assert any("wildcard" in message.lower() for _level, message in ctx.logs)


def test_wildcard_respects_max_hosts(monkeypatch):
    def fake_discover(ctx, domain, **kwargs):
        return {f"host{i}.{domain}" for i in range(50)}

    monkeypatch.setattr(
        "app.scanners.subdomains.discover_subdomains", fake_discover
    )
    monkeypatch.setattr(
        "app.scanners.subdomains.normalize_domain", lambda value: value.strip()
    )
    ctx = DummyContext({"max_wildcard_hosts": 10})
    _plain, discovered, _metadata = network._expand_wildcards(ctx, ["*.example.com"])
    assert len(discovered) == 50  # discover_subdomains caps in production


def test_invalid_wildcard_domain_raises(monkeypatch):
    def fake_normalize(value):
        raise ValueError("Invalid domain")

    monkeypatch.setattr(
        "app.scanners.subdomains.normalize_domain", fake_normalize
    )
    ctx = DummyContext()
    with pytest.raises(ValueError):
        network._expand_wildcards(ctx, ["*.not a domain"])


def test_scan_uses_discovered_hosts(monkeypatch):
    """The scan engine passes wildcard-discovered hosts to the port prober."""
    probed: list[str] = []

    def fake_discover(ctx, domain, **kwargs):
        return {"www." + domain}

    def fake_probe_ports(hosts, ports, timeout, workers, ctx):
        probed.extend(hosts)
        return []

    monkeypatch.setattr(
        "app.scanners.subdomains.discover_subdomains", fake_discover
    )
    monkeypatch.setattr(
        "app.scanners.subdomains.normalize_domain", lambda value: value.strip()
    )
    monkeypatch.setattr(network, "_probe_ports", fake_probe_ports)
    ctx = DummyContext(
        {
            "profile": "common",
            "web_checks": False,
            "cve_lookup": False,
            "service_probes": False,
            "nuclei": False,
            "authenticated": False,
            "scan_unresponsive_hosts": True,
        },
        target="*.example.com",
    )
    result = network.scan(ctx)
    assert "www.example.com" in probed
    assert result.metadata.get("wildcard_expansion") == {
        "example.com": ["www.example.com"]
    }


def test_wildcard_with_no_hosts_completes_without_resolving_literal(monkeypatch):
    monkeypatch.setattr(
        "app.scanners.subdomains.discover_subdomains", lambda *args, **kwargs: set()
    )
    monkeypatch.setattr(
        "app.scanners.subdomains.normalize_domain", lambda value: value.strip()
    )
    ctx = DummyContext(
        {
            "subfinder": False,
            "bruteforce": False,
            "profile": "common",
            "web_checks": False,
            "cve_lookup": False,
            "service_probes": False,
            "nuclei": False,
            "scan_unresponsive_hosts": True,
        },
        target="*.example.invalid",
    )
    result = network.scan(ctx)
    assert result.metadata["host_count"] == 0
    assert result.metadata["no_hosts_discovered"] == ["*.example.invalid"]
    assert any("No hosts discovered" in finding.title for finding in result.findings)
