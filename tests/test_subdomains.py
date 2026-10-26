"""Subdomain discovery, wordlist handling and SecLists download tests."""

from __future__ import annotations

import json

import pytest

from app.scanners import subdomains
from tests.helpers import DummyContext


def test_normalize_domain_accepts_bare_and_url_hosts():
    assert subdomains.normalize_domain("Example.COM.") == "example.com"
    assert subdomains.normalize_domain("https://sub.example.com/path") == "sub.example.com"

    for value in (
        "",
        "*.example.com",
        "192.0.2.1",
        "http://192.0.2.1/",
        "example.com:443/path",
        "not a domain",
        "localhost",
    ):
        with pytest.raises(ValueError):
            subdomains.normalize_domain(value)


def test_wordlist_parsing_and_persistence(data_dir):
    saved = subdomains.save_wordlist(
        "# comment\nwww\nmail\nwww\n*.api\nbad name\n/evil\n"
    )
    assert saved["exists"] is True
    assert saved["editable"] is True
    assert saved["line_count"] == 3
    assert subdomains.read_wordlist() == ["www", "mail", "api"]
    assert "www" in subdomains.wordlist_info()["content"]

    outside = data_dir.parent / "outside.txt"
    with pytest.raises(ValueError):
        subdomains.save_wordlist("www\n", outside)
    assert not outside.exists()


def test_download_seclists_wordlist(monkeypatch, data_dir):
    class Response:
        closed = False

        def raise_for_status(self):
            return None

        def iter_content(self, chunk_size=0):
            assert chunk_size > 0
            yield b"www\n"
            yield b"mail\n# comment\n"

        def close(self):
            self.closed = True

    response = Response()

    def fake_get(url, timeout=0, stream=False):
        assert "SecLists" in url
        assert timeout == 30
        assert stream is True
        return response

    monkeypatch.setattr(subdomains.requests, "get", fake_get)
    info = subdomains.download_seclists_wordlist()

    assert info["downloaded"] is True
    assert info["line_count"] == 2
    assert response.closed is True
    assert subdomains.read_wordlist() == ["www", "mail"]


def test_parse_subfinder_output_formats():
    output = "\n".join(
        [
            json.dumps({"host": "www.example.com", "source": "crtsh"}),
            json.dumps({"host": "api.example.com"}),
            "mail.example.com",
            "example.com",
            "evil.test",
            "not a host",
        ]
    )
    hosts = subdomains._parse_subfinder_output(output, "example.com")
    assert hosts == {"www.example.com", "api.example.com", "mail.example.com"}


def test_scan_subdomains_combines_passive_and_wordlist(monkeypatch, data_dir):
    subdomains.save_wordlist("www\napi\n")
    monkeypatch.setattr(
        subdomains,
        "_run_subfinder",
        lambda _ctx, _domain: {"passive.example.com"},
    )

    def resolve(host):
        if host.startswith("vs-wildcard-"):
            return []
        if host.startswith(("www.", "api.")):
            return ["192.0.2.10"]
        return []

    monkeypatch.setattr(subdomains, "_resolve_host", resolve)

    ctx = DummyContext({"subfinder": True, "bruteforce": True}, target="example.com")
    result = subdomains.scan_subdomains(ctx)

    keys = {finding.key for finding in result.findings}
    assert "subdomain:passive.example.com" in keys
    assert "subdomain:www.example.com" in keys
    assert "subdomain:api.example.com" in keys
    assert "subdomain-summary:example.com" in keys
    assert result.metadata["count"] == 3
    assert result.metadata["subfinder"] == 1
    assert result.metadata["bruteforce"]["resolved"] == 2
    assert result.metadata["subdomains"] == [
        "api.example.com",
        "passive.example.com",
        "www.example.com",
    ]


def test_scan_subdomains_skips_bruteforce_on_wildcard(monkeypatch, data_dir):
    subdomains.save_wordlist("www\n")
    monkeypatch.setattr(subdomains, "_run_subfinder", lambda _ctx, _domain: set())
    monkeypatch.setattr(subdomains, "_resolve_host", lambda _host: ["192.0.2.1"])

    ctx = DummyContext({"subfinder": False, "bruteforce": True}, target="example.com")
    result = subdomains.scan_subdomains(ctx)

    assert result.metadata["count"] == 0
    assert result.metadata["bruteforce"]["reason"] == "wildcard-dns"
    assert any("Wildcard DNS" in message for _level, message in ctx.logs)


def test_scan_subdomains_reports_missing_wordlist(monkeypatch, data_dir):
    monkeypatch.setattr(subdomains, "_run_subfinder", lambda _ctx, _domain: set())
    ctx = DummyContext({"subfinder": False, "bruteforce": True}, target="example.com")
    result = subdomains.scan_subdomains(ctx)

    assert result.metadata["count"] == 0
    assert result.metadata["bruteforce"]["reason"] == "missing-wordlist"
    assert any("wordlist" in message.lower() for _level, message in ctx.logs)
