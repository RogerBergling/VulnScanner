"""testssl.sh JSON parsing and execution gating."""

from __future__ import annotations

from app.scanners import testssl
from app.scanners.base import ScanResult
from tests.helpers import DummyContext

PAYLOAD = [
    {
        "id": "cert_chain_of_trust",
        "severity": "CRITICAL",
        "finding": "Certificate chain is incomplete",
        "cve": "CVE-2020-1234",
    },
    {"id": "service", "severity": "INFO", "finding": "service detected"},
    {"id": "TLS1", "severity": "OK", "finding": "not offered"},
    {
        "id": "forward_secrecy",
        "severity": "WARN",
        "finding": "No forward secrecy",
        "cwe": "CWE-326",
    },
    {"id": "protocol", "severity": "UNKNOWN", "finding": "ignored"},
]


def test_parse_testssl_legacy_list():
    findings = testssl.parse_testssl_json(PAYLOAD, "example.test", 443)
    assert len(findings) == 2
    by_key = {item["key"]: item for item in findings}
    cert = by_key["testssl:cert_chain_of_trust"]
    assert cert["severity"] == "critical"
    assert cert["cve"] == "CVE-2020-1234"
    assert cert["location"] == "example.test:443"
    assert cert["title"].startswith("TLS configuration issue:")
    assert "Rotate" not in cert["remediation"]
    fs = by_key["testssl:forward_secrecy"]
    assert fs["severity"] == "medium"
    assert fs["cwe"] == "CWE-326"
    assert "forward-secret" in fs["remediation"]


def test_parse_testssl_scan_result_shape_and_unknown_payload():
    findings = testssl.parse_testssl_json(
        {"scanResult": [{"id": "cert_expiry", "severity": "HIGH", "finding": "expired"}]},
        "example.test",
        8443,
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"

    assert testssl.parse_testssl_json({"unexpected": True}, "example.test", 443) == []
    assert testssl.parse_testssl_json("not a report", "example.test", 443) == []


def test_run_testssl_uses_json_report(monkeypatch):
    monkeypatch.setattr(testssl, "get_setting", lambda _key, default="": "true")
    monkeypatch.setattr(testssl, "tool_path", lambda _name: "/opt/testssl/testssl.sh")
    calls: list[list[str]] = []

    class Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(command, timeout=0):
        calls.append(command)
        assert timeout == 600
        return Proc()

    monkeypatch.setattr(testssl, "run_tool", fake_run)
    monkeypatch.setattr(testssl, "_read_report", lambda _path: PAYLOAD)

    ctx = DummyContext({"external_tools": True, "testssl": True}, target="example.test")
    result = ScanResult()
    count = testssl.run_testssl(result, "example.test", 443, ctx)

    assert count == 2
    assert len(result.findings) == 2
    assert calls
    command = calls[0]
    assert command[0] == "/opt/testssl/testssl.sh"
    assert "--jsonfile" in command
    assert command[-1] == "example.test:443"


def test_run_testssl_is_optional(monkeypatch):
    called = False

    def fake_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("testssl.sh must not run when disabled")

    monkeypatch.setattr(testssl, "run_tool", fake_run)
    monkeypatch.setattr(testssl, "tool_path", lambda _name: "/opt/testssl/testssl.sh")

    ctx = DummyContext({})
    result = ScanResult()
    assert testssl.run_testssl(result, "example.test", 443, ctx) == 0
    assert not called

    monkeypatch.setattr(testssl, "get_setting", lambda _key, default="": "true")
    monkeypatch.setattr(testssl, "tool_path", lambda _name: None)
    missing = DummyContext({"external_tools": True, "testssl": True})
    assert testssl.run_testssl(result, "example.test", 443, missing) == 0
    assert any("not installed" in message for _level, message in missing.logs)
