"""Trivy command construction, parsing and de-duplication."""

from __future__ import annotations

import json

from app.scanners import trivy
from app.scanners.base import Finding, ScanResult
from tests.helpers import DummyContext

REPORT = {
    "Results": [
        {
            "Target": "package-lock.json",
            "Type": "npm",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-0001",
                    "PkgName": "lodash",
                    "InstalledVersion": "1.0.0",
                    "FixedVersion": "1.0.1",
                    "Severity": "HIGH",
                    "Title": "Prototype pollution",
                    "Description": "A dependency issue.",
                    "CVSS": {"nvd": {"V3Score": 7.5}},
                    "CweIDs": ["CWE-1321"],
                    "Aliases": ["GHSA-test"],
                }
            ],
        },
        {
            "Target": "Dockerfile",
            "Type": "dockerfile",
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "AVDID": "AVD-DS-0002",
                    "Severity": "MEDIUM",
                    "Title": "Container runs as root",
                    "Description": "The container runs as root.",
                    "Message": "Specify a non-root user.",
                    "Resolution": "Add a USER instruction.",
                    "CauseMetadata": {"StartLine": 3},
                    "Type": "Dockerfile",
                }
            ],
        },
        {
            "Target": ".env",
            "Secrets": [
                {
                    "RuleID": "aws-access-key-id",
                    "Title": "AWS Access Key ID",
                    "Severity": "CRITICAL",
                    "StartLine": 2,
                    "Match": "AKIAIOSFODNN7EXAMPLE",
                }
            ],
        },
    ]
}


def _proc(payload: dict) -> object:
    class Proc:
        returncode = 0
        stdout = json.dumps(payload)
        stderr = ""

    return Proc()


def test_scan_trivy_converts_and_deduplicates(monkeypatch, data_dir):
    monkeypatch.setattr(trivy, "get_setting", lambda _key, default="": "true")
    monkeypatch.setattr(trivy, "tool_path", lambda _name: "/usr/local/bin/trivy")
    monkeypatch.setattr(trivy, "ENABLE_EXTERNAL_APIS", False)
    calls: list[list[str]] = []

    def fake_run(command, timeout=0):
        calls.append(command)
        assert timeout == 900
        return _proc(REPORT)

    monkeypatch.setattr(trivy, "run_tool", fake_run)

    result = ScanResult()
    ctx = DummyContext({"external_tools": True, "trivy": True}, target="/srv/repo")
    count = trivy.scan_trivy(ctx, data_dir / "repo", result)

    assert count == 3
    assert len(result.findings) == 3
    categories = {finding.category for finding in result.findings}
    assert categories == {"dependency", "misconfiguration", "secret"}

    dependency = next(item for item in result.findings if item.category == "dependency")
    assert dependency.cve == "CVE-2024-0001"
    assert dependency.cvss == 7.5
    assert dependency.cwe == "CWE-1321"
    assert dependency.raw["detected_by"] == "trivy"

    secret = next(item for item in result.findings if item.category == "secret")
    assert secret.severity == "critical"
    assert "AKIA" in secret.evidence
    assert "AKIAIOSFODNN7EXAMPLE" not in secret.evidence

    command = calls[0]
    assert command[0].endswith("trivy")
    assert command[1] == "fs"
    assert "--scanners" in command
    assert command[command.index("--scanners") + 1] == "vuln,misconfig,secret"
    assert "--skip-db-update" in command
    assert str(data_dir / "trivy-cache") in command


def test_scan_trivy_skips_builtin_duplicates(monkeypatch, data_dir):
    monkeypatch.setattr(trivy, "get_setting", lambda _key, default="": "true")
    monkeypatch.setattr(trivy, "tool_path", lambda _name: "/usr/local/bin/trivy")
    monkeypatch.setattr(trivy, "ENABLE_EXTERNAL_APIS", True)
    monkeypatch.setattr(trivy, "run_tool", lambda *_args, **_kwargs: _proc(REPORT))

    result = ScanResult()
    result.add(
        Finding(
            severity="high",
            title="Existing lodash finding",
            category="dependency",
            cve="CVE-2024-0001",
            raw={"package": "lodash", "version": "1.0.0"},
        )
    )
    ctx = DummyContext({"external_tools": True, "trivy": True}, target="/srv/repo")
    count = trivy.scan_trivy(ctx, data_dir / "repo", result)

    assert count == 2
    statuses = {finding.category for finding in result.findings}
    assert statuses == {"dependency", "misconfiguration", "secret"}


def test_scan_trivy_missing_or_malformed(monkeypatch, data_dir):
    ctx = DummyContext({"external_tools": True, "trivy": True}, target="/srv/repo")
    result = ScanResult()

    monkeypatch.setattr(trivy, "tool_path", lambda _name: None)
    assert trivy.scan_trivy(ctx, data_dir / "repo", result) == 0
    assert any("not installed" in message for _level, message in ctx.logs)

    monkeypatch.setattr(trivy, "tool_path", lambda _name: "/usr/local/bin/trivy")
    monkeypatch.setattr(trivy, "get_setting", lambda _key, default="": "true")

    class BadProc:
        returncode = 1
        stdout = "not json"
        stderr = "boom"

    monkeypatch.setattr(trivy, "run_tool", lambda *_args, **_kwargs: BadProc())
    assert trivy.scan_trivy(ctx, data_dir / "repo", result) == 0
    assert any("usable JSON" in message for _level, message in ctx.logs)
