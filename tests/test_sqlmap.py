"""Tests for the double-gated sqlmap integration (offline)."""

from app.scanners.base import ScanResult
from app.scanners.sqlmap import _parse_sqlmap_output, run_sqlmap
from tests.helpers import DummyContext

SQLMAP_OUTPUT = """
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.8#stable}
[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual
    consent is illegal.

[*] starting @ 12:00:00 /2026-01-01/

[12:00:10] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1
---
[12:00:40] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
[12:00:41] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output'
"""

SQLMAP_CLEAN_OUTPUT = """
[*] starting @ 12:00:00 /2026-01-01/
[12:00:10] [INFO] testing connection to the target URL
[12:00:40] [CRITICAL] all tested parameters do not appear to be injectable.
"""


def test_parse_sqlmap_output_confirmed():
    result = ScanResult()
    added = _parse_sqlmap_output(result, "https://example.test/item?id=1", SQLMAP_OUTPUT)
    assert added == 1
    finding = result.normalized()[0]
    assert finding["severity"] == "critical"
    assert finding["cwe"] == "CWE-89"
    assert "boolean-based blind" in finding["description"]
    assert finding["key"] == "sqlmap:id"
    assert "Payload sample: id=1 AND 1=1" in finding["evidence"]


def test_parse_sqlmap_output_clean():
    result = ScanResult()
    assert _parse_sqlmap_output(result, "https://example.test/?id=1", SQLMAP_CLEAN_OUTPUT) == 0
    assert result.findings == []


def test_run_sqlmap_requires_global_gate(monkeypatch):
    from app.scanners import sqlmap

    monkeypatch.setattr(sqlmap, "setting_or_default", lambda *a, **k: "false")
    result = ScanResult()
    ctx = DummyContext({"sqlmap": True})
    assert run_sqlmap(result, ["https://example.test/?id=1"], ctx) == 0
    assert any("dangerous-tools" in message for _level, message in ctx.logs)


def test_run_sqlmap_requires_scan_option(monkeypatch):
    from app.scanners import sqlmap

    monkeypatch.setattr(sqlmap, "setting_or_default", lambda *a, **k: "true")
    result = ScanResult()
    ctx = DummyContext()
    assert run_sqlmap(result, ["https://example.test/?id=1"], ctx) == 0
    assert ctx.logs == []


def test_run_sqlmap_skipped_without_binary(monkeypatch):
    from app.scanners import sqlmap

    monkeypatch.setattr(sqlmap, "setting_or_default", lambda *a, **k: "true")
    result = ScanResult()
    ctx = DummyContext({"sqlmap": True})
    assert run_sqlmap(result, ["https://example.test/?id=1"], ctx) == 0
    assert any("not installed" in message for _level, message in ctx.logs)


def test_run_sqlmap_invokes_tool(monkeypatch):
    from app.scanners import sqlmap

    class Proc:
        returncode = 0
        stdout = SQLMAP_OUTPUT
        stderr = ""

    calls: list[list[str]] = []

    def fake_run_tool(command, **_kwargs):
        calls.append(command)
        return Proc()

    monkeypatch.setattr(sqlmap, "setting_or_default", lambda *a, **k: "true")
    monkeypatch.setattr(sqlmap, "tool_path", lambda name: "/usr/bin/sqlmap")
    monkeypatch.setattr(sqlmap, "run_tool", fake_run_tool)
    result = ScanResult()
    ctx = DummyContext({"sqlmap": True, "max_sqlmap_targets": 3})
    added = run_sqlmap(result, ["https://example.test/?id=1"], ctx)
    assert added == 1
    assert calls
    assert "--batch" in calls[0]
    assert "https://example.test/?id=1" in calls[0]
