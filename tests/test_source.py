import json
import subprocess

from app.scanners import source
from tests.helpers import DummyContext


def test_semgrep_findings_are_normalized(monkeypatch, tmp_path):
    target = tmp_path / "app.py"
    target.write_text("print('hello')\n", encoding="utf-8")
    payload = {
        "results": [
            {
                "check_id": "python.lang.security.audit.test-rule",
                "path": str(target),
                "start": {"line": 1},
                "extra": {
                    "severity": "ERROR",
                    "message": "A test rule matched.",
                    "lines": "print('hello')",
                    "metadata": {
                        "cwe": ["CWE-79: Improper Neutralization"],
                        "confidence": "HIGH",
                        "remediation": "Fix the data flow.",
                    },
                },
            }
        ],
        "errors": [],
    }
    monkeypatch.setattr(source, "ENABLE_EXTERNAL_APIS", True)
    monkeypatch.setattr(source, "tool_path", lambda name: "/usr/bin/semgrep")
    monkeypatch.setattr(
        source,
        "run_tool",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, json.dumps(payload), ""),
    )

    result = source.scan_source(DummyContext({"external_tools": True}), tmp_path)

    findings = [item for item in result.findings if item.category == "source" and item.key.startswith("semgrep:")]
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].cwe == "CWE-79"
    assert findings[0].location == "app.py:1"
    assert result.metadata["semgrep_findings"] == 1


def test_semgrep_is_skipped_without_external_tools(monkeypatch, tmp_path):
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    monkeypatch.setattr(source, "ENABLE_EXTERNAL_APIS", True)
    monkeypatch.setattr(
        source,
        "run_tool",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("should not run")),
    )

    result = source.scan_source(DummyContext({"external_tools": False}), tmp_path)

    assert result.metadata["semgrep_findings"] == 0
