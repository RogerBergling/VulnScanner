"""Tests for Nuclei network-protocol template execution."""

import json
from types import SimpleNamespace

from app.scanners import nuclei
from app.scanners.base import ScanResult
from tests.helpers import DummyContext


def test_network_templates_build_command_and_parse(data_dir, monkeypatch):
    captured = {}

    def fake_run_tool(command, timeout=0):
        captured["command"] = list(command)
        target_file = command[command.index("-l") + 1]
        captured["targets"] = open(target_file, encoding="utf-8").read()
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "template-id": "smb-check",
                    "info": {
                        "name": "SMB check",
                        "severity": "high",
                        "tags": ["network", "smb"],
                        "classification": {"cve-id": ["CVE-2026-0001"]},
                    },
                    "matched-at": "10.0.0.5:445",
                }
            ) + "\n",
        )

    monkeypatch.setattr(nuclei, "tool_path", lambda name: "/usr/bin/nuclei")
    monkeypatch.setattr(nuclei, "setting_or_default", lambda key, default="": "true")
    monkeypatch.setattr(nuclei, "run_tool", fake_run_tool)
    ctx = DummyContext({"nuclei": True, "nuclei_network": True})
    result = ScanResult()
    nuclei.run_nuclei_network(result, ["10.0.0.5:445", "10.0.0.6:22"], ctx)
    assert "-pt" in captured["command"]
    assert captured["command"][captured["command"].index("-pt") + 1] == "tcp"
    assert "10.0.0.5:445" in captured["targets"]
    assert result.findings[0].severity == "high"
    assert result.findings[0].cve == "CVE-2026-0001"


def test_oast_args_disabled_by_default(monkeypatch):
    ctx = DummyContext({})
    assert nuclei._oast_args(ctx) == ["-no-interactsh"]


def test_oast_args_use_configured_collaborator(monkeypatch):
    monkeypatch.setattr(nuclei, "interactsh_server", lambda: "https://oast.example")
    monkeypatch.setattr(nuclei, "interactsh_token", lambda: "secret")
    ctx = DummyContext({"oast": True})
    assert nuclei._oast_args(ctx) == [
        "-interactsh-server",
        "https://oast.example",
        "-interactsh-token",
        "secret",
    ]
