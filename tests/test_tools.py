import subprocess

from app.scanners import tools


def test_tool_path_prefers_configured_existing_file(tmp_path, monkeypatch):
    executable = tmp_path / "fake-tool"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setitem(tools.TOOL_PATHS, "nmap", str(executable))
    assert tools.tool_path("nmap") == str(executable)
    monkeypatch.setitem(tools.TOOL_PATHS, "nmap", str(tmp_path / "missing"))
    monkeypatch.setattr(tools.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert tools.tool_path("nmap") == "/usr/bin/nmap"


def test_tool_status_reports_available_and_missing(monkeypatch):
    monkeypatch.setattr(tools, "tool_path", lambda name: "/bin/echo" if name == "nmap" else None)

    class Proc:
        stdout = "Nmap version 7.95\n"
        stderr = ""

    monkeypatch.setattr(tools.subprocess, "run", lambda *_args, **_kwargs: Proc())
    status = tools.tool_status()
    assert status["nmap"]["available"] is True
    assert status["nmap"]["version"] == "Nmap version 7.95"
    assert status["nuclei"] == {"available": False, "path": "", "version": ""}


def test_tool_status_handles_version_timeout(monkeypatch):
    monkeypatch.setattr(tools, "tool_path", lambda name: "/bin/tool" if name == "nmap" else None)

    def boom(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="tool", timeout=8)

    monkeypatch.setattr(tools.subprocess, "run", boom)
    status = tools.tool_status()
    assert status["nmap"]["available"] is False


def test_run_tool_uses_arguments_without_shell(monkeypatch):
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured.update(kwargs)
        return subprocess.CompletedProcess(args, 0, "ok", "")

    monkeypatch.setattr(tools.subprocess, "run", fake_run)
    proc = tools.run_tool(["echo", "hello"], timeout=5, cwd="/tmp")
    assert proc.stdout == "ok"
    assert captured["args"] == ["echo", "hello"]
    assert captured["timeout"] == 5
    assert captured["cwd"] == "/tmp"
    assert captured["check"] is False
