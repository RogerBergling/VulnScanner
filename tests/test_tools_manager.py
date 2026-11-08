"""Tests for per-tool source selection and managed binaries."""

from app.scanners import tools
from app.tools_manager import managed_tool_path, set_tool_source, tool_mode


def test_disable_tool_returns_no_path(data_dir):
    set_tool_source("nuclei", "disabled")
    assert tool_mode("nuclei") == "disabled"
    assert tools.tool_path("nuclei") is None


def test_explicit_path_mode(data_dir, tmp_path):
    binary = tmp_path / "nuclei"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    set_tool_source("nuclei", "path", str(binary))
    assert tools.tool_path("nuclei") == str(binary)


def test_managed_tool_path(data_dir):
    target = data_dir / "tools" / "nuclei" / "9.9.9" / "nuclei"
    target.parent.mkdir(parents=True)
    target.write_text("#!/bin/sh\n")
    target.chmod(0o755)
    set_tool_source("nuclei", "managed")
    assert managed_tool_path("nuclei") == str(target)
    assert tools.tool_path("nuclei") == str(target)


def test_unknown_tool_rejected(data_dir):
    import pytest

    with pytest.raises(ValueError):
        set_tool_source("not-a-tool", "system")


def test_tools_api_lists_and_updates_sources(api_client):
    listed = api_client.get("/api/tools")
    assert listed.status_code == 200
    names = {item["name"] for item in listed.json()["tools"]}
    assert {"nuclei", "nmap", "osv-scanner"} <= names

    updated = api_client.patch(
        "/api/tools/nuclei", json={"mode": "disabled", "path": ""}
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["mode"] == "disabled"
    assert tools.tool_path("nuclei") is None
