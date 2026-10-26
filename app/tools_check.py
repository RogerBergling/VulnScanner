"""Check external tool availability and versions for optional integrations."""

from __future__ import annotations

from typing import Any

from .scanners.tools import tool_status


def check_external_tools() -> dict[str, Any]:
    """Return status for each optional external scanner tool."""
    results: dict[str, Any] = {}
    for name, entry in tool_status().items():
        results[name] = {
            "available": bool(entry.get("available")),
            "version": entry.get("version") or "Not installed",
            "path": entry.get("path", ""),
            "outdated_warning": False,
        }
    return results
