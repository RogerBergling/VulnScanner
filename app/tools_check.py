"""Check external tool availability, versions and version-policy status."""

from __future__ import annotations

from typing import Any

from .scanners.tools import tool_status
from .tool_policy import evaluate, get_policy


def check_external_tools() -> dict[str, Any]:
    """Return status for each optional external scanner tool."""
    policy = get_policy()
    results: dict[str, Any] = {}
    for name, entry in tool_status().items():
        version = entry.get("version") or ""
        policy_result = evaluate(name, version, policy)
        results[name] = {
            "available": bool(entry.get("available")),
            "version": version or "Not installed",
            "path": entry.get("path", ""),
            "outdated_warning": policy_result["outdated_warning"],
            "minimum_version": policy_result["minimum_version"],
            "policy_status": policy_result["policy_status"],
            "policy_enabled": policy["enabled"],
        }
    return results
