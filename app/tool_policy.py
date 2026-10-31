"""Optional CLI tool version policy.

Python dependencies are locked, but Nmap/Nuclei/Trivy/etc. are installed by
the operator.  Enterprises need a documented minimum version and a way to
enforce it without silently changing scan behaviour.  The policy is stored in
SQLite and can run in warn-only or strict mode.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .database import get_setting

DEFAULT_MINIMUMS: dict[str, str] = {
    "nmap": "7.80",
    "nuclei": "3.0.0",
    "testssl": "3.0.0",
    "trivy": "0.50.0",
    "subfinder": "2.6.0",
    "osv-scanner": "1.6.0",
    "gitleaks": "8.18.0",
    "semgrep": "1.50.0",
    "git": "2.30.0",
}

# Which optional tools a scan type can use.  The scan options still decide
# whether the tool is actually invoked.
SCAN_TOOLS: dict[str, tuple[str, ...]] = {
    "web": ("nuclei",),
    "network": ("nmap", "testssl"),
    "repo": ("git", "gitleaks", "semgrep", "osv-scanner"),
    "github": ("git", "gitleaks", "semgrep", "osv-scanner"),
    "domain": ("subfinder",),
    "ad": (),
}

_VERSION_RE = re.compile(r"(\d+(?:\.\d+){0,3})")


def parse_version(value: str | None) -> tuple[int, ...]:
    match = _VERSION_RE.search(str(value or ""))
    if not match:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


def compare_versions(installed: str | None, minimum: str | None) -> int | None:
    """Return -1/0/1, or None when either version cannot be parsed."""
    left = parse_version(installed)
    right = parse_version(minimum)
    if not left or not right:
        return None
    width = max(len(left), len(right))
    left = left + (0,) * (width - len(left))
    right = right + (0,) * (width - len(right))
    return (left > right) - (left < right)


def get_policy() -> dict[str, Any]:
    enabled = get_setting("tool_version_policy_enabled", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    warn_only = get_setting("tool_version_policy_warn_only", "true").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    minimums = dict(DEFAULT_MINIMUMS)
    try:
        stored = json.loads(get_setting("tool_min_versions", "{}"))
        if isinstance(stored, dict):
            for name, value in stored.items():
                if name in DEFAULT_MINIMUMS and str(value or "").strip():
                    minimums[name] = str(value).strip()
    except (TypeError, ValueError):
        pass
    return {"enabled": enabled, "warn_only": warn_only, "minimums": minimums}


def set_policy(
    *,
    enabled: bool | None = None,
    warn_only: bool | None = None,
    minimums: dict[str, str] | None = None,
) -> dict[str, Any]:
    from .database import set_setting

    if enabled is not None:
        set_setting("tool_version_policy_enabled", "true" if enabled else "false")
    if warn_only is not None:
        set_setting("tool_version_policy_warn_only", "true" if warn_only else "false")
    if minimums is not None:
        cleaned: dict[str, str] = {}
        for name, value in minimums.items():
            if name not in DEFAULT_MINIMUMS:
                continue
            text = str(value or "").strip()
            if text:
                if not parse_version(text):
                    raise ValueError(f"Invalid minimum version for {name}: {text}")
                cleaned[name] = text
        set_setting("tool_min_versions", json.dumps(cleaned, separators=(",", ":")))
    return get_policy()


def evaluate(name: str, version: str | None, policy: dict[str, Any] | None = None) -> dict[str, Any]:
    policy = policy or get_policy()
    minimum = str(policy.get("minimums", {}).get(name, "") or "")
    if not version or not minimum:
        return {
            "minimum_version": minimum,
            "policy_status": "unknown",
            "outdated_warning": False,
        }
    comparison = compare_versions(version, minimum)
    if comparison is None:
        status = "unknown"
    elif comparison < 0:
        status = "outdated"
    else:
        status = "ok"
    return {
        "minimum_version": minimum,
        "policy_status": status,
        "outdated_warning": status == "outdated",
    }


def enforce_scan_policy(
    scan_type: str, options: dict[str, Any], *, tool_status: dict[str, Any] | None = None
) -> list[str]:
    """Return policy warnings; raise when strict mode finds an outdated tool."""
    policy = get_policy()
    if not policy["enabled"]:
        return []
    if tool_status is None:
        from .scanners.tools import tool_status as read_status

        tool_status = read_status()
    warnings: list[str] = []
    for name in SCAN_TOOLS.get(scan_type, ()):
        entry = tool_status.get(name) or {}
        if not entry.get("available"):
            continue
        result = evaluate(name, entry.get("version"), policy)
        if result["policy_status"] != "outdated":
            continue
        message = (
            f"{name} {entry.get('version')} is older than the configured minimum "
            f"{result['minimum_version']}"
        )
        if policy["warn_only"]:
            warnings.append(message)
        else:
            raise ValueError(
                message + ". Upgrade the tool or switch the tool version policy to warn-only."
            )
    return warnings
