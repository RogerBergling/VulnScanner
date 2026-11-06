"""Scan policies: reusable, GUI-managed configuration presets.

A policy is a set of scan options applied when a scan is created; explicit
per-scan options override the policy. Built-in starter policies model common
workflows (discovery, basic network, web application, PCI-DSS, OWASP Top 10)
and can be disabled but not edited; operators create their own policies with
any name and option set.
"""

from __future__ import annotations

from typing import Any

from .database import get_db, json_dump, json_load, set_setting, setting_or_default, utcnow

BUILTIN_POLICIES: list[dict[str, Any]] = [
    {
        "name": "Discovery",
        "scan_type": "network",
        "description": (
            "Fast asset discovery: top-1000 ports, no web/cve/nuclei depth, "
            "service probes on."
        ),
        "options": {
            "profile": "top1000",
            "web_checks": False,
            "cve_lookup": False,
            "service_probes": True,
            "nuclei": False,
            "scan_unresponsive_hosts": True,
            "connect_timeout": 0.3,
        },
    },
    {
        "name": "Basic network scan",
        "scan_type": "network",
        "description": (
            "Balanced unauthenticated scan: common ports, deep web checks, "
            "service probes, CVE matching and the Nuclei signature engine."
        ),
        "options": {
            "profile": "common",
            "web_checks": True,
            "cve_lookup": True,
            "service_probes": True,
            "nuclei": True,
            "scan_unresponsive_hosts": True,
        },
    },
    {
        "name": "Web application",
        "scan_type": "web",
        "description": (
            "Full web assessment: active checks, Nuclei signature engine, "
            "CVE matching and deep TLS review."
        ),
        "options": {
            "active": True,
            "nuclei": True,
            "cve_lookup": True,
            "external_tools": True,
            "testssl": True,
            "max_web_pages": 10,
        },
    },
    {
        "name": "PCI-DSS",
        "scan_type": "network",
        "description": (
            "Compliance-oriented scan: common ports, deep web checks, CVE "
            "matching, signature engine and TLS review for cardholder "
            "environments."
        ),
        "options": {
            "profile": "common",
            "web_checks": True,
            "cve_lookup": True,
            "service_probes": True,
            "nuclei": True,
            "external_tools": True,
            "testssl": True,
        },
    },
    {
        "name": "OWASP Top 10",
        "scan_type": "web",
        "description": (
            "Web application security: active injection checks plus the "
            "Nuclei signature engine focused on OWASP-relevant tags."
        ),
        "options": {
            "active": True,
            "nuclei": True,
            "nuclei_tags": "cve,xss,lfi,rce,ssrf,ssti,redirect,exposure",
            "cve_lookup": True,
            "max_web_pages": 10,
        },
    },
]


def seed_builtin_policies() -> int:
    """Insert missing built-in policies. Idempotent by name."""
    now = utcnow()
    with get_db() as conn:
        existing = {
            row["name"] for row in conn.execute("SELECT name FROM scan_policies")
        }
        inserted = 0
        for policy in BUILTIN_POLICIES:
            if policy["name"] in existing:
                continue
            conn.execute(
                "INSERT INTO scan_policies"
                "(name, description, scan_type, builtin, options, created_at, updated_at) "
                "VALUES (?, ?, ?, 1, ?, ?, ?)",
                (
                    policy["name"],
                    policy["description"],
                    policy["scan_type"],
                    json_dump(policy["options"]),
                    now,
                    now,
                ),
            )
            inserted += 1
        conn.commit()
    return inserted


def _row_to_dict(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "scan_type": row["scan_type"],
        "builtin": bool(row["builtin"]),
        "options": json_load(row["options"], {}),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def list_policies() -> list[dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_policies ORDER BY builtin DESC, name COLLATE NOCASE"
        ).fetchall()
    return [_row_to_dict(row) for row in rows]


def get_policy(policy_id: int) -> dict[str, Any] | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM scan_policies WHERE id = ?", (policy_id,)
        ).fetchone()
    return _row_to_dict(row) if row else None


def get_scan_policy(policy_id: int) -> dict[str, Any] | None:
    """Alias for callers where `get_policy` collides with the tool policy."""
    return get_policy(policy_id)


def create_policy(name: str, scan_type: str, options: dict[str, Any],
                  description: str = "") -> dict[str, Any]:
    name = name.strip()
    if not name:
        raise ValueError("Policy name is required")
    now = utcnow()
    with get_db() as conn:
        exists = conn.execute(
            "SELECT 1 FROM scan_policies WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()
        if exists:
            raise ValueError(f"A policy named '{name}' already exists")
        cursor = conn.execute(
            "INSERT INTO scan_policies"
            "(name, description, scan_type, builtin, options, created_at, updated_at) "
            "VALUES (?, ?, ?, 0, ?, ?, ?)",
            (name, description, scan_type, json_dump(options), now, now),
        )
        conn.commit()
        return get_policy(int(cursor.lastrowid))  # type: ignore[return-value]


def update_policy(policy_id: int, *, name: str | None = None,
                  description: str | None = None,
                  scan_type: str | None = None,
                  options: dict[str, Any] | None = None) -> dict[str, Any]:
    policy = get_policy(policy_id)
    if not policy:
        raise ValueError("Policy not found")
    if policy["builtin"]:
        raise ValueError("Built-in policies cannot be edited; create your own policy instead")
    fields: list[str] = []
    values: list[Any] = []
    if name is not None:
        name = name.strip()
        if not name:
            raise ValueError("Policy name is required")
        fields.append("name = ?")
        values.append(name)
    if description is not None:
        fields.append("description = ?")
        values.append(description)
    if scan_type is not None:
        fields.append("scan_type = ?")
        values.append(scan_type)
    if options is not None:
        fields.append("options = ?")
        values.append(json_dump(options))
    if not fields:
        return policy
    fields.append("updated_at = ?")
    values.append(utcnow())
    values.append(policy_id)
    with get_db() as conn:
        conn.execute(
            f"UPDATE scan_policies SET {', '.join(fields)} WHERE id = ?", values
        )
        conn.commit()
    return get_policy(policy_id)  # type: ignore[return-value]


def delete_policy(policy_id: int) -> bool:
    policy = get_policy(policy_id)
    if not policy:
        return False
    if policy["builtin"]:
        raise ValueError("Built-in policies cannot be deleted")
    with get_db() as conn:
        conn.execute("DELETE FROM scan_policies WHERE id = ?", (policy_id,))
        conn.commit()
    return True


def merge_policy_options(policy_options: dict[str, Any],
                         scan_options: dict[str, Any]) -> dict[str, Any]:
    """Policy options first; explicit per-scan options win per key."""
    merged = dict(policy_options or {})
    merged.update(scan_options or {})
    return merged


def resolve_policy(policy_id: int | None, scan_type: str,
                   scan_options: dict[str, Any]) -> dict[str, Any]:
    """Return the effective options for a scan, applying a policy if selected."""
    if not policy_id:
        return dict(scan_options)
    policy = get_policy(policy_id)
    if not policy:
        raise ValueError(f"Scan policy {policy_id} does not exist")
    if policy["scan_type"] != scan_type:
        raise ValueError(
            f"Policy '{policy['name']}' is for {policy['scan_type']} scans, "
            f"not {scan_type}"
        )
    merged = merge_policy_options(policy["options"], scan_options)
    merged["policy_id"] = policy_id
    merged["policy_name"] = policy["name"]
    return merged


def default_policy_id() -> int | None:
    """Return the operator-selected default policy id, if any."""
    raw = setting_or_default("default_scan_policy", "")
    try:
        policy_id = int(raw or 0)
    except (TypeError, ValueError):
        return None
    return policy_id or None


def set_default_policy(policy_id: int | None) -> None:
    set_setting("default_scan_policy", str(policy_id) if policy_id else "")


def policy_options_valid(policy_id: int) -> bool:
    return get_policy(policy_id) is not None
