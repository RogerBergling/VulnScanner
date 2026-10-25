"""Endpoint agent enrollment, jobs and scan creation."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .database import get_db, json_dump, json_load, transaction, utcnow
from .security import (
    authenticate_agent,
    consume_enrollment_token,
    hash_token,
    new_agent_token,
)
from .utils import parse_dt


def public_agent(agent: dict[str, Any]) -> dict[str, Any]:
    result = {key: value for key, value in agent.items() if key != "token_hash"}
    result["online"] = is_online(agent.get("last_seen"))
    result["capabilities"] = json_load(agent.get("capabilities"), [])
    result.pop("token_hash", None)
    return result


def is_online(last_seen: str | None, threshold_seconds: int = 120) -> bool:
    seen = parse_dt(last_seen)
    if not seen:
        return False
    return (datetime.now(timezone.utc) - seen).total_seconds() <= threshold_seconds


def agent_capabilities(agent: dict[str, Any]) -> list[str]:
    value = agent.get("capabilities")
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(item) for item in json_load(value, [])]


def agent_supports(agent: dict[str, Any], module: str) -> bool:
    """True only when the agent advertised the module in its last heartbeat."""
    return module in agent_capabilities(agent)


def enroll_agent(
    enrollment_token: str,
    name: str,
    platform: str,
    version: str,
    hostname: str,
    capabilities: list[str],
    ip: str,
) -> dict[str, Any]:
    token_row = consume_enrollment_token(enrollment_token)
    if not token_row:
        raise ValueError("Enrollment token is invalid, expired or already used")
    customer_id = int(token_row["customer_id"])
    group_id = int(token_row["group_id"])
    agent_id = str(uuid.uuid4())
    display_name = (name or token_row["agent_name"] or hostname or f"agent-{agent_id[:8]}").strip()
    agent_token = new_agent_token()
    now = utcnow()
    with transaction() as conn:
        customer = conn.execute("SELECT id FROM customers WHERE id = ?", (customer_id,)).fetchone()
        group = conn.execute(
            "SELECT id FROM asset_groups WHERE id = ? AND customer_id = ?",
            (group_id, customer_id),
        ).fetchone()
        if not customer or not group:
            raise ValueError("The enrollment token references a removed customer or group")
        # Make the asset name unique within the group.
        base_name = display_name
        suffix = 1
        while conn.execute(
            "SELECT 1 FROM assets WHERE group_id = ? AND name = ?",
            (group_id, display_name),
        ).fetchone():
            suffix += 1
            display_name = f"{base_name} ({suffix})"
        cursor = conn.execute(
            "INSERT INTO assets(customer_id, group_id, name, kind, identifier, description, metadata, created_at) "
            "VALUES (?, ?, ?, 'agent', ?, ?, ?, ?)",
            (
                customer_id,
                group_id,
                display_name,
                agent_id,
                f"Managed by VulnScanner agent {agent_id[:8]}",
                json_dump(
                    {
                        "agent_id": agent_id,
                        "platform": platform,
                        "hostname": hostname,
                        "enrolled_at": now,
                    }
                ),
                now,
            ),
        )
        asset_id = int(cursor.lastrowid)
        conn.execute(
            "INSERT INTO agents("
            "id, customer_id, group_id, asset_id, name, token_hash, platform, version, "
            "hostname, capabilities, status, last_ip, last_seen, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?, ?)",
            (
                agent_id,
                customer_id,
                group_id,
                asset_id,
                display_name,
                hash_token(agent_token),
                platform,
                version,
                hostname,
                json_dump(capabilities),
                ip,
                now,
                now,
            ),
        )
    return {
        "agent_id": agent_id,
        "name": display_name,
        "token": agent_token,
        "customer_id": customer_id,
        "group_id": group_id,
        "asset_id": asset_id,
        "poll_interval": 30,
    }


def _ensure_audit_table() -> None:
    with get_db() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_events("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, "
            "actor TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL DEFAULT '')"
        )
        conn.commit()


def heartbeat(agent: dict[str, Any], payload: dict[str, Any], ip: str) -> dict[str, Any]:
    now = utcnow()
    with get_db() as conn:
        conn.execute(
            "UPDATE agents SET status = 'online', last_seen = ?, last_ip = ?, platform = ?, "
            "version = ?, hostname = ?, capabilities = ? WHERE id = ?",
            (
                now,
                ip,
                payload.get("platform") or agent.get("platform") or "",
                payload.get("version") or agent.get("version") or "",
                payload.get("hostname") or agent.get("hostname") or "",
                json_dump(payload.get("capabilities") or json_load(agent.get("capabilities"), [])),
                agent["id"],
            ),
        )
        if agent.get("asset_id"):
            row = conn.execute(
                "SELECT metadata FROM assets WHERE id = ?", (agent["asset_id"],)
            ).fetchone()
            metadata = json_load(row["metadata"], {}) if row else {}
            metadata.update(
                {
                    "platform": payload.get("platform") or agent.get("platform") or "",
                    "hostname": payload.get("hostname") or agent.get("hostname") or "",
                    "last_seen": now,
                    "agent_version": payload.get("version") or "",
                }
            )
            conn.execute(
                "UPDATE assets SET metadata = ? WHERE id = ?",
                (json_dump(metadata), agent["asset_id"]),
            )
        conn.commit()
    return {"ok": True, "next_poll": 30, "server_time": now}


def claim_next_job(agent: dict[str, Any]) -> dict[str, Any] | None:
    now = utcnow()
    with transaction() as conn:
        row = conn.execute(
            "SELECT * FROM agent_jobs WHERE agent_id = ? AND status = 'queued' "
            "ORDER BY created_at LIMIT 1",
            (agent["id"],),
        ).fetchone()
        if not row:
            return None
        updated = conn.execute(
            "UPDATE agent_jobs SET status = 'running', claimed_at = ? "
            "WHERE id = ? AND status = 'queued'",
            (now, row["id"]),
        )
        if updated.rowcount != 1:
            return None
        job = dict(row)
        job["status"] = "running"
        job["claimed_at"] = now
    job["payload"] = json_load(job.get("payload"), {})
    return job


def complete_job(agent: dict[str, Any], job_id: str, status: str, error: str = "") -> None:
    now = utcnow()
    with get_db() as conn:
        conn.execute(
            "UPDATE agent_jobs SET status = ?, completed_at = ?, error = ? "
            "WHERE id = ? AND agent_id = ?",
            (status, now, error, job_id, agent["id"]),
        )
        conn.commit()


def get_job(agent: dict[str, Any], job_id: str) -> dict[str, Any] | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM agent_jobs WHERE id = ? AND agent_id = ?",
            (job_id, agent["id"]),
        ).fetchone()
    if not row:
        return None
    job = dict(row)
    job["payload"] = json_load(job.get("payload"), {})
    return job


def queue_network_scan_job(
    agent: dict[str, Any],
    scan_id: int,
    target: str,
    options: dict[str, Any],
) -> str:
    """Queue a delegated network scan for an existing scan record."""
    if agent.get("status") == "revoked":
        raise ValueError("Agent has been revoked")
    now = utcnow()
    job_id = str(uuid.uuid4())
    with transaction() as conn:
        conn.execute(
            "UPDATE scans SET status = 'waiting_agent', stage = 'Waiting for agent', agent_id = ? "
            "WHERE id = ?",
            (agent["id"], scan_id),
        )
        conn.execute(
            "INSERT INTO agent_jobs(id, agent_id, scan_id, job_type, payload, status, created_at) "
            "VALUES (?, ?, ?, 'scan', ?, 'queued', ?)",
            (
                job_id,
                agent["id"],
                scan_id,
                json_dump(
                    {
                        "scan_id": scan_id,
                        "modules": ["network"],
                        "target": target,
                        "options": dict(options or {}),
                    }
                ),
                now,
            ),
        )
        conn.execute(
            "INSERT INTO scan_events(scan_id, created_at, level, message) VALUES (?, ?, 'info', ?)",
            (
                scan_id,
                now,
                f"Network scan delegated to {agent.get('name') or agent['id']}",
            ),
        )
    return job_id


def create_agent_scan(
    agent: dict[str, Any],
    modules: list[str],
    paths: list[str],
    options: dict[str, Any],
    requested_by: str = "local",
    target: str = "",
) -> int:
    if agent.get("status") == "revoked":
        raise ValueError("Agent has been revoked")
    modules = list(dict.fromkeys(modules or []))
    if not modules:
        modules = ["system", "packages", "ports"]
    if "network" in modules:
        if len(modules) > 1:
            raise ValueError("Run a network scan as its own agent job")
        if not target.strip():
            raise ValueError("A network scan target is required")
        return create_agent_network_scan(agent, target, options, requested_by)
    if "ad" in modules and agent.get("platform", "").lower() != "windows":
        # It is allowed to queue, but the agent will report a clear error.
        pass
    safe_options = dict(options or {})
    safe_options["modules"] = modules
    safe_options["paths"] = paths[:20]
    now = utcnow()
    job_id = str(uuid.uuid4())
    with transaction() as conn:
        scan_id = int(
            conn.execute(
                "INSERT INTO scans("
                "customer_id, group_id, asset_id, agent_id, scan_type, target, status, "
                "progress, stage, options, summary, requested_by, created_at"
                ") VALUES (?, ?, ?, ?, 'agent', ?, 'waiting_agent', 0, 'Waiting for agent', ?, '{}', ?, ?)",
                (
                    agent["customer_id"],
                    agent["group_id"],
                    agent.get("asset_id"),
                    agent["id"],
                    agent.get("hostname") or agent.get("name") or "endpoint",
                    json_dump(safe_options),
                    requested_by,
                    now,
                ),
            ).lastrowid
        )
        conn.execute(
            "INSERT INTO agent_jobs(id, agent_id, scan_id, job_type, payload, status, created_at) "
            "VALUES (?, ?, ?, 'scan', ?, 'queued', ?)",
            (
                job_id,
                agent["id"],
                scan_id,
                json_dump(
                    {
                        "scan_id": scan_id,
                        "modules": modules,
                        "paths": paths[:20],
                        "options": {
                            "exclude_paths": safe_options.get("exclude_paths", []),
                            "max_files": safe_options.get("max_files", 20000),
                        },
                    }
                ),
                now,
            ),
        )
        conn.execute(
            "INSERT INTO scan_events(scan_id, created_at, level, message) VALUES (?, ?, 'info', ?)",
            (scan_id, now, f"Agent job queued for {agent.get('name') or agent['id']}"),
        )
    return scan_id


def create_agent_network_scan(
    agent: dict[str, Any],
    target: str,
    options: dict[str, Any],
    requested_by: str = "local",
) -> int:
    """Create a network scan owned by one agent without running a server worker."""
    if agent.get("status") == "revoked":
        raise ValueError("Agent has been revoked")
    if not target.strip():
        raise ValueError("A network scan target is required")
    safe_options = dict(options or {})
    now = utcnow()
    job_id = str(uuid.uuid4())
    with transaction() as conn:
        scan_id = int(
            conn.execute(
                "INSERT INTO scans("
                "customer_id, group_id, asset_id, agent_id, scan_type, target, status, "
                "progress, stage, options, summary, requested_by, created_at"
                ") VALUES (?, ?, ?, ?, 'network', ?, 'waiting_agent', 0, 'Waiting for agent', ?, '{}', ?, ?)",
                (
                    agent["customer_id"],
                    agent["group_id"],
                    agent.get("asset_id"),
                    agent["id"],
                    target.strip(),
                    json_dump(safe_options),
                    requested_by,
                    now,
                ),
            ).lastrowid
        )
        conn.execute(
            "INSERT INTO agent_jobs(id, agent_id, scan_id, job_type, payload, status, created_at) "
            "VALUES (?, ?, ?, 'scan', ?, 'queued', ?)",
            (
                job_id,
                agent["id"],
                scan_id,
                json_dump(
                    {
                        "scan_id": scan_id,
                        "modules": ["network"],
                        "target": target.strip(),
                        "options": safe_options,
                    }
                ),
                now,
            ),
        )
        conn.execute(
            "INSERT INTO scan_events(scan_id, created_at, level, message) VALUES (?, ?, 'info', ?)",
            (
                scan_id,
                now,
                f"Network scan delegated to {agent.get('name') or agent['id']}",
            ),
        )
    return scan_id


def get_agent(agent_id: str) -> dict[str, Any] | None:
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT ag.*, c.name customer_name, g.name group_name, a.name asset_name
            FROM agents ag
            LEFT JOIN customers c ON c.id = ag.customer_id
            LEFT JOIN asset_groups g ON g.id = ag.group_id
            LEFT JOIN assets a ON a.id = ag.asset_id
            WHERE ag.id = ?
            """,
            (agent_id,),
        ).fetchone()
    return dict(row) if row else None


def _unique_asset_name(
    conn: Any, group_id: int, desired: str, exclude_asset_id: int | None
) -> str:
    candidate = desired
    suffix = 1
    while conn.execute(
        "SELECT 1 FROM assets WHERE group_id = ? AND name = ? AND id != ?",
        (group_id, candidate, exclude_asset_id or 0),
    ).fetchone():
        suffix += 1
        candidate = f"{desired} ({suffix})"
    return candidate


def update_agent(
    agent_id: str,
    *,
    name: str | None = None,
    customer_id: int | None = None,
    group_id: int | None = None,
) -> dict[str, Any]:
    """Rename an agent or move it to another customer/group.

    The asset created at enrollment moves with the agent so historical results
    remain attached to the same endpoint. Existing scans keep the customer and
    group they were originally run under.
    """
    with transaction() as conn:
        row = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()
        if not row:
            raise KeyError("Agent not found")
        agent = dict(row)
        if agent.get("status") == "revoked":
            raise ValueError("Agent has been revoked")

        target_customer = int(customer_id if customer_id is not None else agent["customer_id"])
        target_group = int(group_id if group_id is not None else agent["group_id"])
        group = conn.execute(
            "SELECT * FROM asset_groups WHERE id = ?", (target_group,)
        ).fetchone()
        if not group:
            raise ValueError("Asset group not found")
        if int(group["customer_id"]) != target_customer:
            raise ValueError("Group does not belong to the selected customer")
        if not conn.execute(
            "SELECT 1 FROM customers WHERE id = ?", (target_customer,)
        ).fetchone():
            raise ValueError("Customer not found")

        requested_name = (name if name is not None else agent["name"]).strip()
        if not requested_name:
            raise ValueError("Agent name is required")
        agent_name = requested_name[:160]
        asset_id = agent.get("asset_id")
        if asset_id:
            asset_name = _unique_asset_name(conn, target_group, agent_name, int(asset_id))
            conn.execute(
                "UPDATE assets SET customer_id = ?, group_id = ?, name = ? WHERE id = ?",
                (target_customer, target_group, asset_name, asset_id),
            )
        conn.execute(
            "UPDATE agents SET name = ?, customer_id = ?, group_id = ? WHERE id = ?",
            (agent_name, target_customer, target_group, agent_id),
        )
    updated = get_agent(agent_id)
    if not updated:
        raise KeyError("Agent not found")
    return updated


def rotate_agent_token(agent_id: str) -> str:
    """Replace an agent token. The caller must show the new token exactly once."""
    with transaction() as conn:
        row = conn.execute("SELECT status FROM agents WHERE id = ?", (agent_id,)).fetchone()
        if not row:
            raise KeyError("Agent not found")
        if row["status"] == "revoked":
            raise ValueError("Agent has been revoked")
        token = new_agent_token()
        conn.execute(
            "UPDATE agents SET token_hash = ? WHERE id = ?",
            (hash_token(token), agent_id),
        )
    return token


def revoke_agent(agent_id: str) -> None:
    now = utcnow()
    with get_db() as conn:
        conn.execute("UPDATE agents SET status = 'revoked' WHERE id = ?", (agent_id,))
        conn.execute(
            "UPDATE agent_jobs SET status = 'cancelled', completed_at = ? "
            "WHERE agent_id = ? AND status IN ('queued', 'running')",
            (now, agent_id),
        )
        conn.execute(
            "UPDATE scans SET status = 'cancelled', stage = 'Agent revoked', completed_at = ?, "
            "error = 'Agent was revoked before the scan completed' "
            "WHERE agent_id = ? AND status = 'waiting_agent'",
            (now, agent_id),
        )
        conn.commit()
