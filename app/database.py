"""SQLite storage layer.

SQLite is deliberately used instead of an external database: the application
must work on a single workstation with no services to install.  WAL mode keeps
the web UI responsive while scans write results from background workers.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

from .config import database_path

SCHEMA_VERSION = 3

SCHEMA = """
CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    name TEXT NOT NULL COLLATE NOCASE,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(customer_id, name)
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'host',
    identifier TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(group_id, name)
);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    platform TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    capabilities TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'offline',
    last_ip TEXT NOT NULL DEFAULT '',
    last_seen TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    agent_name TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER REFERENCES customers(id) ON DELETE SET NULL,
    group_id INTEGER REFERENCES asset_groups(id) ON DELETE SET NULL,
    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    agent_id TEXT REFERENCES agents(id) ON DELETE SET NULL,
    scan_type TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'queued',
    progress INTEGER NOT NULL DEFAULT 0,
    stage TEXT NOT NULL DEFAULT 'Queued',
    options TEXT NOT NULL DEFAULT '{}',
    summary TEXT NOT NULL DEFAULT '{}',
    error TEXT NOT NULL DEFAULT '',
    requested_by TEXT NOT NULL DEFAULT 'local',
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    cancelled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scan_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info',
    message TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    cve TEXT NOT NULL DEFAULT '',
    cwe TEXT NOT NULL DEFAULT '',
    cvss REAL,
    location TEXT NOT NULL DEFAULT '',
    resource TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    raw TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset_fp ON findings(asset_id, fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_customer ON scans(customer_id, created_at);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scan_events_scan ON scan_events(scan_id, id);

CREATE TABLE IF NOT EXISTS agent_jobs (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    job_type TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'queued',
    created_at TEXT NOT NULL,
    claimed_at TEXT,
    completed_at TEXT,
    error TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_agent_jobs_agent ON agent_jobs(agent_id, status, created_at);

-- Scan credentials are stored encrypted (Fernet). Global profiles have a NULL
-- customer_id; customer profiles are only used for that customer. Asset
-- bindings select a profile per operating system for a single asset.
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    os TEXT NOT NULL,
    username TEXT NOT NULL,
    domain TEXT NOT NULL DEFAULT '',
    account_type TEXT NOT NULL DEFAULT '',
    auth_type TEXT NOT NULL DEFAULT 'password',
    secret TEXT NOT NULL,
    passphrase TEXT NOT NULL DEFAULT '',
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_credentials_customer ON credentials(customer_id, os);

CREATE TABLE IF NOT EXISTS asset_credential_bindings (
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    os TEXT NOT NULL,
    credential_id INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    PRIMARY KEY (asset_id, os)
);

CREATE TABLE IF NOT EXISTS scan_credentials (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    os TEXT NOT NULL,
    username TEXT NOT NULL,
    domain TEXT NOT NULL DEFAULT '',
    account_type TEXT NOT NULL DEFAULT '',
    auth_type TEXT NOT NULL DEFAULT 'password',
    secret TEXT NOT NULL,
    passphrase TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    PRIMARY KEY (scan_id, os)
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS osv_cache (
    cache_key TEXT PRIMARY KEY,
    response TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS kev_catalog (
    cve_id TEXT PRIMARY KEY,
    vendor_project TEXT NOT NULL DEFAULT '',
    product TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    date_added TEXT NOT NULL DEFAULT '',
    due_date TEXT NOT NULL DEFAULT '',
    known_ransomware TEXT NOT NULL DEFAULT '',
    required_action TEXT NOT NULL DEFAULT '',
    synced_at TEXT NOT NULL
);

-- Scheduled scans define recurring targets that run on a schedule and may send
-- notifications when completed.
CREATE TABLE IF NOT EXISTS scan_schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
    group_id INTEGER REFERENCES asset_groups(id) ON DELETE CASCADE,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    scan_type TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    options TEXT NOT NULL DEFAULT '{}',
    cron_expression TEXT NOT NULL DEFAULT '',
    notify_email TEXT NOT NULL DEFAULT '',
    notify_webhook TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    error TEXT NOT NULL DEFAULT '',
    last_run TEXT,
    next_run TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_schedules_customer ON scan_schedules(customer_id);
CREATE INDEX IF NOT EXISTS idx_scan_schedules_enabled_next ON scan_schedules(enabled, next_run);

-- Continuous inventory: discovered hosts tracked per scan with device type, MAC/IP, last seen
CREATE TABLE IF NOT EXISTS asset_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
    ip_address TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    mac_address TEXT NOT NULL DEFAULT '',
    device_type TEXT NOT NULL DEFAULT '',
    ports TEXT NOT NULL DEFAULT '[]',
    os_guess TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
);
CREATE INDEX IF NOT EXISTS idx_inventory_scan ON asset_inventory(scan_id);
CREATE INDEX IF NOT EXISTS idx_inventory_customer ON asset_inventory(customer_id);
CREATE INDEX IF NOT EXISTS idx_inventory_ip ON asset_inventory(ip_address);

-- Historical finding trends: per-asset fingerprint tracking over scans
CREATE TABLE IF NOT EXISTS finding_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    first_seen_scan_id INTEGER,
    last_seen_scan_id INTEGER,
    severity_at_first TEXT,
    severity_at_last TEXT,
    status_at_first TEXT,
    status_at_last TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_finding_history_asset_fp ON finding_history(asset_id, fingerprint);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(database_path(), timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


@contextmanager
def get_db() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def transaction() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def init_db() -> None:
    with get_db() as conn:
        current_version = conn.execute("PRAGMA user_version").fetchone()[0]

        if current_version < SCHEMA_VERSION:
            # Split SCHEMA into separate migrations for controlled upgrade
            conn.executescript(SCHEMA)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        # Always ensure settings exist
        defaults = {
            "allow_external_apis": "true",
            "nuclei_enabled": "true",
            "nmap_enabled": "true",
            "kev_last_sync": "",
            "product_name": "VulnScanner",
            "risk_acceptance_note": "",
        }
        for key, value in defaults.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)",
                (key, value),
            )
        conn.commit()


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def json_load(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def get_setting(key: str, default: str = "") -> str:
    with get_db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with get_db() as conn:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        conn.commit()


def log_event(scan_id: int, message: str, level: str = "info") -> None:
    with get_db() as conn:
        conn.execute(
            "INSERT INTO scan_events(scan_id, created_at, level, message) VALUES (?, ?, ?, ?)",
            (scan_id, utcnow(), level, message),
        )
        conn.commit()


def update_scan(scan_id: int, **fields: Any) -> None:
    allowed = {
        "status", "progress", "stage", "summary", "error", "started_at",
        "completed_at", "cancelled", "target", "agent_id",
    }
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return
    for key in ("summary",):
        if key in updates and not isinstance(updates[key], str):
            updates[key] = json_dump(updates[key])
    set_sql = ", ".join(f"{key} = ?" for key in updates)
    with get_db() as conn:
        conn.execute(
            f"UPDATE scans SET {set_sql} WHERE id = ?",
            (*updates.values(), scan_id),
        )
        conn.commit()


def scan_cancelled(scan_id: int) -> bool:
    with get_db() as conn:
        row = conn.execute("SELECT cancelled FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return bool(row and row["cancelled"])


def ensure_default_group(customer_id: int) -> int:
    with get_db() as conn:
        row = conn.execute(
            "SELECT id FROM asset_groups WHERE customer_id = ? ORDER BY id LIMIT 1",
            (customer_id,),
        ).fetchone()
        if row:
            return int(row["id"])
        cur = conn.execute(
            "INSERT INTO asset_groups(customer_id, name, description, created_at) "
            "VALUES (?, 'General', 'Default asset group', ?)",
            (customer_id, utcnow()),
        )
        conn.commit()
        return int(cur.lastrowid)
