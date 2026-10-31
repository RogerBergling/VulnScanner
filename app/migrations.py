"""Ordered SQLite schema migrations.

``schema_migrations`` records every applied step.  Existing installations that
predate the table are adopted automatically: their ``PRAGMA user_version`` is
used to mark the historical baseline as applied, then newer migrations run.
Fresh databases get the current baseline schema followed by the same ordered
migrations, so development and production follow one code path.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Callable

# Version 3 is the last schema that existed before the migration ledger was
# introduced.  Keep this in sync with the historical SCHEMA_VERSION.
BASELINE_VERSION = 3
LATEST_VERSION = 5


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    apply: Callable[[sqlite3.Connection], None]


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(str(row[1]) == column for row in rows)


def add_column(
    conn: sqlite3.Connection, table: str, column: str, definition: str
) -> None:
    if not _column_exists(conn, table, column):
        conn.execute(f'ALTER TABLE "{table}" ADD COLUMN "{column}" {definition}')


def _run_sql(conn: sqlite3.Connection, script: str) -> None:
    """Execute a small DDL script without ``executescript``'s implicit commit."""
    for statement in script.split(";"):
        if statement.strip():
            conn.execute(statement)


def _migration_4(conn: sqlite3.Connection) -> None:
    """Session authentication, MFA state and the security audit trail."""
    _run_sql(
        conn,
        """
        CREATE TABLE IF NOT EXISTS auth_sessions (
            id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            csrf_token TEXT NOT NULL,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            ip TEXT NOT NULL DEFAULT '',
            user_agent TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry
            ON auth_sessions(expires_at);
        CREATE INDEX IF NOT EXISTS idx_auth_sessions_user
            ON auth_sessions(username, expires_at);

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            actor TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT 'general',
            target TEXT NOT NULL DEFAULT '',
            detail TEXT NOT NULL DEFAULT '',
            outcome TEXT NOT NULL DEFAULT 'success',
            ip TEXT NOT NULL DEFAULT '',
            user_agent TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_log(category, created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor, created_at);
        """
    )


def _migration_5(conn: sqlite3.Connection) -> None:
    """Notification delivery history and finding-history uniqueness.

    Delivery history makes the Settings "test notification" button and the
    scheduled-scan notifications auditable without scraping application logs.
    """
    # A pre-ledger database may be incomplete. Ensure the history table exists
    # before adding its uniqueness constraint.
    _run_sql(
        conn,
        """
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
        )
        """,
    )
    # Older builds could accumulate duplicate history rows because the table
    # had no uniqueness constraint. Keep the newest row before adding the index.
    conn.execute(
        "DELETE FROM finding_history WHERE id NOT IN ("
        "SELECT MAX(id) FROM finding_history GROUP BY asset_id, fingerprint"
        ")"
    )
    _run_sql(
        conn,
        """
        CREATE TABLE IF NOT EXISTS notification_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            channel TEXT NOT NULL,
            target TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'success',
            detail TEXT NOT NULL DEFAULT '',
            scan_id INTEGER,
            schedule_id INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_notification_created
            ON notification_log(created_at);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_history_unique
            ON finding_history(asset_id, fingerprint);
        """
    )


MIGRATIONS: tuple[Migration, ...] = (
    Migration(4, "session authentication and audit log", _migration_4),
    Migration(5, "notification history and finding-history index", _migration_5),
)


def _ledger_exists(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
    ).fetchone()
    return bool(row)


def apply_migrations(conn: sqlite3.Connection, baseline_schema: str) -> dict:
    """Apply pending migrations and return a small status dictionary."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "version INTEGER PRIMARY KEY, "
        "name TEXT NOT NULL, "
        "applied_at TEXT NOT NULL DEFAULT (datetime('now'))"
        ")"
    )
    applied = {
        int(row[0])
        for row in conn.execute("SELECT version FROM schema_migrations").fetchall()
    }
    user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    adopted = False

    if not applied:
        if user_version >= BASELINE_VERSION:
            # Adopt a pre-ledger database without touching its schema.
            for version, name in (
                (1, "baseline schema"),
                (2, "inventory and finding history"),
                (3, "scan schedules and credentials"),
            ):
                conn.execute(
                    "INSERT OR IGNORE INTO schema_migrations(version, name) VALUES (?, ?)",
                    (version, name),
                )
            applied.update({1, 2, 3})
            adopted = True
        else:
            # Fresh or partially-created database: the baseline is idempotent.
            conn.executescript(baseline_schema)
            for version, name in (
                (1, "baseline schema"),
                (2, "inventory and finding history"),
                (3, "scan schedules and credentials"),
            ):
                conn.execute(
                    "INSERT OR IGNORE INTO schema_migrations(version, name) VALUES (?, ?)",
                    (version, name),
                )
            applied.update({1, 2, 3})
            adopted = True
        conn.commit()

    newly_applied: list[int] = []
    for migration in MIGRATIONS:
        if migration.version in applied:
            continue
        conn.execute("BEGIN IMMEDIATE")
        try:
            migration.apply(conn)
            conn.execute(
                "INSERT INTO schema_migrations(version, name) VALUES (?, ?)",
                (migration.version, migration.name),
            )
            conn.execute(f"PRAGMA user_version = {migration.version}")
            conn.execute("COMMIT")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        applied.add(migration.version)
        newly_applied.append(migration.version)

    if not applied:
        conn.execute(f"PRAGMA user_version = {LATEST_VERSION}")
        conn.commit()
    return {
        "version": max(applied) if applied else LATEST_VERSION,
        "applied": sorted(applied),
        "newly_applied": newly_applied,
        "adopted": adopted,
    }


def upgrade_database_file(path: str) -> dict:
    """Apply all migrations to a standalone database file.

    Used by restore so an older backup is upgraded in a temporary copy before
    it is attached to the live database.
    """
    from .database import SCHEMA

    conn = sqlite3.connect(path, timeout=30, isolation_level=None)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        # The baseline is idempotent and fills in tables missing from an
        # incomplete older backup without touching existing rows.
        conn.executescript(SCHEMA)
        return apply_migrations(conn, SCHEMA)
    finally:
        conn.close()
