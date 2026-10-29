"""Online SQLite backup and selective restore.

The database is the unit of backup. A backup is a consistent SQLite snapshot
created with SQLite's online backup API, so it can be taken while scans are
running. Restores are performed through a transaction, with a safety backup
written first and foreign-key checks before the transaction is committed.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .config import clear_limit_cache, database_path, reload_tool_paths, reports_dir
from .database import (
    SCHEMA_VERSION,
    get_db,
    init_db,
    set_setting,
    utcnow,
)

BACKUP_SUFFIXES = {".db", ".sqlite", ".sqlite3"}
RESTORE_MODES = {"all", "scans", "settings"}

# Insert order is dependency order. Delete order is the reverse.
ALL_TABLES = [
    "customers",
    "asset_groups",
    "assets",
    "agents",
    "enrollment_tokens",
    "scans",
    "scan_events",
    "findings",
    "agent_jobs",
    "credentials",
    "asset_credential_bindings",
    "scan_credentials",
    "settings",
    "osv_cache",
    "kev_catalog",
    "scan_schedules",
    "asset_inventory",
    "finding_history",
]

SCAN_TABLES = {
    "customers",
    "asset_groups",
    "assets",
    "scans",
    "scan_events",
    "findings",
}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _resolve_backup_target(
    destination: str | None,
    *,
    prefix: str,
    overwrite: bool,
) -> Path:
    stamp = _stamp()
    if not destination:
        target = reports_dir() / "backups" / f"{prefix}-{stamp}.db"
    else:
        requested = Path(destination).expanduser()
        if not requested.is_absolute():
            raise ValueError("Backup path must be absolute")
        if requested.exists() and requested.is_dir():
            target = requested / f"{prefix}-{stamp}.db"
        elif requested.exists() and requested.is_file():
            target = requested
        elif requested.suffix.lower() in BACKUP_SUFFIXES:
            target = requested
        else:
            target = requested / f"{prefix}-{stamp}.db"

    target.parent.mkdir(parents=True, exist_ok=True)
    if target.parent.resolve() == database_path().parent.resolve() and target.name == database_path().name:
        raise ValueError("Refusing to overwrite the live database")
    if target.resolve() == database_path().resolve():
        raise ValueError("Refusing to overwrite the live database")
    if target.exists() and not overwrite:
        raise FileExistsError(f"Backup file already exists: {target}")
    return target


def create_backup(
    destination: str | None = None,
    *,
    overwrite: bool = False,
    record: bool = True,
    prefix: str = "vulnscanner",
) -> dict[str, Any]:
    """Create a consistent SQLite backup and return its metadata."""
    target = _resolve_backup_target(destination, prefix=prefix, overwrite=overwrite)
    temporary = target.with_name(
        f".{target.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    )
    try:
        with get_db() as source:
            destination_conn = sqlite3.connect(temporary)
            try:
                source.backup(destination_conn)
            finally:
                destination_conn.close()
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    created_at = utcnow()
    if record:
        set_setting("last_backup_at", created_at)
        set_setting("last_backup_path", str(target))
    return {
        "ok": True,
        "path": str(target),
        "size": _file_size(target),
        "created_at": created_at,
    }


def list_backups(directory: str | None = None) -> dict[str, Any]:
    """List backup files in a directory, newest first."""
    if directory:
        folder = Path(directory).expanduser()
        if not folder.is_absolute():
            raise ValueError("Backup directory must be absolute")
    else:
        folder = reports_dir() / "backups"

    items: list[dict[str, Any]] = []
    if folder.is_dir():
        try:
            candidates = [
                item
                for item in folder.iterdir()
                if item.is_file() and item.suffix.lower() in BACKUP_SUFFIXES
            ]
        except OSError:
            candidates = []

        def _mtime(item: Path) -> float:
            try:
                return item.stat().st_mtime
            except OSError:
                return 0.0

        candidates.sort(key=_mtime, reverse=True)
        for item in candidates[:200]:
            try:
                modified = datetime.fromtimestamp(
                    item.stat().st_mtime, tz=timezone.utc
                ).replace(microsecond=0).isoformat()
            except OSError:
                modified = ""
            items.append(
                {
                    "name": item.name,
                    "path": str(item),
                    "size": _file_size(item),
                    "modified_at": modified,
                }
            )
    return {"directory": str(folder), "backups": items}


def _source_path(path: str) -> Path:
    source = Path(path).expanduser()
    if not source.is_absolute():
        raise ValueError("Restore path must be absolute")
    if not source.is_file():
        raise ValueError("Backup file not found")
    if source.resolve() == database_path().resolve():
        raise ValueError("Restore source is the live database")
    return source.resolve()


def _inspect_source(source: Path, mode: str) -> dict[str, Any]:
    uri = "file:" + quote(source.as_posix()) + "?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=30)
    except sqlite3.Error as exc:
        raise ValueError(f"Could not open backup: {exc}") from exc
    conn.row_factory = sqlite3.Row
    try:
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise ValueError(f"Backup integrity check failed: {integrity}")
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise ValueError(
                    f"Backup schema version {version} is newer than this server "
                    f"({SCHEMA_VERSION}); upgrade VulnScanner before restoring it"
                )
            tables = {
                str(row[0])
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
        except sqlite3.Error as exc:
            raise ValueError(f"Backup is not a readable SQLite database: {exc}") from exc
    finally:
        conn.close()

    if mode == "all":
        # A full restore must not silently drop a table that was absent from an
        # incomplete backup.
        required = set(ALL_TABLES)
    elif mode == "settings":
        required = {"settings"}
    else:
        required = set(SCAN_TABLES)
    missing = sorted(required - tables)
    if missing:
        raise ValueError(
            "Backup is missing required table(s): " + ", ".join(missing)
        )
    return {"version": version, "tables": tables}


def _table_exists(conn: sqlite3.Connection, schema: str, table: str) -> bool:
    row = conn.execute(
        f"SELECT 1 FROM {schema}.sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return bool(row)


def _columns(conn: sqlite3.Connection, schema: str, table: str) -> list[str]:
    rows = conn.execute(f"PRAGMA {schema}.table_info({table})").fetchall()
    return [str(row["name"]) for row in rows]


def _copy_table(conn: sqlite3.Connection, table: str) -> None:
    source_columns = set(_columns(conn, "backup", table))
    target_columns = _columns(conn, "main", table)
    columns = [column for column in target_columns if column in source_columns]
    if not columns:
        return
    column_sql = ", ".join(f'"{column}"' for column in columns)
    try:
        conn.execute(
            f'INSERT INTO main."{table}" ({column_sql}) '
            f'SELECT {column_sql} FROM backup."{table}"'
        )
    except sqlite3.Error as exc:
        raise ValueError(f"Could not restore table {table}: {exc}") from exc


def _check_foreign_keys(conn: sqlite3.Connection) -> None:
    violations = conn.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        first = violations[0]
        raise ValueError(
            "Restore would create invalid references "
            f"(table={first[0]}, rowid={first[1]}); nothing was changed"
        )


def _rollback(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("ROLLBACK")
    except sqlite3.Error:
        pass


def _detach(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("DETACH DATABASE backup")
    except sqlite3.Error:
        pass


def _restore_all(conn: sqlite3.Connection, source: Path, info: dict[str, Any]) -> None:
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("ATTACH DATABASE ? AS backup", (str(source),))
    try:
        conn.execute("BEGIN IMMEDIATE")
        for table in reversed(ALL_TABLES):
            conn.execute(f'DELETE FROM main."{table}"')
        for table in ALL_TABLES:
            if table in info["tables"]:
                _copy_table(conn, table)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        _check_foreign_keys(conn)
        conn.execute("COMMIT")
    except Exception:
        _rollback(conn)
        raise
    finally:
        _detach(conn)
        conn.execute("PRAGMA foreign_keys = ON")


def _restore_settings(conn: sqlite3.Connection, source: Path) -> None:
    conn.execute("ATTACH DATABASE ? AS backup", (str(source),))
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM main.settings")
        _copy_table(conn, "settings")
        conn.execute("COMMIT")
    except Exception:
        _rollback(conn)
        raise
    finally:
        _detach(conn)


def _mapped(conn: sqlite3.Connection, table: str, old_id: Any) -> int | None:
    if old_id is None:
        return None
    row = conn.execute(
        f"SELECT new_id FROM {table} WHERE old_id = ?", (int(old_id),)
    ).fetchone()
    return int(row["new_id"]) if row else None


def _row_value(row: sqlite3.Row, key: str, default: Any = None) -> Any:
    try:
        value = row[key]
    except (IndexError, KeyError):
        return default
    return default if value is None else value


def _copy_mapped(
    conn: sqlite3.Connection,
    table: str,
    expressions: dict[str, str],
    joins: str,
) -> None:
    if not _table_exists(conn, "backup", table):
        return
    source_columns = set(_columns(conn, "backup", table))
    target_columns = _columns(conn, "main", table)
    columns = [
        column
        for column in target_columns
        if column != "id" and (column in expressions or column in source_columns)
    ]
    if not columns:
        return
    select_sql = ", ".join(
        expressions.get(column, f'src."{column}"') for column in columns
    )
    column_sql = ", ".join(f'"{column}"' for column in columns)
    try:
        conn.execute(
            f'INSERT INTO main."{table}" ({column_sql}) '
            f'SELECT {select_sql} FROM backup."{table}" src {joins}'
        )
    except sqlite3.Error as exc:
        raise ValueError(f"Could not restore table {table}: {exc}") from exc


def _restore_scans(conn: sqlite3.Connection, source: Path, info: dict[str, Any]) -> None:
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("ATTACH DATABASE ? AS backup", (str(source),))
    try:
        conn.execute("BEGIN IMMEDIATE")
        for table in ("map_customers", "map_groups", "map_assets", "map_scans"):
            conn.execute(
                f"CREATE TEMP TABLE {table} "
                "(old_id INTEGER PRIMARY KEY, new_id INTEGER NOT NULL)"
            )

        for row in conn.execute("SELECT * FROM backup.customers ORDER BY id"):
            name = str(_row_value(row, "name", "")).strip()
            if not name:
                continue
            existing = conn.execute(
                "SELECT id FROM main.customers WHERE name = ?", (name,)
            ).fetchone()
            if existing:
                new_id = int(existing["id"])
            else:
                new_id = int(
                    conn.execute(
                        "INSERT INTO main.customers(name, description, created_at) "
                        "VALUES (?, ?, ?)",
                        (
                            name,
                            str(_row_value(row, "description", "")),
                            str(_row_value(row, "created_at", utcnow())),
                        ),
                    ).lastrowid
                )
            conn.execute(
                "INSERT INTO map_customers(old_id, new_id) VALUES (?, ?)",
                (int(row["id"]), new_id),
            )

        for row in conn.execute("SELECT * FROM backup.asset_groups ORDER BY id"):
            customer_id = _mapped(conn, "map_customers", _row_value(row, "customer_id"))
            name = str(_row_value(row, "name", "")).strip()
            if customer_id is None or not name:
                continue
            existing = conn.execute(
                "SELECT id FROM main.asset_groups WHERE customer_id = ? AND name = ?",
                (customer_id, name),
            ).fetchone()
            if existing:
                new_id = int(existing["id"])
            else:
                new_id = int(
                    conn.execute(
                        "INSERT INTO main.asset_groups("
                        "customer_id, name, description, created_at) "
                        "VALUES (?, ?, ?, ?)",
                        (
                            customer_id,
                            name,
                            str(_row_value(row, "description", "")),
                            str(_row_value(row, "created_at", utcnow())),
                        ),
                    ).lastrowid
                )
            conn.execute(
                "INSERT INTO map_groups(old_id, new_id) VALUES (?, ?)",
                (int(row["id"]), new_id),
            )

        for row in conn.execute("SELECT * FROM backup.assets ORDER BY id"):
            customer_id = _mapped(conn, "map_customers", _row_value(row, "customer_id"))
            group_id = _mapped(conn, "map_groups", _row_value(row, "group_id"))
            name = str(_row_value(row, "name", "")).strip()
            if customer_id is None or group_id is None or not name:
                continue
            existing = conn.execute(
                "SELECT id FROM main.assets WHERE group_id = ? AND name = ?",
                (group_id, name),
            ).fetchone()
            if existing:
                new_id = int(existing["id"])
            else:
                new_id = int(
                    conn.execute(
                        "INSERT INTO main.assets("
                        "customer_id, group_id, name, kind, identifier, "
                        "description, metadata, created_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            customer_id,
                            group_id,
                            name,
                            str(_row_value(row, "kind", "host")),
                            str(_row_value(row, "identifier", "")),
                            str(_row_value(row, "description", "")),
                            str(_row_value(row, "metadata", "{}")),
                            str(_row_value(row, "created_at", utcnow())),
                        ),
                    ).lastrowid
                )
            conn.execute(
                "INSERT INTO map_assets(old_id, new_id) VALUES (?, ?)",
                (int(row["id"]), new_id),
            )

        # Replacing scan history also invalidates per-scan credentials and jobs
        # that point at the old scan IDs.
        conn.execute("DELETE FROM main.finding_history")
        conn.execute("DELETE FROM main.asset_inventory")
        conn.execute("DELETE FROM main.scan_events")
        conn.execute("DELETE FROM main.findings")
        conn.execute("DELETE FROM main.scan_credentials")
        conn.execute("DELETE FROM main.agent_jobs WHERE scan_id IS NOT NULL")
        conn.execute("DELETE FROM main.scans")

        scan_columns = [
            "customer_id",
            "group_id",
            "asset_id",
            "agent_id",
            "scan_type",
            "target",
            "status",
            "progress",
            "stage",
            "options",
            "summary",
            "error",
            "requested_by",
            "created_at",
            "started_at",
            "completed_at",
            "cancelled",
        ]
        for row in conn.execute("SELECT * FROM backup.scans ORDER BY id"):
            old_id = int(row["id"])
            status = str(_row_value(row, "status", "failed"))
            interrupted = status in {"queued", "running", "waiting_agent"}
            values = [
                _mapped(conn, "map_customers", _row_value(row, "customer_id")),
                _mapped(conn, "map_groups", _row_value(row, "group_id")),
                _mapped(conn, "map_assets", _row_value(row, "asset_id")),
                None,
                str(_row_value(row, "scan_type", "")),
                str(_row_value(row, "target", "")),
                "failed" if interrupted else status,
                100 if interrupted else int(_row_value(row, "progress", 0)),
                "Interrupted" if interrupted else str(_row_value(row, "stage", "Queued")),
                str(_row_value(row, "options", "{}")),
                str(_row_value(row, "summary", "{}")),
                (
                    "Restored scan was not running; start a new scan."
                    if interrupted
                    else str(_row_value(row, "error", ""))
                ),
                str(_row_value(row, "requested_by", "restore")),
                str(_row_value(row, "created_at", utcnow())),
                _row_value(row, "started_at"),
                utcnow() if interrupted else _row_value(row, "completed_at"),
                1 if interrupted else int(_row_value(row, "cancelled", 0)),
            ]
            new_id = int(
                conn.execute(
                    f"INSERT INTO main.scans ({', '.join(scan_columns)}) "
                    f"VALUES ({', '.join('?' for _ in scan_columns)})",
                    values,
                ).lastrowid
            )
            conn.execute(
                "INSERT INTO map_scans(old_id, new_id) VALUES (?, ?)",
                (old_id, new_id),
            )
            if interrupted:
                conn.execute(
                    "INSERT INTO main.scan_events(scan_id, created_at, level, message) "
                    "VALUES (?, ?, 'warning', ?)",
                    (
                        new_id,
                        utcnow(),
                        "Restored scan was not running; start a new scan.",
                    ),
                )

        _copy_mapped(
            conn,
            "scan_events",
            {"scan_id": "ms.new_id"},
            "JOIN map_scans ms ON ms.old_id = src.scan_id",
        )
        _copy_mapped(
            conn,
            "findings",
            {
                "scan_id": "ms.new_id",
                "customer_id": "mc.new_id",
                "asset_id": "ma.new_id",
            },
            "JOIN map_scans ms ON ms.old_id = src.scan_id "
            "LEFT JOIN map_customers mc ON mc.old_id = src.customer_id "
            "LEFT JOIN map_assets ma ON ma.old_id = src.asset_id",
        )
        _copy_mapped(
            conn,
            "asset_inventory",
            {
                "scan_id": "ms.new_id",
                "customer_id": "mc.new_id",
                "asset_id": "ma.new_id",
            },
            "LEFT JOIN map_scans ms ON ms.old_id = src.scan_id "
            "LEFT JOIN map_customers mc ON mc.old_id = src.customer_id "
            "LEFT JOIN map_assets ma ON ma.old_id = src.asset_id",
        )
        _copy_mapped(
            conn,
            "finding_history",
            {
                "asset_id": "ma.new_id",
                "first_seen_scan_id": "mfs.new_id",
                "last_seen_scan_id": "mls.new_id",
            },
            "JOIN map_assets ma ON ma.old_id = src.asset_id "
            "LEFT JOIN map_scans mfs ON mfs.old_id = src.first_seen_scan_id "
            "LEFT JOIN map_scans mls ON mls.old_id = src.last_seen_scan_id",
        )

        _check_foreign_keys(conn)
        conn.execute("COMMIT")
    except Exception:
        _rollback(conn)
        raise
    finally:
        _detach(conn)
        conn.execute("PRAGMA foreign_keys = ON")


def _counts() -> dict[str, int]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM customers) AS customers, "
            "(SELECT COUNT(*) FROM assets) AS assets, "
            "(SELECT COUNT(*) FROM scans) AS scans, "
            "(SELECT COUNT(*) FROM findings) AS findings, "
            "(SELECT COUNT(*) FROM settings) AS settings"
        ).fetchone()
    return {key: int(row[key] or 0) for key in row.keys()}


def restore_database(path: str, mode: str = "all") -> dict[str, Any]:
    """Restore a backup into the live database.

    ``mode`` is ``all`` (full database), ``scans`` (scan history merged into
    the current customers/assets while keeping settings, agents and
    credentials), or ``settings`` (settings table only).
    """
    mode = (mode or "").strip().lower()
    if mode not in RESTORE_MODES:
        raise ValueError("mode must be all, scans or settings")

    source = _source_path(path)
    info = _inspect_source(source, mode)
    if mode in {"all", "scans"}:
        with get_db() as conn:
            active = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE status IN "
                "('queued', 'running', 'waiting_agent')"
            ).fetchone()[0]
        if active:
            raise ValueError(
                "Cancel or wait for active scans before restoring scan data"
            )
    safety = create_backup(
        prefix="vulnscanner-pre-restore",
        record=False,
    )
    try:
        with get_db() as conn:
            if mode == "all":
                _restore_all(conn, source, info)
            elif mode == "settings":
                _restore_settings(conn, source)
            else:
                _restore_scans(conn, source, info)
        # Re-add defaults introduced by this server version and make restored
        # settings visible to scanners immediately.
        init_db()
        reload_tool_paths()
        clear_limit_cache()
    except Exception as exc:
        set_setting("last_restore_error", str(exc)[:2000])
        raise ValueError(
            f"Restore failed: {exc}. The pre-restore safety backup is {safety['path']}"
        ) from exc

    restored_at = utcnow()
    set_setting("last_restore_at", restored_at)
    set_setting("last_restore_source", str(source))
    set_setting("last_restore_mode", mode)
    set_setting("last_restore_safety_backup", str(safety["path"]))
    set_setting("last_restore_error", "")
    return {
        "ok": True,
        "mode": mode,
        "source": str(source),
        "restored_at": restored_at,
        "safety_backup": str(safety["path"]),
        "counts": _counts(),
    }
