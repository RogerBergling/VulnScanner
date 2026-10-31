"""Safe GUI-driven relocation of the SQLite database and data directory.

Moving a live database is a destructive operation if done casually.  This
workflow validates the target, creates a safety backup, copies the database
with SQLite's online backup API, verifies integrity, copies the credential key
and supporting directories, and only then switches the process environment and
the launcher environment file.  The old location is never deleted.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from ..audit import record_request
from ..config import (
    BASE_DIR,
    clear_limit_cache,
    data_dir,
    database_path,
    env_file_path,
    reload_tool_paths,
    reports_dir,
)
from ..database import get_db
from ..envfile import upsert_env_entries
from ..schemas import StorageRelocateRequest, StorageValidateRequest

router = APIRouter(prefix="/api/server/storage", tags=["storage"])

_RELOCATE_LOCK = threading.Lock()
_SUPPORTED_SUFFIXES = {".db", ".sqlite", ".sqlite3"}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _nearest_writable(path: Path) -> bool:
    candidate = path
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    return candidate.is_dir() and os.access(candidate, os.W_OK)


def _resolve_paths(
    data_dir_value: str, database_value: str | None
) -> tuple[Path, Path]:
    data = Path(data_dir_value).expanduser()
    if not data.is_absolute():
        raise ValueError("Data directory must be an absolute path")
    data = data.resolve()
    if data == Path("/"):
        raise ValueError("Refusing to use the filesystem root as the data directory")
    database = (
        Path(database_value).expanduser()
        if database_value
        else data / "vulnscanner.db"
    )
    if not database.is_absolute():
        raise ValueError("Database path must be an absolute path")
    database = database.resolve()
    if database == data:
        raise ValueError("Database path must be a file inside a directory")
    if database.suffix.lower() not in _SUPPORTED_SUFFIXES:
        raise ValueError("Database file must end in .db, .sqlite or .sqlite3")
    return data, database


def _validation(data: Path, database: Path) -> dict[str, Any]:
    current_data = data_dir().resolve()
    current_db = database_path().resolve()
    warnings: list[str] = []
    if database == current_db:
        raise ValueError("The new database path is the current database path")
    if data.exists() and not data.is_dir():
        raise ValueError("Data directory exists and is not a directory")
    if not _nearest_writable(data):
        raise ValueError("Data directory is not writable")
    if database.exists() and not database.is_file():
        raise ValueError("Database path exists and is not a file")
    if not _nearest_writable(database.parent):
        raise ValueError("Database directory is not writable")
    if database == current_data / "vulnscanner.db" and data == current_data:
        raise ValueError("The requested storage location is already active")
    try:
        database.relative_to(BASE_DIR.resolve())
        warnings.append(
            "The database will live inside the VulnScanner checkout. "
            "Use an external path such as /var/lib/vulnscanner for production."
        )
    except ValueError:
        pass
    return {
        "ok": True,
        "data_dir": str(data),
        "database_path": str(database),
        "current_data_dir": str(current_data),
        "current_database_path": str(current_db),
        "data_exists": data.exists(),
        "database_exists": database.exists(),
        "database_size": database.stat().st_size if database.is_file() else 0,
        "warnings": warnings,
    }


def _active_scans() -> int:
    with get_db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE status IN ('queued', 'running', 'waiting_agent')"
        ).fetchone()
    return int(row[0])


def _copy_database(source_path: Path, target_path: Path) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = target_path.with_name(
        f".{target_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    try:
        with get_db() as source:
            destination = sqlite3.connect(temporary)
            try:
                source.backup(destination)
            finally:
                destination.close()
        verify = sqlite3.connect(temporary)
        try:
            result = verify.execute("PRAGMA integrity_check").fetchone()
            if not result or str(result[0]) != "ok":
                raise ValueError(f"Copied database failed integrity check: {result}")
        finally:
            verify.close()
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        if target_path.exists():
            backup = target_path.with_name(
                f"{target_path.name}.before-relocate-{_stamp()}"
            )
            shutil.copy2(target_path, backup)
            try:
                os.chmod(backup, 0o600)
            except OSError:
                pass
        os.replace(temporary, target_path)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _copy_supporting(source: Path, target: Path) -> list[str]:
    """Copy credentials, certificates, wordlists and reports to the new root."""
    copied: list[str] = []
    if source.resolve() == target.resolve():
        return copied
    key = source / "credential.key"
    if key.is_file() and not os.getenv("VS_CREDENTIAL_KEY", "").strip():
        target.mkdir(parents=True, exist_ok=True)
        destination = target / "credential.key"
        shutil.copy2(key, destination)
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass
        copied.append(str(destination))
    for name in ("certs", "wordlists", "reports", "backups", "trivy-cache"):
        folder = source / name
        if not folder.is_dir():
            continue
        destination = target / name
        shutil.copytree(folder, destination, dirs_exist_ok=True)
        copied.append(str(destination))
    return copied


@router.get("")
def storage_status() -> dict[str, Any]:
    current_data = data_dir().resolve()
    current_db = database_path().resolve()
    key = current_data / "credential.key"
    return {
        "data_dir": str(current_data),
        "database_path": str(current_db),
        "database_size": current_db.stat().st_size if current_db.exists() else 0,
        "reports_dir": str(reports_dir()),
        "env_file": str(env_file_path(BASE_DIR)),
        "credential_key_path": str(key),
        "credential_key_configured": bool(
            os.getenv("VS_CREDENTIAL_KEY", "").strip() or key.is_file()
        ),
        "active_scans": _active_scans(),
        "relocation_available": True,
    }


@router.post("/validate")
def validate_storage(payload: StorageValidateRequest) -> dict[str, Any]:
    try:
        data, database = _resolve_paths(payload.data_dir, payload.database_path)
        return _validation(data, database)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/relocate")
def relocate_storage(payload: StorageRelocateRequest, request: Request) -> dict[str, Any]:
    from ..backup import create_backup

    if not _RELOCATE_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="A storage relocation is already running")
    try:
        data, database = _resolve_paths(payload.data_dir, payload.database_path)
        current_data = data_dir().resolve()
        current_db = database_path().resolve()
        validation = _validation(data, database)

        active = _active_scans()
        if active and not payload.force:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"{active} scan(s) are queued or running. Wait for them to finish "
                    "or explicitly force the relocation."
                ),
            )

        if payload.copy_supporting_files and data != current_data:
            try:
                data.relative_to(current_data)
                raise HTTPException(
                    status_code=400,
                    detail="New data directory cannot be inside the current data directory",
                )
            except ValueError:
                pass
            try:
                current_data.relative_to(data)
                raise HTTPException(
                    status_code=400,
                    detail="New data directory cannot contain the current data directory",
                )
            except ValueError:
                pass

        if database.exists() and not payload.overwrite:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Target database already exists: {database}. "
                    "Enable overwrite to replace it (a timestamped copy is kept)."
                ),
            )
        if (
            not payload.copy_supporting_files
            and data != current_data
            and (current_data / "credential.key").is_file()
            and not os.getenv("VS_CREDENTIAL_KEY", "").strip()
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Changing the data directory without copying supporting files "
                    "would leave credential.key behind. Enable copy_supporting_files "
                    "or configure VS_CREDENTIAL_KEY."
                ),
            )

        safety = create_backup(prefix="pre-relocate")
        copied: list[str] = []
        if payload.copy_supporting_files:
            copied = _copy_supporting(current_data, data)
        _copy_database(current_db, database)
        entries = {"VS_DATA_DIR": str(data), "VS_DATABASE": str(database)}
        configured_wordlist = os.getenv("VS_SUBFINDER_WORDLIST", "").strip()
        if configured_wordlist and payload.copy_supporting_files:
            try:
                relative = Path(configured_wordlist).expanduser().resolve().relative_to(
                    current_data
                )
                entries["VS_SUBFINDER_WORDLIST"] = str(data / relative)
            except ValueError:
                pass
        upsert_env_entries(env_file_path(BASE_DIR), entries)

        for key, value in entries.items():
            os.environ[key] = value
        clear_limit_cache()
        reload_tool_paths()

        record_request(
            request,
            "storage.relocated",
            category="maintenance",
            target=str(database),
            detail=(
                f"data_dir {current_data} -> {data}; database {current_db} -> {database}; "
                f"safety backup {safety.get('path', '')}"
            ),
        )
        return {
            "ok": True,
            "restart_required": True,
            "data_dir": str(data),
            "database_path": str(database),
            "previous_data_dir": str(current_data),
            "previous_database_path": str(current_db),
            "safety_backup": safety.get("path", ""),
            "copied": copied,
            "warnings": validation.get("warnings", []),
            "message": (
                "Storage relocated. The running process now uses the new database; "
                "restart VulnScanner to apply all launcher and certificate paths."
            ),
        }
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (OSError, sqlite3.Error) as exc:
        raise HTTPException(status_code=500, detail=f"Storage relocation failed: {exc}") from exc
    finally:
        _RELOCATE_LOCK.release()
