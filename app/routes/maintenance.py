"""Database backup, restore, inspection and maintenance endpoints."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from ..audit import record_request
from ..config import HOST, PORT, database_path
from ..database import get_setting
from ..runtime_settings import sync_env_from_settings
from ..schemas import DatabaseBackupRequest, DatabaseRestoreRequest

router = APIRouter(prefix="/api/server/database", tags=["maintenance"])


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


@router.get("/backups")
def database_backups(directory: str | None = None) -> dict[str, Any]:
    from ..backup import list_backups

    try:
        return list_backups(directory)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/backup", status_code=201)
def backup_database(
    request: Request,
    payload: DatabaseBackupRequest | None = None,
) -> dict[str, Any]:
    from ..backup import create_backup

    try:
        result = create_backup(
            payload.destination if payload else None,
            overwrite=payload.overwrite if payload else False,
        )
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (OSError, sqlite3.Error) as exc:
        raise HTTPException(
            status_code=500, detail=f"Database backup failed: {exc}"
        ) from exc
    record_request(
        request,
        "database.backup",
        category="maintenance",
        target=result.get("path", ""),
        detail=f"{result.get('size', 0)} bytes",
    )
    return result


@router.get("/inspect")
def inspect_database_backup(
    path: str,
    mode: str = Query(default="all", pattern="^(all|scans|settings)$"),
) -> dict[str, Any]:
    from ..backup import inspect_backup

    try:
        return inspect_backup(path, mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/restore")
def restore_database_endpoint(payload: DatabaseRestoreRequest, request: Request) -> dict[str, Any]:
    from ..backup import restore_database
    from ..scans import recover_interrupted_scans

    before = (
        get_setting("bind_host", os.getenv("VS_HOST", HOST)),
        get_setting("bind_port", os.getenv("VS_PORT", str(PORT))),
        get_setting("ssl_enabled", os.getenv("VS_SSL", "true")),
    )
    try:
        result = restore_database(payload.path, payload.mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (OSError, sqlite3.Error) as exc:
        raise HTTPException(
            status_code=500, detail=f"Database restore failed: {exc}"
        ) from exc

    if payload.mode in {"all", "settings"}:
        try:
            sync_env_from_settings()
        except Exception as exc:
            result["env_sync_error"] = str(exc)
    if payload.mode in {"all", "scans"}:
        try:
            recover_interrupted_scans()
        except Exception as exc:
            result["recovery_error"] = str(exc)
    after = (
        get_setting("bind_host", os.getenv("VS_HOST", HOST)),
        get_setting("bind_port", os.getenv("VS_PORT", str(PORT))),
        get_setting("ssl_enabled", os.getenv("VS_SSL", "true")),
    )
    result["restart_required"] = before != after
    record_request(
        request,
        "database.restore",
        category="maintenance",
        target=payload.path,
        detail=(
            f"mode={payload.mode}; source_version={result.get('source_version', '')}; "
            f"upgraded={result.get('upgraded', False)}; "
            f"safety_backup={result.get('safety_backup', '')}"
        ),
    )
    return result


@router.post("/vacuum")
def vacuum_database(request: Request) -> dict[str, Any]:
    db_path = database_path()
    before = _file_size(db_path)
    try:
        from ..database import get_db

        with get_db() as conn:
            conn.execute("VACUUM")
    except sqlite3.Error as exc:
        raise HTTPException(status_code=409, detail=f"Database maintenance failed: {exc}") from exc
    after = _file_size(db_path)
    result = {
        "ok": True,
        "before": before,
        "after": after,
        "saved": max(0, before - after),
    }
    record_request(
        request,
        "database.vacuum",
        category="maintenance",
        detail=f"saved {result['saved']} bytes",
    )
    return result
