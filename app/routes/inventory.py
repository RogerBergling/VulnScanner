"""Discovered inventory and per-asset finding history."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

from ..database import get_db, json_load

router = APIRouter(prefix="/api", tags=["inventory"])


def _inventory_row(row: Any) -> dict[str, Any]:
    data = dict(row)
    data["ports"] = json_load(data.get("ports"), [])
    return data


@router.get("/inventory")
def inventory_list(
    customer_id: int | None = None,
    status: str | None = None,
    q: str | None = None,
    limit: int = Query(default=200, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    clauses: list[str] = []
    params: list[Any] = []
    if customer_id is not None:
        clauses.append("i.customer_id = ?")
        params.append(customer_id)
    if status:
        clauses.append("i.status = ?")
        params.append(status)
    if q:
        clauses.append(
            "(i.ip_address LIKE ? OR i.hostname LIKE ? OR i.device_type LIKE ? "
            "OR i.os_guess LIKE ? OR i.mac_address LIKE ?)"
        )
        like = f"%{q}%"
        params.extend([like, like, like, like, like])
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_db() as conn:
        total = int(
            conn.execute(
                f"SELECT COUNT(*) FROM asset_inventory i {where}", params
            ).fetchone()[0]
        )
        rows = conn.execute(
            f"""
            SELECT i.*, c.name AS customer_name, a.name AS asset_name
            FROM asset_inventory i
            LEFT JOIN customers c ON c.id = i.customer_id
            LEFT JOIN assets a ON a.id = i.asset_id
            {where}
            ORDER BY i.last_seen DESC, i.id DESC
            LIMIT ? OFFSET ?
            """,
            (*params, limit, offset),
        ).fetchall()
        devices = conn.execute(
            f"""
            SELECT i.device_type, COUNT(*) AS count
            FROM asset_inventory i {where}
            GROUP BY i.device_type ORDER BY count DESC
            """,
            params,
        ).fetchall()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "entries": [_inventory_row(row) for row in rows],
        "device_types": [dict(row) for row in devices],
    }


@router.get("/assets/{asset_id}/history")
def asset_history(asset_id: int) -> dict[str, Any]:
    with get_db() as conn:
        asset = conn.execute(
            "SELECT a.*, c.name AS customer_name, g.name AS group_name "
            "FROM assets a LEFT JOIN customers c ON c.id = a.customer_id "
            "LEFT JOIN asset_groups g ON g.id = a.group_id WHERE a.id = ?",
            (asset_id,),
        ).fetchone()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        inventory = conn.execute(
            "SELECT * FROM asset_inventory WHERE asset_id = ? "
            "ORDER BY last_seen DESC, id DESC LIMIT 500",
            (asset_id,),
        ).fetchall()
        history = conn.execute(
            "SELECT * FROM finding_history WHERE asset_id = ? "
            "ORDER BY last_seen DESC, id DESC LIMIT 1000",
            (asset_id,),
        ).fetchall()
        findings = conn.execute(
            "SELECT id, scan_id, severity, category, title, status, first_seen, "
            "last_seen, fingerprint FROM findings WHERE asset_id = ? "
            "ORDER BY last_seen DESC, id DESC LIMIT 500",
            (asset_id,),
        ).fetchall()
    return {
        "asset": dict(asset),
        "inventory": [_inventory_row(row) for row in inventory],
        "history": [dict(row) for row in history],
        "findings": [dict(row) for row in findings],
    }
