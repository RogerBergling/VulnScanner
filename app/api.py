"""HTTP API used by the web UI and endpoint agents."""

from __future__ import annotations

import ipaddress
import json
import os
import platform as os_platform
import shlex
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from fastapi import APIRouter, Body, Depends, File, Form, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import JSONResponse

from . import __version__
from .agents import (
    agent_supports,
    claim_next_job,
    complete_job,
    create_agent_scan,
    enroll_agent,
    get_agent,
    get_job,
    heartbeat,
    is_online,
    public_agent,
    queue_network_scan_job,
    revoke_agent,
    rotate_agent_token,
    update_agent,
)
from .config import (
    AGENT_JOB_TIMEOUT_SECONDS,
    BASE_DIR,
    ENABLE_EXTERNAL_APIS,
    HOST,
    MAX_CIDR_HOSTS,
    PORT,
    SCAN_WORKERS,
    SECLISTS_REPOSITORY_URL,
    TOP_PORTS,
    TOOL_ENV_VARS,
    TOOL_PATHS,
    database_path,
    reports_dir,
    subfinder_wordlist_path,
)
from .credentials import (
    CredentialError,
    asset_credential_bindings,
    copy_scan_credentials,
    create_credential,
    delete_credential,
    list_credentials,
    normalize_input,
    scan_credentials_public,
    set_asset_credential,
    store_scan_credentials,
    update_credential,
)
from .database import (
    ensure_default_group,
    get_db,
    get_setting,
    json_dump,
    json_load,
    log_event,
    set_setting,
    transaction,
    utcnow,
    rows_to_dicts,
)
from .jobs import submit_ad_import, submit_agent_result, submit_scan
from .reporting import build_csv, build_html, build_json
from .schemas import (
    ADImportRequest,
    AdminPasswordUpdate,
    AgentEnrollRequest,
    AgentHeartbeatRequest,
    AgentJobResult,
    AgentScanRequest,
    AgentTokenRequest,
    AgentUpdate,
    AssetCreate,
    AssetCredentialUpdate,
    AssetUpdate,
    BindAddressUpdate,
    CredentialCreate,
    CredentialUpdate,
    CustomerCreate,
    CustomerUpdate,
    FindingStatusUpdate,
    GroupCreate,
    GroupUpdate,
    ScanCreate,
    SettingsUpdate,
    ToolSettingsUpdate,
    WordlistUpdate,
)
from .scanners.ad import process_ad_report
from .scanners.kev import KevSyncError, sync_kev
from .scanners.subdomains import (
    download_seclists_wordlist,
    normalize_domain,
    save_wordlist,
    wordlist_info,
)
from .scanners.tools import tool_status
from .scans import scan_counts
from .security import authenticate_agent, create_enrollment_token
from .utils import (
    format_duration,
    human_age,
    normalize_repo_target,
    normalize_severity,
    normalize_target_url,
    parse_dt,
    risk_label,
    risk_score,
    secure_filename,
    severity_summary,
    utcnow as now_iso,
    validate_host_target,
)

router = APIRouter(prefix="/api")

SCAN_SELECT = """
SELECT s.*, c.name AS customer_name, g.name AS group_name, a.name AS asset_name,
       ag.name AS agent_name
FROM scans s
LEFT JOIN customers c ON c.id = s.customer_id
LEFT JOIN asset_groups g ON g.id = s.group_id
LEFT JOIN assets a ON a.id = s.asset_id
LEFT JOIN agents ag ON ag.id = s.agent_id
"""

_SERVER_STARTED_AT = datetime.now(timezone.utc).replace(microsecond=0)


def _uptime_text(seconds: int) -> str:
    seconds = max(0, int(seconds))
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if not parts:
        parts.append(f"{seconds}s")
    return " ".join(parts)


def _directory_stats(path: Path) -> tuple[int, int]:
    count = 0
    size = 0
    try:
        for item in path.rglob("*"):
            try:
                if item.is_file():
                    count += 1
                    size += item.stat().st_size
            except OSError:
                continue
    except OSError:
        return count, size
    return count, size


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size if path.exists() else 0
    except OSError:
        return 0


def _scan_public(row: Any) -> dict[str, Any]:
    data = dict(row)
    data["summary"] = json_load(data.get("summary"), {})
    data["options"] = json_load(data.get("options"), {})
    data["duration_seconds"] = None
    return data


def _finding_public(row: Any) -> dict[str, Any]:
    data = dict(row)
    data["raw"] = json_load(data.get("raw"), {})
    return data


def _fetch_customer(customer_id: int) -> dict[str, Any]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Customer not found")
    return dict(row)


def _fetch_group(group_id: int) -> dict[str, Any]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM asset_groups WHERE id = ?", (group_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Asset group not found")
    return dict(row)


def _fetch_asset(asset_id: int) -> dict[str, Any]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Asset not found")
    data = dict(row)
    data["metadata"] = json_load(data.get("metadata"), {})
    return data


def _severity_by_customer() -> dict[int, dict[str, int]]:
    query = """
    WITH latest AS (
        SELECT id, customer_id FROM (
            SELECT id, customer_id,
                   ROW_NUMBER() OVER (
                       PARTITION BY customer_id, COALESCE(asset_id, -id)
                       ORDER BY id DESC
                   ) AS rn
            FROM scans WHERE status = 'completed'
        ) WHERE rn = 1
    )
    SELECT latest.customer_id, f.severity, COUNT(*) AS count
    FROM findings f JOIN latest ON latest.id = f.scan_id
    GROUP BY latest.customer_id, f.severity
    """
    with get_db() as conn:
        rows = conn.execute(query).fetchall()
    result: dict[int, dict[str, int]] = {}
    for row in rows:
        bucket = result.setdefault(
            int(row["customer_id"]),
            {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
        )
        severity = normalize_severity(row["severity"])
        bucket[severity] += int(row["count"])
        bucket["total"] += int(row["count"])
    return result


@router.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "product": "VulnScanner",
        "version": __version__,
        "time": utcnow(),
    }


@router.get("/dashboard")
def dashboard() -> dict[str, Any]:
    with get_db() as conn:
        counts_row = conn.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM customers) customers, "
            "(SELECT COUNT(*) FROM asset_groups) groups, "
            "(SELECT COUNT(*) FROM assets) assets, "
            "(SELECT COUNT(*) FROM scans) scans, "
            "(SELECT COUNT(*) FROM agents) agents, "
            "(SELECT COUNT(*) FROM agents WHERE status != 'revoked') active_agents"
        ).fetchone()
        agents = conn.execute("SELECT id, last_seen, status FROM agents WHERE status != 'revoked'").fetchall()
        latest_count = conn.execute(
            """
            WITH latest AS (
                SELECT id FROM (
                    SELECT id, ROW_NUMBER() OVER (
                        PARTITION BY customer_id, COALESCE(asset_id, -id) ORDER BY id DESC
                    ) rn FROM scans WHERE status = 'completed'
                ) WHERE rn = 1
            ) SELECT COUNT(*) c FROM latest
            """
        ).fetchone()["c"]
        severity_rows = conn.execute(
            """
            WITH latest AS (
                SELECT id FROM (
                    SELECT id, ROW_NUMBER() OVER (
                        PARTITION BY customer_id, COALESCE(asset_id, -id) ORDER BY id DESC
                    ) rn FROM scans WHERE status = 'completed'
                ) WHERE rn = 1
            )
            SELECT f.severity, COUNT(*) count FROM findings f
            JOIN latest l ON l.id = f.scan_id GROUP BY f.severity
            """
        ).fetchall()
        recent = conn.execute(
            SCAN_SELECT + " ORDER BY s.created_at DESC LIMIT 10"
        ).fetchall()
        top = conn.execute(
            """
            WITH latest AS (
                SELECT id FROM (
                    SELECT id, ROW_NUMBER() OVER (
                        PARTITION BY customer_id, COALESCE(asset_id, -id) ORDER BY id DESC
                    ) rn FROM scans WHERE status = 'completed'
                ) WHERE rn = 1
            )
            SELECT f.id, f.scan_id, f.severity, f.title, f.cve, f.category, f.location,
                   f.status, f.cvss, f.raw, c.name customer_name, a.name asset_name
            FROM findings f
            JOIN latest l ON l.id = f.scan_id
            LEFT JOIN customers c ON c.id = f.customer_id
            LEFT JOIN assets a ON a.id = f.asset_id
            WHERE f.severity IN ('critical','high') AND f.status != 'false_positive'
            ORDER BY CASE f.severity WHEN 'critical' THEN 0 ELSE 1 END,
                     COALESCE(f.cvss, 0) DESC, f.id DESC
            LIMIT 10
            """
        ).fetchall()
        trend_rows = conn.execute(
            """
            SELECT substr(completed_at, 1, 10) day, severity, COUNT(*) count
            FROM findings f JOIN scans s ON s.id = f.scan_id
            WHERE s.status = 'completed' AND s.completed_at >= date('now', '-13 days')
            GROUP BY day, severity ORDER BY day
            """
        ).fetchall()
        agent_rows = [dict(row) for row in agents]
        scan_stats = scan_counts()

    severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
    for row in severity_rows:
        sev = normalize_severity(row["severity"])
        severity[sev] += int(row["count"])
        severity["total"] += int(row["count"])
    score = risk_score(severity)
    online = sum(1 for row in agent_rows if is_online(row.get("last_seen")))
    top_findings = []
    for row in top:
        item = dict(row)
        item["raw"] = json_load(item.get("raw"), {})
        item["customer_name"] = item.get("customer_name") or "Unassigned"
        item["asset_name"] = item.get("asset_name") or "Ad-hoc target"
        top_findings.append(item)
    trend_map: dict[str, dict[str, Any]] = {}
    for row in trend_rows:
        day = row["day"]
        entry = trend_map.setdefault(
            day,
            {"date": day, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        )
        entry[normalize_severity(row["severity"])] += int(row["count"])
    return {
        "counts": {
            "customers": counts_row["customers"],
            "groups": counts_row["groups"],
            "assets": counts_row["assets"],
            "scans": counts_row["scans"],
            "agents": counts_row["agents"],
            "agents_online": online,
            "running_scans": scan_stats["running"],
            "waiting_agent_scans": scan_stats["waiting_agent"],
            "assessed_assets": latest_count,
        },
        "severity": severity,
        "risk": {"score": score, "label": risk_label(score)},
        "recent_scans": [_scan_public(row) for row in recent],
        "top_findings": top_findings,
        "trend": sorted(trend_map.values(), key=lambda item: item["date"]),
    }


@router.get("/customers")
def list_customers() -> list[dict[str, Any]]:
    severity_map = _severity_by_customer()
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT c.*,
                   (SELECT COUNT(*) FROM asset_groups g WHERE g.customer_id = c.id) groups,
                   (SELECT COUNT(*) FROM assets a WHERE a.customer_id = c.id) assets,
                   (SELECT COUNT(*) FROM scans s WHERE s.customer_id = c.id) scans,
                   (SELECT MAX(s.completed_at) FROM scans s
                    WHERE s.customer_id = c.id AND s.status = 'completed') last_scan
            FROM customers c ORDER BY c.name COLLATE NOCASE
            """
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        sev = severity_map.get(item["id"], {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0})
        item["severity"] = sev
        item["risk_score"] = risk_score(sev)
        result.append(item)
    return result


@router.post("/customers", status_code=201)
def create_customer(payload: CustomerCreate) -> dict[str, Any]:
    with transaction() as conn:
        try:
            cursor = conn.execute(
                "INSERT INTO customers(name, description, created_at) VALUES (?, ?, ?)",
                (payload.name.strip(), payload.description.strip(), utcnow()),
            )
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise HTTPException(status_code=409, detail="A customer with that name already exists") from exc
            raise
        customer_id = int(cursor.lastrowid)
        conn.execute(
            "INSERT INTO asset_groups(customer_id, name, description, created_at) "
            "VALUES (?, 'General', 'Default asset group', ?)",
            (customer_id, utcnow()),
        )
    return get_customer(customer_id)


@router.get("/customers/{customer_id}")
def get_customer(customer_id: int) -> dict[str, Any]:
    customer = _fetch_customer(customer_id)
    severity_map = _severity_by_customer()
    with get_db() as conn:
        groups = conn.execute(
            "SELECT * FROM asset_groups WHERE customer_id = ? ORDER BY name COLLATE NOCASE",
            (customer_id,),
        ).fetchall()
        result_groups = []
        for group in groups:
            group_data = dict(group)
            assets = conn.execute(
                "SELECT * FROM assets WHERE group_id = ? ORDER BY name COLLATE NOCASE",
                (group["id"],),
            ).fetchall()
            asset_list = []
            for asset in assets:
                asset_data = dict(asset)
                asset_data["metadata"] = json_load(asset_data.get("metadata"), {})
                last_scan = conn.execute(
                    SCAN_SELECT + " WHERE s.asset_id = ? ORDER BY s.id DESC LIMIT 1",
                    (asset["id"],),
                ).fetchone()
                asset_data["last_scan"] = _scan_public(last_scan) if last_scan else None
                scan_count = conn.execute(
                    "SELECT COUNT(*) c FROM scans WHERE asset_id = ?", (asset["id"],)
                ).fetchone()["c"]
                asset_data["scan_count"] = scan_count
                asset_list.append(asset_data)
            group_data["assets"] = asset_list
            group_data["scan_count"] = conn.execute(
                "SELECT COUNT(*) c FROM scans WHERE group_id = ?", (group["id"],)
            ).fetchone()["c"]
            result_groups.append(group_data)
        customer["groups"] = result_groups
        customer["scan_count"] = conn.execute(
            "SELECT COUNT(*) c FROM scans WHERE customer_id = ?", (customer_id,)
        ).fetchone()["c"]
        sev = severity_map.get(customer_id, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0})
        customer["severity"] = sev
        customer["risk_score"] = risk_score(sev)
    return customer


@router.patch("/customers/{customer_id}")
def update_customer(customer_id: int, payload: CustomerUpdate) -> dict[str, Any]:
    _fetch_customer(customer_id)
    updates = {}
    if payload.name is not None:
        updates["name"] = payload.name.strip()
    if payload.description is not None:
        updates["description"] = payload.description.strip()
    if updates:
        set_sql = ", ".join(f"{key} = ?" for key in updates)
        try:
            with get_db() as conn:
                conn.execute(
                    f"UPDATE customers SET {set_sql} WHERE id = ?",
                    (*updates.values(), customer_id),
                )
                conn.commit()
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise HTTPException(status_code=409, detail="A customer with that name already exists") from exc
            raise
    return _fetch_customer(customer_id)


@router.delete("/customers/{customer_id}")
def delete_customer(customer_id: int) -> dict[str, Any]:
    _fetch_customer(customer_id)
    with transaction() as conn:
        scans = [row["id"] for row in conn.execute(
            "SELECT id FROM scans WHERE customer_id = ?", (customer_id,)
        ).fetchall()]
        for scan_id in scans:
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.execute("DELETE FROM customers WHERE id = ?", (customer_id,))
    return {"ok": True, "deleted_scan_ids": scans}


@router.post("/customers/{customer_id}/groups", status_code=201)
def create_group(customer_id: int, payload: GroupCreate) -> dict[str, Any]:
    _fetch_customer(customer_id)
    try:
        with get_db() as conn:
            cursor = conn.execute(
                "INSERT INTO asset_groups(customer_id, name, description, created_at) VALUES (?, ?, ?, ?)",
                (customer_id, payload.name.strip(), payload.description.strip(), utcnow()),
            )
            conn.commit()
            group_id = int(cursor.lastrowid)
    except Exception as exc:
        if "UNIQUE" in str(exc):
            raise HTTPException(status_code=409, detail="A group with that name already exists for this customer") from exc
        raise
    return _fetch_group(group_id)


@router.get("/groups/{group_id}")
def get_group(group_id: int) -> dict[str, Any]:
    group = _fetch_group(group_id)
    group["customer"] = _fetch_customer(group["customer_id"])
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM assets WHERE group_id = ? ORDER BY name COLLATE NOCASE",
            (group_id,),
        ).fetchall()
    group["assets"] = []
    for row in rows:
        asset = dict(row)
        asset["metadata"] = json_load(asset.get("metadata"), {})
        group["assets"].append(asset)
    return group


@router.patch("/groups/{group_id}")
def update_group(group_id: int, payload: GroupUpdate) -> dict[str, Any]:
    group = _fetch_group(group_id)
    updates = {}
    if payload.name is not None:
        updates["name"] = payload.name.strip()
    if payload.description is not None:
        updates["description"] = payload.description.strip()
    if updates:
        set_sql = ", ".join(f"{key} = ?" for key in updates)
        try:
            with get_db() as conn:
                conn.execute(
                    f"UPDATE asset_groups SET {set_sql} WHERE id = ?",
                    (*updates.values(), group_id),
                )
                conn.commit()
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise HTTPException(status_code=409, detail="A group with that name already exists") from exc
            raise
    return _fetch_group(group_id)


@router.delete("/groups/{group_id}")
def delete_group(group_id: int) -> dict[str, Any]:
    group = _fetch_group(group_id)
    with transaction() as conn:
        scans = [row["id"] for row in conn.execute(
            "SELECT id FROM scans WHERE group_id = ?", (group_id,)
        ).fetchall()]
        for scan_id in scans:
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.execute("DELETE FROM asset_groups WHERE id = ?", (group_id,))
    return {"ok": True, "customer_id": group["customer_id"], "deleted_scan_ids": scans}


@router.post("/groups/{group_id}/assets", status_code=201)
def create_asset(group_id: int, payload: AssetCreate) -> dict[str, Any]:
    group = _fetch_group(group_id)
    try:
        with get_db() as conn:
            cursor = conn.execute(
                "INSERT INTO assets(customer_id, group_id, name, kind, identifier, description, metadata, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    group["customer_id"],
                    group_id,
                    payload.name.strip(),
                    payload.kind,
                    payload.identifier.strip(),
                    payload.description.strip(),
                    json_dump(payload.metadata),
                    utcnow(),
                ),
            )
            conn.commit()
            asset_id = int(cursor.lastrowid)
    except Exception as exc:
        if "UNIQUE" in str(exc):
            raise HTTPException(status_code=409, detail="An asset with that name already exists in this group") from exc
        raise
    return _fetch_asset(asset_id)


@router.get("/assets/{asset_id}")
def get_asset(asset_id: int) -> dict[str, Any]:
    asset = _fetch_asset(asset_id)
    group = _fetch_group(asset["group_id"])
    customer = _fetch_customer(asset["customer_id"])
    with get_db() as conn:
        scans = conn.execute(
            SCAN_SELECT + " WHERE s.asset_id = ? ORDER BY s.id DESC LIMIT 50", (asset_id,)
        ).fetchall()
        findings = conn.execute(
            "SELECT f.* FROM findings f JOIN scans s ON s.id = f.scan_id "
            "WHERE s.asset_id = ? AND s.id = (SELECT MAX(id) FROM scans WHERE asset_id = ? AND status = 'completed') "
            "ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
            (asset_id, asset_id),
        ).fetchall()
    asset["group"] = group
    asset["customer"] = customer
    asset["scans"] = [_scan_public(row) for row in scans]
    asset["latest_findings"] = [_finding_public(row) for row in findings]
    return asset


@router.patch("/assets/{asset_id}")
def update_asset(asset_id: int, payload: AssetUpdate) -> dict[str, Any]:
    _fetch_asset(asset_id)
    updates: dict[str, Any] = {}
    if payload.name is not None:
        updates["name"] = payload.name.strip()
    if payload.kind is not None:
        updates["kind"] = payload.kind
    if payload.identifier is not None:
        updates["identifier"] = payload.identifier.strip()
    if payload.description is not None:
        updates["description"] = payload.description.strip()
    if payload.metadata is not None:
        updates["metadata"] = json_dump(payload.metadata)
    if updates:
        set_sql = ", ".join(f"{key} = ?" for key in updates)
        try:
            with get_db() as conn:
                conn.execute(
                    f"UPDATE assets SET {set_sql} WHERE id = ?",
                    (*updates.values(), asset_id),
                )
                conn.commit()
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise HTTPException(status_code=409, detail="An asset with that name already exists in this group") from exc
            raise
    return _fetch_asset(asset_id)


@router.delete("/assets/{asset_id}")
def delete_asset(asset_id: int) -> dict[str, Any]:
    asset = _fetch_asset(asset_id)
    with transaction() as conn:
        scans = [row["id"] for row in conn.execute(
            "SELECT id FROM scans WHERE asset_id = ?", (asset_id,)
        ).fetchall()]
        for scan_id in scans:
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    return {"ok": True, "group_id": asset["group_id"], "deleted_scan_ids": scans}


def _credential_error(exc: Exception) -> HTTPException:
    if isinstance(exc, CredentialError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail="Credential operation failed")


def _credential_payload_secret(payload: CredentialCreate | CredentialUpdate) -> tuple[str, str, str]:
    """Return (secret, auth_type, passphrase) from a create/update payload."""
    private_key = getattr(payload, "private_key", None)
    password = getattr(payload, "password", None)
    if private_key:
        return private_key, "key", getattr(payload, "passphrase", None) or ""
    if password:
        auth_type = getattr(payload, "auth_type", None) or "password"
        if auth_type == "key":
            raise CredentialError("Provide a private key when auth_type is 'key'")
        return password, "password", ""
    if getattr(payload, "auth_type", None) == "key":
        raise CredentialError("A private key is required for key authentication")
    return "", "", ""


@router.get("/credentials")
def credentials_list(
    customer_id: int | None = None, os: str | None = None
) -> list[dict[str, Any]]:
    if customer_id is not None:
        _fetch_customer(customer_id)
    try:
        return list_credentials(customer_id, os)
    except CredentialError as exc:
        raise _credential_error(exc) from exc


@router.post("/credentials", status_code=201)
def credentials_create(payload: CredentialCreate) -> dict[str, Any]:
    if payload.customer_id is not None:
        _fetch_customer(payload.customer_id)
    if payload.asset_id is not None:
        _fetch_asset(payload.asset_id)
    try:
        secret, auth_type, passphrase = _credential_payload_secret(payload)
        return create_credential(
            name=payload.name,
            os_name=payload.os,
            username=payload.username,
            secret=secret,
            auth_type=auth_type,
            domain=payload.domain,
            account_type=payload.account_type,
            passphrase=passphrase,
            customer_id=payload.customer_id,
            is_default=payload.is_default,
            asset_id=payload.asset_id,
        )
    except CredentialError as exc:
        raise _credential_error(exc) from exc


@router.patch("/credentials/{credential_id}")
def credentials_update(credential_id: int, payload: CredentialUpdate) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for key in ("name", "username", "domain", "account_type", "is_default"):
        value = getattr(payload, key, None)
        if value is not None:
            fields[key] = value
    if payload.os is not None:
        fields["os_name"] = payload.os
    try:
        secret, auth_type, passphrase = _credential_payload_secret(payload)
        if secret:
            fields["secret"] = secret
            fields["auth_type"] = auth_type
            fields["passphrase"] = passphrase
        elif payload.auth_type is not None:
            fields["auth_type"] = payload.auth_type
        if payload.passphrase is not None and "secret" not in fields:
            fields["passphrase"] = payload.passphrase
        return update_credential(credential_id, **fields)
    except CredentialError as exc:
        raise _credential_error(exc) from exc


@router.delete("/credentials/{credential_id}")
def credentials_delete(credential_id: int) -> dict[str, Any]:
    try:
        delete_credential(credential_id)
    except CredentialError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"ok": True}


@router.get("/assets/{asset_id}/credentials")
def asset_credentials(asset_id: int) -> dict[str, Any]:
    _fetch_asset(asset_id)
    bindings = asset_credential_bindings(asset_id)
    return {
        "asset_id": asset_id,
        "bindings": bindings,
    }


@router.put("/assets/{asset_id}/credentials")
def asset_credentials_update(asset_id: int, payload: AssetCredentialUpdate) -> dict[str, Any]:
    _fetch_asset(asset_id)
    provided = payload.model_fields_set
    try:
        for os_name in ("linux", "windows"):
            if os_name in provided:
                set_asset_credential(asset_id, os_name, getattr(payload, os_name))
    except CredentialError as exc:
        raise _credential_error(exc) from exc
    bindings = asset_credential_bindings(asset_id)
    return {"asset_id": asset_id, "bindings": bindings}


def _clean_options(scan_type: str, options: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    bool_keys = {
        "web": ["active", "external_tools", "testssl"],
        "network": [
            "external_tools",
            "nmap_vulners",
            "authenticated",
            "web_checks",
            "winrm_https",
            "verify_tls",
            "testssl",
        ],
        "repo": [
            "include_secrets",
            "include_dependencies",
            "include_source",
            "git_history",
            "external_tools",
            "trivy",
        ],
        "github": [
            "include_secrets",
            "include_dependencies",
            "include_source",
            "git_history",
            "external_tools",
            "trivy",
        ],
        "domain": ["subfinder", "bruteforce"],
        "ad": [],
    }.get(scan_type, [])
    for key in bool_keys:
        if key in options:
            clean[key] = bool(options[key])
    if scan_type == "network":
        ports = options.get("ports")
        if ports:
            if not isinstance(ports, str) or len(ports) > 2000:
                raise HTTPException(status_code=400, detail="ports must be a string shorter than 2000 characters")
            clean["ports"] = ports
        profile = options.get("profile")
        if profile:
            if profile not in {"common", "top1000", "all", "web"}:
                raise HTTPException(status_code=400, detail="Invalid network port profile")
            clean["profile"] = profile
        if "connect_timeout" in options:
            try:
                timeout = float(options["connect_timeout"])
            except (TypeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail="connect_timeout must be a number") from exc
            clean["connect_timeout"] = max(0.1, min(3.0, timeout))
        if "target_os" in options:
            target_os = str(options["target_os"] or "auto").lower()
            if target_os not in {"auto", "linux", "windows"}:
                raise HTTPException(status_code=400, detail="target_os must be auto, linux or windows")
            clean["target_os"] = target_os
        if "winrm_transport" in options:
            transport = str(options["winrm_transport"] or "ntlm").lower()
            if transport not in {"ntlm", "basic", "credssp", "kerberos"}:
                raise HTTPException(status_code=400, detail="Invalid WinRM transport")
            clean["winrm_transport"] = transport
        for key, low, high in (
            ("max_auth_hosts", 1, 256),
            ("auth_timeout", 3, 90),
            ("max_web_hosts", 1, 200),
            ("max_testssl_hosts", 0, 50),
            ("ssh_port", 1, 65535),
            ("winrm_port", 1, 65535),
        ):
            if key not in options:
                continue
            try:
                value = int(options[key])
            except (TypeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail=f"{key} must be an integer") from exc
            clean[key] = max(low, min(high, value))
    if scan_type == "domain":
        for key, low, high in (
            ("max_words", 1, 50_000),
            ("workers", 1, 100),
            ("max_subdomains", 1, 5_000),
        ):
            if key not in options:
                continue
            try:
                value = int(options[key])
            except (TypeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail=f"{key} must be an integer") from exc
            clean[key] = max(low, min(high, value))
    return clean


def _normalize_scan_target(scan_type: str, target: str) -> str:
    try:
        if scan_type == "web":
            return normalize_target_url(target)
        if scan_type == "network":
            kind, value = validate_host_target(target)
            if kind == "cidr":
                network = ipaddress.ip_network(value, strict=False)
                if network.num_addresses > MAX_CIDR_HOSTS:
                    raise ValueError(
                        f"Network contains {network.num_addresses} addresses; "
                        f"limit is {MAX_CIDR_HOSTS}. Scan smaller ranges."
                    )
            return value
        if scan_type == "github":
            normalized = normalize_repo_target(target)
            if not normalized.startswith(("http://", "https://")):
                raise ValueError("GitHub scans require an https:// repository URL or owner/repo")
            return normalized
        if scan_type == "repo":
            return normalize_repo_target(target)
        if scan_type == "domain":
            return normalize_domain(target)
        if scan_type == "ad":
            path = Path(target).expanduser()
            if not path.is_file():
                raise ValueError("AD scan target must be an existing JSON report file")
            return str(path.resolve())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    raise HTTPException(status_code=400, detail="Unsupported scan type")


def _network_agent(agent_id: str, customer_id: int, group_id: int | None) -> dict[str, Any]:
    agent = get_agent(agent_id.strip())
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.get("status") == "revoked":
        raise HTTPException(status_code=409, detail="Agent has been revoked")
    if int(agent["customer_id"]) != int(customer_id):
        raise HTTPException(status_code=400, detail="Agent does not belong to the selected customer")
    if group_id and int(agent["group_id"]) != int(group_id):
        raise HTTPException(status_code=400, detail="Agent does not belong to the selected group")
    if not agent_supports(agent, "network"):
        raise HTTPException(
            status_code=400,
            detail=(
                "This agent does not advertise network-scan support. "
                "Update the agent to the latest version and restart it."
            ),
        )
    return agent


def _create_scan_record(
    payload: ScanCreate,
    target: str,
    options: dict[str, Any],
    status: str = "queued",
    stage: str = "Queued",
    requested_by: str = "local",
    agent_id: str | None = None,
) -> int:
    _fetch_customer(payload.customer_id)
    customer_id = payload.customer_id
    group_id = payload.group_id
    asset_id = payload.asset_id
    if asset_id:
        asset = _fetch_asset(asset_id)
        if asset["customer_id"] != customer_id:
            raise HTTPException(status_code=400, detail="Asset does not belong to the selected customer")
        if group_id and asset["group_id"] != group_id:
            raise HTTPException(status_code=400, detail="Asset does not belong to the selected group")
        group_id = asset["group_id"]
    if group_id:
        group = _fetch_group(group_id)
        if group["customer_id"] != customer_id:
            raise HTTPException(status_code=400, detail="Group does not belong to the selected customer")
    else:
        group_id = ensure_default_group(customer_id)
        # ensure_default_group may have created a group; use its customer.
    with transaction() as conn:
        cursor = conn.execute(
            "INSERT INTO scans("
            "customer_id, group_id, asset_id, agent_id, scan_type, target, status, progress, "
            "stage, options, summary, requested_by, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, '{}', ?, ?)",
            (
                customer_id,
                group_id,
                asset_id,
                agent_id,
                payload.scan_type,
                target,
                status,
                stage,
                json_dump(options),
                requested_by,
                utcnow(),
            ),
        )
        scan_id = int(cursor.lastrowid)
        conn.execute(
            "INSERT INTO scan_events(scan_id, created_at, level, message) VALUES (?, ?, 'info', ?)",
            (scan_id, utcnow(), f"{payload.scan_type} scan queued for {target}"),
        )
    return scan_id


def _scan_detail(scan_id: int) -> dict[str, Any]:
    with get_db() as conn:
        row = conn.execute(SCAN_SELECT + " WHERE s.id = ?", (scan_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Scan not found")
        scan = _scan_public(row)
        findings = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id",
            (scan_id,),
        ).fetchall()
        events = conn.execute(
            "SELECT * FROM scan_events WHERE scan_id = ? ORDER BY id LIMIT 1000",
            (scan_id,),
        ).fetchall()
        scan["findings"] = [_finding_public(item) for item in findings]
        scan["events"] = [dict(item) for item in events]
        if scan.get("agent_id"):
            agent = conn.execute("SELECT * FROM agents WHERE id = ?", (scan["agent_id"],)).fetchone()
            scan["agent"] = public_agent(dict(agent)) if agent else None
        else:
            scan["agent"] = None
        scan["finding_count"] = len(findings)
        scan["credentials"] = scan_credentials_public(scan_id)
    return scan


@router.get("/scans")
def list_scans(
    customer_id: int | None = None,
    group_id: int | None = None,
    asset_id: int | None = None,
    status: str | None = None,
    scan_type: str | None = None,
    active: bool = False,
    q: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    where = []
    params: list[Any] = []
    if customer_id:
        where.append("s.customer_id = ?")
        params.append(customer_id)
    if group_id:
        where.append("s.group_id = ?")
        params.append(group_id)
    if asset_id:
        where.append("s.asset_id = ?")
        params.append(asset_id)
    if status:
        where.append("s.status = ?")
        params.append(status)
    if scan_type:
        where.append("s.scan_type = ?")
        params.append(scan_type)
    if active:
        where.append("s.status IN ('queued','running','waiting_agent')")
    if q:
        where.append("(s.target LIKE ? OR s.stage LIKE ? OR c.name LIKE ? OR a.name LIKE ?)")
        term = f"%{q.strip()}%"
        params.extend([term, term, term, term])
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    with get_db() as conn:
        total = conn.execute(
            "SELECT COUNT(*) AS total FROM scans s LEFT JOIN customers c ON c.id=s.customer_id "
            "LEFT JOIN assets a ON a.id=s.asset_id" + clause,
            tuple(params),
        ).fetchone()["total"]
        rows = conn.execute(
            SCAN_SELECT + clause + " ORDER BY s.created_at DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
    return {
        "items": [_scan_public(row) for row in rows],
        "total": int(total),
        "limit": limit,
        "offset": offset,
    }


@router.post("/scans", status_code=201)
def create_scan(payload: ScanCreate) -> dict[str, Any]:
    target = payload.target.strip()
    if payload.asset_id:
        asset = _fetch_asset(payload.asset_id)
        if not target:
            target = asset.get("identifier") or ""
    if not target:
        raise HTTPException(status_code=400, detail="A scan target is required")
    normalized_target = _normalize_scan_target(payload.scan_type, target)
    options = _clean_options(payload.scan_type, payload.options)
    credential_entries: dict[str, dict[str, Any]] | None = None
    if payload.credentials:
        if payload.scan_type != "network":
            raise HTTPException(status_code=400, detail="Credentials can only be used for network scans")
        if payload.agent_id:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Per-scan credentials cannot be sent to an agent. "
                    "Run the authenticated scan from the VulnScanner server instead."
                ),
            )
        credential_entries = {}
        for os_name, item in payload.credentials.items():
            data = item.model_dump(exclude_none=True)
            try:
                normalize_input(os_name, data)
            except CredentialError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            credential_entries[os_name] = data
        options["authenticated"] = True
    agent = None
    if payload.agent_id:
        if payload.scan_type != "network":
            raise HTTPException(
                status_code=400,
                detail="An agent can only be selected for network scans",
            )
        # Validate the agent against the group the scan will actually use,
        # including a group derived from the selected asset.
        effective_group_id = payload.group_id
        if effective_group_id is None and payload.asset_id:
            effective_group_id = _fetch_asset(payload.asset_id)["group_id"]
        agent = _network_agent(payload.agent_id, payload.customer_id, effective_group_id)
        if payload.group_id is None and payload.asset_id is None:
            payload.group_id = agent["group_id"]
    scan_id = _create_scan_record(
        payload,
        normalized_target,
        options,
        status="waiting_agent" if agent else "queued",
        stage="Waiting for agent" if agent else "Queued",
        requested_by=payload.requested_by or "local",
        agent_id=agent["id"] if agent else None,
    )
    if agent:
        queue_network_scan_job(agent, scan_id, normalized_target, options)
    else:
        if credential_entries:
            try:
                store_scan_credentials(scan_id, credential_entries)
            except CredentialError as exc:
                with transaction() as conn:
                    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        runtime: dict[str, Any] = {}
        if payload.github_token and payload.scan_type == "github":
            runtime["_github_token"] = payload.github_token.strip()
        submit_scan(scan_id, runtime)
    return _scan_detail(scan_id)


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int) -> dict[str, Any]:
    return _scan_detail(scan_id)


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: int) -> dict[str, Any]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Scan not found")
        if row["status"] in {"completed", "failed", "cancelled"}:
            raise HTTPException(status_code=409, detail=f"Scan is already {row['status']}")
        conn.execute("UPDATE scans SET cancelled = 1 WHERE id = ?", (scan_id,))
        if row["status"] in {"queued", "waiting_agent"}:
            conn.execute(
                "UPDATE scans SET status = 'cancelled', stage = 'Cancelled', progress = 100, "
                "completed_at = ?, error = 'Scan cancelled by user' WHERE id = ?",
                (utcnow(), scan_id),
            )
            conn.execute(
                "UPDATE agent_jobs SET status = 'cancelled', completed_at = ? "
                "WHERE scan_id = ? AND status IN ('queued','running')",
                (utcnow(), scan_id),
            )
        else:
            conn.execute("UPDATE scans SET stage = 'Cancelling…' WHERE id = ?", (scan_id,))
        conn.execute(
            "INSERT INTO scan_events(scan_id, created_at, level, message) VALUES (?, ?, 'warning', 'Cancellation requested by user')",
            (scan_id, utcnow()),
        )
        conn.commit()
    return _scan_detail(scan_id)


@router.post("/scans/{scan_id}/rescan", status_code=201)
def rescan(scan_id: int, request: Request) -> dict[str, Any]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row["scan_type"] not in {"web", "network", "repo", "github", "domain", "ad"}:
        raise HTTPException(status_code=400, detail="Agent scans must be started from the Agents page")
    if not row["customer_id"]:
        raise HTTPException(status_code=400, detail="The original scan no longer has a customer")
    agent_id = row["agent_id"] if row["scan_type"] == "network" else None
    payload = ScanCreate(
        customer_id=row["customer_id"],
        group_id=row["group_id"],
        asset_id=row["asset_id"],
        scan_type=row["scan_type"],
        target=row["target"],
        options=json_load(row["options"], {}),
        requested_by="rescan",
        agent_id=agent_id,
    )
    if agent_id:
        return create_scan(payload)
    new_id = _create_scan_record(payload, row["target"], json_load(row["options"], {}))
    copy_scan_credentials(scan_id, new_id)
    submit_scan(new_id, {})
    return _scan_detail(new_id)


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: int) -> dict[str, Any]:
    with get_db() as conn:
        row = conn.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Scan not found")
        if row["status"] in {"running", "queued", "waiting_agent"}:
            raise HTTPException(status_code=409, detail="Cancel the scan before deleting it")
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
    return {"ok": True}


@router.get("/scans/{scan_id}/findings")
def scan_findings(
    scan_id: int,
    severity: str | None = None,
    category: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    with get_db() as conn:
        if not conn.execute("SELECT 1 FROM scans WHERE id = ?", (scan_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Scan not found")
        where = ["scan_id = ?"]
        params: list[Any] = [scan_id]
        if severity:
            where.append("severity = ?")
            params.append(normalize_severity(severity))
        if category:
            where.append("category = ?")
            params.append(category)
        if status:
            where.append("status = ?")
            params.append(status)
        rows = conn.execute(
            "SELECT * FROM findings WHERE " + " AND ".join(where)
            + " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id",
            tuple(params),
        ).fetchall()
    return [_finding_public(row) for row in rows]


@router.patch("/findings/{finding_id}")
def update_finding(finding_id: int, payload: FindingStatusUpdate) -> dict[str, Any]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Finding not found")
        old_status = row["status"]
        conn.execute("UPDATE findings SET status = ? WHERE id = ?", (payload.status, finding_id))
        conn.execute(
            "INSERT INTO scan_events(scan_id, created_at, level, message) VALUES (?, ?, 'info', ?)",
            (row["scan_id"], utcnow(), f"Finding #{finding_id} status changed from {old_status} to {payload.status}"),
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    return _finding_public(updated)


@router.get("/scans/{scan_id}/export")
def export_scan(scan_id: int, format: str = "html") -> Response:
    scan = _scan_detail(scan_id)
    context: dict[str, Any] = {
        "generated_at": now_iso(),
        "customer": None,
        "group": None,
        "asset": None,
        "summary": scan.get("summary") or {},
    }
    with get_db() as conn:
        if scan.get("customer_id"):
            row = conn.execute("SELECT * FROM customers WHERE id = ?", (scan["customer_id"],)).fetchone()
            context["customer"] = dict(row) if row else None
        if scan.get("group_id"):
            row = conn.execute("SELECT * FROM asset_groups WHERE id = ?", (scan["group_id"],)).fetchone()
            context["group"] = dict(row) if row else None
        if scan.get("asset_id"):
            row = conn.execute("SELECT * FROM assets WHERE id = ?", (scan["asset_id"],)).fetchone()
            context["asset"] = dict(row) if row else None
    findings = scan.get("findings") or []
    filename = secure_filename(
        f"vulnscan-{scan_id}-{scan.get('customer_name') or 'customer'}-{scan.get('scan_type')}"
    )
    if format == "json":
        body = build_json(scan, findings, context)
        return Response(
            body,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}.json"'},
        )
    if format == "csv":
        body = build_csv(scan, findings)
        return Response(
            body,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}.csv"'},
        )
    if format != "html":
        raise HTTPException(status_code=400, detail="format must be html, json or csv")
    body = build_html(scan, findings, context)
    return Response(
        body,
        media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f'inline; filename="{filename}.html"'},
    )


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------

def _agent_from_header(
    x_agent_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    token = x_agent_token
    if not token and authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    agent = authenticate_agent(token)
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid or revoked agent token")
    return agent


@router.get("/agents")
def list_agents() -> list[dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT ag.*, c.name customer_name, g.name group_name, a.name asset_name,
                   (SELECT COUNT(*) FROM scans s WHERE s.agent_id = ag.id) scan_count,
                   (SELECT COUNT(*) FROM agent_jobs j WHERE j.agent_id = ag.id AND j.status = 'queued') queued_jobs
            FROM agents ag
            LEFT JOIN customers c ON c.id = ag.customer_id
            LEFT JOIN asset_groups g ON g.id = ag.group_id
            LEFT JOIN assets a ON a.id = ag.asset_id
            WHERE ag.status != 'revoked'
            ORDER BY ag.name COLLATE NOCASE
            """
        ).fetchall()
    result = []
    for row in rows:
        item = public_agent(dict(row))
        item["last_seen_human"] = human_age(item.get("last_seen"))
        result.append(item)
    return result


def _agent_detail_payload(agent_id: str) -> dict[str, Any]:
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    item = public_agent(agent)
    item["last_seen_human"] = human_age(item.get("last_seen"))
    item["created_human"] = human_age(item.get("created_at"))
    with get_db() as conn:
        stats = conn.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM scans WHERE agent_id = ?) scans,
                (SELECT COUNT(*) FROM agent_jobs WHERE agent_id = ?) jobs,
                (SELECT COUNT(*) FROM agent_jobs WHERE agent_id = ? AND status = 'queued') queued_jobs,
                (SELECT COUNT(*) FROM agent_jobs WHERE agent_id = ?
                    AND status IN ('running', 'processing')) active_jobs,
                (SELECT COUNT(*) FROM agent_jobs WHERE agent_id = ? AND status = 'failed') failed_jobs,
                (SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id
                    WHERE s.agent_id = ?) findings,
                (SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id
                    WHERE s.agent_id = ? AND f.status = 'open') open_findings
            """,
            (agent_id,) * 7,
        ).fetchone()
        job_rows = conn.execute(
            """
            SELECT j.*, s.status scan_status, s.summary scan_summary, s.target scan_target
            FROM agent_jobs j
            LEFT JOIN scans s ON s.id = j.scan_id
            WHERE j.agent_id = ?
            ORDER BY j.created_at DESC LIMIT 25
            """,
            (agent_id,),
        ).fetchall()
        scan_rows = conn.execute(
            SCAN_SELECT + " WHERE s.agent_id = ? ORDER BY s.id DESC LIMIT 15",
            (agent_id,),
        ).fetchall()
    jobs = []
    for row in job_rows:
        job = dict(row)
        payload = json_load(job.pop("payload", None), {})
        job["modules"] = payload.get("modules", [])
        job["paths_count"] = len(payload.get("paths") or [])
        job["scan_summary"] = json_load(job.get("scan_summary"), {})
        job["created_human"] = human_age(job.get("created_at"))
        job["duration"] = format_duration(
            job.get("claimed_at") or job.get("created_at"), job.get("completed_at")
        )
        jobs.append(job)
    item["stats"] = dict(stats) if stats else {}
    item["jobs"] = jobs
    item["scans"] = [_scan_public(row) for row in scan_rows]
    return item


@router.get("/agents/{agent_id}")
def get_agent_detail(agent_id: str) -> dict[str, Any]:
    return _agent_detail_payload(agent_id)


@router.patch("/agents/{agent_id}")
def configure_agent(agent_id: str, payload: AgentUpdate) -> dict[str, Any]:
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent["status"] == "revoked":
        raise HTTPException(status_code=409, detail="Agent has been revoked")
    try:
        update_agent(
            agent_id,
            name=payload.name,
            customer_id=payload.customer_id,
            group_id=payload.group_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "agent": _agent_detail_payload(agent_id)}


@router.post("/agents/{agent_id}/rotate-token")
def rotate_token(agent_id: str, request: Request) -> dict[str, Any]:
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    try:
        token = rotate_agent_token(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    base = str(request.base_url).rstrip("/")
    quoted_token = shlex.quote(token)
    windows_token = token.replace("'", "''")
    linux_command = (
        "# Adjust the paths if the agent was installed elsewhere, then restart the service.\n"
        f"sudo -u vulnscanner /opt/vulnscanner-agent/vulnscanner_agent.py "
        f"--config /var/lib/vulnscanner-agent/agent.json update-token --token {quoted_token}\n"
        "sudo systemctl restart vulnscanner-agent\n"
        "sudo systemctl status vulnscanner-agent --no-pager"
    )
    windows_command = (
        "# Run PowerShell as Administrator. Adjust the paths for a custom install.\n"
        f"py -3 vulnscanner_agent.py --config 'C:\\ProgramData\\VulnScanner Agent\\agent.json' "
        f"update-token --token '{windows_token}'\n"
        "Stop-ScheduledTask -TaskName 'VulnScanner Agent' -ErrorAction SilentlyContinue\n"
        "Start-ScheduledTask -TaskName 'VulnScanner Agent'"
    )
    windows_agent_command = (
        "# PowerShell agent (default Windows installation). Run as Administrator.\n"
        f"& 'C:\\Program Files\\VulnScanner Agent\\VulnScannerAgent.ps1' -Action Configure "
        f"-ConfigPath 'C:\\ProgramData\\VulnScanner Agent\\agent.json' -Token '{windows_token}'\n"
        "Stop-ScheduledTask -TaskName 'VulnScanner Agent' -ErrorAction SilentlyContinue\n"
        "Start-ScheduledTask -TaskName 'VulnScanner Agent'"
    )
    return {
        "token": token,
        "agent_id": agent_id,
        "agent_name": agent["name"],
        "server": base,
        "linux_command": linux_command,
        "windows_command": windows_command,
        "windows_agent_command": windows_agent_command,
        "note": (
            "The previous token stops working immediately. Update the agent "
            "configuration and restart it before it polls again. This token is "
            "shown only once."
        ),
    }



@router.post("/agents/enrollment-tokens", status_code=201)
def create_agent_token(payload: AgentTokenRequest, request: Request) -> dict[str, Any]:
    customer = _fetch_customer(payload.customer_id)
    group = _fetch_group(payload.group_id)
    if group["customer_id"] != customer["id"]:
        raise HTTPException(status_code=400, detail="Group does not belong to the selected customer")
    token, meta = create_enrollment_token(
        payload.customer_id,
        payload.group_id,
        payload.agent_name,
        hours=payload.hours,
        months=payload.months or 0,
        years=payload.years or 0,
    )
    base = str(request.base_url).rstrip("/")
    name = payload.agent_name or "my-agent"
    linux_name = shlex.quote(name)
    windows_name = name.replace("'", "''")
    linux_command = (
        f"curl -fsSL {base}/agent/vulnscanner_agent.py -o vulnscanner_agent.py\n"
        f"python3 vulnscanner_agent.py enroll --server {base} --token {token} --name {linux_name}\n"
        f"python3 vulnscanner_agent.py run"
    )
    windows_command = (
        f"Invoke-WebRequest -UseBasicParsing {base}/agent/vulnscanner_agent.py -OutFile vulnscanner_agent.py\n"
        f"py -3 vulnscanner_agent.py enroll --server {base} --token {token} --name '{windows_name}'\n"
        f"py -3 vulnscanner_agent.py run"
    )
    windows_installer_command = (
        "Invoke-WebRequest -UseBasicParsing "
        f"{base}/agent/install-windows-agent.ps1 -OutFile install-windows-agent.ps1\n"
        f"powershell -ExecutionPolicy Bypass -File .\\install-windows-agent.ps1 "
        f"-Server {base} -Token {token} -Name '{windows_name}'"
    )
    return {
        "token": token,
        "token_prefix": meta["prefix"],
        "expires_at": meta["expires_at"],
        "customer": customer["name"],
        "group": group["name"],
        "linux_command": linux_command,
        "windows_command": windows_command,
        "windows_installer_command": windows_installer_command,
        "agent_url": f"{base}/agent/vulnscanner_agent.py",
        "windows_agent_url": f"{base}/agent/VulnScannerAgent.ps1",
        "windows_installer_url": f"{base}/agent/install-windows-agent.ps1",
        "note": "The token can be used once and is shown only now. Review the command before running it.",
    }


@router.post("/agents/{agent_id}/scan", status_code=201)
def start_agent_scan(agent_id: str, payload: AgentScanRequest) -> dict[str, Any]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent = dict(row)
    if agent["status"] == "revoked":
        raise HTTPException(status_code=409, detail="Agent has been revoked")
    modules = payload.modules
    # Delegated network scans require the module to be advertised in the last
    # heartbeat. Other agent modules remain backward compatible with older
    # capability lists.
    if "network" in modules and not agent_supports(agent, "network"):
        raise HTTPException(
            status_code=400,
            detail=(
                "This agent does not advertise network-scan support. "
                "Update the agent to the latest version and restart it."
            ),
        )
    if "ad" in modules and "windows" not in (agent.get("platform") or "").lower():
        raise HTTPException(status_code=400, detail="Active Directory audits require a Windows agent")
    if any(module in {"secrets", "repo"} for module in modules) and not payload.paths:
        raise HTTPException(
            status_code=400,
            detail="Secrets/repository modules require at least one local path on the agent",
        )
    target = payload.target.strip()
    options = payload.options
    if "network" in modules:
        if len(modules) > 1:
            raise HTTPException(
                status_code=400,
                detail="Run a delegated network scan as a separate job",
            )
        if not target:
            raise HTTPException(status_code=400, detail="A network scan target is required")
        target = _normalize_scan_target("network", target)
        options = _clean_options("network", payload.options)
    try:
        scan_id = create_agent_scan(
            agent, modules, payload.paths, options, target=target
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "scan_id": scan_id,
        "agent_online": is_online(agent.get("last_seen")),
        "message": (
            "Job queued; the agent will start on its next poll."
            if is_online(agent.get("last_seen"))
            else "Agent is currently offline. The job will run when it reconnects."
        ),
        "scan": _scan_detail(scan_id),
    }


@router.delete("/agents/{agent_id}")
def delete_agent(agent_id: str) -> dict[str, Any]:
    with get_db() as conn:
        row = conn.execute("SELECT id FROM agents WHERE id = ?", (agent_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found")
    revoke_agent(agent_id)
    return {"ok": True}


@router.post("/agent/enroll", status_code=201)
def agent_enroll(payload: AgentEnrollRequest, request: Request) -> dict[str, Any]:
    ip = request.client.host if request.client else ""
    try:
        result = enroll_agent(
            payload.enrollment_token,
            payload.name,
            payload.platform,
            payload.version,
            payload.hostname,
            payload.capabilities,
            payload.ip or ip,
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    return result


@router.post("/agent/heartbeat")
def agent_heartbeat(
    payload: AgentHeartbeatRequest,
    request: Request,
    agent: dict[str, Any] = Depends(_agent_from_header),
) -> dict[str, Any]:
    ip = request.client.host if request.client else ""
    return heartbeat(agent, payload.model_dump(), payload.ip or ip)


@router.post("/agent/jobs/next")
def agent_next_job(
    x_agent_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    agent = _agent_from_header(x_agent_token, authorization)
    with get_db() as conn:
        conn.execute(
            "UPDATE agents SET last_seen = ?, status = 'online' WHERE id = ?",
            (utcnow(), agent["id"]),
        )
        conn.commit()
    job = claim_next_job(agent)
    if not job:
        return {"job": None, "next_poll": 30}
    return {"job": job, "next_poll": 5}


@router.post("/agent/jobs/{job_id}/result")
def agent_job_result(
    job_id: str,
    payload: AgentJobResult,
    x_agent_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    agent = _agent_from_header(x_agent_token, authorization)
    job = get_job(agent, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found for this agent")
    if job["status"] in {"completed", "cancelled", "failed"}:
        return {"ok": True, "duplicate": True}
    if job["status"] not in {"running", "processing"}:
        raise HTTPException(status_code=409, detail=f"Job is {job['status']}; it cannot accept results")
    if len(json.dumps(payload.results, default=str)) > 25 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Agent result exceeds 25 MiB")
    scan_id = job.get("scan_id")
    if not scan_id:
        complete_job(agent, job_id, "failed", "Job has no scan")
        raise HTTPException(status_code=400, detail="Job has no associated scan")
    if payload.status == "failed":
        complete_job(agent, job_id, "failed", payload.error or "Agent scan failed")
        with get_db() as conn:
            conn.execute(
                "UPDATE scans SET status = 'failed', progress = 100, stage = 'Agent failed', "
                "completed_at = ?, error = ? WHERE id = ?",
                (utcnow(), (payload.error or "Agent scan failed")[:1500], scan_id),
            )
            conn.execute(
                "INSERT INTO scan_events(scan_id, created_at, level, message) VALUES (?, ?, 'error', ?)",
                (scan_id, utcnow(), (payload.error or "Agent scan failed")[:1500]),
            )
            conn.commit()
        return {"ok": True, "accepted": False}
    if payload.status == "cancelled":
        complete_job(agent, job_id, "cancelled", payload.error or "Cancelled by agent")
        with get_db() as conn:
            conn.execute(
                "UPDATE scans SET status = 'cancelled', progress = 100, stage = 'Cancelled', "
                "completed_at = ? WHERE id = ?",
                (utcnow(), scan_id),
            )
            conn.commit()
        return {"ok": True, "accepted": False}
    if job["status"] == "processing":
        return {"ok": True, "accepted": True, "duplicate": True}
    with get_db() as conn:
        conn.execute(
            "UPDATE agent_jobs SET status = 'processing' WHERE id = ?", (job_id,)
        )
        conn.execute(
            "UPDATE scans SET stage = 'Processing agent report', progress = 5 WHERE id = ?",
            (scan_id,),
        )
        conn.commit()
    submit_agent_result(int(scan_id), payload.results, job_id)
    return {"ok": True, "accepted": True, "scan_id": scan_id}


# ---------------------------------------------------------------------------
# Server monitoring and maintenance
# ---------------------------------------------------------------------------

@router.get("/server/status")
def server_status() -> dict[str, Any]:
    db_path = database_path()
    reports_path = reports_dir()
    now = datetime.now(timezone.utc)
    uptime_seconds = max(0, int((now - _SERVER_STARTED_AT).total_seconds()))
    auth_enabled = bool(os.getenv("VS_ADMIN_PASSWORD"))
    db_stats: dict[str, Any] = {
        "path": str(db_path),
        "size": _file_size(db_path),
        "wal_size": _file_size(Path(str(db_path) + "-wal")),
        "shm_size": _file_size(Path(str(db_path) + "-shm")),
        "journal_mode": "",
        "page_count": 0,
        "page_size": 0,
        "free_pages": 0,
        "schema_version": 0,
        "integrity": "unknown",
        "writable": os.access(db_path.parent, os.W_OK),
    }
    counts: dict[str, int] = {}
    agents_online = 0
    db_error = ""
    try:
        with get_db() as conn:
            db_stats["journal_mode"] = str(conn.execute("PRAGMA journal_mode").fetchone()[0])
            db_stats["page_count"] = int(conn.execute("PRAGMA page_count").fetchone()[0])
            db_stats["page_size"] = int(conn.execute("PRAGMA page_size").fetchone()[0])
            db_stats["free_pages"] = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
            db_stats["schema_version"] = int(conn.execute("PRAGMA user_version").fetchone()[0])
            integrity = conn.execute("PRAGMA quick_check").fetchone()
            db_stats["integrity"] = str(integrity[0]) if integrity else "unknown"
            counts_row = conn.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM customers) customers,
                    (SELECT COUNT(*) FROM asset_groups) groups,
                    (SELECT COUNT(*) FROM assets) assets,
                    (SELECT COUNT(*) FROM scans) scans,
                    (SELECT COUNT(*) FROM findings) findings,
                    (SELECT COUNT(*) FROM agents) agents,
                    (SELECT COUNT(*) FROM agents WHERE status = 'revoked') agents_revoked,
                    (SELECT COUNT(*) FROM scans WHERE status = 'queued') scans_queued,
                    (SELECT COUNT(*) FROM scans WHERE status = 'running') scans_running,
                    (SELECT COUNT(*) FROM scans WHERE status = 'waiting_agent') scans_waiting_agent,
                    (SELECT COUNT(*) FROM agent_jobs WHERE status = 'queued') jobs_queued,
                    (SELECT COUNT(*) FROM agent_jobs
                        WHERE status IN ('running', 'processing')) jobs_running,
                    (SELECT COUNT(*) FROM agent_jobs WHERE status = 'failed') jobs_failed
                """
            ).fetchone()
            counts = dict(counts_row)
            agent_rows = conn.execute("SELECT status, last_seen FROM agents").fetchall()
            agents_online = sum(
                1 for row in agent_rows
                if row["status"] != "revoked" and is_online(row["last_seen"])
            )
    except sqlite3.Error as exc:
        db_error = str(exc)
        db_stats["integrity"] = f"error: {exc}"
    counts["agents_online"] = agents_online
    counts["agents_offline"] = max(
        0, counts.get("agents", 0) - counts.get("agents_revoked", 0) - agents_online
    )
    counts["scans_active"] = (
        counts.get("scans_queued", 0)
        + counts.get("scans_running", 0)
        + counts.get("scans_waiting_agent", 0)
    )

    try:
        usage = shutil.disk_usage(reports_path)
        disk = {
            "path": str(reports_path),
            "total": usage.total,
            "used": usage.used,
            "free": usage.free,
            "percent": round((usage.used / usage.total) * 100, 1) if usage.total else 0.0,
        }
    except OSError as exc:
        disk = {"path": str(reports_path), "error": str(exc), "total": 0, "used": 0, "free": 0, "percent": 0.0}

    report_count, report_size = _directory_stats(reports_path)
    settings = {
        "allow_external_apis": get_setting("allow_external_apis", "true") == "true",
        "nuclei_enabled": get_setting("nuclei_enabled", "true") == "true",
        "nmap_enabled": get_setting("nmap_enabled", "true") == "true",
    }
    tools = tool_status()
    data_writable = os.access(db_path.parent, os.W_OK)
    reports_writable = os.access(reports_path, os.W_OK)
    checks = [
        {
            "id": "database",
            "label": "Database",
            "status": "ok" if not db_error and db_stats["integrity"] == "ok" else "error",
            "detail": (
                f"{db_stats['integrity']} · {db_stats['journal_mode'] or 'unknown'} journal"
                if not db_error else db_error
            ),
        },
        {
            "id": "data",
            "label": "Data directory",
            "status": "ok" if data_writable else "error",
            "detail": str(db_path.parent),
        },
        {
            "id": "reports",
            "label": "Reports directory",
            "status": "ok" if reports_writable else "error",
            "detail": f"{reports_path} · {report_count} files",
        },
        {
            "id": "auth",
            "label": "Dashboard authentication",
            "status": "ok" if auth_enabled else "warning",
            "detail": (
                "HTTP Basic authentication is enabled"
                if auth_enabled else "VS_ADMIN_PASSWORD is not set; keep the bind address on loopback"
            ),
        },
        {
            "id": "external_apis",
            "label": "External API access",
            "status": "ok" if ENABLE_EXTERNAL_APIS and settings["allow_external_apis"] else "info",
            "detail": (
                "Outbound OSV/KEV lookups are allowed"
                if ENABLE_EXTERNAL_APIS and settings["allow_external_apis"]
                else "Air-gapped mode; optional lookups are skipped"
            ),
        },
        {
            "id": "workers",
            "label": "Scan queue",
            "status": "info",
            "detail": (
                f"{counts.get('scans_active', 0)} active scans · "
                f"{SCAN_WORKERS} parallel worker slot(s) · "
                f"{counts.get('jobs_queued', 0)} queued agent jobs"
            ),
        },
    ]
    return {
        "status": "ok" if not db_error else "degraded",
        "product": "VulnScanner",
        "version": __version__,
        "time": now.replace(microsecond=0).isoformat(),
        "started_at": _SERVER_STARTED_AT.isoformat(),
        "uptime_seconds": uptime_seconds,
        "uptime_human": _uptime_text(uptime_seconds),
        "process": {
            "pid": os.getpid(),
            "python": os_platform.python_version(),
            "platform": os_platform.platform(),
            "host": HOST,
            "port": PORT,
            "auth_enabled": auth_enabled,
            "admin_user": os.getenv("VS_ADMIN_USER", "admin") if auth_enabled else "",
            "external_api_environment": ENABLE_EXTERNAL_APIS,
        },
        "database": db_stats,
        "paths": {
            "data_dir": str(db_path.parent),
            "reports_dir": str(reports_path),
            "reports_count": report_count,
            "reports_size": report_size,
        },
        "disk": disk,
        "counts": counts,
        "queue": {
            "scans_queued": counts.get("scans_queued", 0),
            "scans_running": counts.get("scans_running", 0),
            "scans_waiting_agent": counts.get("scans_waiting_agent", 0),
            "jobs_queued": counts.get("jobs_queued", 0),
            "jobs_running": counts.get("jobs_running", 0),
            "jobs_failed": counts.get("jobs_failed", 0),
            "scan_workers": SCAN_WORKERS,
        },
        "settings": settings,
        "tools": tools,
        "limits": {
            "top_ports": len(TOP_PORTS),
            "agent_job_timeout_seconds": AGENT_JOB_TIMEOUT_SECONDS,
            "scan_workers": SCAN_WORKERS,
        },
        "checks": checks,
        "last_backup_at": get_setting("last_backup_at", ""),
        "last_backup_path": get_setting("last_backup_path", ""),
    }


@router.post("/server/database/backup", status_code=201)
def backup_database() -> dict[str, Any]:
    target_dir = reports_dir() / "backups"
    target_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    target = target_dir / f"vulnscanner-{stamp}.db"
    try:
        with get_db() as source:
            destination = sqlite3.connect(target)
            try:
                source.backup(destination)
            finally:
                destination.close()
    except (OSError, sqlite3.Error) as exc:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        raise HTTPException(status_code=500, detail=f"Database backup failed: {exc}") from exc
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    set_setting("last_backup_at", utcnow())
    set_setting("last_backup_path", str(target))
    return {
        "ok": True,
        "path": str(target),
        "size": _file_size(target),
        "created_at": utcnow(),
    }


@router.post("/server/database/vacuum")
def vacuum_database() -> dict[str, Any]:
    db_path = database_path()
    before = _file_size(db_path)
    try:
        with get_db() as conn:
            conn.execute("VACUUM")
    except sqlite3.Error as exc:
        raise HTTPException(status_code=409, detail=f"Database maintenance failed: {exc}") from exc
    after = _file_size(db_path)
    return {
        "ok": True,
        "before": before,
        "after": after,
        "saved": max(0, before - after),
    }


# ---------------------------------------------------------------------------
# Settings and imports
# ---------------------------------------------------------------------------

@router.get("/settings")
def get_settings() -> dict[str, Any]:
    with get_db() as conn:
        kev_count = conn.execute("SELECT COUNT(*) c FROM kev_catalog").fetchone()["c"]
        db_size = database_path().stat().st_size if database_path().exists() else 0
    configured_bind_host = os.getenv("VS_HOST") or HOST
    try:
        configured_bind_port = int(os.getenv("VS_PORT", str(PORT)))
    except ValueError:
        configured_bind_port = PORT
    return {
        "product": "VulnScanner",
        "version": __version__,
        "allow_external_apis": get_setting("allow_external_apis", "true") == "true",
        "nuclei_enabled": get_setting("nuclei_enabled", "true") == "true",
        "nmap_enabled": get_setting("nmap_enabled", "true") == "true",
        "testssl_enabled": get_setting("testssl_enabled", "true") == "true",
        "trivy_enabled": get_setting("trivy_enabled", "true") == "true",
        "subfinder_enabled": get_setting("subfinder_enabled", "true") == "true",
        "external_apis_available": ENABLE_EXTERNAL_APIS,
        "admin_auth_enabled": bool(os.getenv("VS_ADMIN_PASSWORD")),
        "bind_host": configured_bind_host,
        "bind_port": configured_bind_port,
        "active_bind_host": HOST,
        "active_bind_port": PORT,
        "bind_restart_required": configured_bind_host != HOST or configured_bind_port != PORT,
        "kev_last_sync": get_setting("kev_last_sync", ""),
        "kev_count": kev_count,
        "database_path": str(database_path()),
        "database_size": db_size,
        "reports_path": str(reports_dir()),
        "tools": tool_status(),
        "tool_paths": dict(TOOL_PATHS),
        "wordlist_path": str(subfinder_wordlist_path()),
        "seclists_url": SECLISTS_REPOSITORY_URL,
        "limits": {
            "top_ports": len(TOP_PORTS),
            "agent_job_timeout_seconds": AGENT_JOB_TIMEOUT_SECONDS,
            "scan_workers": SCAN_WORKERS,
            "max_web_hosts": int(get_setting("max_web_hosts", "20")),
            "workers": int(get_setting("workers", "300")),
        },
        "smtp": {
            "host": get_setting("smtp_host", ""),
            "port": get_setting("smtp_port", "587"),
            "user": get_setting("smtp_user", ""),
            "from": get_setting("smtp_from", ""),
        },
        "notify_default": {
            "email": get_setting("notify_email_default", ""),
            "webhook": get_setting("notify_webhook_default", ""),
        },
        "max_repo_bytes": int(get_setting("max_repo_bytes", str(512*1024*1024))),
        "max_source_file_bytes": int(get_setting("max_source_file_bytes", str(1024*1024))),
        "max_scan_files": int(get_setting("max_scan_files", "20000")),
        "max_cidr_hosts": int(get_setting("max_cidr_hosts", "256")),
        "agent_job_timeout": int(get_setting("agent_job_timeout", str(60*60))),
    }


@router.patch("/settings")
def update_settings(payload: SettingsUpdate) -> dict[str, Any]:
    # ``exclude_unset`` keeps PATCH semantics: fields omitted by the caller are
    # left untouched instead of being reset to their schema defaults.
    updates = payload.model_dump(exclude_unset=True)

    for key in (
        "allow_external_apis",
        "nuclei_enabled",
        "nmap_enabled",
        "testssl_enabled",
        "trivy_enabled",
        "subfinder_enabled",
    ):
        value = updates.get(key)
        if value is not None:
            set_setting(key, "true" if value else "false")

    for key in (
        "smtp_host",
        "smtp_port",
        "smtp_user",
        "smtp_password",
        "smtp_from",
        "notify_email_default",
        "notify_webhook_default",
    ):
        value = updates.get(key)
        if value is not None:
            set_setting(key, str(value))

    for key in (
        "max_web_hosts",
        "workers",
        "max_repo_bytes",
        "max_source_file_bytes",
        "max_scan_files",
        "max_cidr_hosts",
        "agent_job_timeout",
    ):
        value = updates.get(key)
        if value is not None:
            set_setting(key, str(int(value)))

    return get_settings()


@router.post("/settings/kev/sync")
def sync_kev_catalog() -> dict[str, Any]:
    if not ENABLE_EXTERNAL_APIS or get_setting("allow_external_apis", "true") != "true":
        raise HTTPException(
            status_code=400,
            detail="External APIs are disabled. Enable them in Settings or set VS_ENABLE_EXTERNAL_APIS=true.",
        )
    try:
        return sync_kev()
    except KevSyncError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/ad/import", status_code=201)
def import_ad_report(payload: ADImportRequest) -> dict[str, Any]:
    _fetch_customer(payload.customer_id)
    if payload.group_id:
        group = _fetch_group(payload.group_id)
        if group["customer_id"] != payload.customer_id:
            raise HTTPException(status_code=400, detail="Group does not belong to the selected customer")
    if payload.asset_id:
        asset = _fetch_asset(payload.asset_id)
        if asset["customer_id"] != payload.customer_id:
            raise HTTPException(status_code=400, detail="Asset does not belong to the selected customer")
    if not isinstance(payload.report, dict):
        raise HTTPException(status_code=400, detail="AD report must be a JSON object")
    domain = (payload.report.get("domain") or {})
    domain_name = domain.get("name") if isinstance(domain, dict) else str(domain)
    scan_payload = ScanCreate(
        customer_id=payload.customer_id,
        group_id=payload.group_id,
        asset_id=payload.asset_id,
        scan_type="ad",
        target=f"AD audit: {domain_name or 'imported report'}",
        options={"imported": True},
        requested_by="ad-import",
    )
    scan_id = _create_scan_record(
        scan_payload,
        scan_payload.target,
        {"imported": True},
        status="queued",
        stage="Queued AD import",
        requested_by="ad-import",
    )
    submit_ad_import(scan_id, payload.report)
    return _scan_detail(scan_id)


@router.get("/meta")
def meta() -> dict[str, Any]:
    return {
        "product": "VulnScanner",
        "version": __version__,
        "scan_types": [
            {"id": "web", "name": "Website / web application"},
            {"id": "network", "name": "Server / network services"},
            {"id": "repo", "name": "Local source repository"},
            {"id": "github", "name": "GitHub repository"},
            {"id": "domain", "name": "Domain subdomain discovery"},
            {"id": "ad", "name": "Active Directory report"},
        ],
        "agent_modules": [
            {"id": "system", "name": "System baseline and security configuration"},
            {"id": "packages", "name": "Installed package vulnerabilities (OSV)"},
            {"id": "ports", "name": "Local listening services"},
            {"id": "network", "name": "Network scan from the agent's network position"},
            {"id": "secrets", "name": "Secrets in selected local paths"},
            {"id": "repo", "name": "Repository inventory in selected paths"},
            {"id": "ad", "name": "Active Directory audit (Windows)"},
        ],
    }

# ============================================================================
# Scheduled scans
# ============================================================================

@router.get("/schedules")
def schedules_list(
    customer_id: int | None = None,
    group_id: int | None = None,
    asset_id: int | None = None,
    scan_type: str | None = None,
    enabled: bool | None = None,
) -> list[dict[str, Any]]:
    from .scheduler import get_schedules
    return [s.to_dict() for s in get_schedules(customer_id, group_id, asset_id, scan_type, enabled)]


@router.post("/schedules", status_code=201)
def schedules_create(
    customer_id: int,
    group_id: int,
    asset_id: int,
    scan_type: str,
    target: str,
    options: dict[str, Any] = {},
    cron_expression: str = "",
    notify_email: str | None = None,
    notify_webhook: str | None = None,
    enabled: bool = False,
) -> dict[str, Any]:
    from .scheduler import create_schedule
    s = create_schedule(
        customer_id, group_id, asset_id, scan_type, target, options,
        cron_expression=cron_expression, notify_email=notify_email,
        notify_webhook=notify_webhook, enabled=enabled,
    )
    return s.to_dict()


@router.get("/schedules/{schedule_id}")
def schedules_get(schedule_id: int) -> dict[str, Any]:
    from .scheduler import get_schedule
    s = get_schedule(schedule_id)
    if not s:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return s.to_dict()


@router.patch("/schedules/{schedule_id}")
def schedules_update(
    schedule_id: int,
    scan_type: str | None = None,
    target: str | None = None,
    options: dict[str, Any] | None = None,
    cron_expression: str | None = None,
    notify_email: str | None = None,
    notify_webhook: str | None = None,
    enabled: bool | None = None,
) -> dict[str, Any]:
    from .scheduler import update_schedule
    s = update_schedule(
        schedule_id, scan_type=scan_type, target=target, options=options,
        cron_expression=cron_expression, notify_email=notify_email,
        notify_webhook=notify_webhook, enabled=enabled,
    )
    if not s:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return s.to_dict()


@router.delete("/schedules/{schedule_id}")
def schedules_delete(schedule_id: int) -> dict[str, Any]:
    from .scheduler import delete_schedule
    delete_schedule(schedule_id)
    return {"ok": True}


# ============================================================================
# Trends
# ============================================================================

@router.get("/trends/compare")
def trends_compare(
    older_scan_id: int,
    newer_scan_id: int,
) -> dict[str, Any]:
    from .trends import compare_scans
    return compare_scans(older_scan_id, newer_scan_id)


@router.get("/trends/assets/{asset_id}")
def trends_asset(asset_id: int, limit: int = 10) -> dict[str, Any]:
    from .trends import asset_trend
    return asset_trend(asset_id, limit)


# ============================================================================
# PDF Reports
# ============================================================================

@router.get("/scans/{scan_id}/report/pdf")
def scan_pdf(
    scan_id: int,
    report_type: str = "technical",
) -> Response:
    from .database import get_db
    from .reporting import build_pdf
    with get_db() as conn:
        scan_row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan_row:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings_rows = conn.execute(
        "SELECT severity, title, category, description, evidence, remediation, cve, cwe, cvss, location, fingerprint, status FROM findings WHERE scan_id = ?",
        (scan_id,),
    ).fetchall()
    findings = [dict(r) for r in findings_rows]
    pdf_bytes = build_pdf(
        dict(scan_row),
        findings,
        {"generated_at": str(datetime.now()), "customer": {}, "group": {}, "asset": {}},
        report_type=report_type,
    )
    return Response(content=pdf_bytes, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-{report_type}.pdf"'})

@router.get("/tools/status")
def tools_status() -> dict[str, Any]:
    from .tools_check import check_external_tools
    return {"tools": check_external_tools(), "message": "Run --version manually to confirm the latest releases of optional tools."}

# ============================================================================
# SSL / Certificate management
# ============================================================================

@router.get("/certs/status")
def cert_status() -> dict[str, Any]:
    from .certs import (
        INTERNAL_CERT_FILE,
        INTERNAL_SERVER_CERT,
        INTERNAL_SERVER_KEY,
        WEB_CERT_FILE,
        WEB_KEY_FILE,
        get_internal_cert_paths,
        get_web_cert_paths,
    )

    get_web_cert_paths()
    get_internal_cert_paths()
    web_exists = WEB_CERT_FILE.exists() and WEB_KEY_FILE.exists()
    internal_exists = INTERNAL_SERVER_CERT.exists() and INTERNAL_SERVER_KEY.exists()
    return {
        "web": {
            "cert_path": str(WEB_CERT_FILE) if web_exists else None,
            "key_path": str(WEB_KEY_FILE) if web_exists else None,
            "exists": web_exists,
            "cert_size_bytes": WEB_CERT_FILE.stat().st_size if web_exists else 0,
            "key_size_bytes": WEB_KEY_FILE.stat().st_size if web_exists else 0,
        },
        "internal": {
            "cert_path": str(INTERNAL_SERVER_CERT) if internal_exists else None,
            "key_path": str(INTERNAL_SERVER_KEY) if internal_exists else None,
            "ca_path": str(INTERNAL_CERT_FILE) if INTERNAL_CERT_FILE.exists() else None,
            "exists": internal_exists,
            "cert_size_bytes": INTERNAL_SERVER_CERT.stat().st_size if internal_exists else 0,
            "key_size_bytes": INTERNAL_SERVER_KEY.stat().st_size if internal_exists else 0,
        },
    }


@router.post("/certs/regenerate")
def cert_regenerate(
    mode: str | None = Query(default=None),
    payload: dict[str, Any] | None = Body(default=None),
) -> dict[str, Any]:
    """Regenerate the web certificate, the internal CA, or both.

    ``mode`` is accepted as a query parameter (documented API) and, for
    backwards compatibility with older UI builds, as a JSON body field.
    """
    from .certs import (
        INTERNAL_SERVER_CERT,
        INTERNAL_SERVER_KEY,
        WEB_CERT_FILE,
        WEB_KEY_FILE,
        _generate_internal_ca,
        _generate_self_signed,
    )

    requested = mode
    if requested is None and isinstance(payload, dict):
        candidate = payload.get("mode")
        if isinstance(candidate, str):
            requested = candidate
    mode = (requested or "web").strip().lower()
    if mode not in {"web", "internal", "all"}:
        raise HTTPException(status_code=400, detail="mode must be 'web', 'internal', or 'all'")

    targets: list[str] = []
    result: dict[str, Any] = {"regenerated": True, "mode": mode}
    if mode in {"web", "all"}:
        _generate_self_signed(WEB_CERT_FILE, WEB_KEY_FILE, cn="vulnscanner.local")
        targets.append("web")
        result["web"] = {
            "cert_path": str(WEB_CERT_FILE),
            "key_path": str(WEB_KEY_FILE),
            "cert_size_bytes": WEB_CERT_FILE.stat().st_size,
            "key_size_bytes": WEB_KEY_FILE.stat().st_size,
        }
    if mode in {"internal", "all"}:
        _generate_internal_ca()
        targets.append("internal")
        result["internal"] = {
            "cert_path": str(INTERNAL_SERVER_CERT),
            "key_path": str(INTERNAL_SERVER_KEY),
            "cert_size_bytes": INTERNAL_SERVER_CERT.stat().st_size,
            "key_size_bytes": INTERNAL_SERVER_KEY.stat().st_size,
        }

    result["targets"] = targets
    return result


@router.post("/certs/upload")
def cert_upload(
    cert_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    mode: str = Form("web"),
) -> dict[str, Any]:
    from .certs import (
        INTERNAL_SERVER_CERT,
        INTERNAL_SERVER_KEY,
        MAX_CERT_BYTES,
        WEB_CERT_FILE,
        WEB_KEY_FILE,
        CertificateError,
        save_certificate,
    )

    mode = (mode or "").strip().lower()
    if mode not in {"web", "internal"}:
        raise HTTPException(status_code=400, detail="mode must be 'web' or 'internal'")

    cert_data = cert_file.file.read(MAX_CERT_BYTES + 1)
    key_data = key_file.file.read(MAX_CERT_BYTES + 1)
    if len(cert_data) > MAX_CERT_BYTES or len(key_data) > MAX_CERT_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Certificate and key files must be smaller than {MAX_CERT_BYTES // 1024} KiB each",
        )
    if not cert_data or not key_data:
        raise HTTPException(status_code=400, detail="Certificate and key files must not be empty")

    target_crt = INTERNAL_SERVER_CERT if mode == "internal" else WEB_CERT_FILE
    target_key = INTERNAL_SERVER_KEY if mode == "internal" else WEB_KEY_FILE
    try:
        save_certificate(target_crt, target_key, cert_data, key_data)
    except CertificateError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "uploaded": True,
        "mode": mode,
        "cert_path": str(target_crt),
        "key_path": str(target_key),
        "cert_size_bytes": len(cert_data),
        "key_size_bytes": len(key_data),
    }


def _is_env_entry(line: str, key: str) -> bool:
    stripped = line.strip()
    if stripped.startswith("#"):
        stripped = stripped[1:].lstrip()
    return stripped.startswith(key + "=")


def _upsert_env_entries(path: Path, entries: dict[str, str]) -> None:
    """Add or replace ``KEY=VALUE`` entries while preserving other lines."""
    lines: list[str] = []
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
    for key, value in entries.items():
        entry = f"{key}={value}"
        new_lines: list[str] = []
        found = False
        for line in lines:
            if _is_env_entry(line, key):
                if not found:
                    new_lines.append(entry)
                    found = True
                # Drop duplicate entries for the same key.
            else:
                new_lines.append(line)
        if not found:
            new_lines.append(entry)
        lines = new_lines
    _write_env_file(path, lines)


def _write_env_file(path: Path, lines: list[str]) -> None:
    """Atomically replace ``.env`` with mode 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(lines).rstrip("\n") + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=".env.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp_name, 0o600)
        except OSError:
            pass
        os.replace(temp_name, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


@router.post("/settings/admin-password")
def set_admin_password(payload: AdminPasswordUpdate) -> dict[str, Any]:
    """Set or disable the dashboard password, stored in the project .env file."""
    env_path = BASE_DIR / ".env"
    _upsert_env_entries(env_path, {"VS_ADMIN_PASSWORD": payload.password})

    # The auth middleware reads os.environ per request, so the change applies
    # immediately without a restart.
    if payload.password:
        os.environ["VS_ADMIN_PASSWORD"] = payload.password
    else:
        os.environ.pop("VS_ADMIN_PASSWORD", None)

    return {"ok": True, "set": bool(payload.password), "restart_required": False}


@router.post("/settings/network")
def set_bind_address(payload: BindAddressUpdate) -> dict[str, Any]:
    """Persist the listener bind address to .env; a restart is required.

    Uvicorn binds the socket at startup, so this only writes configuration.
    ``run.sh`` and ``run.bat`` load ``.env`` and apply it on the next start.
    """
    env_path = BASE_DIR / ".env"
    _upsert_env_entries(
        env_path,
        {"VS_HOST": payload.bind_host, "VS_PORT": str(payload.bind_port)},
    )

    # Reflect the saved configuration in the UI immediately, without rebinding.
    os.environ["VS_HOST"] = payload.bind_host
    os.environ["VS_PORT"] = str(payload.bind_port)
    restart_required = payload.bind_host != HOST or payload.bind_port != PORT
    return {
        "ok": True,
        "bind_host": payload.bind_host,
        "bind_port": payload.bind_port,
        "active_bind_host": HOST,
        "active_bind_port": PORT,
        "restart_required": restart_required,
    }


@router.post("/settings/tools")
def set_tool_paths(payload: ToolSettingsUpdate) -> dict[str, Any]:
    """Persist optional tool paths to .env and apply them to this process."""
    entries: dict[str, str] = {}
    for name, raw in payload.paths.items():
        path = (raw or "").strip()
        if not path:
            entries[TOOL_ENV_VARS[name]] = ""
            continue
        expanded = Path(path).expanduser()
        if not expanded.is_absolute():
            raise HTTPException(
                status_code=400,
                detail=f"{name} path must be absolute, for example /usr/local/bin/{name}",
            )
        if not expanded.is_file():
            raise HTTPException(
                status_code=400,
                detail=f"{name} path does not exist or is not a file",
            )
        entries[TOOL_ENV_VARS[name]] = path

    if entries:
        _upsert_env_entries(BASE_DIR / ".env", entries)
        for name, raw in payload.paths.items():
            path = (raw or "").strip()
            os.environ[TOOL_ENV_VARS[name]] = path
            TOOL_PATHS[name] = path

    return {
        "ok": True,
        "tool_paths": dict(TOOL_PATHS),
        "tools": tool_status(),
    }


@router.get("/settings/wordlist")
def get_wordlist() -> dict[str, Any]:
    """Return the editable subdomain wordlist and its provenance."""
    return wordlist_info()


@router.post("/settings/wordlist")
def update_wordlist(payload: WordlistUpdate) -> dict[str, Any]:
    try:
        return save_wordlist(payload.content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not save the wordlist: {exc}") from exc


@router.post("/settings/wordlist/seclists")
def load_seclists_wordlist() -> dict[str, Any]:
    """Download the standard SecLists DNS wordlist into the editable path."""
    if not ENABLE_EXTERNAL_APIS or get_setting("allow_external_apis", "true") != "true":
        raise HTTPException(
            status_code=400,
            detail="External APIs are disabled. Enable them in Settings or set VS_ENABLE_EXTERNAL_APIS=true.",
        )
    try:
        return download_seclists_wordlist()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"Could not download SecLists: {exc}") from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not save the wordlist: {exc}") from exc
