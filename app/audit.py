"""Security audit trail.

Every state-changing API request is recorded automatically by the HTTP
middleware.  Sensitive operations (login, MFA changes, restores, storage
relocation) additionally write a descriptive entry with a stable action name.
The log is queryable from the Audit page and exportable as CSV.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Any

from .database import get_db, utcnow

MAX_DETAIL = 2000


def _clean(value: Any, limit: int = 500) -> str:
    return str(value or "").strip()[:limit]


def record(
    action: str,
    *,
    category: str = "general",
    actor: str = "system",
    target: str = "",
    detail: str = "",
    outcome: str = "success",
    ip: str = "",
    user_agent: str = "",
) -> None:
    """Best-effort audit insert.

    Audit failures must never break the operation being audited.  A locked or
    read-only database is logged by the caller's normal error path.
    """
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO audit_log("
                "created_at, actor, action, category, target, detail, outcome, ip, user_agent"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    utcnow(),
                    _clean(actor, 200) or "anonymous",
                    _clean(action, 120),
                    _clean(category, 40) or "general",
                    _clean(target, 500),
                    _clean(detail, MAX_DETAIL),
                    _clean(outcome, 20) or "success",
                    _clean(ip, 80),
                    _clean(user_agent, 300),
                ),
            )
            conn.commit()
    except Exception:
        return


def record_request(
    request,
    action: str,
    *,
    category: str = "general",
    target: str = "",
    detail: str = "",
    outcome: str = "success",
    actor: str | None = None,
) -> None:
    from .rate_limit import client_ip

    record(
        action,
        category=category,
        actor=actor or getattr(request.state, "actor", "anonymous"),
        target=target or request.url.path,
        detail=detail,
        outcome=outcome,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
    )


def list_entries(
    *,
    limit: int = 100,
    offset: int = 0,
    category: str | None = None,
    action: str | None = None,
    actor: str | None = None,
    outcome: str | None = None,
    query: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> dict[str, Any]:
    clauses: list[str] = []
    params: list[Any] = []
    if category:
        clauses.append("category = ?")
        params.append(category)
    if action:
        clauses.append("action LIKE ?")
        params.append(f"%{action}%")
    if actor:
        clauses.append("actor LIKE ?")
        params.append(f"%{actor}%")
    if outcome:
        clauses.append("outcome = ?")
        params.append(outcome)
    if query:
        clauses.append("(action LIKE ? OR target LIKE ? OR detail LIKE ? OR actor LIKE ?)")
        like = f"%{query}%"
        params.extend([like, like, like, like])
    if since:
        clauses.append("created_at >= ?")
        params.append(since)
    if until:
        clauses.append("created_at <= ?")
        params.append(until)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_db() as conn:
        total = int(
            conn.execute(f"SELECT COUNT(*) FROM audit_log {where}", params).fetchone()[0]
        )
        rows = conn.execute(
            f"SELECT * FROM audit_log {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "entries": [dict(row) for row in rows],
    }


def export_csv(
    *,
    limit: int = 10_000,
    category: str | None = None,
    action: str | None = None,
    actor: str | None = None,
    outcome: str | None = None,
    query: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> str:
    result = list_entries(
        limit=limit,
        offset=0,
        category=category,
        action=action,
        actor=actor,
        outcome=outcome,
        query=query,
        since=since,
        until=until,
    )
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "id",
            "created_at",
            "actor",
            "action",
            "category",
            "target",
            "outcome",
            "ip",
            "detail",
            "user_agent",
        ]
    )
    for entry in reversed(result["entries"]):
        writer.writerow(
            [
                entry.get("id"),
                entry.get("created_at"),
                entry.get("actor"),
                entry.get("action"),
                entry.get("category"),
                entry.get("target"),
                entry.get("outcome"),
                entry.get("ip"),
                entry.get("detail"),
                entry.get("user_agent"),
            ]
        )
    return buffer.getvalue()


def summary() -> dict[str, Any]:
    with get_db() as conn:
        total = int(conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0])
        failures = int(
            conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE outcome = 'failure'"
            ).fetchone()[0]
        )
        generated_at = (
            datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        )
        recent = int(
            conn.execute(
                "SELECT COUNT(*) FROM audit_log "
                "WHERE created_at >= strftime('%Y-%m-%dT%H:%M:%S', 'now', '-1 day')"
            ).fetchone()[0]
        )
    return {
        "total": total,
        "failures": failures,
        "last_24h": recent,
        "generated_at": generated_at,
    }
