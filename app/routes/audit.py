"""Audit trail API and CSV export."""

from __future__ import annotations

from fastapi import APIRouter, Query, Response

from ..audit import export_csv, list_entries, summary

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
def audit_entries(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    category: str | None = None,
    action: str | None = None,
    actor: str | None = None,
    outcome: str | None = None,
    q: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> dict:
    return list_entries(
        limit=limit,
        offset=offset,
        category=category,
        action=action,
        actor=actor,
        outcome=outcome,
        query=q,
        since=since,
        until=until,
    )


@router.get("/summary")
def audit_summary() -> dict:
    return summary()


@router.get("/export")
def audit_export(
    limit: int = Query(default=10_000, ge=1, le=100_000),
    category: str | None = None,
    action: str | None = None,
    actor: str | None = None,
    outcome: str | None = None,
    q: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> Response:
    content = export_csv(
        limit=limit,
        category=category,
        action=action,
        actor=actor,
        outcome=outcome,
        query=q,
        since=since,
        until=until,
    )
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="vulnscanner-audit.csv"'},
    )
