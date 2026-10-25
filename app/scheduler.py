"""Scheduled scans, notifications and background scheduling."""

from __future__ import annotations

import logging
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from typing import Any, List, Optional

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import HTTPException

from .database import get_db, utcnow, get_setting

logger = logging.getLogger("scheduler")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

def _row_to_schedule(row: Any) -> "ScanSchedule":
    return ScanSchedule(
        id=int(row["id"]),
        customer_id=int(row["customer_id"]) if row["customer_id"] is not None else None,
        group_id=int(row["group_id"]) if row["group_id"] is not None else None,
        asset_id=int(row["asset_id"]) if row["asset_id"] is not None else None,
        scan_type=str(row["scan_type"]),
        target=str(row["target"]),
        options=dict(row["options"] or {}),
        cron_expression=str(row["cron_expression"] or ""),
        notify_email=str(row["notify_email"] or "") or None,
        notify_webhook=str(row["notify_webhook"] or "") or None,
        enabled=bool(row["enabled"]),
        status=str(row["status"] or "active"),
        error=str(row["error"] or ""),
        created_at=str(row["created_at"] or ""),
        updated_at=str(row["updated_at"] or ""),
        last_run=str(row["last_run"] or ""),
        next_run=str(row["next_run"] or ""),
    )


class ScanSchedule:
    """A recurring scan definition."""

    def __init__(self, **kwargs: Any) -> None:
        for key, value in kwargs.items():
            setattr(self, key, value)

    @classmethod
    def from_row(cls, row: Any) -> "ScanSchedule":
        return _row_to_schedule(row)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "customer_id": self.customer_id,
            "group_id": self.group_id,
            "asset_id": self.asset_id,
            "scan_type": self.scan_type,
            "target": self.target,
            "options": self.options,
            "cron_expression": self.cron_expression,
            "notify_email": self.notify_email,
            "notify_webhook": self.notify_webhook,
            "enabled": self.enabled,
            "status": self.status,
            "error": self.error,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_run": self.last_run,
            "next_run": self.next_run,
        }


# ---------------------------------------------------------------------------
# Scheduler lifecycle
# ---------------------------------------------------------------------------

_scheduler: BackgroundScheduler | None = None


def _job_target(schedule_id: int) -> None:
    """Called by APScheduler for each due schedule."""
    try:
        from .database import get_db, utcnow, json_dump
        from .jobs import submit_scan

        schedule = get_schedule(schedule_id)
        if not schedule or not schedule.enabled:
            return
        if schedule.status == "failed":
            return

        # Insert scan record into DB (same pattern as API)
        with get_db() as conn:
            cursor = conn.execute(
                "INSERT INTO scans("
                "customer_id, group_id, asset_id, scan_type, target, status, progress, stage, options, summary, requested_by, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    schedule.customer_id,
                    schedule.group_id,
                    schedule.asset_id,
                    schedule.scan_type,
                    schedule.target,
                    "queued",
                    0,
                    "Queued",
                    json_dump(schedule.options or {}),
                    "{}",
                    "schedule",
                    utcnow(),
                ),
            )
            scan_id = int(cursor.lastrowid)
            conn.execute(
                "INSERT INTO scan_events(scan_id, created_at, level, message) VALUES (?, ?, 'info', ?)",
                (scan_id, utcnow(), f"Scheduled scan queued for {schedule.target}"),
            )
            conn.commit()

        submit_scan(scan_id, {"_scheduled": True, "_schedule_id": schedule.id})
        complete_scheduled_run(schedule.id, scan_id)
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Scheduled scan %s failed: %s", schedule_id, exc)
        mark_schedule_failed(schedule_id, str(exc))


def start_scheduler() -> None:
    """Start the background scheduler. Called once at application startup."""
    global _scheduler
    if _scheduler is not None:
        return
    scheduler = BackgroundScheduler()
    # Check for due scheduled scans every 30 seconds.
    scheduler.add_job(
        _scheduled_scan_tick,
        trigger="interval",
        seconds=30,
        id="scheduled_scan_tick",
        replace_existing=True,
    )
    _scheduler = scheduler
    scheduler.start()
    logger.info("Scan scheduler started")


def _scheduled_scan_tick() -> None:
    """APScheduler tick: pick up due schedules."""
    try:
        due = get_due_schedules()
        for schedule in due:
            _job_target(int(schedule["id"]))
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Scheduled scan tick failed: %s", exc)


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None


# ---------------------------------------------------------------------------
# Schedule CRUD
# ---------------------------------------------------------------------------

def create_schedule(
    customer_id: int,
    group_id: int,
    asset_id: int,
    scan_type: str,
    target: str,
    options: dict[str, Any],
    cron_expression: str = "",
    notify_email: str | None = None,
    notify_webhook: str | None = None,
    enabled: bool = False,
) -> ScanSchedule:
    from .database import transaction

    if scan_type not in {"web", "network", "repo", "github", "ad"}:
        raise HTTPException(status_code=400, detail=f"Invalid scan type: {scan_type}")

    with transaction() as conn:
        asset = conn.execute(
            "SELECT id FROM assets WHERE id = ?", (asset_id,)
        ).fetchone()
        group = conn.execute(
            "SELECT id FROM asset_groups WHERE id = ?", (group_id,)
        ).fetchone()
        customer = conn.execute(
            "SELECT id FROM customers WHERE id = ?", (customer_id,)
        ).fetchone()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")

        cursor = conn.execute(
            "INSERT INTO scan_schedules("
            "customer_id, group_id, asset_id, scan_type, target, options, "
            "cron_expression, notify_email, notify_webhook, enabled, status, next_run, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                customer_id,
                group_id,
                asset_id,
                scan_type,
                target,
                _json_dumps(options),
                cron_expression,
                notify_email or None,
                notify_webhook or None,
                1 if enabled else 0,
                "active" if enabled else "paused",
                datetime.utcnow() + _next_run_offset(),
                datetime.utcnow(),
                datetime.utcnow(),
            ),
        )
        schedule_id = int(cursor.lastrowid)
        next_run = datetime.utcnow() + _next_run_offset()
        conn.execute(
            "UPDATE scan_schedules SET next_run = ? WHERE id = ?",
            (next_run, schedule_id),
        )

    return get_schedule(schedule_id)  # type: ignore[return-value]


def get_schedule(schedule_id: int) -> Optional[ScanSchedule]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM scan_schedules WHERE id = ?", (schedule_id,)
        ).fetchone()
        return ScanSchedule.from_row(row) if row else None


def get_schedules(
    customer_id: int | None = None,
    group_id: int | None = None,
    asset_id: int | None = None,
    scan_type: str | None = None,
    enabled: bool | None = None,
) -> List[ScanSchedule]:
    with get_db() as conn:
        query = "SELECT * FROM scan_schedules"
        conditions: List[str] = []
        params: List[Any] = []

        if customer_id is not None:
            conditions.append("customer_id = ?")
            params.append(customer_id)
        if group_id is not None:
            conditions.append("group_id = ?")
            params.append(group_id)
        if asset_id is not None:
            conditions.append("asset_id = ?")
            params.append(asset_id)
        if scan_type is not None:
            conditions.append("scan_type = ?")
            params.append(scan_type)
        if enabled is not None:
            conditions.append("enabled = ?")
            params.append(1 if enabled else 0)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        rows = conn.execute(query, params).fetchall()
        return [ScanSchedule.from_row(row) for row in rows]


def update_schedule(
    schedule_id: int,
    *,
    scan_type: str | None = None,
    target: str | None = None,
    options: dict[str, Any] | None = None,
    cron_expression: str | None = None,
    notify_email: str | None = None,
    notify_webhook: str | None = None,
    enabled: bool | None = None,
) -> Optional[ScanSchedule]:
    updates: dict[str, Any] = {}
    if scan_type is not None:
        updates["scan_type"] = scan_type
    if target is not None:
        updates["target"] = target
    if options is not None:
        updates["options"] = _json_dumps(options)
    if cron_expression is not None:
        updates["cron_expression"] = cron_expression
    if notify_email is not None:
        updates["notify_email"] = notify_email
    if notify_webhook is not None:
        updates["notify_webhook"] = notify_webhook
    if enabled is not None:
        updates["enabled"] = 1 if enabled else 0

    if not updates:
        return get_schedule(schedule_id)

    with get_db() as conn:
        set_sql = ", ".join(f"{key} = ?" for key in updates)
        conn.execute(
            f"UPDATE scan_schedules SET {set_sql}, updated_at = ? WHERE id = ?",
            (*updates.values(), datetime.utcnow(), schedule_id),
        )
        conn.commit()
    return get_schedule(schedule_id)


def delete_schedule(schedule_id: int) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM scan_schedules WHERE id = ?", (schedule_id,))
        conn.commit()


def get_due_schedules() -> List[dict[str, Any]]:
    """Return enabled schedules whose next_run has passed."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_schedules WHERE enabled = 1 AND next_run <= ? ORDER BY next_run ASC",
            (datetime.utcnow(),),
        ).fetchall()
    return [dict(row) for row in rows]


def mark_schedule_failed(schedule_id: int, error: str) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE scan_schedules SET status = 'failed', error = ?, updated_at = ? WHERE id = ?",
            (error, datetime.utcnow(), schedule_id),
        )
        conn.commit()


def complete_scheduled_run(schedule_id: int, scan_id: int) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE scan_schedules SET last_run = ?, status = 'completed', next_run = ? WHERE id = ?",
            (datetime.utcnow(), datetime.utcnow() + _next_run_offset(), schedule_id),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _json_dumps(value: Any) -> str:
    import json

    return json.dumps(value or {})


def _next_run_offset() -> str:
    from datetime import timedelta

    return (datetime.utcnow() + timedelta(days=1)).isoformat()


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

async def send_notification(
    schedule: ScanSchedule,
    scan_id: int,
    status: str,
    message: str,
) -> None:
    """Send email/webhook notifications for a scheduled scan."""
    if status == "completed" and not schedule.notify_email and not schedule.notify_webhook:
        return

    body = f"Scheduled scan {scan_id} for {schedule.target} finished with status: {status}\n\n{message}"
    if schedule.notify_email:
        try:
            import smtplib
            from email.mime.text import MIMEText

            smtp_host = get_setting("smtp_host", "")
            smtp_port = int(get_setting("smtp_port", "587"))
            smtp_user = get_setting("smtp_user", "")
            smtp_pass = get_setting("smtp_password", "")
            from_addr = get_setting("smtp_from", smtp_user or "vulnscanner@localhost")

            if smtp_host and smtp_user and smtp_pass:
                msg = MIMEText(body, "plain", "utf-8")
                msg["Subject"] = f"VulnScanner: Scan {schedule.scan_type} {schedule.target} - {status}"
                msg["From"] = from_addr
                msg["To"] = schedule.notify_email
                with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
                    s.starttls()
                    s.login(smtp_user, smtp_pass)
                    s.sendmail(from_addr, [schedule.notify_email], msg.as_string())
        except Exception as exc:
            logger.error("Email notification failed: %s", exc)

    if schedule.notify_webhook:
        try:
            import httpx

            async with httpx.AsyncClient() as client:
                await client.post(
                    schedule.notify_webhook,
                    json={
                        "schedule_id": schedule.id,
                        "scan_id": scan_id,
                        "status": status,
                        "target": schedule.target,
                        "scan_type": schedule.scan_type,
                        "message": message,
                    },
                    timeout=10.0,
                )
        except Exception as exc:
            logger.error("Webhook notification failed: %s", exc)
