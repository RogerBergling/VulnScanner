"""Scheduled scans, notifications and background scheduling.

Schedules are stored in SQLite and evaluated by a small APScheduler background
loop. A cron expression uses the standard five-field crontab syntax. An empty
expression means "run once per day"; this preserves the original behaviour for
existing rows while allowing proper cron schedules.
"""

from __future__ import annotations

import json
import logging
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from typing import Any, List, Optional

import httpx
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import HTTPException

from .config import AGENT_JOB_TIMEOUT_SECONDS, get_limit
from .database import (
    get_db,
    get_setting,
    json_load,
    transaction,
    utcnow,
)

logger = logging.getLogger("scheduler")

SCAN_TYPES = {"web", "network", "repo", "github", "domain", "ad"}


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _json_dumps(value: Any) -> str:
    return json.dumps(value or {}, ensure_ascii=False, separators=(",", ":"), default=str)


def _cron_trigger(expression: str) -> CronTrigger | None:
    expression = (expression or "").strip()
    if not expression:
        return None
    try:
        return CronTrigger.from_crontab(expression, timezone=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "cron_expression must be a five-field crontab expression "
            "(for example '0 2 * * *')"
        ) from exc


def _next_run(expression: str, base: datetime | None = None) -> str:
    base = base or _now()
    trigger = _cron_trigger(expression)
    if trigger is None:
        return (base + timedelta(days=1)).isoformat()
    fire = trigger.get_next_fire_time(None, base)
    if fire is None:
        return ""
    return fire.astimezone(timezone.utc).replace(microsecond=0).isoformat()


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class ScanSchedule:
    """A recurring scan definition."""

    def __init__(self, **kwargs: Any) -> None:
        for key, value in kwargs.items():
            setattr(self, key, value)

    @classmethod
    def from_row(cls, row: Any) -> "ScanSchedule":
        return cls(
            id=int(row["id"]),
            customer_id=int(row["customer_id"]) if row["customer_id"] is not None else None,
            group_id=int(row["group_id"]) if row["group_id"] is not None else None,
            asset_id=int(row["asset_id"]) if row["asset_id"] is not None else None,
            scan_type=str(row["scan_type"]),
            target=str(row["target"] or ""),
            options=json_load(row["options"], {}),
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
    """Called by the scheduler tick for one due schedule."""
    try:
        from .jobs import submit_scan

        schedule = get_schedule(schedule_id)
        if not schedule or not schedule.enabled or schedule.status == "failed":
            return

        with transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO scans("
                "customer_id, group_id, asset_id, scan_type, target, status, progress, "
                "stage, options, summary, requested_by, created_at"
                ") VALUES (?, ?, ?, ?, ?, 'queued', 0, 'Queued', ?, '{}', 'schedule', ?)",
                (
                    schedule.customer_id,
                    schedule.group_id,
                    schedule.asset_id,
                    schedule.scan_type,
                    schedule.target,
                    _json_dumps(schedule.options),
                    utcnow(),
                ),
            )
            scan_id = int(cursor.lastrowid)
            conn.execute(
                "INSERT INTO scan_events(scan_id, created_at, level, message) "
                "VALUES (?, ?, 'info', ?)",
                (scan_id, utcnow(), f"Scheduled scan queued for {schedule.target}"),
            )
            conn.execute(
                "UPDATE scan_schedules SET last_run = ?, next_run = ?, status = 'active', "
                "error = '', updated_at = ? WHERE id = ?",
                (utcnow(), _next_run(schedule.cron_expression), utcnow(), schedule.id),
            )

        submit_scan(scan_id, {"_scheduled": True, "_schedule_id": schedule.id})
        logger.info("Queued scheduled scan %s for schedule %s", scan_id, schedule.id)
    except Exception as exc:  # pragma: no cover - defensive scheduler boundary
        logger.error("Scheduled scan %s failed: %s", schedule_id, exc)
        mark_schedule_failed(schedule_id, str(exc))


def start_scheduler() -> None:
    """Start the background scheduler. Called once at application startup."""
    global _scheduler
    if _scheduler is not None:
        return
    scheduler = BackgroundScheduler(timezone=timezone.utc)
    scheduler.add_job(
        _scheduled_scan_tick,
        trigger="interval",
        seconds=30,
        id="scheduled_scan_tick",
        replace_existing=True,
    )
    scheduler.add_job(
        _expire_agent_jobs_tick,
        trigger="interval",
        seconds=60,
        id="agent_job_expiry_tick",
        replace_existing=True,
    )
    _scheduler = scheduler
    scheduler.start()
    logger.info("Scan scheduler started")


def _scheduled_scan_tick() -> None:
    """APScheduler tick: pick up due schedules."""
    try:
        for schedule in get_due_schedules():
            _job_target(int(schedule["id"]))
    except Exception as exc:  # pragma: no cover - defensive scheduler boundary
        logger.error("Scheduled scan tick failed: %s", exc)


def _expire_agent_jobs_tick() -> None:
    try:
        from .agents import expire_stale_agent_jobs

        expire_stale_agent_jobs(get_limit("agent_job_timeout", AGENT_JOB_TIMEOUT_SECONDS))
    except Exception as exc:  # pragma: no cover - defensive scheduler boundary
        logger.error("Agent job expiry tick failed: %s", exc)


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None


# ---------------------------------------------------------------------------
# Schedule CRUD
# ---------------------------------------------------------------------------


def _resolve_scope(
    conn: Any,
    customer_id: int,
    group_id: int | None,
    asset_id: int | None,
    target: str,
) -> tuple[int, int, int | None, str]:
    customer = conn.execute("SELECT id FROM customers WHERE id = ?", (customer_id,)).fetchone()
    if not customer:
        raise ValueError("Customer not found")

    resolved_group = group_id
    resolved_asset = asset_id
    resolved_target = (target or "").strip()

    if asset_id is not None:
        asset = conn.execute(
            "SELECT id, customer_id, group_id, identifier FROM assets WHERE id = ?",
            (asset_id,),
        ).fetchone()
        if not asset:
            raise ValueError("Asset not found")
        if int(asset["customer_id"]) != int(customer_id):
            raise ValueError("Asset does not belong to the selected customer")
        if resolved_group is not None and int(asset["group_id"]) != int(resolved_group):
            raise ValueError("Asset does not belong to the selected group")
        resolved_group = int(asset["group_id"])
        if not resolved_target:
            resolved_target = str(asset["identifier"] or "")

    if resolved_group is None:
        default = conn.execute(
            "SELECT id FROM asset_groups WHERE customer_id = ? ORDER BY id LIMIT 1",
            (customer_id,),
        ).fetchone()
        if default:
            resolved_group = int(default["id"])
        else:
            resolved_group = int(
                conn.execute(
                    "INSERT INTO asset_groups(customer_id, name, description, created_at) "
                    "VALUES (?, 'General', 'Default asset group', ?)",
                    (customer_id, utcnow()),
                ).lastrowid
            )
    group = conn.execute(
        "SELECT id, customer_id FROM asset_groups WHERE id = ?", (resolved_group,)
    ).fetchone()
    if not group:
        raise ValueError("Group not found")
    if int(group["customer_id"]) != int(customer_id):
        raise ValueError("Group does not belong to the selected customer")

    if not resolved_target:
        raise ValueError("A schedule needs a target or an asset with an identifier")
    return int(customer_id), int(resolved_group), resolved_asset, resolved_target


def create_schedule(
    customer_id: int,
    group_id: int | None,
    asset_id: int | None,
    scan_type: str,
    target: str,
    options: dict[str, Any],
    cron_expression: str = "",
    notify_email: str | None = None,
    notify_webhook: str | None = None,
    enabled: bool = False,
) -> ScanSchedule:
    scan_type = (scan_type or "").strip().lower()
    if scan_type not in SCAN_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid scan type: {scan_type}")
    next_run = _next_run(cron_expression)

    with transaction() as conn:
        customer_id, group_id, asset_id, target = _resolve_scope(
            conn, customer_id, group_id, asset_id, target
        )
        now = utcnow()
        cursor = conn.execute(
            "INSERT INTO scan_schedules("
            "customer_id, group_id, asset_id, scan_type, target, options, "
            "cron_expression, notify_email, notify_webhook, enabled, status, "
            "next_run, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                customer_id,
                group_id,
                asset_id,
                scan_type,
                target,
                _json_dumps(options),
                (cron_expression or "").strip(),
                (notify_email or "").strip(),
                (notify_webhook or "").strip(),
                1 if enabled else 0,
                "active" if enabled else "paused",
                next_run,
                now,
                now,
            ),
        )
        schedule_id = int(cursor.lastrowid)

    schedule = get_schedule(schedule_id)
    if not schedule:
        raise RuntimeError("Could not save the schedule")
    return schedule


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

        query += " ORDER BY id"
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
    current = get_schedule(schedule_id)
    if not current:
        return None

    updates: dict[str, Any] = {}
    if scan_type is not None:
        scan_type = scan_type.strip().lower()
        if scan_type not in SCAN_TYPES:
            raise ValueError(f"Invalid scan type: {scan_type}")
        updates["scan_type"] = scan_type
    if target is not None:
        resolved_target = target.strip()
        if not resolved_target and current.asset_id:
            with get_db() as conn:
                asset = conn.execute(
                    "SELECT identifier FROM assets WHERE id = ?", (current.asset_id,)
                ).fetchone()
            resolved_target = str(asset["identifier"] or "").strip() if asset else ""
        if not resolved_target:
            raise ValueError("A schedule needs a target or an asset with an identifier")
        updates["target"] = resolved_target
    if options is not None:
        updates["options"] = _json_dumps(options)
    if cron_expression is not None:
        updates["cron_expression"] = cron_expression.strip()
        updates["next_run"] = _next_run(cron_expression)
    if notify_email is not None:
        updates["notify_email"] = notify_email.strip()
    if notify_webhook is not None:
        updates["notify_webhook"] = notify_webhook.strip()
    if enabled is not None:
        updates["enabled"] = 1 if enabled else 0
        updates["status"] = "active" if enabled else "paused"
        if enabled:
            updates["next_run"] = _next_run(
                updates.get("cron_expression", current.cron_expression)
            )

    if not updates:
        return current

    with transaction() as conn:
        set_sql = ", ".join(f"{key} = ?" for key in updates)
        conn.execute(
            f"UPDATE scan_schedules SET {set_sql}, updated_at = ? WHERE id = ?",
            (*updates.values(), utcnow(), schedule_id),
        )
    return get_schedule(schedule_id)


def delete_schedule(schedule_id: int) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM scan_schedules WHERE id = ?", (schedule_id,))
        conn.commit()


def get_due_schedules() -> List[dict[str, Any]]:
    """Return enabled schedules whose next_run has passed."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_schedules WHERE enabled = 1 AND status != 'failed' "
            "AND next_run != '' AND next_run <= ? ORDER BY next_run ASC",
            (utcnow(),),
        ).fetchall()
    return [dict(row) for row in rows]


def mark_schedule_failed(schedule_id: int, error: str) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE scan_schedules SET status = 'failed', error = ?, updated_at = ? "
            "WHERE id = ?",
            (error[:2000], utcnow(), schedule_id),
        )
        conn.commit()


def complete_scheduled_run(schedule_id: int, scan_id: int) -> None:
    """Record that a scheduled run was queued.

    Completion notification is handled separately by
    :func:`notify_scheduled_scan` from the scan worker, so this function only
    advances the schedule clock.
    """
    schedule = get_schedule(schedule_id)
    if not schedule:
        return
    with get_db() as conn:
        conn.execute(
            "UPDATE scan_schedules SET last_run = ?, status = 'active', "
            "next_run = ?, updated_at = ? WHERE id = ?",
            (utcnow(), _next_run(schedule.cron_expression), utcnow(), schedule_id),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


def _smtp_password() -> str:
    value = get_setting("smtp_password", "")
    if not value:
        return ""
    try:
        from .credentials import decrypt_secret

        return decrypt_secret(value)
    except Exception:
        # Older installations stored this value in plaintext. Keep working
        # until the operator re-saves it through Settings.
        return value


def send_notification(
    schedule: ScanSchedule,
    scan_id: int,
    status: str,
    message: str,
    notify_email: str | None = None,
    notify_webhook: str | None = None,
) -> None:
    """Send email/webhook notifications for a scheduled scan."""
    email = notify_email if notify_email is not None else schedule.notify_email
    webhook = notify_webhook if notify_webhook is not None else schedule.notify_webhook
    email = email or get_setting("notify_email_default", "")
    webhook = webhook or get_setting("notify_webhook_default", "")
    if not email and not webhook:
        return

    body = (
        f"Scheduled scan {scan_id} for {schedule.target} finished with status: {status}\n\n"
        f"{message}"
    )
    if email:
        try:
            smtp_host = get_setting("smtp_host", "")
            smtp_port = int(get_setting("smtp_port", "587"))
            smtp_user = get_setting("smtp_user", "")
            smtp_pass = _smtp_password()
            from_addr = get_setting("smtp_from", smtp_user or "vulnscanner@localhost")

            if smtp_host and smtp_user and smtp_pass:
                msg = MIMEText(body, "plain", "utf-8")
                msg["Subject"] = (
                    f"VulnScanner: Scan {schedule.scan_type} {schedule.target} - {status}"
                )
                msg["From"] = from_addr
                msg["To"] = email
                if smtp_port == 465:
                    client = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10)
                else:
                    client = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
                with client as smtp:
                    if smtp_port != 465:
                        smtp.starttls()
                    smtp.login(smtp_user, smtp_pass)
                    smtp.sendmail(from_addr, [email], msg.as_string())
        except Exception as exc:
            logger.error("Email notification failed: %s", exc)

    if webhook:
        try:
            httpx.post(
                webhook,
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


def notify_scheduled_scan(scan_id: int, schedule_id: int, status: str, message: str) -> None:
    schedule = get_schedule(schedule_id)
    if not schedule:
        return
    send_notification(schedule, scan_id, status, message)


def _next_run_offset() -> str:
    """Backward-compatible helper used by older callers/tests."""
    return _next_run("")
