from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from app import db
from app.core import scan_engine
from app.core.security import audit


_started = False
_lock = threading.Lock()


def compute_next_run(cadence: str, hour: int, minute: int, day_of_week: int | None = None, after: datetime | None = None) -> str:
    now = after or datetime.now(timezone.utc)
    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if cadence == "daily":
        if candidate <= now:
            candidate += timedelta(days=1)
    else:
        target_day = 0 if day_of_week is None else day_of_week
        days = (target_day - now.weekday()) % 7
        candidate += timedelta(days=days)
        if candidate <= now:
            candidate += timedelta(days=7)
    return candidate.isoformat()


def create_due_scan(schedule: dict[str, Any]) -> int:
    now = db.utc_now()
    with db.connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans(repository_id, profile, status, selected_tools, tool_status, stages_json,
                              coverage_json, api_url, openapi_path, startup_command, auth_profile_id,
                              progress, summary, created_by, created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                schedule["repository_id"], schedule["profile"], "queued", schedule["selected_tools"],
                "{}", "{}", "{}", schedule["api_url"], schedule["openapi_path"], None,
                schedule.get("auth_profile_id"), 0, "{}", schedule.get("created_by"), now,
            ),
        )
        next_run = compute_next_run(
            schedule["cadence"], schedule["hour"], schedule["minute"], schedule["day_of_week"],
            datetime.now(timezone.utc) + timedelta(seconds=1),
        )
        conn.execute(
            "UPDATE schedules SET last_run=?, next_run=?, updated_at=? WHERE id=?",
            (now, next_run, now, schedule["id"]),
        )
    audit(None, None, "scheduled_scan_create", "success", "scan", cursor.lastrowid, {"schedule_id": schedule["id"]})
    scan_engine.submit_scan(cursor.lastrowid)
    return cursor.lastrowid


def tick() -> None:
    now = db.utc_now()
    with db.connection() as conn:
        rows = conn.execute(
            "SELECT * FROM schedules WHERE enabled=1 AND next_run <= ? ORDER BY next_run LIMIT 10", (now,)
        ).fetchall()
    for row in rows:
        create_due_scan(dict(row))


def _loop() -> None:
    while True:
        try:
            tick()
        except Exception:
            pass
        time.sleep(30)


def start_scheduler() -> None:
    global _started
    with _lock:
        if _started:
            return
        _started = True
        thread = threading.Thread(target=_loop, name="yashsec-scheduler", daemon=True)
        thread.start()
