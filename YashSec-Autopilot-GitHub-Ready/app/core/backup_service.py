from __future__ import annotations

import hashlib
import shutil
import sqlite3
from pathlib import Path

from app import db
from app.config import BACKUP_DIR, DB_PATH


def _checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_backup(reason: str, created_by: int | None = None) -> dict:
    if not DB_PATH.exists():
        db.init_db()
    stamp = db.utc_now().replace(":", "-").replace("+", "_")
    destination = BACKUP_DIR / f"yashsec-{stamp}.db"
    source = sqlite3.connect(DB_PATH)
    target = sqlite3.connect(destination)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    size = destination.stat().st_size
    checksum = _checksum(destination)
    with db.connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO backups(path, reason, status, size_bytes, checksum_sha256, created_by, created_at)
            VALUES(?,?,'completed',?,?,?,?)
            """,
            (str(destination), reason, size, checksum, created_by, db.utc_now()),
        )
    _apply_retention()
    return {
        "id": cursor.lastrowid,
        "path": str(destination),
        "reason": reason,
        "size_bytes": size,
        "checksum_sha256": checksum,
        "created_at": db.utc_now(),
    }


def _apply_retention(limit: int = 10) -> None:
    with db.connection() as conn:
        rows = conn.execute(
            "SELECT id, path, reason FROM backups WHERE status='completed' ORDER BY id DESC"
        ).fetchall()
        automatic = [row for row in rows if row["reason"] not in {"manual", "user-created"}]
        for row in automatic[limit:]:
            path = Path(row["path"])
            try:
                path.unlink(missing_ok=True)
            except OSError:
                continue
            conn.execute("UPDATE backups SET status='expired' WHERE id=?", (row["id"],))


def list_backups() -> list[dict]:
    with db.connection() as conn:
        rows = conn.execute("SELECT * FROM backups ORDER BY id DESC").fetchall()
    results = []
    for row in rows:
        item = dict(row)
        item["available"] = Path(item["path"]).exists()
        results.append(item)
    return results


def restore_backup(backup_id: int, restored_by: int | None = None) -> dict:
    with db.connection() as conn:
        row = conn.execute("SELECT * FROM backups WHERE id=?", (backup_id,)).fetchone()
    if not row:
        raise ValueError("Backup not found.")
    source = Path(row["path"])
    if not source.exists():
        raise ValueError("Backup file is no longer available.")
    if _checksum(source) != row["checksum_sha256"]:
        raise ValueError("Backup checksum verification failed.")
    create_backup("pre-restore", restored_by)
    temporary = DB_PATH.with_suffix(".restore.tmp")
    shutil.copy2(source, temporary)
    with sqlite3.connect(temporary) as conn:
        result = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if result != "ok":
            temporary.unlink(missing_ok=True)
            raise ValueError(f"Restored database failed integrity check: {result}")
    temporary.replace(DB_PATH)
    db.init_db()
    return {"restored": True, "backup_id": backup_id, "path": str(source)}
