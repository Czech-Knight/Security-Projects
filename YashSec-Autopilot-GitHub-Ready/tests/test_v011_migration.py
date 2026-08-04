from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app import db
from app.core import security


V011_MINIMAL_SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'reviewer')),
    created_at TEXT NOT NULL
);
CREATE TABLE sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    user_id INTEGER,
    username TEXT,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    result TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT NOT NULL DEFAULT '{}'
);
"""


def test_v011_database_migrates_in_place_with_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "yashsec.db"
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    now = db.utc_now()

    with sqlite3.connect(database) as conn:
        conn.executescript(V011_MINIMAL_SCHEMA)
        conn.execute(
            "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
            ("legacy-admin", security.hash_password("Legacy-Owner-Password-42"), "admin", now),
        )
        conn.execute(
            "INSERT INTO sessions(token,user_id,expires_at,created_at) VALUES('legacy-raw-token',1,?,?)",
            (now, now),
        )
        conn.execute(
            """
            INSERT INTO audit_logs(
                timestamp,user_id,username,action,resource_type,resource_id,
                result,ip_address,user_agent,details
            ) VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (now, 1, "legacy-admin", "legacy_login", "session", "1", "success", "127.0.0.1", "legacy-agent", "{}"),
        )
        conn.execute("PRAGMA user_version=0")

    monkeypatch.setattr(db, "DB_PATH", database)
    monkeypatch.setattr(db, "BACKUP_DIR", backup_dir)
    db.init_db()

    with db.connection() as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
        user = conn.execute("SELECT * FROM users WHERE username='legacy-admin'").fetchone()
        role = conn.execute(
            """
            SELECT r.name FROM roles r
            JOIN user_roles ur ON ur.role_id=r.id
            WHERE ur.user_id=?
            """,
            (user["id"],),
        ).fetchone()[0]
        assert role == "owner"
        assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        audit = conn.execute("SELECT previous_hash,event_hash,user_agent FROM audit_logs").fetchone()
        assert audit["previous_hash"] == "GENESIS"
        assert len(audit["event_hash"]) == 64
        assert audit["user_agent"] == "legacy-agent"
        recorded_backup = conn.execute("SELECT path,status FROM backups").fetchone()
        assert recorded_backup["status"] == "completed"
        assert Path(recorded_backup["path"]).exists()

    assert len(list(backup_dir.glob("pre-migration-v0-to-v6-*.db"))) == 1
    assert security.verify_audit_chain()[0]
