from __future__ import annotations

import json
import sqlite3
import threading
import hashlib
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from app.config import BACKUP_DIR, DB_PATH
from app.core.audit_chain import event_hash


SCHEMA_VERSION = 6
_DB_LOCK = threading.RLock()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connection(*, path: Path | None = None) -> Iterator[sqlite3.Connection]:
    db_path = path or DB_PATH
    with _DB_LOCK:
        conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    if not _table_exists(conn, table):
        return set()
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _add_column(conn: sqlite3.Connection, table: str, name: str, definition: str) -> None:
    if name not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def _create_core_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'reviewer',
            is_active INTEGER NOT NULL DEFAULT 1,
            failed_login_count INTEGER NOT NULL DEFAULT 0,
            first_failed_login_at TEXT,
            locked_until TEXT,
            password_changed_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS repositories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            source_type TEXT NOT NULL,
            source TEXT NOT NULL,
            local_path TEXT NOT NULL,
            default_branch TEXT,
            detected_stack TEXT NOT NULL DEFAULT '[]',
            startup_candidates TEXT NOT NULL DEFAULT '[]',
            port_hints TEXT NOT NULL DEFAULT '[]',
            approved_command_hash TEXT,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repository_id INTEGER NOT NULL,
            profile TEXT NOT NULL,
            status TEXT NOT NULL,
            selected_tools TEXT NOT NULL,
            tool_status TEXT NOT NULL DEFAULT '{}',
            stages_json TEXT NOT NULL DEFAULT '{}',
            coverage_json TEXT NOT NULL DEFAULT '{}',
            api_url TEXT,
            openapi_path TEXT,
            startup_command TEXT,
            auth_profile_id INTEGER,
            progress INTEGER NOT NULL DEFAULT 0,
            summary TEXT NOT NULL DEFAULT '{}',
            log_path TEXT,
            error TEXT,
            cancellation_requested INTEGER NOT NULL DEFAULT 0,
            created_by INTEGER,
            started_at TEXT,
            completed_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(repository_id) REFERENCES repositories(id) ON DELETE CASCADE,
            FOREIGN KEY(auth_profile_id) REFERENCES api_auth_profiles(id) ON DELETE SET NULL,
            FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            repository_id INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL DEFAULT 'medium',
            tool TEXT NOT NULL,
            category TEXT,
            cwe TEXT,
            owasp TEXT,
            file_path TEXT,
            line_start INTEGER,
            line_end INTEGER,
            function_name TEXT,
            endpoint TEXT,
            evidence TEXT,
            remediation TEXT,
            references_json TEXT NOT NULL DEFAULT '[]',
            raw_json TEXT NOT NULL DEFAULT '{}',
            review_status TEXT NOT NULL DEFAULT 'open',
            reviewer_notes TEXT NOT NULL DEFAULT '',
            assigned_reviewer_id INTEGER,
            first_seen_at TEXT,
            last_seen_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(scan_id, fingerprint),
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
            FOREIGN KEY(repository_id) REFERENCES repositories(id) ON DELETE CASCADE,
            FOREIGN KEY(assigned_reviewer_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            result TEXT NOT NULL,
            purpose TEXT,
            correlation_id TEXT,
            ip_address TEXT,
            user_agent TEXT,
            details TEXT NOT NULL DEFAULT '{}',
            previous_hash TEXT,
            event_hash TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repository_id INTEGER,
            finding_id INTEGER,
            user_id INTEGER,
            provider TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(repository_id) REFERENCES repositories(id) ON DELETE CASCADE,
            FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE SET NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            repository_id INTEGER NOT NULL,
            cadence TEXT NOT NULL CHECK(cadence IN ('daily', 'weekly')),
            hour INTEGER NOT NULL,
            minute INTEGER NOT NULL,
            day_of_week INTEGER,
            profile TEXT NOT NULL,
            selected_tools TEXT NOT NULL,
            api_url TEXT,
            openapi_path TEXT,
            auth_profile_id INTEGER,
            enabled INTEGER NOT NULL DEFAULT 1,
            next_run TEXT NOT NULL,
            last_run TEXT,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(repository_id) REFERENCES repositories(id) ON DELETE CASCADE,
            FOREIGN KEY(auth_profile_id) REFERENCES api_auth_profiles(id) ON DELETE SET NULL,
            FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
        );
        """
    )


def _migrate_legacy_tables(conn: sqlite3.Connection) -> None:
    # Existing v0.1.1 tables are expanded in place. Sessions are invalidated because
    # v1 stores only hashes and maintains separate idle/absolute expiration.
    if _table_exists(conn, "users"):
        for name, definition in (
            ("is_active", "INTEGER NOT NULL DEFAULT 1"),
            ("failed_login_count", "INTEGER NOT NULL DEFAULT 0"),
            ("first_failed_login_at", "TEXT"),
            ("locked_until", "TEXT"),
            ("password_changed_at", "TEXT"),
            ("updated_at", "TEXT"),
        ):
            _add_column(conn, "users", name, definition)
        conn.execute("UPDATE users SET updated_at=COALESCE(updated_at, created_at), password_changed_at=COALESCE(password_changed_at, created_at)")

    if _table_exists(conn, "sessions") and "token_hash" not in _columns(conn, "sessions"):
        conn.execute("ALTER TABLE sessions RENAME TO sessions_v011_legacy")

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            idle_expires_at TEXT NOT NULL,
            absolute_expires_at TEXT NOT NULL,
            revoked_at TEXT,
            client_instance_id TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        DROP TABLE IF EXISTS sessions_v011_legacy;
        """
    )

    for table, additions in {
        "repositories": (
            ("approved_command_hash", "TEXT"),
            ("created_by", "INTEGER"),
        ),
        "scans": (
            ("stages_json", "TEXT NOT NULL DEFAULT '{}'"),
            ("coverage_json", "TEXT NOT NULL DEFAULT '{}'"),
            ("auth_profile_id", "INTEGER"),
            ("cancellation_requested", "INTEGER NOT NULL DEFAULT 0"),
            ("created_by", "INTEGER"),
        ),
        "findings": (
            ("confidence", "TEXT NOT NULL DEFAULT 'medium'"),
            ("function_name", "TEXT"),
            ("endpoint", "TEXT"),
            ("assigned_reviewer_id", "INTEGER"),
            ("first_seen_at", "TEXT"),
            ("last_seen_at", "TEXT"),
        ),
        "audit_logs": (
            ("purpose", "TEXT"),
            ("correlation_id", "TEXT"),
            ("previous_hash", "TEXT"),
            ("event_hash", "TEXT"),
        ),
        "schedules": (
            ("auth_profile_id", "INTEGER"),
            ("created_by", "INTEGER"),
        ),
    }.items():
        if _table_exists(conn, table):
            for name, definition in additions:
                _add_column(conn, table, name, definition)

    if _table_exists(conn, "findings"):
        conn.execute("UPDATE findings SET first_seen_at=COALESCE(first_seen_at, created_at), last_seen_at=COALESCE(last_seen_at, updated_at)")


def _create_security_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL,
            system_role INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id INTEGER NOT NULL,
            permission_id INTEGER NOT NULL,
            PRIMARY KEY(role_id, permission_id),
            FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
            FOREIGN KEY(permission_id) REFERENCES permissions(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS user_roles (
            user_id INTEGER NOT NULL,
            role_id INTEGER NOT NULL,
            PRIMARY KEY(user_id, role_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS project_memberships (
            repository_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(repository_id, user_id),
            FOREIGN KEY(repository_id) REFERENCES repositories(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE RESTRICT
        );

        CREATE TABLE IF NOT EXISTS api_auth_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repository_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            auth_type TEXT NOT NULL CHECK(auth_type IN ('bearer','api_key_header','api_key_query','basic','oauth_client_credentials','cookie')),
            config_json TEXT NOT NULL DEFAULT '{}',
            secret_ref TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            verified INTEGER NOT NULL DEFAULT 0,
            verification_url TEXT,
            verified_identity TEXT,
            last_verified_at TEXT,
            last_error TEXT,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(repository_id, name),
            FOREIGN KEY(repository_id) REFERENCES repositories(id) ON DELETE CASCADE,
            FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL UNIQUE,
            reason TEXT NOT NULL,
            status TEXT NOT NULL,
            size_bytes INTEGER,
            checksum_sha256 TEXT,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
        );
        """
    )


def _seed_rbac(conn: sqlite3.Connection) -> None:
    permissions = {
        "users.manage": "Create, disable and assign local users",
        "settings.manage": "Change application security and provider settings",
        "projects.create": "Register repositories",
        "projects.read": "View permitted repositories",
        "projects.update": "Redetect and edit permitted repositories",
        "projects.delete": "Delete permitted repositories",
        "projects.start": "Approve and execute repository startup commands",
        "scans.create": "Create scans",
        "scans.cancel": "Cancel scans",
        "scans.read": "View scans and logs",
        "findings.read": "View findings",
        "findings.comment": "Add reviewer notes",
        "findings.change_status": "Change ordinary finding workflow state",
        "findings.accept_risk": "Accept security risk",
        "fixes.generate": "Generate fix proposals",
        "fixes.apply": "Apply approved patches",
        "fixes.rollback": "Roll back applied patches",
        "reports.generate": "Generate and export reports",
        "audit.read": "View and export audit records",
        "auth_profiles.manage": "Create and change authenticated API profiles",
        "auth_profiles.use": "Use authenticated API profiles in scans",
        "backups.manage": "Create and restore database backups",
    }
    for code, description in permissions.items():
        conn.execute(
            "INSERT INTO permissions(code, description) VALUES(?,?) ON CONFLICT(code) DO UPDATE SET description=excluded.description",
            (code, description),
        )

    roles = {
        "owner": "Full local application owner",
        "security_engineer": "Runs scans, triages findings and prepares remediation",
        "reviewer": "Reviews evidence and ordinary finding states",
        "auditor": "Read-only evidence, reports and audit access",
        "viewer": "Read-only dashboard and project access",
    }
    for name, description in roles.items():
        conn.execute(
            "INSERT INTO roles(name, description, system_role) VALUES(?,?,1) ON CONFLICT(name) DO UPDATE SET description=excluded.description",
            (name, description),
        )

    role_permissions = {
        "owner": set(permissions),
        "security_engineer": {
            "projects.create", "projects.read", "projects.update", "projects.start",
            "scans.create", "scans.cancel", "scans.read",
            "findings.read", "findings.comment", "findings.change_status", "findings.accept_risk",
            "fixes.generate", "fixes.apply", "fixes.rollback",
            "reports.generate", "auth_profiles.manage", "auth_profiles.use", "backups.manage",
        },
        "reviewer": {
            "projects.read", "scans.read", "findings.read", "findings.comment",
            "findings.change_status", "reports.generate", "auth_profiles.use",
        },
        "auditor": {"projects.read", "scans.read", "findings.read", "reports.generate", "audit.read"},
        "viewer": {"projects.read", "scans.read", "findings.read"},
    }
    conn.execute("DELETE FROM role_permissions")
    for role_name, codes in role_permissions.items():
        role_id = conn.execute("SELECT id FROM roles WHERE name=?", (role_name,)).fetchone()["id"]
        for code in codes:
            permission_id = conn.execute("SELECT id FROM permissions WHERE code=?", (code,)).fetchone()["id"]
            conn.execute(
                "INSERT OR IGNORE INTO role_permissions(role_id, permission_id) VALUES(?,?)",
                (role_id, permission_id),
            )

    # Map v0.1.1 users into the new model without deleting the legacy role column.
    users = conn.execute("SELECT id, role FROM users").fetchall()
    known_roles = set(roles)
    for user in users:
        legacy_role = str(user["role"] or "reviewer")
        if legacy_role in known_roles:
            new_role = legacy_role
        else:
            new_role = "owner" if legacy_role == "admin" else "reviewer"
        role_id = conn.execute("SELECT id FROM roles WHERE name=?", (new_role,)).fetchone()["id"]
        conn.execute("INSERT OR IGNORE INTO user_roles(user_id, role_id) VALUES(?,?)", (user["id"], role_id))


def _file_checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _current_user_version() -> int:
    if not DB_PATH.exists() or DB_PATH.stat().st_size == 0:
        return 0
    try:
        with sqlite3.connect(DB_PATH) as conn:
            return int(conn.execute("PRAGMA user_version").fetchone()[0])
    except sqlite3.DatabaseError:
        return 0


def _pre_migration_backup(existing_version: int) -> dict[str, Any] | None:
    if not DB_PATH.exists() or DB_PATH.stat().st_size == 0 or existing_version >= SCHEMA_VERSION:
        return None
    stamp = utc_now().replace(":", "-").replace("+", "_")
    destination = BACKUP_DIR / f"pre-migration-v{existing_version}-to-v{SCHEMA_VERSION}-{stamp}.db"
    source = sqlite3.connect(DB_PATH)
    target = sqlite3.connect(destination)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    return {
        "path": str(destination),
        "reason": f"pre-migration-v{existing_version}-to-v{SCHEMA_VERSION}",
        "size_bytes": destination.stat().st_size,
        "checksum_sha256": _file_checksum(destination),
        "created_at": utc_now(),
    }


def _rebuild_audit_chain(conn: sqlite3.Connection) -> None:
    if not _table_exists(conn, "audit_logs"):
        return
    rows = conn.execute("SELECT * FROM audit_logs ORDER BY id ASC").fetchall()
    previous = "GENESIS"
    for row in rows:
        event = {
            "timestamp": row["timestamp"],
            "user_id": row["user_id"],
            "username": row["username"],
            "action": row["action"],
            "resource_type": row["resource_type"],
            "resource_id": row["resource_id"],
            "result": row["result"],
            "purpose": row["purpose"],
            "correlation_id": row["correlation_id"],
            "ip_address": row["ip_address"],
            "user_agent": row["user_agent"],
            "details": json_load(row["details"], {}),
        }
        digest = event_hash(event, previous)
        conn.execute(
            "UPDATE audit_logs SET previous_hash=?, event_hash=? WHERE id=?",
            (previous, digest, row["id"]),
        )
        previous = digest


def _create_indexes(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, revoked_at);
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(review_status);
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit_logs(correlation_id);
        CREATE INDEX IF NOT EXISTS idx_schedules_next_run ON schedules(enabled, next_run);
        CREATE INDEX IF NOT EXISTS idx_membership_user ON project_memberships(user_id, repository_id);
        CREATE INDEX IF NOT EXISTS idx_auth_profiles_repo ON api_auth_profiles(repository_id, enabled);
        """
    )


def init_db() -> None:
    existing_version = _current_user_version()
    migration_backup = _pre_migration_backup(existing_version)
    with connection() as conn:
        # Create original/core tables first so old databases can be expanded safely.
        _create_core_tables(conn)
        _migrate_legacy_tables(conn)
        _create_security_tables(conn)
        _seed_rbac(conn)
        _create_indexes(conn)
        if existing_version < 6:
            _rebuild_audit_chain(conn)
        if migration_backup:
            conn.execute(
                """
                INSERT OR IGNORE INTO backups(path, reason, status, size_bytes, checksum_sha256, created_at)
                VALUES(?,?,'completed',?,?,?)
                """,
                (
                    migration_backup["path"], migration_backup["reason"],
                    migration_backup["size_bytes"], migration_backup["checksum_sha256"],
                    migration_backup["created_at"],
                ),
            )
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")


def integrity_check() -> tuple[bool, str]:
    if not DB_PATH.exists():
        return True, "Database will be created on first run."
    try:
        with connection() as conn:
            result = conn.execute("PRAGMA integrity_check").fetchone()[0]
        return result == "ok", str(result)
    except sqlite3.DatabaseError as exc:
        return False, str(exc)


def schema_version() -> int:
    with connection() as conn:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def json_load(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


def json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
