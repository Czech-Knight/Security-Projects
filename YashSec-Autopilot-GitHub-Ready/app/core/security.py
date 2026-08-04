from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from fastapi import Depends, Header, HTTPException, Request, status

from app import db
from app.config import settings
from app.core.audit_chain import event_hash

try:  # Argon2id is preferred in installed builds.
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerifyMismatchError

    _ARGON2 = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2, hash_len=32, salt_len=16)
except ImportError:  # Development fallback; requirements.txt installs argon2-cffi.
    _ARGON2 = None
    InvalidHashError = VerifyMismatchError = ValueError  # type: ignore[assignment]


PBKDF2_ROUNDS = 600_000
SENSITIVE_KEYS = {"password", "token", "secret", "authorization", "cookie", "api_key", "client_secret"}
_STEP_UP: dict[str, tuple[int, datetime, str]] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    if _ARGON2 is not None:
        return _ARGON2.hash(password)
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    if encoded.startswith("$argon2") and _ARGON2 is not None:
        try:
            return bool(_ARGON2.verify(encoded, password))
        except (VerifyMismatchError, InvalidHashError):
            return False
    try:
        algorithm, rounds, salt_hex, digest_hex = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(rounds)
        )
        return hmac.compare_digest(candidate.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def _needs_rehash(encoded: str) -> bool:
    if _ARGON2 is None:
        return encoded.startswith("pbkdf2_sha256$") and int(encoded.split("$", 2)[1]) < PBKDF2_ROUNDS
    if not encoded.startswith("$argon2"):
        return True
    try:
        return _ARGON2.check_needs_rehash(encoded)
    except InvalidHashError:
        return True


def setup_required() -> bool:
    with db.connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


def initialize_owner(username: str, password: str) -> dict[str, Any]:
    if not setup_required():
        raise ValueError("Initial setup has already been completed.")
    now = db.utc_now()
    with db.connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO users(username, password_hash, role, is_active, failed_login_count,
                              password_changed_at, created_at, updated_at)
            VALUES(?,?,'admin',1,0,?,?,?)
            """,
            (username, hash_password(password), now, now, now),
        )
        role_id = conn.execute("SELECT id FROM roles WHERE name='owner'").fetchone()["id"]
        conn.execute("INSERT INTO user_roles(user_id, role_id) VALUES(?,?)", (cursor.lastrowid, role_id))
    return get_user(cursor.lastrowid) or {"id": cursor.lastrowid, "username": username}


def _user_access_payload(conn: Any, user_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT id, username, is_active, locked_until, created_at FROM users WHERE id=?",
        (user_id,),
    ).fetchone()
    if not row:
        return None
    roles = [r["name"] for r in conn.execute(
        "SELECT roles.name FROM roles JOIN user_roles ON user_roles.role_id=roles.id WHERE user_roles.user_id=? ORDER BY roles.name",
        (user_id,),
    ).fetchall()]
    permissions = [r["code"] for r in conn.execute(
        """
        SELECT DISTINCT permissions.code
        FROM permissions
        JOIN role_permissions ON role_permissions.permission_id=permissions.id
        JOIN user_roles ON user_roles.role_id=role_permissions.role_id
        WHERE user_roles.user_id=? ORDER BY permissions.code
        """,
        (user_id,),
    ).fetchall()]
    payload = dict(row)
    payload["roles"] = roles
    payload["permissions"] = permissions
    payload["role"] = "owner" if "owner" in roles else (roles[0] if roles else "viewer")
    return payload


def get_user(user_id: int) -> dict[str, Any] | None:
    with db.connection() as conn:
        return _user_access_payload(conn, user_id)


def authenticate(username: str, password: str) -> tuple[dict[str, Any] | None, str | None]:
    now = _now()
    with db.connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not row:
            return None, "invalid"
        if not row["is_active"]:
            return None, "disabled"
        locked_until = _parse_datetime(row["locked_until"])
        if locked_until and locked_until > now:
            return None, "locked"
        if verify_password(password, row["password_hash"]):
            replacement = hash_password(password) if _needs_rehash(row["password_hash"]) else row["password_hash"]
            conn.execute(
                """
                UPDATE users SET password_hash=?, failed_login_count=0, first_failed_login_at=NULL,
                                 locked_until=NULL, updated_at=? WHERE id=?
                """,
                (replacement, db.utc_now(), row["id"]),
            )
            return _user_access_payload(conn, row["id"]), None

        first_failed = _parse_datetime(row["first_failed_login_at"])
        window = timedelta(minutes=settings.login_window_minutes)
        failures = int(row["failed_login_count"] or 0)
        if first_failed is None or now - first_failed > window:
            failures = 1
            first_failed = now
        else:
            failures += 1
        lock_until: datetime | None = None
        if failures >= settings.login_max_failures:
            lock_until = now + timedelta(minutes=settings.lockout_minutes)
        conn.execute(
            """
            UPDATE users SET failed_login_count=?, first_failed_login_at=?, locked_until=?, updated_at=? WHERE id=?
            """,
            (failures, first_failed.isoformat(), lock_until.isoformat() if lock_until else None, db.utc_now(), row["id"]),
        )
        return None, "locked" if lock_until else "invalid"


def create_session(user_id: int, client_instance_id: str | None = None) -> str:
    token = secrets.token_urlsafe(48)
    now = _now()
    idle = now + timedelta(minutes=settings.session_idle_minutes)
    absolute = now + timedelta(hours=settings.session_absolute_hours)
    with db.connection() as conn:
        conn.execute(
            "DELETE FROM sessions WHERE absolute_expires_at < ? OR revoked_at IS NOT NULL",
            (now.isoformat(),),
        )
        conn.execute(
            """
            INSERT INTO sessions(token_hash, user_id, created_at, last_seen_at, idle_expires_at,
                                 absolute_expires_at, client_instance_id)
            VALUES(?,?,?,?,?,?,?)
            """,
            (_token_hash(token), user_id, now.isoformat(), now.isoformat(), idle.isoformat(), absolute.isoformat(), client_instance_id),
        )
    return token


def revoke_session(token: str) -> None:
    with db.connection() as conn:
        conn.execute("UPDATE sessions SET revoked_at=? WHERE token_hash=?", (db.utc_now(), _token_hash(token)))


def revoke_all_sessions(user_id: int) -> None:
    with db.connection() as conn:
        conn.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", (db.utc_now(), user_id))


def get_user_from_token(token: str) -> dict[str, Any] | None:
    now = _now()
    with db.connection() as conn:
        session = conn.execute(
            """
            SELECT * FROM sessions WHERE token_hash=? AND revoked_at IS NULL
            """,
            (_token_hash(token),),
        ).fetchone()
        if not session:
            return None
        idle = _parse_datetime(session["idle_expires_at"])
        absolute = _parse_datetime(session["absolute_expires_at"])
        if not idle or not absolute or idle <= now or absolute <= now:
            conn.execute("UPDATE sessions SET revoked_at=? WHERE token_hash=?", (now.isoformat(), session["token_hash"]))
            return None
        user = _user_access_payload(conn, session["user_id"])
        if not user or not user["is_active"]:
            return None
        next_idle = min(absolute, now + timedelta(minutes=settings.session_idle_minutes))
        conn.execute(
            "UPDATE sessions SET last_seen_at=?, idle_expires_at=? WHERE token_hash=?",
            (now.isoformat(), next_idle.isoformat(), session["token_hash"]),
        )
        user["session_absolute_expires_at"] = absolute.isoformat()
        return user


def bearer_token(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Login required")
    return authorization.split(" ", 1)[1].strip()


def current_user(token: str = Depends(bearer_token)) -> dict[str, Any]:
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid")
    return user


def has_permission(user: dict[str, Any], permission: str) -> bool:
    return permission in set(user.get("permissions") or [])


def require_permission(permission: str) -> Callable[..., dict[str, Any]]:
    def dependency(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
        if not has_permission(user, permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Permission required: {permission}")
        return user

    return dependency


def can_access_repository(user: dict[str, Any], repository_id: int, *, write: bool = False) -> bool:
    if "owner" in set(user.get("roles") or []):
        return True
    with db.connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM project_memberships WHERE repository_id=? AND user_id=?",
            (repository_id, user["id"]),
        ).fetchone()
    return row is not None


def require_repository_access(user: dict[str, Any], repository_id: int, *, write: bool = False) -> None:
    if not can_access_repository(user, repository_id, write=write):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have access to this project")


def create_step_up_grant(user_id: int, password: str, purpose: str) -> str:
    with db.connection() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE id=?", (user_id,)).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        raise ValueError("Password verification failed.")
    token = secrets.token_urlsafe(36)
    _STEP_UP[_token_hash(token)] = (user_id, _now() + timedelta(minutes=5), purpose)
    return token


def consume_step_up_grant(token: str, user_id: int, purpose: str) -> bool:
    key = _token_hash(token)
    grant = _STEP_UP.pop(key, None)
    return bool(grant and grant[0] == user_id and grant[1] > _now() and grant[2] == purpose)


def _redact(value: Any, key: str = "") -> Any:
    lowered = key.lower()
    if any(marker in lowered for marker in SENSITIVE_KEYS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str) and len(value) > 3000:
        return value[:3000] + "...[TRUNCATED]"
    return value


def audit(
    request: Request | None,
    user: dict[str, Any] | None,
    action: str,
    result: str,
    resource_type: str | None = None,
    resource_id: str | int | None = None,
    details: dict[str, Any] | None = None,
    *,
    purpose: str | None = None,
    correlation_id: str | None = None,
) -> str:
    timestamp = db.utc_now()
    correlation = correlation_id or secrets.token_hex(12)
    ip_address = request.client.host if request and request.client else None
    user_agent = request.headers.get("user-agent") if request else None
    safe_details = _redact(details or {})
    with db.connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        previous_row = conn.execute("SELECT event_hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
        previous_hash = previous_row["event_hash"] if previous_row and previous_row["event_hash"] else "GENESIS"
        event = {
            "timestamp": timestamp,
            "user_id": user.get("id") if user else None,
            "username": user.get("username") if user else None,
            "action": action,
            "resource_type": resource_type,
            "resource_id": str(resource_id) if resource_id is not None else None,
            "result": result,
            "purpose": purpose,
            "correlation_id": correlation,
            "ip_address": ip_address,
            "details": safe_details,
        }
        event["user_agent"] = user_agent
        digest = event_hash(event, previous_hash)
        conn.execute(
            """
            INSERT INTO audit_logs(timestamp, user_id, username, action, resource_type, resource_id,
                                   result, purpose, correlation_id, ip_address, user_agent, details,
                                   previous_hash, event_hash)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                timestamp, event["user_id"], event["username"], action, resource_type, event["resource_id"],
                result, purpose, correlation, ip_address, user_agent, db.json_dump(safe_details), previous_hash, digest,
            ),
        )
    return correlation


def verify_audit_chain() -> tuple[bool, str]:
    with db.connection() as conn:
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
            "details": db.json_load(row["details"], {}),
        }
        event["user_agent"] = row["user_agent"]
        expected = event_hash(event, previous)
        if row["previous_hash"] != previous or row["event_hash"] != expected:
            return False, f"Audit chain verification failed at event {row['id']}."
        previous = row["event_hash"]
    return True, f"Verified {len(rows)} audit event(s)."
