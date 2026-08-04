from __future__ import annotations

import hmac
import json
import os
import secrets
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from app import __version__, db
from app.config import DATA_DIR, DB_PATH, REPORT_DIR, STATIC_DIR, settings
from app.core import ai_service, backup_service, demo_mode, process_manager, reports, scan_engine, scheduler, startup_detector, tool_registry
from app.core import auth_profiles as auth_profile_service
from app.core.process_manager import command_fingerprint
from app.core.repo_service import (
    clone_repository,
    extract_zip_repository,
    repository_name_from_path,
    validate_local_repository,
)
from app.core.security import (
    audit,
    authenticate,
    bearer_token,
    can_access_repository,
    consume_step_up_grant,
    create_session,
    create_step_up_grant,
    current_user,
    get_user,
    hash_password,
    has_permission,
    initialize_owner,
    require_permission,
    require_repository_access,
    revoke_session,
    setup_required,
    verify_audit_chain,
)
from app.core.target_policy import is_local_target, validate_dynamic_target


docs_url = "/api/docs" if settings.docs_enabled else None
app = FastAPI(title="YashSec Autopilot", version=__version__, docs_url=docs_url, redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


_DEMO_AI_LOCK = threading.Lock()
_DEMO_AI_REQUESTS: dict[str, list[float]] = {}
_DEMO_SESSION_LOCK = threading.Lock()
_DEMO_SESSION_REQUESTS: dict[str, list[float]] = {}


def _enforce_demo_ai_limit(request: Request) -> None:
    if not settings.demo_mode:
        return
    identity = request.client.host if request.client else "unknown"
    now = time.monotonic()
    cutoff = now - 3600
    with _DEMO_AI_LOCK:
        recent = [stamp for stamp in _DEMO_AI_REQUESTS.get(identity, []) if stamp >= cutoff]
        if len(recent) >= settings.demo_ai_requests_per_hour:
            raise HTTPException(status_code=429, detail="Public demo AI limit reached. Try again later or run YashSec locally.")
        recent.append(now)
        _DEMO_AI_REQUESTS[identity] = recent


def _enforce_demo_session_limit(request: Request) -> None:
    if not settings.demo_mode:
        return
    identity = request.client.host if request.client else "unknown"
    now = time.monotonic()
    cutoff = now - 3600
    with _DEMO_SESSION_LOCK:
        recent = [stamp for stamp in _DEMO_SESSION_REQUESTS.get(identity, []) if stamp >= cutoff]
        if len(recent) >= settings.demo_session_requests_per_hour:
            raise HTTPException(status_code=429, detail="Public demo session limit reached. Try again later.")
        recent.append(now)
        _DEMO_SESSION_REQUESTS[identity] = recent


# ----------------------------- Request models -----------------------------

class SetupRequest(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,50}$")
    password: str = Field(min_length=12, max_length=200)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=300)
    client_instance_id: str | None = Field(default=None, max_length=200)


class ReauthRequest(BaseModel):
    password: str = Field(min_length=1, max_length=300)
    purpose: str = Field(min_length=2, max_length=100)


class UserCreate(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,50}$")
    password: str = Field(min_length=12, max_length=200)
    role: Literal["owner", "security_engineer", "reviewer", "auditor", "viewer"] = "reviewer"


class UserRoleUpdate(BaseModel):
    roles: list[Literal["owner", "security_engineer", "reviewer", "auditor", "viewer"]]


class RepositoryCreate(BaseModel):
    source_type: Literal["local", "git"]
    source: str = Field(min_length=1, max_length=2000)
    name: str | None = Field(default=None, max_length=120)
    branch: str | None = Field(default=None, max_length=160)


class StartRequest(BaseModel):
    command: str = Field(min_length=1, max_length=1000)
    confirmed: bool
    environment: dict[str, str] = Field(default_factory=dict)


class ScanCreate(BaseModel):
    repository_id: int
    profile: Literal["quick", "standard", "full", "api", "custom"] = "standard"
    selected_tools: list[str] = Field(default_factory=lambda: ["builtin", "semgrep", "gitleaks", "trivy"])
    api_url: str | None = Field(default=None, max_length=1000)
    openapi_path: str | None = Field(default=None, max_length=1000)
    startup_command: str | None = Field(default=None, max_length=1000)
    confirm_startup: bool = False
    auth_profile_id: int | None = None
    confirm_remote_target: bool = False

    @field_validator("selected_tools")
    @classmethod
    def validate_tools(cls, values: list[str]) -> list[str]:
        allowed = {"builtin", "semgrep", "gitleaks", "trivy", "dynamic", "schemathesis", "zap"}
        cleaned = list(dict.fromkeys(value for value in values if value in allowed))
        return cleaned or ["builtin"]

    @field_validator("api_url")
    @classmethod
    def validate_api_url(cls, value: str | None) -> str | None:
        if value:
            validate_dynamic_target(value)
        return value


class FindingUpdate(BaseModel):
    review_status: Literal["open", "reviewed", "false_positive", "accepted_risk", "fixed"] | None = None
    reviewer_notes: str | None = Field(default=None, max_length=10_000)


class ChatRequest(BaseModel):
    repository_id: int
    question: str = Field(min_length=2, max_length=8000)
    finding_id: int | None = None
    provider: Literal["ollama", "airllm"] | None = None


class ScheduleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    repository_id: int
    cadence: Literal["daily", "weekly"] = "daily"
    hour: int = Field(ge=0, le=23)
    minute: int = Field(ge=0, le=59)
    day_of_week: int | None = Field(default=None, ge=0, le=6)
    profile: Literal["quick", "standard", "full", "api", "custom"] = "standard"
    selected_tools: list[str] = Field(default_factory=lambda: ["builtin", "semgrep", "gitleaks", "trivy"])
    api_url: str | None = Field(default=None, max_length=1000)
    openapi_path: str | None = Field(default=None, max_length=1000)
    auth_profile_id: int | None = None


class ScheduleUpdate(BaseModel):
    enabled: bool


class AISettingsUpdate(BaseModel):
    ai_provider: Literal["ollama", "airllm"] | None = None
    ollama_url: str | None = Field(default=None, max_length=1000)
    ollama_model: str | None = Field(default=None, max_length=300)
    airllm_url: str | None = Field(default=None, max_length=1000)


class AuthProfileCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    auth_type: Literal["bearer", "api_key_header", "api_key_query", "basic", "oauth_client_credentials", "cookie"]
    config: dict[str, Any] = Field(default_factory=dict)
    secret: dict[str, Any] = Field(default_factory=dict)


class AuthProfileSecretUpdate(BaseModel):
    secret: dict[str, Any]


class AuthProfileTest(BaseModel):
    base_url: str = Field(min_length=8, max_length=1000)
    verification_url: str | None = Field(default=None, max_length=1000)
    confirm_remote_target: bool = False


class BackupCreate(BaseModel):
    reason: str = Field(default="manual", min_length=2, max_length=160)


# ----------------------------- Security middleware -----------------------------

@app.middleware("http")
async def security_boundary(request: Request, call_next):
    length = request.headers.get("content-length")
    if length:
        try:
            request_bytes = int(length)
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header."})
        if request_bytes < 0:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header."})
        if request_bytes > settings.max_request_bytes and not request.url.path.endswith("/import-zip"):
            return JSONResponse(status_code=413, content={"detail": "Request body exceeds the configured limit."})
    if request.url.path.startswith("/api/") and settings.require_transport_token:
        supplied = request.headers.get("x-yashsec-transport", "")
        if not hmac.compare_digest(supplied, settings.transport_token):
            return JSONResponse(status_code=401, content={"detail": "Desktop transport authentication failed."})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self' http://127.0.0.1:* http://localhost:*; frame-ancestors 'none'"
    )
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "no-cache"
    return response


@app.on_event("startup")
def startup() -> None:
    db.init_db()
    if settings.demo_mode:
        demo_mode.seed_demo_workspace()
    else:
        scheduler.start_scheduler()
    ok, message = verify_audit_chain()
    app.state.audit_chain = {"valid": ok, "message": message}


@app.on_event("shutdown")
def shutdown() -> None:
    process_manager.stop_all_processes()


# ----------------------------- Decode / access helpers -----------------------------

def _decode_repository(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["detected_stack"] = db.json_load(result.get("detected_stack"), [])
    result["startup_candidates"] = db.json_load(result.get("startup_candidates"), [])
    result["port_hints"] = db.json_load(result.get("port_hints"), [])
    return result


def _decode_scan(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["selected_tools"] = db.json_load(result.get("selected_tools"), [])
    result["tool_status"] = db.json_load(result.get("tool_status"), {})
    result["stages"] = db.json_load(result.pop("stages_json", "{}"), {})
    result["coverage"] = db.json_load(result.pop("coverage_json", "{}"), {})
    result["summary"] = db.json_load(result.get("summary"), {})
    return result


def _decode_finding(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["references"] = db.json_load(result.pop("references_json", "[]"), [])
    result["raw"] = db.json_load(result.pop("raw_json", "{}"), {})
    return result


def _get_repository(repository_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    with db.connection() as conn:
        row = conn.execute("SELECT * FROM repositories WHERE id=?", (repository_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Repository not found")
    if user:
        require_repository_access(user, repository_id)
    return _decode_repository(dict(row))


def _get_scan(scan_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    with db.connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    result = _decode_scan(dict(row))
    if user:
        require_repository_access(user, result["repository_id"])
    return result


def _get_finding(finding_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    with db.connection() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    result = _decode_finding(dict(row))
    if user:
        require_repository_access(user, result["repository_id"])
    return result


def _detect_openapi(repo_path: Path) -> str | None:
    for candidate in (
        "openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.yml", "swagger.json",
        "docs/openapi.yaml", "docs/openapi.yml", "docs/openapi.json",
    ):
        if (repo_path / candidate).exists():
            return candidate
    return None


def _grant_project_creator(repository_id: int, user: dict[str, Any]) -> None:
    with db.connection() as conn:
        role_name = "owner" if "owner" in set(user.get("roles") or []) else "security_engineer"
        role_id = conn.execute("SELECT id FROM roles WHERE name=?", (role_name,)).fetchone()["id"]
        conn.execute(
            "INSERT OR REPLACE INTO project_memberships(repository_id, user_id, role_id, created_at) VALUES(?,?,?,?)",
            (repository_id, user["id"], role_id, db.utc_now()),
        )


def _visible_repository_clause(user: dict[str, Any], alias: str = "repositories") -> tuple[str, list[Any]]:
    if "owner" in set(user.get("roles") or []):
        return "", []
    return f"{alias}.id IN (SELECT repository_id FROM project_memberships WHERE user_id=?)", [user["id"]]


# ----------------------------- Shell and setup -----------------------------

@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/favicon.ico")
def favicon() -> FileResponse:
    return FileResponse(STATIC_DIR / "logo.svg", media_type="image/svg+xml")


@app.get("/api/health")
def health() -> dict[str, Any]:
    integrity_ok, integrity_message = db.integrity_check()
    return {
        "status": "ok" if integrity_ok else "degraded",
        "name": settings.app_name,
        "version": __version__,
        "bind": f"{settings.host}:{settings.port}",
        "transport_protected": settings.require_transport_token,
        "setup_required": setup_required(),
        "demo_mode": settings.demo_mode,
        "database": {"healthy": integrity_ok, "message": integrity_message, "schema_version": db.schema_version()},
        "audit_chain": getattr(app.state, "audit_chain", {"valid": True, "message": "Not checked"}),
    }


@app.get("/api/setup/status")
def setup_status() -> dict[str, Any]:
    integrity_ok, integrity_message = db.integrity_check()
    return {
        "required": setup_required(),
        "demo_mode": settings.demo_mode,
        "version": __version__,
        "data_directory": str(DATA_DIR),
        "database_path": str(DB_PATH),
        "database_healthy": integrity_ok,
        "database_message": integrity_message,
        "privacy": (
            "Public read-only portfolio demo. AI prompts may use the configured Ollama Cloud endpoint; never paste secrets."
            if settings.demo_mode
            else "Local-first. External AI transfer is disabled unless explicitly configured and approved."
        ),
    }


@app.post("/api/setup/initialize")
def setup_initialize(payload: SetupRequest, request: Request) -> dict[str, Any]:
    if settings.demo_mode:
        raise HTTPException(status_code=403, detail="First-run setup is disabled in public demo mode.")
    try:
        user = initialize_owner(payload.username, payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    token = create_session(user["id"], "first-run")
    audit(request, user, "setup_initialize", "success", "application", purpose="Create first local owner")
    return {"token": token, "user": user}


@app.post("/api/demo/session")
def create_demo_session(request: Request) -> dict[str, Any]:
    if not settings.demo_mode:
        raise HTTPException(status_code=404, detail="Demo mode is not enabled.")
    _enforce_demo_session_limit(request)
    with db.connection() as conn:
        row = conn.execute("SELECT id FROM users WHERE username=? AND is_active=1", (demo_mode.DEMO_USERNAME,)).fetchone()
    if not row:
        raise HTTPException(status_code=503, detail="Demo workspace is not ready.")
    user = get_user(int(row["id"]))
    if not user:
        raise HTTPException(status_code=503, detail="Demo user is unavailable.")
    token = create_session(user["id"], "public-demo")
    with db.connection() as conn:
        conn.execute(
            "DELETE FROM sessions WHERE user_id=? AND client_instance_id='public-demo' AND token_hash NOT IN "
            "(SELECT token_hash FROM sessions WHERE user_id=? AND client_instance_id='public-demo' ORDER BY created_at DESC LIMIT 200)",
            (user["id"], user["id"]),
        )
    audit(request, user, "demo_session", "success", "session", purpose="Read-only portfolio demonstration")
    return {"token": token, "user": user, "demo_mode": True}


# ----------------------------- Authentication and RBAC -----------------------------

@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request) -> dict[str, Any]:
    if setup_required():
        raise HTTPException(status_code=409, detail="Complete first-run setup before signing in.")
    user, reason = authenticate(payload.username, payload.password)
    if not user:
        audit(request, None, "login", reason or "failure", "session", details={"username": payload.username})
        detail = "Account is temporarily locked. Try again later." if reason == "locked" else "Invalid username or password"
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)
    token = create_session(user["id"], payload.client_instance_id)
    audit(request, user, "login", "success", "session")
    return {"token": token, "user": user}


@app.post("/api/auth/logout")
def logout(request: Request, token: str = Depends(bearer_token), user: dict[str, Any] = Depends(current_user)) -> dict[str, bool]:
    revoke_session(token)
    audit(request, user, "logout", "success", "session")
    return {"logged_out": True}


@app.post("/api/auth/reauth")
def reauthenticate(payload: ReauthRequest, request: Request, user: dict[str, Any] = Depends(current_user)) -> dict[str, str]:
    try:
        grant = create_step_up_grant(user["id"], payload.password, payload.purpose)
    except ValueError as exc:
        audit(request, user, "reauth", "failure", "session", purpose=payload.purpose)
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    audit(request, user, "reauth", "success", "session", purpose=payload.purpose)
    return {"step_up_token": grant, "purpose": payload.purpose, "expires_in_seconds": "300"}


@app.get("/api/auth/me")
def me(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return user


@app.get("/api/roles")
def roles_list(user: dict[str, Any] = Depends(require_permission("users.manage"))) -> list[dict[str, Any]]:
    with db.connection() as conn:
        rows = conn.execute("SELECT * FROM roles ORDER BY id").fetchall()
    return [dict(row) for row in rows]


@app.get("/api/users")
def users_list(user: dict[str, Any] = Depends(require_permission("users.manage"))) -> list[dict[str, Any]]:
    with db.connection() as conn:
        rows = conn.execute("SELECT id FROM users ORDER BY username").fetchall()
    return [get_user(row["id"]) for row in rows if get_user(row["id"])]


@app.post("/api/users")
def create_user(payload: UserCreate, request: Request, user: dict[str, Any] = Depends(require_permission("users.manage"))) -> dict[str, Any]:
    now = db.utc_now()
    legacy_role = "admin" if payload.role == "owner" else "reviewer"
    try:
        with db.connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO users(username, password_hash, role, is_active, password_changed_at, created_at, updated_at)
                VALUES(?,?,?,1,?,?,?)
                """,
                (payload.username, hash_password(payload.password), legacy_role, now, now, now),
            )
            role_id = conn.execute("SELECT id FROM roles WHERE name=?", (payload.role,)).fetchone()["id"]
            conn.execute("INSERT INTO user_roles(user_id, role_id) VALUES(?,?)", (cursor.lastrowid, role_id))
    except Exception as exc:
        audit(request, user, "user_create", "failure", "user", details={"username": payload.username})
        raise HTTPException(status_code=409, detail="Username already exists") from exc
    created = get_user(cursor.lastrowid)
    audit(request, user, "user_create", "success", "user", cursor.lastrowid, {"role": payload.role})
    return created or {"id": cursor.lastrowid, "username": payload.username}


@app.patch("/api/users/{user_id}/roles")
def update_user_roles(user_id: int, payload: UserRoleUpdate, request: Request, user: dict[str, Any] = Depends(require_permission("users.manage"))) -> dict[str, Any]:
    if not payload.roles:
        raise HTTPException(status_code=400, detail="At least one role is required")
    with db.connection() as conn:
        if not conn.execute("SELECT 1 FROM users WHERE id=?", (user_id,)).fetchone():
            raise HTTPException(status_code=404, detail="User not found")
        conn.execute("DELETE FROM user_roles WHERE user_id=?", (user_id,))
        for role in set(payload.roles):
            role_id = conn.execute("SELECT id FROM roles WHERE name=?", (role,)).fetchone()["id"]
            conn.execute("INSERT INTO user_roles(user_id, role_id) VALUES(?,?)", (user_id, role_id))
        conn.execute("UPDATE sessions SET revoked_at=? WHERE user_id=?", (db.utc_now(), user_id))
    audit(request, user, "user_roles_update", "success", "user", user_id, {"roles": payload.roles})
    return get_user(user_id) or {}


# ----------------------------- Tools and repositories -----------------------------

@app.get("/api/tools")
def tools(refresh: bool = False, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    if settings.demo_mode:
        refresh = False
    # Login and dashboard use the fast presence-only path. Full version/health
    # checks happen only when the user explicitly opens or refreshes Tool Manager.
    return {
        "tools": tool_registry.inspect_all_tools(force=refresh),
        "ai": ai_service.provider_health(refresh=refresh),
    }


@app.post("/api/system/pick-folder")
def pick_folder(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        selected = filedialog.askdirectory(title="Select a repository folder")
        root.destroy()
        return {"path": selected or None}
    except Exception as exc:
        raise HTTPException(status_code=501, detail=f"Native picker unavailable; paste the path manually. ({exc})") from exc


@app.post("/api/repositories")
def add_repository(payload: RepositoryCreate, request: Request, user: dict[str, Any] = Depends(require_permission("projects.create"))) -> dict[str, Any]:
    try:
        if payload.source_type == "local":
            path = validate_local_repository(payload.source)
            name = payload.name or repository_name_from_path(path)
        else:
            path = clone_repository(payload.source, payload.name, payload.branch)
            name = payload.name or repository_name_from_path(path)
        detection = startup_detector.detect_repository(path)
        now = db.utc_now()
        with db.connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO repositories(name, source_type, source, local_path, default_branch,
                                         detected_stack, startup_candidates, port_hints, created_by, created_at, updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    name, payload.source_type, payload.source, str(path), payload.branch,
                    db.json_dump(detection["stacks"]), db.json_dump(detection["startup_candidates"]),
                    db.json_dump(detection["port_hints"]), user["id"], now, now,
                ),
            )
        _grant_project_creator(cursor.lastrowid, user)
        audit(request, user, "repository_add", "success", "repository", cursor.lastrowid, {"source_type": payload.source_type})
        return _get_repository(cursor.lastrowid, user)
    except (ValueError, RuntimeError) as exc:
        audit(request, user, "repository_add", "failure", "repository", details={"error": str(exc)})
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/repositories/import-zip")
async def import_zip_repository(
    request: Request,
    archive: UploadFile = File(...),
    name: str | None = Form(default=None),
    user: dict[str, Any] = Depends(require_permission("projects.create")),
) -> dict[str, Any]:
    if not archive.filename or not archive.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="A ZIP archive is required")
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as handle:
        total = 0
        while chunk := await archive.read(1024 * 1024):
            total += len(chunk)
            if total > 1024 * 1024 * 1024:
                handle.close()
                Path(handle.name).unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="ZIP exceeds the 1 GB import limit")
            handle.write(chunk)
        temporary = Path(handle.name)
    try:
        path = extract_zip_repository(temporary, name or Path(archive.filename).stem)
        detection = startup_detector.detect_repository(path)
        now = db.utc_now()
        with db.connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO repositories(name, source_type, source, local_path, detected_stack,
                                         startup_candidates, port_hints, created_by, created_at, updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    name or path.name, "zip", archive.filename, str(path), db.json_dump(detection["stacks"]),
                    db.json_dump(detection["startup_candidates"]), db.json_dump(detection["port_hints"]),
                    user["id"], now, now,
                ),
            )
        _grant_project_creator(cursor.lastrowid, user)
        audit(request, user, "repository_zip_import", "success", "repository", cursor.lastrowid, {"filename": archive.filename})
        return _get_repository(cursor.lastrowid, user)
    except (ValueError, RuntimeError) as exc:
        audit(request, user, "repository_zip_import", "failure", "repository", details={"error": str(exc)})
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        temporary.unlink(missing_ok=True)


@app.get("/api/repositories")
def repositories_list(user: dict[str, Any] = Depends(require_permission("projects.read"))) -> list[dict[str, Any]]:
    clause, params = _visible_repository_clause(user)
    query = "SELECT * FROM repositories"
    if clause:
        query += " WHERE " + clause
    query += " ORDER BY updated_at DESC"
    with db.connection() as conn:
        rows = conn.execute(query, params).fetchall()
    return [_decode_repository(dict(row)) for row in rows]


@app.get("/api/repositories/{repository_id}")
def repository_detail(repository_id: int, user: dict[str, Any] = Depends(require_permission("projects.read"))) -> dict[str, Any]:
    result = _get_repository(repository_id, user)
    result["runtime"] = process_manager.process_status(repository_id)
    result["detected_openapi"] = _detect_openapi(Path(result["local_path"]))
    result["auth_profiles"] = auth_profile_service.list_profiles(repository_id) if has_permission(user, "auth_profiles.use") else []
    return result


@app.post("/api/repositories/{repository_id}/redetect")
def redetect_repository(repository_id: int, request: Request, user: dict[str, Any] = Depends(require_permission("projects.update"))) -> dict[str, Any]:
    repo = _get_repository(repository_id, user)
    detection = startup_detector.detect_repository(repo["local_path"])
    with db.connection() as conn:
        conn.execute(
            "UPDATE repositories SET detected_stack=?, startup_candidates=?, port_hints=?, updated_at=? WHERE id=?",
            (db.json_dump(detection["stacks"]), db.json_dump(detection["startup_candidates"]), db.json_dump(detection["port_hints"]), db.utc_now(), repository_id),
        )
    audit(request, user, "repository_redetect", "success", "repository", repository_id)
    return _get_repository(repository_id, user)


@app.post("/api/repositories/{repository_id}/start")
def start_repository(repository_id: int, payload: StartRequest, request: Request, user: dict[str, Any] = Depends(require_permission("projects.start"))) -> dict[str, Any]:
    if not payload.confirmed:
        raise HTTPException(status_code=400, detail="Explicit command confirmation is required")
    repo = _get_repository(repository_id, user)
    result = process_manager.start_repository_process(repository_id, Path(repo["local_path"]), payload.command, environment=payload.environment)
    with db.connection() as conn:
        conn.execute("UPDATE repositories SET approved_command_hash=?, updated_at=? WHERE id=?", (result["command_hash"], db.utc_now(), repository_id))
    audit(request, user, "repository_start", "success", "repository", repository_id, {"command_hash": result["command_hash"], "working_directory": repo["local_path"]})
    return result


@app.post("/api/repositories/{repository_id}/stop")
def stop_repository(repository_id: int, request: Request, user: dict[str, Any] = Depends(require_permission("projects.start"))) -> dict[str, Any]:
    _get_repository(repository_id, user)
    stopped = process_manager.stop_repository_process(repository_id)
    audit(request, user, "repository_stop", "success" if stopped else "not_running", "repository", repository_id)
    return {"stopped": stopped}


# ----------------------------- Authenticated API profiles -----------------------------

@app.get("/api/repositories/{repository_id}/auth-profiles")
def auth_profiles_list(repository_id: int, user: dict[str, Any] = Depends(require_permission("auth_profiles.use"))) -> list[dict[str, Any]]:
    _get_repository(repository_id, user)
    return auth_profile_service.list_profiles(repository_id)


@app.post("/api/repositories/{repository_id}/auth-profiles")
def create_auth_profile(repository_id: int, payload: AuthProfileCreate, request: Request, user: dict[str, Any] = Depends(require_permission("auth_profiles.manage"))) -> dict[str, Any]:
    _get_repository(repository_id, user)
    try:
        profile = auth_profile_service.create_profile(repository_id, payload.name, payload.auth_type, payload.config, payload.secret, user["id"])
    except Exception as exc:
        audit(request, user, "auth_profile_create", "failure", "repository", repository_id, {"error": str(exc)})
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(request, user, "auth_profile_create", "success", "auth_profile", profile["id"], {"type": payload.auth_type})
    return profile


@app.put("/api/auth-profiles/{profile_id}/secret")
def update_auth_profile_secret(profile_id: int, payload: AuthProfileSecretUpdate, request: Request, user: dict[str, Any] = Depends(require_permission("auth_profiles.manage"))) -> dict[str, bool]:
    profile = auth_profile_service.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Authentication profile not found")
    _get_repository(profile["repository_id"], user)
    auth_profile_service.update_profile_secret(profile_id, payload.secret)
    audit(request, user, "auth_profile_secret_replace", "success", "auth_profile", profile_id)
    return {"updated": True}


@app.post("/api/auth-profiles/{profile_id}/test")
def test_auth_profile(profile_id: int, payload: AuthProfileTest, request: Request, user: dict[str, Any] = Depends(require_permission("auth_profiles.use"))) -> dict[str, Any]:
    profile = auth_profile_service.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Authentication profile not found")
    _get_repository(profile["repository_id"], user)
    validate_dynamic_target(payload.base_url)
    if not is_local_target(payload.base_url) and not payload.confirm_remote_target:
        raise HTTPException(status_code=400, detail="Remote authentication tests require explicit confirmation.")
    try:
        result = auth_profile_service.verify_profile(profile_id, payload.base_url, payload.verification_url)
    except Exception as exc:
        audit(request, user, "auth_profile_test", "failure", "auth_profile", profile_id, {"error": str(exc)})
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(request, user, "auth_profile_test", "success" if result["verified"] else "failure", "auth_profile", profile_id, {"target": result["target"]})
    return result


@app.delete("/api/auth-profiles/{profile_id}")
def delete_auth_profile(profile_id: int, request: Request, user: dict[str, Any] = Depends(require_permission("auth_profiles.manage"))) -> dict[str, bool]:
    profile = auth_profile_service.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Authentication profile not found")
    _get_repository(profile["repository_id"], user)
    auth_profile_service.remove_profile(profile_id)
    audit(request, user, "auth_profile_delete", "success", "auth_profile", profile_id)
    return {"deleted": True}


# ----------------------------- Scans and findings -----------------------------

@app.post("/api/scans")
def create_scan(payload: ScanCreate, request: Request, user: dict[str, Any] = Depends(require_permission("scans.create"))) -> dict[str, Any]:
    repo = _get_repository(payload.repository_id, user)
    if payload.api_url and not is_local_target(payload.api_url) and not payload.confirm_remote_target:
        raise HTTPException(status_code=400, detail="Remote dynamic scans require explicit confirmation.")
    if payload.startup_command and (not has_permission(user, "projects.start") or not payload.confirm_startup):
        raise HTTPException(status_code=403, detail="Startup permission and explicit confirmation are required")
    if payload.auth_profile_id:
        if not has_permission(user, "auth_profiles.use"):
            raise HTTPException(status_code=403, detail="Permission required: auth_profiles.use")
        profile = auth_profile_service.get_profile(payload.auth_profile_id)
        if not profile or profile["repository_id"] != payload.repository_id:
            raise HTTPException(status_code=400, detail="Authentication profile does not belong to this repository")
    openapi_path = payload.openapi_path or _detect_openapi(Path(repo["local_path"]))
    if payload.startup_command:
        detected_hashes = {command_fingerprint(item.get("command", ""), Path(repo["local_path"])) for item in repo["startup_candidates"] if item.get("command")}
        supplied_hash = command_fingerprint(payload.startup_command, Path(repo["local_path"]))
        if supplied_hash not in detected_hashes and supplied_hash != repo.get("approved_command_hash"):
            # Custom commands remain possible, but the audit and UI must treat them as a fresh approval.
            pass
    with db.connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans(repository_id, profile, status, selected_tools, tool_status, stages_json, coverage_json,
                              api_url, openapi_path, startup_command, auth_profile_id, progress, summary, created_by, created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                payload.repository_id, payload.profile, "queued", db.json_dump(payload.selected_tools), "{}", "{}", "{}",
                payload.api_url, openapi_path, payload.startup_command if payload.confirm_startup else None,
                payload.auth_profile_id, 0, "{}", user["id"], db.utc_now(),
            ),
        )
    scan_engine.submit_scan(cursor.lastrowid)
    audit(request, user, "scan_create", "success", "scan", cursor.lastrowid, {"tools": payload.selected_tools, "auth_profile_id": payload.auth_profile_id})
    return _get_scan(cursor.lastrowid, user)


@app.post("/api/scans/{scan_id}/cancel")
def cancel_scan(scan_id: int, request: Request, user: dict[str, Any] = Depends(require_permission("scans.cancel"))) -> dict[str, bool]:
    scan = _get_scan(scan_id, user)
    if scan["status"] not in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="Only queued or running scans can be cancelled")
    scan_engine.request_cancel(scan_id)
    audit(request, user, "scan_cancel", "requested", "scan", scan_id)
    return {"cancellation_requested": True}


@app.get("/api/scans")
def scans_list(repository_id: int | None = None, limit: int = Query(default=50, ge=1, le=500), user: dict[str, Any] = Depends(require_permission("scans.read"))) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    visible, visible_params = _visible_repository_clause(user)
    if visible:
        clauses.append(visible)
        params.extend(visible_params)
    if repository_id:
        require_repository_access(user, repository_id)
        clauses.append("scans.repository_id=?")
        params.append(repository_id)
    query = "SELECT scans.*, repositories.name AS repository_name FROM scans JOIN repositories ON repositories.id=scans.repository_id"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY scans.id DESC LIMIT ?"
    params.append(limit)
    with db.connection() as conn:
        rows = conn.execute(query, params).fetchall()
    return [_decode_scan(dict(row)) for row in rows]


@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: int, user: dict[str, Any] = Depends(require_permission("scans.read"))) -> dict[str, Any]:
    scan = _get_scan(scan_id, user)
    with db.connection() as conn:
        scan["finding_count"] = conn.execute("SELECT COUNT(*) FROM findings WHERE scan_id=?", (scan_id,)).fetchone()[0]
    return scan


@app.get("/api/scans/{scan_id}/log")
def scan_log(scan_id: int, user: dict[str, Any] = Depends(require_permission("scans.read"))) -> dict[str, Any]:
    scan = _get_scan(scan_id, user)
    path = Path(scan["log_path"]) if scan.get("log_path") else None
    text = path.read_text(encoding="utf-8", errors="ignore")[-50_000:] if path and path.exists() else ""
    return {"log": text}


@app.get("/api/findings")
def findings_list(
    scan_id: int | None = None,
    repository_id: int | None = None,
    severity: str | None = None,
    review_status: str | None = None,
    tool: str | None = None,
    search: str | None = None,
    limit: int = Query(default=250, ge=1, le=2000),
    user: dict[str, Any] = Depends(require_permission("findings.read")),
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    visible, visible_params = _visible_repository_clause(user, "repositories")
    if visible:
        clauses.append(visible)
        params.extend(visible_params)
    filters = {"findings.scan_id": scan_id, "findings.repository_id": repository_id, "findings.severity": severity, "findings.review_status": review_status, "findings.tool": tool}
    for key, value in filters.items():
        if value is not None:
            clauses.append(f"{key}=?")
            params.append(value)
    if search:
        clauses.append("(findings.title LIKE ? OR findings.description LIKE ? OR findings.file_path LIKE ? OR findings.endpoint LIKE ?)")
        value = f"%{search}%"
        params.extend([value, value, value, value])
    query = "SELECT findings.* FROM findings JOIN repositories ON repositories.id=findings.repository_id"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY CASE findings.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, findings.id DESC LIMIT ?"
    params.append(limit)
    with db.connection() as conn:
        rows = conn.execute(query, params).fetchall()
    return [_decode_finding(dict(row)) for row in rows]


@app.get("/api/findings/{finding_id}")
def finding_detail(finding_id: int, user: dict[str, Any] = Depends(require_permission("findings.read"))) -> dict[str, Any]:
    return _get_finding(finding_id, user)


@app.patch("/api/findings/{finding_id}")
def update_finding(
    finding_id: int,
    payload: FindingUpdate,
    request: Request,
    x_step_up_token: str | None = Header(default=None),
    user: dict[str, Any] = Depends(current_user),
) -> dict[str, Any]:
    finding = _get_finding(finding_id, user)
    updates: dict[str, Any] = {"updated_at": db.utc_now()}
    if payload.reviewer_notes is not None:
        if not has_permission(user, "findings.comment"):
            raise HTTPException(status_code=403, detail="Permission required: findings.comment")
        updates["reviewer_notes"] = payload.reviewer_notes
    if payload.review_status is not None:
        permission = "findings.accept_risk" if payload.review_status == "accepted_risk" else "findings.change_status"
        if not has_permission(user, permission):
            raise HTTPException(status_code=403, detail=f"Permission required: {permission}")
        if payload.review_status == "accepted_risk":
            if not x_step_up_token or not consume_step_up_grant(x_step_up_token, user["id"], "accept-risk"):
                raise HTTPException(status_code=401, detail="Fresh password confirmation is required to accept risk")
            if not payload.reviewer_notes or len(payload.reviewer_notes.strip()) < 10:
                raise HTTPException(status_code=400, detail="A meaningful risk-acceptance reason is required")
        updates["review_status"] = payload.review_status
    columns = ", ".join(f"{key}=?" for key in updates)
    with db.connection() as conn:
        conn.execute(f"UPDATE findings SET {columns} WHERE id=?", (*updates.values(), finding_id))
    audit(request, user, "finding_update", "success", "finding", finding_id, updates, purpose="Human review")
    return _get_finding(finding_id, user)


# ----------------------------- Dashboard, reports and AI -----------------------------

@app.get("/api/dashboard")
def dashboard(user: dict[str, Any] = Depends(require_permission("projects.read"))) -> dict[str, Any]:
    visible, params = _visible_repository_clause(user)
    where = f" WHERE {visible}" if visible else ""
    with db.connection() as conn:
        repo_count = conn.execute("SELECT COUNT(*) FROM repositories" + where, params).fetchone()[0]
        scan_count = conn.execute(
            "SELECT COUNT(*) FROM scans JOIN repositories ON repositories.id=scans.repository_id" + where,
            params,
        ).fetchone()[0]
        finding_count = conn.execute(
            "SELECT COUNT(*) FROM findings JOIN repositories ON repositories.id=findings.repository_id" + where,
            params,
        ).fetchone()[0]
        severity_rows = conn.execute(
            "SELECT findings.severity, COUNT(*) AS count FROM findings JOIN repositories ON repositories.id=findings.repository_id" + where + " GROUP BY findings.severity",
            params,
        ).fetchall()
        recent = conn.execute(
            "SELECT scans.*, repositories.name AS repository_name FROM scans JOIN repositories ON repositories.id=scans.repository_id" + where + " ORDER BY scans.id DESC LIMIT 8",
            params,
        ).fetchall()
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for row in severity_rows:
        severities[row["severity"]] = row["count"]
    missing_tools = [tool for tool in tool_registry.inspect_all_tools(force=False) if not tool["available"]]
    return {
        "repositories": repo_count,
        "scans": scan_count,
        "findings": finding_count,
        "severities": severities,
        "recent_scans": [_decode_scan(dict(row)) for row in recent],
        "missing_tools": len(missing_tools),
        "privacy_mode": "public-demo" if settings.demo_mode else "local",
    }


@app.get("/api/reports/{scan_id}")
def download_report(scan_id: int, format: Literal["html", "json", "docx"] = "docx", user: dict[str, Any] = Depends(require_permission("reports.generate"))) -> FileResponse:
    scan = _get_scan(scan_id, user)
    repo = _get_repository(scan["repository_id"], user)
    with db.connection() as conn:
        rows = conn.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
    findings = [_decode_finding(dict(row)) for row in rows]
    if format == "json":
        path, media = reports.generate_json(scan, repo, findings), "application/json"
    elif format == "html":
        path, media = reports.generate_html(scan, repo, findings), "text/html"
    else:
        path = reports.generate_docx(scan, repo, findings)
        media = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    return FileResponse(path, media_type=media, filename=path.name)


@app.get("/api/ai/health")
def ai_health(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return ai_service.provider_health(refresh=True)


@app.get("/api/ai/settings")
def ai_settings(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return ai_service.current_ai_settings()


@app.patch("/api/ai/settings")
def update_ai_settings(payload: AISettingsUpdate, request: Request, user: dict[str, Any] = Depends(require_permission("settings.manage"))) -> dict[str, Any]:
    data = {key: value for key, value in payload.model_dump().items() if value is not None}
    if data.get("ollama_url"):
        try:
            ai_service.validate_ollama_endpoint(data["ollama_url"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if data.get("airllm_url"):
        validate_dynamic_target(data["airllm_url"])
    result = ai_service.save_ai_settings(data)
    audit(request, user, "ai_settings_update", "success", "settings", details={"keys": list(data)})
    return result


@app.post("/api/ai/chat")
def ai_chat(payload: ChatRequest, request: Request, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    _enforce_demo_ai_limit(request)
    repo = _get_repository(payload.repository_id, user)
    if settings.demo_mode and repo.get("source") != "bundled-demo-target":
        raise HTTPException(status_code=403, detail="Public demo AI is limited to the bundled sample repository.")
    finding = _get_finding(payload.finding_id, user) if payload.finding_id else None
    if finding and finding["repository_id"] != payload.repository_id:
        raise HTTPException(status_code=400, detail="Finding does not belong to the selected repository")
    try:
        result = ai_service.chat(repo["local_path"], payload.question, finding, payload.provider)
    except RuntimeError as exc:
        audit(request, user, "ai_chat", "failure", "repository", payload.repository_id, {"error": str(exc)})
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    with db.connection() as conn:
        conn.execute(
            "INSERT INTO chat_messages(repository_id, finding_id, user_id, provider, role, content, created_at) VALUES(?,?,?,?,?,?,?)",
            (payload.repository_id, payload.finding_id, user["id"], result["provider"], "user", payload.question, db.utc_now()),
        )
        conn.execute(
            "INSERT INTO chat_messages(repository_id, finding_id, user_id, provider, role, content, created_at) VALUES(?,?,?,?,?,?,?)",
            (payload.repository_id, payload.finding_id, user["id"], result["provider"], "assistant", result["content"], db.utc_now()),
        )
    audit(request, user, "ai_chat", "success", "repository", payload.repository_id, {"finding_id": payload.finding_id, "provider": result["provider"]})
    return result


# ----------------------------- Schedules, backups and audit -----------------------------

@app.get("/api/schedules")
def schedules_list(user: dict[str, Any] = Depends(require_permission("scans.read"))) -> list[dict[str, Any]]:
    visible, params = _visible_repository_clause(user)
    query = "SELECT schedules.*, repositories.name AS repository_name FROM schedules JOIN repositories ON repositories.id=schedules.repository_id"
    if visible:
        query += " WHERE " + visible
    query += " ORDER BY schedules.id DESC"
    with db.connection() as conn:
        rows = conn.execute(query, params).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["selected_tools"] = db.json_load(item.get("selected_tools"), [])
        item["enabled"] = bool(item["enabled"])
        output.append(item)
    return output


@app.post("/api/schedules")
def create_schedule(payload: ScheduleCreate, request: Request, user: dict[str, Any] = Depends(require_permission("scans.create"))) -> dict[str, Any]:
    _get_repository(payload.repository_id, user)
    tools = ScanCreate.validate_tools(payload.selected_tools)
    next_run = scheduler.compute_next_run(payload.cadence, payload.hour, payload.minute, payload.day_of_week)
    now = db.utc_now()
    with db.connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO schedules(name, repository_id, cadence, hour, minute, day_of_week, profile,
                                  selected_tools, api_url, openapi_path, auth_profile_id, enabled, next_run,
                                  created_by, created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                payload.name, payload.repository_id, payload.cadence, payload.hour, payload.minute,
                payload.day_of_week, payload.profile, db.json_dump(tools), payload.api_url,
                payload.openapi_path, payload.auth_profile_id, 1, next_run, user["id"], now, now,
            ),
        )
    audit(request, user, "schedule_create", "success", "schedule", cursor.lastrowid)
    return {"id": cursor.lastrowid, "next_run": next_run}


@app.patch("/api/schedules/{schedule_id}")
def update_schedule(schedule_id: int, payload: ScheduleUpdate, request: Request, user: dict[str, Any] = Depends(require_permission("scans.create"))) -> dict[str, Any]:
    with db.connection() as conn:
        row = conn.execute("SELECT * FROM schedules WHERE id=?", (schedule_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Schedule not found")
        require_repository_access(user, row["repository_id"])
        next_run = row["next_run"]
        if payload.enabled:
            next_run = scheduler.compute_next_run(row["cadence"], row["hour"], row["minute"], row["day_of_week"])
        conn.execute("UPDATE schedules SET enabled=?, next_run=?, updated_at=? WHERE id=?", (int(payload.enabled), next_run, db.utc_now(), schedule_id))
    audit(request, user, "schedule_update", "success", "schedule", schedule_id, {"enabled": payload.enabled})
    return {"id": schedule_id, "enabled": payload.enabled, "next_run": next_run}


@app.delete("/api/schedules/{schedule_id}")
def delete_schedule(schedule_id: int, request: Request, user: dict[str, Any] = Depends(require_permission("scans.create"))) -> dict[str, bool]:
    with db.connection() as conn:
        row = conn.execute("SELECT repository_id FROM schedules WHERE id=?", (schedule_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Schedule not found")
        require_repository_access(user, row["repository_id"])
        conn.execute("DELETE FROM schedules WHERE id=?", (schedule_id,))
    audit(request, user, "schedule_delete", "success", "schedule", schedule_id)
    return {"deleted": True}


@app.get("/api/backups")
def backups_list(user: dict[str, Any] = Depends(require_permission("backups.manage"))) -> list[dict[str, Any]]:
    return backup_service.list_backups()


@app.post("/api/backups")
def create_backup(payload: BackupCreate, request: Request, user: dict[str, Any] = Depends(require_permission("backups.manage"))) -> dict[str, Any]:
    result = backup_service.create_backup(payload.reason, user["id"])
    audit(request, user, "backup_create", "success", "backup", result["id"], {"reason": payload.reason})
    return result


@app.post("/api/backups/{backup_id}/restore")
def restore_backup(
    backup_id: int,
    request: Request,
    x_step_up_token: str | None = Header(default=None),
    user: dict[str, Any] = Depends(require_permission("backups.manage")),
) -> dict[str, Any]:
    if not x_step_up_token or not consume_step_up_grant(x_step_up_token, user["id"], "restore-backup"):
        raise HTTPException(status_code=401, detail="Fresh password confirmation is required")
    result = backup_service.restore_backup(backup_id, user["id"])
    audit(request, user, "backup_restore", "success", "backup", backup_id)
    return result


@app.get("/api/audit")
def audit_logs(
    action: str | None = None,
    username: str | None = None,
    limit: int = Query(default=200, ge=1, le=2000),
    user: dict[str, Any] = Depends(require_permission("audit.read")),
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if action:
        clauses.append("action=?")
        params.append(action)
    if username:
        clauses.append("username=?")
        params.append(username)
    query = "SELECT * FROM audit_logs"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with db.connection() as conn:
        rows = conn.execute(query, params).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["details"] = db.json_load(item.get("details"), {})
        output.append(item)
    return output


@app.get("/api/audit/verify")
def verify_audit(user: dict[str, Any] = Depends(require_permission("audit.read"))) -> dict[str, Any]:
    valid, message = verify_audit_chain()
    return {"valid": valid, "message": message}
