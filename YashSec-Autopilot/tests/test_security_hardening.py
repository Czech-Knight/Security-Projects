from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app import db
from app.core import auth_profiles, backup_service, credential_store, security
from app.core.target_policy import TargetPolicyError, validate_dynamic_target


@pytest.fixture()
def isolated_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    database = tmp_path / "yashsec.db"
    secrets = tmp_path / "secrets"
    backups = tmp_path / "backups"
    secrets.mkdir()
    backups.mkdir()
    monkeypatch.setattr(db, "DB_PATH", database)
    monkeypatch.setattr(credential_store, "SECRET_DIR", secrets)
    monkeypatch.setattr(backup_service, "DB_PATH", database)
    monkeypatch.setattr(backup_service, "BACKUP_DIR", backups)
    security._STEP_UP.clear()
    db.init_db()
    return database


def test_password_hash_and_hashed_session(isolated_data: Path) -> None:
    owner = security.initialize_owner("owner", "Correct-Horse-Battery-42")
    authenticated, reason = security.authenticate("owner", "Correct-Horse-Battery-42")
    assert reason is None
    assert authenticated and "owner" in authenticated["roles"]

    token = security.create_session(owner["id"], "test-client")
    with db.connection() as conn:
        row = conn.execute("SELECT token_hash FROM sessions WHERE user_id=?", (owner["id"],)).fetchone()
        password_hash = conn.execute("SELECT password_hash FROM users WHERE id=?", (owner["id"],)).fetchone()[0]
    assert row["token_hash"] != token
    assert len(row["token_hash"]) == 64
    assert password_hash.startswith("$argon2") or password_hash.startswith("pbkdf2_sha256$")
    assert security.get_user_from_token(token)["id"] == owner["id"]


def test_role_permissions_are_deny_by_default(isolated_data: Path) -> None:
    owner = security.initialize_owner("owner", "Correct-Horse-Battery-42")
    with db.connection() as conn:
        now = db.utc_now()
        cursor = conn.execute(
            "INSERT INTO users(username,password_hash,role,is_active,password_changed_at,created_at,updated_at) VALUES(?,?,?,1,?,?,?)",
            ("viewer", security.hash_password("Viewer-Password-123"), "reviewer", now, now, now),
        )
        role_id = conn.execute("SELECT id FROM roles WHERE name='viewer'").fetchone()[0]
        conn.execute("INSERT INTO user_roles(user_id,role_id) VALUES(?,?)", (cursor.lastrowid, role_id))
    viewer = security.get_user(cursor.lastrowid)
    assert owner and security.has_permission(owner, "users.manage")
    assert viewer and security.has_permission(viewer, "projects.read")
    assert not security.has_permission(viewer, "projects.create")
    assert not security.has_permission(viewer, "findings.accept_risk")
    assert not security.has_permission(viewer, "backups.manage")


def test_auth_profile_secret_is_separated_from_database(isolated_data: Path) -> None:
    owner = security.initialize_owner("owner", "Correct-Horse-Battery-42")
    now = db.utc_now()
    with db.connection() as conn:
        repo_id = conn.execute(
            "INSERT INTO repositories(name,source_type,source,local_path,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            ("demo", "local", "demo", str(isolated_data.parent), owner["id"], now, now),
        ).lastrowid
    profile = auth_profiles.create_profile(repo_id, "API user", "bearer", {"prefix": "Bearer"}, {"token": "never-store-this-plain"}, owner["id"])
    with db.connection() as conn:
        row = conn.execute("SELECT config_json, secret_ref FROM api_auth_profiles WHERE id=?", (profile["id"],)).fetchone()
    assert "never-store-this-plain" not in row["config_json"]
    assert "never-store-this-plain" not in isolated_data.read_bytes().decode("latin1", errors="ignore")
    context = auth_profiles.resolve_context(profile["id"])
    assert context.headers["Authorization"] == "Bearer never-store-this-plain"
    public = auth_profiles.get_profile(profile["id"])
    assert public and "secret_ref" not in public


def test_backup_uses_consistent_sqlite_copy(isolated_data: Path) -> None:
    owner = security.initialize_owner("owner", "Correct-Horse-Battery-42")
    result = backup_service.create_backup("manual", owner["id"])
    backup = Path(result["path"])
    assert backup.exists()
    with sqlite3.connect(backup) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_remote_dynamic_target_rejected() -> None:
    assert validate_dynamic_target("http://127.0.0.1:4000")
    with pytest.raises(TargetPolicyError):
        validate_dynamic_target("https://example.com")


def test_embedded_target_credentials_rejected() -> None:
    with pytest.raises(TargetPolicyError):
        validate_dynamic_target("http://user:password@127.0.0.1:8000")


def test_safe_request_revalidates_redirect_destination(monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx
    from app.core.target_policy import safe_request

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://example.com/private"}, request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    with client, pytest.raises(TargetPolicyError):
        safe_request(client, "GET", "http://127.0.0.1:8000")


def test_auth_profile_rejects_header_injection(isolated_data: Path) -> None:
    owner = security.initialize_owner("owner", "Correct-Horse-Battery-42")
    now = db.utc_now()
    with db.connection() as conn:
        repo_id = conn.execute(
            "INSERT INTO repositories(name,source_type,source,local_path,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            ("demo", "local", "demo", str(isolated_data.parent), owner["id"], now, now),
        ).lastrowid
    with pytest.raises(ValueError):
        auth_profiles.create_profile(
            repo_id,
            "Injected header",
            "api_key_header",
            {"header_name": "X-API-Key\r\nX-Injected"},
            {"api_key": "secret"},
            owner["id"],
        )


def test_audit_chain_detects_user_agent_tamper(isolated_data: Path) -> None:
    from starlette.requests import Request

    owner = security.initialize_owner("owner", "Correct-Horse-Battery-42")
    request = Request({
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"user-agent", b"YashSec-Test-Agent")],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 8787),
        "scheme": "http",
        "query_string": b"",
    })
    security.audit(request, owner, "test_event", "success")
    assert security.verify_audit_chain()[0]
    with db.connection() as conn:
        conn.execute("UPDATE audit_logs SET user_agent='tampered' WHERE action='test_event'")
    valid, message = security.verify_audit_chain()
    assert not valid
    assert "failed" in message.lower()


def test_demo_seed_is_idempotent_and_read_only(isolated_data: Path) -> None:
    from app.core import demo_mode

    first = demo_mode.seed_demo_workspace()
    second = demo_mode.seed_demo_workspace()
    assert first == second

    with db.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM users WHERE username='demo-viewer'").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM repositories WHERE source='bundled-demo-target'").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM scans WHERE profile='demo'").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM findings WHERE scan_id=?", (first["scan_id"],)).fetchone()[0] >= 1
        role = conn.execute(
            "SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=?",
            (first["user_id"],),
        ).fetchone()[0]
        scan = conn.execute("SELECT coverage_json, summary FROM scans WHERE id=?", (first["scan_id"],)).fetchone()
    assert role == "viewer"
    assert db.json_load(scan["coverage_json"], {})["dynamic_testing"] == "skipped"
    assert db.json_load(scan["summary"], {})["coverage_complete"] is False


def test_remote_ollama_is_https_allowlisted_and_keyed(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace
    from app.core import ai_service

    monkeypatch.setattr(
        ai_service,
        "settings",
        SimpleNamespace(
            allow_cloud_ai=True,
            cloud_ai_hosts=("ollama.com",),
            ollama_api_key="server-side-test-key",
            ai_provider="ollama",
            ollama_url="https://ollama.com",
            ollama_model="gpt-oss:20b",
            airllm_url="http://127.0.0.1:8765",
        ),
    )
    ai_service.validate_ollama_endpoint("https://ollama.com")
    assert ai_service._ollama_headers("https://ollama.com") == {
        "Authorization": "Bearer server-side-test-key"
    }
    with pytest.raises(ValueError):
        ai_service.validate_ollama_endpoint("http://ollama.com")
    with pytest.raises(ValueError):
        ai_service.validate_ollama_endpoint("https://example.com")
