from __future__ import annotations

import base64
import json
import secrets
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx

from app import db
from app.core.credential_store import delete_secret, load_secret_json, save_secret
from app.core.http_redaction import redact_headers
from app.core.target_policy import safe_request, validate_dynamic_target


SUPPORTED_AUTH_TYPES = {
    "bearer",
    "api_key_header",
    "api_key_query",
    "basic",
    "oauth_client_credentials",
    "cookie",
}

_NAME_RE = re.compile(r"^[A-Za-z0-9_. -]{2,100}$")
_HTTP_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,80}$")


def _bounded_mapping(value: dict[str, Any], *, label: str) -> None:
    if len(value) > 30:
        raise ValueError(f"{label} contains too many fields.")
    encoded = json.dumps(value, ensure_ascii=False, default=str)
    if len(encoded.encode("utf-8")) > 64 * 1024:
        raise ValueError(f"{label} exceeds the 64 KB limit.")
    for key, item in value.items():
        if not isinstance(key, str) or len(key) > 100:
            raise ValueError(f"{label} contains an invalid field name.")
        if isinstance(item, str) and len(item) > 32_000:
            raise ValueError(f"{label} field '{key}' is too large.")


def _validate_profile_input(name: str, auth_type: str, config: dict[str, Any], secret: dict[str, Any]) -> None:
    if not _NAME_RE.fullmatch(name.strip()):
        raise ValueError("Profile name may contain letters, numbers, spaces, dots, underscores and hyphens.")
    if auth_type not in SUPPORTED_AUTH_TYPES:
        raise ValueError(f"Unsupported authentication type: {auth_type}")
    _bounded_mapping(config, label="Profile configuration")
    _bounded_mapping(secret, label="Profile secret")
    for value in list(config.values()) + list(secret.values()):
        if isinstance(value, str) and ("\r" in value or "\n" in value):
            raise ValueError("Authentication profile values cannot contain line breaks.")
    if auth_type == "api_key_header":
        header = str(config.get("header_name") or "X-API-Key")
        if not _HTTP_NAME_RE.fullmatch(header):
            raise ValueError("API key header name is invalid.")
    if auth_type == "api_key_query":
        parameter = str(config.get("parameter_name") or "api_key")
        if not _HTTP_NAME_RE.fullmatch(parameter):
            raise ValueError("API key query parameter name is invalid.")
    if auth_type == "cookie":
        cookie = str(config.get("cookie_name") or "session")
        if not _HTTP_NAME_RE.fullmatch(cookie):
            raise ValueError("Cookie name is invalid.")
    if auth_type == "oauth_client_credentials":
        validate_dynamic_target(str(config.get("token_url") or ""))



@dataclass
class HttpAuthContext:
    profile_id: int | None = None
    profile_name: str = "Anonymous"
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    identity: str | None = None
    secret_values: list[str] = field(default_factory=list)

    def public_summary(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "profile_name": self.profile_name,
            "headers": redact_headers(self.headers),
            "query_parameters": list(self.params),
            "cookies": list(self.cookies),
            "identity": self.identity,
        }


def _public(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["config"] = db.json_load(result.pop("config_json", "{}"), {})
    result.pop("secret_ref", None)
    result["enabled"] = bool(result.get("enabled"))
    result["verified"] = bool(result.get("verified"))
    return result


def list_profiles(repository_id: int) -> list[dict[str, Any]]:
    with db.connection() as conn:
        rows = conn.execute(
            "SELECT * FROM api_auth_profiles WHERE repository_id=? ORDER BY name", (repository_id,)
        ).fetchall()
    return [_public(dict(row)) for row in rows]


def get_profile(profile_id: int) -> dict[str, Any] | None:
    with db.connection() as conn:
        row = conn.execute("SELECT * FROM api_auth_profiles WHERE id=?", (profile_id,)).fetchone()
    return _public(dict(row)) if row else None


def create_profile(
    repository_id: int,
    name: str,
    auth_type: str,
    config: dict[str, Any],
    secret: dict[str, Any],
    created_by: int,
) -> dict[str, Any]:
    _validate_profile_input(name, auth_type, config, secret)
    name = name.strip()
    secret_ref = f"YashSec/AuthProfile/{repository_id}/{secrets.token_hex(16)}"
    save_secret(secret_ref, secret)
    now = db.utc_now()
    try:
        with db.connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO api_auth_profiles(repository_id, name, auth_type, config_json, secret_ref,
                                              enabled, verified, created_by, created_at, updated_at)
                VALUES(?,?,?,?,?,1,0,?,?,?)
                """,
                (repository_id, name, auth_type, db.json_dump(config), secret_ref, created_by, now, now),
            )
    except Exception:
        delete_secret(secret_ref)
        raise
    return get_profile(cursor.lastrowid) or {"id": cursor.lastrowid}


def update_profile_secret(profile_id: int, secret: dict[str, Any]) -> None:
    with db.connection() as conn:
        row = conn.execute("SELECT secret_ref, name, auth_type, config_json FROM api_auth_profiles WHERE id=?", (profile_id,)).fetchone()
        if not row:
            raise ValueError("Authentication profile not found.")
        _validate_profile_input(row["name"], row["auth_type"], db.json_load(row["config_json"], {}), secret)
        save_secret(row["secret_ref"], secret)
        conn.execute(
            "UPDATE api_auth_profiles SET verified=0, last_error=NULL, updated_at=? WHERE id=?",
            (db.utc_now(), profile_id),
        )


def remove_profile(profile_id: int) -> None:
    with db.connection() as conn:
        row = conn.execute("SELECT secret_ref FROM api_auth_profiles WHERE id=?", (profile_id,)).fetchone()
        if not row:
            return
        conn.execute("DELETE FROM api_auth_profiles WHERE id=?", (profile_id,))
    delete_secret(row["secret_ref"])


def _oauth_token(config: dict[str, Any], secret: dict[str, Any]) -> tuple[str, str]:
    token_url = str(config.get("token_url") or "")
    validate_dynamic_target(token_url)
    data = {"grant_type": "client_credentials"}
    if config.get("scope"):
        data["scope"] = str(config["scope"])
    if config.get("audience"):
        data["audience"] = str(config["audience"])
    client_id = str(secret.get("client_id") or config.get("client_id") or "")
    client_secret = str(secret.get("client_secret") or "")
    if not client_id or not client_secret:
        raise ValueError("OAuth client ID and client secret are required.")
    with httpx.Client(timeout=20) as client:
        response = safe_request(client, "POST", token_url, data=data, auth=(client_id, client_secret))
    response.raise_for_status()
    payload = response.json()
    access_token = str(payload.get("access_token") or "")
    if not access_token:
        raise ValueError("OAuth token endpoint did not return access_token.")
    return str(payload.get("token_type") or "Bearer"), access_token


def resolve_context(profile_id: int | None) -> HttpAuthContext:
    if profile_id is None:
        return HttpAuthContext()
    with db.connection() as conn:
        row = conn.execute("SELECT * FROM api_auth_profiles WHERE id=? AND enabled=1", (profile_id,)).fetchone()
    if not row:
        raise ValueError("Authentication profile is missing or disabled.")
    config = db.json_load(row["config_json"], {})
    secret = load_secret_json(row["secret_ref"])
    context = HttpAuthContext(profile_id=row["id"], profile_name=row["name"], identity=row["verified_identity"])
    auth_type = row["auth_type"]

    if auth_type == "bearer":
        token = str(secret.get("token") or "")
        if not token:
            raise ValueError("Bearer token is missing.")
        prefix = str(config.get("prefix") or "Bearer")
        context.headers["Authorization"] = f"{prefix} {token}".strip()
        context.secret_values.append(token)
    elif auth_type == "api_key_header":
        name = str(config.get("header_name") or "X-API-Key")
        value = str(secret.get("api_key") or "")
        if not value:
            raise ValueError("API key is missing.")
        context.headers[name] = value
        context.secret_values.append(value)
    elif auth_type == "api_key_query":
        name = str(config.get("parameter_name") or "api_key")
        value = str(secret.get("api_key") or "")
        if not value:
            raise ValueError("API key is missing.")
        context.params[name] = value
        context.secret_values.append(value)
    elif auth_type == "basic":
        username = str(secret.get("username") or config.get("username") or "")
        password = str(secret.get("password") or "")
        if not username or not password:
            raise ValueError("Basic authentication username and password are required.")
        encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        context.headers["Authorization"] = f"Basic {encoded}"
        context.identity = username
        context.secret_values.extend([password, encoded])
    elif auth_type == "cookie":
        name = str(config.get("cookie_name") or "session")
        value = str(secret.get("cookie_value") or "")
        if not value:
            raise ValueError("Cookie value is missing.")
        context.cookies[name] = value
        context.secret_values.append(value)
    elif auth_type == "oauth_client_credentials":
        token_type, token = _oauth_token(config, secret)
        context.headers["Authorization"] = f"{token_type} {token}"
        context.secret_values.append(token)
    return context


def verify_profile(profile_id: int, base_url: str, verification_url: str | None = None) -> dict[str, Any]:
    validate_dynamic_target(base_url)
    context = resolve_context(profile_id)
    profile = get_profile(profile_id)
    target = verification_url or (profile.get("verification_url") if profile else None) or base_url
    if target.startswith("/"):
        target = urljoin(base_url.rstrip("/") + "/", target.lstrip("/"))
    validate_dynamic_target(target)
    try:
        with httpx.Client(timeout=20) as client:
            response = safe_request(
                client,
                "GET",
                target,
                headers=context.headers,
                params=context.params,
                cookies=context.cookies,
            )
        verified = 200 <= response.status_code < 300
        identity = None
        if verified:
            try:
                body = response.json()
                if isinstance(body, dict):
                    for key in ("username", "email", "name", "sub", "id", "role"):
                        if body.get(key) is not None:
                            identity = f"{key}={body[key]}"
                            break
            except (ValueError, json.JSONDecodeError):
                pass
        message = f"HTTP {response.status_code}"
    except httpx.HTTPError as exc:
        verified = False
        identity = None
        message = str(exc)

    with db.connection() as conn:
        conn.execute(
            """
            UPDATE api_auth_profiles
            SET verified=?, verification_url=?, verified_identity=?, last_verified_at=?, last_error=?, updated_at=?
            WHERE id=?
            """,
            (
                int(verified), target, identity, db.utc_now(), None if verified else message, db.utc_now(), profile_id,
            ),
        )
    return {"verified": verified, "status": message, "identity": identity, "target": target, "context": context.public_summary()}
