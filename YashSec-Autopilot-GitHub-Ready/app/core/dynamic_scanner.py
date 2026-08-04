from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx
import yaml

from app.core.auth_profiles import HttpAuthContext
from app.core.http_redaction import redact_text
from app.core.normalizer import with_defaults
from app.core.target_policy import is_local_target, safe_request, validate_dynamic_target


STACK_TRACE_PATTERNS = re.compile(
    r"(?i)(traceback \(most recent call last\)|at [\w.$]+\([^\n]+:\d+\)|system\.exception|sqlstate\[|werkzeug debugger|django version)"
)
SENSITIVE_PATH_WORDS = ("cv", "resume", "admin", "audit", "consent", "user", "account", "career-pathways")


def _load_schema(schema_value: str, repo: Path, auth: HttpAuthContext) -> dict[str, Any] | None:
    if schema_value.startswith(("http://", "https://")):
        validate_dynamic_target(schema_value)
        with httpx.Client(timeout=10, verify=not is_local_target(schema_value)) as client:
            response = safe_request(
                client,
                "GET",
                schema_value,
                headers=auth.headers,
                params=auth.params,
                cookies=auth.cookies,
            )
        response.raise_for_status()
        try:
            return response.json()
        except json.JSONDecodeError:
            loaded = yaml.safe_load(response.text)
            return loaded if isinstance(loaded, dict) else None
    path = Path(schema_value)
    if not path.is_absolute():
        path = repo / path
    try:
        path = path.resolve()
        path.relative_to(repo.resolve())
    except (ValueError, OSError):
        raise ValueError("OpenAPI path must remain inside the selected repository.")
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="ignore")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        loaded = yaml.safe_load(text)
        return loaded if isinstance(loaded, dict) else None


def _security_header_findings(response: httpx.Response) -> list[dict]:
    expected = {
        "x-content-type-options": ("Missing X-Content-Type-Options header", "low", "Set X-Content-Type-Options: nosniff."),
        "content-security-policy": ("Missing Content-Security-Policy header", "medium", "Define a restrictive Content-Security-Policy appropriate for the application."),
        "referrer-policy": ("Missing Referrer-Policy header", "low", "Set a privacy-preserving Referrer-Policy."),
    }
    findings: list[dict] = []
    for header, (title, severity, remediation) in expected.items():
        if header not in response.headers:
            findings.append(
                with_defaults(
                    {
                        "title": title,
                        "description": f"The response from {response.url} did not include {header}.",
                        "severity": severity,
                        "confidence": "high",
                        "tool": "yashsec-dynamic",
                        "category": "security-headers",
                        "owasp": "A05:2021 Security Misconfiguration",
                        "file_path": str(response.url),
                        "endpoint": str(response.url),
                        "evidence": f"HTTP {response.status_code}; header absent",
                        "remediation": remediation,
                    }
                )
            )
    if response.url.scheme == "https" and "strict-transport-security" not in response.headers:
        findings.append(
            with_defaults(
                {
                    "title": "Missing Strict-Transport-Security header",
                    "description": "HTTPS responses should normally enforce HSTS after deployment configuration has been validated.",
                    "severity": "medium",
                    "confidence": "high",
                    "tool": "yashsec-dynamic",
                    "category": "security-headers",
                    "owasp": "A02:2021 Cryptographic Failures",
                    "file_path": str(response.url),
                    "endpoint": str(response.url),
                    "remediation": "Enable HSTS with an appropriate max-age after confirming all traffic is HTTPS-only.",
                }
            )
        )
    return findings


def _replace_path_parameters(path: str, invalid: bool = False) -> str:
    replacement = "invalid-yashsec-value" if invalid else "1"
    return re.sub(r"\{[^}]+\}", replacement, path)


def _client(api_url: str, auth: HttpAuthContext | None = None) -> httpx.Client:
    context = auth or HttpAuthContext()
    return httpx.Client(
        timeout=8,
        follow_redirects=False,
        verify=not is_local_target(api_url),
        headers={"User-Agent": "YashSec-Autopilot/1.0", **context.headers},
        params=context.params,
        cookies=context.cookies,
    )


def run_safe_dynamic_checks(
    repo: Path,
    api_url: str,
    schema_value: str | None = None,
    auth_context: HttpAuthContext | None = None,
) -> list[dict]:
    validate_dynamic_target(api_url)
    auth = auth_context or HttpAuthContext()
    findings: list[dict] = []
    authenticated = _client(api_url, auth)
    anonymous = _client(api_url)
    try:
        base_response = safe_request(authenticated, "GET", api_url)
        findings.extend(_security_header_findings(base_response))
        rate_signal = any(
            header in base_response.headers
            for header in ("ratelimit-limit", "x-ratelimit-limit", "retry-after", "ratelimit-remaining", "x-ratelimit-remaining")
        )
        statuses: list[int] = []
        if not rate_signal:
            for _ in range(8):
                try:
                    probe = safe_request(authenticated, "GET", api_url)
                    statuses.append(probe.status_code)
                    if probe.status_code == 429 or any(
                        header in probe.headers
                        for header in ("ratelimit-limit", "x-ratelimit-limit", "retry-after", "ratelimit-remaining", "x-ratelimit-remaining")
                    ):
                        rate_signal = True
                        break
                except httpx.HTTPError:
                    break
            if not rate_signal:
                findings.append(
                    with_defaults(
                        {
                            "title": "Rate-limit enforcement could not be verified",
                            "description": "A light request probe did not observe HTTP 429 or standard rate-limit headers. This is a coverage warning, not proof that rate limiting is absent.",
                            "severity": "info",
                            "confidence": "low",
                            "tool": "yashsec-dynamic",
                            "category": "rate-limit-verification",
                            "owasp": "API4:2023 Unrestricted Resource Consumption",
                            "file_path": api_url,
                            "endpoint": api_url,
                            "evidence": f"Profile={auth.profile_name}; probe statuses={statuses}",
                            "remediation": "Run an authorised staging test against the documented quota and verify per-client enforcement and reset behaviour.",
                        }
                    )
                )
        match = STACK_TRACE_PATTERNS.search(base_response.text[:200_000])
        if match:
            findings.append(
                with_defaults(
                    {
                        "title": "Stack trace or internal error details exposed",
                        "description": "The base response contains a pattern associated with internal stack traces or debugging output.",
                        "severity": "high",
                        "confidence": "high",
                        "tool": "yashsec-dynamic",
                        "category": "error-information-leakage",
                        "cwe": "CWE-209",
                        "owasp": "A05:2021 Security Misconfiguration",
                        "file_path": str(base_response.url),
                        "endpoint": str(base_response.url),
                        "evidence": redact_text(match.group(0), auth.secret_values),
                        "remediation": "Return a generic client error and retain detailed exceptions only in protected server-side logs.",
                    }
                )
            )
    except httpx.HTTPError as exc:
        findings.append(
            with_defaults(
                {
                    "title": "API target could not be reached",
                    "description": "The configured API target was unavailable during dynamic checks.",
                    "severity": "info",
                    "confidence": "high",
                    "tool": "yashsec-dynamic",
                    "category": "coverage-gap",
                    "file_path": api_url,
                    "endpoint": api_url,
                    "evidence": redact_text(str(exc), auth.secret_values),
                    "remediation": "Start the application, confirm the URL and rerun dynamic testing.",
                }
            )
        )
        authenticated.close()
        anonymous.close()
        return findings

    schema = _load_schema(schema_value, repo, auth) if schema_value else None
    if not schema:
        authenticated.close()
        anonymous.close()
        return findings

    paths = schema.get("paths") or {}
    tested = 0
    for path, operations in paths.items():
        if tested >= 25 or not isinstance(operations, dict):
            break
        get_operation = operations.get("get")
        if not isinstance(get_operation, dict):
            continue
        test_path = _replace_path_parameters(path)
        target = urljoin(api_url.rstrip("/") + "/", test_path.lstrip("/"))
        try:
            auth_response = safe_request(authenticated, "GET", target)
            anonymous_response = safe_request(anonymous, "GET", target)
        except httpx.HTTPError:
            continue
        tested += 1
        declared_security = get_operation.get("security", schema.get("security"))

        if declared_security and anonymous_response.status_code < 300:
            findings.append(
                with_defaults(
                    {
                        "title": "Protected endpoint accepted an anonymous request",
                        "description": "The OpenAPI security requirement indicates authentication, but the operation returned success without credentials.",
                        "severity": "high",
                        "confidence": "high",
                        "tool": "yashsec-dynamic",
                        "category": "authentication-check",
                        "cwe": "CWE-306",
                        "owasp": "API2:2023 Broken Authentication",
                        "file_path": target,
                        "endpoint": path,
                        "evidence": f"Anonymous GET {path}: HTTP {anonymous_response.status_code}; authenticated profile '{auth.profile_name}': HTTP {auth_response.status_code}",
                        "remediation": "Apply authentication middleware to the operation and verify the OpenAPI security declaration matches runtime behaviour.",
                    }
                )
            )
        elif any(word in path.lower() for word in SENSITIVE_PATH_WORDS) and anonymous_response.status_code < 300:
            findings.append(
                with_defaults(
                    {
                        "title": "Potential anonymous access to a sensitive endpoint",
                        "description": "A sensitive-looking GET endpoint returned a successful response without credentials.",
                        "severity": "high",
                        "confidence": "medium",
                        "tool": "yashsec-dynamic",
                        "category": "authentication-check",
                        "cwe": "CWE-306",
                        "owasp": "A01:2021 Broken Access Control",
                        "file_path": target,
                        "endpoint": path,
                        "evidence": f"Anonymous GET {path}: HTTP {anonymous_response.status_code}",
                        "remediation": "Confirm whether the endpoint is intentionally public; otherwise enforce authentication and object-level authorisation.",
                    }
                )
            )

        if auth.profile_id and auth_response.status_code in {401, 403}:
            findings.append(
                with_defaults(
                    {
                        "title": "Authenticated API profile was rejected",
                        "description": "The selected authentication profile did not gain access to this operation. Authenticated coverage may be incomplete.",
                        "severity": "info",
                        "confidence": "high",
                        "tool": "yashsec-dynamic",
                        "category": "coverage-gap",
                        "file_path": target,
                        "endpoint": path,
                        "evidence": f"Profile '{auth.profile_name}' received HTTP {auth_response.status_code} for GET {path}",
                        "remediation": "Verify the profile identity, token scope, expiry and expected role before relying on authenticated test coverage.",
                    }
                )
            )

        invalid_target = urljoin(api_url.rstrip("/") + "/", _replace_path_parameters(path, invalid=True).lstrip("/"))
        try:
            invalid_response = safe_request(authenticated, "GET", invalid_target)
        except httpx.HTTPError:
            continue
        if invalid_response.status_code >= 500:
            findings.append(
                with_defaults(
                    {
                        "title": "Invalid path input caused a server error",
                        "description": "A malformed path parameter produced an HTTP 5xx response instead of a controlled validation error.",
                        "severity": "medium",
                        "confidence": "high",
                        "tool": "yashsec-dynamic",
                        "category": "input-validation",
                        "cwe": "CWE-20",
                        "owasp": "API8:2023 Security Misconfiguration",
                        "file_path": invalid_target,
                        "endpoint": path,
                        "evidence": redact_text(f"HTTP {invalid_response.status_code}; body: {invalid_response.text[:600]}", auth.secret_values),
                        "remediation": "Validate path parameters before business logic and return a consistent 4xx response.",
                    }
                )
            )
        if STACK_TRACE_PATTERNS.search(invalid_response.text[:200_000]):
            findings.append(
                with_defaults(
                    {
                        "title": "Invalid input exposed internal exception details",
                        "description": "A malformed request returned stack trace or framework diagnostic information.",
                        "severity": "high",
                        "confidence": "high",
                        "tool": "yashsec-dynamic",
                        "category": "error-information-leakage",
                        "cwe": "CWE-209",
                        "owasp": "A05:2021 Security Misconfiguration",
                        "file_path": invalid_target,
                        "endpoint": path,
                        "evidence": redact_text(invalid_response.text[:1200], auth.secret_values),
                        "remediation": "Use central exception handling and sanitised error responses.",
                    }
                )
            )
    authenticated.close()
    anonymous.close()
    return findings
