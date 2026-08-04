from __future__ import annotations

import re
import time
from pathlib import Path

from app.core.auth_profiles import HttpAuthContext
from app.core.executables import resolve_executable
from app.core.http_redaction import redact_text
from app.core.normalizer import with_defaults
from app.scanners.base import ScannerResult, run_command


def run(
    repo: Path,
    output_dir: Path,
    schema: str,
    api_url: str,
    auth_context: HttpAuthContext | None = None,
) -> ScannerResult:
    executable = resolve_executable(("st", "schemathesis"))
    if not executable:
        return ScannerResult("schemathesis", "missing", [], "Schemathesis is not installed.")
    auth = auth_context or HttpAuthContext()
    raw_path = output_dir / "schemathesis.txt"
    started = time.time()
    command = [executable, "run", schema, "--url", api_url, "--workers", "2", "--max-examples", "25"]
    for name, value in auth.headers.items():
        command.extend(["--header", f"{name}: {value}"])
    if auth.cookies:
        cookie = "; ".join(f"{name}={value}" for name, value in auth.cookies.items())
        command.extend(["--header", f"Cookie: {cookie}"])
    try:
        completed = run_command(command, repo, timeout=1800)
    except Exception as exc:
        return ScannerResult("schemathesis", "error", [], f"Schemathesis failed: {redact_text(str(exc), auth.secret_values)}")
    text = (completed.stdout or "") + "\n" + (completed.stderr or "")
    text = redact_text(text, auth.secret_values)
    raw_path.write_text(text, encoding="utf-8", errors="replace")
    findings: list[dict] = []
    if completed.returncode != 0:
        failure_blocks = re.findall(r"(?is)(?:FAILURES?|ERRORS?).{0,2500}", text)
        evidence = (failure_blocks[0] if failure_blocks else text[-2500:]).strip()
        findings.append(
            with_defaults(
                {
                    "title": "OpenAPI property-based tests reported failures",
                    "description": "Schemathesis generated API test cases that produced one or more failing checks.",
                    "severity": "high",
                    "confidence": "medium",
                    "tool": "schemathesis",
                    "category": "api-contract-fuzzing",
                    "owasp": "API8:2023 Security Misconfiguration",
                    "endpoint": api_url,
                    "evidence": evidence,
                    "remediation": "Review the failing operation and generated reproduction command, fix the API behavior, then rerun the scan.",
                    "raw": {"return_code": completed.returncode, "auth_profile": auth.profile_name},
                }
            )
        )
    return ScannerResult(
        "schemathesis",
        "completed" if completed.returncode in (0, 1) else "error",
        findings,
        f"Schemathesis completed with {len(findings)} summarised failure(s) using profile '{auth.profile_name}'. Full redacted output is retained.",
        str(raw_path),
        time.time() - started,
    )
