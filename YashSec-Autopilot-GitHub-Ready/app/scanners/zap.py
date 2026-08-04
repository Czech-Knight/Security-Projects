from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from app.core.executables import resolve_executable
from app.core.normalizer import with_defaults
from app.scanners.base import ScannerResult, run_command


RISK_MAP = {"3": "high", "2": "medium", "1": "low", "0": "info"}


def _docker_target(url: str) -> str:
    parsed = urlparse(url)
    if parsed.hostname in {"127.0.0.1", "localhost"}:
        netloc = "host.docker.internal"
        if parsed.port:
            netloc += f":{parsed.port}"
        return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
    return url


def _parse(path: Path) -> list[dict]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return []
    findings: list[dict] = []
    for site in payload.get("site", []):
        for alert in site.get("alerts", []):
            instances = alert.get("instances") or [{}]
            instance = instances[0]
            findings.append(
                with_defaults(
                    {
                        "title": alert.get("name") or alert.get("alert") or "OWASP ZAP alert",
                        "description": alert.get("desc") or "ZAP detected a web application security concern.",
                        "severity": RISK_MAP.get(str(alert.get("riskcode")), alert.get("riskdesc", "medium").split()[0]),
                        "tool": "owasp-zap",
                        "category": alert.get("pluginid"),
                        "cwe": f"CWE-{alert.get('cweid')}" if alert.get("cweid") not in (None, "-1", -1) else None,
                        "owasp": alert.get("wascid"),
                        "file_path": instance.get("uri"),
                        "evidence": instance.get("evidence") or instance.get("param") or alert.get("otherinfo"),
                        "remediation": alert.get("solution") or "Apply the ZAP recommendation and verify through retesting.",
                        "references": [alert.get("reference")] if alert.get("reference") else [],
                        "raw": alert,
                    }
                )
            )
    return findings


def run(repo: Path, output_dir: Path, api_url: str) -> ScannerResult:
    docker = resolve_executable(("docker",))
    if not docker:
        return ScannerResult("zap", "missing", [], "Docker Desktop is required for the packaged OWASP ZAP baseline scan.")
    raw_path = output_dir / "zap.json"
    html_path = output_dir / "zap.html"
    started = time.time()
    mount = f"{output_dir.resolve()}:/zap/wrk/:rw"
    command = [
        docker, "run", "--rm", "-v", mount, "-t", "ghcr.io/zaproxy/zaproxy:stable",
        "zap-baseline.py", "-t", _docker_target(api_url), "-J", raw_path.name, "-r", html_path.name, "-I",
    ]
    try:
        completed = run_command(command, repo, timeout=1800)
    except Exception as exc:
        return ScannerResult("zap", "error", [], f"OWASP ZAP failed: {exc}")
    if not raw_path.exists():
        return ScannerResult("zap", "error", [], (completed.stderr or completed.stdout or "ZAP did not produce a report")[-1800:])
    findings = _parse(raw_path)
    return ScannerResult(
        "zap", "completed", findings, f"OWASP ZAP baseline completed with {len(findings)} alert(s).", str(raw_path), time.time() - started
    )
