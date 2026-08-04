from __future__ import annotations

import time
from pathlib import Path

from app.core.executables import resolve_executable
from app.core.normalizer import parse_json_file, semgrep_findings
from app.scanners.base import ScannerResult, run_command


def run(repo: Path, output_dir: Path) -> ScannerResult:
    executable = resolve_executable(("semgrep",))
    if not executable:
        return ScannerResult("semgrep", "missing", [], "Semgrep is not installed.")
    raw_path = output_dir / "semgrep.json"
    started = time.time()
    command = [
        executable,
        "scan",
        "--config",
        "auto",
        "--json",
        "--output",
        str(raw_path),
        "--metrics=on",
        "--exclude",
        "node_modules",
        "--exclude",
        ".venv",
        "--exclude",
        "dist",
        str(repo),
    ]
    try:
        completed = run_command(command, repo, timeout=1200)
    except Exception as exc:
        return ScannerResult("semgrep", "error", [], f"Semgrep failed: {exc}")
    payload = parse_json_file(raw_path, {})
    findings = semgrep_findings(payload, repo)
    status = "completed" if raw_path.exists() else "error"
    message = f"Semgrep completed with {len(findings)} finding(s)."
    if status == "error":
        message = (completed.stderr or completed.stdout or "Semgrep did not produce JSON output.")[:1200]
    return ScannerResult("semgrep", status, findings, message, str(raw_path) if raw_path.exists() else None, time.time() - started)
