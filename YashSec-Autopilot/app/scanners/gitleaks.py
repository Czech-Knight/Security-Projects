from __future__ import annotations

import time
from pathlib import Path

from app.core.executables import resolve_executable
from app.core.normalizer import gitleaks_findings, parse_json_file
from app.scanners.base import ScannerResult, run_command


def _commands(executable: str, repo: Path, raw_path: Path) -> list[list[str]]:
    return [
        [executable, "dir", str(repo), "--report-format", "json", "--report-path", str(raw_path), "--exit-code", "0", "--no-banner"],
        [executable, "detect", "--source", str(repo), "--report-format", "json", "--report-path", str(raw_path), "--exit-code", "0", "--no-banner"],
    ]


def run(repo: Path, output_dir: Path) -> ScannerResult:
    executable = resolve_executable(("gitleaks",))
    if not executable:
        return ScannerResult("gitleaks", "missing", [], "Gitleaks is not installed.")
    raw_path = output_dir / "gitleaks.json"
    started = time.time()
    errors: list[str] = []
    for command in _commands(executable, repo, raw_path):
        try:
            completed = run_command(command, repo, timeout=600)
        except Exception as exc:
            errors.append(str(exc))
            continue
        if raw_path.exists() or completed.returncode == 0:
            payload = parse_json_file(raw_path, [])
            findings = gitleaks_findings(payload if isinstance(payload, list) else [], repo)
            return ScannerResult(
                "gitleaks",
                "completed",
                findings,
                f"Gitleaks completed with {len(findings)} finding(s).",
                str(raw_path) if raw_path.exists() else None,
                time.time() - started,
            )
        errors.append((completed.stderr or completed.stdout or "Unknown Gitleaks error")[:800])
    return ScannerResult("gitleaks", "error", [], "Gitleaks failed: " + " | ".join(errors)[:1400])
