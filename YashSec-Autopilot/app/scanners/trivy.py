from __future__ import annotations

import time
from pathlib import Path

from app.core.executables import resolve_executable
from app.core.normalizer import parse_json_file, trivy_findings
from app.scanners.base import ScannerResult, run_command


def run(repo: Path, output_dir: Path) -> ScannerResult:
    executable = resolve_executable(("trivy",))
    if not executable:
        return ScannerResult("trivy", "missing", [], "Trivy is not installed.")
    raw_path = output_dir / "trivy.json"
    started = time.time()
    command = [
        executable,
        "fs",
        "--scanners",
        "vuln,misconfig",
        "--format",
        "json",
        "--output",
        str(raw_path),
        "--skip-dirs",
        "node_modules",
        "--skip-dirs",
        ".venv",
        "--skip-dirs",
        ".git",
        str(repo),
    ]
    try:
        completed = run_command(command, repo, timeout=1800)
    except Exception as exc:
        return ScannerResult("trivy", "error", [], f"Trivy failed: {exc}")
    if not raw_path.exists():
        return ScannerResult("trivy", "error", [], (completed.stderr or completed.stdout or "Trivy did not produce JSON output")[:1200])
    findings = trivy_findings(parse_json_file(raw_path, {}))
    return ScannerResult(
        "trivy", "completed", findings, f"Trivy completed with {len(findings)} finding(s).", str(raw_path), time.time() - started
    )
