from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.core.subprocess_utils import run_captured_command


@dataclass
class ScannerResult:
    key: str
    status: str
    findings: list[dict[str, Any]]
    message: str
    raw_path: str | None = None
    duration_seconds: float | None = None


def run_command(
    command: list[str],
    cwd: Path,
    timeout: int,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return run_captured_command(
        command,
        cwd=cwd,
        timeout=timeout,
        check=False,
        env=merged_env,
    )


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
