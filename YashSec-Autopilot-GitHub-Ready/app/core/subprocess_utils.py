from __future__ import annotations

import locale
import os
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


def decode_process_output(value: bytes | str | None) -> str:
    """Decode third-party CLI output without allowing locale errors to crash YashSec."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value

    candidates: list[str] = ["utf-8", "utf-8-sig"]
    preferred = locale.getpreferredencoding(False)
    if preferred:
        candidates.append(preferred)
    if os.name == "nt":
        candidates.extend(["mbcs", "cp437"])

    seen: set[str] = set()
    for encoding in candidates:
        key = encoding.lower()
        if key in seen:
            continue
        seen.add(key)
        try:
            return value.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue

    return value.decode("utf-8", errors="replace")


def run_captured_command(
    command: Sequence[str],
    *,
    cwd: str | Path | None = None,
    timeout: float | None = None,
    check: bool = False,
    env: Mapping[str, str] | None = None,
    **kwargs: Any,
) -> subprocess.CompletedProcess[str]:
    """Run a command in binary mode, then safely decode stdout/stderr.

    Python's text=True uses the Windows ANSI code page by default. Third-party
    security tools often emit UTF-8 or OEM-code-page output, which can trigger
    UnicodeDecodeError in subprocess reader threads. Capturing bytes first keeps
    scanner failures isolated and makes decoding deterministic.
    """
    completed = subprocess.run(
        list(command),
        cwd=str(cwd) if cwd is not None else None,
        capture_output=True,
        text=False,
        timeout=timeout,
        check=check,
        env=dict(env) if env is not None else None,
        **kwargs,
    )
    return subprocess.CompletedProcess(
        args=completed.args,
        returncode=completed.returncode,
        stdout=decode_process_output(completed.stdout),
        stderr=decode_process_output(completed.stderr),
    )
