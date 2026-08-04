from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Iterable

from app.config import DATA_DIR, ROOT_DIR


def resolve_executable(candidates: Iterable[str]) -> str | None:
    executable_dir = Path(sys.executable).resolve().parent
    search_dirs = [
        executable_dir,
        executable_dir / "tools" / "bin",
        DATA_DIR.parent / "tools" / "bin",
        ROOT_DIR / ".venv" / "Scripts",
        ROOT_DIR / ".venv" / "bin",
        ROOT_DIR / "tools" / "bin",
    ]
    suffixes = [".exe", ".cmd", ".bat", ""] if os.name == "nt" else [""]
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
        for directory in search_dirs:
            for suffix in suffixes:
                path = directory / f"{candidate}{suffix}"
                if path.exists() and path.is_file():
                    return str(path)
    return None
