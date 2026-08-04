from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from app.config import REPOSITORY_DIR
from app.core.subprocess_utils import run_captured_command


EXCLUDED_ROOTS = {
    Path("C:/Windows"),
    Path("C:/Program Files"),
    Path("C:/Program Files (x86)"),
    Path("/"),
    Path("/etc"),
    Path("/usr"),
    Path("/var"),
}


def slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip()).strip("-.")
    return cleaned[:80] or "repository"


def validate_local_repository(path_value: str) -> Path:
    path = Path(path_value).expanduser().resolve()
    if not path.exists() or not path.is_dir():
        raise ValueError(f"Repository folder does not exist: {path}")
    for blocked in EXCLUDED_ROOTS:
        try:
            if path == blocked.resolve():
                raise ValueError("Select a project repository folder, not an operating-system root folder.")
        except OSError:
            continue
    if len(path.parts) < 2:
        raise ValueError("Repository path is too broad. Select the specific project folder.")
    return path


def clone_repository(url: str, name: str | None = None, branch: str | None = None) -> Path:
    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http", "ssh", "git"} and not url.startswith("git@"):
        raise ValueError("Only Git HTTPS/SSH URLs are supported.")
    if not shutil.which("git"):
        raise RuntimeError("Git is not installed. Open Tools & Setup for installation instructions.")

    repo_name = name or Path(parsed.path).stem or "repository"
    destination = REPOSITORY_DIR / slugify(repo_name)
    if destination.exists():
        suffix = 2
        while (REPOSITORY_DIR / f"{slugify(repo_name)}-{suffix}").exists():
            suffix += 1
        destination = REPOSITORY_DIR / f"{slugify(repo_name)}-{suffix}"

    command = ["git", "clone", "--depth", "1"]
    if branch:
        command.extend(["--branch", branch])
    command.extend([url, str(destination)])
    completed = run_captured_command(command, timeout=600, check=False)
    if completed.returncode != 0:
        safe_error = (completed.stderr or completed.stdout or "Git clone failed").replace(url, "<repository-url>")
        raise RuntimeError(safe_error.strip()[:1200])
    return destination.resolve()


def repository_name_from_path(path: Path) -> str:
    return path.name or "repository"


def extract_zip_repository(archive_path: str | Path, name: str | None = None) -> Path:
    import stat
    import zipfile

    archive = Path(archive_path).expanduser().resolve()
    if not archive.exists() or not archive.is_file() or archive.suffix.lower() != ".zip":
        raise ValueError("Select a valid ZIP archive.")
    if archive.stat().st_size > 1024 * 1024 * 1024:
        raise ValueError("ZIP archive exceeds the 1 GB import limit.")
    repo_name = slugify(name or archive.stem)
    destination = REPOSITORY_DIR / repo_name
    suffix = 2
    while destination.exists():
        destination = REPOSITORY_DIR / f"{repo_name}-{suffix}"
        suffix += 1
    destination.mkdir(parents=True)
    total_size = 0
    try:
        with zipfile.ZipFile(archive) as bundle:
            entries = bundle.infolist()
            if len(entries) > 100_000:
                raise ValueError("ZIP archive contains too many entries.")
            for info in entries:
                total_size += info.file_size
                if total_size > 2 * 1024 * 1024 * 1024:
                    raise ValueError("ZIP archive expands beyond the 2 GB safety limit.")
                normalized = Path(info.filename.replace("\\", "/"))
                if normalized.is_absolute() or ".." in normalized.parts:
                    raise ValueError(f"Unsafe ZIP path detected: {info.filename}")
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ValueError("Symbolic links are not allowed in ZIP imports.")
                target = (destination / normalized).resolve()
                target.relative_to(destination.resolve())
            bundle.extractall(destination)
        children = [child for child in destination.iterdir() if child.name not in {"__MACOSX"}]
        if len(children) == 1 and children[0].is_dir():
            nested = children[0]
            flattened = destination.with_name(destination.name + "-flat")
            nested.rename(flattened)
            shutil.rmtree(destination, ignore_errors=True)
            flattened.rename(destination)
        return destination.resolve()
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
