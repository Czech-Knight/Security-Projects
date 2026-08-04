from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import httpx

from app.config import RUNTIME_DIR
from app.core.target_policy import safe_request, validate_dynamic_target


_processes: dict[int, subprocess.Popen[Any]] = {}
_log_handles: dict[int, Any] = {}
_lock = threading.Lock()

# Shell-control tokens are never accepted from a detected/user-edited command.
_FORBIDDEN = ("\n", "\r", "&&", "||", "|", ">", "<", "`", "$(", "${")
_ALLOWED_ENV_PREFIXES = (
    "PORT",
    "HOST",
    "NODE_",
    "NPM_",
    "PYTHON",
    "DJANGO_",
    "FLASK_",
    "UVICORN_",
    "ASPNETCORE_",
    "JAVA_",
)


def command_fingerprint(command: str, repo_path: Path) -> str:
    canonical = f"{repo_path.resolve()}\n{command.strip()}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_command(command: str) -> list[str]:
    text = command.strip()
    if not text:
        raise ValueError("Startup command cannot be empty.")
    if any(marker in text for marker in _FORBIDDEN):
        raise ValueError("Shell control operators and command substitution are not allowed.")
    try:
        parts = shlex.split(text, posix=os.name != "nt")
    except ValueError as exc:
        raise ValueError(f"Startup command could not be parsed safely: {exc}") from exc
    cleaned = [part.strip('"') for part in parts if part.strip('"')]
    if not cleaned:
        raise ValueError("Startup command has no executable.")
    return cleaned


def _resolve_command(parts: list[str]) -> list[str]:
    original_executable = parts[0]
    executable = shutil.which(original_executable)
    if executable:
        resolved = executable
    elif Path(original_executable).exists():
        resolved = str(Path(original_executable).resolve())
    else:
        raise ValueError(f"Executable was not found: {original_executable}")

    # Windows package-manager shims such as npm.cmd and npx.cmd must be run via
    # cmd.exe. Keep the user's simple command name (for example `npm`) instead of
    # injecting a quoted absolute path such as C:\Program Files\nodejs\npm.CMD.
    # The latter can be double-escaped by CreateProcess/cmd and fail as
    # `\"C:\Program Files...\" is not recognized`. No shell operators are
    # accepted by _parse_command, and shell=True remains disabled.
    if os.name == "nt" and Path(resolved).suffix.lower() in {".cmd", ".bat"}:
        comspec = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
        command_token = original_executable if not any(sep in original_executable for sep in ("/", "\\")) else resolved
        return [comspec, "/d", "/s", "/c", command_token, *parts[1:]]

    parts[0] = resolved
    return parts


def _safe_environment(overrides: dict[str, str] | None = None) -> dict[str, str]:
    # Keep the variables required by Windows command shims and language runtimes,
    # while excluding arbitrary repository-provided secrets by default.
    base_keys = {
        "PATH",
        "PATHEXT",
        "COMSPEC",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "HOMEDRIVE",
        "HOMEPATH",
        "HOME",
        "LANG",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
    }
    env = {key: value for key, value in os.environ.items() if key.upper() in base_keys}
    for key, value in (overrides or {}).items():
        upper = key.upper()
        if upper in base_keys or upper.startswith(_ALLOWED_ENV_PREFIXES):
            if len(key) <= 120 and len(value) <= 4000:
                env[key] = value
    return env


def _close_log_handle(repository_id: int) -> None:
    with _lock:
        handle = _log_handles.pop(repository_id, None)
    if handle:
        try:
            handle.flush()
            handle.close()
        except OSError:
            pass


def _forget_process(repository_id: int) -> None:
    with _lock:
        _processes.pop(repository_id, None)
    _close_log_handle(repository_id)


def start_repository_process(
    repository_id: int,
    repo_path: Path,
    command: str,
    *,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    repo_path = repo_path.resolve()
    if not repo_path.exists() or not repo_path.is_dir():
        raise ValueError("Repository working directory is unavailable.")

    # Stop the old process before launching the replacement. Starting first can
    # make the new application fail with EADDRINUSE and then leave no process alive.
    with _lock:
        previous = _processes.get(repository_id)
    if previous and previous.poll() is None:
        _terminate_process_tree(previous)
    _forget_process(repository_id)

    parts = _resolve_command(_parse_command(command))
    log_path = RUNTIME_DIR / f"repository-{repository_id}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_handle = log_path.open("a", encoding="utf-8", errors="replace")
    log_handle.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] START {command}\n")
    log_handle.flush()

    kwargs: dict[str, Any] = {
        "cwd": str(repo_path),
        "stdout": log_handle,
        "stderr": subprocess.STDOUT,
        "stdin": subprocess.DEVNULL,
        "shell": False,
        "text": False,
        "env": _safe_environment(environment),
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    else:
        kwargs["start_new_session"] = True

    try:
        process = subprocess.Popen(parts, **kwargs)
    except Exception:
        log_handle.close()
        raise

    with _lock:
        _processes[repository_id] = process
        _log_handles[repository_id] = log_handle

    return {
        "pid": process.pid,
        "log_path": str(log_path),
        "status": "starting",
        "command": parts,
        "command_hash": command_fingerprint(command, repo_path),
    }


def _terminate_process_tree(process: subprocess.Popen[Any]) -> None:
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                timeout=20,
                check=False,
            )
        else:
            os.killpg(process.pid, 15)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, 9)
    except (OSError, subprocess.SubprocessError):
        try:
            process.kill()
        except OSError:
            pass


def stop_repository_process(repository_id: int) -> bool:
    with _lock:
        process = _processes.get(repository_id)
    running = bool(process and process.poll() is None)
    if running and process is not None:
        _terminate_process_tree(process)
    _forget_process(repository_id)
    return running


def stop_all_processes() -> None:
    with _lock:
        identifiers = list(_processes)
    for repository_id in identifiers:
        stop_repository_process(repository_id)


def process_status(repository_id: int) -> dict[str, Any]:
    with _lock:
        process = _processes.get(repository_id)
    log_path = RUNTIME_DIR / f"repository-{repository_id}.log"
    if not process:
        return {"running": False, "pid": None, "return_code": None, "log_path": str(log_path)}
    code = process.poll()
    return {"running": code is None, "pid": process.pid, "return_code": code, "log_path": str(log_path)}


def repository_log_tail(repository_id: int, max_chars: int = 4000) -> str:
    path = RUNTIME_DIR / f"repository-{repository_id}.log"
    try:
        with path.open("rb") as handle:
            size = path.stat().st_size
            handle.seek(max(0, size - max_chars * 2))
            data = handle.read()
        text = data.decode("utf-8", errors="replace")
        return text[-max_chars:].strip()
    except OSError:
        return ""


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.35):
            return True
    except OSError:
        return False


def _probe_url(port: int) -> str | None:
    if not _port_open(port):
        return None
    for scheme in ("http", "https"):
        url = f"{scheme}://127.0.0.1:{port}"
        try:
            validate_dynamic_target(url)
            with httpx.Client(timeout=1.5, verify=False, follow_redirects=False) as client:
                response = safe_request(client, "GET", url, max_redirects=2)
            if response.status_code < 600:
                return url
        except (httpx.HTTPError, ValueError):
            continue
    return None


def wait_for_repository_url(
    repository_id: int,
    port_hints: list[int],
    timeout_seconds: int = 50,
) -> dict[str, Any]:
    """Wait for a local application and stop early when its command exits.

    The returned diagnostic is suitable for scan logs and avoids the previous
    behaviour where YashSec waited the full timeout even after npm had failed.
    """
    valid_hints = [int(p) for p in port_hints if 1 <= int(p) <= 65535]
    # Never attach a scan to an unrelated local service. Use detected ports when
    # available; only fall back to common development ports when detection found none.
    ports = list(dict.fromkeys(valid_hints or [3000, 4000, 5000, 5173, 8000, 8080]))
    deadline = time.monotonic() + max(1, timeout_seconds)
    exit_seen_at: float | None = None

    while time.monotonic() < deadline:
        for port in ports:
            url = _probe_url(port)
            if url:
                return {
                    "url": url,
                    "status": "reachable",
                    "message": f"Discovered {url}",
                    "return_code": None,
                    "log_tail": repository_log_tail(repository_id),
                }

        status = process_status(repository_id)
        if not status["running"] and status["return_code"] is not None:
            if exit_seen_at is None:
                exit_seen_at = time.monotonic()
            # Give a detached child a brief chance to bind, but do not wait 50 s
            # after an obviously failed command.
            if time.monotonic() - exit_seen_at >= 2.0:
                tail = repository_log_tail(repository_id)
                message = f"Repository command exited with code {status['return_code']} before a local URL became reachable."
                if tail:
                    message += f" Last output: {tail[-1200:]}"
                return {
                    "url": None,
                    "status": "exited",
                    "message": message,
                    "return_code": status["return_code"],
                    "log_tail": tail,
                }

        time.sleep(0.75)

    tail = repository_log_tail(repository_id)
    return {
        "url": None,
        "status": "timeout",
        "message": "The repository command remained running, but none of the detected local ports became reachable before the timeout.",
        "return_code": process_status(repository_id).get("return_code"),
        "log_tail": tail,
    }


def discover_local_url(port_hints: list[int], timeout_seconds: int = 45) -> str | None:
    """Backward-compatible port discovery for callers without a tracked process."""
    ports = list(dict.fromkeys(port_hints or [3000, 4000, 5000, 5173, 8000, 8080]))
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        for port in ports:
            url = _probe_url(port)
            if url:
                return url
        time.sleep(1.0)
    return None
