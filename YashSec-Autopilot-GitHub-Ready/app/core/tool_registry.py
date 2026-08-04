from __future__ import annotations

import platform
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from typing import Iterable

from app.core.executables import resolve_executable
from app.core.subprocess_utils import run_captured_command


@dataclass(frozen=True)
class ToolSpec:
    key: str
    name: str
    executables: tuple[str, ...]
    purpose: str
    required: bool
    install_windows: list[str]
    official_url: str
    version_args: tuple[str, ...] = ("--version",)


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        key="git",
        name="Git for Windows",
        executables=("git",),
        purpose="Clone Git repositories and inspect repository metadata.",
        required=False,
        install_windows=["winget install --id Git.Git -e", "Restart the terminal after installation."],
        official_url="https://git-scm.com/install/windows",
    ),
    ToolSpec(
        key="semgrep",
        name="Semgrep Community Edition",
        executables=("semgrep",),
        purpose="Static analysis for insecure coding patterns and common vulnerabilities.",
        required=False,
        install_windows=[".\\.venv\\Scripts\\python.exe -m pip install --upgrade semgrep"],
        official_url="https://docs.semgrep.dev/getting-started/quickstart-ce",
    ),
    ToolSpec(
        key="gitleaks",
        name="Gitleaks",
        executables=("gitleaks",),
        purpose="Detect hard-coded passwords, tokens, keys, and other secrets.",
        required=False,
        install_windows=[
            "Download the Windows x64 archive from the official Releases page.",
            "Extract gitleaks.exe into this project's tools\\bin folder, or add its folder to PATH.",
        ],
        official_url="https://github.com/gitleaks/gitleaks/releases",
    ),
    ToolSpec(
        key="trivy",
        name="Trivy",
        executables=("trivy",),
        purpose="Scan dependencies, filesystems, containers, and infrastructure configuration.",
        required=False,
        install_windows=[
            "Follow the official Windows installation method in Trivy documentation.",
            "Extract trivy.exe into this project's tools\\bin folder, or add its folder to PATH.",
            "After installation, run: trivy --version",
        ],
        official_url="https://trivy.dev/docs/latest/getting-started/installation/",
    ),
    ToolSpec(
        key="schemathesis",
        name="Schemathesis",
        executables=("st", "schemathesis"),
        purpose="Generate API test cases from OpenAPI schemas.",
        required=False,
        install_windows=[".\\.venv\\Scripts\\python.exe -m pip install --upgrade schemathesis"],
        official_url="https://schemathesis.readthedocs.io/en/stable/quick-start/",
    ),
    ToolSpec(
        key="docker",
        name="Docker Desktop",
        executables=("docker",),
        purpose="Run OWASP ZAP and optional isolated services or scan targets.",
        required=False,
        install_windows=[
            "Install Docker Desktop for Windows and enable the WSL 2 backend.",
            "Start Docker Desktop, then verify with: docker version",
        ],
        official_url="https://docs.docker.com/desktop/setup/install/windows-install/",
        version_args=("version", "--format", "{{.Client.Version}}"),
    ),
    ToolSpec(
        key="ollama",
        name="Ollama",
        executables=("ollama",),
        purpose="Recommended low-latency local AI provider for the built-in assistant pane.",
        required=False,
        install_windows=[
            "Install Ollama for Windows from the official site.",
            "Pull a model: ollama pull qwen3:8b",
            "Verify: ollama list",
        ],
        official_url="https://docs.ollama.com/windows",
    ),
    ToolSpec(
        key="node",
        name="Node.js",
        executables=("node",),
        purpose="Start and test Node.js/React repositories when required by the target project.",
        required=False,
        install_windows=["winget install --id OpenJS.NodeJS.LTS -e"],
        official_url="https://nodejs.org/en/download",
    ),
    ToolSpec(
        key="java",
        name="Java",
        executables=("java",),
        purpose="Start and test Java repositories when required by the target project.",
        required=False,
        install_windows=["Install the JDK required by the target repository."],
        official_url="https://adoptium.net/",
    ),
    ToolSpec(
        key="dotnet",
        name=".NET SDK",
        executables=("dotnet",),
        purpose="Start and test .NET repositories when required by the target project.",
        required=False,
        install_windows=["Install the SDK version required by the target repository."],
        official_url="https://dotnet.microsoft.com/download",
    ),
)

_CACHE_TTL_SECONDS = 300.0
_CACHE_LOCK = threading.Lock()
_CACHE: list[dict] | None = None
_CACHE_AT = 0.0


def _find_executable(candidates: Iterable[str]) -> str | None:
    return resolve_executable(candidates)


def _version(executable: str, args: tuple[str, ...]) -> str | None:
    try:
        completed = run_captured_command(
            [executable, *args],
            timeout=4,
            check=False,
        )
        text = (completed.stdout or completed.stderr).strip().splitlines()
        return text[0][:240] if text else None
    except (OSError, subprocess.SubprocessError):
        return None


def _presence_only(spec: ToolSpec) -> dict:
    """Fast, non-blocking startup check: locate the executable but do not run it."""
    executable = _find_executable(spec.executables)
    payload = asdict(spec)
    payload.update(
        {
            "available": executable is not None,
            "path": executable,
            "version": None,
            "platform": platform.platform(),
            "health_state": "not_tested",
        }
    )
    return payload


def inspect_tool(spec: ToolSpec) -> dict:
    executable = _find_executable(spec.executables)
    version = _version(executable, spec.version_args) if executable else None
    payload = asdict(spec)
    payload.update(
        {
            "available": executable is not None,
            "path": executable,
            "version": version,
            "platform": platform.platform(),
            "health_state": "working" if executable and version else ("detected" if executable else "missing"),
        }
    )
    return payload


def _cached_copy() -> list[dict] | None:
    with _CACHE_LOCK:
        if _CACHE is None or time.monotonic() - _CACHE_AT > _CACHE_TTL_SECONDS:
            return None
        return [dict(item) for item in _CACHE]


def inspect_all_tools(*, force: bool = True) -> list[dict]:
    """Inspect tools without making login wait on every third-party CLI.

    force=False is used by login/dashboard and performs only fast executable discovery
    unless a recent full health snapshot is already cached. force=True is used by the
    Tool Manager's explicit 'Test again' action and runs version checks in parallel.
    """
    global _CACHE, _CACHE_AT

    if not force:
        cached = _cached_copy()
        if cached is not None:
            return cached
        return [_presence_only(spec) for spec in TOOLS]

    with ThreadPoolExecutor(max_workers=len(TOOLS), thread_name_prefix="yashsec-tool-check") as pool:
        results = list(pool.map(inspect_tool, TOOLS))

    with _CACHE_LOCK:
        _CACHE = [dict(item) for item in results]
        _CACHE_AT = time.monotonic()
    return results


def get_tool(key: str) -> dict:
    for spec in TOOLS:
        if spec.key == key:
            return inspect_tool(spec)
    raise KeyError(key)
