from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


APP_DIR_NAME = "YashSec Autopilot"
ROOT_DIR = Path(__file__).resolve().parents[1]
PACKAGED = bool(getattr(sys, "frozen", False))
RESOURCE_ROOT = Path(getattr(sys, "_MEIPASS", ROOT_DIR))
ENV_PATH = ROOT_DIR / ".env"


def _load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip().lstrip("\ufeff")
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_env_file(ENV_PATH)


def _default_data_dir() -> Path:
    explicit = os.getenv("YASHSEC_DATA_DIR")
    if explicit:
        return Path(explicit).expanduser().resolve()
    portable = os.getenv("YASHSEC_PORTABLE_MODE", "false").lower() == "true"
    if portable or (not PACKAGED and os.name != "nt"):
        return (ROOT_DIR / "data").resolve()
    if os.name == "nt":
        local_app_data = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA")
        if local_app_data:
            return Path(local_app_data) / APP_DIR_NAME / "data"
    return Path.home() / ".local" / "share" / "yashsec-autopilot"


DATA_DIR = _default_data_dir()
REPOSITORY_DIR = DATA_DIR / "repositories"
REPORT_DIR = DATA_DIR / "reports"
RUNTIME_DIR = DATA_DIR / "runtime"
BACKUP_DIR = DATA_DIR / "backups"
SECRET_DIR = DATA_DIR / "secrets"
LOG_DIR = DATA_DIR / "logs"
STATIC_DIR = RESOURCE_ROOT / "app" / "static"
DB_PATH = DATA_DIR / "yashsec.db"


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("YASHSEC_APP_NAME", "YashSec Autopilot")
    environment: str = os.getenv("YASHSEC_ENV", "development")
    host: str = os.getenv("YASHSEC_HOST", "127.0.0.1")
    port: int = int(os.getenv("YASHSEC_PORT", "8787"))
    transport_token: str = os.getenv("YASHSEC_TRANSPORT_TOKEN", "")
    session_idle_minutes: int = int(os.getenv("YASHSEC_SESSION_IDLE_MINUTES", "60"))
    session_absolute_hours: int = int(os.getenv("YASHSEC_SESSION_ABSOLUTE_HOURS", "12"))
    login_window_minutes: int = int(os.getenv("YASHSEC_LOGIN_WINDOW_MINUTES", "15"))
    login_max_failures: int = int(os.getenv("YASHSEC_LOGIN_MAX_FAILURES", "5"))
    lockout_minutes: int = int(os.getenv("YASHSEC_LOCKOUT_MINUTES", "15"))
    max_scan_workers: int = int(os.getenv("YASHSEC_MAX_SCAN_WORKERS", "2"))
    allow_remote_dynamic_scan: bool = os.getenv("YASHSEC_ALLOW_REMOTE_DYNAMIC_SCAN", "false").lower() == "true"
    demo_mode: bool = os.getenv("YASHSEC_DEMO_MODE", "false").lower() == "true"
    allow_cloud_ai: bool = os.getenv("YASHSEC_ALLOW_CLOUD_AI", "false").lower() == "true"
    cloud_ai_hosts: tuple[str, ...] = tuple(
        host.strip().lower()
        for host in os.getenv("YASHSEC_CLOUD_AI_HOSTS", "ollama.com").split(",")
        if host.strip()
    )
    ai_provider: str = os.getenv("YASHSEC_AI_PROVIDER", "ollama")
    ollama_url: str = os.getenv("YASHSEC_OLLAMA_URL", "http://127.0.0.1:11434")
    ollama_model: str = os.getenv("YASHSEC_OLLAMA_MODEL", "qwen3:8b")
    ollama_api_key: str = os.getenv("OLLAMA_API_KEY", "")
    airllm_url: str = os.getenv("YASHSEC_AIRLLM_URL", "http://127.0.0.1:8765")
    docs_enabled: bool = os.getenv("YASHSEC_DOCS_ENABLED", "false" if PACKAGED else "true").lower() == "true"
    max_request_bytes: int = int(os.getenv("YASHSEC_MAX_REQUEST_BYTES", str(2 * 1024 * 1024)))
    demo_ai_requests_per_hour: int = int(os.getenv("YASHSEC_DEMO_AI_REQUESTS_PER_HOUR", "20"))
    demo_session_requests_per_hour: int = int(os.getenv("YASHSEC_DEMO_SESSION_REQUESTS_PER_HOUR", "30"))

    @property
    def require_transport_token(self) -> bool:
        return bool(self.transport_token)


settings = Settings()

_container_mode = os.getenv("YASHSEC_CONTAINER_MODE", "false").lower() == "true"
_allowed_hosts = {"127.0.0.1", "localhost"} | ({"0.0.0.0"} if _container_mode else set())
if settings.host not in _allowed_hosts:
    raise RuntimeError("YashSec backend may only bind to loopback, except inside the explicit container profile.")

for directory in (DATA_DIR, REPOSITORY_DIR, REPORT_DIR, RUNTIME_DIR, BACKUP_DIR, SECRET_DIR, LOG_DIR):
    directory.mkdir(parents=True, exist_ok=True)
