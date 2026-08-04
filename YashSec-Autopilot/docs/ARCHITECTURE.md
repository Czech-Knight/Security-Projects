# YashSec Autopilot Architecture — v1.0.0 RC1

## 1. Windows desktop release architecture

```text
YashSec Autopilot.exe (Tauri/Rust)
        │
        ├── native Windows window and single-instance lifecycle
        ├── random loopback port selection
        ├── per-launch 64-character transport token
        └── starts and owns YashSecBackend.exe
                    │
                    ▼
          FastAPI on 127.0.0.1:<random-port>
                    │
                    ├── authentication, RBAC and project memberships
                    ├── repository onboarding and deterministic detection
                    ├── scan orchestration and scanner adapters
                    ├── authenticated API profiles and target policy
                    ├── findings, audit, reports and local AI
                    └── SQLite under LocalAppData
```

The desktop shell waits for an authenticated backend health response before opening the main window. API requests from the desktop UI include the per-launch `X-YashSec-Transport` value. Closing the shell terminates the managed backend. The Windows build must still be validated on Windows 11 x64 before this lifecycle is called production-ready.

## 2. Source/development mode

```text
Windows browser
    │  http://127.0.0.1:8787
    ▼
FastAPI + bundled HTML/CSS/JavaScript
```

Source mode intentionally keeps the frontend dependency-free. It is useful for development and regression testing; the target release experience is the Tauri desktop shell.

## 3. Application services

```text
FastAPI application
├── first-run Owner, login, session and step-up authentication
├── deny-by-default permissions and project-level membership checks
├── local folder, Git and safe ZIP repository onboarding
├── stack, startup command, port and OpenAPI detection
├── scan engine
│   ├── built-in scanner
│   ├── Semgrep
│   ├── Gitleaks
│   ├── Trivy
│   ├── safe dynamic checks
│   ├── Schemathesis
│   └── passive OWASP ZAP baseline
├── authenticated API profiles
│   ├── bearer token
│   ├── API-key header/query
│   ├── HTTP Basic
│   ├── cookie
│   └── OAuth client credentials
├── normalised findings and human review
├── tamper-evident audit chain
├── DOCX / HTML / JSON reporting
├── SQLite migration, integrity, backup and restore
└── local AI
    ├── Ollama interactive provider
    └── optional AirLLM worker
```

## 4. Security boundaries

- Normal backend binding is loopback-only.
- The packaged desktop API additionally requires a per-launch transport token.
- Remote dynamic targets are disabled by default and require explicit configuration plus per-request confirmation.
- Repository commands are displayed and approved before execution, parsed without `shell=True`, run with restricted environment inheritance and cleaned up after scan completion.
- Auth-profile secret material is separated from SQLite metadata. Packaged Windows builds use DPAPI; the non-Windows fallback exists for development tests only.
- Scanner output and HTTP context are redacted before persistence.
- Repository content is treated as untrusted data by the AI layer.
- AI cannot execute commands, alter finding status or write source files.

## 5. Data locations

### Packaged Windows build

```text
%LOCALAPPDATA%\YashSec Autopilot\data\yashsec.db
%LOCALAPPDATA%\YashSec Autopilot\data\repositories\
%LOCALAPPDATA%\YashSec Autopilot\data\runtime\
%LOCALAPPDATA%\YashSec Autopilot\data\reports\
%LOCALAPPDATA%\YashSec Autopilot\data\backups\
%LOCALAPPDATA%\YashSec Autopilot\data\secrets\
%LOCALAPPDATA%\YashSec Autopilot\data\logs\
```

### Source mode

By default, source mode uses the repository `data` directory. `YASHSEC_DATA_DIR` can select an isolated path. Runtime data is excluded from the release ZIP.

## 6. Scanner failure and coverage model

Each scanner stage records a separate state such as `waiting`, `running`, `completed`, `missing`, `skipped`, `error` or `cancelled`.

- `completed`: selected required stages completed.
- `completed_partial`: useful evidence exists, but one or more selected stages were unavailable, skipped or failed.
- `failed`: no useful selected stage completed or orchestration failed fatally.
- `cancelled`: cancellation was requested and cleanup completed.

A missing optional tool never turns the whole application into a broken state, and no-finding output is never represented as proof of security.

## 7. Release boundary

The Python source, tests, UI, PyInstaller specification, Tauri source, Inno Setup script and Windows CI workflow are included. Rust/Tauri compilation, packaged-backend lifecycle, Inno installation, upgrade/uninstall behaviour, WebView2 integration and code signing require Windows validation.
