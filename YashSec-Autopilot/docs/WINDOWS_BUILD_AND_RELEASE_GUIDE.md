# Windows Build and Release Guide

## 1. Deliverable architecture

```text
YashSec Autopilot.exe       Tauri/Rust desktop lifecycle and WebView2 window
YashSecBackend.exe          PyInstaller-packaged FastAPI sidecar
YashSec-Autopilot-Setup-x64.exe  Inno Setup installer
```

On launch, the desktop shell:

1. obtains a free loopback port;
2. creates a random 64-character transport token;
3. starts `YashSecBackend.exe` on `127.0.0.1`;
4. waits for authenticated `/api/health`;
5. opens the UI with the token transferred once through the local launch URL;
6. removes the token from browser history and sends it in `X-YashSec-Transport`;
7. terminates the backend when the desktop process exits.

## 2. Windows build prerequisites

- Windows 11 x64.
- Python 3.11 x64.
- Microsoft C++ Build Tools with **Desktop development with C++**.
- Rust stable MSVC (`rustup`, target `x86_64-pc-windows-msvc`).
- Microsoft Edge WebView2 Runtime.
- Inno Setup 6.
- Git for Windows.

WebView2 is normally already present on supported Windows 10/11 systems, but the development machine should verify it.

## 3. Build commands

From the repository root:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\build-installer.ps1
```

The script performs:

1. creation of `.venv-build`;
2. dependency installation;
3. Python tests;
4. PyInstaller backend build;
5. Rust release build;
6. portable folder assembly;
7. Inno Setup compilation.

## 4. Outputs

```text
dist\backend\YashSecBackend.exe
dist\desktop\YashSec Autopilot.exe
dist\desktop\YashSecBackend.exe
dist\installer\YashSec-Autopilot-Setup-x64.exe
```

## 5. Portable validation

Before installing:

```powershell
cd .\dist\desktop
.\YashSec Autopilot.exe
```

Verify:

- one desktop window opens;
- no browser tab is required;
- first-run setup appears on a clean data directory;
- Task Manager shows the desktop and backend processes;
- closing the window removes the backend process;
- `%LOCALAPPDATA%\YashSec Autopilot\data` is created;
- the backend is not listening on a LAN address.

## 6. Installer validation

Interactive:

```powershell
.\dist\installer\YashSec-Autopilot-Setup-x64.exe
```

Silent test:

```powershell
.\dist\installer\YashSec-Autopilot-Setup-x64.exe /VERYSILENT /NORESTART /SUPPRESSMSGBOXES
```

Verify Start Menu shortcut, optional desktop shortcut, installed files, first launch and Add/Remove Programs entry.

## 7. Upgrade behaviour

The fixed Inno `AppId` makes later installers recognise the installed product. Before upgrading:

1. close YashSec;
2. create a database backup;
3. install the newer build over the same Program Files location;
4. launch and allow schema migration;
5. verify repositories, scans, findings and audit history;
6. confirm user data remains under LocalAppData.

The uninstaller deliberately does not delete LocalAppData.

## 8. GitHub Actions build

Run **Windows Release Candidate** manually or push a version tag. The Windows runner:

- installs Python and Rust;
- runs compile and pytest checks;
- builds both executables;
- starts the packaged backend and calls authenticated health;
- builds the Inno installer;
- performs a silent install smoke test;
- uploads portable ZIP and installer artifacts.

## 9. Code signing

The current project is signing-ready but does not include a private certificate. Production distribution should sign both executables and the installer with an organisation-controlled certificate. Never place a signing private key in the repository.

## 10. Release naming

```text
YashSec-Autopilot-v1.0.0-Portable-x64.zip
YashSec-Autopilot-Setup-x64.exe
SHA256SUMS.txt
RELEASE_NOTES.md
```

## 11. Honest validation statement

A build is not “Windows tested” merely because the source compiles on Linux. Mark it validated only after the Windows workflow or a clean Windows 11 VM has executed the release checklist.
