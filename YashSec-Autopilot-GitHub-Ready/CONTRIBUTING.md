# Contributing

Thank you for helping improve YashSec Autopilot.

## Development setup

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\setup.ps1
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
```

Run the backend with `start.ps1`, or use:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8787
```

## Before a pull request

```powershell
.\.venv\Scripts\python.exe -m compileall -q app airllm_worker
.\.venv\Scripts\python.exe -m pytest -q
node --check app\static\app.js
.\.venv\Scripts\python.exe scripts\repository_hygiene.py
```

Keep changes local-first and deny-by-default. Do not add silent command execution, automatic source modification, unauthorised remote targets, browser-exposed credentials, or claims of complete coverage when a stage was skipped.

New findings should include deterministic evidence, severity rationale, confidence, CWE/OWASP mapping when appropriate, remediation, and tests. AI-generated interpretation must remain visibly separate from scanner-confirmed evidence.

Never commit real tokens, keys, private source, client data, databases, logs, reports, or downloaded scanner binaries.
