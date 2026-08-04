# Windows 11 Quick Start

## Core application — about five minutes after Python is installed

```powershell
cd C:\path\to\YashSec-Autopilot
Set-ExecutionPolicy -Scope Process Bypass
.\setup.ps1
.\start.ps1
```

Open `http://127.0.0.1:8787` and create the first Owner account in the setup wizard. `setup.ps1` never prints or commits a default password.

## First proof that the system works

1. Open **Repositories**.
2. Select **Add repository**.
3. Choose the local folder `sample_targets\vulnerable_demo`.
4. Select **Scan**.
5. Leave **Built-in checks** enabled.
6. Launch the scan.
7. Open **Findings**, review one result, save a status, and export a DOCX report.

That path requires no Semgrep, Docker, AirLLM, or other optional application.

## Add the recommended local AI

1. Install Ollama for Windows.
2. Start Ollama.
3. Run:

```powershell
ollama pull qwen3:8b
```

4. Open **Tools & Setup** and verify that Ollama is ready.
5. Open **AI Assistant**, select a repository, and ask a question.

## Add Python-based scanners

```powershell
.\install-python-tools.ps1
.\doctor.ps1
```

## Troubleshooting

### PowerShell blocks scripts

Use this only for the current terminal:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

### Port 8787 is already used

Change both values:

```text
YASHSEC_PORT=8790
```

in `.env`, then edit the URL in `start.ps1`, or start manually:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8790
```

### A repository startup command fails

Run the command manually in the target repository first. Confirm that dependencies, database services, and environment variables are present. Then paste the corrected command into the scan window.

### Static scan works but API tests are skipped

Supply a local API URL or confirm a detected startup command. Schemathesis additionally requires an OpenAPI file or URL. ZAP requires Docker Desktop.
