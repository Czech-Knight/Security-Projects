# External Tools and Connection Guide

The core YashSec application works with Python alone. Optional tools increase scan coverage and enable local AI assistance.

For complete Windows 11 x64 download, installation, integration, verification, troubleshooting, Ollama, and AirLLM instructions, read:

**[`docs/EXTERNAL_TOOLS_INSTALLATION_AND_INTEGRATION_GUIDE.md`](docs/EXTERNAL_TOOLS_INSTALLATION_AND_INTEGRATION_GUIDE.md)**

## Fast setup

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\setup.ps1
.\install-python-tools.ps1
.\doctor.ps1
.\start.ps1
```

## How binaries are discovered

YashSec checks:

1. Windows `PATH`
2. `.venv\Scripts`
3. `tools\bin`

You can therefore copy standalone `gitleaks.exe` and `trivy.exe` into `tools\bin` without changing the global PATH.

## Recommended local AI

```powershell
ollama pull qwen3:8b
```

Default connection:

```text
http://127.0.0.1:11434
```

AirLLM remains an optional slower worker documented in `airllm_worker/README.md` and in the detailed integration guide.
