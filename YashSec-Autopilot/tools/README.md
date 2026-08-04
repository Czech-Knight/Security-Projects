# Project-local external binaries

Place optional Windows executables in `tools/bin` when you do not want to modify the global Windows `PATH`.

Supported examples:

- `gitleaks.exe`
- `trivy.exe`

YashSec searches in this order:

1. The current process `PATH`
2. The project virtual environment (`.venv/Scripts` on Windows)
3. `tools/bin` inside this project

After adding a binary, restart YashSec and run:

```powershell
.\doctor.ps1
```

Do not commit third-party binaries to a public GitHub repository unless their licences and your repository policy explicitly permit it. The `tools/bin` directory is intended for local use.
