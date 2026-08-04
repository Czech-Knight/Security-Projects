# External Tools Installation and Integration Guide

## 1. Integration rule

YashSec must remain functional when every optional tool is missing. The Tool Manager detects capabilities in this order:

1. Windows `PATH`;
2. the directory containing `YashSecBackend.exe`;
3. `YashSecBackend.exe\..\tools\bin`;
4. `%LOCALAPPDATA%\YashSec Autopilot\tools\bin`;
5. development `.venv\Scripts`;
6. repository `tools\bin`.

After installing or copying a binary, restart YashSec or use **Tool Manager → Test again**.

Do not download a binary from an untrusted mirror. Record the source, version and checksum used in a controlled deployment.

## 2. Capability profiles

### Minimum

- YashSec desktop and built-in scanner.
- Git recommended for Git URL import and backup branches.

### Recommended local security profile

- Semgrep
- Gitleaks
- Trivy
- Schemathesis
- Docker Desktop
- OWASP ZAP through the official Docker image
- Ollama

### Target runtime tools

Install only when required by repositories under test:

- Node.js LTS
- Java/JDK
- .NET SDK
- project-specific databases or services

## 3. Git for Windows

Purpose: clone repositories and support Git-aware workflows.

```powershell
winget install --id Git.Git -e
```

Close and reopen PowerShell, then verify:

```powershell
git --version
git config --global --get credential.helper
```

Private HTTPS repositories should use Git Credential Manager. SSH repositories should use an already-approved local SSH key. Do not paste long-lived GitHub tokens into YashSec source or database fields.

## 4. Semgrep Community Edition

Purpose: language-aware static analysis and custom security rules.

Recommended isolated installation for source/development mode:

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade semgrep
.\.venv\Scripts\semgrep.exe --version
```

A globally installed `semgrep` on PATH also works. YashSec executes Semgrep in the selected repository and parses its machine-readable output. Tool failure is isolated to the Semgrep stage.

Official documentation: `https://semgrep.dev/docs/getting-started/quickstart-ce`

## 5. Gitleaks

Purpose: hard-coded token, password, private key and credential detection.

1. Download the Windows x64 archive from the official releases page.
2. Verify the release and checksum where supplied.
3. Extract `gitleaks.exe` into either:

```text
%LOCALAPPDATA%\YashSec Autopilot\tools\bin\
```

or a trusted directory on PATH.

Verify:

```powershell
gitleaks version
```

YashSec redacts recognised secret values before persistent storage. Still treat raw scanner logs as sensitive.

Official project and releases:

- `https://github.com/gitleaks/gitleaks`
- `https://github.com/gitleaks/gitleaks/releases`

## 6. Trivy

Purpose: dependency vulnerabilities, filesystem packages, configuration and infrastructure-as-code risks.

Use an official Windows installation method from Trivy documentation, then verify:

```powershell
trivy --version
trivy filesystem --scanners vuln,misconfig .
```

For a project-local binary, place `trivy.exe` in the same `tools\bin` directory described above.

Trivy downloads vulnerability databases. The first scan can take longer and requires network access unless an approved offline database workflow is configured.

Official installation: `https://trivy.dev/docs/latest/getting-started/installation/`

## 7. Schemathesis

Purpose: generate edge-case and malformed API requests from OpenAPI/Swagger.

Install into the YashSec development virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade schemathesis
.\.venv\Scripts\st.exe --help
```

Requirements for a useful YashSec stage:

- reachable authorised API URL;
- valid OpenAPI path or URL;
- authentication profile when protected endpoints are expected.

Official documentation: `https://schemathesis.readthedocs.io/`

## 8. Docker Desktop

Purpose: run OWASP ZAP and optionally isolate supported target services.

Install Docker Desktop from the official Windows installer, enable the WSL 2 backend, start Docker and verify:

```powershell
docker version
docker run --rm hello-world
```

YashSec does not install or start Docker silently. When Docker is stopped, ZAP is marked missing/error and other scanners continue.

Official documentation: `https://docs.docker.com/desktop/setup/install/windows-install/`

## 9. OWASP ZAP

YashSec uses the official ZAP Docker image and the **baseline** scan adapter. The baseline scan spiders for a limited time and waits for passive analysis; it does not run the full active attack sequence.

Manual verification:

```powershell
docker pull ghcr.io/zaproxy/zaproxy:stable
docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:4000
```

When the target is running on Windows localhost, Docker commonly reaches it through `host.docker.internal`. YashSec's adapter handles its own target mapping; inspect the live log if Docker networking differs.

Do not substitute `zap-full-scan.py` without explicit target ownership, a safety review and a dedicated confirmation flow. Full scan performs active attacks and can run much longer.

Official documentation:

- `https://www.zaproxy.org/docs/docker/baseline-scan/`
- `https://www.zaproxy.org/docs/docker/full-scan/`

## 10. Ollama

See `OLLAMA_AND_AIRLLM_GUIDE.md`. Minimal setup:

```powershell
ollama pull qwen3:8b
ollama list
Invoke-RestMethod http://127.0.0.1:11434/api/tags
```

YashSec default endpoint: `http://127.0.0.1:11434`.

## 11. AirLLM

See `OLLAMA_AND_AIRLLM_GUIDE.md`. AirLLM is experimental, disk-intensive and substantially slower than a smaller Ollama model. It is never a required scanner.

## 12. Node.js

```powershell
winget install --id OpenJS.NodeJS.LTS -e
node --version
npm --version
```

YashSec uses Node only to start a target repository after explicit approval. It does not run `npm install` automatically.

## 13. Java

Install the JDK version required by the target repository. Verify:

```powershell
java -version
```

YashSec can detect Maven and Gradle startup candidates. Review wrapper scripts and dependency installation behaviour before approval.

## 14. .NET SDK

Install the SDK required by the target repository:

```powershell
dotnet --info
```

YashSec can detect `.sln` and `.csproj` targets but cannot infer business-safe runtime configuration in every project.

## 15. Troubleshooting table

| Tool state | Meaning | Correct action |
|---|---|---|
| Installed and working | Executable found and version command succeeded | Run selected profile |
| Missing optional | Tool is not found | Install, add to PATH, or copy to trusted tools directory |
| Incompatible | Executable exists but command/output is unsupported | Install a supported version and retest |
| Connection failed | Service executable exists but service is stopped/unreachable | Start the service and verify endpoint |
| Scanner error | Tool ran but exited unsuccessfully | Read the stage log; other scanners continue |
| Skipped | Required URL/schema/auth input was unavailable | Configure input or accept partial coverage |

## 16. Verification after installation

1. Restart YashSec.
2. Open **Tool Manager**.
3. Confirm executable path and version.
4. Run Quick against `sample_targets/vulnerable_demo`.
5. Run Standard after Trivy is connected.
6. Start the demo API only after reviewing the command.
7. Run Full and confirm missing runtime stages are shown honestly.
