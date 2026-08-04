# Release Status — v1.0.0 RC1

## Implemented and tested

- Windows PowerShell setup and launch scripts.
- Local FastAPI server bound to `127.0.0.1`.
- Premium responsive single-page GUI.
- Local username/password login with Argon2id/PBKDF2 migration support, hashed sessions, throttling, and lockout.
- Deny-by-default RBAC with Owner, Security Engineer, Reviewer, Auditor, and Viewer roles.
- Local-folder and Git repository registration.
- Technology-stack, startup-command, port, and OpenAPI detection.
- Explicit approval before any repository startup command runs.
- Built-in static security checks that work without external scanners.
- Semgrep, Gitleaks, Trivy, Schemathesis, and OWASP ZAP adapters.
- Safe dynamic API checks for local/authorised targets.
- Missing-tool diagnostics and installation guidance.
- Background scan queue, progress, raw logs, and failure isolation.
- Finding normalisation, deduplication, evidence, remediation, and metadata.
- Finding review states and reviewer notes.
- Audit log for sensitive application actions.
- Daily/weekly scheduled scans.
- DOCX, HTML, and JSON report export.
- Project-aware AI pane with local Ollama by default, opt-in allow-listed Ollama Cloud, and an optional AirLLM adapter.
- Optional AirLLM worker.
- Intentionally vulnerable local demo repository.
- GitHub Actions quality workflow.

## Automated verification completed

- Python compilation completed for `app` and `airllm_worker`.
- Eighteen automated security and regression tests currently pass, including demo-mode idempotency and remote Ollama boundary checks.
- FastAPI smoke test completed for login, repository registration, scan creation, background completion, findings retrieval, schedule creation, and DOCX report generation.
- Safe dynamic checks completed against the included local demo API.
- JavaScript syntax check completed with Node.js.

## Coverage depends on external configuration

- Semgrep results require Semgrep to be installed.
- Gitleaks results require the Gitleaks executable on PATH.
- Trivy results require Trivy on PATH and its vulnerability database to be available.
- Schemathesis requires the CLI, a reachable API, and an OpenAPI schema.
- ZAP requires Docker Desktop and a reachable local/staging target.
- Ollama chat requires Ollama and a downloaded model.
- AirLLM requires a separate CUDA/PyTorch/model environment and can be slow.
- Private Git cloning relies on Git Credential Manager or SSH already configured on the machine.

## Production hardening still required for real customer deployment

- Organisation-specific authentication/SSO.
- Formal threat modelling and penetration testing of YashSec itself.
- Encrypted database fields or an approved enterprise database.
- Authenticated API scan profiles for the target application's real identity model.
- Project-specific Semgrep/custom rules.
- Formal retention, backup, incident-response, and compliance approval.
- Secure code-signing and installer packaging.
