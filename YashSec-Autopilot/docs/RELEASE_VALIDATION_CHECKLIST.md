# Release Validation Checklist

## Source and regression

- [ ] `python -m compileall -q app airllm_worker`
- [ ] `python -m pytest -q`
- [ ] Built-in demo detects expected insecure patterns.
- [ ] Repository detection tests pass.
- [ ] RBAC route tests pass.
- [ ] Auth-profile secret does not appear in SQLite.
- [ ] Audit-chain verification passes.
- [ ] Backup creation and integrity check pass.

## Clean Windows 11 x64

- [ ] Install on a machine without Python.
- [ ] Install on a machine without optional scanners.
- [ ] First-run owner creation succeeds.
- [ ] No default account exists.
- [ ] LocalAppData directory is used.
- [ ] Backend binds only to loopback.
- [ ] Another browser without the transport token cannot use the desktop backend API.
- [ ] Desktop closes backend and target child processes.

## Projects and scans

- [ ] Add local folder.
- [ ] Clone public Git repository.
- [ ] Import safe ZIP.
- [ ] Reject traversal ZIP fixture.
- [ ] Show detected command, source and confidence.
- [ ] Refuse unconfirmed command.
- [ ] Quick scan works with all optional tools missing.
- [ ] Standard scan marks missing Trivy as partial coverage.
- [ ] Full scan skips unavailable runtime/schema stages honestly.
- [ ] Cancel preserves completed evidence and stops cleanup.

## Authenticated API

- [ ] Create bearer profile.
- [ ] Confirm secret is absent from API response and database metadata.
- [ ] Test profile against local identity endpoint.
- [ ] Run authenticated safe dynamic checks.
- [ ] Confirm Authorization/Cookie values are redacted from logs.
- [ ] Reject remote URL while remote scanning is disabled.

## Findings and reports

- [ ] Open exact file/line evidence.
- [ ] Reviewer note persists.
- [ ] Accepted risk requires permission, password and reason.
- [ ] AI cannot change finding status.
- [ ] DOCX, HTML and JSON export.
- [ ] Partial coverage warning appears in report.

## AI

- [ ] Ollama unavailable state is clear.
- [ ] Ollama local chat works after model pull.
- [ ] AirLLM unavailable state does not affect scanners.
- [ ] `.env` and private key files are not indexed.
- [ ] Repository prompt injection is treated as data.

## Installer lifecycle

- [ ] Portable executable starts.
- [ ] Inno interactive install succeeds.
- [ ] Silent install succeeds.
- [ ] Start Menu launch succeeds.
- [ ] Upgrade preserves user data.
- [ ] Uninstall removes Program Files binaries.
- [ ] Uninstall preserves LocalAppData.
- [ ] Reinstall reuses/migrates existing data.

## Accessibility and UI

- [ ] 1366×768 usable.
- [ ] 200% Windows text scaling usable.
- [ ] Keyboard focus is visible.
- [ ] Findings can be filtered without mouse-only dependency.
- [ ] Colour is not the only severity/status signal.
- [ ] Reduced-motion mode preserves information.
- [ ] Dark and light themes remain readable.
