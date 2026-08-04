# YashSec Autopilot v1.0.0 RC1 Release Notes

## Position

Hardened source release candidate and Windows build kit. Source verification results are recorded in `RELEASE_MANIFEST.txt`. Windows artifacts must pass the supplied Windows 11 validation checklist before stable promotion.

## Improvements from v0.1.1

- First-run Owner instead of default credentials.
- Argon2id password storage and legacy PBKDF2 migration.
- Login throttling, lockout, hashed revocable sessions, idle/absolute expiry, and step-up authentication.
- Deny-by-default RBAC with project membership enforcement.
- Bearer/API-key/Basic/cookie/OAuth client-credentials profiles with protected secrets.
- Redirect-aware target validation and explicit remote-target confirmation.
- Safer ZIP import and `shell=False` startup execution.
- Automatic cleanup of target processes started for a scan.
- Honest stage coverage and `completed_partial` results.
- Hash-chained audit records including user-agent context.
- SQLite schema v6, pre-migration backups, integrity checks, and restore controls.
- Quiet Power hybrid UI following the supplied Windows UX guide.
- PyInstaller, Tauri, Inno Setup, and Windows CI build configuration.

## Known RC1 limitations

- Automatic patch application/rollback is not enabled.
- Authenticated context is applied to safe dynamic checks and Schemathesis, not ZAP baseline.
- Cancellation cannot forcibly interrupt every blocking third-party subprocess yet.
- Windows Job Object quotas, code signing, and signed updates remain future hardening.
- Windows executable/installer validation must be completed on Windows 11 x64.
