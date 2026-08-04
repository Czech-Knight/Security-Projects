# Security Hardening Implemented in v1.0.0 RC1

## Security boundary

- Loopback-only backend configuration.
- Per-launch desktop transport token support.
- Production API documentation disabled.
- CSP, no-sniff, no-referrer and restricted browser permissions.
- Request size limit with a dedicated ZIP upload path.

## Identity and access

- First-run owner; no fixed default credential.
- Argon2id and legacy PBKDF2 verification/migration.
- Login throttling and temporary lockout.
- Hashed, idle-expiring and absolutely expiring sessions.
- Logout and role-change revocation.
- Roles, granular permissions and project memberships.
- Server-side permission checks on routes.
- Fresh password grants for accepted risk and backup restore.

## Secret handling

- Auth-profile secrets separated from SQLite metadata.
- Windows DPAPI in packaged builds.
- Encrypted development fallback for non-Windows tests.
- Secret and header redaction before scanner log persistence.
- Known secret files excluded from AI repository indexing.

## Repository and target safety

- Safe ZIP extraction, archive limits and symlink rejection.
- Startup command parsing with `shell=False`.
- Shell control-operator rejection.
- Restricted inherited environment.
- Complete process-tree termination where supported.
- Dynamic targets restricted to loopback by default.
- ZAP baseline, not full active scan.

## Evidence integrity and recovery

- Stable finding fingerprints and deduplication.
- Stage-by-stage coverage record.
- `completed_partial` instead of misleading success.
- Hash-chained tamper-evident audit events.
- SQLite schema versioning and in-place migration.
- Database integrity checks.
- SQLite online backup and validated restore path.

## AI boundary

- Repository content explicitly marked untrusted.
- Prompt-injection resistance instructions.
- Limited retrieved context.
- Evidence, interpretation, assumptions and missing information labels.
- No shell, finding-status or source-edit capability.

## Deferred from stable scope

These remain planned or require additional Windows validation:

- automatic code patch application and rollback UI;
- Windows Job Object resource limits beyond process-tree cleanup;
- external OIDC/SAML SSO;
- organisation-wide central policy management;
- signed automatic update channel;
- remote active scanning workflow;
- centrally verifiable immutable audit service;
- production code-signing certificate.
