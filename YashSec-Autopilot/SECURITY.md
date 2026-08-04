# Security Policy

## Supported release

Security fixes are currently applied to the latest release candidate on the default branch.

## Intended use

YashSec Autopilot is for authorised defensive assessment. Do not use it against repositories, APIs, hosts, accounts, or data without permission.

## Safe defaults

- Source installs bind to `127.0.0.1`.
- Remote dynamic scanning is disabled.
- Startup commands require exact-command review and explicit authorisation.
- ZAP integration uses the baseline workflow by default.
- Secrets detected by Gitleaks are redacted before database storage.
- Remote Ollama is disabled unless explicitly allowed, HTTPS-protected, host-allow-listed, and provided a server-side key.
- Public demo mode is read-only and limited to bundled data.

## Sensitive and client data

Keep private repositories, CVs, logs, tokens, internal documents, and client evidence on an approved local or internal machine. Cloud AI transmits selected context to a third party and must not be enabled without data-owner approval.

## Reporting a vulnerability

Do not open a public issue containing an exploit, credential, private repository content, or client data. Use GitHub's private vulnerability reporting feature when enabled, or contact the repository owner privately. Include the affected version, impact, minimal reproduction, and a redacted suggested fix.

## Secret exposure response

1. Revoke or rotate the credential immediately.
2. Remove it from the working tree.
3. Inspect and rewrite Git history where required.
4. Invalidate caches, deployments, and artifacts containing it.
5. Review audit logs for unauthorised use.
6. Add a regression check that would have caught the exposure.

See [docs/SECURITY_AND_SANITIZATION.md](docs/SECURITY_AND_SANITIZATION.md).
