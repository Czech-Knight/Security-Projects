# Security and Sanitisation Report

## Scope

This report documents the repository-hygiene work applied before packaging YashSec Autopilot for GitHub. It is not a guarantee that future edits are secret-free; run the included checks before every release.

## Removed from the supplied archive

- project virtual environment and downloaded Python packages;
- Python bytecode, pytest caches, and build caches;
- local `.env` configuration;
- runtime SQLite databases and database sidecars;
- local logs, reports, backups, cloned repositories, and secret-store contents;
- bundled third-party scanner executables;
- personal command/history notes;
- generated runtime state and machine-specific paths where they were not required documentation.

The source package retains empty runtime folders using `.gitkeep` so a fresh clone has the expected layout.

## Credential handling after sanitisation

- `.env` is ignored. Only `.env.example` is tracked.
- `setup.ps1` creates `.env` from the safe example and does not create a default account password.
- The first Owner account is created interactively during first run.
- GitHub credentials are not stored by YashSec.
- Authentication-profile secrets are stored separately from normal profile metadata.
- `OLLAMA_API_KEY` is accepted only as a server environment secret and is never returned by the settings API.
- Demo viewer credentials are not hard-coded. A random unusable password is generated internally and access is granted through a restricted demo-session endpoint.

## Repository protections

`.gitignore` excludes virtual environments, all `.env` variants except `.env.example`, private-key formats, databases, logs, runtime data, downloaded tools, desktop build output, and editor files.

`.dockerignore` prevents local configuration, tests, documentation archives, build output, Git metadata, runtime data, and downloaded tools from entering the image build context when they are not required.

`scripts/repository_hygiene.py` checks for prohibited tracked paths, oversized files, common high-confidence credential formats, private-key headers, and personal home-directory paths.

CI runs compilation, tests, JavaScript syntax checking, and repository hygiene. CodeQL and Dependabot configuration are also included.

## Intentional vulnerable data

`sample_targets/vulnerable_demo` is intentionally insecure and exists only to demonstrate scanner behaviour. Its values are labelled as demo-only placeholders. Findings from that directory are expected and must not be copied into a real application.

## Public demo controls

Public demo mode is read-only and seeds only the bundled target. It disables arbitrary repository ingestion, process execution, dynamic target access, scan creation, and administrative actions through RBAC and demo-specific startup behaviour.

A public deployment must use:

```dotenv
YASHSEC_DEMO_MODE=true
YASHSEC_ALLOW_REMOTE_DYNAMIC_SCAN=false
```

Do not publish local mode directly to the internet.

## Release checklist

```text
[ ] Delete local .env before packaging
[ ] Delete .venv and caches before packaging
[ ] Confirm data folders contain only .gitkeep
[ ] Confirm tools/bin contains only .gitkeep
[ ] Run scripts/repository_hygiene.py
[ ] Run tests and compileall
[ ] Inspect git status and git diff --cached
[ ] Search Git history after the first commit if any secret was ever staged
[ ] Rotate any credential that may have appeared in an earlier repository/history
[ ] Verify the deployed browser never receives OLLAMA_API_KEY
```

## Important limitation

A clean working tree does not erase a secret from existing Git history. This package is prepared as a new clean repository. When integrating it into an older repository, inspect and, where necessary, rewrite history and rotate the affected credential.
