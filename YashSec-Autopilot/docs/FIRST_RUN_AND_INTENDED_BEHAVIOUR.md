# First Run and Intended Behaviour

## 1. Purpose of the first run

The first run establishes a secure local workspace. It does **not** attempt to install every scanner or download an AI model automatically.

The intended sequence is:

1. Show the local-first privacy promise.
2. Create the first local **Owner** account with a password of at least 12 characters.
3. Test optional tools and local AI providers.
4. Explain exactly which capabilities are available and which will be skipped.
5. Enter the dashboard and guide the user to **Add Project**.

There is no default `admin/change-me` account.

## 2. Data locations

Installed Windows builds use these locations:

```text
Database and application data
%LOCALAPPDATA%\YashSec Autopilot\data\

Imported/cloned repositories
%LOCALAPPDATA%\YashSec Autopilot\data\repositories\

Reports
%LOCALAPPDATA%\YashSec Autopilot\data\reports\

Backups
%LOCALAPPDATA%\YashSec Autopilot\data\backups\

Runtime logs
%LOCALAPPDATA%\YashSec Autopilot\data\runtime\

Protected secret blobs
%LOCALAPPDATA%\YashSec Autopilot\data\secrets\
```

Normal upgrades and uninstall preserve this directory. A user must deliberately remove it when a complete data deletion is required.

Development mode uses the repository `data/` directory unless `YASHSEC_DATA_DIR` is set.

## 3. Login and session behaviour

- Passwords are stored using Argon2id when the dependency is available.
- Older PBKDF2 records are verified and upgraded after a successful login.
- Five failed attempts inside the configured window trigger a temporary lockout.
- Session tokens are random and only their SHA-256 hashes are stored.
- A session has both idle and absolute expiration.
- Logout revokes the current session immediately.
- Changing a user's roles revokes that user's existing sessions.

## 4. Role behaviour

### Owner

Application-wide user, role, settings, backup, project and scan administration.

### Security Engineer

Creates and inspects projects, launches scans, manages authenticated API profiles, reviews findings and generates reports for assigned projects.

### Reviewer

Reads assigned projects and findings, adds reviewer notes and performs permitted status changes. High-risk acceptance is separated by permission and step-up authentication.

### Auditor

Read-only access to permitted projects, reports and tamper-evident audit history.

### Viewer

Read-only portfolio and project visibility for explicitly assigned projects.

The backend checks permission and project membership on every protected request. Hiding a UI button is not considered an authorisation control.

## 5. Add Project behaviour

### Local folder

The native or fallback folder picker selects an existing local repository. YashSec stores the path and scans in place; it does not silently copy or modify source code.

### Git repository

YashSec clones using the installed Git executable. Private authentication relies on Git Credential Manager or existing SSH credentials. Tokens are not requested for storage inside the project database.

### ZIP archive

ZIP import extracts into the YashSec repository workspace. The importer rejects:

- path traversal outside the destination;
- symbolic links;
- excessive archive size;
- excessive extracted file count or expanded size.

## 6. Detection confirmation

Repository understanding begins with deterministic inspection of files such as `package.json`, `pyproject.toml`, `manage.py`, Compose files, `pom.xml`, `.csproj`, OpenAPI files and README commands.

The UI shows:

- detected stack;
- candidate command;
- source of the command;
- confidence;
- working directory;
- port hints;
- OpenAPI schema when found.

A command is never executed merely because it was detected. A materially changed command requires fresh confirmation.

## 7. Scan profiles

### Quick

Built-in scanner, Semgrep and Gitleaks. Best for fast developer feedback. Missing optional tools are marked as missing; the built-in scanner still runs.

### Standard

Quick profile plus Trivy dependency/configuration coverage.

### Full

All selected static tools plus approved local API checks, Schemathesis and passive ZAP baseline where the required runtime and schema are available.

### Custom

User-selected stages. The built-in scanner is always included as a stable fallback.

## 8. Runtime and API behaviour

Static stages do not require an API URL.

Dynamic stages require either:

- a supplied local URL; or
- an explicitly approved startup command that produces a reachable local URL.

Default dynamic target policy permits `localhost`, `127.0.0.1` and loopback IPv6. Remote targets remain disabled unless the administrator deliberately sets `YASHSEC_ALLOW_REMOTE_DYNAMIC_SCAN=true`. This environment switch does not replace written authorisation.

## 9. Authenticated API profiles

Per-project profiles support:

- bearer token;
- API key header;
- API key query parameter;
- HTTP Basic;
- session cookie;
- OAuth 2.0 client credentials.

Profile metadata is stored in SQLite. Passwords, tokens, cookies and client secrets are protected separately. Packaged Windows builds use DPAPI tied to the current Windows user. Secrets are never returned to the browser UI.

The **Test profile** operation should call a safe identity or verification endpoint and record status without exposing the credential.

## 10. Live scan behaviour

The stage list is the source of truth. Supported states:

```text
waiting
running
completed
completed_with_warnings
missing
skipped
error / failed
cancelled
```

A scanner failure does not erase independent results. Final status rules:

- `completed`: all selected, required stages completed;
- `completed_partial`: useful evidence exists, but at least one selected stage was missing, skipped or failed;
- `failed`: no useful selected stage completed or a fatal orchestration error occurred;
- `cancelled`: the user requested cancellation and cleanup completed.

No smooth fake progress percentage is used.

## 11. Findings and human review

Evidence appears before AI interpretation. A finding can include file, line, function, endpoint, scanner evidence, CWE/OWASP mapping, confidence and remediation.

Review states:

```text
open
reviewed
false_positive
accepted_risk
fixed
```

Accepted risk requires:

- the correct permission;
- fresh password confirmation;
- a meaningful written reason.

AI cannot change a status.

## 12. Local AI behaviour

Ollama is the default interactive provider. AirLLM is optional.

The assistant:

- retrieves limited repository excerpts;
- excludes common secret files;
- treats repository text as untrusted data;
- distinguishes scanner evidence, repository evidence, interpretation, assumptions and missing information;
- never runs commands;
- never edits files;
- never applies patches;
- never marks findings resolved.

## 13. Reports

DOCX, HTML and JSON reports include scan status, findings and coverage limitations. A partial scan must not be presented as complete assurance. “No findings detected” includes a reminder that this is not proof of security.

## 14. Shutdown and recovery

Closing the desktop shell terminates the managed backend. Target repository processes started by YashSec are terminated during shutdown. On next launch, SQLite integrity and the audit hash chain are checked. Database backups can be created from Settings by authorised users.
