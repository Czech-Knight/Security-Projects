# YashSec Improv — implementation roadmap

This document separates implemented work from proposals. A feature is **not done**
until its API/UI, permission checks, tests and Windows desktop regression checks
have been exercised. The improvement branch is based on `main`, which was
initially created from the repository's existing `yash` branch.

## Current implementation

### Scan comparison (initial implementation; runtime validation pending)
- `app/core/scan_comparison.py` compares findings across the two latest finished
  scans of the same repository and profile.
- Only stages successfully completed in *both* scans contribute to new,
  persisting and not-re-detected categories. Missing coverage is separate.
- `GET /api/repositories/{repository_id}/scan-comparison` enforces existing
  scan-read and project-access permissions.
- Scans UI includes a Compare action and links comparison items to finding detail.
- `tests/test_scan_comparison.py` includes unit/regression cases, which must
  be executed together with the existing suite before marking the feature done.
- Caveat: the existing fingerprint includes title and line number; changes in
  these fields may register as changed findings. "Not re-detected" is never
  automatically treated as a verified fix.

### Security progress dashboard (initial implementation; runtime validation pending)
- `GET /api/repositories/{repository_id}/security-progress` provides a bounded
  history of finished scans of the latest profile under project-access checks.
- Projects UI has a Progress button with per-scan counts, critical/high breakdown
  and a coverage-aware bar chart.
- `tests/test_progress_dashboard.py` covers chronology, counts, coverage and
  incompatible scan histories; test execution is still pending.
- Caveat: the chart counts findings **per scan**, not unique unresolved issues.
  Partial scans are clearly marked, and trend changes are not proof of a fix.

## Requested features — remaining work (feature 15 has an initial implementation)

| Feature | First useful deliverable | Required safety/quality gate |
|---|---|---|
| 1. API Security Testing Studio | Import OpenAPI and run repeatable auth, authorization and validation test cases | Authorized target allow-list; non-destructive defaults; redact secrets |
| 2. Dependency Attack Path Analysis | Connect scanner package findings to repository imports and call sites | Mark unproven reachability as inferred, not confirmed |
| 3. Attack Surface Mapping | Graph discovered endpoints, services, ports and auth boundaries | No unsolicited network probing; evidence source per node |
| 4. Security Test Coverage Map | Mark tested, skipped and untested endpoints and components | Do not claim an endpoint tested from scanner execution alone |
| 5. Request & Response Inspector | Browse redacted HTTP request/response pairs for approved test runs | Mask cookies, auth headers, tokens and sensitive bodies |
| 6. AI Security Testing Assistant | AI writes a proposed test plan from code and schema context | Human confirmation before running any new requests/commands |
| 7. AI Patch Generator | Generate a proposed patch and reviewable diff on a new branch | No auto-merge, protected paths, mandatory rollback and tests |
| 8. AI False Positive Reviewer | Label evidence confidence and request missing context | Only a human may mark a finding false positive |
| 9. Automatic GitHub PR Security Review | Run permitted scans against changed PR files and post results | Least-privilege GitHub credentials; fork/PR trust boundaries |
| 10. Visual Security Workflow Builder | Model approved scan stages as a dependency graph | No arbitrary shell commands; concurrency and cancellation limits |
| 11. Security Alerts | Notify on newly observed critical findings | Deduplicate notifications; opt-in external delivery |
| 12. Isolated Testing Environment | Start disposable target containers and clean them up | Restrict network/privileges, cap CPU/memory, no production writes |
| 13. Custom Scanner Plugin System | Versioned scanner adapter interface with schema validation | Signed/trusted plugin sources, sandbox or explicit install approval |
| 14. OWASP Testing Checklist | Per-project test case status and linked evidence | Manual vs automated results clearly distinguished |
| 15. Security Progress Dashboard | Initial per-project findings trend is implemented; add verified new/persisting/not-re-detected trend integration | Coverage context on every trend; exclude incompatible scans |

## Suggested delivery order

1. Confirm scan comparison and regression tests on Windows and in CI.
2. Build a normalized evidence/event model and endpoint coverage map.
3. Add the OWASP checklist, progress dashboard and notification policies.
4. Implement API studio and redacted request/response inspection.
5. Add the container isolation layer before expanding dynamic automation.
6. Add safe scanner plugins, attack surface/dependency graphs and AI review.
7. Add approval-gated AI patch preview, workflow builder and GitHub PR integration.

The public portfolio demo must remain read-only and unable to target third-party
systems. No remote scanner, patch execution or GitHub write should be enabled
in that mode.

## Release verification

From the `YashSec-Autopilot` directory:

```powershell
.\.venv\Scripts\python.exe -m compileall -q app airllm_worker
.\.venv\Scripts\python.exe -m pytest -q
node --check app\static\app.js
.\.venv\Scripts\python.exe scripts\repository_hygiene.py
```

Also manually verify the scans Compare UI against a fixture with two finished
scans of the same profile, one with a missing Semgrep stage, and a project user
without cross-project permissions. No tests have been claimed to pass solely
because test files were committed.
