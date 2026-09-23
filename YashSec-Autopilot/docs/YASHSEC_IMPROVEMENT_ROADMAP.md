# YashSec improvements

Working notes for the `YashSec-Improv` branch. This branch is based on `main`.

## In this branch

### Scan comparison

The Scans page now has a Compare action. The backend compares the latest two finished scans for the same project and scan profile, showing newly detected, recurring and no-longer-detected findings.

Only scanner stages completed in both runs are compared. Findings from missing or failed stages are excluded, so a skipped scan cannot make an issue appear fixed.

Files: `app/core/scan_comparison.py`, `app/main.py`, `app/static/app.js` and `tests/test_scan_comparison.py`.

### Security progress

The Projects page now has a Progress view with finding counts across recent scans. The chart separates complete and partial runs and includes a critical/high breakdown.

Counts are per scan, not a running total of unresolved issues. The comparison view is better suited to checking which findings changed between runs.

Files: `app/core/progress_dashboard.py`, `app/main.py`, `app/static/app.js` and `tests/test_progress_dashboard.py`.

## Next features

| Feature | Scope |
| --- | --- |
| API testing studio | Import an OpenAPI definition; create and run repeatable authentication, access-control and validation checks. |
| Request/response inspector | Show redacted requests and responses from approved test runs. |
| Endpoint coverage | Track tested, skipped and untested API routes. |
| OWASP test checklist | Keep manual test notes, status and evidence with each project. |
| Security alerts | Notify on new critical findings without repeating alerts for the same issue. |
| Attack surface map | Visualize discovered endpoints, services, ports and authentication boundaries. |
| Dependency attack paths | Connect vulnerable packages to their use in application code. |
| Isolated test environment | Run test targets in disposable, resource-limited containers. |
| Scanner plugins | Add a documented adapter interface for approved external scanners. |
| Visual workflows | Configure scan stages, dependencies and approval steps without arbitrary shell execution. |
| GitHub PR review | Scan changed files and report newly introduced findings on authorized pull requests. |
| AI testing assistant | Suggest test cases based on the target's code and API schema; require approval before execution. |
| AI false-positive review | Summarize supporting and missing evidence without changing review status automatically. |
| AI patch preview | Prepare a proposed change and diff on a separate branch; require review and passing tests before applying it. |
| Security progress (follow-up) | Add a reliable new/recurring/resolved trend once finding identities are stable across scans. |

## Development order

1. Run and verify the two views already added, including project permissions and partial-scan cases.
2. Stabilize finding identities across scans and add endpoint-level coverage.
3. Build the API testing studio, request/response inspector and OWASP checklist.
4. Add disposable test environments before expanding dynamic scanning.
5. Add the remaining integrations, graphs, alerts and guided remediation features.

Keep the public demo read-only. Actual scans, outbound requests, code changes and GitHub writes must stay behind the local application's existing permission and approval controls.

## Before merging

Run from `YashSec-Autopilot`:

```powershell
.\.venv\Scripts\python.exe -m compileall -q app airllm_worker
.\.venv\Scripts\python.exe -m pytest -q
node --check app\static\app.js
.\.venv\Scripts\python.exe scripts\repository_hygiene.py
```

Also verify the comparison and progress views in the Windows app. Check a pair of runs where one scanner is unavailable, and confirm users cannot access another project's results.

The new tests have been added but have not yet been run in this environment.
