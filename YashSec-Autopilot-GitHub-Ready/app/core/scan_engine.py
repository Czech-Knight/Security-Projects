from __future__ import annotations

import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

from app import db
from app.config import RUNTIME_DIR, settings
from app.core import builtin_scanner, dynamic_scanner, process_manager
from app.core.auth_profiles import HttpAuthContext, resolve_context
from app.core.http_redaction import redact_text
from app.core.normalizer import with_defaults
from app.scanners import gitleaks, schemathesis, semgrep, trivy, zap
from app.scanners.base import ScannerResult


_executor = ThreadPoolExecutor(max_workers=settings.max_scan_workers, thread_name_prefix="yashsec-scan")


def _write_log(log_path: Path, message: str, secrets: list[str] | None = None) -> None:
    safe = redact_text(message, secrets or [])
    with log_path.open("a", encoding="utf-8", errors="replace") as handle:
        handle.write(f"[{db.utc_now()}] {safe}\n")


def _update_scan(scan_id: int, **updates: Any) -> None:
    if not updates:
        return
    json_fields = {"selected_tools", "tool_status", "summary", "stages_json", "coverage_json"}
    columns = ", ".join(f"{key} = ?" for key in updates)
    values = [db.json_dump(value) if key in json_fields else value for key, value in updates.items()]
    with db.connection() as conn:
        conn.execute(f"UPDATE scans SET {columns} WHERE id = ?", (*values, scan_id))


def _get_scan_and_repo(scan_id: int) -> tuple[dict[str, Any], dict[str, Any]]:
    with db.connection() as conn:
        scan_row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not scan_row:
            raise RuntimeError(f"Scan {scan_id} no longer exists")
        repo_row = conn.execute("SELECT * FROM repositories WHERE id = ?", (scan_row["repository_id"],)).fetchone()
        if not repo_row:
            raise RuntimeError("Repository no longer exists")
    scan = dict(scan_row)
    repo = dict(repo_row)
    scan["selected_tools"] = db.json_load(scan.get("selected_tools"), [])
    repo["port_hints"] = db.json_load(repo.get("port_hints"), [])
    return scan, repo


def _cancel_requested(scan_id: int) -> bool:
    with db.connection() as conn:
        row = conn.execute("SELECT cancellation_requested FROM scans WHERE id=?", (scan_id,)).fetchone()
    return bool(row and row["cancellation_requested"])


def request_cancel(scan_id: int) -> None:
    _update_scan(scan_id, cancellation_requested=1)


def _save_findings(scan_id: int, repository_id: int, findings: list[dict[str, Any]]) -> int:
    now = db.utc_now()
    inserted = 0
    seen: set[str] = set()
    with db.connection() as conn:
        for raw_finding in findings:
            finding = with_defaults(raw_finding)
            if finding["fingerprint"] in seen:
                continue
            seen.add(finding["fingerprint"])
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO findings(
                    scan_id, repository_id, fingerprint, title, description, severity, confidence, tool, category,
                    cwe, owasp, file_path, line_start, line_end, function_name, endpoint, evidence, remediation,
                    references_json, raw_json, review_status, reviewer_notes, first_seen_at, last_seen_at, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    scan_id, repository_id, finding["fingerprint"], finding["title"], finding["description"],
                    finding["severity"], finding.get("confidence", "medium"), finding["tool"], finding.get("category"),
                    finding.get("cwe"), finding.get("owasp"), finding.get("file_path"), finding.get("line_start"),
                    finding.get("line_end"), finding.get("function_name"), finding.get("endpoint"),
                    str(finding.get("evidence") or "")[:10_000], finding.get("remediation"),
                    db.json_dump(finding.get("references") or []), db.json_dump(finding.get("raw") or {}),
                    "open", "", now, now, now, now,
                ),
            )
            if cursor.rowcount:
                inserted += 1
    return inserted


def _result_payload(result: ScannerResult) -> dict[str, Any]:
    return {
        "status": result.status,
        "message": result.message,
        "raw_path": result.raw_path,
        "duration_seconds": round(result.duration_seconds or 0, 2),
        "finding_count": len(result.findings),
    }


def _run_builtin(repo_path: Path, output_dir: Path) -> ScannerResult:
    findings = builtin_scanner.scan(repo_path)
    return ScannerResult("builtin", "completed", findings, f"Built-in checks completed with {len(findings)} finding(s).")


def _run_dynamic(repo_path: Path, output_dir: Path, api_url: str, schema: str | None, auth: HttpAuthContext) -> ScannerResult:
    try:
        findings = dynamic_scanner.run_safe_dynamic_checks(repo_path, api_url, schema, auth)
        return ScannerResult(
            "dynamic", "completed", findings,
            f"Safe dynamic checks completed with {len(findings)} finding(s) using profile '{auth.profile_name}'."
        )
    except Exception as exc:
        return ScannerResult("dynamic", "error", [], f"Safe dynamic checks failed: {redact_text(str(exc), auth.secret_values)}")


def _summary(scan_id: int, tool_status: dict[str, Any]) -> dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    with db.connection() as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) AS count FROM findings WHERE scan_id = ? GROUP BY severity", (scan_id,)
        ).fetchall()
    for row in rows:
        counts[row["severity"]] = row["count"]
    completed = [key for key, value in tool_status.items() if value.get("status") == "completed"]
    unavailable = [key for key, value in tool_status.items() if value.get("status") in {"missing", "skipped", "error"}]
    total = sum(counts.values())
    weighted = counts["critical"] * 25 + counts["high"] * 12 + counts["medium"] * 5 + counts["low"]
    score = max(0, 100 - min(100, weighted))
    return {
        **counts,
        "total": total,
        "security_score": score,
        "completed_tools": completed,
        "unavailable_tools": unavailable,
        "coverage_complete": bool(completed) and not unavailable,
        "message": "No findings detected is not proof of complete security." if total == 0 else None,
    }


def _coverage(tool_status: dict[str, Any], auth: HttpAuthContext) -> dict[str, Any]:
    return {
        "source_static": (tool_status.get("builtin") or {}).get("status", "not_selected"),
        "language_static": (tool_status.get("semgrep") or {}).get("status", "not_selected"),
        "secrets": (tool_status.get("gitleaks") or {}).get("status", "not_selected"),
        "dependencies": (tool_status.get("trivy") or {}).get("status", "not_selected"),
        "runtime_safe": (tool_status.get("dynamic") or {}).get("status", "not_selected"),
        "openapi_fuzzing": (tool_status.get("schemathesis") or {}).get("status", "not_selected"),
        "zap_baseline": (tool_status.get("zap") or {}).get("status", "not_selected"),
        "authenticated_profile": auth.public_summary(),
    }


def submit_scan(scan_id: int) -> None:
    _executor.submit(_execute_scan, scan_id)


def _execute_scan(scan_id: int) -> None:
    log_path = RUNTIME_DIR / f"scan-{scan_id}.log"
    tool_status: dict[str, Any] = {}
    stages: dict[str, Any] = {}
    auth = HttpAuthContext()
    runtime_started_by_scan = False
    repository_id: int | None = None
    try:
        scan, repo = _get_scan_and_repo(scan_id)
        repository_id = int(repo["id"])
        repo_path = Path(repo["local_path"]).resolve()
        output_dir = RUNTIME_DIR / f"scan-{scan_id}"
        output_dir.mkdir(parents=True, exist_ok=True)
        if scan.get("auth_profile_id"):
            auth = resolve_context(int(scan["auth_profile_id"]))
        _update_scan(
            scan_id,
            status="running",
            progress=0,
            started_at=db.utc_now(),
            log_path=str(log_path),
            error=None,
            stages_json=stages,
            cancellation_requested=0,
        )
        _write_log(log_path, f"Starting scan for {repo_path}; auth profile={auth.profile_name}", auth.secret_values)

        api_url = scan.get("api_url")
        if api_url:
            from app.core.target_policy import validate_dynamic_target
            validate_dynamic_target(api_url)
        if not api_url and scan.get("startup_command"):
            stages["runtime_start"] = {"status": "running", "message": "Starting approved repository command"}
            _update_scan(scan_id, stages_json=stages)
            _write_log(log_path, f"Starting approved repository command: {scan['startup_command']}")
            try:
                process_manager.start_repository_process(repo["id"], repo_path, scan["startup_command"])
                runtime_started_by_scan = True
                runtime_probe = process_manager.wait_for_repository_url(
                    repo["id"], repo.get("port_hints") or [], timeout_seconds=50
                )
                api_url = runtime_probe.get("url")
                if api_url:
                    _update_scan(scan_id, api_url=api_url)
                    stages["runtime_start"] = {"status": "completed", "message": f"Discovered {api_url}"}
                    _write_log(log_path, f"Discovered local application URL: {api_url}")
                elif runtime_probe.get("status") == "exited":
                    message = str(runtime_probe.get("message") or "Repository command exited before startup completed.")
                    stages["runtime_start"] = {"status": "failed", "message": message}
                    _write_log(log_path, f"Runtime startup failed: {message}")
                    _write_log(log_path, "Static checks will continue; dynamic stages will be skipped.")
                else:
                    message = str(runtime_probe.get("message") or "No reachable local URL discovered")
                    stages["runtime_start"] = {"status": "completed_with_warnings", "message": message}
                    _write_log(log_path, f"{message} Static checks will continue.")
            except Exception as exc:
                stages["runtime_start"] = {"status": "failed", "message": str(exc)}
                _write_log(log_path, f"Startup command failed: {exc}")
            _update_scan(scan_id, stages_json=stages)

        selected = list(scan.get("selected_tools") or ["builtin", "semgrep", "gitleaks", "trivy"])
        if "builtin" not in selected:
            selected.insert(0, "builtin")

        runners: list[tuple[str, Callable[[], ScannerResult]]] = []
        for key in selected:
            stages[key] = {"status": "waiting", "message": "Waiting"}
            if key == "builtin":
                runners.append((key, lambda rp=repo_path, od=output_dir: _run_builtin(rp, od)))
            elif key == "semgrep":
                runners.append((key, lambda rp=repo_path, od=output_dir: semgrep.run(rp, od)))
            elif key == "gitleaks":
                runners.append((key, lambda rp=repo_path, od=output_dir: gitleaks.run(rp, od)))
            elif key == "trivy":
                runners.append((key, lambda rp=repo_path, od=output_dir: trivy.run(rp, od)))
            elif key == "dynamic":
                if api_url:
                    runners.append((key, lambda rp=repo_path, od=output_dir, url=api_url, schema=scan.get("openapi_path"), ctx=auth: _run_dynamic(rp, od, url, schema, ctx)))
                else:
                    tool_status[key] = {"status": "skipped", "message": "No API URL was supplied or discovered.", "finding_count": 0}
                    stages[key] = dict(tool_status[key])
            elif key == "schemathesis":
                if api_url and scan.get("openapi_path"):
                    runners.append((key, lambda rp=repo_path, od=output_dir, schema=scan["openapi_path"], url=api_url, ctx=auth: schemathesis.run(rp, od, schema, url, ctx)))
                else:
                    tool_status[key] = {"status": "skipped", "message": "Schemathesis requires an API URL and OpenAPI schema.", "finding_count": 0}
                    stages[key] = dict(tool_status[key])
            elif key == "zap":
                if api_url:
                    runners.append((key, lambda rp=repo_path, od=output_dir, url=api_url: zap.run(rp, od, url)))
                else:
                    tool_status[key] = {"status": "skipped", "message": "OWASP ZAP requires a reachable URL.", "finding_count": 0}
                    stages[key] = dict(tool_status[key])

        _update_scan(scan_id, stages_json=stages, tool_status=tool_status)
        total_steps = max(1, len(runners))
        for index, (key, runner) in enumerate(runners, start=1):
            if _cancel_requested(scan_id):
                stages[key] = {"status": "cancelled", "message": "Cancelled before execution"}
                for pending, _ in runners[index:]:
                    stages[pending] = {"status": "cancelled", "message": "Cancelled"}
                _update_scan(
                    scan_id,
                    status="cancelled",
                    progress=int((index - 1) / total_steps * 100),
                    stages_json=stages,
                    tool_status=tool_status,
                    summary=_summary(scan_id, tool_status),
                    coverage_json=_coverage(tool_status, auth),
                    completed_at=db.utc_now(),
                )
                _write_log(log_path, "Scan cancelled by user; completed results were preserved.")
                return
            stages[key] = {"status": "running", "message": f"Running {key}"}
            _update_scan(scan_id, progress=int((index - 1) / total_steps * 90), stages_json=stages, tool_status=tool_status)
            _write_log(log_path, f"Running {key}")
            try:
                result = runner()
            except Exception as exc:
                result = ScannerResult(key, "error", [], f"Unhandled scanner error: {redact_text(str(exc), auth.secret_values)}")
            inserted = _save_findings(scan_id, repo["id"], result.findings)
            payload = _result_payload(result)
            payload["inserted_count"] = inserted
            tool_status[key] = payload
            stage_status = result.status
            if result.status == "completed" and result.message.lower().find("warning") >= 0:
                stage_status = "completed_with_warnings"
            stages[key] = {**payload, "status": stage_status}
            _write_log(log_path, f"{key}: {result.status}; {result.message}", auth.secret_values)
            _update_scan(scan_id, progress=int(index / total_steps * 90), stages_json=stages, tool_status=tool_status)

        stages["normalisation"] = {"status": "completed", "message": "Findings normalised and deduplicated"}
        summary = _summary(scan_id, tool_status)
        completed_count = len(summary["completed_tools"])
        unavailable_count = len(summary["unavailable_tools"])
        if completed_count == 0:
            final_status = "failed"
        elif unavailable_count:
            final_status = "completed_partial"
        else:
            final_status = "completed"
        _update_scan(
            scan_id,
            status=final_status,
            progress=100,
            tool_status=tool_status,
            stages_json=stages,
            coverage_json=_coverage(tool_status, auth),
            summary=summary,
            completed_at=db.utc_now(),
        )
        _write_log(log_path, f"Scan finished with status={final_status}; summary={summary}")
    except Exception as exc:
        error = f"{exc}\n{traceback.format_exc()}"
        _write_log(log_path, error, auth.secret_values)
        _update_scan(
            scan_id,
            status="failed",
            progress=100,
            tool_status=tool_status,
            stages_json=stages,
            coverage_json=_coverage(tool_status, auth),
            error=redact_text(str(exc), auth.secret_values)[:3000],
            completed_at=db.utc_now(),
            summary=_summary(scan_id, tool_status),
        )
    finally:
        if runtime_started_by_scan and repository_id is not None:
            stopped = process_manager.stop_repository_process(repository_id)
            stages["runtime_cleanup"] = {
                "status": "completed",
                "message": "Scan-started repository process was stopped." if stopped else "No running repository process remained to stop.",
            }
            try:
                _update_scan(scan_id, stages_json=stages)
                _write_log(log_path, stages["runtime_cleanup"]["message"], auth.secret_values)
            except Exception:
                pass
