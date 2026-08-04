from __future__ import annotations

import secrets
from collections import Counter
from pathlib import Path
from typing import Any

from app import db
from app.config import ROOT_DIR
from app.core import builtin_scanner
from app.core.security import hash_password


DEMO_USERNAME = "demo-viewer"
DEMO_SEED_VERSION = "2"


def _insert_demo_user(conn: Any, now: str) -> int:
    row = conn.execute("SELECT id FROM users WHERE username=?", (DEMO_USERNAME,)).fetchone()
    if row:
        user_id = int(row["id"])
    else:
        random_unusable_password = secrets.token_urlsafe(48)
        cursor = conn.execute(
            """
            INSERT INTO users(username, password_hash, role, is_active, failed_login_count,
                              password_changed_at, created_at, updated_at)
            VALUES(?,?,'viewer',1,0,?,?,?)
            """,
            (DEMO_USERNAME, hash_password(random_unusable_password), now, now, now),
        )
        user_id = int(cursor.lastrowid)
    viewer_role = conn.execute("SELECT id FROM roles WHERE name='viewer'").fetchone()
    conn.execute("DELETE FROM user_roles WHERE user_id=?", (user_id,))
    conn.execute("INSERT INTO user_roles(user_id, role_id) VALUES(?,?)", (user_id, int(viewer_role["id"])))
    return user_id


def seed_demo_workspace() -> dict[str, int]:
    """Create an idempotent, read-only portfolio workspace from the bundled sample target."""
    now = db.utc_now()
    repo_path = (ROOT_DIR / "sample_targets" / "vulnerable_demo").resolve()
    if not repo_path.exists():
        raise RuntimeError(f"Demo target is missing: {repo_path}")

    with db.connection() as conn:
        user_id = _insert_demo_user(conn, now)
        repo_row = conn.execute("SELECT id FROM repositories WHERE source='bundled-demo-target'").fetchone()
        if repo_row:
            repository_id = int(repo_row["id"])
        else:
            cursor = conn.execute(
                """
                INSERT INTO repositories(name, source_type, source, local_path, default_branch,
                                         detected_stack, startup_candidates, port_hints,
                                         created_by, created_at, updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "Vulnerable Demo API",
                    "local",
                    "bundled-demo-target",
                    str(repo_path),
                    "main",
                    db.json_dump(["Node.js", "Express"]),
                    db.json_dump([{"command": "npm start", "source": "package.json", "confidence": 0.95, "label": "Node.js start script", "notes": "Detected from package.json scripts."}]),
                    db.json_dump([3000]),
                    user_id,
                    now,
                    now,
                ),
            )
            repository_id = int(cursor.lastrowid)

        viewer_role_id = int(conn.execute("SELECT id FROM roles WHERE name='viewer'").fetchone()["id"])
        conn.execute(
            "INSERT OR REPLACE INTO project_memberships(repository_id, user_id, role_id, created_at) VALUES(?,?,?,?)",
            (repository_id, user_id, viewer_role_id, now),
        )

        scan_row = conn.execute(
            "SELECT id FROM scans WHERE repository_id=? AND profile='demo' ORDER BY id DESC LIMIT 1",
            (repository_id,),
        ).fetchone()
        if scan_row:
            scan_id = int(scan_row["id"])
        else:
            findings = builtin_scanner.scan(repo_path)
            counts = Counter(item["severity"] for item in findings)
            tool_status = {"builtin": {"status": "completed", "message": f"{len(findings)} demo finding(s)"}}
            stages = {
                "repository_inspection": {"status": "completed"},
                "builtin": {"status": "completed"},
                "external_scanners": {"status": "skipped", "reason": "Public demo is read-only"},
                "dynamic_testing": {"status": "skipped", "reason": "Disabled in public demo"},
            }
            coverage = {
                "repository_inspection": "completed",
                "builtin": "completed",
                "external_scanners": "skipped",
                "dynamic_testing": "skipped",
            }
            summary = {
                "total": len(findings),
                "critical": counts.get("critical", 0),
                "high": counts.get("high", 0),
                "medium": counts.get("medium", 0),
                "low": counts.get("low", 0),
                "by_severity": dict(counts),
                "coverage_complete": False,
                "demo": True,
            }
            cursor = conn.execute(
                """
                INSERT INTO scans(repository_id, profile, status, selected_tools, tool_status,
                                  stages_json, coverage_json, progress, summary, created_by,
                                  started_at, completed_at, created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    repository_id,
                    "demo",
                    "completed_partial",
                    db.json_dump(["builtin"]),
                    db.json_dump(tool_status),
                    db.json_dump(stages),
                    db.json_dump(coverage),
                    100,
                    db.json_dump(summary),
                    user_id,
                    now,
                    now,
                    now,
                ),
            )
            scan_id = int(cursor.lastrowid)
            for finding in findings:
                conn.execute(
                    """
                    INSERT INTO findings(
                        scan_id, repository_id, fingerprint, title, description, severity, confidence,
                        tool, category, cwe, owasp, file_path, line_start, line_end, function_name,
                        endpoint, evidence, remediation, references_json, raw_json, review_status,
                        reviewer_notes, first_seen_at, last_seen_at, created_at, updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        scan_id,
                        repository_id,
                        finding["fingerprint"],
                        finding["title"],
                        finding["description"],
                        finding["severity"],
                        finding["confidence"],
                        finding["tool"],
                        finding.get("category"),
                        finding.get("cwe"),
                        finding.get("owasp"),
                        finding.get("file_path"),
                        finding.get("line_start"),
                        finding.get("line_end"),
                        finding.get("function_name"),
                        finding.get("endpoint"),
                        finding.get("evidence"),
                        finding.get("remediation"),
                        db.json_dump(finding.get("references") or []),
                        db.json_dump(finding.get("raw") or {}),
                        "open",
                        "Seeded from the bundled intentionally vulnerable demo target.",
                        now,
                        now,
                        now,
                        now,
                    ),
                )

        # Keep seeded metadata current when the demo schema evolves without creating duplicate scans.
        stages = {
            "repository_inspection": {"status": "completed"},
            "builtin": {"status": "completed"},
            "external_scanners": {"status": "skipped", "reason": "Public demo is read-only"},
            "dynamic_testing": {"status": "skipped", "reason": "Disabled in public demo"},
        }
        current_counts = Counter()
        for row in conn.execute("SELECT severity, COUNT(*) AS count FROM findings WHERE scan_id=? GROUP BY severity", (scan_id,)):
            current_counts[str(row["severity"])] = int(row["count"])
        total_findings = sum(current_counts.values())
        coverage = {
            "repository_inspection": "completed",
            "builtin": "completed",
            "external_scanners": "skipped",
            "dynamic_testing": "skipped",
        }
        summary = {
            "total": total_findings,
            "critical": current_counts.get("critical", 0),
            "high": current_counts.get("high", 0),
            "medium": current_counts.get("medium", 0),
            "low": current_counts.get("low", 0),
            "by_severity": dict(current_counts),
            "coverage_complete": False,
            "demo": True,
        }
        conn.execute(
            "UPDATE repositories SET startup_candidates=?, local_path=?, updated_at=? WHERE id=?",
            (
                db.json_dump([{"command": "npm start", "source": "package.json", "confidence": 0.95, "label": "Node.js start script", "notes": "Detected from package.json scripts."}]),
                str(repo_path),
                now,
                repository_id,
            ),
        )
        conn.execute(
            "UPDATE scans SET stages_json=?, coverage_json=?, summary=?, progress=100, status='completed_partial' WHERE id=?",
            (db.json_dump(stages), db.json_dump(coverage), db.json_dump(summary), scan_id),
        )

        conn.execute(
            "INSERT INTO app_settings(key, value, updated_at) VALUES('demo_seed_version',?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (DEMO_SEED_VERSION, now),
        )

    return {"user_id": user_id, "repository_id": repository_id, "scan_id": scan_id}
