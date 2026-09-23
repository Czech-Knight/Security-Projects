"""Turn finished scan summaries into a per-project security trend."""
from __future__ import annotations

from typing import Any


def summarize_scan_history(scans: list[dict[str, Any]]) -> dict[str, Any]:
    """Scans arrive most-recent-first and must belong to one project/profile.

    Trend values are *per scan*, not a count of unique unresolved vulnerabilities.
    Partial coverage is explicitly shown rather than normalized away.
    """
    if not scans:
        return {"available": False, "message": "No finished scans to chart."}
    profile = scans[0]["profile"]
    repo_id = scans[0]["repository_id"]
    points: list[dict[str, Any]] = []
    for scan in reversed(scans[:12]):
        if scan["profile"] != profile or scan["repository_id"] != repo_id:
            raise ValueError("Progress charts require scans of the same project and profile.")
        if scan["status"] not in {"completed", "completed_partial"}:
            raise ValueError("Progress charts only accept finished scans.")
        summary = scan.get("summary") or {}
        tool_status = scan.get("tool_status") or {}
        points.append({
            "scan_id": scan["id"],
            "completed_at": scan.get("completed_at"),
            "critical": int(summary.get("critical") or 0),
            "high": int(summary.get("high") or 0),
            "total": int(summary.get("total") or 0),
            "complete": scan["status"] == "completed" and bool(summary.get("coverage_complete")),
            "completed_tools": sorted(
                key for key, stage in tool_status.items()
                if isinstance(stage, dict) and stage.get("status") == "completed"
            ),
        })
    return {
        "available": True,
        "repository_id": repo_id,
        "profile": profile,
        "points": points,
        "notice": (
            "Counts represent findings in each scan, not unique open vulnerabilities. "
            "Different scanner rules, skipped stages, and partial coverage can change counts."
        ),
    }
