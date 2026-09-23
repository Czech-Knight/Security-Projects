"""Compare evidence across two scans without mistaking missing coverage for remediation."""
from __future__ import annotations

from typing import Any


FINAL_STATES = {"completed", "completed_partial"}


def _stage_for_finding(tool: str) -> str:
    # The built-in scanner writes its own display name rather than its runner key.
    return "builtin" if tool == "yashsec-builtin" else tool


def _completed_tools(scan: dict[str, Any]) -> set[str]:
    return {
        key for key, payload in (scan.get("tool_status") or {}).items()
        if isinstance(payload, dict) and payload.get("status") == "completed"
    }


def _public_finding(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        key: finding.get(key)
        for key in ("id", "title", "severity", "tool", "file_path", "line_start", "endpoint", "review_status")
    }


def compare_scans(
    before: dict[str, Any],
    after: dict[str, Any],
    before_findings: list[dict[str, Any]],
    after_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return evidence changes for completed stages shared by both scans.

    Not re-detected is *not* proof that a vulnerability was fixed. Stages that
    did not finish in both scans must never contribute to that category.
    """
    if before.get("status") not in FINAL_STATES or after.get("status") not in FINAL_STATES:
        raise ValueError("Only finished, usable scans can be compared.")
    if before.get("repository_id") != after.get("repository_id"):
        raise ValueError("Scans must belong to the same repository.")
    if before.get("profile") != after.get("profile"):
        raise ValueError("Scans must use the same scan profile.")
    if int(before["id"]) >= int(after["id"]):
        raise ValueError("The baseline scan must precede the latest scan.")

    common = _completed_tools(before) & _completed_tools(after)
    original = {
        item["fingerprint"]: item
        for item in before_findings
        if _stage_for_finding(str(item.get("tool") or "")) in common
    }
    current = {
        item["fingerprint"]: item
        for item in after_findings
        if _stage_for_finding(str(item.get("tool") or "")) in common
    }
    original_keys, current_keys = set(original), set(current)

    # Non-comparable stages may contain evidence, but cannot be called new/fixed.
    unassessed_before = sum(
        _stage_for_finding(str(item.get("tool") or "")) not in common for item in before_findings
    )
    unassessed_after = sum(
        _stage_for_finding(str(item.get("tool") or "")) not in common for item in after_findings
    )

    def records(keys: set[str], lookup: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        return [_public_finding(lookup[key]) for key in sorted(keys)]

    return {
        "available": True,
        "repository_id": after["repository_id"],
        "profile": after["profile"],
        "baseline_scan_id": before["id"],
        "latest_scan_id": after["id"],
        "comparable_tools": sorted(common),
        "coverage_warning": (
            "Only scanner stages completed in both scans are compared. "
            "Not re-detected findings still require human verification."
        ),
        "new": records(current_keys - original_keys, current),
        "not_redetected": records(original_keys - current_keys, original),
        "persisting": records(original_keys & current_keys, current),
        "unassessed_before": unassessed_before,
        "unassessed_after": unassessed_after,
    }
