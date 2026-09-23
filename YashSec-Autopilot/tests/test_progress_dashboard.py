"""Regression tests for the per-repository security progress dashboard."""
import pytest

from app.core.progress_dashboard import summarize_scan_history


def scan(scan_id, total, *, status="completed", complete=True, profile="quick", repository_id=7):
    return {
        "id": scan_id,
        "repository_id": repository_id,
        "profile": profile,
        "status": status,
        "completed_at": "2026-09-23T00:00:00+00:00",
        "summary": {
            "total": total,
            "critical": total if total > 0 else 0,
            "high": 0,
            "coverage_complete": complete,
        },
        "tool_status": {"builtin": {"status": "completed"}},
    }


def test_progress_order_counts_and_coverage_are_preserved():
    result = summarize_scan_history([
        scan(3, 1, status="completed_partial", complete=False),
        scan(2, 2),
        scan(1, 3),
    ])
    assert result["available"] is True
    assert [item["scan_id"] for item in result["points"]] == [1, 2, 3]
    assert [item["total"] for item in result["points"]] == [3, 2, 1]
    assert [item["complete"] for item in result["points"]] == [True, True, False]
    assert "not unique open vulnerabilities" in result["notice"]


def test_no_scans_returns_explicit_empty_state():
    assert summarize_scan_history([])["available"] is False


@pytest.mark.parametrize(
    "history",
    [
        [scan(3, 1), scan(2, 1, profile="full")],
        [scan(3, 1), scan(2, 1, repository_id=8)],
        [scan(3, 1), scan(2, 1, status="running")],
    ],
)
def test_incompatible_history_is_rejected(history):
    with pytest.raises(ValueError):
        summarize_scan_history(history)
