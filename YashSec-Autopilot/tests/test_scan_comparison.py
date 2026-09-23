"""Regression tests for coverage-aware scan comparison."""
import pytest

from app.core.scan_comparison import compare_scans


def scan(scan_id, stages, status="completed", profile="quick", repository_id=7):
    return {
        "id": scan_id,
        "repository_id": repository_id,
        "profile": profile,
        "status": status,
        "tool_status": {name: {"status": value} for name, value in stages.items()},
    }


def finding(fingerprint, tool="semgrep", finding_id=1):
    return {
        "id": finding_id,
        "fingerprint": fingerprint,
        "tool": tool,
        "title": fingerprint,
        "severity": "medium",
        "file_path": "app/example.py",
        "line_start": 10,
        "endpoint": None,
        "review_status": "open",
    }


def test_new_persisting_and_not_redetected_are_separated():
    baseline = scan(1, {"semgrep": "completed", "builtin": "completed"})
    latest = scan(2, {"semgrep": "completed", "builtin": "completed"})
    result = compare_scans(
        baseline,
        latest,
        [finding("removed"), finding("shared"), finding("builtin-old", "yashsec-builtin")],
        [finding("added"), finding("shared"), finding("builtin-new", "yashsec-builtin")],
    )
    assert [x["title"] for x in result["new"]] == ["added", "builtin-new"]
    assert [x["title"] for x in result["not_redetected"]] == ["builtin-old", "removed"]
    assert [x["title"] for x in result["persisting"]] == ["shared"]
    assert result["comparable_tools"] == ["builtin", "semgrep"]


def test_missing_stage_cannot_be_used_as_evidence_of_a_fix():
    baseline = scan(5, {"semgrep": "completed", "builtin": "completed"})
    latest = scan(6, {"semgrep": "missing", "builtin": "completed"}, status="completed_partial")
    result = compare_scans(
        baseline, latest,
        [finding("semgrep-vulnerability"), finding("builtin-vulnerability", "yashsec-builtin")],
        [finding("builtin-vulnerability", "yashsec-builtin")],
    )
    assert result["not_redetected"] == []
    assert result["persisting"][0]["title"] == "builtin-vulnerability"
    assert result["unassessed_before"] == 1
    assert result["comparable_tools"] == ["builtin"]


@pytest.mark.parametrize(
    "baseline,latest",
    [
        (scan(1, {"builtin": "completed"}, status="running"), scan(2, {"builtin": "completed"})),
        (scan(1, {"builtin": "completed"}, repository_id=10), scan(2, {"builtin": "completed"})),
        (scan(1, {"builtin": "completed"}, profile="quick"), scan(2, {"builtin": "completed"}, profile="full")),
        (scan(2, {"builtin": "completed"}), scan(1, {"builtin": "completed"})),
    ],
)
def test_invalid_scan_pairs_are_rejected(baseline, latest):
    with pytest.raises(ValueError):
        compare_scans(baseline, latest, [], [])
