from client360.models import Finding
from client360.analyzers.risk_engine import calculate_score, score_label, summarise_findings


def test_calculate_score_reduces_by_severity_points():
    findings = [
        Finding("A", "Cat", "Critical", "asset", "e", "impact", "fix"),
        Finding("B", "Cat", "High", "asset", "e", "impact", "fix"),
    ]
    assert calculate_score(findings) == 60


def test_score_label():
    assert score_label(35) == "Critical"
    assert score_label(55) == "High"
    assert score_label(80) == "Medium"
    assert score_label(95) == "Low"


def test_summarise_findings_includes_all_severities():
    findings = [Finding("A", "Cat", "Low", "asset", "e", "impact", "fix")]
    summary = summarise_findings(findings)
    assert summary["Critical"] == 0
    assert summary["High"] == 0
    assert summary["Medium"] == 0
    assert summary["Low"] == 1
