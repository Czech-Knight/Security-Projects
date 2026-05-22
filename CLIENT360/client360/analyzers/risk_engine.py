from collections import Counter
from typing import Iterable, List, Dict
from client360.models import Finding

SEVERITY_POINTS = {
    "Critical": 25,
    "High": 15,
    "Medium": 8,
    "Low": 3,
}


def calculate_score(findings: Iterable[Finding]) -> int:
    total = sum(SEVERITY_POINTS.get(f.severity, 0) for f in findings)
    return max(0, 100 - total)


def score_label(score: int) -> str:
    if score <= 40:
        return "Critical"
    if score <= 70:
        return "High"
    if score <= 85:
        return "Medium"
    return "Low"


def summarise_findings(findings: Iterable[Finding]) -> Dict[str, int]:
    counter = Counter(f.severity for f in findings)
    return {level: counter.get(level, 0) for level in ["Critical", "High", "Medium", "Low"]}


def category_summary(findings: Iterable[Finding]) -> Dict[str, int]:
    counter = Counter(f.category for f in findings)
    return dict(counter)


def findings_to_rows(findings: Iterable[Finding]) -> List[Dict[str, str]]:
    return [f.to_dict() for f in findings]
