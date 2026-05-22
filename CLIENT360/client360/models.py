from dataclasses import dataclass, asdict
from typing import Dict


@dataclass(frozen=True)
class Finding:
    title: str
    category: str
    severity: str
    asset: str
    evidence: str
    business_impact: str
    recommendation: str
    status: str = "Open"

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)
