from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any


@dataclass
class Service:
    port: int
    protocol: str
    state: str
    name: str
    product: str = ""
    version: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Host:
    ip: str
    hostname: str
    status: str
    os_guess: str
    services: List[Service]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["services"] = [service.to_dict() for service in self.services]
        return data


@dataclass
class Finding:
    title: str
    category: str
    severity: str
    asset: str
    evidence: str
    business_impact: str
    recommendation: str
    status: str = "Open"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
