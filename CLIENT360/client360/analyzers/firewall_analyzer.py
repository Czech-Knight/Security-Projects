from typing import List
import pandas as pd
from client360.models import Finding

DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 27017}
ADMIN_PORTS = {22: "SSH", 3389: "RDP", 5900: "VNC"}
PUBLIC_SOURCES = {"0.0.0.0/0", "Any", "any", "*", "Internet"}


def _port_to_int(value) -> int | None:
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def analyze_firewall_rules(rules: pd.DataFrame) -> List[Finding]:
    findings: List[Finding] = []
    required_columns = {"rule_id", "source", "destination", "port", "protocol", "action", "description"}
    missing = required_columns.difference(rules.columns)
    if missing:
        raise ValueError(f"Firewall data missing columns: {sorted(missing)}")

    for _, row in rules.iterrows():
        rule_id = str(row["rule_id"])
        source = str(row["source"]).strip()
        destination = str(row["destination"]).strip()
        action = str(row["action"]).strip().lower()
        description = str(row["description"]).strip()
        port = _port_to_int(row["port"])

        if action == "allow" and source in PUBLIC_SOURCES and destination in {"Any", "any", "*"}:
            findings.append(Finding(
                title="Overly broad firewall allow rule",
                category="Firewall",
                severity="Critical",
                asset=f"Firewall rule {rule_id}",
                evidence=f"Source {source} to destination {destination} is allowed.",
                business_impact="Any-to-any allow rules can bypass segmentation and expose internal services.",
                recommendation="Replace broad allow rules with least-privilege source, destination and port combinations.",
            ))

        if action == "allow" and source in PUBLIC_SOURCES and port in ADMIN_PORTS:
            findings.append(Finding(
                title=f"Public {ADMIN_PORTS[port]} allowed by firewall",
                category="Firewall",
                severity="Critical" if port == 3389 else "High",
                asset=f"Firewall rule {rule_id}",
                evidence=f"Rule allows port {port} from {source}.",
                business_impact="Public administrative access increases the chance of brute-force and exploitation attempts.",
                recommendation="Restrict admin access to VPN or trusted management IP ranges.",
            ))

        if action == "allow" and source in PUBLIC_SOURCES and port in DATABASE_PORTS:
            findings.append(Finding(
                title="Database port exposed through firewall",
                category="Firewall",
                severity="Critical",
                asset=f"Firewall rule {rule_id}",
                evidence=f"Rule allows database-related port {port} from {source}.",
                business_impact="Public database exposure can lead to unauthorised data access or ransomware risk.",
                recommendation="Block public database access and require private network or application-tier access only.",
            ))

        if description.lower() in {"", "nan", "none"}:
            findings.append(Finding(
                title="Firewall rule missing description",
                category="Firewall Documentation",
                severity="Low",
                asset=f"Firewall rule {rule_id}",
                evidence="Description field is empty.",
                business_impact="Undocumented rules are harder to review, approve, troubleshoot and safely remove.",
                recommendation="Add business purpose, owner and review date to the firewall rule description.",
            ))

    return findings
