from typing import List
import pandas as pd
from client360.models import Finding

CRITICAL_PORTS = {3389: "RDP", 3306: "MySQL", 1433: "MSSQL", 5432: "PostgreSQL"}
HIGH_PORTS = {22: "SSH", 5900: "VNC"}
PUBLIC_SOURCES = {"0.0.0.0/0", "::/0", "*", "Any", "any", "Internet"}


def _is_public_source(value: str) -> bool:
    return str(value).strip() in PUBLIC_SOURCES


def _normalise_port(port_value) -> int | None:
    text = str(port_value).strip()
    if text in {"*", "Any", "any"}:
        return None
    if "-" in text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def analyze_cloud_rules(rules: pd.DataFrame, provider_label: str) -> List[Finding]:
    findings: List[Finding] = []
    required_columns = {"asset", "rule_name", "direction", "access", "protocol", "source", "destination", "port"}
    missing = required_columns.difference(rules.columns)
    if missing:
        raise ValueError(f"{provider_label} rule data missing columns: {sorted(missing)}")

    for _, row in rules.iterrows():
        direction = str(row["direction"]).lower()
        access = str(row["access"]).lower()
        source = str(row["source"]).strip()
        port = _normalise_port(row["port"])
        asset = str(row["asset"])
        rule_name = str(row["rule_name"])

        if direction == "inbound" and access == "allow" and _is_public_source(source):
            if port is None:
                findings.append(Finding(
                    title=f"{provider_label} allows all public inbound traffic",
                    category=f"{provider_label} Cloud Security",
                    severity="Critical",
                    asset=asset,
                    evidence=f"Rule {rule_name} allows inbound traffic from {source} to port {row['port']}.",
                    business_impact="A broad public inbound rule can expose services directly to internet-based attacks.",
                    recommendation="Restrict inbound access to trusted IP ranges, VPN, or private connectivity.",
                ))
            elif port in CRITICAL_PORTS:
                findings.append(Finding(
                    title=f"Public {CRITICAL_PORTS[port]} exposure detected",
                    category=f"{provider_label} Cloud Security",
                    severity="Critical",
                    asset=asset,
                    evidence=f"Rule {rule_name} allows TCP/UDP {port} from {source}.",
                    business_impact=f"{CRITICAL_PORTS[port]} exposed publicly can invite brute-force, exploit attempts and data compromise.",
                    recommendation="Remove public exposure and restrict access to VPN, bastion, or trusted administrator IPs.",
                ))
            elif port in HIGH_PORTS:
                findings.append(Finding(
                    title=f"Public {HIGH_PORTS[port]} exposure detected",
                    category=f"{provider_label} Cloud Security",
                    severity="High",
                    asset=asset,
                    evidence=f"Rule {rule_name} allows TCP/UDP {port} from {source}.",
                    business_impact=f"{HIGH_PORTS[port]} exposed publicly increases attack surface.",
                    recommendation="Restrict access to trusted IP ranges or private administrative connectivity.",
                ))
            elif port == 80:
                findings.append(Finding(
                    title="Public HTTP service detected",
                    category=f"{provider_label} Cloud Security",
                    severity="Medium",
                    asset=asset,
                    evidence=f"Rule {rule_name} allows HTTP port 80 from {source}.",
                    business_impact="Plain HTTP may expose traffic to interception if not redirected to HTTPS.",
                    recommendation="Confirm HTTP redirects to HTTPS and keep TLS certificates valid.",
                ))

    return findings
