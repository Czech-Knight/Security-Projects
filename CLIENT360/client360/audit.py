from pathlib import Path
from typing import Dict, List, Tuple
import pandas as pd

from client360.collectors.csv_loader import load_csv
from client360.models import Finding
from client360.utils.config_loader import load_config
from client360.analyzers.microsoft365_analyzer import analyze_microsoft365_users
from client360.analyzers.cloud_analyzer import analyze_cloud_rules
from client360.analyzers.firewall_analyzer import analyze_firewall_rules
from client360.analyzers.backup_analyzer import analyze_backups
from client360.analyzers.network_analyzer import analyze_network_devices
from client360.analyzers.risk_engine import calculate_score, score_label, summarise_findings, category_summary


def load_all_data(config: Dict) -> Dict[str, pd.DataFrame]:
    paths = config["paths"]
    return {
        "microsoft365_users": load_csv(paths["microsoft365_users"]),
        "azure_nsg_rules": load_csv(paths["azure_nsg_rules"]),
        "aws_security_groups": load_csv(paths["aws_security_groups"]),
        "firewall_rules": load_csv(paths["firewall_rules"]),
        "backup_status": load_csv(paths["backup_status"]),
        "network_devices": load_csv(paths["network_devices"]),
    }


def run_audit(config_path: str = "config.example.yaml") -> Tuple[Dict, Dict[str, pd.DataFrame], List[Finding]]:
    config = load_config(config_path)
    data = load_all_data(config)
    policy = config.get("risk_policy", {})

    findings: List[Finding] = []
    findings += analyze_microsoft365_users(
        data["microsoft365_users"],
        stale_days=int(policy.get("stale_account_days", 90)),
    )
    findings += analyze_cloud_rules(data["azure_nsg_rules"], "Azure")
    findings += analyze_cloud_rules(data["aws_security_groups"], "AWS")
    findings += analyze_firewall_rules(data["firewall_rules"])
    findings += analyze_backups(
        data["backup_status"],
        warning_hours=int(policy.get("backup_warning_hours", 24)),
        critical_hours=int(policy.get("backup_critical_hours", 72)),
    )
    findings += analyze_network_devices(data["network_devices"])

    return config, data, findings


def audit_summary(findings: List[Finding]) -> Dict:
    score = calculate_score(findings)
    return {
        "score": score,
        "risk_label": score_label(score),
        "severity_counts": summarise_findings(findings),
        "category_counts": category_summary(findings),
        "total_findings": len(findings),
    }
