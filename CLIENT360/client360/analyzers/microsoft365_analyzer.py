from datetime import datetime
from typing import List
import pandas as pd

from client360.models import Finding


def analyze_microsoft365_users(users: pd.DataFrame, stale_days: int = 90) -> List[Finding]:
    findings: List[Finding] = []

    required_columns = {
        "display_name", "user_principal_name", "role", "mfa_enabled",
        "last_sign_in_days_ago", "mailbox_type", "license_assigned"
    }
    missing = required_columns.difference(users.columns)
    if missing:
        raise ValueError(f"Microsoft 365 user data missing columns: {sorted(missing)}")

    for _, row in users.iterrows():
        name = str(row["display_name"])
        upn = str(row["user_principal_name"])
        role = str(row["role"]).lower()
        mfa_enabled = str(row["mfa_enabled"]).strip().lower() in {"true", "yes", "1"}
        last_sign_in = int(row["last_sign_in_days_ago"])
        licensed = str(row["license_assigned"]).strip().lower() in {"true", "yes", "1"}

        if not mfa_enabled and "admin" in role:
            findings.append(Finding(
                title="Administrator account without MFA",
                category="Microsoft 365",
                severity="Critical",
                asset=upn,
                evidence=f"Role is {row['role']} and MFA is disabled.",
                business_impact="Admin compromise may allow tenant-wide account, email and data access.",
                recommendation="Enable MFA or conditional access for every administrator account immediately.",
            ))
        elif not mfa_enabled:
            findings.append(Finding(
                title="User account without MFA",
                category="Microsoft 365",
                severity="High",
                asset=upn,
                evidence="MFA is disabled for this user.",
                business_impact="Password compromise could allow unauthorised mailbox and application access.",
                recommendation="Enable MFA or enrol the user in conditional access-based MFA.",
            ))

        if last_sign_in >= stale_days and licensed:
            findings.append(Finding(
                title="Stale licensed Microsoft 365 account",
                category="Microsoft 365",
                severity="Medium",
                asset=upn,
                evidence=f"Last sign-in was {last_sign_in} days ago and the account is licensed.",
                business_impact="Unused accounts increase attack surface and may waste licence cost.",
                recommendation="Review whether the user still requires access; disable or remove licence if not required.",
            ))

        if "test" in upn.lower() or "temp" in upn.lower():
            findings.append(Finding(
                title="Potential temporary or test account detected",
                category="Microsoft 365",
                severity="Low",
                asset=upn,
                evidence=f"Account name contains a temporary/test naming pattern: {name}",
                business_impact="Forgotten test accounts can become unmanaged access paths.",
                recommendation="Confirm account owner and remove the account if it is no longer required.",
            ))

    return findings
