from datetime import datetime, timezone
from typing import List
import pandas as pd
from client360.models import Finding


def _parse_iso(value: str) -> datetime:
    text = str(value).strip().replace("Z", "+00:00")
    return datetime.fromisoformat(text)


def analyze_backups(backups: pd.DataFrame, warning_hours: int = 24, critical_hours: int = 72) -> List[Finding]:
    findings: List[Finding] = []
    required_columns = {"server_name", "backup_type", "last_backup_time", "status", "retention_days", "recovery_tested"}
    missing = required_columns.difference(backups.columns)
    if missing:
        raise ValueError(f"Backup data missing columns: {sorted(missing)}")

    now = datetime.now(timezone.utc)

    for _, row in backups.iterrows():
        server = str(row["server_name"])
        status = str(row["status"]).lower()
        last_backup = _parse_iso(row["last_backup_time"])
        age_hours = (now - last_backup).total_seconds() / 3600
        retention_days = int(row["retention_days"])
        recovery_tested = str(row["recovery_tested"]).strip().lower() in {"true", "yes", "1"}

        if status != "success":
            findings.append(Finding(
                title="Backup job failed",
                category="Backup and DR",
                severity="High",
                asset=server,
                evidence=f"Latest backup status is {row['status']}.",
                business_impact="Failed backups may prevent recovery after deletion, ransomware or server failure.",
                recommendation="Investigate backup job logs and confirm the next backup completes successfully.",
            ))

        if age_hours >= critical_hours:
            findings.append(Finding(
                title="Critical server backup is stale",
                category="Backup and DR",
                severity="Critical",
                asset=server,
                evidence=f"Last backup is approximately {age_hours:.1f} hours old.",
                business_impact="A stale backup may cause significant data loss during recovery.",
                recommendation="Run an immediate backup and verify backup schedule health.",
            ))
        elif age_hours >= warning_hours:
            findings.append(Finding(
                title="Backup older than expected",
                category="Backup and DR",
                severity="Medium",
                asset=server,
                evidence=f"Last backup is approximately {age_hours:.1f} hours old.",
                business_impact="Backup age exceeds the expected daily backup window.",
                recommendation="Check scheduling, storage capacity, agent health and alerting.",
            ))

        if retention_days < 14:
            findings.append(Finding(
                title="Backup retention below recommended baseline",
                category="Backup and DR",
                severity="Medium",
                asset=server,
                evidence=f"Retention is {retention_days} days.",
                business_impact="Short retention may limit recovery options after delayed detection of data loss.",
                recommendation="Review business requirements and increase retention where appropriate.",
            ))

        if not recovery_tested:
            findings.append(Finding(
                title="Recovery test not recorded",
                category="Backup and DR",
                severity="Medium",
                asset=server,
                evidence="Recovery tested field is false.",
                business_impact="Backups that are not restore-tested may fail when needed most.",
                recommendation="Schedule and document a restore test for this system.",
            ))

    return findings
