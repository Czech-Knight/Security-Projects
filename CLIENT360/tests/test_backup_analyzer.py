from datetime import datetime, timedelta, timezone
import pandas as pd
from client360.analyzers.backup_analyzer import analyze_backups


def test_failed_backup_detected():
    df = pd.DataFrame([
        {
            "server_name": "srv1",
            "backup_type": "Image",
            "last_backup_time": datetime.now(timezone.utc).isoformat(),
            "status": "Failed",
            "retention_days": 30,
            "recovery_tested": True,
        }
    ])
    findings = analyze_backups(df)
    assert any(f.title == "Backup job failed" for f in findings)


def test_stale_backup_detected():
    old_time = datetime.now(timezone.utc) - timedelta(hours=100)
    df = pd.DataFrame([
        {
            "server_name": "srv1",
            "backup_type": "Image",
            "last_backup_time": old_time.isoformat(),
            "status": "Success",
            "retention_days": 30,
            "recovery_tested": True,
        }
    ])
    findings = analyze_backups(df)
    assert any(f.title == "Critical server backup is stale" for f in findings)
