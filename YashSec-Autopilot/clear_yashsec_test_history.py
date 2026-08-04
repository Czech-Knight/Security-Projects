from __future__ import annotations

import argparse
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app.config import BACKUP_DIR, DB_PATH


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Back up the YashSec database, then clear test scan history."
    )
    parser.add_argument(
        "--findings-only",
        action="store_true",
        help="Delete findings only. Old scan summary counts may remain stale.",
    )
    args = parser.parse_args()

    if not DB_PATH.exists():
        raise SystemExit(f"Database not found: {DB_PATH}")

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup_path = BACKUP_DIR / f"before-clear-{stamp}.db"

    source = sqlite3.connect(DB_PATH)
    try:
        backup = sqlite3.connect(backup_path)
        try:
            source.backup(backup)
        finally:
            backup.close()

        source.execute("PRAGMA foreign_keys=ON")
        scan_count = source.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        finding_count = source.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

        if args.findings_only:
            source.execute("DELETE FROM findings")
            source.execute("DELETE FROM sqlite_sequence WHERE name='findings'")
            mode = "findings only"
        else:
            # Findings are deleted automatically through the scan foreign key.
            source.execute("DELETE FROM scans")
            source.execute("DELETE FROM sqlite_sequence WHERE name IN ('scans', 'findings')")
            mode = "scan history and findings"

        source.commit()
    finally:
        source.close()

    print(f"Database: {DB_PATH}")
    print(f"Backup:   {backup_path}")
    print(f"Cleared:  {mode}")
    print(f"Previous scans: {scan_count}")
    print(f"Previous findings: {finding_count}")
    if args.findings_only:
        print("Note: existing scan summary cards may still contain old stored counts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
