"""Regenerates demo data used by the project."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

print("Demo data is already included in data/sample. You can edit those CSV files to simulate another client.")
