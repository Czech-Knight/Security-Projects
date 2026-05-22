from pathlib import Path
import pandas as pd


def load_csv(path: str) -> pd.DataFrame:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"CSV file not found: {file_path}")
    return pd.read_csv(file_path)
