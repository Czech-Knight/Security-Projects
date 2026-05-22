from pathlib import Path
from typing import Any, Dict
import yaml


DEFAULT_CONFIG = "config.example.yaml"


def load_config(config_path: str = DEFAULT_CONFIG) -> Dict[str, Any]:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)
