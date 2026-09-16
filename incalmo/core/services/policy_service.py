from pathlib import Path

import yaml

POLICIES_DIR = Path("config/policies")


def load_policy(name: str) -> str:
    text = (POLICIES_DIR / f"{name}.yaml").read_text()
    yaml.safe_load(text)
    return text
