"""CCM-RiskDrift: Continuous Compliance Monitoring and Risk Drift Detection.

M.Tech Phase-II implementation (Jainee Shroff, PIET, Parul University).
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_config(path=None):
    path = Path(path) if path else ROOT / "config.json"
    with open(path, encoding="utf-8") as f:
        return json.load(f)
