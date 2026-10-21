"""Configuration loading and validation.

All configuration is plain JSON under ``config/``.  Validation is strict so
that a typo never silently changes risk behaviour.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "rdf.sqlite3"
POLICY_DIR = PROJECT_ROOT / "policies"

CRITICALITY_LEVELS = ("Low", "Medium", "High", "Critical")
COMPONENTS = ("V", "C", "D", "A")


class ConfigError(ValueError):
    """Raised when a configuration file is missing or invalid."""


def _load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError as exc:
        raise ConfigError(f"Configuration file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a JSON object")
    return data


def validate_weights(weights: dict[str, Any], label: str = "weights") -> dict[str, float]:
    if set(weights) != set(COMPONENTS):
        raise ConfigError(f"{label} must define exactly V, C, D, A (got {sorted(weights)})")
    out: dict[str, float] = {}
    for key in COMPONENTS:
        val = weights[key]
        if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(val):
            raise ConfigError(f"{label}.{key} must be a finite number")
        if val < 0:
            raise ConfigError(f"{label}.{key} must be >= 0")
        out[key] = float(val)
    total = sum(out.values())
    if not math.isclose(total, 1.0, abs_tol=1e-6):
        raise ConfigError(f"{label} must sum to 1.0 (got {total:.6f})")
    return out


def load_risk_model(path: Path | None = None) -> dict[str, Any]:
    model = _load_json(path or CONFIG_DIR / "risk_model.json")
    for key in ("model_version", "weights", "vulnerability", "compliance", "drift", "criticality", "bands"):
        if key not in model:
            raise ConfigError(f"risk_model.json missing key: {key}")
    model["weights"] = validate_weights(model["weights"])
    for name, ws in model.get("alternative_weight_sets", {}).items():
        model["alternative_weight_sets"][name] = validate_weights(ws, f"alternative_weight_sets.{name}")
    if set(model["criticality"]) != set(CRITICALITY_LEVELS):
        raise ConfigError("criticality must define Low, Medium, High, Critical")
    for lvl, val in model["criticality"].items():
        if not isinstance(val, (int, float)) or not 0 <= val <= 100:
            raise ConfigError(f"criticality.{lvl} must be within 0..100")
    return model


def load_asset_policy(path: Path | None = None) -> dict[str, Any]:
    cfg = _load_json(path or CONFIG_DIR / "asset_policy.json")
    for key in ("assets", "policy_params", "collector"):
        if key not in cfg:
            raise ConfigError(f"asset_policy.json missing key: {key}")
    seen: set[str] = set()
    for asset in cfg["assets"]:
        aid = asset.get("asset_id")
        if not isinstance(aid, str) or not aid.strip():
            raise ConfigError("every asset needs a non-empty asset_id")
        if aid in seen:
            raise ConfigError(f"duplicate asset_id {aid}")
        seen.add(aid)
        if asset.get("criticality") not in CRITICALITY_LEVELS:
            raise ConfigError(f"asset {aid}: criticality must be one of {CRITICALITY_LEVELS}")
    timeout = cfg["collector"].get("command_timeout_seconds", 15)
    if not isinstance(timeout, (int, float)) or not 1 <= timeout <= 300:
        raise ConfigError("collector.command_timeout_seconds must be within 1..300")
    return cfg


def find_asset(cfg: dict[str, Any], asset_id: str) -> dict[str, Any]:
    for asset in cfg["assets"]:
        if asset["asset_id"] == asset_id:
            return asset
    raise ConfigError(f"asset_id '{asset_id}' not defined in asset_policy.json")
