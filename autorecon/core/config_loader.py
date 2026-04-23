# Author: TK
# Date: 22-04-2026
# Purpose: Load and merge config files and provide helper funcs for accessing config values safely.
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from autorecon.exceptions import ConfigError

ConfigDict = dict[str, Any]

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "default.yaml"


def _read_yaml_file(path: Path) -> ConfigDict:
    """Read a YAML file and return a dict"""
    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")
    
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in config file: {path}") from exc
    except OSError as exc:
        raise ConfigError(f"Could not read config file: {path}") from exc
    
    if raw is None:
        return {}
    
    if not isinstance(raw, dict):
        raise ConfigError(f"Config file must contain a YAML mapping/object: {path}")
    
    return raw

def _deep_merge(base: ConfigDict, override: ConfigDict) -> ConfigDict:
    """Recursively merge override values into base."""
    merged = dict(base)
    
    for key, value in override.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
            
    return merged

def load_config(config_path: str | Path | None = None) -> ConfigDict:
    """
    Loads config.
    - Always load config/default.yaml first
    - If a custom config path is provided, it overrides matching keys.
    """
    base_config = _read_yaml_file(DEFAULT_CONFIG_PATH)
    
    if config_path is None:
        return base_config
    
    custom_path = Path(config_path)
    custom_config = _read_yaml_file(custom_path)
    
    return _deep_merge(base_config, custom_config)

def get_config_value(config: ConfigDict, dotted_key: str, default: Any = None) -> Any:
    """
    Safely fetch nested config vals using dot notation.
    """
    current: Any = config
    
    for part in dotted_key.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
        
    return current
        