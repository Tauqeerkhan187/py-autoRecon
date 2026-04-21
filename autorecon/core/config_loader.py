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
        raw