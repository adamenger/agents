"""Load strings and configuration from config.yml."""

from __future__ import annotations

import os
from pathlib import Path

import yaml

# In Docker: WORKDIR is /app, config.yml is at /app/config.yml
# In dev: config.yml is at the project root (same dir as pyproject.toml)
_CONFIG_PATH = Path(os.environ.get("THREAT_INTEL_CONFIG_PATH", "/app/config.yml"))

_cache: dict | None = None


def _load() -> dict:
    global _cache
    if _cache is None:
        with open(_CONFIG_PATH) as f:
            _cache = yaml.safe_load(f)
    return _cache



def get_defaults() -> dict:
    """Return the defaults section, or empty dict if config is unavailable."""
    try:
        return _load().get("defaults", {})
    except (FileNotFoundError, OSError):
        return {}


def get_prompts() -> dict[str, str]:
    return _load()["prompts"]


def get_known_domains() -> dict:
    return _load()["known_domains"]


def get_output_strings() -> dict[str, str]:
    return _load()["output"]
