"""Known-good domain suffixes and exact domains loaded from config.yml."""

from __future__ import annotations

from functools import lru_cache

from .yaml_config import get_known_domains


@lru_cache(maxsize=1)
def _load() -> tuple[frozenset[str], frozenset[str]]:
    cfg = get_known_domains()
    suffixes = frozenset(cfg.get("suffixes", []))
    exact = frozenset(cfg.get("exact", []))
    return suffixes, exact


def is_known_good(domain: str) -> bool:
    """Check if a domain is known-good by suffix or exact match."""
    suffixes, exact = _load()
    domain = domain.lower().rstrip(".")
    if domain in exact:
        return True
    return any(domain.endswith(suffix) for suffix in suffixes)
