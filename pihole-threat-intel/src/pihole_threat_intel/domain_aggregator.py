from __future__ import annotations

import structlog

from .known_domains import is_known_good
from .models import DomainStats

log = structlog.get_logger()


def filter_known_good(domains: list[DomainStats]) -> list[DomainStats]:
    """Remove domains that match the known-good allowlist."""
    filtered = [d for d in domains if not is_known_good(d.domain)]
    log.info(
        "filtered_known_good",
        before=len(domains),
        after=len(filtered),
        removed=len(domains) - len(filtered),
    )
    return filtered


def remove_already_evaluated(
    domains: list[DomainStats], evaluated: set[str]
) -> list[DomainStats]:
    """Remove domains that have already been evaluated within the TTL window."""
    filtered = [d for d in domains if d.domain not in evaluated]
    log.info(
        "removed_already_evaluated",
        before=len(domains),
        after=len(filtered),
        skipped=len(domains) - len(filtered),
    )
    return filtered


def batch_domains(domains: list[DomainStats], batch_size: int) -> list[list[DomainStats]]:
    """Split domains into batches of the given size."""
    batches = [domains[i : i + batch_size] for i in range(0, len(domains), batch_size)]
    log.info("batched_domains", total=len(domains), batches=len(batches), batch_size=batch_size)
    return batches
