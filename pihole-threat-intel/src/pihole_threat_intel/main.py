from __future__ import annotations

import asyncio

import structlog

from .agent import evaluate_batch
from .config import settings
from .datasource import DataSource
from .domain_aggregator import batch_domains, filter_known_good, remove_already_evaluated
from .logging_config import setup_logging
from .models import DomainEvaluation, RunStats, ThreatLevel
from .output import StdoutHandler

log = structlog.get_logger()


def _get_datasource() -> DataSource:
    if settings.data_source == "opensearch":
        from .opensearch_source import OpenSearchSource

        return OpenSearchSource()
    else:
        from .sqlite_source import SQLiteSource

        return SQLiteSource()


async def run() -> None:
    setup_logging()
    log.info("starting_pihole_threat_intel", data_source=settings.data_source)

    stats = RunStats()
    handler = StdoutHandler()
    ds = _get_datasource()

    # 1. Query for last 24h of pihole logs
    domain_stats = ds.fetch_domain_stats()
    stats.total_domains_queried = len(domain_stats)

    if not domain_stats:
        log.warning("no_domains_found")
        handler.emit_summary([], stats)
        return

    # 2. Filter known-good domains
    filtered = filter_known_good(domain_stats)
    stats.domains_after_filtering = len(filtered)

    # 3. Remove already-evaluated domains (within TTL)
    already_evaluated = ds.fetch_already_evaluated_domains()
    stats.domains_already_evaluated = len(already_evaluated)
    to_evaluate = remove_already_evaluated(filtered, already_evaluated)
    stats.domains_to_evaluate = len(to_evaluate)

    if not to_evaluate:
        log.info("no_new_domains_to_evaluate")
        handler.emit_summary([], stats)
        return

    # 4. Load previous evaluations for learning context
    previous = ds.fetch_previous_evaluations()

    # 5. Batch and evaluate
    batches = batch_domains(to_evaluate, settings.batch_size)
    all_evaluations: list[DomainEvaluation] = []

    for i, batch in enumerate(batches):
        log.info("processing_batch", batch=i + 1, total=len(batches), domains=len(batch))
        evaluations = await evaluate_batch(batch, previous)
        all_evaluations.extend(evaluations)
        stats.batches_processed += 1

        if not evaluations:
            stats.errors += 1

    # 6. Tally results
    for ev in all_evaluations:
        match ev.threat_level:
            case ThreatLevel.BENIGN:
                stats.benign_count += 1
            case ThreatLevel.SUSPICIOUS:
                stats.suspicious_count += 1
            case ThreatLevel.MALICIOUS:
                stats.malicious_count += 1
            case ThreatLevel.UNKNOWN:
                stats.unknown_count += 1
        if ev.escalated:
            stats.escalations += 1
    stats.evaluations_produced = len(all_evaluations)

    # 7. Store evaluations
    stored = ds.store_evaluations(all_evaluations)
    log.info("evaluations_stored", count=stored)

    # 8. Emit alerts for non-benign domains
    for ev in all_evaluations:
        if ev.threat_level in (ThreatLevel.SUSPICIOUS, ThreatLevel.MALICIOUS):
            handler.emit_alert(ev)

    # 9. Emit summary report
    handler.emit_summary(all_evaluations, stats)

    log.info("run_complete", **stats.model_dump())


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
