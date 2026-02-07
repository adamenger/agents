from __future__ import annotations

from datetime import datetime, timedelta, timezone

import structlog
from opensearchpy import OpenSearch

from .config import settings
from .models import DomainEvaluation, DomainStats

log = structlog.get_logger()


def _get_client() -> OpenSearch:
    return OpenSearch(
        hosts=[{"host": settings.opensearch_host, "port": settings.opensearch_port}],
        use_ssl=False,
        verify_certs=False,
        timeout=30,
    )


def fetch_domain_stats(lookback_hours: int | None = None) -> list[DomainStats]:
    """Query pihole indices for unique domains with counts, clients, and query types.

    Uses a terms aggregation on the domain field to avoid pulling raw docs.
    """
    hours = lookback_hours or settings.lookback_hours
    client = _get_client()

    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)

    # Build index pattern for the lookback window
    index_pattern = f"{settings.opensearch_pihole_index_prefix}-*"

    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": since.isoformat(), "lte": now.isoformat()}}},
                    {"term": {"action.keyword": "query"}},
                ]
            }
        },
        "aggs": {
            "domains": {
                "terms": {"field": "domain.keyword", "size": 10000},
                "aggs": {
                    "clients": {"terms": {"field": "client_or_target.keyword", "size": 100}},
                    "query_types": {"terms": {"field": "query_type.keyword", "size": 20}},
                },
            }
        },
    }

    log.info("querying_opensearch", index=index_pattern, since=since.isoformat(), hours=hours)

    try:
        resp = client.search(index=index_pattern, body=query)
    except Exception:
        log.exception("opensearch_query_failed")
        return []

    buckets = resp.get("aggregations", {}).get("domains", {}).get("buckets", [])
    results = []
    for bucket in buckets:
        clients = [c["key"] for c in bucket.get("clients", {}).get("buckets", [])]
        qtypes = [q["key"] for q in bucket.get("query_types", {}).get("buckets", [])]
        results.append(
            DomainStats(
                domain=bucket["key"],
                query_count=bucket["doc_count"],
                unique_clients=clients,
                query_types=qtypes,
            )
        )

    log.info("opensearch_query_complete", unique_domains=len(results))
    return results


def _ensure_evaluations_index(client: OpenSearch) -> None:
    """Create the pihole-evaluations index with explicit mapping if it doesn't exist."""
    index = settings.opensearch_evaluations_index
    if client.indices.exists(index=index):
        return

    mapping = {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "domain": {"type": "keyword"},
                "threat_level": {"type": "keyword"},
                "confidence": {"type": "integer"},
                "reasoning": {"type": "text"},
                "indicators": {"type": "keyword"},
                "evaluated_by": {"type": "keyword"},
                "escalated": {"type": "boolean"},
                "query_count": {"type": "integer"},
                "unique_clients": {"type": "keyword"},
                "evaluated_at": {"type": "date"},
            }
        },
    }

    client.indices.create(index=index, body=mapping)  # type: ignore[call-arg]
    log.info("created_evaluations_index", index=index)


def fetch_previous_evaluations(count: int | None = None) -> list[DomainEvaluation]:
    """Load recent evaluations for learning context."""
    n = count or settings.previous_evaluations_count
    client = _get_client()
    index = settings.opensearch_evaluations_index

    if not client.indices.exists(index=index):
        return []

    query = {
        "size": n,
        "sort": [{"evaluated_at": {"order": "desc"}}],
        "query": {"match_all": {}},
    }

    try:
        resp = client.search(index=index, body=query)
    except Exception:
        log.exception("fetch_previous_evaluations_failed")
        return []

    results = []
    for hit in resp["hits"]["hits"]:
        src = hit["_source"]
        results.append(DomainEvaluation(**src))

    log.info("loaded_previous_evaluations", count=len(results))
    return results


def fetch_already_evaluated_domains() -> set[str]:
    """Get domains evaluated within the TTL window to avoid re-evaluation."""
    client = _get_client()
    index = settings.opensearch_evaluations_index

    if not client.indices.exists(index=index):
        return set()

    since = datetime.now(timezone.utc) - timedelta(days=settings.evaluation_ttl_days)

    query = {
        "size": 0,
        "query": {"range": {"evaluated_at": {"gte": since.isoformat()}}},
        "aggs": {"domains": {"terms": {"field": "domain", "size": 50000}}},
    }

    try:
        resp = client.search(index=index, body=query)
    except Exception:
        log.exception("fetch_already_evaluated_failed")
        return set()

    buckets = resp.get("aggregations", {}).get("domains", {}).get("buckets", [])
    domains = {b["key"] for b in buckets}
    log.info("already_evaluated_domains", count=len(domains))
    return domains


def store_evaluations(evaluations: list[DomainEvaluation]) -> int:
    """Bulk-index evaluations into OpenSearch. Returns count of successfully indexed docs."""
    if not evaluations:
        return 0

    client = _get_client()
    _ensure_evaluations_index(client)

    actions = []
    for ev in evaluations:
        actions.append({"index": {"_index": settings.opensearch_evaluations_index}})
        actions.append(ev.model_dump(mode="json"))

    try:
        resp = client.bulk(body=actions)
    except Exception:
        log.exception("bulk_index_failed")
        return 0

    errors = resp.get("errors", False)
    items = resp.get("items", [])
    success_count = sum(1 for item in items if item.get("index", {}).get("status", 500) < 300)

    if errors:
        failed = [item for item in items if item.get("index", {}).get("status", 500) >= 300]
        log.warning("bulk_index_partial_failure", failed=len(failed), succeeded=success_count)
    else:
        log.info("bulk_index_complete", count=success_count)

    return success_count
