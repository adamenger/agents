"""OpenSearch data source — reads from pihole indices, stores evaluations."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import structlog
from opensearchpy import OpenSearch

from .config import settings
from .datasource import DataSource
from .models import DomainEvaluation, DomainStats

log = structlog.get_logger()


class OpenSearchSource(DataSource):
    def __init__(self) -> None:
        self._client = OpenSearch(
            hosts=[{"host": settings.opensearch_host, "port": settings.opensearch_port}],
            use_ssl=False,
            verify_certs=False,
            timeout=30,
        )

    def fetch_domain_stats(self) -> list[DomainStats]:
        now = datetime.now(timezone.utc)
        since = now - timedelta(hours=settings.lookback_hours)
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

        log.info("querying_opensearch", index=index_pattern, since=since.isoformat())

        try:
            resp = self._client.search(index=index_pattern, body=query)
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

    def _ensure_evaluations_index(self) -> None:
        index = settings.opensearch_evaluations_index
        if self._client.indices.exists(index=index):
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

        self._client.indices.create(index=index, body=mapping)
        log.info("created_evaluations_index", index=index)

    def fetch_previous_evaluations(self) -> list[DomainEvaluation]:
        n = settings.previous_evaluations_count
        index = settings.opensearch_evaluations_index

        if not self._client.indices.exists(index=index):
            return []

        query = {
            "size": n,
            "sort": [{"evaluated_at": {"order": "desc"}}],
            "query": {"match_all": {}},
        }

        try:
            resp = self._client.search(index=index, body=query)
        except Exception:
            log.exception("fetch_previous_evaluations_failed")
            return []

        results = [DomainEvaluation(**hit["_source"]) for hit in resp["hits"]["hits"]]
        log.info("loaded_previous_evaluations", count=len(results))
        return results

    def fetch_already_evaluated_domains(self) -> set[str]:
        index = settings.opensearch_evaluations_index

        if not self._client.indices.exists(index=index):
            return set()

        since = datetime.now(timezone.utc) - timedelta(days=settings.evaluation_ttl_days)

        query = {
            "size": 0,
            "query": {"range": {"evaluated_at": {"gte": since.isoformat()}}},
            "aggs": {"domains": {"terms": {"field": "domain", "size": 50000}}},
        }

        try:
            resp = self._client.search(index=index, body=query)
        except Exception:
            log.exception("fetch_already_evaluated_failed")
            return set()

        buckets = resp.get("aggregations", {}).get("domains", {}).get("buckets", [])
        domains = {b["key"] for b in buckets}
        log.info("already_evaluated_domains", count=len(domains))
        return domains

    def store_evaluations(self, evaluations: list[DomainEvaluation]) -> int:
        if not evaluations:
            return 0

        self._ensure_evaluations_index()

        actions = []
        for ev in evaluations:
            actions.append({"index": {"_index": settings.opensearch_evaluations_index}})
            actions.append(ev.model_dump(mode="json"))

        try:
            resp = self._client.bulk(body=actions)
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
