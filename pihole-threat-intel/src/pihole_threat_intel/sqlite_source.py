"""SQLite data source — reads PiHole's FTL database directly."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import structlog

from .config import settings
from .datasource import DataSource
from .models import DomainEvaluation, DomainStats

log = structlog.get_logger()

QUERY_TYPE_MAP = {
    1: "A", 2: "AAAA", 3: "ANY", 4: "SRV", 5: "SOA",
    6: "PTR", 7: "TXT", 8: "NAPTR", 9: "MX", 10: "DS",
    11: "RRSIG", 12: "DNSKEY", 13: "NS", 14: "OTHER",
    15: "SVCB", 16: "HTTPS",
}

# Status codes that represent allowed/forwarded queries (not blocked)
ALLOWED_STATUSES = (2, 3, 12, 13, 14, 17)


class SQLiteSource(DataSource):
    def __init__(self) -> None:
        self._pihole_db = settings.sqlite_pihole_db
        self._eval_db = settings.sqlite_eval_db
        self._ensure_eval_db()

    def _pihole_conn(self) -> sqlite3.Connection:
        """Open PiHole FTL DB in read-only mode."""
        conn = sqlite3.connect(f"file:{self._pihole_db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    def _eval_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._eval_db)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_eval_db(self) -> None:
        """Create the evaluations table if it doesn't exist."""
        Path(self._eval_db).parent.mkdir(parents=True, exist_ok=True)
        conn = self._eval_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS evaluations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                reasoning TEXT NOT NULL,
                indicators TEXT NOT NULL DEFAULT '[]',
                evaluated_by TEXT NOT NULL,
                escalated INTEGER NOT NULL DEFAULT 0,
                query_count INTEGER NOT NULL DEFAULT 0,
                unique_clients TEXT NOT NULL DEFAULT '[]',
                evaluated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_eval_domain ON evaluations(domain)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_eval_at ON evaluations(evaluated_at)
        """)
        conn.commit()
        conn.close()

    def fetch_domain_stats(self) -> list[DomainStats]:
        since = datetime.now(timezone.utc) - timedelta(hours=settings.lookback_hours)
        since_ts = int(since.timestamp())

        log.info("querying_pihole_sqlite", db=self._pihole_db, since=since.isoformat())

        try:
            conn = self._pihole_conn()
        except Exception:
            log.exception("pihole_db_open_failed", db=self._pihole_db)
            return []

        try:
            # Aggregate domains with counts, clients, and query types
            rows = conn.execute("""
                SELECT domain,
                       COUNT(*) as query_count,
                       GROUP_CONCAT(DISTINCT client) as clients,
                       GROUP_CONCAT(DISTINCT type) as types
                FROM queries
                WHERE timestamp > ?
                  AND status IN (2, 3, 12, 13, 14, 17)
                GROUP BY domain
            """, (since_ts,)).fetchall()
        except Exception:
            log.exception("pihole_db_query_failed")
            return []
        finally:
            conn.close()

        results = []
        for row in rows:
            clients = row["clients"].split(",") if row["clients"] else []
            type_ids = row["types"].split(",") if row["types"] else []
            query_types = [QUERY_TYPE_MAP.get(int(t), f"TYPE{t}") for t in type_ids]

            results.append(DomainStats(
                domain=row["domain"],
                query_count=row["query_count"],
                unique_clients=clients,
                query_types=query_types,
            ))

        log.info("pihole_sqlite_query_complete", unique_domains=len(results))
        return results

    def fetch_previous_evaluations(self) -> list[DomainEvaluation]:
        n = settings.previous_evaluations_count
        conn = self._eval_conn()

        try:
            rows = conn.execute("""
                SELECT * FROM evaluations
                ORDER BY evaluated_at DESC
                LIMIT ?
            """, (n,)).fetchall()
        except Exception:
            log.exception("fetch_previous_evaluations_failed")
            return []
        finally:
            conn.close()

        results = [self._row_to_evaluation(row) for row in rows]
        log.info("loaded_previous_evaluations", count=len(results))
        return results

    def fetch_already_evaluated_domains(self) -> set[str]:
        since = datetime.now(timezone.utc) - timedelta(days=settings.evaluation_ttl_days)

        conn = self._eval_conn()
        try:
            rows = conn.execute("""
                SELECT DISTINCT domain FROM evaluations
                WHERE evaluated_at > ?
            """, (since.isoformat(),)).fetchall()
        except Exception:
            log.exception("fetch_already_evaluated_failed")
            return set()
        finally:
            conn.close()

        domains = {row["domain"] for row in rows}
        log.info("already_evaluated_domains", count=len(domains))
        return domains

    def store_evaluations(self, evaluations: list[DomainEvaluation]) -> int:
        if not evaluations:
            return 0

        conn = self._eval_conn()
        count = 0
        try:
            for ev in evaluations:
                conn.execute("""
                    INSERT INTO evaluations
                        (domain, threat_level, confidence, reasoning, indicators,
                         evaluated_by, escalated, query_count, unique_clients, evaluated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ev.domain,
                    ev.threat_level.value,
                    ev.confidence,
                    ev.reasoning,
                    ",".join(ev.indicators),
                    ev.evaluated_by,
                    1 if ev.escalated else 0,
                    ev.query_count,
                    ",".join(ev.unique_clients),
                    ev.evaluated_at.isoformat(),
                ))
                count += 1
            conn.commit()
        except Exception:
            log.exception("sqlite_store_failed")
            conn.rollback()
            return 0
        finally:
            conn.close()

        log.info("sqlite_store_complete", count=count)
        return count

    @staticmethod
    def _row_to_evaluation(row: sqlite3.Row) -> DomainEvaluation:
        indicators = row["indicators"].split(",") if row["indicators"] else []
        clients = row["unique_clients"].split(",") if row["unique_clients"] else []
        return DomainEvaluation(
            domain=row["domain"],
            threat_level=row["threat_level"],
            confidence=row["confidence"],
            reasoning=row["reasoning"],
            indicators=indicators,
            evaluated_by=row["evaluated_by"],
            escalated=bool(row["escalated"]),
            query_count=row["query_count"],
            unique_clients=clients,
            evaluated_at=row["evaluated_at"],
        )
