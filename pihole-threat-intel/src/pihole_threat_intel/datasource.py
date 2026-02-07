"""Abstract data source for domain stats and evaluation storage."""

from __future__ import annotations

from abc import ABC, abstractmethod

from .models import DomainEvaluation, DomainStats


class DataSource(ABC):
    """Backend-agnostic interface for reading DNS data and storing evaluations.

    Implementations:
        - SQLiteSource: reads PiHole's FTL database directly (lightweight, local)
        - OpenSearchSource: reads from OpenSearch indices (SIEM/corporate setup)
    """

    @abstractmethod
    def fetch_domain_stats(self) -> list[DomainStats]:
        """Query unique domains with counts, clients, and query types."""

    @abstractmethod
    def fetch_previous_evaluations(self) -> list[DomainEvaluation]:
        """Load recent evaluations for LLM learning context."""

    @abstractmethod
    def fetch_already_evaluated_domains(self) -> set[str]:
        """Get domains evaluated within the TTL window to skip re-evaluation."""

    @abstractmethod
    def store_evaluations(self, evaluations: list[DomainEvaluation]) -> int:
        """Persist evaluations. Returns count of successfully stored records."""
