from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum

from pydantic import BaseModel, Field


class ThreatLevel(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class DomainStats(BaseModel):
    """Aggregated stats for a single domain from OpenSearch."""

    domain: str
    query_count: int
    unique_clients: list[str]
    query_types: list[str]


class DomainEvaluation(BaseModel):
    """Result of LLM threat evaluation for a single domain."""

    domain: str
    threat_level: ThreatLevel
    confidence: int = Field(ge=0, le=100)
    reasoning: str
    indicators: list[str] = Field(default_factory=list)
    evaluated_by: str
    escalated: bool = False
    query_count: int = 0
    unique_clients: list[str] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SingleEvaluation(BaseModel):
    """LLM's evaluation of one domain within a batch."""

    domain: str
    threat_level: ThreatLevel
    confidence: int = Field(ge=0, le=100)
    reasoning: str
    indicators: list[str] = Field(default_factory=list)


class BatchEvaluationResult(BaseModel):
    """Structured output from the LLM for a batch of domains."""

    evaluations: list[SingleEvaluation]


class RunStats(BaseModel):
    """Statistics for a single agent run."""

    total_domains_queried: int = 0
    domains_after_filtering: int = 0
    domains_already_evaluated: int = 0
    domains_to_evaluate: int = 0
    batches_processed: int = 0
    evaluations_produced: int = 0
    escalations: int = 0
    errors: int = 0
    benign_count: int = 0
    suspicious_count: int = 0
    malicious_count: int = 0
    unknown_count: int = 0
