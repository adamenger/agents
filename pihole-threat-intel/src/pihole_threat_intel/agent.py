from __future__ import annotations

from datetime import datetime, timezone

import structlog
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.ollama import OllamaProvider

from .config import settings
from .models import (
    BatchEvaluationResult,
    DomainEvaluation,
    DomainStats,
    SingleEvaluation,
)
from .yaml_config import get_prompts

# TODO: Uncomment when enabling Claude escalation
# from pydantic_ai.models.anthropic import AnthropicModel

log = structlog.get_logger()


def _build_agent() -> Agent[None, BatchEvaluationResult]:
    model = OpenAIChatModel(
        model_name=settings.ollama_model,
        provider=OllamaProvider(base_url=f"{settings.ollama_base_url}/v1"),
    )
    return Agent(
        model,
        output_type=BatchEvaluationResult,
        instructions=get_prompts()["deepseek_system_prompt"],
        retries=3,
    )


# TODO: Uncomment when enabling Claude escalation
# def _build_claude_agent() -> Agent[None, BatchEvaluationResult]:
#     model = AnthropicModel(
#         settings.claude_model,
#         api_key=settings.anthropic_api_key,
#     )
#     return Agent(
#         model,
#         output_type=BatchEvaluationResult,
#         instructions=get_prompts()["claude_system_prompt"],
#     )


def _format_learning_context(previous: list[DomainEvaluation]) -> str:
    if not previous:
        return get_prompts()["no_previous_evaluations"]
    lines = []
    for ev in previous:
        indicators_str = ", ".join(ev.indicators) if ev.indicators else "none"
        lines.append(
            f"- {ev.domain}: {ev.threat_level} (confidence: {ev.confidence}) -- {indicators_str}"
        )
    return get_prompts()["previous_evaluations_header"] + "\n" + "\n".join(lines)


def _format_batch_prompt(batch: list[DomainStats], learning_context: str) -> str:
    domain_lines = []
    for d in batch:
        clients = ", ".join(d.unique_clients[:5])
        qtypes = ", ".join(d.query_types)
        domain_lines.append(
            f"- {d.domain} | queries: {d.query_count} | clients: {clients} | types: {qtypes}"
        )

    return get_prompts()["batch_user_prompt"].format(
        learning_context=learning_context,
        domain_list="\n".join(domain_lines),
    )


async def evaluate_batch(
    batch: list[DomainStats],
    previous_evaluations: list[DomainEvaluation],
) -> list[DomainEvaluation]:
    """Evaluate a batch of domains using the configured Ollama model."""
    agent = _build_agent()
    learning_context = _format_learning_context(previous_evaluations)
    user_prompt = _format_batch_prompt(batch, learning_context)

    domain_lookup = {d.domain: d for d in batch}

    log.info("evaluating_batch", domains=len(batch))

    try:
        result = await agent.run(user_prompt)
        raw_evaluations: list[SingleEvaluation] = result.output.evaluations
    except Exception:
        log.exception("llm_batch_failed", domains=len(batch))
        return []

    evaluations: list[DomainEvaluation] = []
    for single in raw_evaluations:
        stats = domain_lookup.get(single.domain)
        ev = DomainEvaluation(
            domain=single.domain,
            threat_level=single.threat_level,
            confidence=single.confidence,
            reasoning=single.reasoning,
            indicators=single.indicators,
            evaluated_by=settings.ollama_model,
            escalated=False,
            query_count=stats.query_count if stats else 0,
            unique_clients=stats.unique_clients if stats else [],
            evaluated_at=datetime.now(timezone.utc),
        )
        evaluations.append(ev)

    log.info("batch_evaluated", results=len(evaluations))

    # TODO: Uncomment when enabling Claude escalation
    # escalation_candidates = [
    #     ev for ev in evaluations
    #     if ev.confidence < settings.escalation_confidence_threshold
    #     and ev.threat_level != ThreatLevel.BENIGN
    # ]
    # if escalation_candidates:
    #     log.info("escalating_to_claude", count=len(escalation_candidates))
    #     escalation_stats = [domain_lookup[ev.domain] for ev in escalation_candidates if ev.domain in domain_lookup]
    #     claude_agent = _build_claude_agent()
    #     claude_prompt = _format_batch_prompt(escalation_stats, learning_context)
    #     try:
    #         claude_result = await claude_agent.run(claude_prompt)
    #         claude_lookup = {e.domain: e for e in claude_result.output.evaluations}
    #         for i, ev in enumerate(evaluations):
    #             if ev.domain in claude_lookup:
    #                 c = claude_lookup[ev.domain]
    #                 evaluations[i] = DomainEvaluation(
    #                     domain=c.domain,
    #                     threat_level=c.threat_level,
    #                     confidence=c.confidence,
    #                     reasoning=c.reasoning,
    #                     indicators=c.indicators,
    #                     evaluated_by=settings.claude_model,
    #                     escalated=True,
    #                     query_count=ev.query_count,
    #                     unique_clients=ev.unique_clients,
    #                     evaluated_at=datetime.now(timezone.utc),
    #                 )
    #     except Exception:
    #         log.exception("claude_escalation_failed")

    return evaluations
