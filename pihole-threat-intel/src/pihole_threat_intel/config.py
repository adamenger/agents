from pydantic_settings import BaseSettings

from .yaml_config import get_defaults

_defaults = get_defaults()


class Settings(BaseSettings):
    model_config = {"env_prefix": "THREAT_INTEL_"}

    # OpenSearch
    opensearch_host: str = _defaults.get("opensearch_host", "localhost")
    opensearch_port: int = _defaults.get("opensearch_port", 9200)
    opensearch_pihole_index_prefix: str = _defaults.get("opensearch_pihole_index_prefix", "pihole")
    opensearch_evaluations_index: str = _defaults.get("opensearch_evaluations_index", "pihole-evaluations")

    # Ollama
    ollama_base_url: str = _defaults.get("ollama_base_url", "http://localhost:11434")
    ollama_model: str = _defaults.get("ollama_model", "qwen3:14b")

    # TODO: Uncomment when enabling Claude escalation
    # anthropic_api_key: str = ""
    # claude_model: str = "claude-sonnet-4-5-20250929"
    # escalation_confidence_threshold: int = 70

    # Agent behavior
    batch_size: int = _defaults.get("batch_size", 25)
    lookback_hours: int = _defaults.get("lookback_hours", 24)
    previous_evaluations_count: int = _defaults.get("previous_evaluations_count", 20)
    evaluation_ttl_days: int = _defaults.get("evaluation_ttl_days", 7)


settings = Settings()
