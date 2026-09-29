"""Environment-driven configuration. All settings are overridable via
`CYBER_PATROL_*` environment variables (see docker-compose.yml / .env.example).
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CYBER_PATROL_", env_file=".env", extra="ignore")

    anthropic_api_key: str

    # When set, the Anthropic SDK targets this base URL instead of
    # https://api.anthropic.com -- useful for Anthropic-compatible
    # aggregator endpoints (e.g. https://openrouter.ai/api/v1).
    anthropic_base_url: str | None = None

    # claude-sonnet-5 balances reasoning quality against latency/cost for a
    # per-event classification workload; claude-haiku-4-5-20251001 is a
    # solid lower-latency/cost alternative for high event-rate deployments
    # that need to screen large volumes before a second-tier Sonnet pass.
    # Verify current model strings at https://docs.claude.com before
    # deploying -- these are renamed/superseded over time.
    model: str = "claude-sonnet-5"

    # Server-side floor, independent of anything the model claims: a
    # verdict is only allowed to trigger action=kill if BOTH
    # severity=critical AND confidence >= this floor. See
    # llm_engine.ThreatHuntingEngine._parse_tool_input.
    kill_confidence_floor: float = 0.85

    # Output token budget per verdict. Keep small -- this is a structured
    # tool-call reply, not a long-form essay. Also relevant when operating
    # on a near-empty credit balance: OpenRouter rejects max_tokens
    # reservations larger than what the balance can afford.
    max_tokens: int = 1024

    host: str = "0.0.0.0"
    port: int = 8000


settings = Settings()
