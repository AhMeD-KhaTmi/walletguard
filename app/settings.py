"""Application settings shared by baseline and hardened modes."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    redis_url: str = "redis://127.0.0.1:6379/0"
    llm_base_url: str = "http://127.0.0.1:8001"
    llm_timeout_s: float = 10.0
    waf_mode: str = "off"

    @classmethod
    def from_env(cls) -> "Settings":
        settings = cls(
            redis_url=os.getenv("REDIS_URL", cls.redis_url),
            llm_base_url=os.getenv("LLM_BASE_URL", cls.llm_base_url),
            llm_timeout_s=float(os.getenv("LLM_TIMEOUT_S", "10")),
            waf_mode=os.getenv("WAF_MODE", "off"),
        )
        if settings.waf_mode not in {"off", "observe", "enforce"}:
            raise ValueError("WAF_MODE must be off, observe or enforce")
        if settings.llm_timeout_s <= 0:
            raise ValueError("LLM_TIMEOUT_S must be positive")
        return settings
