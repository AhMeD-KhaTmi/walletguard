import asyncio
from dataclasses import dataclass
import hashlib
import math
import os
from common.tokens import estimate_tokens
from common.agent import MOCK_OUTPUT_CAP

IN_PER_1K = 0.003      # simulated price per 1k input tokens (USD)
OUT_PER_1K = 0.015     # simulated price per 1k output tokens (USD)
OUTPUT_HARD_CAP = MOCK_OUTPUT_CAP


@dataclass(frozen=True)
class Latency:
    tokens_per_s: float = 20_000
    base_ms: float = 0
    jitter_ms: float = 0
    cap_s: float = 2
    seed: int = 42

    def __post_init__(self):
        if any(not math.isfinite(x) or x < 0 for x in
               (self.tokens_per_s, self.base_ms, self.jitter_ms, self.cap_s)) or self.tokens_per_s == 0:
            raise ValueError("mock latency values must be finite, nonnegative, with positive throughput")

    @classmethod
    def from_env(cls):
        return cls(tokens_per_s=float(os.getenv("MOCK_TOKENS_PER_S", "20000")),
                   base_ms=float(os.getenv("MOCK_BASE_MS", "0")),
                   jitter_ms=float(os.getenv("MOCK_JITTER_MS", "0")),
                   cap_s=float(os.getenv("MOCK_DELAY_CAP_S", "2")),
                   seed=int(os.getenv("MOCK_SEED", "42")))

    def delay(self, prompt: str, output: int) -> float:
        digest = hashlib.sha256(f"{self.seed}:{output}:{prompt}".encode()).digest()
        fraction = int.from_bytes(digest[:8], "big") / (2**64 - 1)
        return min(self.cap_s, output / self.tokens_per_s + (self.base_ms + fraction * self.jitter_ms) / 1000)


async def complete(prompt: str, max_output_tokens: int, latency: Latency | None = None) -> tuple[str, int, int, float]:
    if isinstance(max_output_tokens, bool) or not isinstance(max_output_tokens, int) or max_output_tokens < 1:
        raise ValueError("max_output_tokens must be a positive integer")
    n_in = estimate_tokens(prompt)
    n_out = max(1, min(max_output_tokens, OUTPUT_HARD_CAP))
    await asyncio.sleep((latency or Latency()).delay(prompt, n_out))
    text = " ".join(["lorem"] * n_out)
    cost = n_in / 1000 * IN_PER_1K + n_out / 1000 * OUT_PER_1K
    return text, n_in, n_out, cost
