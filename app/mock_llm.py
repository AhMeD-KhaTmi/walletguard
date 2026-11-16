import asyncio
from common.tokens import estimate_tokens

IN_PER_1K = 0.003      # simulated price per 1k input tokens (USD)
OUT_PER_1K = 0.015     # simulated price per 1k output tokens (USD)
OUTPUT_HARD_CAP = 32_000   # deliberately huge in the baseline (vulnerable)


async def complete(prompt: str, max_output_tokens: int) -> tuple[str, int, int, float]:
    if isinstance(max_output_tokens, bool) or not isinstance(max_output_tokens, int) or max_output_tokens < 1:
        raise ValueError("max_output_tokens must be a positive integer")
    n_in = estimate_tokens(prompt)
    n_out = max(1, min(max_output_tokens, OUTPUT_HARD_CAP))
    await asyncio.sleep(min(n_out / 20_000, 2.0))        # simulated generation time
    text = ("lorem " * n_out)[: n_out * 4]               # about n_out tokens
    cost = n_in / 1000 * IN_PER_1K + n_out / 1000 * OUT_PER_1K
    return text, n_in, n_out, cost
