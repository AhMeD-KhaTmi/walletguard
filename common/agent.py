"""Dependency-free context rules shared by the simulated agent and WAF reservation."""

import hashlib

from common.tokens import estimate_tokens

AGENT_VERSION = "context-loop-v1"
DEFAULT_AGENT_STEPS = 3
MAX_AGENT_STEPS = 8
MOCK_OUTPUT_CAP = 32_000


def tool_result(prompt: str, step: int) -> str:
    digest = hashlib.sha256(f"{step}:{prompt}".encode()).digest()
    product = int.from_bytes(digest[:4], "big") % 5000 + 1
    return f"catalogue_result step {step} product {product} status available"


def next_context(context: str, generated: str, observation: str) -> str:
    return f"{context}\nassistant {generated}\ntool {observation}"


def reserve_tokens(prompt: str, output: int, steps: int) -> int:
    """Exact upper bound for repeated inputs, outputs and deterministic tool markers."""
    output = min(output, MOCK_OUTPUT_CAP)
    growth = output + 2 + estimate_tokens(tool_result(prompt, 1))
    return steps * (estimate_tokens(prompt) + output) + growth * steps * (steps - 1) // 2
