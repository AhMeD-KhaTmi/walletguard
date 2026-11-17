"""Network-visible, synthetic LLM. Bind to loopback, never a public interface."""

from fastapi import FastAPI

from app.mock_llm import Latency, complete
from app.schemas import ChatIn, Completion, Usage
from common.tokens import TOKENIZER_VERSION
from dataclasses import asdict

app = FastAPI(title="P20 local mock LLM", version="1.0.0")
latency = Latency.from_env()
usage_totals = {"calls": 0, "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0}


@app.get("/health")
async def health():
    return {"status": "ok", "backend": "synthetic", "cost_is_simulated": True,
            "tokenizer": TOKENIZER_VERSION, "latency": asdict(latency)}


@app.post("/complete", response_model=Completion)
async def completion(body: ChatIn) -> Completion:
    text, n_in, n_out, cost = await complete(body.prompt, body.max_output_tokens, latency)
    usage_totals["calls"] += 1
    usage_totals["tokens_in"] += n_in
    usage_totals["tokens_out"] += n_out
    usage_totals["cost_usd"] += cost
    return Completion(text=text, usage=Usage(tokens_in=n_in, tokens_out=n_out, cost_usd=cost))


@app.get("/_metrics/usage")
async def usage():
    return dict(usage_totals)
