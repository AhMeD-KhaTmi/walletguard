"""Network-visible, synthetic LLM. Bind to loopback, never a public interface."""

from fastapi import FastAPI

from app.mock_llm import complete
from app.schemas import ChatIn, Completion, Usage

app = FastAPI(title="P20 local mock LLM", version="1.0.0")


@app.get("/health")
async def health():
    return {"status": "ok", "backend": "synthetic", "cost_is_simulated": True}


@app.post("/complete", response_model=Completion)
async def completion(body: ChatIn) -> Completion:
    text, n_in, n_out, cost = await complete(body.prompt, body.max_output_tokens)
    return Completion(text=text, usage=Usage(tokens_in=n_in, tokens_out=n_out, cost_usd=cost))
