"""Bounded simulated tool loop with real local HTTP calls and growing context."""

import math

import httpx
from fastapi import HTTPException
from pydantic import ValidationError

from app.mock_llm import IN_PER_1K, OUT_PER_1K
from app.schemas import AgentCompletion, AgentStep, ChatIn, Completion, Usage
from common.agent import MOCK_OUTPUT_CAP, next_context, tool_result
from common.tokens import TOKENIZER_VERSION, estimate_tokens


async def run_agent(client: httpx.AsyncClient, body: ChatIn, scope: dict) -> AgentCompletion:
    context = body.prompt
    iterations = []
    totals = {"tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0}
    for step in range(1, body.agent_steps + 1):
        scope["p20.generation"] = "started"
        try:
            response = await client.post("/complete", json={"prompt": context,
                                                          "max_output_tokens": body.max_output_tokens},
                                         headers={"Connection": "close"})
            response.raise_for_status()
            completion = Completion.model_validate(response.json())
            usage = completion.usage
            expected_cost = usage.tokens_in / 1000 * IN_PER_1K + usage.tokens_out / 1000 * OUT_PER_1K
            if (usage.tokens_in != estimate_tokens(context) or usage.tokens_out != estimate_tokens(completion.text)
                    or usage.tokens_out > min(body.max_output_tokens, MOCK_OUTPUT_CAP)
                    or not math.isclose(usage.cost_usd, expected_cost, abs_tol=1e-12)):
                raise ValueError("inconsistent synthetic token accounting")
        except httpx.ConnectError as exc:
            scope["p20.generation"] = "not_generated"
            raise HTTPException(502, "mock LLM unavailable") from exc
        except httpx.TimeoutException as exc:
            raise HTTPException(504, "mock LLM timed out; usage may be uncertain") from exc
        except (httpx.HTTPError, ValidationError, ValueError) as exc:
            raise HTTPException(502, "mock LLM unavailable or invalid response") from exc

        for key, value in usage.model_dump().items():
            totals[key] += value
        iterations.append(AgentStep(iteration=step, tool="catalogue_lookup", usage=usage))
        scope["p20.usage"] = Usage(**totals)
        scope["p20.agent_steps_completed"] = step
        scope["p20.generation"] = "completed"
        context = next_context(context, completion.text, tool_result(body.prompt, step))

    return AgentCompletion(text=completion.text, usage=Usage(**totals), iterations=iterations,
                           agent_steps=len(iterations), tokenizer=TOKENIZER_VERSION)
