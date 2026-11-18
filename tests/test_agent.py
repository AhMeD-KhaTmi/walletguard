import json

import httpx
import pytest

from app.main import create_app
from app.mock_llm import Latency, complete
from app.settings import Settings
from common.agent import next_context, reserve_tokens, tool_result
from common.tokens import TOKENIZER_VERSION, estimate_tokens
from conftest import TEST_REDIS_URL
from waf.config import Config


async def test_mock_exact_tokens_and_deterministic_latency():
    latency = Latency(jitter_ms=5, seed=42)
    assert latency.delay("a b", 10) == latency.delay("a b", 10)
    text, n_in, n_out, _ = await complete("a\tb\n c", 7, Latency(cap_s=0))
    assert (n_in, n_out) == (3, 7)
    assert estimate_tokens(text) == 7 and estimate_tokens("") == 0
    with pytest.raises(ValueError):
        Latency(tokens_per_s=0)


@pytest.mark.parametrize("failure,known", [("connect", True), ("timeout", False)])
async def test_partial_agent_usage_and_reservation_recovery(redis_db, llm_url, failure, known):
    cfg = Config(mode="enforce", redis_url=TEST_REDIS_URL)
    api = create_app(Settings(redis_url=TEST_REDIS_URL, llm_base_url=llm_url, waf_mode="enforce"), cfg)
    calls = []

    def backend(request):
        body = json.loads(request.content)
        calls.append(body)
        if len(calls) > 1:
            error = httpx.ConnectError if failure == "connect" else httpx.ReadTimeout
            raise error("synthetic backend failure", request=request)
        return httpx.Response(200, json={"text": "lorem lorem lorem", "usage": {
            "tokens_in": estimate_tokens(body["prompt"]), "tokens_out": 3, "cost_usd": .000048}})

    async with api.router.lifespan_context(api), httpx.AsyncClient(base_url="http://target",
            transport=httpx.ASGITransport(app=api, client=("10.20.0.21", 1234))) as client:
        token = (await client.post("/login", json={"username": "user1", "password": "Passw0rd!1"})).json()["token"]
        async with httpx.AsyncClient(base_url="http://mock", transport=httpx.MockTransport(backend)) as fake:
            original, api.state.llm = api.state.llm, fake
            try:
                result = await client.post("/chat", headers={"authorization": f"Bearer {token}"},
                                           json={"prompt": "hello", "max_output_tokens": 10, "agent_steps": 3})
                assert result.status_code == (502 if known else 504)
            finally:
                api.state.llm = original
    assert len(calls) == 2
    assert calls[1]["prompt"] == next_context("hello", "lorem lorem lorem", tool_result("hello", 1))
    assert redis_db.hget("p20:app:usage:total", "agent_steps") == "1"
    assert redis_db.hget("p20:app:usage:total", "tokens_out") == "3"
    row = redis_db.xrevrange("p20:stream:waf_decisions", count=1)[0][1]
    assert row["llm_tokens_charged"] == "4" and row["agent_steps_completed"] == "1"
    assert row["accounting_status"] == ("known" if known else "uncertain")
    assert float(row["tokens_refunded"]) == (reserve_tokens("hello", 10, 3) - 4 if known else 0)


async def test_real_agent_loop_grows_context_and_charges_exact_total(redis_db, llm_url):
    api = create_app(Settings(redis_url=TEST_REDIS_URL, llm_base_url=llm_url, waf_mode="enforce"))
    async with api.router.lifespan_context(api), httpx.AsyncClient(base_url="http://target",
            transport=httpx.ASGITransport(app=api, client=("10.20.0.21", 1234))) as client:
        token = (await client.post("/login", json={"username": "user1", "password": "Passw0rd!1"})).json()["token"]
        reply = await client.post("/chat", headers={"authorization": f"Bearer {token}"},
                                  json={"prompt": "hello world", "max_output_tokens": 8})
        assert reply.status_code == 200
        body = reply.json()
        steps = body["iterations"]
        assert body["agent_steps"] == 3 and body["tokenizer"] == TOKENIZER_VERSION
        assert [s["usage"]["tokens_in"] for s in steps] == [2, 19, 36]
        assert body["usage"]["tokens_out"] == 24
        assert int(reply.headers["x-tokens-in"]) == 57
        assert int(reply.headers["x-agent-steps"]) == 3
    row = redis_db.xrevrange("p20:stream:waf_decisions", count=1)[0][1]
    assert int(row["tokens_reserved"]) == reserve_tokens("hello world", 8, 3) == 81
    assert row["llm_tokens_charged"] == "81"
    assert redis_db.hget("p20:app:usage:total", "agent_steps") == "3"


async def test_agent_task_budget_precedes_any_generation(redis_db, llm_url):
    api = create_app(Settings(redis_url=TEST_REDIS_URL, llm_base_url=llm_url, waf_mode="enforce"))
    async with api.router.lifespan_context(api), httpx.AsyncClient(base_url="http://target",
            transport=httpx.ASGITransport(app=api, client=("10.20.0.21", 1234))) as client:
        token = (await client.post("/login", json={"username": "user1", "password": "Passw0rd!1"})).json()["token"]
        response = await client.post("/chat", headers={"authorization": f"Bearer {token}"},
                                     json={"prompt": "catalogue " * 10_000, "agent_steps": 8, "max_output_tokens": 900})
        assert response.status_code == 400 and response.json()["error"] == "token_cost_exceeds_capacity"
        invalid = await client.post("/chat", headers={"authorization": f"Bearer {token}"},
                                    json={"prompt": "hi", "agent_steps": True})
        assert invalid.status_code == 422
    assert not redis_db.exists("p20:app:usage:total")
