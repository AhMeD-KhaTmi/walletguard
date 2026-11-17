import httpx
import pytest

from app.main import create_app
from app.settings import Settings
from common.tokens import estimate_tokens
from conftest import TEST_REDIS_URL


@pytest.fixture
async def api_client(redis_db, llm_url):
    api = create_app(Settings(redis_url=TEST_REDIS_URL, llm_base_url=llm_url))
    async with api.router.lifespan_context(api):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=api), base_url="http://target",
        ) as client:
            yield client, api


async def login(client):
    result = await client.post("/login", json={"username": "user1", "password": "Passw0rd!1"})
    assert result.status_code == 200
    return {"authorization": "Bearer " + result.json()["token"]}


async def test_baseline_unlimited_logins_and_full_catalogue(api_client):
    client, _ = api_client
    for _ in range(1000):
        result = await client.post("/login", json={"username": "user1", "password": "wrong"})
        assert result.status_code == 401
        assert result.json()["detail"] == "wrong password"
    missing = await client.post("/login", json={"username": "absent", "password": "wrong"})
    assert missing.json()["detail"] == "unknown user"
    ids = []
    for page in range(1, 51):
        result = await client.get("/products", params={"page": page, "per_page": 100})
        assert result.status_code == 200
        ids.extend(item["id"] for item in result.json()["items"])
    assert ids == list(range(1, 5001))


async def test_real_http_mock_usage_headers_and_counters(api_client, redis_db):
    client, _ = api_client
    headers = await login(client)
    prompt = "hello from the API"
    for _ in range(2):
        result = await client.post("/chat", headers=headers, json={"prompt": prompt, "agent_steps": 1, "max_output_tokens": 32000})
        assert result.status_code == 200
        usage = result.json()["usage"]
        assert usage["tokens_in"] == estimate_tokens(prompt)
        assert usage["tokens_out"] == 32000
        assert int(result.headers["x-tokens-in"]) == usage["tokens_in"]
        assert int(result.headers["x-tokens-out"]) == usage["tokens_out"]
        assert float(result.headers["x-cost-usd"]) == pytest.approx(usage["cost_usd"], abs=0.000001)
        assert estimate_tokens(result.json()["text"]) == usage["tokens_out"]
    total = (await client.get("/_metrics/usage")).json()
    account = redis_db.hgetall("p20:app:usage:user1")
    assert total == account
    assert int(total["requests"]) == 2
    assert int(total["tokens_out"]) == 64000
    assert int(total["tokens_in"]) == 2 * estimate_tokens(prompt)
    assert float(total["cost_usd"]) == pytest.approx(2 * usage["cost_usd"])


@pytest.mark.parametrize("output", [-10, 0, True, 1.5, "100"])
async def test_invalid_output_does_not_generate_or_charge(api_client, redis_db, output):
    client, _ = api_client
    result = await client.post("/chat", headers=await login(client), json={"prompt": "hello", "agent_steps": 1, "max_output_tokens": output})
    assert result.status_code == 422
    assert redis_db.hgetall("p20:app:usage:total") == {}


async def test_authentication_and_session_expiry(api_client, redis_db):
    client, _ = api_client
    body = {"prompt": "hello", "agent_steps": 1, "max_output_tokens": 10}
    assert (await client.post("/chat", json=body)).status_code == 401
    headers = await login(client)
    key = "p20:app:session:" + headers["authorization"][7:]
    assert 0 < redis_db.ttl(key) <= 3600
    redis_db.delete(key)
    assert (await client.post("/chat", headers=headers, json=body)).status_code == 401
    assert not redis_db.exists("p20:app:usage:total")


async def test_readiness_and_openapi(api_client):
    client, _ = api_client
    health = await client.get("/health")
    assert health.status_code == 200
    assert health.json()["dependencies"] == {"redis": "ok", "mock_llm": "ok"}
    assert health.json()["waf_mode"] == "off"
    assert health.json()["cost_is_simulated"] is True
    spec = (await client.get("/openapi.json")).json()
    assert {"/login", "/products", "/chat", "/health", "/_metrics/usage"} <= spec["paths"].keys()
    assert (await client.get("/docs")).status_code == 200


@pytest.mark.parametrize("failure,expected", [("connect", 502), ("timeout", 504), ("bad_json", 502)])
async def test_backend_failure_is_explicit_not_retried_or_charged(api_client, redis_db, failure, expected):
    client, api = api_client
    headers = await login(client)
    calls = []

    def backend(request):
        calls.append(request)
        if failure == "connect":
            raise httpx.ConnectError("offline", request=request)
        if failure == "timeout":
            raise httpx.ReadTimeout("late", request=request)
        return httpx.Response(200, json={"unexpected": "data"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(backend), base_url="http://mock") as fake:
        original = api.state.llm
        api.state.llm = fake
        try:
            result = await client.post("/chat", headers=headers, json={"prompt": "hello", "agent_steps": 1})
            assert result.status_code == expected
            assert len(calls) == 1
            assert not redis_db.exists("p20:app:usage:total")
        finally:
            api.state.llm = original


async def test_readiness_reports_unavailable_backend(api_client):
    client, api = api_client

    def offline(request):
        raise httpx.ConnectError("offline", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(offline), base_url="http://mock") as fake:
        original = api.state.llm
        api.state.llm = fake
        try:
            result = await client.get("/health")
            assert result.status_code == 503
            assert result.json()["dependencies"]["mock_llm"] == "unavailable"
        finally:
            api.state.llm = original


def test_invalid_mode_rejected(monkeypatch):
    monkeypatch.setenv("WAF_MODE", "typo")
    with pytest.raises(ValueError, match="WAF_MODE"):
        Settings.from_env()
