import asyncio
import json
import time
from dataclasses import replace

import httpx
import pytest
import redis.asyncio as aioredis
from redis.exceptions import ConnectionError

from app.main import create_app
from app.settings import Settings
from conftest import TEST_REDIS_URL
from waf.bans import BanStore
from waf.buckets import TokenBucket
from waf.config import Config
from waf.features import FeatureStore
from waf.state import State


class Offline:
    def pipeline(self, *args, **kwargs):
        return self

    def get(self, *args):
        return self

    def pttl(self, *args):
        return self

    def hincrby(self, *args):
        return self

    def hincrbyfloat(self, *args):
        return self

    async def execute(self):
        raise ConnectionError("test outage")

    async def eval(self, *args):
        raise ConnectionError("test outage")

    async def sismember(self, *args):
        raise ConnectionError("test outage")

    async def exists(self, *args):
        raise ConnectionError("test outage")

    async def set(self, *args, **kwargs):
        raise ConnectionError("test outage")

    async def delete(self, *args, **kwargs):
        raise ConnectionError("test outage")

    async def xadd(self, *args, **kwargs):
        raise ConnectionError("test outage")

    async def zrangebyscore(self, *args, **kwargs):
        raise ConnectionError("test outage")


@pytest.fixture
async def redis_async(redis_db):
    async with aioredis.from_url(TEST_REDIS_URL, decode_responses=True) as r:
        yield r


@pytest.fixture
def policy():
    return Config(mode="enforce", redis_url=TEST_REDIS_URL, run_id="test-defenses")


@pytest.fixture
async def target(redis_db, llm_url, policy):
    app = create_app(Settings(redis_url=TEST_REDIS_URL, llm_base_url=llm_url, waf_mode=policy.mode), policy)
    async with app.router.lifespan_context(app):
        yield app


def client(app, ip="10.20.0.11"):
    return httpx.AsyncClient(base_url="http://target", transport=httpx.ASGITransport(app=app, client=(ip, 1234)))


async def login(c):
    result = await c.post("/login", json={"username": "user1", "password": "Passw0rd!1"})
    assert result.status_code == 200, result.text
    return {"authorization": "Bearer " + result.json()["token"]}


async def test_login_throttle_retry_and_budget_ban(target, redis_db):
    async with client(target) as c:
        for _ in range(5):
            assert (await c.post("/login", json={"username": "user1", "password": "wrong"})).status_code == 401
        for _ in range(5):
            result = await c.post("/login", json={"username": "user1", "password": "wrong"})
            assert result.status_code == 429
            assert int(result.headers["retry-after"]) >= 1
        assert (await c.get("/products")).status_code == 403
    ban = json.loads(redis_db.get("p20:ban:10.20.0.11"))
    assert ban["reason"] == "budget" and ban["source"] == "waf"
    assert 0 < redis_db.ttl("p20:ban:10.20.0.11") <= 600
    rows = redis_db.xrange("p20:stream:waf_decisions")
    assert any(f["decision"] == "ban" for _, f in rows)
    assert all(f["schema_version"] == "2" and f["request_id"] for _, f in rows)


async def test_account_limit_across_source_ips(target):
    for i in range(6):
        async with client(target, f"10.20.0.{20+i}") as c:
            result = await c.post("/login", json={"username": "user2", "password": "wrong"})
            assert result.status_code == (401 if i < 5 else 429)
            if i == 5:
                assert result.json()["error"] == "login_acct"


async def test_honeypot_boundary_ban_and_allowlist(target, redis_db):
    redis_db.sadd("p20:allowlist", "10.20.0.2")
    async with client(target, "10.20.0.2") as c:
        assert (await c.get("/.env")).status_code == 404
        assert not redis_db.exists("p20:ban:10.20.0.2")
    async with client(target) as c:
        assert (await c.get("/admin-backup-unrelated")).status_code == 404
        assert not redis_db.exists("p20:ban:10.20.0.11")
        assert (await c.get("/admin-backup/private")).status_code == 404
        assert redis_db.exists("p20:ban:10.20.0.11")
        assert (await c.get("/products", headers={"x-forwarded-for": "10.20.0.2"})).status_code == 403


async def test_existing_external_ban_uses_same_rule(target, redis_db):
    redis_db.set("p20:ban:10.20.0.11", json.dumps({"reason": "ebpf_conn_flood", "source": "ebpf"}), ex=10)
    async with client(target) as c:
        assert (await c.get("/products")).status_code == 403


async def test_output_policy_and_actual_token_charge(target, redis_db):
    async with client(target) as c:
        headers = await login(c)
        assert (await c.post("/chat", headers=headers, json={"prompt": "hello", "agent_steps": 1, "max_output_tokens": 32000})).status_code == 400
        response = await c.post("/chat", headers=headers, json={"prompt": "hello", "agent_steps": 1, "max_output_tokens": 100})
        assert response.status_code == 200
        request_id = response.headers["x-request-id"]
    row = next(f for _, f in redis_db.xrange("p20:stream:waf_decisions") if f["request_id"] == request_id)
    assert int(row["llm_tokens_charged"]) == 101
    assert float(row["tokens_reserved"]) == 101
    assert float(row["tokens_refunded"]) == 0
    assert row["accounting_status"] == "known"
    assert 19899 <= float(redis_db.hget("p20:bkt:llm_tok:user1", "tokens")) < 20000
    assert target.state.runtime.timings[-1]["waf_overhead_ms"] >= float(row["latency_ms"])


async def test_token_exhaustion_with_valid_under_cap_chat(redis_db, llm_url, policy):
    budgets = {**policy.budgets, "llm_tok": (10, .001)}
    policy = replace(policy, budgets=budgets)
    app = create_app(Settings(redis_url=TEST_REDIS_URL, llm_base_url=llm_url, waf_mode="enforce"), policy)
    async with app.router.lifespan_context(app), client(app) as c:
        headers = await login(c)
        assert (await c.post("/chat", headers=headers, json={"prompt": "hi", "agent_steps": 1, "max_output_tokens": 8})).status_code == 200
        result = await c.post("/chat", headers=headers, json={"prompt": "hi", "agent_steps": 1, "max_output_tokens": 8})
        assert result.status_code == 429 and result.json()["error"] == "llm_tok"
        assert (await c.post("/chat", headers=headers, json={"prompt": "hi", "agent_steps": 1, "max_output_tokens": 20})).status_code == 400
    assert redis_db.hget("p20:app:usage:total", "requests") == "1"


@pytest.mark.parametrize("failure,refund", [("connect", True), ("timeout", False), ("invalid", False)])
async def test_reservations_refund_only_known_unused_generation(target, redis_db, failure, refund):
    async with client(target) as c:
        headers = await login(c)
        def backend(request):
            if failure == "connect":
                raise httpx.ConnectError("offline", request=request)
            if failure == "timeout":
                raise httpx.ReadTimeout("unknown", request=request)
            return httpx.Response(200, json={"broken": True})
        async with httpx.AsyncClient(base_url="http://mock", transport=httpx.MockTransport(backend)) as mock:
            original = target.state.llm
            target.state.llm = mock
            try:
                result = await c.post("/chat", headers=headers, json={"prompt": "hello", "agent_steps": 1, "max_output_tokens": 100})
                assert result.status_code in (502, 504)
            finally:
                target.state.llm = original
    row = redis_db.xrevrange("p20:stream:waf_decisions", count=1)[0][1]
    assert float(row["tokens_refunded"]) == (101 if refund else 0)
    assert row["accounting_status"] == ("known" if refund else "uncertain")


async def test_observe_collects_every_request_without_enforcement(redis_db, llm_url, policy):
    policy = replace(policy, mode="observe", max_body_bytes=50)
    app = create_app(Settings(redis_url=TEST_REDIS_URL, llm_base_url=llm_url, waf_mode="observe"), policy)
    async with app.router.lifespan_context(app), client(app) as c:
        for _ in range(12):
            assert (await c.post("/login", json={"username": "user1", "password": "wrong"})).status_code == 401
        assert (await c.get("/.env")).status_code == 404
        # Oversized shadow input must be replayed in full to normal API validation.
        result = await c.post("/login", json={"username": "u"*200, "password": "x"})
        assert result.status_code == 401
    assert redis_db.xlen("p20:stream:waf_features") == 14
    assert redis_db.xlen("p20:stream:waf_decisions") == 14
    assert not redis_db.keys("p20:ban:*")
    assert not redis_db.keys("p20:bkt:*")
    assert not redis_db.keys("p20:strike:*")
    assert any(f["decision"].startswith("would_") for _, f in redis_db.xrange("p20:stream:waf_decisions"))


async def test_body_size_and_chunk_replay(target):
    async with client(target) as c:
        response = await c.post("/login", content=b"x"*1_000_001)
        assert response.status_code == 413
    from waf.middleware import buffer_body
    messages = iter([{"type": "http.request", "body": b"ab", "more_body": True},
                     {"type": "http.request", "body": b"cd", "more_body": True},
                     {"type": "http.request", "body": b"ef", "more_body": False}])
    async def receive():
        return next(messages)
    prefix, replay, oversize = await buffer_body(receive, 3)
    assert prefix == b"abcd" and oversize
    actual = b""
    while True:
        msg = await replay()
        actual += msg["body"]
        if not msg.get("more_body", False):
            break
    assert actual == b"abcdef"


async def test_buckets_concurrent_atomic_and_capped_refund(redis_async):
    bucket = TokenBucket(redis_async)
    results = await asyncio.gather(*(bucket.take("p20:bkt:race", 5, .001) for _ in range(30)))
    assert sum(result[0] for result in results) == 5
    await asyncio.gather(*(bucket.refund("p20:bkt:race", 5, 2) for _ in range(20)))
    assert float(await redis_async.hget("p20:bkt:race", "tokens")) == 5
    for values in ((5, 1, -1), (5, 0, 1), (5, 1, float("nan")), (5, 1, 6)):
        with pytest.raises(ValueError):
            await bucket.take("bad", *values)


async def test_bucket_outage_and_recovery_do_not_grant_new_burst(redis_async):
    bucket = TokenBucket(redis_async)
    assert (await bucket.take("p20:bkt:recover", 5, .001, 3))[0]
    bucket.r = Offline()
    assert (await bucket.take("p20:bkt:recover", 5, .001, 2))[0]
    assert not (await bucket.take("p20:bkt:recover", 5, .001))[0]
    bucket.r = redis_async
    assert not (await bucket.take("p20:bkt:recover", 5, .001))[0]
    assert float(await redis_async.hget("p20:bkt:recover", "tokens")) < .1


async def test_ban_pubsub_expiry_strike_ttl_and_local_recovery(redis_async, policy):
    state = State(replace(policy, ban_ttl_s=1))
    state.r = redis_async
    store = BanStore(state)
    async with redis_async.pubsub() as channel:
        await channel.subscribe("p20:ch:ban")
        await channel.get_message(timeout=1)
        assert await store.ban("10.0.0.8", "honeypot")
        event = await channel.get_message(ignore_subscribe_messages=True, timeout=1)
        assert json.loads(event["data"])["reason"] == "honeypot"
    assert await store.is_banned("10.0.0.8")
    assert await store.strike("10.0.0.8") == 1
    assert await redis_async.pttl("p20:strike:budget:10.0.0.8") > 0
    state.r = Offline()
    assert await store.ban("10.0.0.9", "budget")
    assert await store.is_banned("10.0.0.9")
    state.r = redis_async
    assert await store.is_banned("10.0.0.9")
    assert await redis_async.pttl("p20:ban:10.0.0.9") <= 1000
    await asyncio.sleep(1.05)
    assert not await store.is_banned("10.0.0.9")


async def test_features_count_more_than_100_and_flag_saturation(redis_async, policy):
    state = State(replace(policy, max_events=150))
    state.r = redis_async
    features = FeatureStore(state)
    for _ in range(160):
        await features.record("10.0.0.8", "/products", 200)
    values = await features.extract("10.0.0.8", "/chat", {}, {"prompt": "hello", "agent_steps": 1}, 10)
    assert values["req_60s"] == 150 and values["window_saturated"] == 1
    assert values["prompt_tokens"] == 1


async def test_cached_session_local_usage_and_outage_protection(target, redis_db):
    async with client(target) as c:
        headers = await login(c)
        assert (await c.post("/chat", headers=headers, json={"prompt": "hi", "agent_steps": 1, "max_output_tokens": 8})).status_code == 200
        state = target.state.runtime
        original = state.r
        state.r = Offline()
        try:
            result = await c.post("/chat", headers=headers, json={"prompt": "hi", "agent_steps": 1, "max_output_tokens": 8})
            assert result.status_code == 200, result.text
            assert result.headers["x-usage-store"] == "local_uncertain_redis_commit"
            assert state.outage_usage["requests"] == 1
            assert state.outage_events
            assert (await c.post("/login", json={"username": "user1", "password": "Passw0rd!1"})).status_code == 503
            assert (await c.get("/.env")).status_code == 404
            assert (await c.get("/products")).status_code == 403
        finally:
            state.r = original
    assert redis_db.hget("p20:app:usage:total", "requests") == "1"


def test_missing_ml_and_kernel_integration_are_explicit(policy):
    with pytest.raises(ValueError, match="missing"):
        create_app(Settings(redis_url=TEST_REDIS_URL, waf_mode="enforce"), replace(policy, enable_ml=True, model_path="/tmp/p20-does-not-exist.joblib"))
    with pytest.raises(ValueError, match="integration is pending"):
        create_app(Settings(redis_url=TEST_REDIS_URL, waf_mode="enforce"), replace(policy, use_ebpf_signals=True))


async def test_duplicate_authorization_uses_same_account_as_app(target, redis_db):
    async with client(target) as c:
        first = (await login(c))["authorization"]
        second = await c.post("/login", json={"username": "user2", "password": "Passw0rd!2"})
        second = "Bearer "+second.json()["token"]
        result = await c.post("/chat", headers=[("authorization", first), ("authorization", second)],
                              json={"prompt": "hello", "agent_steps": 1, "max_output_tokens": 10})
        assert result.status_code == 200
    row = redis_db.xrevrange("p20:stream:waf_decisions", count=1)[0][1]
    assert row["client_id"] == "user1"
    assert redis_db.exists("p20:bkt:llm_tok:user1")
    assert not redis_db.exists("p20:bkt:llm_tok:user2")
    assert redis_db.hget("p20:app:usage:user1", "requests") == "1"


async def test_partial_generation_refund_and_actual_decision_accounting(target, redis_db):
    async with client(target) as c:
        headers = await login(c)
        def backend(request):
            return httpx.Response(200, json={"text": "tiny tiny tiny tiny tiny", "usage": {"tokens_in": 1, "tokens_out": 5, "cost_usd": .000078}})
        async with httpx.AsyncClient(base_url="http://mock", transport=httpx.MockTransport(backend)) as mock:
            original = target.state.llm
            target.state.llm = mock
            try:
                assert (await c.post("/chat", headers=headers, json={"prompt": "hi", "agent_steps": 1, "max_output_tokens": 100})).status_code == 200
            finally:
                target.state.llm = original
    row = redis_db.xrevrange("p20:stream:waf_decisions", count=1)[0][1]
    assert float(row["tokens_reserved"]) == 101
    assert float(row["tokens_refunded"]) == 95
    assert row["llm_tokens_charged"] == "6"


async def test_strike_recovery_keeps_outage_strikes(redis_async, policy):
    state = State(policy)
    state.r = redis_async
    store = BanStore(state)
    assert await store.strike("10.0.0.7") == 1
    initial_ttl = await redis_async.pttl("p20:strike:budget:10.0.0.7")
    state.r = Offline()
    assert await store.strike("10.0.0.7") == 2
    assert await store.strike("10.0.0.7") == 3
    state.r = redis_async
    assert await store.strike("10.0.0.7") == 4
    assert await redis_async.pttl("p20:strike:budget:10.0.0.7") <= initial_ttl


async def test_local_strikes_are_atomic_under_concurrency(policy):
    state = State(policy)
    state.r = Offline()
    bans = BanStore(state)
    counts = await asyncio.gather(*(bans.strike("10.0.0.7") for _ in range(20)))
    assert sorted(counts) == list(range(1, 21))


async def test_local_logout_is_not_undone_by_outage_cached_auth(target):
    async with client(target) as c:
        headers = await login(c)
    state = target.state.runtime
    original = state.r
    state.r = Offline()
    try:
        with pytest.raises(ConnectionError):
            await state.logout(headers["authorization"])
        assert await state.user(headers["authorization"]) is None
    finally:
        state.r = original


async def test_schema_mismatch_is_not_silently_accepted(redis_db, llm_url, policy):
    redis_db.set("p20:meta:schema_version", "1")
    app = create_app(Settings(redis_url=TEST_REDIS_URL, llm_base_url=llm_url, waf_mode="enforce"), policy)
    with pytest.raises(ValueError, match="schema mismatch"):
        async with app.router.lifespan_context(app):
            pass


async def test_benign_multi_ip_smoke_stays_unbanned(target, redis_db):
    for i in range(1, 4):
        async with client(target, f"10.20.0.{30+i}") as c:
            for _ in range(5):
                assert (await c.get("/products")).status_code == 200
            login_result = await c.post("/login", json={"username": f"user{i}", "password": f"Passw0rd!{i}"})
            assert login_result.status_code == 200
            headers = {"authorization": "Bearer "+login_result.json()["token"]}
            assert (await c.post("/chat", headers=headers, json={"prompt": "hello", "agent_steps": 1, "max_output_tokens": 20})).status_code == 200
    assert not redis_db.keys("p20:ban:*")


async def test_full_waf_timing_includes_allowlist_lookup(target):
    original = target.state.runtime.allowlisted
    async def delayed(ip):
        await asyncio.sleep(.02)
        return await original(ip)
    target.state.runtime.allowlisted = delayed
    async with client(target) as c:
        assert (await c.get("/products")).status_code == 200
    assert target.state.runtime.timings[-1]["waf_overhead_ms"] >= 20


async def test_cancelled_app_before_generation_refunds_reservation(target, redis_db):
    async with client(target) as c:
        headers = await login(c)
    # Replace the route only in this unit test to cancel after WAF reservation.
    target.router.routes[:] = [r for r in target.router.routes if getattr(r, "path", None) != "/chat"]
    @target.post("/chat")
    async def cancelled():
        raise asyncio.CancelledError()
    async with client(target) as c:
        with pytest.raises(asyncio.CancelledError):
            await c.post("/chat", headers=headers, json={"prompt": "hi", "agent_steps": 1, "max_output_tokens": 10})
    row = redis_db.xrevrange("p20:stream:waf_decisions", count=1)[0][1]
    assert float(row["tokens_refunded"]) == float(row["tokens_reserved"]) == 11
    assert row["llm_tokens_charged"] == "0"
