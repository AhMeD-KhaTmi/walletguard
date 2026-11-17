import json

import httpx
import pytest

from app.main import create_app
from app.settings import Settings
from conftest import TEST_REDIS_URL


@pytest.fixture
async def web_api(redis_db, llm_url):
    app = create_app(Settings(redis_url=TEST_REDIS_URL, llm_base_url=llm_url))
    async with app.router.lifespan_context(app):
        yield app


def client(app, ip="127.0.0.1"):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=(ip, 12345)),
        base_url="http://target",
    )


async def test_demo_and_assets_are_public_but_dashboard_html_is_not_static(web_api):
    async with client(web_api, "10.20.0.12") as c:
        page = await c.get("/")
        assert page.status_code == 200
        assert "Simulated agent playground" in page.text
        assert 'id="agent-trace"' in page.text
        assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
        for path in ("/assets/style.css", "/assets/demo.js", "/assets/dashboard.js"):
            assert (await c.get(path)).status_code == 200
        for path in ("/assets/dashboard.html", "/assets/../templates/dashboard.html"):
            assert (await c.get(path)).status_code == 404


@pytest.mark.parametrize("path", ["/dashboard", "/dashboard/", "/dashboard/data", "/dashboard/evidence"])
async def test_dashboard_denies_remote_and_spoofed_headers(web_api, path):
    async with client(web_api, "10.20.0.12") as c:
        result = await c.get(path, headers={"x-forwarded-for": "127.0.0.1", "x-real-ip": "127.0.0.1"}, follow_redirects=True)
        assert result.status_code == 403
        assert "Completed chat" not in result.text


async def test_dashboard_allows_loopback_and_explicit_management_ip(web_api, redis_db):
    for ip in ("127.0.0.1", "::1", "10.20.0.2"):
        if ip == "10.20.0.2":
            redis_db.sadd("p20:allowlist", ip)
        async with client(web_api, ip) as c:
            assert (await c.get("/dashboard")).status_code == 200
            result = await c.get("/dashboard/data")
            assert result.status_code == 200
            assert result.headers["cache-control"] == "no-store"
            data = result.json()
            assert data["integration"] == "not_connected"
            assert data["dependencies"] == {"redis": "ok", "mock_llm": "ok"}
            assert data["usage"]["requests"] == 0
            assert data["decisions"] is None
            assert data["bans"] == []


async def test_dashboard_uses_real_usage_and_omits_sensitive_redis_fields(web_api, redis_db):
    redis_db.hset("p20:app:usage:total", mapping={"requests": 3, "tokens_in": 30, "tokens_out": 400, "cost_usd": .00609})
    redis_db.set("p20:app:session:never-expose-this", "user1")
    redis_db.xadd("p20:stream:waf_decisions", {"schema_version": "2", "ts_ms": "1000", "ip": "10.0.0.3", "route": "/chat", "decision": "allow", "reason": "<script>alert(1)</script>", "anomaly_score": "-0.5", "prompt": "private prompt", "authorization": "secret bearer"})
    redis_db.set("p20:ban:10.0.0.3", json.dumps({"source": "waf", "ip": "10.0.0.3", "reason": "honeypot", "private": "hidden"}), ex=60)
    redis_db.set("p20:ban:10.0.0.4", json.dumps({"source": "ebpf", "ip": "10.0.0.4", "reason": "ebpf_conn_flood"}), ex=60)
    async with client(web_api) as c:
        result = await c.get("/dashboard/data")
        data = result.json()
        assert data["usage"] == {"requests": 3, "tokens_in": 30, "tokens_out": 400, "cost_usd": .00609}
        assert len(data["decisions"]) == 1
        assert data["bans"][0]["ip"] == "10.0.0.3"
        assert len(data["bans"]) == 1
        for secret in ("never-expose-this", "private prompt", "secret bearer", "hidden"):
            assert secret not in result.text
        # User/telemetry strings are always rendered through textContent, not HTML.
        for asset in ("/assets/demo.js", "/assets/dashboard.js"):
            assert "innerHTML" not in (await c.get(asset)).text


async def test_legacy_telemetry_is_not_presented_as_verified(web_api, redis_db):
    redis_db.xadd("p20:stream:waf_decisions", {"ip": "10.0.0.3", "decision": "allow"})
    async with client(web_api) as c:
        data = (await c.get("/dashboard/data")).json()
        assert data["decisions"] is None


@pytest.mark.parametrize("value", ["nan", "inf", "-1", "invalid"])
async def test_corrupt_usage_is_unavailable_instead_of_fabricated(web_api, redis_db, value):
    redis_db.hset("p20:app:usage:total", mapping={"cost_usd": value})
    async with client(web_api) as c:
        response = await c.get("/dashboard/data")
        assert response.status_code == 200
        assert response.json()["usage"] is None
        assert "could not be read completely" in response.json()["telemetry_note"]


async def test_management_failure_is_closed_for_remote_but_visible_locally(web_api):
    from redis.exceptions import ConnectionError

    class Offline:
        async def sismember(self, *args):
            raise ConnectionError("offline")

        async def ping(self):
            raise ConnectionError("offline")

    original = web_api.state.redis
    web_api.state.redis = Offline()
    try:
        async with client(web_api, "10.20.0.2") as c:
            assert (await c.get("/dashboard/data")).status_code == 403
        async with client(web_api) as c:
            data = (await c.get("/dashboard/data")).json()
            assert data["dependencies"]["redis"] == "unavailable"
            assert data["usage"] is None
            assert data["bans"] is None
    finally:
        web_api.state.redis = original


async def test_logout_revokes_actual_server_session(web_api, redis_db):
    async with client(web_api) as c:
        login = await c.post("/login", json={"username": "user1", "password": "Passw0rd!1"})
        token = login.json()["token"]
        headers = {"authorization": f"Bearer {token}"}
        assert redis_db.exists("p20:app:session:" + token)
        assert (await c.post("/logout", headers=headers)).status_code == 200
        assert not redis_db.exists("p20:app:session:" + token)
        assert (await c.post("/chat", headers=headers, json={"prompt": "hello"})).status_code == 401
        assert (await c.post("/logout")).status_code == 401


async def test_dashboard_is_read_only(web_api, redis_db):
    redis_db.set("p20:meta:schema_version", "2")
    before = sorted(redis_db.keys("*"))
    async with client(web_api) as c:
        assert (await c.get("/dashboard/data")).status_code == 200
        assert (await c.post("/dashboard/data")).status_code == 405
    assert sorted(redis_db.keys("*")) == before
