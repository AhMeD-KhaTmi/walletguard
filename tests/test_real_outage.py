"""Failure checks against an owned, disposable Redis, never the user's service."""

import asyncio
import socket
import subprocess
import time

import httpx
import pytest
import redis

from app.main import create_app
from app.settings import Settings
from waf.config import Config


@pytest.fixture
def disposable_redis(tmp_path):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    command = ["redis-server", "--bind", "127.0.0.1", "--port", str(port),
               "--save", "", "--appendonly", "no", "--dir", str(tmp_path)]
    processes = []
    def start():
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(process)
        with redis.Redis(host="127.0.0.1", port=port, db=15, socket_timeout=.2) as r:
            for _ in range(100):
                if process.poll() is not None:
                    pytest.fail("owned Redis exited on startup")
                try:
                    if r.ping():
                        break
                except redis.RedisError:
                    pass
                time.sleep(.02)
            else:
                pytest.fail("owned Redis did not start")
            r.flushdb()
        return process
    try:
        yield f"redis://127.0.0.1:{port}/15", start
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


async def test_actual_redis_loss_cached_auth_local_ban_and_recovery(disposable_redis, llm_url):
    url, start = disposable_redis
    process = start()
    cfg = Config(mode="enforce", redis_url=url)
    app = create_app(Settings(redis_url=url, llm_base_url=llm_url, waf_mode="enforce"), cfg)
    async with app.router.lifespan_context(app), httpx.AsyncClient(
        base_url="http://target", transport=httpx.ASGITransport(app=app, client=("10.20.0.9", 1234)),
    ) as c:
        result = await c.post("/login", json={"username": "user1", "password": "Passw0rd!1"})
        assert result.status_code == 200
        headers = {"authorization": "Bearer " + result.json()["token"]}
        body = {"prompt": "hello", "max_output_tokens": 10}
        assert (await c.post("/chat", headers=headers, json=body)).status_code == 200
        process.terminate()
        process.wait(timeout=5)
        response = await c.post("/chat", headers=headers, json=body)
        assert response.status_code == 200, response.text
        assert response.headers["x-usage-store"] == "local_uncertain_redis_commit"
        assert app.state.runtime.outage_usage["tokens_out"] == 10
        assert (await c.get("/.env")).status_code == 404
        assert (await c.get("/products")).status_code == 403
        # Restart the owned Redis empty: pending local ban must reconcile with remaining TTL.
        process = start()
        assert (await c.get("/products")).status_code == 403
        assert await app.state.runtime.r.pttl("p20:ban:10.20.0.9") > 0


async def test_expired_cached_session_is_not_extended_during_outage(disposable_redis, llm_url):
    url, start = disposable_redis
    process = start()
    app = create_app(Settings(redis_url=url, llm_base_url=llm_url))
    async with app.router.lifespan_context(app), httpx.AsyncClient(
        base_url="http://target", transport=httpx.ASGITransport(app=app),
    ) as c:
        await app.state.runtime.r.set("p20:app:session:short", "user1", px=50)
        assert await app.state.runtime.user("Bearer short") == "user1"
        process.terminate()
        process.wait(timeout=5)
        await asyncio.sleep(.06)
        response = await c.post("/chat", headers={"authorization": "Bearer short"}, json={"prompt": "hi"})
        assert response.status_code == 503
