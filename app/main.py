"""One target API for C0–C4; only the WAF mode changes protection."""

import secrets
import time
import asyncio
from contextlib import asynccontextmanager

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, Header, HTTPException, Response, Request
from fastapi.staticfiles import StaticFiles
from redis.exceptions import RedisError
from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff

from app.schemas import ChatIn, AgentCompletion, LoginIn
from app.agent import run_agent
from common.agent import AGENT_VERSION
from common.tokens import TOKENIZER_VERSION
from app.settings import Settings
from app.web import STATIC, web_router
from waf.config import Config
from waf.state import State

# Synthetic demo accounts; deliberately simple target authentication.
USERS = {f"user{i}": f"Passw0rd!{i}" for i in range(1, 51)}
PRODUCTS = [
    {"id": i, "name": f"Product {i}", "price": round(5 + (i * 37) % 200, 2)}
    for i in range(1, 5001)
]


def create_app(settings: Settings | None = None, waf_config: Config | None = None) -> FastAPI:
    cfg = settings or Settings.from_env()
    policy = waf_config or Config.from_env(mode=cfg.waf_mode, redis_url=cfg.redis_url)
    if policy.mode != cfg.waf_mode or policy.redis_url != cfg.redis_url:
        raise ValueError("application and WAF configuration must agree")
    if policy.use_ebpf_signals:
        raise ValueError("eBPF signal integration is pending; use C0–C3 for now")
    runtime = State(policy)
    if policy.enable_ml and policy.mode != "off":
        from waf.scoring import Scorer
        runtime.scorer = Scorer(policy.model_path)

    @asynccontextmanager
    async def lifespan(api: FastAPI):
        async with (
            aioredis.from_url(
                cfg.redis_url, decode_responses=True,
                socket_connect_timeout=2, socket_timeout=2,
                retry=Retry(NoBackoff(), 0),
            ) as redis_client,
            httpx.AsyncClient(
                base_url=cfg.llm_base_url, timeout=cfg.llm_timeout_s,
                trust_env=False,
            ) as llm_client,
        ):
            api.state.redis = redis_client
            runtime.r = redis_client
            if policy.mode != "off":
                try:
                    await redis_client.set("p20:meta:schema_version", "2", nx=True)
                    if await redis_client.get("p20:meta:schema_version") != "2":
                        raise ValueError("Redis schema mismatch; expected version 2")
                except RedisError:
                    runtime.event("startup", {"status": "redis_unavailable", "ts_ms": int(time.time()*1000)})
            api.state.llm = llm_client
            yield

    api = FastAPI(title="P20 target API", version="1.0.0", lifespan=lifespan)
    api.state.settings = cfg
    api.state.runtime = runtime
    api.state.waf_config = policy
    api.include_router(web_router())
    api.mount("/assets", StaticFiles(directory=STATIC), name="assets")

    @api.get("/health", tags=["Operations"])
    async def health(response: Response):
        dependencies = {"redis": "unavailable", "mock_llm": "unavailable"}
        try:
            if await api.state.redis.ping():
                dependencies["redis"] = "ok"
        except RedisError:
            pass
        try:
            result = await api.state.llm.get("/health")
            if (result.status_code == 200 and result.json().get("backend") == "synthetic"
                    and result.json().get("tokenizer") == TOKENIZER_VERSION):
                dependencies["mock_llm"] = "ok"
        except (httpx.HTTPError, ValueError, AttributeError):
            pass
        ready = all(v == "ok" for v in dependencies.values())
        response.status_code = 200 if ready else 503
        return {
            "status": "ok" if ready else "degraded",
            "waf_mode": cfg.waf_mode,
            "dependencies": dependencies,
            "cost_is_simulated": True,
            "agent_version": AGENT_VERSION, "tokenizer": TOKENIZER_VERSION,
            "active_agent_tasks": runtime.active_agent_tasks,
            "controls": {"buckets": policy.enable_buckets and policy.mode == "enforce",
                         "honeypot": policy.enable_honeypot and policy.mode == "enforce",
                         "ml": runtime.scorer is not None, "kernel": False},
        }

    @api.post("/login", tags=["Target"])
    async def login(body: LoginIn):
        # Intentionally unlimited and enumerable in C0.
        if body.username not in USERS:
            raise HTTPException(401, "unknown user")
        if USERS[body.username] != body.password:
            raise HTTPException(401, "wrong password")
        token = secrets.token_hex(16)
        try:
            await runtime.create_session(token, body.username)
        except RedisError as exc:
            raise HTTPException(503, "session store unavailable") from exc
        return {"token": token}

    @api.post("/logout", tags=["Target"])
    async def logout(authorization: str | None = Header(default=None)):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "missing token")
        try:
            await runtime.logout(authorization)
        except RedisError as exc:
            raise HTTPException(503, "session store unavailable") from exc
        return {"status": "logged_out"}

    @api.get("/products", tags=["Target"])
    async def products(page: int = 1, per_page: int = 20):
        # Intentionally permits unrestricted crawling in C0.
        per_page = max(1, min(per_page, 100))
        start = (max(page, 1) - 1) * per_page
        return {"page": page, "items": PRODUCTS[start:start + per_page], "total": len(PRODUCTS)}

    async def current_user(authorization: str | None) -> str:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "missing token")
        user, degraded = await runtime.lookup(authorization)
        if not user:
            if degraded:
                raise HTTPException(503, "session unavailable in local cache during Redis outage")
            raise HTTPException(401, "invalid token")
        return user

    @api.post("/chat", response_model=AgentCompletion, tags=["Target"])
    async def chat(
        body: ChatIn, response: Response, request: Request,
        authorization: str | None = Header(default=None),
    ):
        user = await current_user(authorization)
        runtime.active_agent_tasks += 1
        try:
            completion = await run_agent(api.state.llm, body, request.scope)
        finally:
            try:
                known_usage = request.scope.get("p20.usage")
                if known_usage is not None:
                    store = await asyncio.shield(runtime.charge(user, known_usage,
                        agent_steps=request.scope["p20.agent_steps_completed"]))
            finally:
                runtime.active_agent_tasks -= 1

        usage = completion.usage
        request.scope["p20.usage"] = usage
        response.headers["X-Tokens-In"] = str(usage.tokens_in)
        response.headers["X-Tokens-Out"] = str(usage.tokens_out)
        response.headers["X-Cost-USD"] = f"{usage.cost_usd:.6f}"
        response.headers["X-Usage-Store"] = store
        response.headers["X-Agent-Steps"] = str(completion.agent_steps)
        response.headers["X-Tokenizer"] = TOKENIZER_VERSION
        return completion

    @api.get("/_metrics/usage", tags=["Operations"])
    async def usage():
        try:
            return await api.state.redis.hgetall("p20:app:usage:total")
        except RedisError as exc:
            raise HTTPException(503, "usage store unavailable") from exc

    @api.get("/robots.txt", include_in_schema=False)
    async def robots():
        return Response(
            "User-agent: *\nDisallow: /admin-backup/\nDisallow: /internal/export\n",
            media_type="text/plain",
        )

    if cfg.waf_mode != "off":
        from waf.middleware import WAFMiddleware
        api.add_middleware(WAFMiddleware, state=runtime)
    return api


app = create_app()
