"""Bounded local snapshots, cached authentication and nonfatal telemetry."""

import time
import asyncio
from collections import OrderedDict, deque

from redis.exceptions import RedisError


class State:
    def __init__(self, config):
        self.config = config
        self.r = None
        self.sessions = OrderedDict()
        self.revoked = OrderedDict()
        self.allowed = OrderedDict()
        self.timings = deque(maxlen=config.telemetry_limit)
        self.outage_events = deque(maxlen=config.telemetry_limit)
        self.outage_usage = {"requests": 0, "agent_steps": 0, "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0}
        self.dropped_events = 0
        self.dropped_timings = 0
        self.cache_evictions = 0
        self.scorer = None
        self.waf = None
        self.active_agent_tasks = 0

    async def eval(self, *args):
        return await self.r.eval(*args)

    def cache(self, cache, key, value):
        cache[key] = value
        cache.move_to_end(key)
        while len(cache) > self.config.max_clients:
            cache.popitem(last=False)
            self.cache_evictions += 1

    def timing(self, row):
        if len(self.timings) == self.timings.maxlen:
            self.dropped_timings += 1
        self.timings.append(row)

    def event(self, kind, fields):
        if len(self.outage_events) == self.outage_events.maxlen:
            self.dropped_events += 1
        self.outage_events.append({"kind": kind, **fields})

    async def allowlisted(self, ip):
        try:
            yes = bool(await self.r.sismember(self.config.allowlist_key, ip))
            self.cache(self.allowed, ip, (yes, time.monotonic()+self.config.allowlist_cache_s))
            return yes
        except RedisError:
            yes, expiry = self.allowed.get(ip, (False, 0))
            return yes and time.monotonic() < expiry

    async def create_session(self, token, user):
        started = time.monotonic()
        await self.r.set(f"p20:app:session:{token}", user, ex=3600)
        self.cache(self.sessions, token, (user, started+3600))

    async def lookup(self, authorization):
        if not authorization or not authorization.startswith("Bearer "):
            return None, False
        token = authorization[7:]
        if self.revoked.get(token, 0) > time.monotonic():
            return None, False
        started = time.monotonic()
        try:
            pipe = self.r.pipeline()
            pipe.get(f"p20:app:session:{token}")
            pipe.pttl(f"p20:app:session:{token}")
            user, ttl = await pipe.execute()
            if self.revoked.get(token, 0) > time.monotonic():
                return None, False
            if user and ttl > 0:
                self.cache(self.sessions, token, (user, started+ttl/1000))
                return user, False
            self.sessions.pop(token, None)
            return None, False
        except RedisError:
            user, expiry = self.sessions.get(token, (None, 0))
            return (user if time.monotonic() < expiry else None), True

    async def user(self, authorization):
        return (await self.lookup(authorization))[0]

    async def logout(self, authorization):
        token = authorization[7:]
        self.cache(self.revoked, token, time.monotonic()+3600)
        self.sessions.pop(token, None)
        await self.r.delete(f"p20:app:session:{token}")

    async def charge(self, user, usage, *, agent_steps=1):
        pipe = self.r.pipeline()
        for key in ("p20:app:usage:total", f"p20:app:usage:{user}"):
            for field, value in (("requests", 1), ("agent_steps", agent_steps),
                                 ("tokens_in", usage.tokens_in), ("tokens_out", usage.tokens_out)):
                pipe.hincrby(key, field, value)
            pipe.hincrbyfloat(key, "cost_usd", usage.cost_usd)
        try:
            await pipe.execute()
            return "redis"
        except (RedisError, asyncio.CancelledError) as exc:
            self.outage_usage["requests"] += 1
            self.outage_usage["agent_steps"] += agent_steps
            for field in ("tokens_in", "tokens_out", "cost_usd"):
                self.outage_usage[field] += getattr(usage, field)
            self.event("usage", {"ts_ms": int(time.time()*1000), "client_id": user,
                                 **usage.model_dump(), "redis_commit": "uncertain"})
            if isinstance(exc, asyncio.CancelledError):
                raise
            return "local_uncertain_redis_commit"

    async def log(self, stream, fields, maxlen):
        try:
            await self.r.xadd(stream, fields, maxlen=maxlen, approximate=True)
        except RedisError:
            self.event(stream, fields)
