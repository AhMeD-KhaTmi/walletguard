"""Atomic, allowlist-aware ban/strike writer and expiring outage snapshots."""

import json
import math
import time
import asyncio
from collections import OrderedDict

from redis.exceptions import RedisError

BAN_LUA = """
if redis.call('SISMEMBER', KEYS[1],ARGV[1]) == 1 then return 0 end
local remaining = tonumber(ARGV[3])
local t=redis.call('TIME')
local now=tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000)
remaining=math.min(remaining,tonumber(ARGV[5])-now)
if remaining <= 0 then return 0 end
if redis.call('PTTL',KEYS[2]) < remaining then
  redis.call('SET',KEYS[2],ARGV[2],'PX',remaining)
  redis.call('PUBLISH','p20:ch:ban',ARGV[4])
end
return 1
"""
STRIKE_LUA = """
local old=tonumber(redis.call('GET',KEYS[1])) or 0
local count=math.max(old,tonumber(ARGV[2]))+1
local ttl=redis.call('PTTL',KEYS[1])
local remaining=tonumber(ARGV[3])
if ttl > 0 then remaining=math.min(ttl,remaining) end
redis.call('SET',KEYS[1],count,'PX',math.max(1,remaining))
return {count,redis.call('PTTL',KEYS[1])}
"""


class BanStore:
    def __init__(self, state, *, shadow=False):
        self.state = state
        self.cfg = state.config
        self.prefix = "p20:shadow:" if shadow else "p20:"
        self.shadow = shadow
        self.cache = OrderedDict()
        self.pending = OrderedDict()
        self.strikes = OrderedDict()
        self.strike_lock = asyncio.Lock()

    async def _write(self, ip, payload, remaining_ms):
        event = json.dumps({"op": "add", "ip": ip, "ttl_s": math.ceil(remaining_ms/1000), "reason": payload["reason"]})
        return await self.state.r.eval(
            BAN_LUA, 2, self.cfg.allowlist_key, f"p20:ban:{ip}",
            ip, json.dumps(payload), remaining_ms, event,
            payload["ts_ms"]+payload["ttl_s"]*1000,
        )

    async def _reconcile(self):
        for ip, (payload, expiry) in list(self.pending.items()):
            remaining = math.floor((expiry-time.monotonic())*1000)
            if remaining > 0:
                await self._write(ip, payload, remaining)
            self.pending.pop(ip, None)

    async def is_banned(self, ip):
        started = time.monotonic()
        if self.shadow:
            return self.cache.get(ip, ({}, 0))[1] > time.monotonic()
        try:
            await self._reconcile()
            pipe = self.state.r.pipeline()
            pipe.get(f"p20:ban:{ip}")
            pipe.pttl(f"p20:ban:{ip}")
            raw, ttl = await pipe.execute()
            if raw and ttl > 0:
                self.state.cache(self.cache, ip, ({}, started+ttl/1000))
                return True  # All contract reasons, including ebpf_conn_flood, behave alike.
            self.cache.pop(ip, None)
            return False
        except RedisError:
            return self.cache.get(ip, ({}, 0))[1] > time.monotonic()

    async def ban(self, ip, reason):
        if self.shadow:
            return True  # Shadow decisions never become real or local enforcement bans.
        if await self.state.allowlisted(ip):
            return False
        payload = {"ip": ip, "reason": reason, "source": "waf",
                   "ts_ms": int(time.time()*1000), "ttl_s": self.cfg.ban_ttl_s}
        expiry = time.monotonic()+self.cfg.ban_ttl_s
        try:
            written = await self._write(ip, payload, self.cfg.ban_ttl_s*1000)
            if not written:
                return False
        except RedisError:
            self.state.cache(self.pending, ip, (payload, expiry))
        self.state.cache(self.cache, ip, (payload, expiry))
        return True

    async def strike(self, ip, kind="budget"):
        async with self.strike_lock:
            return await self._strike(ip, kind)

    async def _strike(self, ip, kind):
        key = f"{self.prefix}strike:{kind}:{ip}"
        now = time.monotonic()
        count, expiry = self.strikes.get(key, (0, 0))
        if expiry <= now:
            count, expiry = 0, now+self.cfg.strike_window_s
        try:
            count, ttl = await self.state.r.eval(STRIKE_LUA, 1, key,
                                                self.cfg.strike_window_s*1000, count,
                                                max(1, math.floor((expiry-now)*1000)))
            expiry = now+ttl/1000
        except RedisError:
            count += 1
        self.state.cache(self.strikes, key, (count, expiry))
        return count

    async def has_budget_strike(self, ip, kind="budget"):
        key = f"{self.prefix}strike:{kind}:{ip}"
        try:
            return bool(await self.state.r.exists(key))
        except RedisError:
            count, expiry = self.strikes.get(key, (0, 0))
            return count > 0 and expiry > time.monotonic()
