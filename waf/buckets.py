"""Atomic Redis budgets with one-worker, conservative outage protection."""

import asyncio
import math
import time
from collections import OrderedDict

from redis.exceptions import RedisError

TAKE_LUA = """
local cap, rate, cost = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
local t = redis.call('TIME')
local now = tonumber(t[1])*1000 + math.floor(tonumber(t[2])/1000)
local d = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens, ts = tonumber(d[1]) or cap, tonumber(d[2]) or now
tokens = math.min(cap, tokens + math.max(0,now-ts)/1000*rate)
local limit = tonumber(ARGV[4])
if limit >= 0 then tokens = math.min(tokens, limit) end
local ok, retry = 0, 0
if tokens >= cost then tokens=tokens-cost; ok=1
else retry=math.ceil((cost-tokens)/rate*1000) end
redis.call('HSET',KEYS[1],'tokens',tokens,'ts',now)
redis.call('PEXPIRE',KEYS[1],math.ceil(cap/rate*2000)+1000)
return {ok,tostring(tokens),retry}
"""

REFUND_LUA = """
local cap, amount, limit = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
local cur = tonumber(redis.call('HGET',KEYS[1],'tokens'))
if cur == nil then return false end
local t=redis.call('TIME')
local now=tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000)
local ts=tonumber(redis.call('HGET',KEYS[1],'ts')) or now
cur=math.min(cap,cur+math.max(0,now-ts)/1000*tonumber(ARGV[4]))
if limit >= 0 then cur = math.min(cur,limit) end
cur=math.min(cap,cur+amount)
redis.call('HSET',KEYS[1],'tokens',cur,'ts',now)
return tostring(cur)
"""


class TokenBucket:
    def __init__(self, r, max_keys=20_000):
        self.r = r
        self.lock = asyncio.Lock()
        self.mirrors = OrderedDict()
        self.dirty = set()
        self.degraded = False
        self.max_keys = max_keys
        self.lost_history = False

    @staticmethod
    def validate(*values):
        if any(isinstance(v, bool) or not math.isfinite(float(v)) or v <= 0 for v in values):
            raise ValueError("bucket parameters must be positive finite numbers")

    def _balance(self, key, capacity, rate):
        row = self.mirrors.get(key)
        if row is None:
            return 0.0  # Unknown outage/recovery state never grants a fresh burst.
        tokens, stamp, _, _ = row
        return min(capacity, tokens + max(0, time.monotonic()-stamp)*rate)

    def _remember(self, key, tokens, capacity, rate):
        self.mirrors[key] = (tokens, time.monotonic(), capacity, rate)
        self.mirrors.move_to_end(key)
        while len(self.mirrors) > self.max_keys:
            old, _ = self.mirrors.popitem(last=False)
            if old in self.dirty:
                self.lost_history = True
            self.dirty.discard(old)

    async def take(self, key: str, capacity: float, refill_per_s: float, cost: float = 1):
        self.validate(capacity, refill_per_s, cost)
        if cost > capacity:
            raise ValueError("cost exceeds capacity and can never be retried successfully")
        async with self.lock:
            local = self._balance(key, capacity, refill_per_s)
            limit = local if self.degraded or key in self.dirty or (self.lost_history and key not in self.mirrors) else -1
            try:
                allowed, tokens, retry_ms = await self.r.eval(
                    TAKE_LUA, 1, key, capacity, refill_per_s, cost, limit,
                )
                tokens = float(tokens)
                self.degraded = False
                self.dirty.discard(key)
                result = bool(allowed), tokens, retry_ms/1000
            except RedisError:
                self.degraded = True
                self.dirty.add(key)
                allowed = local >= cost
                tokens = local-cost if allowed else local
                result = allowed, tokens, 0.0 if allowed else (cost-local)/refill_per_s
            self._remember(key, tokens, capacity, refill_per_s)
            return result

    async def refund(self, key: str, capacity: float, amount: float):
        self.validate(capacity)
        if not math.isfinite(float(amount)) or amount < 0:
            raise ValueError("refund must be finite and nonnegative")
        if not amount:
            return
        async with self.lock:
            row = self.mirrors.get(key)
            rate = row[3] if row else 0
            local = self._balance(key, capacity, rate)
            try:
                tokens = await self.r.eval(
                    REFUND_LUA, 1, key, capacity, amount,
                    local if self.degraded or key in self.dirty else -1, rate,
                )
                self.degraded = False
                self.dirty.discard(key)
                tokens = float(tokens) if tokens is not None else 0
            except RedisError:
                self.degraded = True
                self.dirty.add(key)
                tokens = min(capacity, local+amount)
            self._remember(key, tokens, capacity, rate)


# Non-refilling monetary reservations. Missing/changed authority never initializes
# silently, and finalized request IDs cannot refund twice. No TTL resets spend.
SPEND_TAKE_LUA = """
local cap,cost=tonumber(ARGV[1]),tonumber(ARGV[2])
local configured=tonumber(redis.call('HGET',KEYS[1],'cap'))
if configured==nil then return {-1,0} end
if configured~=cap then return {-2,0} end
local field='r:'..ARGV[3]
local old=redis.call('HGET',KEYS[1],field)
if old then return {1,tonumber(redis.call('HGET',KEYS[1],'used'))} end
local used=tonumber(redis.call('HGET',KEYS[1],'used')) or 0
if used+cost>cap then return {0,used} end
used=used+cost
redis.call('HSET',KEYS[1],'used',used,field,cost)
return {1,used}
"""
SPEND_FINISH_LUA = """
local field='r:'..ARGV[1]
local reserve=tonumber(redis.call('HGET',KEYS[1],field))
if reserve==nil then return 0 end
local charged=tonumber(ARGV[2])
if charged<0 or charged>reserve then return -1 end
redis.call('HINCRBY',KEYS[1],'used',charged-reserve)
redis.call('HDEL',KEYS[1],field)
return reserve-charged
"""
SPEND_INIT_LUA = """
if redis.call('EXISTS',KEYS[1])==1 then
 if tonumber(redis.call('HGET',KEYS[1],'cap'))~=tonumber(ARGV[1]) then return -1 end
 return 0
end
redis.call('HSET',KEYS[1],'cap',ARGV[1],'used',0)
return 1
"""


class SpendLedger:
    """Optional strict period authority; normal token-bucket fallback is separate."""
    def __init__(self,state):self.state=state

    async def reserve(self,key,cap,amount,request_id):
        if any(type(v)is not int or v<=0 or v>2**53-1 for v in (cap,amount)) or not request_id:raise ValueError('invalid integer spend reservation')
        try:
            status,used=await self.state.eval(SPEND_TAKE_LUA,1,key,cap,amount,request_id)
            return int(status),int(used)
        except RedisError:return -1,None

    async def finish(self,key,request_id,charged):
        if type(charged)is not int or charged<0:raise ValueError('invalid integer spend charge')
        try:return int(await self.state.eval(SPEND_FINISH_LUA,1,key,request_id,charged))
        except RedisError:return None  # Retain full reservation when reconciliation is unavailable.
