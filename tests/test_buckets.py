import asyncio
import pytest
import redis.asyncio as aioredis
from waf.buckets import TokenBucket


async def test_burst_reject_refill():
    r = aioredis.from_url("redis://localhost:6379/15", decode_responses=True)
    await r.flushdb()
    tb = TokenBucket(r)
    res = [(await tb.take("t", 5, 1, 1))[0] for _ in range(7)]
    assert res == [True] * 5 + [False] * 2          # burst of 5, then rejected
    await asyncio.sleep(2.1)
    assert (await tb.take("t", 5, 1, 1))[0] is True  # refilled about 2 tokens
    # weighted cost (the LLM token case)
    with pytest.raises(ValueError, match="exceeds capacity"):
        await tb.take("big", 100, 10, 150)
    await r.aclose()
