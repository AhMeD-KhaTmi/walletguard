"""Time-window request features with bounded history and explicit saturation."""

import json
import math
import statistics
import time
import uuid
from collections import Counter, OrderedDict, deque

from redis.exceptions import RedisError

from common.tokens import estimate_tokens
from common.agent import DEFAULT_AGENT_STEPS, MAX_AGENT_STEPS, reserve_tokens

FEATURE_VERSION = 3
FEATURES_BASE = [
    "is_chat", "is_login", "is_products", "is_other", "body_size",
    "prompt_tokens", "max_out_tokens", "prompt_entropy", "has_ua",
    "has_accept_lang", "req_10s", "req_60s", "distinct_paths_60s",
    "fail_ratio_60s", "mean_gap_s", "std_gap_s", "window_saturated",
    "agent_steps", "task_token_budget",
]
FEATURES_EBPF = FEATURES_BASE + ["ebpf_conn_rate_10s", "ebpf_egress_bytes_60s", "ebpf_ip_available", "ebpf_host_available"]
RECORD_LUA = """
redis.call('ZADD',KEYS[1],ARGV[1],ARGV[2])
redis.call('ZREMRANGEBYSCORE',KEYS[1],'-inf',tonumber(ARGV[1])-60000)
local n = redis.call('ZCARD',KEYS[1])
if n > tonumber(ARGV[3]) then
  redis.call('ZREMRANGEBYRANK',KEYS[1],0,n-tonumber(ARGV[3])-1)
end
redis.call('EXPIRE',KEYS[1],120)
return n
"""


def entropy(s):
    n = len(s)
    return -sum(c/n*math.log2(c/n) for c in Counter(s).values()) if n else 0.0


class FeatureStore:
    def __init__(self, state):
        self.state = state
        self.cfg = state.config
        self.history = OrderedDict()

    async def record(self, ip, path, status):
        now = int(time.time()*1000)
        events = self.history.get(ip, deque(maxlen=self.cfg.max_events))
        events.append((now, path, status))
        self.state.cache(self.history, ip, events)
        try:
            await self.state.r.eval(RECORD_LUA, 1, f"p20:win:{ip}", now,
                                    json.dumps([now, path, status, uuid.uuid4().hex]), self.cfg.max_events)
        except RedisError:
            pass

    async def extract(self, ip, path, headers, body, body_len):
        now = int(time.time()*1000)
        source = "redis"
        try:
            raw = await self.state.r.zrangebyscore(f"p20:win:{ip}", now-60000, now,
                                                 start=0, num=self.cfg.max_events)
            events = [tuple(json.loads(row)[:3]) for row in raw]
        except (RedisError, ValueError, TypeError):
            events = list(self.history.get(ip, ()))
            source = "local"
        events = [e for e in events if 0 <= now-e[0] <= 60000]
        logins = [e for e in events if e[1] == "/login"]
        stamps = sorted(e[0] for e in events)[-10:]
        gaps = [(b-a)/1000 for a, b in zip(stamps, stamps[1:])]
        prompt = body.get("prompt", "")
        prompt = prompt if isinstance(prompt, str) else ""
        output = body.get("max_output_tokens", 256 if path == "/chat" else 0)
        output = output if type(output) is int and output >= 0 else 0
        steps = body.get("agent_steps", DEFAULT_AGENT_STEPS) if path == "/chat" else 0
        steps = min(steps, MAX_AGENT_STEPS + 1) if type(steps) is int and steps > 0 else 0
        return {
            "is_chat": int(path == "/chat"), "is_login": int(path == "/login"),
            "is_products": int(path == "/products"),
            "is_other": int(path not in {"/chat", "/login", "/products"}),
            "body_size": body_len, "prompt_tokens": estimate_tokens(prompt) if path == "/chat" else 0,
            "max_out_tokens": min(output, self.cfg.max_output_cap+1), "prompt_entropy": entropy(prompt),
            "has_ua": int(bool(headers.get("user-agent"))),
            "has_accept_lang": int(bool(headers.get("accept-language"))),
            "req_10s": sum(now-e[0] <= 10000 for e in events), "req_60s": len(events),
            "distinct_paths_60s": len({e[1] for e in events}),
            "fail_ratio_60s": sum(e[2] in (401, 403, 429) for e in logins)/len(logins) if logins else 0,
            "mean_gap_s": statistics.mean(gaps) if gaps else 60.0,
            "std_gap_s": statistics.pstdev(gaps) if len(gaps) > 1 else 0.0,
            "window_saturated": int(len(events) >= self.cfg.max_events),
            "agent_steps": steps,
            "task_token_budget": reserve_tokens(prompt, output, steps) if steps else 0,
            "history_source": source,
        }
