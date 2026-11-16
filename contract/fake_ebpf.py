# Usage: python contract/fake_ebpf.py 10.0.0.5     (pretend this IP is flooding connections)
import sys
import time
import redis

r = redis.Redis(decode_responses=True)
ip, now = sys.argv[1], int(time.time() * 1000)
r.hset(f"p20:sig:ip:{ip}", mapping={"conn_rate_1s": 50, "conn_rate_10s": 400, "syn_rate_10s": 400,
                                    "failed_conn_10s": 0, "bytes_in_10s": 100000, "updated_ms": now})
r.expire(f"p20:sig:ip:{ip}", 60)
r.hset("p20:sig:host", mapping={"egress_bytes_llm_60s": 5_000_000, "egress_conns_llm_60s": 30,
                                "unexpected_exec_count": 0, "updated_ms": now})
r.expire("p20:sig:host", 120)
print("fake signals written for", ip)
print("Check bans arrive on the channel: docker exec -it p20-redis redis-cli SUBSCRIBE p20:ch:ban")