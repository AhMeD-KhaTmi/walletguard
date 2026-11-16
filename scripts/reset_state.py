"""Clear only documented P20 runtime keys; leave unrelated data untouched."""

import argparse
import os
import sys

import redis

PREFIXES = (
    "p20:ban:", "p20:bkt:", "p20:shadow:", "p20:strike:",
    "p20:win:", "p20:sig:", "p20:app:", "p20:eval:",
)
EXACT = {
    "p20:stream:waf_decisions", "p20:stream:waf_features",
    "p20:stream:ebpf_events", "p20:xdp:drops",
}


def reset(client: redis.Redis) -> int:
    client.ping()
    keys = [
        key for key in client.scan_iter(match="p20:*", count=500)
        if key in EXACT or key.startswith(PREFIXES)
    ]
    for start in range(0, len(keys), 500):
        client.delete(*keys[start:start + 500])
    return len(keys)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--redis-url", default=os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0"))
    args = parser.parse_args()
    try:
        with redis.Redis.from_url(
            args.redis_url, decode_responses=True,
            socket_connect_timeout=2, socket_timeout=2,
        ) as client:
            count = reset(client)
    except (redis.RedisError, ValueError):
        print("Reset failed: check Redis connectivity and REDIS_URL; no success claimed.", file=sys.stderr)
        return 1
    print(f"Reset Redis runtime state: {count} keys removed; allowlist and schema preserved.")
    print("Local process history and kernel maps/counters must be reset separately.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
