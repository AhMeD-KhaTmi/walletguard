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
SESSION_PREFIX = "p20:app:session:"


def reset(client: redis.Redis, keep_sessions: bool = False) -> int:
    client.ping()
    keys = [
        key for key in client.scan_iter(match="p20:*", count=500)
        if key in EXACT or key.startswith(PREFIXES)
    ]
    if keep_sessions:
        # MASTER_PLAN 7.1: start the measured DoW phase with fresh policy state while
        # keeping the authenticated sessions established in the setup phase.
        keys = [key for key in keys if not key.startswith(SESSION_PREFIX)]
    for start in range(0, len(keys), 500):
        client.delete(*keys[start:start + 500])
    return len(keys)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--redis-url", default=os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0"))
    parser.add_argument("--keep-sessions", action="store_true",
                        help="keep p20:app:session:* (DoW setup -> measured phase split)")
    args = parser.parse_args()
    try:
        with redis.Redis.from_url(
            args.redis_url, decode_responses=True,
            socket_connect_timeout=2, socket_timeout=2,
        ) as client:
            count = reset(client, keep_sessions=args.keep_sessions)
    except (redis.RedisError, ValueError):
        print("Reset failed: check Redis connectivity and REDIS_URL; no success claimed.", file=sys.stderr)
        return 1
    kept = "sessions preserved" if args.keep_sessions else "allowlist and schema preserved"
    print(f"Reset Redis runtime state: {count} keys removed; {kept}.")
    print("Local process history and kernel maps/counters must be reset separately.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
