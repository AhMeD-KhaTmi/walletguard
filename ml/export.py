"""Export observe samples with stream IDs, run identity and explicit IP labels."""

import argparse
import json
import os
from pathlib import Path

import pandas as pd
import redis


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--redis-url", default=os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0"))
    parser.add_argument("--output", default="ml/data/all.csv")
    parser.add_argument("--labels", help="JSON mapping run_id -> source IP -> benign/attack")
    args = parser.parse_args()
    labels = json.loads(Path(args.labels).read_text()) if args.labels else {}
    with redis.Redis.from_url(args.redis_url, decode_responses=True, socket_timeout=2, socket_connect_timeout=2) as client:
        rows = []
        for stream_id, fields in client.xrange("p20:stream:waf_features", count=500_000):
            label = labels.get(fields.get("run_id"), {}).get(fields.get("ip"), "unknown")
            if label not in {"benign", "attack", "unknown"}:
                raise ValueError("labels must be benign, attack or unknown")
            rows.append({"stream_id": stream_id, **fields, "label": label})
    if not rows:
        raise ValueError("no observe samples available; no empty training file written")
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(output, index=False)
    print(f"Exported {len(rows)} samples; unknown labels must be resolved before training")


if __name__ == "__main__":
    main()
