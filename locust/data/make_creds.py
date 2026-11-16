"""Generate a seeded synthetic credential list for the stuffing workload.

No real leaked credentials are used or downloaded. Entries are built from the
documented synthetic demo accounts (`user1..user50` / `Passw0rd!N`) plus random
non-existent usernames, so the "valid" fraction of the list is known by construction
and the resulting ASR is explainable.

    python3 locust/data/make_creds.py                       # default seed 42
    python3 locust/data/make_creds.py --seed 7 --count 500
    python3 locust/data/make_creds.py --verify locust/data/creds_seed42.json

The output file contains demo passwords: keep it out of Git and out of shared logs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import string
from pathlib import Path

SCHEMA_VERSION = 1
DEFAULT_SEED = 42
DEFAULT_COUNT = 2000
DEFAULT_VALID_FRACTION = 0.10
DEMO_USERS = 50
SYNTHETIC_PASSWORDS = ("Summer2024!", "qwerty123", "letmein", "P@ssw0rd", "changeme",
                       "hunter2", "admin123", "welcome1", "azerty", "Password1")


def demo_accounts() -> list[tuple[str, str]]:
    """The accounts the target application actually has (see app/main.py)."""
    return [(f"user{i}", f"Passw0rd!{i}") for i in range(1, DEMO_USERS + 1)]


def generate(seed: int = DEFAULT_SEED, count: int = DEFAULT_COUNT,
             valid_fraction: float = DEFAULT_VALID_FRACTION) -> dict:
    if count < 1:
        raise ValueError("count must be >= 1")
    if not 0.0 <= valid_fraction <= 1.0:
        raise ValueError("valid_fraction must be within [0, 1]")
    rng = random.Random(seed)
    accounts = demo_accounts()
    valid_count = round(count * valid_fraction)
    entries: list[dict] = []
    for _ in range(valid_count):
        username, password = rng.choice(accounts)
        entries.append({"username": username, "password": password, "kind": "valid"})
    alphabet = string.ascii_lowercase + string.digits
    for _ in range(count - valid_count):
        username = "u_" + "".join(rng.choice(alphabet) for _ in range(8))
        password = rng.choice(SYNTHETIC_PASSWORDS) + "".join(rng.choice(alphabet) for _ in range(3))
        entries.append({"username": username, "password": password, "kind": "invalid"})
    rng.shuffle(entries)
    for index, entry in enumerate(entries, start=1):
        entry["id"] = f"c{index:05d}"
    entries = [{key: entry[key] for key in ("id", "username", "password", "kind")}
               for entry in entries]
    return {
        "schema_version": SCHEMA_VERSION,
        "source": "synthetic-demo-accounts",
        "seed": seed,
        "count": len(entries),
        "valid_fraction": valid_fraction,
        "valid_count": valid_count,
        "demo_users": DEMO_USERS,
        "entries": entries,
    }


def file_hash(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(dataset: dict, path: str | Path) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(dataset, indent=1) + "\n", encoding="utf-8")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--valid-fraction", type=float, default=DEFAULT_VALID_FRACTION)
    parser.add_argument("--out", default=None)
    parser.add_argument("--verify", metavar="FILE",
                        help="check that FILE matches a regeneration from its own seed")
    args = parser.parse_args()

    if args.verify:
        existing = json.loads(Path(args.verify).read_text(encoding="utf-8"))
        regenerated = generate(existing["seed"], existing["count"], existing["valid_fraction"])
        if regenerated != existing:
            print(f"MISMATCH: {args.verify} does not reproduce from its recorded seed")
            return 1
        print(f"ok: {args.verify} reproduces; sha256={file_hash(args.verify)}")
        return 0

    dataset = generate(args.seed, args.count, args.valid_fraction)
    out = Path(args.out or f"locust/data/creds_seed{args.seed}.json")
    write(dataset, out)
    print(f"wrote {out}: {dataset['count']} entries, {dataset['valid_count']} valid "
          f"({dataset['valid_fraction']:.0%}), seed={dataset['seed']}")
    print(f"sha256={file_hash(out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
