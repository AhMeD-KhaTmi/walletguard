"""Fit the predeclared token allowance using only fresh tagged C1 calibration runs.

This computes calibration statistics, not the runtime token-bucket backend.
"""

import argparse
from collections import defaultdict, deque
import hashlib
import json
import math
from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eval.compute_metrics import read_attempts


def read_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def select_policy(ledgers):
    """Fixed 60s peak rule and two-task burst; no held-out outcomes enter it."""
    max_task, max_window = 0, 0
    tasks = 0
    for ledger in ledgers:
        window = deque()
        total = 0
        for stamp, cost in sorted(ledger):
            if not math.isfinite(stamp) or type(cost) is not int or cost <= 0:
                raise ValueError("calibration needs finite timestamps and positive integer costs")
            while window and stamp-window[0][0] > 60_000:
                total -= window.popleft()[1]
            window.append((stamp, cost))
            total += cost
            max_task, max_window = max(max_task, cost), max(max_window, total)
            tasks += 1
    if not tasks:
        raise ValueError("no successful measured calibration chats")
    return {"capacity": max(20_000, math.ceil(2*max_task/5000)*5000),
            "refill_per_s": max(100, math.ceil(1.25*max_window/60/50)*50),
            "largest_task_tokens": max_task, "largest_account_60s_tokens": max_window,
            "measured_chat_tasks": tasks}


def fit(runs):
    ledgers = defaultdict(list)
    provenance = []
    for path in sorted(Path(runs).iterdir()):
        if not path.is_dir():
            continue
        m = json.loads((path / "manifest.json").read_text())
        if (m.get("campaign_stage") != "calibration" or m.get("config") != "C1"
                or m.get("workload") != "benign" or m.get("invalid") is not False
                or m.get("feature_version") != 3):
            raise ValueError("only valid fresh tagged benign C1 calibration runs may fit policy")
        features = {r["request_id"]: r for r in read_jsonl(path / "features.jsonl")}
        decisions = {r["request_id"]: r for r in read_jsonl(path / "decisions.jsonl")}
        seen = set()
        for row in read_attempts(path):
            if row.get("phase") != "measured" or row.get("route") != "/chat":
                continue
            if row.get("outcome") != "success":
                raise ValueError("calibration chat errors/unknowns cannot silently disappear")
            rid = row.get("request_id")
            if not rid or rid in seen or rid not in features or rid not in decisions:
                raise ValueError("calibration requires unique client/feature/decision joins")
            seen.add(rid)
            feature, decision = features[rid], decisions[rid]
            account = decision["client_id"]
            raw_cost = float(feature["task_token_budget"])
            if not math.isfinite(raw_cost) or not raw_cost.is_integer() or raw_cost <= 0:
                raise ValueError("whole-task calibration costs must be positive integers")
            cost = int(raw_cost)
            if not account or int(decision["llm_tokens_charged"]) != cost:
                raise ValueError("synthetic task bounds and independently accounted usage must agree")
            ledgers[(m["run_id"], account)].append((int(decision["ts_ms"]), cost))
        provenance.append({"run_id": m["run_id"], "seed": m["seed"],
                           "scenario": m["benign_scenario"],
                           "files": {name: hashlib.sha256((path/name).read_bytes()).hexdigest()
                                     for name in ["manifest.json", "features.jsonl", "decisions.jsonl"]}})
    scenarios = {p["scenario"] for p in provenance}
    seeds = {p["seed"] for p in provenance}
    if scenarios != {"normal", "varied"} or seeds != {101, 102, 103} or len(provenance) != 6:
        raise ValueError("expected the six predeclared calibration runs, seeds 101/102/103")
    return {"kind": "token_budget_calibration", "rule": "60s peak x1.25; two-task burst; round 50/s and 5000",
            "legacy": {"capacity": 20_000, "refill_per_s": 100},
            "candidate": select_policy(ledgers.values()), "calibration_runs": provenance,
            "validation_seeds": [201, 202, 203], "frozen_before_validation": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = fit(args.runs)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x") as stream:
        stream.write(json.dumps(result, indent=2)+"\n")
    print(json.dumps(result["candidate"], indent=2))


if __name__ == "__main__":
    main()
