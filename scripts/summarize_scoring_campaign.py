"""Validate matched original-model scoring runs and retain every outcome."""

import argparse
from collections import defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
from statistics import median
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eval.compute_metrics import read_attempts
from scripts.run_c23_benchmark import run_summary

MODEL_HASH = "bb0116a167318df1749a0edf5cf5b95362ccde59f6b8580d732ed82d05722ca1"


def summarize(root, output):
    index = json.loads((root / "index.json").read_text())
    expected = {(w, r, v) for w in ["benign", "mixed"] for r in [1, 2, 3]
                for v in ["direct", "batch"]}
    if (len(index) != 12 or len({e["run_id"] for e in index}) != 12 or
            {(e["workload"], e["repetition"], e["variant"]) for e in index} != expected):
        raise ValueError("all twelve distinct protocol runs are required")
    rows, pairs, groups = [], defaultdict(dict), defaultdict(list)
    for entry in index:
        run = root / "runs" / entry["run_id"]
        m = json.loads((run / "manifest.json").read_text())
        size = 1 if entry["variant"] == "direct" else 32
        if (m.get("invalid") is not False or m["code_revision"].get("dirty") is not False
                or m["config"] != "C3" or m["seed"] != 600+entry["repetition"]
                or m["model_hash"] != MODEL_HASH or m["worker_stop_timeout_s"] != 5
                or m["scoring_policy"]["batch_size"] != size
                or m["scoring_policy"]["collection_wait_ms"] != 2
                or m["scoring_policy"]["queue_capacity"] != 256):
            raise ValueError(f"protocol mismatch: {run.name}")
        row = run_summary(run, MODEL_HASH)
        labels = json.loads((run / "labels.json").read_text())[run.name]
        attempts = [a for a in read_attempts(run) if a["phase"] == "measured"]
        benign = [a for a in attempts if labels[a["ip"]] == "benign"]
        row.update(variant=entry["variant"], benign_attempts=len(benign),
                   benign_policy_denials=sum(a["outcome"] == "blocked" for a in benign),
                   benign_unknown=sum(a["outcome"] in {"error", "timeout", "unknown"} for a in benign))
        row["benign_auto_bans"] = sum(labels.get(b["ip"]) == "benign"
            for b in json.loads((run / "bans.json").read_text()))
        usage = json.loads((run / "usage.json").read_text())
        api, mock = usage["after"], usage["mock_after"]
        if (any(int(api.get(a, 0)) != int(mock[b]) for a, b in
                [("tokens_in", "tokens_in"), ("tokens_out", "tokens_out"), ("agent_steps", "calls")])
                or not math.isclose(float(api.get("cost_usd", 0)), float(mock["cost_usd"]), abs_tol=1e-7)):
            raise ValueError(f"API/mock usage mismatch: {run.name}")
        row["server_tokens_out_total"] = int(mock["tokens_out"])
        pairs[(entry["workload"], entry["repetition"])][entry["variant"]] = m
        groups[(entry["workload"], entry["variant"])].append(row)
        rows.append(row)
    for pair in pairs.values():
        for field in ["identities", "seed", "policy_hash", "effective_policy_hash", "client_timeout_s",
                      "duration_requested", "users", "spawn_rate", "mock", "tokenizer", "agent_version",
                      "workload_sha256", "code_revision", "model_hash", "worker_stop_timeout_s"]:
            if pair["direct"][field] != pair["batch"][field]:
                raise ValueError(f"unmatched {field}")
    summary = {}
    for (workload, variant), items in sorted(groups.items()):
        result = {k: sum(int(r[k]) for r in items) for k in
                  ["benign_attempts", "benign_policy_denials", "benign_unknown", "benign_auto_bans"]}
        result["metrics"] = {}
        for metric in ["latency_p50_ms", "latency_p95_ms", "waf_overhead_p95_ms", "scoring_p95_ms",
                       "app_cpu_pct", "app_rss_mb", "asr", "unknown_outcomes", "server_tokens_out_total"]:
            values = [float(r[metric]) for r in items if r.get(metric) not in (None, "")]
            if workload == "benign" and metric in {"asr", "unknown_outcomes"}:
                if values:
                    raise ValueError("benign-only runs cannot report malicious ASR")
                continue
            if len(values) != 3:
                raise ValueError(f"incomplete {metric}")
            result["metrics"][metric] = dict(median=median(values), min=min(values), max=max(values))
        result["benign_safety_passed"] = all(
            (r["benign_policy_denials"]+r["benign_unknown"])/r["benign_attempts"] <= .01
            and r["benign_auto_bans"] == 0 for r in items)
        summary.setdefault(workload, {})[variant] = result
    output.mkdir(parents=True, exist_ok=True)
    with (output / "performance.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(dict.fromkeys(k for r in rows for k in r)))
        writer.writeheader()
        writer.writerows(rows)
    result = dict(kind="matched_original_model_scoring_performance", runs=12, pairs=6,
                  model_sha256=MODEL_HASH, summary=summary, kernel_integrated=False,
                  validator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    (output / "performance.json").write_text(json.dumps(result, indent=2)+"\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(summarize(args.runs, args.output), indent=2))
