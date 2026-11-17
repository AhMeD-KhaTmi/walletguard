"""Join a C2/C3 run's labeled client attempts to finalized application timings."""

import argparse
import json
import math
from pathlib import Path
from statistics import fmean
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eval.compute_metrics import percentile, read_attempts


def summarize(run_dir: Path, labels: dict, evidence: dict) -> dict:
    manifest = json.loads((run_dir / "manifest.json").read_text())
    run_id, config = manifest["run_id"], manifest["config"]
    if config not in {"C2", "C3"} or manifest.get("readiness") != "ok" or manifest.get("invalid") is not False:
        raise ValueError("expected a valid C2 or C3 run manifest")
    if evidence.get("run_id") != run_id or evidence.get("dropped_timings") != 0:
        raise ValueError("app snapshot has the wrong run ID or incomplete timings")

    measured = [row for row in read_attempts(run_dir) if row["phase"] == "measured"]
    run_labels = labels.get(run_id, {})
    if not measured or any(row["run_id"] != run_id or run_labels.get(row["ip"]) not in {"benign", "attack", "probe"}
                           for row in measured):
        raise ValueError("measured attempts require matching run IDs and source labels")

    timings = {}
    for row in evidence["timings"]:
        request_id = row["request_id"]
        if row["run_id"] != run_id or not request_id or request_id in timings:
            raise ValueError("app timing request IDs must be unique and belong to the run")
        timings[request_id] = row

    joined = []
    client_ids = set()
    http_attempts = [row for row in measured if row.get("route") != "tcp://"]
    for attempt in http_attempts:
        request_id = attempt.get("request_id")
        received_http = (attempt.get("status") or 0) >= 100
        if request_id in client_ids or (received_http and request_id not in timings):
            raise ValueError("client replies must join uniquely to finalized timings")
        if request_id:
            client_ids.add(request_id)
        if request_id in timings:
            joined.append(timings[request_id])
    if not joined:
        raise ValueError("no measured attempts joined to finalized timings")

    overhead = [float(row["waf_overhead_ms"]) for row in joined]
    scoring = [float(row["scoring_ms"]) for row in joined]
    if any(not math.isfinite(v) or v < 0 for v in overhead + scoring):
        raise ValueError("nonfinite or negative app timing")
    if any((v > 0) != (config == "C3") for v in scoring):
        raise ValueError("scoring timings do not match the configured mode")

    benign = [row for row in measured if run_labels[row["ip"]] == "benign"]
    outcome = [row["outcome"] for row in benign]
    denied = outcome.count("blocked")
    benign_latency = [float(row["latency_ms"]) for row in benign if row["outcome"] == "success"]
    if any(not math.isfinite(v) or v < 0 for v in benign_latency):
        raise ValueError("nonfinite or negative client latency")
    return {
        "run_id": run_id, "config": config, "workload": manifest["workload"],
        "repetition": manifest["repetition"],
        "measured_attempts": len(measured), "http_attempts": len(http_attempts),
        "timed_attempts": len(joined), "timing_coverage": len(joined) / len(http_attempts),
        "benign_attempts": len(benign), "benign_policy_denials": denied,
        "false_positive_rate": denied / len(benign) if benign else None,
        "benign_errors": outcome.count("error"), "benign_timeouts": outcome.count("timeout"),
        "benign_unknown": outcome.count("unknown"),
        "benign_unsuccessful_rate": (len(benign) - outcome.count("success")) / len(benign) if benign else None,
        "latency_p50_ms": percentile(benign_latency, .50),
        "latency_p95_ms": percentile(benign_latency, .95),
        "latency_p99_ms": percentile(benign_latency, .99),
        "waf_overhead_ms_mean": fmean(overhead),
        "waf_overhead_p50_ms": percentile(overhead, .50),
        "waf_overhead_p95_ms": percentile(overhead, .95),
        "scoring_p50_ms": percentile(scoring, .50) if config == "C3" else None,
        "scoring_p95_ms": percentile(scoring, .95) if config == "C3" else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--app-evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        summary = summarize(args.run_dir, json.loads(args.labels.read_text()),
                            json.loads(args.app_evidence.read_text()))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"App benchmark validation failed: {exc}\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
