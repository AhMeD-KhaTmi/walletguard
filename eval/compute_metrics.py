"""Aggregate client attempt records (and optional WAF decisions) into result rows.

Supersedes the earlier starter that guessed a false-positive rate from unlabeled
decisions. Every number here comes from either
(a) the workload's own attempt records - the denominator source in all configs, or
(b) the WAF decision stream captured during the run, for detection only.

A metric with no evidence is written as an empty cell and listed in
`unavailable_fields`; it is never rendered as zero.

    python3 eval/compute_metrics.py --runs eval/runs --out eval/results.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from eval import manifest as manifest_mod  # noqa: E402

DENIAL_DECISIONS = {"throttle", "block", "ban", "would_throttle", "would_block", "would_ban"}
ASR_WORKLOADS = {"credential_stuffing", "scraping", "dow"}

COLUMNS = [
    "run_id", "config", "workload", "attack", "repetition", "seed", "duration_s",
    "measured_attempts",
    "malicious_attempts", "attack_success", "unknown_outcomes", "asr",
    "unique_objectives", "tokens_in", "tokens_out", "simulated_cost_usd",
    "detected_malicious_requests", "detection_rate", "observation_coverage",
    "benign_attempts", "benign_policy_denials", "false_positive_rate",
    "benign_errors", "benign_timeouts",
    "latency_p50_ms", "latency_p95_ms", "latency_p99_ms",
    "time_to_ban_ms", "run_valid", "evidence_path", "unavailable_fields",
]


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * quantile
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def read_attempts(run_dir: pathlib.Path) -> list[dict]:
    rows: list[dict] = []
    for path in sorted(run_dir.glob("attempts-*.jsonl")):
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    return rows


def read_decisions(run_dir: pathlib.Path) -> list[dict] | None:
    path = run_dir / "decisions.jsonl"
    if not path.is_file():
        return None
    entries = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def _round(value: float | None, digits: int = 4) -> float | None:
    return None if value is None else round(value, digits)


def summarise(run_dir: pathlib.Path, labels: dict | None = None) -> dict:
    manifest = None
    if (run_dir / "manifest.json").is_file():
        manifest = manifest_mod.load(run_dir / "manifest.json")
    attempts = read_attempts(run_dir)
    decisions = read_decisions(run_dir)
    row: dict = {column: "" for column in COLUMNS}
    unavailable: list[str] = []
    row.update({
        "run_id": run_dir.name,
        "config": (manifest or {}).get("config", ""),
        "workload": (manifest or {}).get("workload", ""),
        "attack": (manifest or {}).get("attack", ""),
        "repetition": (manifest or {}).get("repetition", ""),
        "seed": (manifest or {}).get("seed", ""),
        "duration_s": (manifest or {}).get("duration_s", ""),
        "evidence_path": str(run_dir).replace("\\", "/"),
    })
    if manifest is None:
        unavailable.append("manifest")
    if not attempts:
        unavailable.append("attempts")
        row["measured_attempts"] = 0
        row["unavailable_fields"] = ",".join(unavailable)
        row["run_valid"] = "false"
        return row

    measured = [a for a in attempts if a.get("phase") == "measured"]
    row["measured_attempts"] = len(measured)
    workload = row["workload"]
    benign_pool = set()
    if labels:
        benign_pool = {ip for ip, label in labels.items() if label == "benign"}

    malicious = [a for a in measured if a.get("objective")]
    if workload in ASR_WORKLOADS:
        successes = [a for a in malicious if a.get("outcome") == "success"]
        unknown = [a for a in malicious if a.get("outcome") in {"timeout", "unknown"}]
        row["malicious_attempts"] = len(malicious)
        row["attack_success"] = len(successes)
        row["unknown_outcomes"] = len(unknown)
        row["asr"] = _round(len(successes) / len(malicious)) if malicious else None
        if not malicious:
            unavailable.append("malicious_attempts")
        if workload == "credential_stuffing":
            row["unique_objectives"] = len({a.get("client_id") for a in successes if a.get("client_id")})
        elif workload == "scraping":
            harvested = {pid for a in successes for pid in (a.get("product_ids") or [])}
            row["unique_objectives"] = len(harvested)
        else:
            row["unique_objectives"] = len({a.get("client_id") for a in successes if a.get("client_id")})
        row["tokens_in"] = sum(int(a.get("tokens_in") or 0) for a in malicious)
        row["tokens_out"] = sum(int(a.get("tokens_out") or 0) for a in malicious)
        row["simulated_cost_usd"] = _round(sum(float(a.get("cost_usd") or 0.0) for a in malicious), 6)
    elif workload == "honeypot":
        row["time_to_ban_ms"] = client_time_to_ban(measured)
        if row["time_to_ban_ms"] is None:
            unavailable.append("time_to_ban_ms")
    else:  # benign and churn probes: no ASR objective
        row["malicious_attempts"] = 0

    # --- detection correlation (WAF decision stream, captured during the run) ---
    if decisions is None:
        unavailable += ["detected_malicious_requests", "detection_rate", "observation_coverage"]
    elif workload in ASR_WORKLOADS:
        flagged = {
            d.get("request_id") for d in decisions
            if d.get("request_id") and d.get("decision") in DENIAL_DECISIONS
        }
        stream_ids = {d.get("request_id") for d in decisions if d.get("request_id")}
        covered = [a for a in malicious if a.get("request_id") in stream_ids]
        detected = [a for a in malicious if a.get("request_id") in flagged]
        row["detected_malicious_requests"] = len(detected)
        row["observation_coverage"] = _round(len(covered) / len(malicious)) if malicious else None
        row["detection_rate"] = _round(len(detected) / len(malicious)) if malicious else None

    # --- benign impact ---
    benign = benign_pool & {a.get("ip") for a in measured}
    if benign or workload == "benign":
        benign_attempts = [a for a in measured if a.get("objective") is False]
        denied = [a for a in benign_attempts if a.get("outcome") == "blocked"]
        row["benign_attempts"] = len(benign_attempts)
        row["benign_policy_denials"] = len(denied)
        row["false_positive_rate"] = _round(len(denied) / len(benign_attempts)) if benign_attempts else None
        row["benign_errors"] = sum(1 for a in benign_attempts if a.get("outcome") == "error")
        row["benign_timeouts"] = sum(1 for a in benign_attempts if a.get("outcome") == "timeout")

    # --- client-side latency: successful measured responses only ---
    latencies = [float(a["latency_ms"]) for a in measured
                 if a.get("outcome") == "success" and a.get("latency_ms") is not None]
    if latencies:
        row["latency_p50_ms"] = _round(percentile(latencies, 0.50), 3)
        row["latency_p95_ms"] = _round(percentile(latencies, 0.95), 3)
        row["latency_p99_ms"] = _round(percentile(latencies, 0.99), 3)
    else:
        unavailable += ["latency_p50_ms", "latency_p95_ms", "latency_p99_ms"]

    readiness = (manifest or {}).get("readiness", "unknown")
    row["run_valid"] = ("true" if readiness == "ok" and measured
                        and not (manifest or {}).get("invalid") else "false")
    row["unavailable_fields"] = ",".join(sorted(set(unavailable)))
    return row


def client_time_to_ban(attempts: list[dict]) -> int | None:
    """First decoy 404 -> first follow-up 403, client-observed."""
    decoys = [a for a in attempts if a.get("intent") == "decoy_hit"]
    followups = [a for a in attempts if a.get("intent") == "ban_check" and a.get("status") == 403]
    if not decoys or not followups:
        return None
    first_decoy = min(int(a["started_ms"]) for a in decoys)
    first_ban = min(int(a["started_ms"]) for a in followups)
    return max(0, first_ban - first_decoy)


def load_labels(path: str | pathlib.Path | None, run_id: str) -> dict | None:
    if not path:
        return None
    data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    return data.get(run_id)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", default="eval/runs", help="directory containing run subdirectories")
    parser.add_argument("--out", default="eval/results.csv")
    parser.add_argument("--labels", help="JSON: run_id -> source IP -> benign/attack")
    parser.add_argument("--json", help="also write the aggregated rows to this JSON file")
    args = parser.parse_args()

    runs_dir = pathlib.Path(args.runs)
    run_dirs = sorted(path for path in runs_dir.iterdir() if path.is_dir()) if runs_dir.is_dir() else []
    if not run_dirs:
        print(f"no run directories under {runs_dir}", file=sys.stderr)
        return 1

    rows = [summarise(path, load_labels(args.labels, path.name)) for path in run_dirs]
    rows.sort(key=lambda row: (str(row["config"]), str(row["workload"]), str(row["run_id"])))
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} with {len(rows)} row(s)")
    for row in rows:
        if row["workload"] in ASR_WORKLOADS:
            print(f"  {row['run_id']}: attempts={row['malicious_attempts']} "
                  f"success={row['attack_success']} asr={row['asr']} "
                  f"unknown={row['unknown_outcomes']} "
                  f"detected={row['detected_malicious_requests']} "
                  f"valid={row['run_valid']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
