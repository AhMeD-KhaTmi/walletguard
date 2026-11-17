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
import statistics
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from eval import manifest as manifest_mod  # noqa: E402

DENIAL_DECISIONS = {"throttle", "block", "ban", "would_throttle", "would_block", "would_ban"}
ASR_WORKLOADS = {"credential_stuffing", "scraping", "dow"}
# `mixed` and `combined` run several attack objectives in one row: ASR is an aggregate
# and per-attack ASR must come from the separated workloads (documented in schema.md).
AGGREGATE_WORKLOADS = {"mixed", "combined"}

COLUMNS = [
    "run_id", "config", "workload", "attack", "repetition", "seed", "duration_s",
    "measured_attempts",
    "malicious_attempts", "attack_success", "unknown_outcomes", "asr",
    "unique_objectives",
    "detected_malicious_requests", "detection_rate", "observation_coverage",
    "benign_attempts", "benign_policy_denials", "false_positive_rate",
    "benign_errors", "benign_timeouts",
    "latency_p50_ms", "latency_p95_ms", "latency_p99_ms",
    "waf_overhead_ms_mean", "scoring_p50_ms", "scoring_p95_ms",
    "time_to_ban_ms", "time_to_redis_ban_ms", "time_to_map_insert_ms",
    "time_to_first_xdp_drop_ms",
    "tokens_in", "tokens_out", "simulated_cost_usd",
    "app_cpu_pct", "app_rss_mb", "agent_cpu_pct", "agent_rss_mb", "xdp_dropped_packets",
    "code_revision", "policy_hash", "model_hash", "manifest_path",
    "evidence_path", "run_valid", "unavailable_fields",
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


def read_bans(run_dir: pathlib.Path) -> list[dict] | None:
    path = run_dir / "bans.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _round(value: float | None, digits: int = 4) -> float | None:
    return None if value is None else round(value, digits)


def summarise(run_dir: pathlib.Path, labels: dict | None = None) -> dict:
    manifest = None
    if (run_dir / "manifest.json").is_file():
        manifest = manifest_mod.load(run_dir / "manifest.json")
    attempts = read_attempts(run_dir)
    decisions = read_decisions(run_dir)
    bans = read_bans(run_dir)
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
    # --- provenance (MASTER_PLAN 7.3): every row must be traceable to a revision ---
    revision = (manifest or {}).get("code_revision") or {}
    # Keep the dirty flag visible: a run from an uncommitted tree must not look like a
    # run of the commit in HEAD.
    commit = revision.get("commit") or ""
    row["code_revision"] = f"{commit}-dirty" if commit and revision.get("dirty") else commit
    row["policy_hash"] = (manifest or {}).get("policy_hash") or ""
    row["model_hash"] = (manifest or {}).get("model_hash") or ""
    row["manifest_path"] = str(run_dir / "manifest.json").replace("\\", "/")
    for field in ("code_revision", "policy_hash", "model_hash"):
        if not row[field]:
            unavailable.append(field)

    # --- cost/resources (MASTER_PLAN 7.3): sampled or explicitly unavailable ---
    resource_block = (manifest or {}).get("resources") or {}
    app = resource_block.get("app") or {}
    agent = resource_block.get("agent") or {}
    sampled_fields = (
        ("app_cpu_pct", app.get("cpu_pct")),
        ("app_rss_mb", app.get("rss_mb_peak")),
        ("agent_cpu_pct", agent.get("cpu_pct")),
        ("agent_rss_mb", agent.get("rss_mb_peak")),
        ("xdp_dropped_packets", resource_block.get("xdp_dropped_packets")),
    )
    for field, value in sampled_fields:
        if value is None:
            unavailable.append(field)
        else:
            row[field] = (int(value) if field == "xdp_dropped_packets"
                          else _round(float(value), 3))
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
    if workload in ASR_WORKLOADS or workload in AGGREGATE_WORKLOADS:
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
        elif workload == "dow":
            row["unique_objectives"] = len({a.get("client_id") for a in successes if a.get("client_id")})
        else:
            # Several objectives share this row; a single "unique" count would be
            # meaningless, so it is reported as unavailable rather than invented.
            unavailable.append("unique_objectives")
        row["tokens_in"] = sum(int(a.get("tokens_in") or 0) for a in malicious)
        row["tokens_out"] = sum(int(a.get("tokens_out") or 0) for a in malicious)
        row["simulated_cost_usd"] = _round(sum(float(a.get("cost_usd") or 0.0) for a in malicious), 6)
    elif workload == "honeypot":
        # Follow-ups are phase="followup", so the client-observed latency must be
        # computed over every attempt in the run, not only phase="measured".
        row["time_to_ban_ms"] = client_time_to_ban(attempts)
        if row["time_to_ban_ms"] is None:
            unavailable.append("time_to_ban_ms")
    else:  # benign and churn probes: no ASR objective
        row["malicious_attempts"] = 0

    # --- detection correlation (WAF decision stream, captured during the run) ---
    if decisions is None:
        unavailable += ["detected_malicious_requests", "detection_rate", "observation_coverage"]
    elif workload in ASR_WORKLOADS or workload in AGGREGATE_WORKLOADS:
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
    if benign or workload in {"benign", "mixed"}:
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

    # --- WAF overhead: decision-stream latency_ms excludes downstream app/mock time ---
    if decisions:
        overheads = [float(d["latency_ms"]) for d in decisions
                     if d.get("latency_ms") not in (None, "")]
        if overheads:
            row["waf_overhead_ms_mean"] = _round(sum(overheads) / len(overheads), 3)
        else:
            unavailable.append("waf_overhead_ms_mean")
    else:
        unavailable.append("waf_overhead_ms_mean")
    # The decision record carries `anomaly_score` but no per-request scoring duration,
    # so scoring percentiles cannot be produced from it (and no model runs in C0-C2).
    unavailable += ["scoring_p50_ms", "scoring_p95_ms"]

    # --- server-side ban timing: Redis held the ban at this timestamp ---
    if bans is None:
        unavailable.append("time_to_redis_ban_ms")
    else:
        row["time_to_redis_ban_ms"] = redis_time_to_ban(bans, measured)
        if row["time_to_redis_ban_ms"] is None:
            unavailable.append("time_to_redis_ban_ms")
    # Kernel-layer response fields need the sensor/agent, which does not run in C0-C2.
    unavailable += ["time_to_map_insert_ms", "time_to_first_xdp_drop_ms"]

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


def redis_time_to_ban(bans: list[dict], attempts: list[dict]) -> int | None:
    """First measured malicious request from the banned IP -> Redis ban ``ts_ms``.

    MASTER_PLAN 7.3: ban timing starts at the first measured malicious request from the
    relevant IP, not at the first WAF decision and not at the client's follow-up probe.
    """
    first_attempt: dict[str, int] = {}
    for attempt in attempts:
        if not attempt.get("objective") or attempt.get("started_ms") is None:
            continue
        ip = attempt.get("ip")
        started = int(attempt["started_ms"])
        if ip not in first_attempt or started < first_attempt[ip]:
            first_attempt[ip] = started
    latencies = []
    for ban in bans:
        ip, ts_ms = ban.get("ip"), ban.get("ts_ms")
        if ip in first_attempt and isinstance(ts_ms, (int, float)):
            latencies.append(max(0, int(ts_ms) - first_attempt[ip]))
    return min(latencies) if latencies else None


SUMMARY_METRICS = [
    "malicious_attempts", "attack_success", "asr", "detection_rate",
    "observation_coverage", "benign_policy_denials", "false_positive_rate",
    "latency_p50_ms", "latency_p95_ms", "latency_p99_ms", "waf_overhead_ms_mean",
    "time_to_ban_ms", "time_to_redis_ban_ms", "tokens_out", "simulated_cost_usd",
    "app_cpu_pct", "app_rss_mb",
]


def summarise_repetitions(rows: list[dict], metrics: list[str] | None = None) -> list[dict]:
    """Median and range per (config, workload) across valid repetitions (7.2.6).

    Invalid runs are excluded rather than averaged in, and `repetitions` states how many
    rows actually contributed, so a single-run group cannot masquerade as a median.
    """
    groups: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        if row.get("run_valid") != "true":
            continue
        groups.setdefault((str(row["config"]), str(row["workload"])), []).append(row)
    summary = []
    for (config, workload), group in sorted(groups.items()):
        for metric in metrics or SUMMARY_METRICS:
            values = [float(row[metric]) for row in group if row.get(metric) not in ("", None)]
            if not values:
                continue
            summary.append({
                "config": config, "workload": workload, "metric": metric,
                "repetitions": len(values),
                "median": round(statistics.median(values), 4),
                "min": round(min(values), 4), "max": round(max(values), 4),
            })
    return summary


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
    parser.add_argument("--summary-out", default=None,
                        help="also write per-(config, workload) median/range across repetitions")
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
    if args.summary_out:
        summary = summarise_repetitions(rows)
        summary_path = pathlib.Path(args.summary_out)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with summary_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=[
                "config", "workload", "metric", "repetitions", "median", "min", "max"])
            writer.writeheader()
            writer.writerows(summary)
        print(f"wrote {summary_path} with {len(summary)} row(s)")
    print(f"wrote {out} with {len(rows)} row(s)")
    for row in rows:
        if row["workload"] in ASR_WORKLOADS or row["workload"] in AGGREGATE_WORKLOADS:
            print(f"  {row['run_id']}: attempts={row['malicious_attempts']} "
                  f"success={row['attack_success']} asr={row['asr']} "
                  f"unknown={row['unknown_outcomes']} "
                  f"detected={row['detected_malicious_requests']} "
                  f"valid={row['run_valid']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
