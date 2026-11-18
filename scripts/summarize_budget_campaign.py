"""Validate the independent budget campaign and export per-run safety evidence."""

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

from eval.compute_metrics import COLUMNS, percentile, read_attempts
from scripts.run_c23_benchmark import APP_FIELDS, BASELINE_FIELDS, run_summary


MODEL_HASH = "bb0116a167318df1749a0edf5cf5b95362ccde59f6b8580d732ed82d05722ca1"
MODEL_THRESHOLD = json.loads((Path(__file__).resolve().parents[1] /
                            "ml/artifacts/model_base_agent_v3.json").read_text())["threshold"]


def add_scenario_baseline_deltas(rows):
    key = lambda row: (row["scenario"], row["workload"], row["repetition"])
    baselines = {key(row): row for row in rows if row["config"] == "C0"}
    for row in rows:
        base = baselines[key(row)]
        for p in [50, 95]:
            field = f"latency_p{p}_ms"
            row[f"latency_delta_p{p}_ms"] = (float(row[field])-float(base[field])
                if row.get(field) not in (None, "") and base.get(field) not in (None, "") else None)


def summarize_campaign(root, output):
    root, output = Path(root), Path(output)
    index = json.loads((root / "index.json").read_text())
    if len(index) != 36 or len({r["run_id"] for r in index}) != 36:
        raise ValueError("independent protocol requires all 36 distinct validation runs")
    rows, triplets, groups, usage_records = [], defaultdict(dict), defaultdict(list), {}
    for entry in index:
        run = root / "runs" / entry["run_id"]
        m = json.loads((run / "manifest.json").read_text())
        if (m.get("campaign_stage") != "validation" or m.get("invalid") is not False
                or m["code_revision"].get("dirty") is not False
                or m["seed"] not in {201, 202, 203}):
            raise ValueError("only valid clean-source independent validation runs are accepted")
        config, workload, scenario = m["config"], m["workload"], entry["scenario"]
        row = run_summary(run, MODEL_HASH)
        row.update(scenario=scenario, effective_policy_hash=m["effective_policy_hash"])
        labels = json.loads((run / "labels.json").read_text())[m["run_id"]]
        attempts = [r for r in read_attempts(run) if r["phase"] == "measured"]
        benign = [r for r in attempts if labels[r["ip"]] == "benign"]
        successful_latency = [r["latency_ms"] for r in benign if r["outcome"] == "success"]
        row["benign_attempts"] = len(benign)
        row["benign_policy_denials"] = sum(r["outcome"] == "blocked" for r in benign)
        row["false_positive_rate"] = row["benign_policy_denials"]/len(benign) if benign else None
        for name, outcome in [("benign_errors", "error"), ("benign_timeouts", "timeout"),
                              ("benign_unknown", "unknown")]:
            row[name] = sum(r["outcome"] == outcome for r in benign)
        row["benign_unsuccessful_rate"] = sum(r["outcome"] != "success" for r in benign)/len(benign) if benign else None
        for p in [50, 95, 99]:
            row[f"latency_p{p}_ms"] = percentile(successful_latency, p/100)
        bans = json.loads((run / "bans.json").read_text())
        row["benign_auto_bans"] = sum(labels.get(b["ip"]) == "benign" for b in bans)
        decisions = ([] if config == "C0" else [json.loads(line)
                     for line in (run / "decisions.jsonl").read_text().splitlines() if line.strip()])
        row["token_budget_throttles"] = sum(d.get("decision") == "throttle" and d.get("reason") == "llm_tok"
                                              for d in decisions)
        benign_ids = {r["request_id"] for r in benign if r.get("request_id")}
        scored = [d for d in decisions if d.get("request_id") in benign_ids
                  and d.get("anomaly_score") not in (None, "")]
        row["benign_anomaly_scored"] = len(scored)
        row["benign_anomaly_flags"] = sum(float(d["anomaly_score"]) < MODEL_THRESHOLD for d in scored)
        usage = json.loads((run / "usage.json").read_text())
        api, mock = usage["after"], usage["mock_after"]
        for a, b in [("tokens_in", "tokens_in"), ("tokens_out", "tokens_out"), ("agent_steps", "calls")]:
            if int(api.get(a, 0)) != int(mock[b]):
                raise ValueError(f"independent API/mock usage mismatch: {run.name}")
        if not math.isclose(float(api.get("cost_usd", 0)), float(mock["cost_usd"]), abs_tol=1e-7):
            raise ValueError("API/mock cost mismatch")
        usage_records[run.name] = usage
        row["server_tokens_in_total"] = int(mock["tokens_in"])
        row["server_tokens_out_total"] = int(mock["tokens_out"])
        row["server_cost_usd_total"] = float(mock["cost_usd"])
        key = (scenario, workload, m["repetition"])
        if config in triplets[key]:
            raise ValueError("duplicate configuration in matched triplet")
        triplets[key][config] = m
        groups[(scenario, workload, config)].append(row)
        rows.append(row)
    if len(triplets) != 12 or any(set(t) != {"C0", "C2", "C3"} for t in triplets.values()):
        raise ValueError("incomplete C0/C2/C3 triplets")
    for triplet in triplets.values():
        base = triplet["C0"]
        for m in triplet.values():
            for key in ["identities", "seed", "policy_hash", "effective_policy_hash", "client_timeout_s",
                        "duration_requested", "users", "spawn_rate", "mock", "tokenizer",
                        "agent_version", "workload_sha256", "code_revision"]:
                if m[key] != base[key]:
                    raise ValueError(f"unmatched {key}")
    add_scenario_baseline_deltas(rows)
    summary = {}
    mixed_by_attack = defaultdict(lambda: {"attempts": 0, "success": 0, "unknown": 0})
    for entry in index:
        if entry["workload"] != "mixed":
            continue
        for attempt in read_attempts(root / "runs" / entry["run_id"]):
            if attempt.get("phase") != "measured" or not attempt.get("objective") or not attempt.get("attack"):
                continue
            aggregate = mixed_by_attack[(entry["config"], attempt["attack"])]
            aggregate["attempts"] += 1
            aggregate["success"] += attempt["outcome"] == "success"
            aggregate["unknown"] += attempt["outcome"] in {"timeout", "unknown"}
    metrics = ["asr", "false_positive_rate", "latency_p50_ms", "latency_p95_ms",
               *BASELINE_FIELDS, "waf_overhead_p50_ms", "waf_overhead_p95_ms", "scoring_p95_ms",
               "server_tokens_out_total", "server_cost_usd_total", "unknown_outcomes"]
    for (scenario, workload, config), items in sorted(groups.items()):
        if len(items) != 3:
            raise ValueError("expected three repetitions per group")
        group = {key: sum(int(r.get(key) or 0) for r in items)
                 for key in ["benign_attempts", "benign_policy_denials", "benign_auto_bans",
                             "benign_errors", "benign_timeouts", "benign_unknown", "token_budget_throttles",
                             "benign_anomaly_scored", "benign_anomaly_flags"]}
        group["benign_model_flag_rate"] = (group["benign_anomaly_flags"]/group["benign_anomaly_scored"]
                                           if group["benign_anomaly_scored"] else None)
        group["pooled_false_positive_rate"] = (group["benign_policy_denials"] / group["benign_attempts"]
                                                if group["benign_attempts"] else None)
        group["worst_case_policy_denial_rate"] = (
            (group["benign_policy_denials"]+group["benign_errors"]+group["benign_timeouts"]+group["benign_unknown"])
            / group["benign_attempts"] if group["benign_attempts"] else None)
        group["run_metrics"] = {}
        for key in metrics:
            values = [float(r[key]) for r in items if r.get(key) not in (None, "")]
            if values:
                group["run_metrics"][key] = {"median": median(values), "min": min(values), "max": max(values)}
        if group["benign_attempts"]:
            group["policy_safety_target_passed"] = (
                group["worst_case_policy_denial_rate"] <= .01 and group["benign_auto_bans"] == 0
                and all((r["benign_unsuccessful_rate"] or 0) <= .01 for r in items))
            group["client_outcomes_complete"] = all(group[key] == 0 for key in
                ["benign_errors", "benign_timeouts", "benign_unknown"])
            group["application_safety_target_passed"] = (
                group["pooled_false_positive_rate"] <= .01 and group["benign_auto_bans"] == 0
                and all(group[key] == 0 for key in ["benign_errors", "benign_timeouts", "benign_unknown"])
                and all((r["benign_unsuccessful_rate"] or 0) <= .01 for r in items)
                and all((r["false_positive_rate"] or 0) <= .01 for r in items))
        summary.setdefault(f"{scenario}-{workload}", {})[config] = group
    output.mkdir(parents=True, exist_ok=True)
    fields = list(dict.fromkeys([*COLUMNS, *APP_FIELDS, *BASELINE_FIELDS, "scenario", "effective_policy_hash",
                                 "benign_auto_bans", "token_budget_throttles", "benign_anomaly_scored", "benign_anomaly_flags",
                                 "server_tokens_in_total", "server_tokens_out_total", "server_cost_usd_total"]))
    with (output / "results.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    result = {"kind": "independent_application_budget_validation", "runs": len(rows),
              "triplets": len(triplets), "model_sha256": MODEL_HASH,
              "summary": summary, "server_usage": usage_records,
              "mixed_per_attack": {f"{config}-{attack}": {**value, "asr": value["success"]/value["attempts"]}
                                   for (config, attack), value in sorted(mixed_by_attack.items())},
              "validator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "joint_IT6_complete": False, "kernel_integrated": False}
    (output / "validation.json").write_text(json.dumps(result, indent=2)+"\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = summarize_campaign(args.runs, args.output)
    print(json.dumps({"runs": result["runs"], "summary": result["summary"]}, indent=2))
