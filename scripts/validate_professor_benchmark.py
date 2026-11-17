"""Validate the frozen professor-update campaign and export auditable summaries."""

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--runs", type=Path, default=root / "eval/runs/professor-aa51185")
parser.add_argument("--output", type=Path, default=root / "docs/evidence/professor_benchmark")
args = parser.parse_args()
run_root = args.runs
revision = "aa51185caa87307672e4042683a9e6ccfbbfe59d"
model_hash = "bb0116a167318df1749a0edf5cf5b95362ccde59f6b8580d732ed82d05722ca1"
with (run_root / "results.csv").open() as f:
    rows = list(csv.DictReader(f))
assert len(rows) == len({r["run_id"] for r in rows}) == 81
assert Counter(r["config"] for r in rows) == {"C0": 27, "C2": 27, "C3": 27}
assert hashlib.sha256((root / "ml/model_base.joblib").read_bytes()).hexdigest() == model_hash
groups = defaultdict(list)
pairs = defaultdict(dict)
usage_status = {}
benign_bans = []
for row in rows:
    name = row["run_id"]
    path = run_root / "runs" / name
    m = json.loads((path / "manifest.json").read_text())
    assert row["run_valid"] == "true" and row["code_revision"] == revision
    assert m["feature_version"] == 3 and m["tokenizer"] == "synthetic-whitespace-v1"
    assert m["agent_version"] == "context-loop-v1" and m["default_agent_steps"] == 3
    assert m["environment"]["btf_available"]
    assert m["mock"]["tokenizer"] == m["tokenizer"]
    assert m["model_hash"] == (model_hash if row["config"] == "C3" else None)
    assert not m["invalid"] and not m["invalid_reasons"] and m["readiness"] == "ok"
    assert m["workers"] and all(p["returncode"] == 0 and not p["overran"] for p in m["per_identity"])
    assert len(set(w["ip"] for w in m["workers"])) == len(m["identities"])
    triplet = (row["workload"], row["profile"], row["repetition"])
    assert row["config"] not in pairs[triplet]
    pairs[triplet][row["config"]] = m
    usage = json.loads((path / "usage.json").read_text())
    api, mock = usage["after"], usage["mock_after"]
    exact = (int(api.get("agent_steps", 0)) == int(mock["calls"])
             and int(api.get("tokens_in", 0)) == int(mock["tokens_in"])
             and int(api.get("tokens_out", 0)) == int(mock["tokens_out"])
             and math.isclose(float(api.get("cost_usd", 0)), float(mock["cost_usd"]), abs_tol=1e-8))
    assert exact, (name, api, mock)
    usage_status[name] = {"api": api, "mock": mock, "exact_token_agreement": exact}
    labels = json.loads((path / "labels.json").read_text())[name]
    for ban in json.loads((path / "bans.json").read_text()):
        if labels.get(ban["ip"]) == "benign":
            benign_bans.append({"run_id": name, "config": row["config"], **ban})
    row["server_tokens_out_total"] = int(api.get("tokens_out", 0))
    row["server_cost_usd_total"] = float(api.get("cost_usd", 0))
    if row["config"] != "C0":
        assert (path / "app-evidence.json").is_file()
        assert float(row["timing_coverage"]) > .98
        assert row["waf_overhead_p50_ms"] and row["waf_overhead_p95_ms"]
    groups[(row["workload"], row["profile"], row["config"])].append(row)
assert len(pairs) == 27 and all(set(v) == {"C0","C2","C3"} for v in pairs.values())
for key, triplet in pairs.items():
    reference = triplet["C0"]
    for m in triplet.values():
        for field in ("identities", "seed", "policy_hash", "client_timeout_s", "duration_requested",
                      "users", "spawn_rate", "mock", "tokenizer", "agent_version"):
            assert m[field] == reference[field], (key, field)
        seedmap = lambda data: {w["ip"]: (w["configured_seed"], w["derived_seed"]) for w in data["workers"]}
        assert seedmap(m) == seedmap(reference), key

out = {"runtime": "context-loop-v1", "feature_version": 3, "revision": revision,
       "model_sha256": model_hash, "accepted_runs": 81,
       "invalid_attempts": json.loads((run_root/"failures.json").read_text()) if (run_root/"failures.json").exists() else [],
       "runs_by_config": {"C0":27,"C2":27,"C3":27},
       "server_usage": usage_status, "benign_bans": benign_bans, "groups": {}}
metrics = ("measured_attempts","malicious_attempts","attack_success","unknown_outcomes","asr",
           "benign_attempts","benign_policy_denials","false_positive_rate",
           "benign_errors","benign_timeouts","benign_unknown",
           "latency_p50_ms","latency_p95_ms","latency_delta_p50_ms","latency_delta_p95_ms",
           "waf_overhead_p50_ms","waf_overhead_p95_ms","scoring_p95_ms","app_cpu_pct",
           "server_tokens_out_total","server_cost_usd_total")
for (workload, profile, config), items in sorted(groups.items()):
    assert len(items) == 3
    label = workload + ("-" + profile if profile else "")
    fields = {}
    for metric in metrics:
        values = [float(r[metric]) for r in items if r.get(metric) not in (None, "")]
        if values:
            fields[metric] = {"median":statistics.median(values),"min":min(values),"max":max(values)}
    fields["benign_attempts_total"] = sum(int(r.get("benign_attempts") or 0) for r in items)
    fields["benign_denials_total"] = sum(int(r.get("benign_policy_denials") or 0) for r in items)
    out["groups"].setdefault(label,{})[config] = fields
target = args.output
target.mkdir(parents=True, exist_ok=True)
(target / "validated.json").write_text(json.dumps(out,indent=2)+"\n")
for name in ("results.csv", "summary.csv"):
    (target / name).write_bytes((run_root/name).read_bytes())
print("Verified all 81 runs, 27 matched triplets, and exact API/mock token agreement")
print(f"Recorded {len(benign_bans)} benign bans; see validated.json for acceptance limitations")
