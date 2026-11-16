"""Build the label file B's ML tooling needs: ``run_id -> source IP -> benign/attack``.

Labels come from the workload each run actually executed and from the addresses
observed in that run's own attempt records - never from a detector. The optional
split file suggests disjoint fit/calibration/test run groups so a test run is never
also a training run.

    python3 eval/labels.py --runs eval/runs --out eval/runs/labels.json \
        --splits-out eval/runs/splits.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from eval import manifest as manifest_mod  # noqa: E402

LABELS = {"benign": "benign", "credential_stuffing": "attack", "scraping": "attack",
          "dow": "attack", "honeypot": "attack", "churn": "attack"}


def collect(runs_dir: pathlib.Path) -> tuple[dict, dict]:
    labels: dict[str, dict[str, str]] = {}
    workloads: dict[str, str] = {}
    for run_dir in sorted(path for path in runs_dir.iterdir() if path.is_dir()):
        manifest_path = run_dir / "manifest.json"
        if not manifest_path.is_file():
            continue
        manifest = manifest_mod.load(manifest_path)
        workload = manifest.get("workload", "")
        if workload not in LABELS:
            raise ValueError(f"{run_dir.name}: unknown workload {workload!r}")
        ips = {identity["ip"] for identity in manifest.get("identities", [])}
        observed = set()
        for path in run_dir.glob("attempts-*.jsonl"):
            with path.open(encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        observed.add(json.loads(line)["ip"])
        missing = observed - ips
        if missing:
            raise ValueError(f"{run_dir.name}: traffic from undeclared addresses {sorted(missing)}")
        labels[run_dir.name] = {ip: LABELS[workload] for ip in sorted(ips)}
        workloads[run_dir.name] = workload
    return labels, workloads


def suggest_splits(workloads: dict[str, str]) -> dict:
    benign = sorted(run_id for run_id, workload in workloads.items() if workload == "benign")
    attacks = sorted(run_id for run_id, workload in workloads.items() if workload != "benign")
    if len(benign) < 3:
        return {"status": "insufficient_benign_runs",
                "detail": "need at least 3 independent benign runs for fit + calibration + held-out test",
                "benign_runs": benign, "attack_runs": attacks}
    return {
        "status": "ok",
        "benign_fit": benign[:-2],
        "benign_calibration": benign[-2:-1],
        "test": benign[-1:] + attacks,
        "note": "fit/calibration/test run IDs are disjoint; attacks are test-only",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", default="eval/runs")
    parser.add_argument("--out", default="eval/runs/labels.json")
    parser.add_argument("--splits-out", default=None)
    args = parser.parse_args()

    labels, workloads = collect(pathlib.Path(args.runs))
    if not labels:
        print(f"no manifests found under {args.runs}", file=sys.stderr)
        return 1
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(labels, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {out} for {len(labels)} run(s)")
    for run_id, mapping in labels.items():
        print(f"  {run_id} [{workloads[run_id]}] -> {len(mapping)} IP(s)")
    if args.splits_out:
        splits = suggest_splits(workloads)
        pathlib.Path(args.splits_out).write_text(json.dumps(splits, indent=2) + "\n",
                                                 encoding="utf-8")
        print(f"wrote {args.splits_out}: {splits['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
