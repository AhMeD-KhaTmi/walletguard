"""Build the label file B's ML tooling needs: ``run_id -> source IP -> benign/attack``.

Labels come from the workload each run actually executed and from the addresses
observed in that run's own attempt records - never from a detector. Connection-churn
probes are labelled ``probe``: they have no ASR objective and must not be trained as
attacks. The optional split file suggests disjoint fit/calibration/test run groups,
restricted to C1 runs because only observe mode writes ``p20:stream:waf_features``.

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
          "dow": "attack", "honeypot": "attack",
          # Connection churn is an integration probe for the kernel sensor
          # (MASTER_PLAN 3.4/IT-2), not an attack objective: it has no ASR and its
          # traffic must not enter an attack training class.
          "churn": "probe",
          # mixed/combined carry both roles inside one run: labelled per identity below.
          "mixed": None, "combined": "attack"}
PROBE_WORKLOADS = {"churn"}
# Only observe mode writes p20:stream:waf_features, so only these runs can carry
# training features. C0/C2 benign traffic is evidence of behaviour, not training data.
FEATURE_CONFIGS = {"C1"}


def label_for(workload: str, identity: dict) -> str:
    if LABELS[workload] is not None:
        return LABELS[workload]
    return "benign" if identity.get("role") == "benign" else "attack"


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
        ips = {identity["ip"]: label_for(workload, identity)
               for identity in manifest.get("identities", [])}
        observed = set()
        for path in run_dir.glob("attempts-*.jsonl"):
            with path.open(encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        observed.add(json.loads(line)["ip"])
        missing = observed - set(ips)
        if missing:
            raise ValueError(f"{run_dir.name}: traffic from undeclared addresses {sorted(missing)}")
        labels[run_dir.name] = dict(sorted(ips.items()))
        workloads[run_dir.name] = workload
    return labels, workloads


def suggest_splits(workloads: dict[str, str], configs: dict[str, str] | None = None,
                   features: set[str] | None = None) -> dict:
    """Disjoint fit/calibration/test groups for runs that actually carry features.

    A run only produces `p20:stream:waf_features` in C1 (observe). Benign traffic from
    C0 or C2 is useful as behaviour evidence but cannot train or calibrate a detector,
    so it is left out of the groups instead of silently inflating them. Probe runs
    (connection churn) are kept separate: they exist to exercise kernel signals.

    `features` is the set of run IDs whose manifest records a non-empty archived feature
    export. When it is supplied, a C1 run that predates the archive step is excluded too:
    without that check a featureless run could land in fit or calibration and B would
    train on nothing.
    """

    def config_of(run_id: str) -> str:
        if configs is None:  # older call sites predate per-run configs
            return "C1"
        return configs.get(run_id, "")

    def carries_features(run_id: str) -> bool:
        return features is None or run_id in features

    benign = sorted(run_id for run_id, workload in workloads.items()
                    if workload == "benign" and config_of(run_id) in FEATURE_CONFIGS
                    and carries_features(run_id))
    probes = sorted(run_id for run_id, workload in workloads.items()
                    if workload in PROBE_WORKLOADS)
    attack_runs = sorted(run_id for run_id, workload in workloads.items()
                         if workload != "benign" and workload not in PROBE_WORKLOADS)
    attacks = [run_id for run_id in attack_runs if carries_features(run_id)]
    if len(benign) < 3:
        return {"status": "insufficient_benign_runs",
                "detail": ("need at least 3 independent benign C1 runs with an archived "
                           "feature export for fit + calibration + held-out test"),
                "benign_runs": benign, "attack_runs": attack_runs, "probe_runs": probes}
    result = {
        "status": "ok",
        "benign_fit": benign[:-2],
        "benign_calibration": benign[-2:-1],
        "test": benign[-1:] + attacks,
        "attack_runs": attack_runs,
        "probe_runs": probes,
        "note": "fit/calibration/test run IDs are disjoint; attacks are test-only",
    }
    attack_features = [run_id for run_id in attacks if config_of(run_id) in FEATURE_CONFIGS]
    # Always state the result, not only the unavailable case: a consumer reading
    # splits.json must not have to tell "key absent" apart from "no C1 attack run".
    result["attack_features"] = attack_features or "unavailable"
    if not attack_features:
        result["attack_features_detail"] = (
            "no C1 observe-mode attack runs with an archived feature export: the listed "
            "attack runs were measured for enforcement ASR and write no waf_features, so "
            "detector precision/recall (MASTER_PLAN 6.4) cannot be computed from them")
    return result


def run_configs(runs_dir: pathlib.Path) -> dict[str, str]:
    """`run_id -> config` from the manifests, so splits can exclude feature-less runs."""
    configs: dict[str, str] = {}
    for run_dir in sorted(path for path in runs_dir.iterdir() if path.is_dir()):
        manifest_path = run_dir / "manifest.json"
        if manifest_path.is_file():
            configs[run_dir.name] = str(manifest_mod.load(manifest_path).get("config") or "")
    return configs


def feature_runs(runs_dir: pathlib.Path) -> set[str]:
    """Run IDs with an archived, non-empty feature export.

    `manifest.features` is written by the harness after traffic, before the reset that
    deletes `p20:stream:waf_features`. Checking the file as well as the recorded count
    keeps a hand-edited or partially copied run out of a training split.
    """
    found: set[str] = set()
    for run_dir in sorted(path for path in runs_dir.iterdir() if path.is_dir()):
        manifest_path = run_dir / "manifest.json"
        if not manifest_path.is_file():
            continue
        info = manifest_mod.load(manifest_path).get("features") or {}
        rows = info.get("rows")
        name = info.get("file")
        if isinstance(rows, int) and rows > 0 and name and (run_dir / name).is_file():
            found.add(run_dir.name)
    return found


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
        splits = suggest_splits(workloads, run_configs(pathlib.Path(args.runs)),
                                feature_runs(pathlib.Path(args.runs)))
        pathlib.Path(args.splits_out).write_text(json.dumps(splits, indent=2) + "\n",
                                                 encoding="utf-8")
        print(f"wrote {args.splits_out}: {splits['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
