"""B's adapter around A's unchanged harness, with explicit workload provenance.

--agent-scenario varied selects B's benign-only multi-step script. Other scenarios
and all attack scripts remain A's originals. The adapter adds effective policy
metadata and campaign partition tags to every manifest, including failed runs.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from eval import harness
from waf.config import Config


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--agent-scenario", choices=["normal", "varied"], default="normal")
    parser.add_argument("--campaign-stage", choices=["calibration", "validation", "smoke"], required=True)
    opts, remainder = parser.parse_known_args()
    if opts.agent_scenario == "varied":
        if "--workload" not in remainder or remainder[remainder.index("--workload")+1] != "benign":
            raise ValueError("varied agent scenario is benign-only")
        harness.WORKLOADS = {**harness.WORKLOADS,
                            "benign": ("scripts/agent_benign_workload.py", 10, "benign")}
    original_metadata = harness.workload_metadata
    original_command = harness.workload_command

    def command(args, entry, run_dir):
        argv, env, log = original_command(args, entry, run_dir)
        argv += ["--stop-timeout", "5"]
        if os.environ.get("P20_SAFE_DRIVER") == "1":
            executable = argv.index("-f")-1
            argv[executable:executable+1] = [sys.executable, str(ROOT / "scripts/locust_deadline_driver.py")]
            if env["P20_SETUP_GATE"] == "0":
                argv[argv.index("-t")+1] = f"{harness._seconds(args.duration)+10:g}s"
        return argv, env, log

    harness.workload_command = command

    def metadata(args):
        cfg = Config.from_env(mode=harness.CONFIGS[args.config]["WAF_MODE"], redis_url=args.redis_url)
        policy = {"budgets": cfg.budgets, "strike_limit": cfg.strike_limit,
                  "strike_window_s": cfg.strike_window_s, "ban_ttl_s": cfg.ban_ttl_s,
                  "max_output_cap": cfg.max_output_cap}
        policy.update(account_pressure_bans=cfg.account_pressure_bans,
                      wallet_capacity=cfg.wallet_capacity, wallet_refill_per_s=cfg.wallet_refill_per_s)
        script = harness.WORKLOADS[args.workload][0]
        return {**original_metadata(args), "campaign_stage": opts.campaign_stage,
                "worker_stop_timeout_s": 5,
                "worker_lifecycle": "supervised_deadline_v1" if os.environ.get("P20_SAFE_DRIVER") == "1" else "original",
                "worker_driver_sha256": (hashlib.sha256((ROOT / "scripts/locust_deadline_driver.py").read_bytes()).hexdigest()
                                         if os.environ.get("P20_SAFE_DRIVER") == "1" else None),
                "benign_scenario": opts.agent_scenario if args.workload == "benign" else None,
                "workload_script": script,
                "workload_sha256": hashlib.sha256((ROOT / script).read_bytes()).hexdigest(),
                "effective_policy": policy,
                "scoring_policy": {"batch_size": cfg.scoring_batch_size,
                                   "collection_wait_ms": cfg.scoring_batch_wait_ms,
                                   "queue_capacity": cfg.scoring_queue_capacity,
                                   "execution": "direct" if cfg.scoring_batch_size == 1 else "microbatch"},
                "effective_policy_hash": hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()}

    harness.workload_metadata = metadata
    sys.argv = [sys.argv[0], *remainder]
    return harness.main()


if __name__ == "__main__":
    raise SystemExit(main())
