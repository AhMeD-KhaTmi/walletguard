"""One measured run: reset state, start C0/C1/C2, drive real multi-IP traffic, archive evidence.

This is Member A's config orchestration. It refuses to pretend:

* C4 is rejected until the kernel layer exists, and C3 is rejected without a compatible
  model file - the same readiness rules the application enforces;
* services are started with explicit flags for the requested config, then `/health`
  is used to confirm the *effective* mode rather than trusting the environment;
* the allowlist is checked before traffic, because an exempted measured address
  silently invalidates every defense result;
* a run whose readiness fails is written with ``run_valid=false`` instead of a row
  of zeroes.

    sudo .venv/bin/python eval/harness.py run --config C2 --workload credential_stuffing
    .venv/bin/python eval/harness.py run --config C0 --workload dow --profile overcap --dry-run

Traffic runs inside the namespaces from `eval/identities.json`; the harness itself must
run as root to enter them (``sudo``).  Use ``--no-netns`` only for a local smoke test
from the host address.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from eval import identities, manifest as manifest_mod  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[1]
OVERRUN_GRACE_S = 20.0

CONFIGS = {
    "C0": {"WAF_MODE": "off", "WAF_BUCKETS": "0", "WAF_HONEYPOT": "0",
           "WAF_ML": "0", "WAF_EBPF_SIGNALS": "0"},
    "C1": {"WAF_MODE": "observe", "WAF_BUCKETS": "1", "WAF_HONEYPOT": "1",
           "WAF_ML": "0", "WAF_EBPF_SIGNALS": "0"},
    "C2": {"WAF_MODE": "enforce", "WAF_BUCKETS": "1", "WAF_HONEYPOT": "1",
           "WAF_ML": "0", "WAF_EBPF_SIGNALS": "0"},
    "C3": {"WAF_MODE": "enforce", "WAF_BUCKETS": "1", "WAF_HONEYPOT": "1",
           "WAF_ML": "1", "WAF_EBPF_SIGNALS": "0"},
    "C4": {"WAF_MODE": "enforce", "WAF_BUCKETS": "1", "WAF_HONEYPOT": "1",
           "WAF_ML": "1", "WAF_EBPF_SIGNALS": "1"},
}
BLOCKED_CONFIGS = {"C3": "C3 is blocked until Member B trains and freezes a compatible base model; "
                         "no model file exists in this checkout, and the application refuses "
                         "WAF_ML=1 without one",
                   "C4": "C4 is blocked: the eBPF sensor/XDP integration does not exist yet, "
                         "so WAF_EBPF_SIGNALS=1 is refused by the application"}
WORKLOADS = {
    "benign": ("locust/benign.py", 5, "benign"),
    "credential_stuffing": ("locust/attack_credential_stuffing.py", 3, "credential_stuffing"),
    "scraping": ("locust/attack_scraping.py", 3, "scraping"),
    "dow": ("locust/attack_dow.py", 2, "dow"),
    "honeypot": ("locust/attack_honeypot.py", 1, "honeypot"),
    "churn": ("locust/attack_churn.py", 1, "churn"),
}


def log(message: str) -> None:
    print(f"[harness] {message}", flush=True)


def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        return probe.connect_ex(("127.0.0.1", port)) != 0


def http_json(url: str, timeout: float = 3.0) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):
        return None


def wait_for_health(url: str, seconds: float = 20.0) -> dict | None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        payload = http_json(url + "/health")
        if payload is not None:
            return payload
        time.sleep(0.2)
    return None


def start_service(name: str, args: list[str], env: dict, log_path: pathlib.Path) -> subprocess.Popen:
    handle = log_path.open("w", encoding="utf-8")
    log(f"starting {name}: {' '.join(args)}")
    return subprocess.Popen(args, cwd=REPO, env=env, stdout=handle, stderr=subprocess.STDOUT,
                            start_new_session=True)


def stop_service(process: subprocess.Popen, name: str) -> None:
    if process.poll() is not None:
        return
    log(f"stopping {name}")
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        process.wait(timeout=10)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass


def redis_client(redis_url: str):
    import redis

    return redis.Redis.from_url(redis_url, decode_responses=True,
                                socket_connect_timeout=2, socket_timeout=3)


def preflight(args, data: dict) -> list[str]:
    problems: list[str] = []
    if not port_free(args.api_port):
        problems.append(f"port {args.api_port} is already in use; stop the previous API first")
    if not port_free(args.mock_port):
        problems.append(f"port {args.mock_port} is already in use; stop the previous mock first")
    try:
        client = redis_client(args.redis_url)
        client.ping()
        allowlist = set(client.smembers("p20:allowlist"))
        identities.assert_allowlist_safe(data, allowlist)
        client.close()
    except identities.IdentityError as exc:
        problems.append(str(exc))
    except Exception as exc:  # noqa: BLE001 - any Redis failure is a readiness failure
        problems.append(f"Redis not reachable at {args.redis_url}: {exc}")
    if not args.no_netns:
        if os.geteuid() != 0:
            problems.append("namespaces need root: run with sudo, or pass --no-netns for a host smoke test")
        existing = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout
        for entry in identities.identities_for(data, args.workload):
            if entry["ns"] not in existing.split():
                problems.append(f"namespace {entry['ns']} is missing; run scripts/make_netns.sh")
    script = REPO / WORKLOADS[args.workload][0]
    if not script.is_file():
        problems.append(f"workload script missing: {script}")
    if args.workload == "credential_stuffing":
        creds = pathlib.Path(os.environ.get("P20_CREDS", REPO / "locust/data/creds_seed42.json"))
        if not creds.is_file():
            problems.append(f"credential dataset missing: {creds}; run locust/data/make_creds.py")
    if not shutil.which("locust") and not (REPO / ".venv/bin/locust").exists():
        problems.append("locust is not installed (pip install -r locust/requirements.txt)")
    return problems


def reset_state(args) -> None:
    result = subprocess.run([args.python, str(REPO / "scripts/reset_state.py"),
                             "--redis-url", args.redis_url],
                            cwd=REPO, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"reset failed: {result.stderr.strip() or result.stdout.strip()}")
    log(result.stdout.strip().splitlines()[0] if result.stdout.strip() else "reset ok")


def snapshot_decisions(redis_url: str, path: pathlib.Path) -> int:
    client = redis_client(redis_url)
    try:
        entries = client.xrange("p20:stream:waf_decisions", min="-", max="+", count=200_000)
    finally:
        client.close()
    with path.open("w", encoding="utf-8") as handle:
        for entry_id, fields in entries:
            handle.write(json.dumps({"stream_id": entry_id, **fields}) + "\n")
    return len(entries)


def workload_command(args, entry: dict, run_dir: pathlib.Path) -> tuple[list[str], dict, pathlib.Path]:
    script, users, _ = WORKLOADS[args.workload]
    per_identity = max(1, args.users // max(1, len(identities.identities_for(args.data, args.workload))))
    target = args.target
    python = args.python
    locust_bin = str(REPO / ".venv/bin/locust") if (REPO / ".venv/bin/locust").exists() else "locust"
    command = [locust_bin, "-f", str(REPO / script), "--headless",
               "-u", str(per_identity), "-r", str(args.spawn_rate),
               "-t", args.duration, "--host", target, "--only-summary",
               "--exit-code-on-error", "0"]
    env = {
        **os.environ,
        "P20_RUN_ID": args.run_id,
        "P20_TARGET": target,
        "P20_RUNS_DIR": str(REPO / args.runs),
        "P20_TIMEOUT": str(args.timeout),
        "P20_SEED": str(args.seed),
        "P20_EXPECT_IP": entry["ip"],
        "P20_ATTACKER_ACCOUNT": args.data["attacker_account"],
        "P20_DOW_PROFILE": args.profile,
        "P20_PER_PAGE": str(args.per_page),
        "P20_DEADLINE_S": str(_seconds(args.duration) + 3),
    }
    if args.max_output:
        env["P20_MAX_OUTPUT"] = str(args.max_output)
    if args.workload == "benign":
        env["P20_BENIGN_ACCOUNTS"] = ",".join(identities.accounts_for(args.data, entry["ns"]))
    if args.no_netns:
        env.pop("P20_EXPECT_IP")
    else:
        command = ["ip", "netns", "exec", entry["ns"], *command]
    return command, env, run_dir / f"locust-{entry['ns']}-{entry['ip']}.log"


def run_workload(args, run_dir: pathlib.Path) -> list[dict]:
    processes = []
    handles = []
    entries = identities.identities_for(args.data, args.workload)
    for entry in entries:
        command, env, log_path = workload_command(args, entry, run_dir)
        if args.dry_run:
            log(f"DRY RUN would execute: {' '.join(command)}")
            continue
        handle = log_path.open("w", encoding="utf-8")
        handles.append(handle)
        processes.append((entry, subprocess.Popen(command, cwd=REPO, env=env, stdout=handle,
                                                  stderr=subprocess.STDOUT,
                                                  start_new_session=True)))
    started = time.time()
    # One shared deadline for all identities: a single stuck process must not
    # stretch the run, and the last process inherits whatever time is left.
    deadline = started + _seconds(args.duration) + OVERRUN_GRACE_S
    results = []
    for entry, process in processes:
        overran = False
        try:
            process.wait(timeout=max(1.0, deadline - time.time()))
        except subprocess.TimeoutExpired:
            overran = True
            log(f"workload for {entry['ns']} passed the run deadline; terminating it")
            terminate(process)
        results.append({"ns": entry["ns"], "ip": entry["ip"],
                        "returncode": process.returncode, "overran": overran})
    for handle in handles:
        handle.close()
    elapsed = round(time.time() - started, 2)
    overran = [row["ns"] for row in results if row["overran"]]
    log(f"workload finished in {elapsed}s" + (f" (overran: {', '.join(overran)})" if overran else ""))
    return results


def terminate(process: subprocess.Popen) -> None:
    """Stop a workload process group: graceful interrupt, then TERM, then KILL."""
    for sig, grace in ((signal.SIGINT, 10), (signal.SIGTERM, 5)):
        if process.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(process.pid), sig)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=grace)
            return
        except subprocess.TimeoutExpired:
            continue
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except ProcessLookupError:
        pass


def last_activity_ms(run_dir: pathlib.Path) -> int:
    """Latest attempt completion time recorded in this run, in epoch milliseconds."""
    latest = 0
    for path in run_dir.glob("attempts-*.jsonl"):
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    latest = max(latest, int(json.loads(line).get("ended_ms") or 0))
                except (ValueError, TypeError):
                    continue
    return latest


def _seconds(duration: str) -> float:
    text = duration.strip().lower()
    for suffix, factor in (("ms", 0.001), ("s", 1.0), ("m", 60.0), ("h", 3600.0)):
        if text.endswith(suffix):
            return float(text[: -len(suffix)]) * factor
    return float(text)


def run(args) -> int:
    args.data = identities.load(args.identities)
    args.run_id = args.run_id or (f"{args.workload}-{args.config.lower()}-r{args.repetition}-"
                                 f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}")
    args.runs = pathlib.Path(args.runs)
    run_dir = args.runs / args.run_id
    if run_dir.exists() and not args.dry_run:
        log(f"refusing to overwrite existing evidence: {run_dir}")
        return 1
    if not args.dry_run:
        run_dir.mkdir(parents=True, exist_ok=True)
        _give_ownership(args.runs, recursive=False)

    if args.profile not in {"undercap", "overcap"}:
        log(f"unknown --profile {args.profile}")
        return 1

    problems = preflight(args, args.data)
    if problems:
        for problem in problems:
            log(f"READINESS FAIL: {problem}")
        if not args.dry_run:
            run_dir.mkdir(parents=True, exist_ok=True)
            manifest_mod.write(run_dir / "manifest.json", manifest_mod.build(
                run_id=args.run_id, config=args.config, workload=args.workload,
                attack=args.workload if args.workload != "benign" else None,
                repetition=args.repetition, repo_root=REPO, target=args.target,
                flags=CONFIGS[args.config],
                identities=identities.identities_for(args.data, args.workload),
                accounts={"attacker": args.data["attacker_account"]},
                duration_s=_seconds(args.duration), users=args.users,
                spawn_rate=args.spawn_rate, client_timeout_s=args.timeout, datasets=[],
                policy_path=REPO / "waf/config.py",
                notes=[f"readiness failure: {problem}" for problem in problems],
                extra={"readiness": "failed", "invalid": True},
            ))
        return 1
    if args.dry_run:
        run_workload(args, run_dir)
        log("dry run complete; nothing was reset, started or measured")
        return 0

    env = {
        **os.environ,
        "PYTHONPATH": str(REPO),
        "REDIS_URL": args.redis_url,
        "LLM_BASE_URL": f"http://127.0.0.1:{args.mock_port}",
        "P20_RUN_ID": args.run_id,
        **CONFIGS[args.config],
    }
    mock = api = None
    started_utc = manifest_mod.utc_now()
    t0 = time.time()
    try:
        reset_state(args)
        mock = start_service("mock LLM", [args.python, "-m", "uvicorn",
                                          "app.llm_service:app", "--host", "127.0.0.1",
                                          "--port", str(args.mock_port)],
                             env, run_dir / "mock.log")
        api = start_service("API", [args.python, "-m", "uvicorn", "app.main:app",
                                    "--host", "0.0.0.0", "--port", str(args.api_port),
                                    "--no-proxy-headers"],
                            env, run_dir / "api.log")
        health = wait_for_health(f"http://127.0.0.1:{args.api_port}")
        if health is None or health.get("status") != "ok":
            log("API did not become healthy (Redis and mock must both answer); see api.log")
            return 1
        (run_dir / "health.json").write_text(json.dumps(health, indent=2) + "\n", encoding="utf-8")
        expected = CONFIGS[args.config]
        mismatch = []
        if health.get("waf_mode") != expected["WAF_MODE"]:
            mismatch.append(f"waf_mode={health.get('waf_mode')} != {expected['WAF_MODE']}")
        controls = health.get("controls", {})
        enforce = expected["WAF_MODE"] == "enforce"
        if bool(controls.get("buckets")) != (enforce and expected["WAF_BUCKETS"] == "1"):
            mismatch.append("buckets control does not match the requested config")
        if bool(controls.get("honeypot")) != (enforce and expected["WAF_HONEYPOT"] == "1"):
            mismatch.append("honeypot control does not match the requested config")
        if bool(controls.get("ml")) != (enforce and expected["WAF_ML"] == "1"):
            mismatch.append("ml control does not match the requested config")
        if mismatch:
            log("effective configuration mismatch: " + "; ".join(mismatch))
            return 1
        log(f"readiness ok: {health['waf_mode']} / {controls}")

        usage_before = http_json(f"http://127.0.0.1:{args.api_port}/_metrics/usage") or {}
        workload_started_ms = int(time.time() * 1000)
        results = run_workload(args, run_dir)
        usage_after = http_json(f"http://127.0.0.1:{args.api_port}/_metrics/usage") or {}
        (run_dir / "usage.json").write_text(json.dumps(
            {"before": usage_before, "after": usage_after}, indent=2) + "\n", encoding="utf-8")

        decisions = None
        if expected["WAF_MODE"] != "off":
            decisions = snapshot_decisions(args.redis_url, run_dir / "decisions.jsonl")
            log(f"archived {decisions} WAF decision record(s)")
        duration = round(time.time() - t0, 2)
        budget_ms = workload_started_ms + int((_seconds(args.duration) + 5) * 1000)
        last_ms = last_activity_ms(run_dir)
        late_traffic = bool(last_ms and last_ms > budget_ms)
        if late_traffic:
            log(f"WARNING: traffic continued {(last_ms - budget_ms) / 1000:.1f}s past the budget")
        overran = [row["ns"] for row in results if row["overran"]]
        manifest = manifest_mod.build(
            run_id=args.run_id, config=args.config, workload=args.workload,
            attack=args.workload if args.workload != "benign" else None,
            repetition=args.repetition, repo_root=REPO, target=args.target,
            flags=CONFIGS[args.config], identities=identities.identities_for(args.data, args.workload),
            accounts={"attacker": args.data["attacker_account"],
                      "benign_pool": args.data["benign_accounts"]["accounts"]},
            duration_s=duration, users=args.users, spawn_rate=args.spawn_rate,
            client_timeout_s=args.timeout,
            datasets=[os.environ.get("P20_CREDS", str(REPO / "locust/data/creds_seed42.json"))],
            policy_path=REPO / "waf/config.py", started_utc=started_utc,
            extra={"readiness": "ok", "profile": args.profile, "per_identity": results,
                   "duration_requested": args.duration,
                   "overran": overran, "late_traffic": late_traffic,
                   "invalid": late_traffic,
                   "waf_decisions_archived": decisions},
        )
        manifest_mod.write(run_dir / "manifest.json", manifest)
        nonzero = sum(row["returncode"] != 0 for row in results)
        log(f"run complete: {run_dir} ({duration}s, {nonzero} non-zero exit(s))")
    finally:
        if api is not None:
            stop_service(api, "API")
        if mock is not None:
            stop_service(mock, "mock LLM")
        _give_ownership(run_dir)
        _give_ownership(args.runs, recursive=False)
    return 0


def _give_ownership(path: pathlib.Path, recursive: bool = True) -> None:
    """Keep evidence files owned by the invoking user, not root."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid or not gid:
        return
    targets = [path, *path.rglob("*")] if recursive and path.is_dir() else [path]
    for target in targets:
        try:
            os.chown(target, int(uid), int(gid))
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", default="eval/runs")
    parser.add_argument("--python", default=str(REPO / ".venv/bin/python"))
    parser.add_argument("--redis-url", default=os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0"))
    parser.add_argument("--identities", default=str(identities.DEFAULT_PATH))
    sub = parser.add_subparsers(dest="command", required=True)
    run_parser = sub.add_parser("run", help="execute one measured run")
    run_parser.add_argument("--config", required=True, choices=sorted(CONFIGS))
    run_parser.add_argument("--workload", required=True, choices=sorted(WORKLOADS))
    run_parser.add_argument("--repetition", type=int, default=1)
    run_parser.add_argument("--duration", default="45s")
    run_parser.add_argument("--users", type=int, default=0,
                            help="total virtual users across identities (0 = workload default)")
    run_parser.add_argument("--spawn-rate", type=float, default=5)
    run_parser.add_argument("--timeout", type=float, default=3.0)
    run_parser.add_argument("--seed", type=int, default=42)
    run_parser.add_argument("--profile", default="undercap", choices=["undercap", "overcap"])
    run_parser.add_argument("--max-output", type=int, default=0)
    run_parser.add_argument("--per-page", type=int, default=100)
    run_parser.add_argument("--target", default="http://10.20.0.1:8000")
    run_parser.add_argument("--api-port", type=int, default=8000)
    run_parser.add_argument("--mock-port", type=int, default=8001)
    run_parser.add_argument("--run-id", default=None)
    run_parser.add_argument("--no-netns", action="store_true")
    run_parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.config in BLOCKED_CONFIGS:
        log(BLOCKED_CONFIGS[args.config])
        return 2
    args.data = identities.load(args.identities)
    if args.users <= 0:
        args.users = WORKLOADS[args.workload][1]
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
