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
import hashlib
import json
import math
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

from eval import identities, manifest as manifest_mod, resources  # noqa: E402
from common.agent import AGENT_VERSION, DEFAULT_AGENT_STEPS
from common.tokens import TOKENIZER_VERSION
from waf.features import FEATURE_VERSION

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
BLOCKED_CONFIGS = {"C4": "C4 is blocked: the eBPF sensor/XDP integration does not exist yet, "
                         "so WAF_EBPF_SIGNALS=1 is refused by the application"}
WORKLOADS = {
    "benign": ("locust/benign.py", 5, "benign"),
    "credential_stuffing": ("locust/attack_credential_stuffing.py", 3, "credential_stuffing"),
    "scraping": ("locust/attack_scraping.py", 3, "scraping"),
    "dow": ("locust/attack_dow.py", 2, "dow"),
    "honeypot": ("locust/attack_honeypot.py", 1, "honeypot"),
    "churn": ("locust/attack_churn.py", 1, "churn"),
    # 5 benign + 9 attacker identities (MASTER_PLAN 7.2.4)
    "mixed": ("locust/mixed.py", 14, "mixed"),
    # 9 attacker identities, no setup phase (MASTER_PLAN 7.1)
    "combined": ("locust/mixed.py", 9, "combined"),
}
SETUP_GATED_WORKLOADS = {"dow"}
SETUP_TIMEOUT_S = 45.0


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
    if args.config == "C3" and not args.model.is_file():
        problems.append(f"C3 model missing: {args.model}")
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


def reset_state(args, keep_sessions: bool = False) -> None:
    command = [args.python, str(REPO / "scripts/reset_state.py"),
               "--redis-url", args.redis_url]
    if keep_sessions:
        command.append("--keep-sessions")
    result = subprocess.run(command, cwd=REPO, capture_output=True, text=True)
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


def snapshot_bans(redis_url: str, path: pathlib.Path) -> int:
    """Archive ``p20:ban:<ip>`` records so server-side ban timing survives the reset.

    The decision stream says *that* an IP was banned; this file says *when* Redis held
    the ban, which is what `time_to_redis_ban_ms` is measured against.
    """
    client = redis_client(redis_url)
    try:
        entries = []
        for key in client.scan_iter(match="p20:ban:*", count=500):
            raw = client.get(key)
            try:
                payload = json.loads(raw) if raw else {}
            except ValueError:
                payload = {"raw": raw}
            entries.append({"ip": key.split("p20:ban:", 1)[-1], **payload})
    finally:
        client.close()
    entries.sort(key=lambda entry: (entry.get("ts_ms") or 0, entry.get("ip") or ""))
    path.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    return len(entries)


def read_worker_meta(run_dir: pathlib.Path) -> list[dict]:
    """Per-process seeds actually used, written by each workload worker."""
    workers = []
    for path in sorted(run_dir.glob("worker-*.json")):
        try:
            workers.append(json.loads(path.read_text(encoding="utf-8")))
        except ValueError:
            workers.append({"status": "unreadable", "file": path.name})
    workers.sort(key=lambda worker: (str(worker.get("ip")), int(worker.get("pid") or 0)))
    return workers


def snapshot_features(redis_url: str, path: pathlib.Path) -> dict:
    """Archive the C1 observe-mode feature stream before the next reset deletes it.

    `scripts/reset_state.py` removes ``p20:stream:waf_features``; without this copy a
    C1 run leaves no feature matrix behind and B cannot train or evaluate a detector.
    The row count and SHA-256 are recorded in the manifest so the export is checkable.
    """
    client = redis_client(redis_url)
    try:
        entries = client.xrange("p20:stream:waf_features", min="-", max="+", count=500_000)
    finally:
        client.close()
    with path.open("w", encoding="utf-8") as handle:
        for entry_id, fields in entries:
            handle.write(json.dumps({"stream_id": entry_id, **fields}) + "\n")
    return {"status": "ok", "file": path.name, "rows": len(entries),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "stream": "p20:stream:waf_features"}


def invalid_reasons(results: list[dict], late_traffic: bool) -> list[str]:
    """MASTER_PLAN 7.2.5: missing measured evidence invalidates the run.

    A worker that exited non-zero may have stopped part-way through its budget; one
    that had to be terminated at the deadline has an unknown tail. Either way the
    attempt denominator is incomplete, so the row must not be summarised as valid.
    """
    reasons = ["late_traffic"] if late_traffic else []
    for row in results:
        name = row.get("ns")
        if row.get("overran"):
            reasons.append(f"overran:{name}")
        code = row.get("returncode")
        if code is not None and code != 0:
            reasons.append(f"exit:{name}:{code}")
    return reasons


def workload_command(args, entry: dict, run_dir: pathlib.Path) -> tuple[list[str], dict, pathlib.Path]:
    script, users, _ = WORKLOADS[args.workload]
    per_identity = max(1, args.users // max(1, len(identities.identities_for(args.data, args.workload))))
    target = args.target
    python = args.python
    locust_bin = str(REPO / ".venv/bin/locust") if (REPO / ".venv/bin/locust").exists() else "locust"
    gated = args.workload in SETUP_GATED_WORKLOADS and not args.no_setup_gate
    # A gated run spends setup time inside the same Locust process, so its own -t must
    # be generous; the client deadline (armed when the gate opens) enforces the window.
    run_time = (f"{_seconds(args.duration) + SETUP_TIMEOUT_S + 60:.0f}s"
                if gated else args.duration)
    command = [locust_bin, "-f", str(REPO / script), "--headless",
               "-u", str(per_identity), "-r", str(args.spawn_rate),
               "-t", run_time, "--stop-timeout", str(math.ceil(args.timeout + 1)),
               "--host", target, "--only-summary",
               "--exit-code-on-error", "0"]
    env = {
        **os.environ,
        "P20_RUN_ID": args.run_id,
        "P20_TARGET": target,
        "P20_RUNS_DIR": str(REPO / args.runs),
        "P20_TIMEOUT": str(args.timeout),
        "P20_SEED": str(args.seed),
        "P20_WORKER_ID": entry["ns"],
        "P20_EXPECT_IP": entry["ip"],
        "P20_ATTACKER_ACCOUNT": args.data["attacker_account"],
        "P20_DOW_PROFILE": args.profile,
        "P20_DOW_PACE_S": str(args.dow_pace),
        "P20_PER_PAGE": str(args.per_page),
        "P20_DEADLINE_S": str(_seconds(args.duration)),
        "P20_GATE_DIR": str(pathlib.Path(args.runs, args.run_id, "gate")),
        "P20_SETUP_GATE": "1" if gated else "0",
        "P20_GATE_TIMEOUT": str(SETUP_TIMEOUT_S + 30),
    }
    if args.max_output:
        env["P20_MAX_OUTPUT"] = str(args.max_output)
    role = entry.get("role")
    if args.workload in {"mixed", "combined"}:
        env["P20_ROLE"] = str(role)
    if role == "benign":
        env["P20_BENIGN_ACCOUNTS"] = ",".join(identities.accounts_for(args.data, entry["ns"]))
    if args.no_netns:
        env.pop("P20_EXPECT_IP")
    else:
        command = ["ip", "netns", "exec", entry["ns"], *command]
    return command, env, run_dir / f"locust-{entry['ns']}-{entry['ip']}.log"


class SetupError(RuntimeError):
    """The setup phase of a gated workload did not complete before the deadline."""


def write_gate(gate_dir: pathlib.Path, payload: dict) -> None:
    """Publish gate state atomically: workload processes poll it from their namespaces."""
    gate_dir.mkdir(parents=True, exist_ok=True)
    target = gate_dir / "gate.json"
    temporary = gate_dir / f".gate-{os.getpid()}.tmp"
    temporary.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    os.replace(temporary, target)


def wait_for_setup(gate_dir: pathlib.Path, expected: int, timeout: float) -> bool:
    """Wait until every spawned user has written its setup-ready marker.

    Files, not Redis: the clients run inside network namespaces whose loopback is not
    the host's (see ``GatedUser.await_measured_phase``).
    """
    deadline = time.time() + timeout
    stable_since = None
    while time.time() < deadline:
        count = len(list(gate_dir.glob("setup-ready-*.json")))
        if count >= expected:
            # Let the last spawned users finish their login before resetting state,
            # otherwise a straggler's setup login would be charged to fresh buckets.
            stable_since = stable_since or time.time()
            if time.time() - stable_since >= 0.5:
                return True
        else:
            stable_since = None
        time.sleep(0.1)
    return False


def open_measured_phase(args, run_dir: pathlib.Path, expected: int) -> None:
    """DoW: wait for every setup login, reset policy state, keep sessions, open the gate."""
    gate_dir = run_dir / "gate"
    if not wait_for_setup(gate_dir, expected, SETUP_TIMEOUT_S):
        # Tell the waiting users to stop instead of leaving them until P20_GATE_TIMEOUT.
        write_gate(gate_dir, {"abort": True, "ts_ms": int(time.time() * 1000)})
        raise SetupError(
            f"setup logins did not finish within {SETUP_TIMEOUT_S:.0f}s for {expected} identit"
            f"{'y' if expected == 1 else 'ies'}")
    reset_state(args, keep_sessions=True)
    now = time.time()
    write_gate(gate_dir, {"measured": True, "ts_ms": int(now * 1000),
                          "deadline_epoch_s": now + _seconds(args.duration),
                          "opened_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                          "setup_markers": expected})
    log("setup phase complete: policy state reset, sessions preserved, measured phase open")


def run_workload(args, run_dir: pathlib.Path, on_started=None) -> tuple[list[dict], float]:
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
    if on_started is not None and not args.dry_run:
        # The measured window starts when the harness opens the gate, not at spawn.
        try:
            on_started()
        except BaseException:
            for entry, process in processes:
                terminate(process)
            for handle in handles:
                handle.close()
            raise
    measured_started = time.time()
    # One shared deadline for all identities: a single stuck process must not
    # stretch the run, and the last process inherits whatever time is left.
    deadline = measured_started + _seconds(args.duration) + OVERRUN_GRACE_S
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
    elapsed = round(time.time() - measured_started, 2)
    overran = [row["ns"] for row in results if row["overran"]]
    log(f"workload finished in {elapsed}s" + (f" (overran: {', '.join(overran)})" if overran else ""))
    return results, measured_started


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


def workload_metadata(args) -> dict:
    """Record effective DoW spacing without inventing it for older manifests."""
    return {
        "profile": args.profile if args.workload == "dow" else None,
        "dow_pace_s": max(0.0, args.dow_pace) if args.workload == "dow" else None,
    }


def run(args) -> int:
    args.data = identities.load(args.identities)
    args.run_id = args.run_id or (f"{args.workload}-{args.config.lower()}-r{args.repetition}-"
                                 f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}")
    args.runs = pathlib.Path(args.runs)
    if not args.runs.is_absolute():
        # Anchor relative run directories to the repo, not to the invoker's cwd.
        args.runs = REPO / args.runs
    run_dir = args.runs / args.run_id
    if run_dir.exists() and not args.dry_run:
        log(f"refusing to overwrite existing evidence: {run_dir}")
        return 1
    if not args.dry_run:
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "gate").mkdir(exist_ok=True)
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
                seed=args.seed,
                flags=CONFIGS[args.config],
                identities=identities.identities_for(args.data, args.workload),
                accounts={"attacker": args.data["attacker_account"]},
                duration_s=_seconds(args.duration), users=args.users,
                spawn_rate=args.spawn_rate, client_timeout_s=args.timeout, datasets=[],
                policy_path=REPO / "waf/config.py",
                notes=[f"readiness failure: {problem}" for problem in problems],
                extra={"readiness": "failed", "invalid": True, **workload_metadata(args)},
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
        "WAF_MODEL_PATH": str(args.model),
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
        mock_health = http_json(f"http://127.0.0.1:{args.mock_port}/health")
        flags = CONFIGS[args.config]
        mismatch = []
        if health.get("waf_mode") != flags["WAF_MODE"]:
            mismatch.append(f"waf_mode={health.get('waf_mode')} != {flags['WAF_MODE']}")
        controls = health.get("controls", {})
        enforce = flags["WAF_MODE"] == "enforce"
        if bool(controls.get("buckets")) != (enforce and flags["WAF_BUCKETS"] == "1"):
            mismatch.append("buckets control does not match the requested config")
        if bool(controls.get("honeypot")) != (enforce and flags["WAF_HONEYPOT"] == "1"):
            mismatch.append("honeypot control does not match the requested config")
        if bool(controls.get("ml")) != (enforce and flags["WAF_ML"] == "1"):
            mismatch.append("ml control does not match the requested config")
        if mismatch:
            log("effective configuration mismatch: " + "; ".join(mismatch))
            return 1
        log(f"readiness ok: {health['waf_mode']} / {controls}")

        usage_before = http_json(f"http://127.0.0.1:{args.api_port}/_metrics/usage") or {}
        mock_usage_before = http_json(f"http://127.0.0.1:{args.mock_port}/_metrics/usage") or {}
        sampler = resources.Sampler(api.pid, interval_s=args.sample_interval)
        sampler.start()
        on_started = None
        if args.workload in SETUP_GATED_WORKLOADS and not args.no_setup_gate:
            identity_count = len(identities.identities_for(args.data, args.workload))
            per_identity = max(1, args.users // max(1, identity_count))
            # Every spawned user logs in once during setup. Distinct from `flags`:
            # shadowing the config dict here crashed the run *after* traffic (2026-11-17).
            expected_setups = identity_count * per_identity
            on_started = lambda: open_measured_phase(args, run_dir, expected_setups)  # noqa: E731
        try:
            results, measured_started = run_workload(args, run_dir, on_started=on_started)
        except SetupError as exc:
            log(f"run invalid: {exc}")
            manifest_mod.write(run_dir / "manifest.json", manifest_mod.build(
                run_id=args.run_id, config=args.config, workload=args.workload,
                attack=args.workload if args.workload != "benign" else None,
                repetition=args.repetition, repo_root=REPO, target=args.target,
                seed=args.seed,
                flags=CONFIGS[args.config],
                identities=identities.identities_for(args.data, args.workload),
                accounts={"attacker": args.data["attacker_account"]},
                duration_s=0.0, users=args.users, spawn_rate=args.spawn_rate,
                client_timeout_s=args.timeout, datasets=[],
                policy_path=REPO / "waf/config.py", started_utc=started_utc,
                notes=[f"setup phase failed: {exc}"],
                extra={"readiness": "failed", "invalid": True},
            ))
            return 1
        finally:
            sampled = sampler.stop()
        measured_ms = int(measured_started * 1000)
        measured_elapsed = round(time.time() - measured_started, 2)
        drain_deadline = time.monotonic() + 30
        while time.monotonic() < drain_deadline:
            idle = http_json(f"http://127.0.0.1:{args.api_port}/health")
            if idle is not None and idle.get("active_agent_tasks", 0) == 0:
                break
            time.sleep(.1)
        else:
            log("agent tasks failed to drain before capture")
            return 1
        usage_after = http_json(f"http://127.0.0.1:{args.api_port}/_metrics/usage") or {}
        (run_dir / "usage.json").write_text(json.dumps(
            {"before": usage_before, "after": usage_after,
             "mock_before": mock_usage_before,
             "mock_after": http_json(f"http://127.0.0.1:{args.mock_port}/_metrics/usage")}, indent=2) + "\n", encoding="utf-8")

        decisions = None
        if flags["WAF_MODE"] != "off":
            decisions = snapshot_decisions(args.redis_url, run_dir / "decisions.jsonl")
            log(f"archived {decisions} WAF decision record(s)")
        bans = snapshot_bans(args.redis_url, run_dir / "bans.json")
        log(f"archived {bans} Redis ban record(s)")
        duration = round(time.time() - t0, 2)
        budget_ms = measured_ms + int((_seconds(args.duration) + 5) * 1000)
        last_ms = last_activity_ms(run_dir)
        late_traffic = bool(last_ms and last_ms > budget_ms)
        if late_traffic:
            log(f"WARNING: traffic continued {(last_ms - budget_ms) / 1000:.1f}s past the budget")
        overran = [row["ns"] for row in results if row["overran"]]
        nonzero_exit = [row["ns"] for row in results
                        if row["returncode"] not in (0, None)]
        reasons = invalid_reasons(results, late_traffic)
        app_evidence = None
        if args.config in {"C2", "C3"}:
            app_evidence = http_json(f"http://127.0.0.1:{args.api_port}/dashboard/evidence", timeout=20)
            if app_evidence is not None:
                (run_dir / "app-evidence.json").write_text(json.dumps(app_evidence) + "\n", encoding="utf-8")
            if (not app_evidence or app_evidence.get("run_id") != args.run_id
                    or app_evidence.get("dropped_timings") != 0):
                reasons.append("incomplete_application_timings")
        invalid = bool(reasons)
        if reasons:
            log("run invalid: " + ", ".join(reasons))
        if flags["WAF_MODE"] == "observe":
            features = snapshot_features(args.redis_url, run_dir / "features.jsonl")
            log(f"archived {features['rows']} C1 feature row(s)")
        else:
            # C0/C2 never write the stream, so this is not a zero-row measurement.
            features = {"status": "not_applicable", "rows": None, "file": None,
                        "reason": f"WAF_MODE={flags['WAF_MODE']} does not write "
                                  "p20:stream:waf_features"}
        manifest = manifest_mod.build(
            run_id=args.run_id, config=args.config, workload=args.workload,
            attack=args.workload if args.workload != "benign" else None,
            repetition=args.repetition, repo_root=REPO, target=args.target,
            seed=args.seed,
            flags=CONFIGS[args.config], identities=identities.identities_for(args.data, args.workload),
            accounts={"attacker": args.data["attacker_account"],
                      "benign_pool": args.data["benign_accounts"]["accounts"]},
            duration_s=measured_elapsed, users=args.users, spawn_rate=args.spawn_rate,
            client_timeout_s=args.timeout,
            datasets=[os.environ.get("P20_CREDS", str(REPO / "locust/data/creds_seed42.json"))],
            policy_path=REPO / "waf/config.py", started_utc=started_utc,
            model_path=args.model if args.config == "C3" else None,
            extra={"readiness": "ok",
                   "agent_version": AGENT_VERSION, "default_agent_steps": DEFAULT_AGENT_STEPS,
                   "tokenizer": TOKENIZER_VERSION, "feature_version": FEATURE_VERSION,
                   "mock": mock_health,
                   # `--profile` has an argparse default, so writing it for every workload
                   # would stamp "undercap" onto benign and scraping runs. Only the
                   # profiled workload records it.
                   **workload_metadata(args),
                   "per_identity": results,
                   "duration_requested": args.duration, "wall_duration_s": duration,
                   "overran": overran, "late_traffic": late_traffic,
                   "nonzero_exit": nonzero_exit,
                   "invalid": invalid, "invalid_reasons": reasons,
                   "workers": read_worker_meta(run_dir),
                   "features": features,
                   "waf_decisions_archived": decisions,
                   "bans_archived": bans,
                   "app_evidence_archived": app_evidence is not None,
                   "resources": {
                       "sampling_interval_requested_s": args.sample_interval,
                       "cpu_count": os.cpu_count(),
                       "app": sampled,
                       "agent": {"status": "not_used_in_this_run", "cpu_pct": None,
                                 "rss_mb_peak": None},
                       "xdp_dropped_packets": None,
                       "xdp_status": "not_used_in_this_run",
                   }},
        )
        manifest_mod.write(run_dir / "manifest.json", manifest)
        nonzero = len(nonzero_exit)
        log(f"run complete: {run_dir} ({duration}s, {nonzero} non-zero exit(s))")
    finally:
        if api is not None:
            stop_service(api, "API")
        if mock is not None:
            stop_service(mock, "mock LLM")
        _give_ownership(run_dir)
        _give_ownership(args.runs, recursive=False)
    return int(invalid)


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
    run_parser.add_argument("--model", type=pathlib.Path,
                            default=os.getenv("WAF_MODEL_PATH", str(REPO / "ml/model_base.joblib")))
    run_parser.add_argument("--seed", type=int, default=42)
    run_parser.add_argument("--profile", default="undercap", choices=["undercap", "overcap"])
    run_parser.add_argument("--max-output", type=int, default=0)
    run_parser.add_argument("--dow-pace", type=float, default=0.0,
                            help="DoW only: fixed seconds between chat attempts per user "
                                 "(0 = unpaced burst). A paced under-cap run is what lets "
                                 "the WAF reach llm_tok instead of ip_req")
    run_parser.add_argument("--per-page", type=int, default=100)
    run_parser.add_argument("--target", default="http://10.20.0.1:8000")
    run_parser.add_argument("--api-port", type=int, default=8000)
    run_parser.add_argument("--mock-port", type=int, default=8001)
    run_parser.add_argument("--run-id", default=None)
    run_parser.add_argument("--sample-interval", type=float, default=1.0,
                            help="seconds between app CPU/RSS samples during the measured phase")
    run_parser.add_argument("--no-netns", action="store_true")
    run_parser.add_argument("--no-setup-gate", action="store_true",
                            help="DoW only: skip the setup -> reset -> measure split (debugging)")
    run_parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    args.model = args.model.resolve()
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be positive and finite")

    if args.config in BLOCKED_CONFIGS:
        log(BLOCKED_CONFIGS[args.config])
        return 2
    args.data = identities.load(args.identities)
    if args.users <= 0:
        args.users = WORKLOADS[args.workload][1]
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
