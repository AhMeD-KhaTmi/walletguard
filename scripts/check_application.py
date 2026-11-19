"""Real HTTP development probes for C0/C1/C2; not the joint attack evaluation."""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import httpx
import redis

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def service(module, env):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        port = listener.getsockname()[1]
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", module, "--fd", str(listener.fileno()),
             "--no-proxy-headers", "--log-level", "error"],
            cwd=ROOT, env=env, pass_fds=(listener.fileno(),),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            url = f"http://127.0.0.1:{port}"
            with httpx.Client(timeout=.3, trust_env=False) as client:
                for _ in range(80):
                    if process.poll() is not None:
                        raise RuntimeError("owned service exited before readiness")
                    try:
                        if client.get(url+"/health").status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(.05)
                else:
                    raise RuntimeError("service readiness failed")
            yield url
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def run(output):
    url = "redis://127.0.0.1:6379/15"
    env = {**os.environ, "REDIS_URL": url, "WAF_ML": "0", "WAF_EBPF_SIGNALS": "0"}
    results = {"kind": "development_http_checks_not_final_asr", "kernel_integrated": False, "runs": []}
    try:
        with service("app.llm_service:app", env) as backend:
            for name, mode in (("C0", "off"), ("C1", "observe"), ("C2", "enforce")):
                for workload in ("logins", "catalogue", "chat_output_policy", "honeypot"):
                    # Each workload has a new application process and fully reset scratch state.
                    subprocess.run(["bash", "scripts/reset_state.sh"], cwd=ROOT, env=env, check=True, stdout=subprocess.DEVNULL)
                    current = {**env, "WAF_MODE": mode, "WAF_BUCKETS": "1", "WAF_HONEYPOT": "1",
                               "P20_RUN_ID": f"dev-{name}-{workload}", "LLM_BASE_URL": backend}
                    with service("app.main:app", current) as target:
                        with httpx.Client(base_url=target, timeout=10, trust_env=False) as c:
                            codes = []
                            if workload == "logins":
                                for _ in range(12):
                                    codes.append(c.post("/login", json={"username": "user1", "password": "Passw0rd!1"}).status_code)
                                assert codes[:5] == [200]*5
                                assert (any(x in (429, 403) for x in codes) if mode == "enforce" else codes == [200]*12)
                            elif workload == "catalogue":
                                # Forty-five small pages now fit the qualified burst/item
                                # allowances. Large pages exercise resource exhaustion.
                                codes = [c.get(f"/products?page={page}&per_page=100").status_code for page in range(1, 46)]
                                assert (any(x in (429, 403) for x in codes) if mode == "enforce" else codes == [200]*45)
                            elif workload == "chat_output_policy":
                                login = c.post("/login", json={"username": "user1", "password": "Passw0rd!1"})
                                login.raise_for_status()
                                response = c.post("/chat", headers={"authorization": "Bearer "+login.json()["token"]},
                                                  json={"prompt": "synthetic development probe", "max_output_tokens": 32000})
                                codes = [response.status_code]
                                assert codes == ([400] if mode == "enforce" else [200])
                            else:
                                codes = [c.get("/.env").status_code, c.get("/products").status_code]
                                assert codes == ([404, 403] if mode == "enforce" else [404, 200])
                            evidence = c.get("/dashboard/evidence")
                            evidence.raise_for_status()
                            assert evidence.json()["dropped_events"] == 0
                            with redis.Redis.from_url(url, decode_responses=True) as r:
                                features = r.xlen("p20:stream:waf_features")
                                decisions = r.xlen("p20:stream:waf_decisions")
                                if mode == "observe":
                                    assert features == decisions
                                    assert not list(r.scan_iter("p20:ban:*"))
                                    assert not list(r.scan_iter("p20:bkt:*"))
                            results["runs"].append({"config": name, "workload": workload,
                                                    "catalogue_per_page": 100 if workload == "catalogue" else None,
                                                    "response_codes": codes, "observe_samples": features,
                                                    "decision_records": decisions,
                                                    "timings": evidence.json()["timings"], "passed": True})
    finally:
        subprocess.run(["bash", "scripts/reset_state.sh"], cwd=ROOT, env=env, check=True, stdout=subprocess.DEVNULL)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2)+"\n")
    print(f"Passed {len(results['runs'])} real-HTTP application checks. All owned services stopped; DB 15 runtime state reset.")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT/"docs/evidence/application_http_checks.json")
    run(parser.parse_args().output)
