"""Launch the local C0 demo and HTTP mock; Ctrl+C stops both owned processes."""

import argparse
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from contextlib import ExitStack
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--mock-port", type=int, default=8001)
    parser.add_argument("--mode", choices=["off", "observe", "enforce"], default="off")
    args = parser.parse_args()
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    env = {**os.environ, "WAF_MODE": args.mode, "WAF_BUCKETS": "0" if args.mode == "off" else "1", "WAF_HONEYPOT": "0" if args.mode == "off" else "1", "WAF_ML": "0", "WAF_EBPF_SIGNALS": "0", "LLM_BASE_URL": f"http://127.0.0.1:{args.mock_port}"}
    processes = []
    try:
        with ExitStack() as stack:
            # Reserve both ports first; never reuse or stop an unrelated server.
            sockets = []
            for port in (args.mock_port, args.port):
                listener = stack.enter_context(socket.socket())
                listener.bind(("127.0.0.1", port))
                listener.listen(128)
                sockets.append(listener)
            for module, listener in zip(("app.llm_service:app", "app.main:app"), sockets):
                processes.append(subprocess.Popen(
                    [sys.executable, "-m", "uvicorn", module, "--fd", str(listener.fileno()), "--no-proxy-headers", "--log-level", "warning"],
                    cwd=ROOT, env=env, pass_fds=(listener.fileno(),),
                ))
            url = f"http://127.0.0.1:{args.port}"
            with httpx.Client(timeout=.5, trust_env=False) as client:
                for _ in range(40):
                    if stop.is_set() or any(p.poll() is not None for p in processes):
                        raise RuntimeError("A demo service stopped before readiness")
                    try:
                        if client.get(url + "/health").status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(.25)
                else:
                    raise RuntimeError("Dependencies not ready; check Redis and the mock")
            label = {"off": "C0 baseline", "observe": "C1 observe only", "enforce": "C2 application defenses"}[args.mode]
            print(f"Demo application: {url}/\nManagement dashboard: {url}/dashboard\n{label}, simulated costs. Ctrl+C stops both services. No state was reset automatically.", flush=True)
            while not stop.wait(.25):
                if any(p.poll() is not None for p in processes):
                    raise RuntimeError("A demo service exited unexpectedly")
        return 0
    except (OSError, RuntimeError) as exc:
        print(f"Demo stopped: {exc}", file=sys.stderr)
        return 1
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
