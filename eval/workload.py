"""Shared Locust plumbing for Member A's workloads.

This module lives in `eval/` on purpose: `locust/` has no `__init__.py` (that would
shadow the installed `locust` package and break the CLI), so workload files cannot
import a sibling module reliably. Repo-root imports are explicit and validated.

Every workload class derives from `LoggedUser`, which:

* verifies the process really uses the expected source IPv4 address (`P20_EXPECT_IP`);
* applies the client timeout from `P20_TIMEOUT` (default 3 s);
* shares one attempt log per process (one JSONL file per workload/source IP).
"""

from __future__ import annotations

import json
import os
import pathlib
import random
import time
import uuid
from typing import Any

from locust import HttpUser
from locust.exception import StopUser

from eval.clientlog import AttemptLog, execute

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_CREDS = ROOT / "locust" / "data" / "creds_seed42.json"
DEFAULT_TIMEOUT_S = 3.0
_LOGS: dict[tuple[str, str | None], AttemptLog] = {}


def env_float(name: str, default: float) -> float:
    return float(os.environ.get(name, default))


def env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


def env_list(name: str) -> list[str]:
    return [value.strip() for value in os.environ.get(name, "").split(",") if value.strip()]


def read_gate(path: pathlib.Path) -> dict:
    """Read the harness gate file, tolerating a concurrent atomic replace."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def creds_path() -> pathlib.Path:
    return pathlib.Path(os.environ.get("P20_CREDS", DEFAULT_CREDS))


def load_creds(path: pathlib.Path | str | None = None) -> dict:
    source = pathlib.Path(path or creds_path())
    if not source.exists():
        raise SystemExit(
            f"credential dataset not found: {source}\n"
            "Generate it first: python3 locust/data/make_creds.py"
        )
    return json.loads(source.read_text(encoding="utf-8"))


def get_log(workload: str, attack: str | None, target: str) -> AttemptLog:
    key = (workload, attack)
    if key not in _LOGS:
        _LOGS[key] = AttemptLog(workload=workload, attack=attack, target=target)
    return _LOGS[key]


class LoggedUser(HttpUser):
    """Base class: one authenticated-or-anonymous client with per-attempt records."""

    abstract = True
    workload = "generic"
    attack: str | None = None
    # Gated users must not start their clock at spawn: they spend that time in setup.
    gated = False
    # Declared on the class, not only in on_start: a gated user's *setup* login also
    # goes through send(), which checks this before the measured phase has opened.
    deadline: float | None = None

    def on_start(self) -> None:
        self.client.timeout = env_float("P20_TIMEOUT", DEFAULT_TIMEOUT_S)
        self.log = get_log(self.workload, self.attack, self.host)
        expected = os.environ.get("P20_EXPECT_IP")
        if expected and self.log.ip != expected:
            raise RuntimeError(
                f"source address is {self.log.ip}, expected {expected}; "
                "run inside the matching namespace"
            )
        self.rng = random.Random(env_int("P20_SEED", 42) ^ os.getpid())
        self.token: str | None = None
        # Independent stop condition: Locust's own --run-time has proved unreliable
        # here, so the client also refuses to start an attempt after its budget.
        if not self.gated:
            self.arm_deadline(env_float("P20_DEADLINE_S", 0.0))

    def arm_deadline(self, seconds: float) -> None:
        self.deadline = time.monotonic() + seconds if seconds > 0 else None

    # --- helpers used by the task methods -------------------------------------

    @property
    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def _past_deadline(self) -> bool:
        if self.deadline is not None and time.monotonic() >= self.deadline:
            # Stopping this user is not enough: Locust would keep the run alive until its
            # own --run-time, which is deliberately generous for gated workloads.
            try:
                self.environment.runner.quit()
            except Exception:  # noqa: BLE001 - shutdown is best effort
                pass
            return True
        return False

    def send(self, *, request, classify, route: str, method: str, intent: str,
             objective: bool = True, phase: str = "measured",
             unknown_on_timeout: bool = False, **extra: Any) -> dict:
        if self._past_deadline():
            raise StopUser()
        return execute(
            self.log, request=request, classify=classify, route=route, method=method,
            intent=intent, objective=objective, phase=phase,
            unknown_on_timeout=unknown_on_timeout, **extra,
        )

    def login(self, username: str, password: str, *, phase: str = "setup",
              objective: bool = False, client_id: str | None = None) -> dict:
        """Log in, capture the bearer token in memory only, and record the attempt."""
        from eval.clientlog import classify_login

        def call():
            response = self.client.post(
                "/login", json={"username": username, "password": password},
                name="/login", catch_response=False,
            )
            self._last_token = None
            if response.status_code == 200:
                try:
                    self._last_token = (response.json() or {}).get("token")
                except ValueError:
                    self._last_token = None
            return response

        row = self.send(request=call, classify=classify_login, route="/login",
                        method="POST", intent=f"login:{username}", objective=objective,
                        phase=phase, client_id=client_id or username)
        if row["outcome"] == "success":
            self.token = self._last_token
        return row


class GatedUser(LoggedUser):
    """DoW setup/measure split (MASTER_PLAN 7.1).

    The user logs in, announces that setup is finished, then blocks until the harness
    has cleared runtime state and opened the measured phase. The session token stays in
    this process's memory, so no bearer token is ever written to disk and the measured
    phase still starts against fresh buckets, bans and streams.

    ``abstract`` is declared here, not inherited: Locust discovers every User subclass
    visible in the locustfile's namespace, including imported ones, and would otherwise
    try to run this class - which has no tasks.
    """

    abstract = True
    gated = True

    def await_measured_phase(self) -> None:
        """Announce that setup is done, then block until the harness opens the gate.

        The channel is a file in the run directory, not Redis: every workload process
        runs inside ``ip netns exec``, and a network namespace has its own loopback, so
        ``redis://127.0.0.1:6379`` inside the namespace reaches nothing. The mount
        namespace is shared, so the run directory is reachable from every identity and
        leaves the gate timing in the run directory as evidence.
        """
        configured = os.environ.get("P20_GATE_DIR", "")
        if not configured:
            raise RuntimeError(
                "P20_GATE_DIR is not set; gated workloads must be started by eval/harness.py")
        gate_dir = pathlib.Path(configured)
        if not gate_dir.is_absolute():
            # Path("") is Path("."), which would make the gate depend on the cwd.
            raise RuntimeError(f"P20_GATE_DIR must be an absolute path, got {configured!r}")
        timeout = env_float("P20_GATE_TIMEOUT", 45.0)
        # One marker per *user*, so a per_identity > 1 run cannot open the gate after the
        # first user of a process has logged in while its siblings are still in setup.
        marker = gate_dir / f"setup-ready-{self.log.ip}-{os.getpid()}-{uuid.uuid4().hex[:8]}.json"
        marker.write_text(json.dumps({"ip": self.log.ip, "pid": os.getpid(),
                                      "ts_ms": int(time.time() * 1000)}) + "\n",
                          encoding="utf-8")
        gate = gate_dir / "gate.json"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = read_gate(gate)
            if state.get("measured"):
                # The measured window starts now, not at spawn.
                self.arm_deadline(env_float("P20_DEADLINE_S", 0.0))
                return
            if state.get("abort"):
                raise StopUser()
            time.sleep(0.05)
        raise RuntimeError("setup finished but the harness never opened the measured phase")
