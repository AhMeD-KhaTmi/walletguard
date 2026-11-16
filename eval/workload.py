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
        budget = env_float("P20_DEADLINE_S", 0.0)
        self.deadline = time.monotonic() + budget if budget > 0 else None

    # --- helpers used by the task methods -------------------------------------

    @property
    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def _past_deadline(self) -> bool:
        return self.deadline is not None and time.monotonic() >= self.deadline

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
