"""Client-side attempt records: the denominator for every ASR and FPR claim.

A workload records one line per *attempt it decided to send*, before transmission
(`begin`) and after the outcome is known (`finish`). Locust's own success/failure
flag is never used as attack success: the objective predicates in this module are.

Rules implemented here (see `docs/MASTER_PLAN.md` section 7.1):

* intent is recorded before transmission, so scheduled-but-unsent actions are visible;
* sent attempts keep their timeouts and unknown outcomes instead of disappearing;
* setup logins are separate from measured malicious requests (`phase="setup"`);
* no bearer session, password or raw prompt is written to the record.
"""

from __future__ import annotations

import json
import os
import pathlib
import socket
import time
import uuid
from typing import Any, Callable
from urllib.parse import urlsplit

OUTCOMES = ("success", "fail", "blocked", "timeout", "error", "unknown")

RUNS_DIR = pathlib.Path(os.environ.get("P20_RUNS_DIR", "eval/runs"))


def utc_ms() -> int:
    return int(time.time() * 1000)


def local_ipv4(target: str) -> str:
    """Actual source address the kernel will use for `target` (no packet is sent)."""
    parts = urlsplit(target)
    if not parts.hostname:
        raise ValueError(f"target must be an absolute URL, got {target!r}")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((socket.gethostbyname(parts.hostname), port))
        return probe.getsockname()[0]


def _header(headers, name: str) -> str:
    """Read a response header case-insensitively (real HTTP stacks vary in casing)."""
    if not headers:
        return ""
    getter = getattr(headers, "get", None)
    if getter is not None:
        for candidate in (name, name.lower(), "-".join(part.capitalize() for part in name.split("-"))):
            value = getter(candidate)
            if value is not None:
                return value
    try:
        for key, value in headers.items():
            if key.lower() == name.lower():
                return value
    except AttributeError:
        pass
    return ""


def _error_outcome(exc: BaseException) -> str:
    name = type(exc).__name__.lower()
    text = str(exc).lower()
    if "greenletexit" in name or "keyboardinterrupt" in name:
        # Our own shutdown killed the request mid-flight: the server may have
        # processed it, so the outcome is unknown rather than a failure.
        return "unknown"
    if "timeout" in name or "timed out" in text:
        return "timeout"
    return "error"


class AttemptLog:
    """One JSONL file per workload process, so concurrent namespaces never interleave."""

    def __init__(self, *, workload: str, attack: str | None = None,
                 root: pathlib.Path | str | None = None, target: str | None = None,
                 run_id: str | None = None, ip: str | None = None):
        self.run_id = run_id or os.environ.get("P20_RUN_ID", "unlabelled")
        self.workload = workload
        self.attack = attack
        self.target = target or os.environ.get("P20_TARGET", "")
        self.ip = ip or (local_ipv4(self.target) if self.target else "unknown")
        base = pathlib.Path(root) if root else RUNS_DIR / self.run_id
        base.mkdir(parents=True, exist_ok=True)
        self.path = base / f"attempts-{workload}-{self.ip}-{os.getpid()}.jsonl"
        self._handle = self.path.open("a", encoding="utf-8")

    def worker_meta(self, *, configured_seed: int, derived_seed: int,
                    timeout_s: float, target: str | None = None) -> pathlib.Path | None:
        """Record the seed this process really used, once per worker process.

        Locust runs many users as greenlets inside one process per namespace, and the
        RNG is seeded with ``configured_seed ^ pid``. A manifest that only repeats
        ``--seed`` therefore cannot reproduce a worker's stream; this file states how
        the configured seed was expanded. It contains no session, password or prompt.
        """
        path = self.path.parent / f"worker-{self.ip}-{os.getpid()}.json"
        if path.exists():
            return None
        path.write_text(json.dumps({
            "workload": self.workload, "attack": self.attack, "ip": self.ip,
            "pid": os.getpid(), "configured_seed": configured_seed,
            "derived_seed": derived_seed, "client_timeout_s": timeout_s,
            "target": target,
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def begin(self, *, route: str, method: str, intent: str, objective: bool,
              phase: str = "measured", **extra: Any) -> dict:
        return {
            "attempt_id": uuid.uuid4().hex,
            "t0": time.perf_counter(),
            "started_ms": utc_ms(),
            "record": {
                "run_id": self.run_id, "workload": self.workload, "attack": self.attack,
                "phase": phase, "objective": bool(objective), "ip": self.ip,
                "pid": os.getpid(), "route": route, "method": method, "intent": intent,
                **extra,
            },
        }

    def finish(self, pending: dict, *, outcome: str, reason: str, status: int | None = None,
               **extra: Any) -> dict:
        if outcome not in OUTCOMES:
            raise ValueError(f"unknown outcome {outcome!r}")
        row = {
            **pending["record"],
            "attempt_id": pending["attempt_id"],
            "started_ms": pending["started_ms"],
            "ended_ms": utc_ms(),
            "latency_ms": round((time.perf_counter() - pending["t0"]) * 1000, 3),
            "status": status,
            "outcome": outcome,
            "reason": reason,
            "unresolved": outcome in {"timeout", "unknown"},
            **extra,
        }
        self._handle.write(json.dumps(row, sort_keys=True) + "\n")
        self._handle.flush()
        return row

    def close(self) -> None:
        self._handle.close()


def execute(log: AttemptLog, *, request: Callable[[], Any], classify: Callable[[Any], tuple],
            route: str, method: str, intent: str, objective: bool = True,
            phase: str = "measured", unknown_on_timeout: bool = False, **extra: Any) -> dict:
    """Send one attempt through `request()`, record it, and never lose the denominator."""
    pending = log.begin(route=route, method=method, intent=intent, objective=objective,
                        phase=phase, **extra)
    try:
        response = request()
    except Exception as exc:
        error = exc
    except BaseException as exc:
        log.finish(pending, outcome="unknown", reason=type(exc).__name__)
        raise
    else:
        # Locust wraps Requests transport failures in a status-0 response.
        error = getattr(response, "error", None)
    if error is not None:
        outcome = _error_outcome(error)
        if outcome == "timeout" and unknown_on_timeout:
            outcome = "unknown"
        return log.finish(pending, outcome=outcome, reason=type(error).__name__,
                          detail=str(error)[:200])
    try:
        outcome, reason, metrics = classify(response)
    except Exception as exc:  # a broken response body must not hide the attempt
        return log.finish(pending, outcome="error", reason=f"classify_{type(exc).__name__}",
                          status=getattr(response, "status_code", None), detail=str(exc)[:200])
    headers = getattr(response, "headers", None) or {}
    metrics.setdefault("request_id", _header(headers, "x-request-id") or None)
    metrics.setdefault("response_bytes", len(getattr(response, "content", b"") or b""))
    return log.finish(pending, outcome=outcome, reason=reason,
                      status=getattr(response, "status_code", None), **metrics)


# --- objective predicates -------------------------------------------------------

def classify_login(response) -> tuple[str, str, dict]:
    status = response.status_code
    if status == 200:
        token = (response.json() or {}).get("token")
        if isinstance(token, str) and token:
            return "success", "valid_credentials", {}
        return "fail", "no_token", {}
    if status == 401:
        return "fail", "invalid_credentials", {}
    if status == 429:
        return "blocked", "throttled", {}
    if status == 403:
        return "blocked", "banned", {}
    if status in (400, 422):
        return "fail", "rejected_input", {}
    return "error", f"http_{status}", {}


def classify_products(response, expected_ids: list[int] | None = None,
                      record_ids: bool = False) -> tuple[str, str, dict]:
    status = response.status_code
    if status == 200:
        body = response.json() or {}
        items = body.get("items") or []
        ids = [item.get("id") for item in items if isinstance(item, dict)]
        metrics: dict = {"item_count": len(ids)}
        if record_ids:
            metrics["product_ids"] = ids
        if not ids:
            return "fail", "empty_page", metrics
        if expected_ids is not None and not set(expected_ids) <= set(ids):
            return "fail", "partial_page", metrics
        return "success", "page_data", metrics
    if status == 429:
        return "blocked", "throttled", {}
    if status == 403:
        return "blocked", "banned", {}
    return "error", f"http_{status}", {}


def classify_chat(response) -> tuple[str, str, dict]:
    status = response.status_code
    headers = response.headers or {}
    if status == 504:
        return "unknown", "backend_generation_timeout", {}
    if status == 200:
        try:
            tokens_out = int(_header(headers, "x-tokens-out") or 0)
        except (TypeError, ValueError):
            tokens_out = 0
        try:
            tokens_in = int(_header(headers, "x-tokens-in") or 0)
        except (TypeError, ValueError):
            tokens_in = 0
        try:
            cost = float(_header(headers, "x-cost-usd") or 0.0)
        except (TypeError, ValueError):
            cost = 0.0
        metrics = {
            "tokens_in": tokens_in, "tokens_out": tokens_out, "cost_usd": cost,
            "usage_store": _header(headers, "x-usage-store"),
        }
        if tokens_out > 0:
            return "success", "accounted_usage", metrics
        return "fail", "no_accounted_usage", metrics
    if status == 429:
        return "blocked", "throttled", {}
    if status == 403:
        return "blocked", "banned", {}
    if status == 400:
        return "blocked", "output_policy", {}
    return "error", f"http_{status}", {}


def classify_probe(response) -> tuple[str, str, dict]:
    """Decoy and churn probes: any non-transport HTTP answer is a delivered attempt."""
    status = response.status_code
    return "success", f"http_{status}", {"content_bytes": len(response.content or b"")}
