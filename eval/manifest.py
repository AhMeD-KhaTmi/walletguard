"""Run manifests: everything a result row needs to be interpretable later.

A manifest is written next to the raw attempt records for every run. It records the
seeds, rates, identities, flags, dataset hashes, software versions and code revision
required by `docs/MASTER_PLAN.md` section 7.2. Missing information is recorded as an
explicit status value, never as a plausible-looking number.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import platform
import socket
import subprocess
import sys
import time
from importlib import metadata

SCHEMA = "p20-run-manifest"
SCHEMA_VERSION = 1
WATCHED_PACKAGES = ("locust", "fastapi", "uvicorn", "redis", "pytest", "scikit-learn")


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_file(path: str | pathlib.Path) -> str | None:
    source = pathlib.Path(path)
    if not source.is_file():
        return None
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def git_revision(repo_root: pathlib.Path) -> dict:
    def git(*args: str) -> str | None:
        try:
            result = subprocess.run(["git", *args], cwd=repo_root, capture_output=True,
                                    text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            return None
        return result.stdout.strip() if result.returncode == 0 else None

    commit = git("rev-parse", "HEAD")
    if commit is None:
        return {"commit": None, "dirty": None, "status": "git_unavailable"}
    status = git("status", "--porcelain")
    return {"commit": commit, "dirty": bool(status), "status": "ok"}


def software_versions() -> dict:
    versions = {"python": platform.python_version(), "python_implementation": sys.implementation.name}
    for package in WATCHED_PACKAGES:
        try:
            versions[package] = metadata.version(package)
        except metadata.PackageNotFoundError:
            versions[package] = None
    return versions


def environment() -> dict:
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "kernel": platform.release(),
        "cpu_count": os.cpu_count(),
        "machine": platform.machine(),
        "os_release": platform.freedesktop_os_release(),
        "btf_available": pathlib.Path("/sys/kernel/btf/vmlinux").is_file(),
    }


def dataset_entries(paths: list[str | pathlib.Path]) -> list[dict]:
    entries = []
    for path in paths:
        source = pathlib.Path(path)
        entries.append({
            "path": str(source),
            "exists": source.is_file(),
            "bytes": source.stat().st_size if source.is_file() else None,
            "sha256": sha256_file(source),
        })
    return entries


def build(*, run_id: str, config: str, workload: str, attack: str | None, repetition: int,
          repo_root: pathlib.Path, target: str, flags: dict, identities: list[dict],
          accounts: dict, duration_s: float, users: int, spawn_rate: float,
          client_timeout_s: float, datasets: list[str | pathlib.Path],
          seed: int | None = None,
          policy_path: str | pathlib.Path | None = None,
          model_path: str | pathlib.Path | None = None,
          started_utc: str | None = None, ended_utc: str | None = None,
          notes: list[str] | None = None, extra: dict | None = None) -> dict:
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "config": config,
        "workload": workload,
        "attack": attack,
        "repetition": repetition,
        "started_utc": started_utc or utc_now(),
        "ended_utc": ended_utc,
        "duration_s": duration_s,
        # The caller passes the seed it actually used. Reading `P20_SEED` from the
        # environment silently stamped the default 42 on runs started with another
        # `--seed`, because the harness only exports that variable into the child
        # workload processes.
        "seed": int(seed if seed is not None else os.environ.get("P20_SEED", "42")),
        "target": target,
        "users": users,
        "spawn_rate": spawn_rate,
        "client_timeout_s": client_timeout_s,
        "identities": identities,
        "accounts": accounts,
        "flags": flags,
        "code_revision": git_revision(repo_root),
        "software": software_versions(),
        "environment": environment(),
        "datasets": dataset_entries(datasets),
        "policy_hash": sha256_file(policy_path) if policy_path else None,
        "model_hash": sha256_file(model_path) if model_path else None,
        "sensor": {"interface": None, "attach_mode": None, "status": "not_used_in_this_run"},
        "notes": notes or [],
        **(extra or {}),
    }


def write(path: str | pathlib.Path, manifest: dict) -> pathlib.Path:
    output = pathlib.Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def load(path: str | pathlib.Path) -> dict:
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
