"""Load and validate the canonical client identity plan (`identities.json`).

The identity plan is shared with `scripts/make_netns.sh`, the run manifests and the
ML label files, so it is validated here instead of being duplicated in each tool.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

DEFAULT_PATH = Path(__file__).with_name("identities.json")
WORKLOADS = ("benign", "credential_stuffing", "scraping", "dow", "honeypot", "churn")


class IdentityError(ValueError):
    """The identity plan is inconsistent or unsafe to run."""


def load(path: str | Path | None = None) -> dict:
    data = json.loads(Path(path or DEFAULT_PATH).read_text(encoding="utf-8"))
    validate(data)
    return data


def validate(data: dict) -> None:
    if data.get("schema_version") != 1:
        raise IdentityError("identities.json: unsupported schema_version")
    bridge = data["bridge"]
    network = ipaddress.ip_network(bridge["cidr"])
    if ipaddress.ip_address(bridge["ip"]) not in network:
        raise IdentityError("identities.json: bridge ip is outside its cidr")

    seen_ns: set[str] = set()
    seen_ip: set[str] = set()
    for group in ("benign", "attack", "probe"):
        for entry in _entries(data, group):
            if entry["ns"] in seen_ns:
                raise IdentityError(f"duplicate namespace {entry['ns']}")
            if entry["ip"] in seen_ip:
                raise IdentityError(f"duplicate address {entry['ip']}")
            if ipaddress.ip_address(entry["ip"]) not in network:
                raise IdentityError(f"{entry['ip']} is outside {network}")
            if entry["ip"] in management_ips(data):
                raise IdentityError(f"{entry['ip']} is a management address")
            seen_ns.add(entry["ns"])
            seen_ip.add(entry["ip"])

    benign_accounts = {account for entry in data["benign"] for account in entry["accounts"]}
    if data["attacker_account"] in benign_accounts:
        raise IdentityError("attacker account must never appear in the benign pool")


def _entries(data: dict, group: str) -> list[dict]:
    if group == "attack":
        return [entry for entries in data["attack"].values() for entry in entries]
    return data[group]


def management_ips(data: dict) -> set[str]:
    return set(data["management"]["hosts"])


def all_ips(data: dict) -> set[str]:
    return {entry["ip"] for group in ("benign", "attack", "probe") for entry in _entries(data, group)}


def benign_ips(data: dict) -> list[str]:
    return [entry["ip"] for entry in data["benign"]]


def attack_ips(data: dict, workload: str) -> list[str]:
    if workload not in data["attack"]:
        raise IdentityError(f"unknown attack workload {workload!r}")
    return [entry["ip"] for entry in data["attack"][workload]]


def probe_ips(data: dict) -> list[str]:
    return [entry["ip"] for entry in data["probe"]]


def identities_for(data: dict, workload: str) -> list[dict]:
    """Namespaces/IPs that must originate traffic for a workload."""
    if workload == "benign":
        return list(data["benign"])
    if workload in data["attack"]:
        return list(data["attack"][workload])
    if workload in {"honeypot", "churn"}:
        return [entry for entry in data["probe"] if workload in entry["workloads"]]
    raise IdentityError(f"unknown workload {workload!r}")


def accounts_for(data: dict, ns: str) -> list[str]:
    for entry in data["benign"]:
        if entry["ns"] == ns:
            return list(entry["accounts"])
    return []


def assert_allowlist_safe(data: dict, allowlist: set[str]) -> None:
    """Measured traffic must never be exempted from defense by the allowlist."""
    offenders = all_ips(data) & set(allowlist)
    if offenders:
        raise IdentityError(
            "measured addresses found in p20:allowlist: " + ", ".join(sorted(offenders))
        )
