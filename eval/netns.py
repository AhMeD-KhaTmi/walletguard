"""Create/remove the isolated client namespaces described by `identities.json`.

Every measured client must have a real, distinct source IPv4 address. This module
turns the identity plan into explicit `ip` commands; `scripts/make_netns.sh` and
`scripts/teardown_netns.sh` are thin privileged wrappers so the plan is defined once.

Usage:
    python3 eval/netns.py apply --dry-run     # print the exact commands
    sudo python3 eval/netns.py apply          # create bridge + namespaces
    sudo python3 eval/netns.py check          # verify addresses inside each ns
    sudo python3 eval/netns.py cleanup        # remove namespaces + bridge
"""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eval import identities  # noqa: E402  (after the repository-root bootstrap)


def veth_names(ns: str) -> tuple[str, str]:
    suffix = ns[2:] if ns.startswith("ns") else ns
    return f"veth{suffix}", f"veth{suffix}br"


def apply_commands(data: dict) -> list[list[str]]:
    bridge = data["bridge"]["interface"]
    cidr = data["bridge"]["cidr"]
    commands = [
        ["ip", "link", "add", bridge, "type", "bridge"],
        ["ip", "addr", "add", f'{data["bridge"]["ip"]}/{cidr.split("/")[1]}', "dev", bridge],
        ["ip", "link", "set", bridge, "up"],
    ]
    for group in ("benign", "attack", "probe"):
        entries = (
            [entry for entries in data["attack"].values() for entry in entries]
            if group == "attack"
            else data[group]
        )
        for entry in entries:
            ns, ip = entry["ns"], entry["ip"]
            host_side, bridge_side = veth_names(ns)
            commands += [
                ["ip", "netns", "add", ns],
                ["ip", "link", "add", host_side, "type", "veth", "peer", "name", bridge_side],
                ["ip", "link", "set", host_side, "netns", ns],
                ["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"],
                ["ip", "netns", "exec", ns, "ip", "addr", "add", f"{ip}/24", "dev", host_side],
                ["ip", "netns", "exec", ns, "ip", "link", "set", host_side, "up"],
                ["ip", "netns", "exec", ns, "ip", "route", "add", "default", "via",
                 data["bridge"]["ip"]],
                ["ip", "link", "set", bridge_side, "master", bridge],
                ["ip", "link", "set", bridge_side, "up"],
            ]
    return commands


def cleanup_commands(data: dict) -> list[list[str]]:
    commands = []
    for group in ("benign", "attack", "probe"):
        entries = (
            [entry for entries in data["attack"].values() for entry in entries]
            if group == "attack"
            else data[group]
        )
        for entry in entries:
            commands.append(["ip", "netns", "del", entry["ns"]])
    commands.append(["ip", "link", "del", data["bridge"]["interface"]])
    return commands


def _run(commands: list[list[str]], tolerate: bool = True) -> int:
    failures = 0
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            if tolerate:
                print(f"skip  {' '.join(command)}  ({detail})")
            else:
                failures += 1
                print(f"FAIL  {' '.join(command)}  ({detail})", file=sys.stderr)
    return failures


def check(data: dict) -> int:
    failures = 0
    for group in ("benign", "attack", "probe"):
        entries = (
            [entry for entries in data["attack"].values() for entry in entries]
            if group == "attack"
            else data[group]
        )
        for entry in entries:
            result = subprocess.run(
                ["ip", "netns", "exec", entry["ns"], "ip", "-4", "-br", "addr", "show"],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                failures += 1
                print(f"MISSING {entry['ns']}: {result.stderr.strip()}", file=sys.stderr)
            elif entry["ip"] not in result.stdout:
                failures += 1
                print(f"WRONG   {entry['ns']}: expected {entry['ip']}, got {result.stdout.strip()}",
                      file=sys.stderr)
            else:
                print(f"ok      {entry['ns']} {entry['ip']}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=["apply", "cleanup", "check"])
    parser.add_argument("--file", default=str(Path(identities.DEFAULT_PATH)))
    parser.add_argument("--dry-run", action="store_true", help="print commands, change nothing")
    args = parser.parse_args()

    data = identities.load(args.file)
    if args.action == "check":
        if os.geteuid() != 0 or args.dry_run:
            print("check needs root (sudo) to enter namespaces", file=sys.stderr)
        return check(data)

    commands = apply_commands(data) if args.action == "apply" else cleanup_commands(data)
    if args.dry_run:
        for command in commands:
            print(shlex.join(command))
        return 0
    if os.geteuid() != 0:
        print("root is required to create network namespaces; use the shell wrapper with sudo",
              file=sys.stderr)
        return 1
    if not shutil.which("ip"):
        print("the `ip` command is missing (install iproute2)", file=sys.stderr)
        return 1
    failures = _run(commands)
    if args.action == "apply":
        failures += check(data)
    if failures:
        print(f"{failures} problem(s); the environment is not ready for measured traffic",
              file=sys.stderr)
        return 1
    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
