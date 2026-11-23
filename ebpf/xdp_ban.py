"""Enforce schema-v2 Redis bans with an XDP source-IPv4 drop program.

Boundary and safety rules:

* ``p20:ban:*`` plus its remaining Redis TTL is the source of truth. This
  process never writes bans and never extends them: the Redis PTTL becomes a
  monotonic deadline stored in the XDP map, so a dead loader cannot keep an
  expired ban dropping forever.
* Only the source address of untagged IPv4 Ethernet frames is checked.
  Non-IPv4 and malformed frames pass.
* Local host addresses (loopback, the bridge address, any other local IPv4)
  and ``p20:allowlist`` members are never installed. The allowlist is
  re-read on every reconcile; newly allowlisted addresses are removed.
* Pub/sub ``p20:ch:ban`` triggers an immediate full reconcile. A periodic
  full scan covers missed messages, key deletion, TTL expiry and agent
  restarts.
* If Redis becomes unreachable, the existing map is kept (no fail-open
  flush); kernel deadlines still expire entries. This is not a guarantee
  that Redis stays authoritative while the agent is down.
* ``p20:xdp:drops`` is written here with cumulative per-IP counters for the
  published part of the run. Drops that happen while the loader is dead
  cannot be published by it.

Run on the canonical lab interface, after Redis and before C4 traffic::

    sudo python3 ebpf/xdp_ban.py p20br0     # iface is positional or --iface
"""

from __future__ import annotations

import argparse
import ctypes
import ipaddress
import json
import signal
import socket
import struct
import subprocess
import time

BAN_PREFIX = "p20:ban:"
BAN_CHANNEL = "p20:ch:ban"
ALLOWLIST_KEY = "p20:allowlist"
DROPS_KEY = "p20:xdp:drops"
SCHEMA_KEY = "p20:meta:schema_version"

XDP_SOURCE = r"""
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* Value is the absolute CLOCK_MONOTONIC deadline in nanoseconds. */
BPF_HASH(banned_ips, u32, u64, 10240);
BPF_HASH(drop_by_ip, u32, u64, 10240);
BPF_ARRAY(drop_count, u64, 1);

int xdp_drop_banned(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    u32 src = ip->saddr;
    u64 *deadline = banned_ips.lookup(&src);
    if (!deadline) return XDP_PASS;
    /* Kernel-side expiry: no loader is needed to stop an old ban. */
    if (bpf_ktime_get_ns() >= *deadline) return XDP_PASS;

    u64 zero = 0;
    u64 *by_ip = drop_by_ip.lookup_or_try_init(&src, &zero);
    if (by_ip) __sync_fetch_and_add(by_ip, 1);
    u32 idx = 0;
    u64 *total = drop_count.lookup(&idx);
    if (total) __sync_fetch_and_add(total, 1);
    return XDP_DROP;
}
"""


def _emit(payload: dict) -> None:
    print(json.dumps(payload, sort_keys=True), flush=True)


def ip_to_u32(ip: str) -> int:
    """Native-order u32 matching ``struct iphdr.saddr`` on this host."""
    return struct.unpack("=I", socket.inet_aton(ip))[0]


def u32_to_ip(value: int) -> str:
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("u32 address out of range")
    return socket.inet_ntoa(struct.pack("=I", value))


def _valid_ipv4(text) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except (TypeError, ValueError):
        return False
    return (isinstance(address, ipaddress.IPv4Address)
            and not address.is_multicast and not address.is_unspecified)


def valid_ban_ip(key: str, raw: str | None) -> str | None:
    """Return the canonical IPv4 only for a contract-shaped ban record.

    A malformed value or a key/value mismatch is ignored instead of being
    guessed: an attacker-controlled or truncated Redis value must not create
    a drop entry for a different address.
    """
    if not isinstance(key, str) or not key.startswith(BAN_PREFIX):
        return None
    text = key[len(BAN_PREFIX):]
    if not _valid_ipv4(text):
        return None
    try:
        record = json.loads(raw) if isinstance(raw, str) else None
    except ValueError:
        return None
    if not isinstance(record, dict) or record.get("ip") != text:
        return None
    return str(ipaddress.IPv4Address(text))


def eligible_bans(records: dict[str, str | None], *, allowlist=(),
                  excluded=()) -> dict[str, str]:
    """Map canonical IP -> Redis key for bans that may be installed."""
    allow = {str(ipaddress.IPv4Address(ip)) for ip in allowlist if _valid_ipv4(ip)}
    skip = {str(ipaddress.IPv4Address(ip)) for ip in excluded if _valid_ipv4(ip)}
    result = {}
    for key, raw in records.items():
        ip = valid_ban_ip(key, raw)
        if ip is None or ip in allow or ip in skip:
            continue
        result[ip] = key
    return result


def plan_reconciliation(desired, installed) -> tuple[list[str], list[str]]:
    desired = {str(ipaddress.IPv4Address(ip)) for ip in desired}
    installed = {str(ipaddress.IPv4Address(ip)) for ip in installed}
    return sorted(desired - installed), sorted(installed - desired)


def ban_deadline(pttl_ms: int, now_ns: int) -> int:
    """Absolute CLOCK_MONOTONIC deadline from the remaining Redis TTL."""
    if type(pttl_ms) is not int or pttl_ms <= 0:
        raise ValueError("ban must have a positive remaining TTL")
    if type(now_ns) is not int or now_ns < 0:
        raise ValueError("now_ns must be a nonnegative monotonic timestamp")
    return now_ns + pttl_ms * 1_000_000


def local_ipv4_addresses() -> set[str]:
    """Never install a drop for an address of this host."""
    output = subprocess.run(
        ["ip", "-4", "-o", "addr", "show"],
        check=True, capture_output=True, text=True,
    ).stdout
    addresses = {"127.0.0.1"}
    for line in output.splitlines():
        fields = line.split()
        if "inet" not in fields:
            continue
        cidr = fields[fields.index("inet") + 1]
        try:
            addresses.add(str(ipaddress.IPv4Address(cidr.split("/", 1)[0])))
        except ValueError:
            continue
    return addresses


def xdp_details(iface: str) -> str:
    result = subprocess.run(
        ["ip", "-details", "link", "show", "dev", iface],
        check=False, capture_output=True, text=True,
    )
    return result.stdout if result.returncode == 0 else ""


def xdp_attachment(iface: str) -> str:
    """Best available evidence of an attached XDP program (empty if none)."""
    for line in xdp_details(iface).splitlines():
        # iproute2 prints ``prog/xdp`` (and variants such as ``prog/xdpgeneric``).
        if "prog/xdp" in line:
            return " ".join(line.split())
    result = subprocess.run(
        ["bpftool", "net"], check=False, capture_output=True, text=True)
    if result.returncode == 0:
        in_xdp = False
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped == "xdp:":
                in_xdp = True
                continue
            if not in_xdp:
                continue
            if not stripped:
                in_xdp = False
                continue
            if (stripped.startswith(iface + "(")
                    or stripped.startswith(iface + " ")
                    or f" {iface}(" in stripped):
                return f"bpftool net: {stripped}"
    return ""


def has_xdp(iface: str) -> bool:
    return bool(xdp_attachment(iface))


class BanReconciler:
    """Read Redis bans and keep the XDP map equal to their live TTLs."""

    def __init__(self, client, banned_map, *, excluded):
        self.client = client
        self.banned_map = banned_map
        # ip -> absolute monotonic deadline currently installed in the map.
        self.installed: dict[str, int] = {}
        self.excluded = set(excluded)

    def _records(self) -> dict[str, str | None]:
        records = {}
        for key in self.client.scan_iter(match=BAN_PREFIX + "*", count=200):
            key = key.decode() if isinstance(key, bytes) else key
            if key.startswith(BAN_PREFIX):
                records[key] = self.client.get(key)
        return records

    def _allowlist(self) -> set[str]:
        return {str(ipaddress.IPv4Address(value))
                for value in self.client.smembers(ALLOWLIST_KEY)
                if _valid_ipv4(value)}

    def reconcile(self) -> dict:
        records = self._records()
        allow = self._allowlist()
        wanted = eligible_bans(
            records, allowlist=allow, excluded=self.excluded)
        now_ns = time.monotonic_ns()
        desired: dict[str, int] = {}
        skipped: list[str] = []
        errors: list[dict] = []
        for ip, key in sorted(wanted.items()):
            pttl = int(self.client.pttl(key))
            if pttl == -2:  # expired between SCAN/GET and PTTL
                continue
            if pttl <= 0:  # -1: no expiry; never install an unbounded drop
                skipped.append(ip)
                continue
            desired[ip] = ban_deadline(pttl, now_ns)

        add, remove = plan_reconciliation(desired, self.installed)
        for ip in remove:
            try:
                del self.banned_map[ctypes.c_uint32(ip_to_u32(ip))]
            except KeyError:
                pass
            except Exception as exc:  # keep tracking a still-installed entry
                errors.append({"ip": ip, "action": "remove", "error": str(exc)})
                continue
            self.installed.pop(ip, None)
        for ip in add:
            try:
                self.banned_map[ctypes.c_uint32(ip_to_u32(ip))] = \
                    ctypes.c_uint64(desired[ip])
            except Exception as exc:
                errors.append({"ip": ip, "action": "add", "error": str(exc)})
                continue
            self.installed[ip] = desired[ip]
        refreshed = []
        for ip, deadline in desired.items():
            # Mirror TTL changes in both directions (an admin may shorten a
            # ban with EXPIRE); ignore sub-millisecond rounding churn.
            if (ip in self.installed
                    and abs(deadline - self.installed[ip]) > 5_000_000):
                try:
                    self.banned_map[ctypes.c_uint32(ip_to_u32(ip))] = \
                        ctypes.c_uint64(deadline)
                except Exception as exc:
                    errors.append({"ip": ip, "action": "refresh",
                                   "error": str(exc)})
                    continue
                self.installed[ip] = deadline
                refreshed.append(ip)
        return {
            "added": add,
            "removed": remove,
            "refreshed": refreshed,
            "skipped_no_ttl": skipped,
            "errors": errors,
            "ban_keys": len(records),
            "map_size": len(self.installed),
        }


class DropReporter:
    """Publish cumulative kernel drop counters as absolute Redis values."""

    def __init__(self, client, *, bpf, reset: bool):
        self.client = client
        self.bpf = bpf
        self.base_total = 0
        self.base_by_ip: dict[str, int] = {}
        if reset:
            self.client.delete(DROPS_KEY)
        else:
            stored = self.client.hgetall(DROPS_KEY)
            try:
                self.base_total = int(stored.get("total_dropped_pkts", "0"))
            except ValueError:
                self.base_total = 0
            for field, value in stored.items():
                if not field.startswith("dropped_pkts:"):
                    continue
                ip = field.split(":", 1)[1]
                try:
                    self.base_by_ip[ip] = int(value)
                except ValueError:
                    continue

    def _kernel_total(self) -> int:
        return int(self.bpf["drop_count"][0].value)

    def _kernel_by_ip(self, ip: str) -> int:
        value = self.bpf["drop_by_ip"].get(ctypes.c_uint32(ip_to_u32(ip)))
        return 0 if value is None else int(value.value)

    def publish(self, *, installed, seen) -> dict:
        mapping = {
            "total_dropped_pkts": str(self.base_total + self._kernel_total()),
            "map_size": str(len(installed)),
            "updated_ms": str(int(time.time() * 1000)),
        }
        for ip in sorted(seen):
            mapping[f"dropped_pkts:{ip}"] = str(
                self.base_by_ip.get(ip, 0) + self._kernel_by_ip(ip))
        self.client.hset(DROPS_KEY, mapping=mapping)
        return mapping


def _mode_flags(BPF) -> dict[str, int]:
    return {
        "native": getattr(BPF, "XDP_FLAGS_DRV_MODE", 1 << 2),
        "generic": getattr(BPF, "XDP_FLAGS_SKB_MODE", 1 << 1),
    }


def attach_xdp(bpf, fn, BPF, iface: str, requested: str) -> tuple[str, int,
                                                                 dict]:
    flags_by_mode = _mode_flags(BPF)
    attempts = ("native", "generic") if requested == "auto" else (requested,)
    failures = {}
    for mode in attempts:
        try:
            bpf.attach_xdp(iface, fn, flags_by_mode[mode])
        except Exception as exc:
            failures[mode] = str(exc)
            _emit({"xdp_attach_attempt": mode, "iface": iface,
                   "result": "failed", "error": str(exc)})
            continue
        return mode, flags_by_mode[mode], failures
    raise RuntimeError(
        f"XDP is unavailable on {iface}: {failures}. Use the documented "
        "tc/nftables consumer of the same Redis bans instead of claiming a "
        "kernel drop path.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("iface_positional", nargs="?", help="interface (compat)")
    parser.add_argument("--iface", default=None,
                        help="interface to attach XDP to (default p20br0)")
    parser.add_argument("--mode", choices=("auto", "native", "generic"),
                        default="auto",
                        help="auto tries native, then generic/skb")
    parser.add_argument("--redis-url", default="redis://127.0.0.1:6379/0")
    parser.add_argument("--run-id", default="xdp-ban")
    parser.add_argument("--reconcile-interval", type=float, default=2.0,
                        help="periodic full scan seconds (default 2.0)")
    parser.add_argument("--publish-interval", type=float, default=1.0)
    parser.add_argument("--duration", type=float, default=0.0,
                        help="seconds to run (0 means until SIGINT/SIGTERM)")
    parser.add_argument("--replace-existing", action="store_true",
                        help="replace an XDP program already on the interface")
    parser.add_argument("--keep-drops", action="store_true",
                        help="keep existing p20:xdp:drops totals as a base")
    args = parser.parse_args(argv)
    iface = args.iface or args.iface_positional or "p20br0"
    if args.reconcile_interval <= 0 or args.publish_interval <= 0:
        parser.error("intervals must be positive")
    if args.duration < 0:
        parser.error("--duration must be nonnegative")
    if not args.run_id or len(args.run_id) > 128:
        parser.error("--run-id must be nonempty and at most 128 characters")

    # Supplied by the system Python on the Ubuntu VM, not by .venv.
    from bcc import BPF
    import redis

    client = redis.Redis.from_url(
        args.redis_url, decode_responses=True,
        socket_connect_timeout=2, socket_timeout=2)
    if client.get(SCHEMA_KEY) != "2":
        raise SystemExit("Redis schema v2 is required before enforcing bans")

    if has_xdp(iface) and not args.replace_existing:
        raise SystemExit(
            f"an XDP program is already attached to {iface}; pass "
            "--replace-existing only if it is this loader's stale program")

    excluded = local_ipv4_addresses() | {"127.0.0.1"}
    bpf = BPF(text=XDP_SOURCE)
    fn = bpf.load_func("xdp_drop_banned", BPF.XDP)
    mode, flags, failures = attach_xdp(bpf, fn, BPF, iface, args.mode)
    attached = {
        "xdp": "attached",
        "iface": iface,
        "mode": mode,
        "requested_mode": args.mode,
        "run_id": args.run_id,
        "excluded_local_addresses": sorted(excluded),
        "evidence": xdp_attachment(iface),
    }
    if failures:
        attached["attach_failures"] = failures
    _emit(attached)

    reconciler = BanReconciler(
        client, bpf["banned_ips"], excluded=excluded)
    reporter = DropReporter(
        client, bpf=bpf, reset=not args.keep_drops)
    seen: set[str] = set()

    def sync(reason: str) -> dict:
        result = reconciler.reconcile()
        seen.update(reconciler.installed)
        if (result["added"] or result["removed"] or result["errors"]
                or result["skipped_no_ttl"] or result["refreshed"]):
            result.update({"xdp": "sync", "reason": reason,
                           "run_id": args.run_id})
            _emit(result)
        return result

    running = True

    def request_stop(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    pubsub = client.pubsub(ignore_subscribe_messages=True)
    pubsub.subscribe(BAN_CHANNEL)
    now = time.monotonic()
    next_sync = now + args.reconcile_interval
    next_publish = now + args.publish_interval
    end = now + args.duration if args.duration > 0 else None
    last_error = 0.0

    def report_error(where: str, exc: Exception) -> None:
        nonlocal last_error
        now_err = time.monotonic()
        if now_err - last_error >= 5:
            last_error = now_err
            _emit({"xdp": "redis_unavailable", "where": where,
                   "error": str(exc), "run_id": args.run_id})

    try:
        try:
            sync("startup")
            reporter.publish(installed=reconciler.installed, seen=seen)
        except Exception as exc:
            report_error("startup", exc)
        while running and (end is None or time.monotonic() < end):
            reason = None
            try:
                message = pubsub.get_message(timeout=0.25)
                if message is not None:
                    reason = "pubsub"
            except Exception as exc:
                report_error("pubsub", exc)
                try:
                    pubsub.close()
                except Exception:
                    pass
                time.sleep(0.5)
                pubsub = client.pubsub(ignore_subscribe_messages=True)
                pubsub.subscribe(BAN_CHANNEL)
                continue
            if reason is not None or time.monotonic() >= next_sync:
                try:
                    sync(reason or "periodic")
                except Exception as exc:
                    report_error("reconcile", exc)
                next_sync = time.monotonic() + args.reconcile_interval
            if time.monotonic() >= next_publish:
                try:
                    reporter.publish(
                        installed=reconciler.installed, seen=seen)
                except Exception as exc:
                    report_error("publish", exc)
                next_publish = time.monotonic() + args.publish_interval
    finally:
        try:
            reporter.publish(installed=reconciler.installed, seen=seen)
        except Exception:
            pass
        try:
            pubsub.close()
        except Exception:
            pass
        try:
            BPF.remove_xdp(iface, flags)
        except Exception as exc:
            _emit({"xdp": "detach_error", "iface": iface, "error": str(exc)})
        if has_xdp(iface):
            subprocess.run(["ip", "link", "set", "dev", iface, "xdp", "off"],
                           check=False, capture_output=True)
        _emit({"xdp": "stopped", "iface": iface, "mode": mode,
               "detached": not has_xdp(iface), "run_id": args.run_id})


if __name__ == "__main__":
    main()
