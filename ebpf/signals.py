"""Rolling kernel measurements and the Redis Bridge schema-v2 signal writer.

This module does not synthesize observations. Only callers that have attached and
checked a real probe may mark its channel healthy. A lost-event interval must be
marked unhealthy until a complete new observation window has elapsed.
"""

from collections import defaultdict, deque
import ipaddress
import json
import time


IP_FIELDS = {
    "conn_rate_1s": ("accepted", 1),
    "conn_rate_10s": ("accepted", 10),
    "syn_rate_10s": ("syn", 10),
    "failed_conn_10s": ("failed", 10),
    "bytes_in_10s": ("inbound_bytes", 10),
}
HOST_FIELDS = {
    "egress_bytes_llm_60s": ("egress_bytes", 60),
    "egress_conns_llm_60s": ("egress_conn", 60),
    "unexpected_exec_count": ("unexpected_exec", 60),
}
CHANNELS = frozenset({source for source, _ in (*IP_FIELDS.values(), *HOST_FIELDS.values())})


def observed_ipv4(ip: str) -> str:
    """Reject forwarded-header text, arbitrary Redis keys and IPv6 identities."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"not a source IPv4 address: {ip!r}") from exc
    if not isinstance(address, ipaddress.IPv4Address) or address.is_multicast:
        raise ValueError(f"not a source IPv4 address: {ip!r}")
    return str(address)


class RollingSignals:
    def __init__(self):
        self._events = defaultdict(deque)
        self._ip_seen: dict[str, int] = {}

    def add(self, channel: str, *, when_ns: int, value: int = 1, ip: str | None = None):
        if channel not in CHANNELS:
            raise ValueError(f"unknown measured channel: {channel}")
        if type(when_ns) is not int or when_ns < 0 or type(value) is not int or value <= 0:
            raise ValueError("kernel timestamp and positive integral count/bytes required")
        if channel in {name for name, _ in IP_FIELDS.values()}:
            if ip is None:
                raise ValueError("IP measurement requires a kernel-observed source address")
            ip = observed_ipv4(ip)
            self._ip_seen[ip] = max(when_ns, self._ip_seen.get(ip, 0))
        elif ip is not None:
            raise ValueError("host measurement must not be attributed to a client IP")
        self._events[(channel, ip)].append((when_ns, value))

    def active_ips(self, now_ns: int) -> list[str]:
        """Stop refreshing old IP hashes; their 60-second Redis TTL must expire."""
        expired = [ip for ip, stamp in self._ip_seen.items()
                   if stamp <= now_ns - 60_000_000_000]
        for ip in expired:
            del self._ip_seen[ip]
            for channel, _ in IP_FIELDS.values():
                self._events.pop((channel, ip), None)
        return sorted(self._ip_seen)

    def snapshot(self, *, now_ns: int, healthy: set[str], ip: str | None = None) -> dict:
        """Return measured fields only; healthy channels with no events yield real zero."""
        if not healthy <= CHANNELS:
            raise ValueError("unknown probe-health channel")
        fields = IP_FIELDS if ip is not None else HOST_FIELDS
        if ip is not None:
            ip = observed_ipv4(ip)
        result = {}
        for field, (channel, seconds) in fields.items():
            if channel not in healthy:
                continue
            events = self._events[channel, ip]
            cutoff = now_ns - seconds * 1_000_000_000
            # All fields have at most a 60-second window; discard older events.
            while events and events[0][0] <= now_ns - 60_000_000_000:
                events.popleft()
            result[field] = sum(amount for stamp, amount in events if cutoff < stamp <= now_ns)
        return result


def signal_hash(values: dict, *, updated_ms: int) -> dict[str, str]:
    if type(updated_ms) is not int or updated_ms < 0:
        raise ValueError("updated_ms must be an epoch millisecond timestamp")
    allowed = set(IP_FIELDS) if set(values) <= set(IP_FIELDS) else set(HOST_FIELDS)
    if not set(values) <= allowed:
        raise ValueError("mixed or unknown signal fields")
    if any(type(value) is not int or value < 0 for value in values.values()):
        raise ValueError("signal values must be measured nonnegative integers")
    return {
        **{field: str(value) for field, value in values.items()},
        "updated_ms": str(updated_ms),
        "available_fields": json.dumps(sorted(values), separators=(",", ":")),
    }


class SignalPublisher:
    def __init__(self, redis_client, signals: RollingSignals):
        self.redis = redis_client
        self.signals = signals

    def publish(self, *, healthy: set[str], now_ns: int | None = None,
                updated_ms: int | None = None):
        if self.redis.get("p20:meta:schema_version") != "2":
            raise RuntimeError("Redis schema v2 is required before publishing real signals")
        now_ns = time.monotonic_ns() if now_ns is None else now_ns
        updated_ms = int(time.time() * 1000) if updated_ms is None else updated_ms
        snapshots = [(f"p20:sig:ip:{ip}", self.signals.snapshot(
            now_ns=now_ns, healthy=healthy, ip=ip), 60)
                     for ip in self.signals.active_ips(now_ns)]
        snapshots.append(("p20:sig:host", self.signals.snapshot(
            now_ns=now_ns, healthy=healthy), 120))
        for key, values, ttl_s in snapshots:
            # HSET alone retains stale fields after a probe fails. Replace each
            # hash atomically so absence can never be mistaken for a measured zero.
            with self.redis.pipeline(transaction=True) as pipe:
                pipe.delete(key)
                pipe.hset(key, mapping=signal_hash(values, updated_ms=updated_ms))
                pipe.expire(key, ttl_s)
                pipe.execute()
