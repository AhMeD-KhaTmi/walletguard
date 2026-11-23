"""Unit checks for the XDP ban reconciliation logic (no BCC or root needed)."""

import json

import pytest

from ebpf.xdp_ban import (
    ban_deadline,
    eligible_bans,
    ip_to_u32,
    plan_reconciliation,
    u32_to_ip,
    valid_ban_ip,
)


def record(ip: str) -> str:
    return json.dumps({
        "ip": ip, "reason": "unit", "source": "waf",
        "ts_ms": 0, "ttl_s": 60,
    })


@pytest.mark.parametrize("ip", ["10.20.0.25", "10.20.0.1", "192.0.2.7",
                                "255.255.255.254"])
def test_address_encoding_roundtrip(ip):
    assert u32_to_ip(ip_to_u32(ip)) == ip


def test_contract_shaped_ban_is_accepted():
    assert valid_ban_ip("p20:ban:10.20.0.25", record("10.20.0.25")) == \
        "10.20.0.25"


@pytest.mark.parametrize("key, raw", [
    ("p20:allowlist", record("10.20.0.25")),          # wrong key namespace
    ("p20:ban:not-an-ip", record("10.20.0.25")),      # invalid key address
    ("p20:ban:2001:db8::1", record("2001:db8::1")),   # IPv6 is not enforced
    ("p20:ban:224.0.0.1", record("224.0.0.1")),       # multicast
    ("p20:ban:0.0.0.0", record("0.0.0.0")),           # unspecified
    ("p20:ban:10.20.0.25", None),                     # expired/empty value
    ("p20:ban:10.20.0.25", "{not json"),
    ("p20:ban:10.20.0.25", "[]"),                     # not an object
    ("p20:ban:10.20.0.25", record("10.20.0.11")),     # key/value mismatch
    ("p20:ban:10.20.0.25", json.dumps({"reason": "x"})),
])
def test_non_contract_or_mismatched_bans_are_ignored(key, raw):
    assert valid_ban_ip(key, raw) is None


def test_allowlist_and_local_addresses_never_enter_the_map():
    records = {
        "p20:ban:10.20.0.25": record("10.20.0.25"),
        "p20:ban:10.20.0.11": record("10.20.0.11"),
        "p20:ban:10.20.0.1": record("10.20.0.1"),
        "p20:ban:bogus": record("10.20.0.25"),
    }
    wanted = eligible_bans(
        records,
        allowlist={"10.20.0.11", "not-an-address"},
        excluded={"10.20.0.1"},
    )
    assert wanted == {"10.20.0.25": "p20:ban:10.20.0.25"}


def test_reconciliation_plan_is_a_symmetric_difference():
    added, removed = plan_reconciliation(
        desired={"10.20.0.25", "10.20.0.26"},
        installed={"10.20.0.11", "10.20.0.26"},
    )
    assert added == ["10.20.0.25"]
    assert removed == ["10.20.0.11"]
    assert plan_reconciliation({"10.20.0.25"}, {"10.20.0.25"}) == ([], [])


def test_reconciliation_rejects_invalid_programming_input():
    with pytest.raises(ValueError):
        plan_reconciliation({"bogus"}, set())


def test_deadline_is_remaining_ttl_on_the_monotonic_clock():
    assert ban_deadline(1_500, 10_000) == 10_000 + 1_500_000_000
    for bad in (0, -1, None, True):
        with pytest.raises(ValueError):
            ban_deadline(bad, 10)


def test_u32_range_is_checked():
    with pytest.raises(ValueError):
        u32_to_ip(-1)
    with pytest.raises(ValueError):
        u32_to_ip(1 << 32)
