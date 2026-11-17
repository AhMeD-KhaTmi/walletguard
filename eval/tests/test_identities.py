from eval import identities


def test_identity_plan_is_internally_consistent():
    data = identities.load()
    assert len(identities.benign_ips(data)) == 5
    assert len(identities.attack_ips(data, "credential_stuffing")) == 3
    assert len(identities.attack_ips(data, "scraping")) == 3
    assert len(identities.attack_ips(data, "dow")) == 3
    assert len(identities.probe_ips(data)) == 1
    assert identities.management_ips(data) == {"127.0.0.1", "10.20.0.1"}


def test_mixed_workload_covers_benign_and_every_attack_pool():
    data = identities.load()
    entries = identities.identities_for(data, "mixed")
    assert len(entries) == 14
    roles = [entry["role"] for entry in entries]
    assert roles.count("benign") == 5
    assert {"credential_stuffing", "scraping", "dow"} <= set(roles)
    ips = [entry["ip"] for entry in entries]
    assert len(ips) == len(set(ips))


def test_combined_workload_is_attack_only():
    data = identities.load()
    entries = identities.identities_for(data, "combined")
    assert len(entries) == 9
    assert all(entry["role"] != "benign" for entry in entries)


def test_attacker_account_is_not_in_the_benign_pool():
    data = identities.load()
    pool = {account for entry in data["benign"] for account in entry["accounts"]}
    assert data["attacker_account"] == "user50"
    assert "user50" not in pool
    assert len(pool) == 49


def test_duplicate_address_is_rejected():
    data = identities.load()
    data["benign"][1]["ip"] = data["benign"][0]["ip"]
    try:
        identities.validate(data)
    except identities.IdentityError as exc:
        assert "duplicate address" in str(exc)
    else:
        raise AssertionError("duplicate address accepted")


def test_attacker_account_in_benign_pool_is_rejected():
    data = identities.load()
    data["benign"][0]["accounts"].append(data["attacker_account"])
    try:
        identities.validate(data)
    except identities.IdentityError as exc:
        assert "attacker account" in str(exc)
    else:
        raise AssertionError("reserved account accepted in benign pool")


def test_measured_addresses_may_never_be_allowlisted():
    data = identities.load()
    identities.assert_allowlist_safe(data, {"127.0.0.1"})
    try:
        identities.assert_allowlist_safe(data, {"127.0.0.1", "10.20.0.19"})
    except identities.IdentityError as exc:
        assert "10.20.0.19" in str(exc)
    else:
        raise AssertionError("benign/attacker address allowed on the allowlist")


def test_unknown_workload_is_rejected():
    data = identities.load()
    for bad in ("dos", "benign "):
        try:
            identities.identities_for(data, bad)
        except identities.IdentityError:
            continue
        raise AssertionError(f"unknown workload {bad!r} accepted")
