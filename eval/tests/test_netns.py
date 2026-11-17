from eval import identities, netns


def _all_entries(data):
    return (data["benign"] + data["probe"]
            + [entry for entries in data["attack"].values() for entry in entries])


def test_apply_covers_every_declared_identity():
    data = identities.load()
    commands = [" ".join(command) for command in netns.apply_commands(data)]
    assert any("link add p20br0 type bridge" in command for command in commands)
    for entry in _all_entries(data):
        assert any(command.endswith(f"ip netns add {entry['ns']}") for command in commands), entry["ns"]
        assert any(entry["ip"] in command for command in commands), entry["ip"]
        assert any(f"exec {entry['ns']} ip route add default via 10.20.0.1" in command
                   for command in commands), entry["ns"]


def test_apply_is_idempotent_by_construction():
    """Every namespace is deleted by cleanup and re-created by apply, never reused."""
    data = identities.load()
    cleanup = [" ".join(command) for command in netns.cleanup_commands(data)]
    apply_cmds = [" ".join(command) for command in netns.apply_commands(data)]
    for entry in _all_entries(data):
        assert f"ip netns del {entry['ns']}" in cleanup
        assert f"ip netns add {entry['ns']}" in apply_cmds
    assert "ip link del p20br0" in cleanup


def test_only_planned_namespaces_are_touched():
    data = identities.load()
    planned = {entry["ns"] for entry in _all_entries(data)}
    touched = set()
    for command in netns.cleanup_commands(data):
        if command[:3] == ["ip", "netns", "del"]:
            touched.add(command[3])
    assert touched == planned


def test_veth_names_fit_the_linux_interface_limit():
    data = identities.load()
    for entry in _all_entries(data):
        host_side, bridge_side = netns.veth_names(entry["ns"])
        assert len(host_side) <= 15
        assert len(bridge_side) <= 15
        assert host_side != bridge_side
