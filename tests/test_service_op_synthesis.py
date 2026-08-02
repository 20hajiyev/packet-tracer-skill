"""Service operations must actually be emitted, not merely supported.

`pkt_editor` could already apply every one of these -- `set_router_dhcp_pool`,
`enable_server_service`, `set_management_vlan`, `enable_telnet`. Nothing emitted
them, because the only code that built them returned early whenever the prompt
named no VLAN. The labs opened anyway, so the gap was invisible.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_pkt import _management_vlan_id, _synthesize_service_ops  # noqa: E402
from intent_parser import IntentPlan, parse_intent  # noqa: E402


def _devices() -> list[dict[str, object]]:
    return [
        {"name": "R1", "type": "Router"},
        {"name": "SW1", "type": "Switch"},
        {"name": "SW2", "type": "Switch"},
        {"name": "PC1", "type": "PC"},
        {"name": "SRV1", "type": "Server"},
    ]


def test_flat_network_gets_a_dhcp_pool() -> None:
    """The VLAN path covers segmented networks; this is the case it missed."""
    plan = parse_intent("1 router 1 switch 3 komputer qur dhcp routerden verilsin")

    _synthesize_service_ops(plan, _devices())

    pools = [op for op in plan.router_ops if op["op"] == "set_router_dhcp_pool"]
    assert len(pools) == 1
    assert pools[0]["device"] == "R1"
    assert pools[0]["gateway"] == "192.168.1.1"


def test_vlan_prompts_keep_their_per_vlan_pools() -> None:
    """No second pool on top of the ones the VLAN path already emits."""
    plan = IntentPlan(goal="generate", prompt="test")
    plan.vlan_ids = [10, 20]
    plan.topology_requirements = {"needs_dhcp_pool": True}

    _synthesize_service_ops(plan, _devices())

    assert not [op for op in plan.router_ops if op["op"] == "set_router_dhcp_pool"]


def test_management_vlan_and_telnet_reach_every_switch() -> None:
    plan = parse_intent("2 switch 1 router 4 komputer qur management vlan 99 ve telnet olsun")

    _synthesize_service_ops(plan, _devices())

    svi = [op for op in plan.management_ops if op["op"] == "set_management_vlan"]
    telnet = [op for op in plan.management_ops if op["op"] == "enable_telnet"]

    assert {op["device"] for op in svi} == {"SW1", "SW2"}
    assert all(op["vlan"] == 99 for op in svi)
    # Telnet belongs on the router too -- it is reached over the same network.
    assert {op["device"] for op in telnet} == {"SW1", "SW2", "R1"}


def test_management_vlan_does_not_steal_a_data_vlan() -> None:
    plan = IntentPlan(goal="generate", prompt="test")
    plan.capabilities = ["management_vlan"]
    plan.vlan_ids = [10, 20, 99]

    assert _management_vlan_id(plan) == 99


def test_no_management_vlan_without_the_capability() -> None:
    plan = IntentPlan(goal="generate", prompt="test")
    plan.vlan_ids = [10, 20]

    assert _management_vlan_id(plan) is None


def test_server_services_are_enabled_and_given_a_record() -> None:
    plan = parse_intent("1 router 1 switch 2 komputer 1 server qur serverde dns ve http olsun")

    _synthesize_service_ops(plan, _devices())

    enabled = {op["service"] for op in plan.server_ops if op["op"] == "enable_server_service"}
    records = [op for op in plan.server_ops if op["op"] == "set_server_dns_record"]

    assert enabled == {"dns", "http"}
    assert records and records[0]["value"] == "192.168.1.10"


def test_service_names_are_lowercase_for_the_editor() -> None:
    """`_set_enabled_service` keys on lowercase names.

    Passing `DNS` raised KeyError from inside donor validation, which surfaced
    as "no ranked donor candidate passed compatibility validation: 'DNS'" and
    pointed at the donor instead of the service name.
    """
    plan = parse_intent("1 router 1 switch 2 komputer 1 server qur serverde dns ve http olsun")

    _synthesize_service_ops(plan, _devices())

    for op in plan.server_ops:
        if op["op"] == "enable_server_service":
            assert op["service"] == str(op["service"]).lower()


def test_unknown_service_is_ignored_rather_than_raising() -> None:
    import xml.etree.ElementTree as ET

    from pkt_editor import _set_enabled_service

    engine = ET.Element("ENGINE")
    _set_enabled_service(engine, "no-such-service")  # must not raise

    assert list(engine) == []


def test_capabilities_are_read_from_configuration_not_file_names() -> None:
    """A lab called `telnet.pkt` counted; a lab that configures telnet did not.

    Every keyword capability is matched against the sample's path, so the local
    campus donor -- nineteen `line vty` blocks, nineteen `interface Vlan` blocks
    -- was credited with nothing, and management prompts were refused as
    "missing critical capability coverage". Reading the running-config took the
    bundled corpus from 5 telnet samples to 230.
    """
    from sample_catalog import config_capability_tags

    switch_config = "\n".join(
        [
            "interface Vlan99",
            " ip address 192.168.99.2 255.255.255.0",
            "ip default-gateway 192.168.99.1",
            "line vty 0 4",
            " transport input telnet",
        ]
    )

    # `interface Vlan99` is also VLAN evidence, which is correct -- the point
    # here is that both management capabilities are found from config alone.
    assert {"telnet", "management_vlan"} <= config_capability_tags(switch_config)


def test_configuration_evidence_is_specific() -> None:
    """Unrelated config must not be credited with capabilities it lacks."""
    from sample_catalog import config_capability_tags

    assert config_capability_tags("hostname R1\ninterface GigabitEthernet0/0") == set()
    assert config_capability_tags("") == set()


def test_host_config_is_on_by_default_because_it_was_measured(monkeypatch) -> None:
    """`end_device_mutation` was blocked with nothing recording why.

    Same shape as `device_prune` and `remove_link`, both of which proved safe
    once tested. Two files generated with host config enabled were opened in
    Packet Tracer -- a flat router-DHCP lab and a three-VLAN lab with a pool per
    VLAN -- and both opened.
    """
    from generate_pkt import _allowed_mutations, _host_config_enabled

    monkeypatch.delenv("PACKET_TRACER_HOST_CONFIG", raising=False)
    assert _host_config_enabled()
    assert "end_device_mutation" in _allowed_mutations()

    monkeypatch.setenv("PACKET_TRACER_HOST_CONFIG", "0")
    assert not _host_config_enabled()
    assert "end_device_mutation" not in _allowed_mutations()


def test_hosts_are_put_on_the_dhcp_pool() -> None:
    """A pool nothing requests an address from is not really DHCP."""
    plan = parse_intent("1 router 1 switch 3 komputer qur dhcp routerden verilsin")

    _synthesize_service_ops(plan, _devices())

    dhcp_hosts = {op["device"] for op in plan.end_device_ops if op["op"] == "set_host_dhcp"}
    assert dhcp_hosts == {"PC1", "SRV1"}


def test_extra_routers_are_planned_rather_than_dropped() -> None:
    """"2 router" produced one router, and the file opened, so nothing complained.

    Routers were matched singularly -- `next(...)` on both the target and donor
    side -- and `standalone_targets` excludes Router by kind, so every router
    past the first belonged to no code path at all.
    """
    from intent_parser import parse_intent

    from generate_pkt import _seed_devices_from_plan

    seeded = _seed_devices_from_plan(parse_intent("2 router 2 switch 4 pc qur"))
    routers = [device for device in seeded if device["type"] == "Router"]

    assert [device["name"] for device in routers] == ["R1", "R2"]


def test_configuration_evidence_covers_the_measured_blind_spots() -> None:
    """Both directions of the filename error were measured over 292 samples.

    36 labs configure RIP and none were credited; 22 configure a static route
    and none were credited; all three `hsrp` credits were filename coincidences.
    """
    from sample_catalog import CONFIG_EVIDENCE_PATTERNS, config_capability_tags

    for capability in ("rip", "static_route", "acl", "nat", "hsrp", "ospf"):
        assert capability in CONFIG_EVIDENCE_PATTERNS

    assert "static_route" in config_capability_tags("ip route 0.0.0.0 0.0.0.0 10.0.0.1")
    assert "hsrp" in config_capability_tags("standby 1 ip 192.168.1.254")
    assert "hsrp" not in config_capability_tags("interface GigabitEthernet0/0")
