"""Service operations must actually be emitted, not merely supported.

`pkt_editor` could already apply every one of these -- `set_router_dhcp_pool`,
`enable_server_service`, `set_management_vlan`, `enable_telnet`. Nothing emitted
them, because the only code that built them returned early whenever the prompt
named no VLAN. The labs opened anyway, so the gap was invisible.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

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


def test_wireless_config_is_on_by_default_because_it_was_measured(monkeypatch) -> None:
    """The last unmeasured entries on the blocked list.

    Until the donor pool was widened there was no wireless donor to test them
    against. Two labs generated with them allowed opened in Packet Tracer: a
    home network with a named WPA2 network and two laptops, and one with three
    laptops, two tablets and an explicit channel.
    """
    from generate_pkt import _allowed_mutations, _wireless_config_enabled

    monkeypatch.delenv("PACKET_TRACER_WIRELESS_CONFIG", raising=False)
    assert _wireless_config_enabled()
    allowed = _allowed_mutations()
    assert "wireless_mutation" in allowed
    assert "wireless_client_association" in allowed

    monkeypatch.setenv("PACKET_TRACER_WIRELESS_CONFIG", "0")
    assert "wireless_mutation" not in _allowed_mutations()


def test_a_named_network_reaches_the_access_point_and_its_clients() -> None:
    """`_extract_wireless_ops` only reads `set AP1 ssid TEST security ...`.

    Nobody writes prompts that way, so an ordinary Azerbaijani sentence produced
    a wireless lab still carrying the donor's own network name.
    """
    from generate_pkt import _synthesize_wireless_ops

    plan = parse_intent("1 wireless router 2 laptop qur ssid EvSebeke wpa2 sifre Gizli123")
    devices = [
        {"name": "WRT1", "type": "WirelessRouter"},
        {"name": "Laptop1", "type": "Laptop"},
        {"name": "Laptop2", "type": "Laptop"},
    ]

    _synthesize_wireless_ops(plan, devices)

    ssid_ops = [op for op in plan.wireless_ops if op["op"] == "set_wireless_ssid"]
    joins = [op for op in plan.wireless_ops if op["op"] == "associate_wireless_client"]

    assert [op["device"] for op in ssid_ops] == ["WRT1"]
    assert ssid_ops[0]["ssid"] == "EvSebeke"
    assert ssid_ops[0]["passphrase"] == "Gizli123"
    assert ssid_ops[0]["auth_type"] == "4"  # wpa2
    assert {op["device"] for op in joins} == {"Laptop1", "Laptop2"}


def test_the_network_name_keeps_the_capitalisation_it_was_given() -> None:
    """Normalisation lowercases everything, but an SSID is user-visible and a
    lowercased passphrase is not even the same secret."""
    plan = parse_intent("1 wireless router 2 laptop qur ssid EvSebeke wpa2 sifre Gizli123")

    assert plan.wireless_settings["ssid"] == "EvSebeke"
    assert plan.wireless_settings["passphrase"] == "Gizli123"


def test_no_wireless_ops_without_a_named_network() -> None:
    """With no SSID there is nothing to apply; the donor's own network stands."""
    from generate_pkt import _synthesize_wireless_ops

    plan = parse_intent("1 wireless router 2 laptop qur")
    _synthesize_wireless_ops(plan, [{"name": "WRT1", "type": "WirelessRouter"}])

    assert plan.wireless_ops == []


def test_ordinary_words_after_ssid_are_not_read_as_a_network_name() -> None:
    assert "ssid" not in parse_intent("1 wireless router qur ssid olsun").wireless_settings


def test_orphaned_donor_images_are_dropped() -> None:
    """A donor's picture bank is inherited whole, however few devices survive.

    A four-device home network came out at 2.8 MB: 3.6 MB of orphaned JPEGs
    against 58 KB of devices. The bank also carries the paths they came from --
    `../../../Users/78-USER/Downloads/...` -- so every generated lab
    republished a stranger's photos and their account name.
    """
    import xml.etree.ElementTree as ET

    from generate_pkt import prune_unused_images

    root = ET.fromstring(
        "<PACKETTRACER5><PIXMAPBANK>"
        "<IMAGE><IMAGE_PATH>/home/someone/holiday.jpg</IMAGE_PATH>"
        "<IMAGE_CONTENT>AAAA</IMAGE_CONTENT></IMAGE>"
        "<IMAGE><IMAGE_PATH>/home/someone/used.jpg</IMAGE_PATH>"
        "<IMAGE_CONTENT>BBBB</IMAGE_CONTENT></IMAGE>"
        "</PIXMAPBANK><DEVICES><DEVICE>"
        "<CUSTOM_IMAGE_LOGICAL>/home/someone/used.jpg</CUSTOM_IMAGE_LOGICAL>"
        "</DEVICE></DEVICES></PACKETTRACER5>"
    )

    removed = prune_unused_images(root)

    remaining = [image.findtext("IMAGE_PATH") for image in root.findall(".//PIXMAPBANK/IMAGE")]
    assert removed == 1
    assert remaining == ["/home/someone/used.jpg"]


def test_a_referenced_image_is_never_dropped() -> None:
    import xml.etree.ElementTree as ET

    from generate_pkt import prune_unused_images

    root = ET.fromstring(
        "<PACKETTRACER5><PIXMAPBANK>"
        "<IMAGE><IMAGE_PATH>bg.png</IMAGE_PATH></IMAGE>"
        "</PIXMAPBANK><WORKSPACE>"
        "<CLUSTER_BG_IMAGE>bg.png</CLUSTER_BG_IMAGE>"
        "</WORKSPACE></PACKETTRACER5>"
    )

    assert prune_unused_images(root) == 0
    assert len(root.findall(".//PIXMAPBANK/IMAGE")) == 1


def test_a_pathless_bank_entry_is_left_alone() -> None:
    """It carries no content either; guessing at its purpose is not worth it."""
    import xml.etree.ElementTree as ET

    from generate_pkt import prune_unused_images

    root = ET.fromstring(
        "<PACKETTRACER5><PIXMAPBANK>"
        "<IMAGE><IMAGE_PATH></IMAGE_PATH><IMAGE_CONTENT></IMAGE_CONTENT></IMAGE>"
        "</PIXMAPBANK></PACKETTRACER5>"
    )

    assert prune_unused_images(root) == 0
    assert len(root.findall(".//PIXMAPBANK/IMAGE")) == 1


def test_a_lab_with_no_picture_bank_is_untouched() -> None:
    import xml.etree.ElementTree as ET

    from generate_pkt import prune_unused_images

    assert prune_unused_images(ET.fromstring("<PACKETTRACER5><DEVICES/></PACKETTRACER5>")) == 0


def test_a_cloned_host_reuses_the_link_the_blueprint_planned() -> None:
    """Clones were wired twice, and the second cable always took the same port.

    The blueprint already plans a connection for every host, with a port of its
    own. The clone path allocated a second one by scanning ports already in the
    blueprint -- which, for a host whose link was in that very list, always
    returned `FastEthernet0/1`. At 100 hosts that put 16 cables on one interface
    and Packet Tracer refused the lab.
    """
    from intent_parser import parse_intent

    from generate_pkt import _build_donor_prune_plan, build_prompt_blueprint

    blueprint, prepared = build_prompt_blueprint(parse_intent("100 komputer 6 switch 1 router qur"))
    adapted, _ = _build_donor_prune_plan(prepared, blueprint)

    clones = [op for op in adapted.edit_operations if op["op"] == "duplicate_host"]
    assert clones, "this topology needs cloned hosts"

    ports = [(str(op["switch"]), str(op["switch_port"])) for op in clones]
    assert len(ports) == len(set(ports)), "two clones were given the same switch port"


def test_no_interface_carries_two_cables_at_scale(tmp_path) -> None:
    """The contract is about the file, not the plan.

    A cloned switch's uplink is emitted after the clone exists and wrote its
    blueprint port straight out, so the core switch could hand the same
    interface to two access switches -- `SW1 FastEthernet0/7` carrying both SW3
    and SW21. The plan is allowed to propose a collision, because
    `_resolve_port_conflicts` reconciles afterwards; what must never happen is a
    saved lab with two cables on one port.
    """
    import subprocess
    import sys as _sys
    from collections import Counter

    from pkt_codec import decode_pkt_auto, parse_pkt_xml

    output = tmp_path / "wide.pkt"
    subprocess.run(
        [_sys.executable, str(ROOT / "scripts" / "generate_pkt.py"),
         "--prompt", "40 komputer 22 switch 1 router qur", "--output", str(output)],
        capture_output=True, text=True, cwd=str(ROOT), timeout=1800,
    )
    if not output.exists():
        pytest.skip("generation needs a local donor lab")

    xml, _container = decode_pkt_auto(output.read_bytes(), verify=False)
    root = parse_pkt_xml(xml)
    names = {
        device.findtext("./ENGINE/SAVE_REF_ID") or "": device.findtext("./ENGINE/NAME")
        for device in root.findall(".//DEVICES/DEVICE")
    }
    used: Counter[tuple[str, str]] = Counter()
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        ends = [names.get(cable.findtext(tag) or "", "") for tag in ("FROM", "TO")]
        ports = [port.text or "" for port in cable.findall("PORT")]
        for name, port in zip(ends, ports):
            if name and port:
                used[(name, port)] += 1

    doubled = [key for key, count in used.items() if count > 1]
    assert not doubled, f"interfaces carrying two cables: {doubled[:3]}"


def _security(prompt: str) -> list[str]:
    from generate_pkt import _synthesize_security_ops

    plan = parse_intent(prompt)
    devices = [
        {"name": "R1", "type": "Router", "model": "ISR4331"},
        {"name": "SW1", "type": "Switch"},
        {"name": "SW2", "type": "Switch"},
    ]
    _synthesize_security_ops(plan, devices)
    return sorted({str(op["op"]) for op in plan.router_ops + plan.switch_ops})


def test_nat_emits_the_acl_it_needs_as_well() -> None:
    """NAT overload without a matching ACL configures nothing."""
    assert _security("1 router 1 switch 4 pc qur nat olsun") == [
        "add_acl_rule",
        "set_acl",
        "set_pat_overload",
    ]


def test_acl_alone_does_not_pull_in_nat() -> None:
    assert _security("2 router 2 switch 6 pc qur acl olsun") == ["add_acl_rule", "set_acl"]


def test_layer_two_hardening_is_emitted() -> None:
    assert _security("2 switch 1 router 4 pc qur stp olsun") == ["set_stp"]
    assert _security("2 switch 1 router 4 pc qur etherchannel lacp olsun") == ["set_etherchannel"]
    assert _security("2 switch 1 router 4 pc qur port security olsun") == ["set_port_security"]


def test_a_plain_topology_gets_no_security_configuration() -> None:
    assert _security("1 router 1 switch 3 pc qur") == []


def _resilience(prompt: str) -> list[str]:
    from generate_pkt import _synthesize_resilience_ops

    plan = parse_intent(prompt)
    devices = [
        {"name": "R1", "type": "Router", "model": "ISR4331"},
        {"name": "R2", "type": "Router", "model": "ISR4331"},
        {"name": "SW1", "type": "Switch"},
    ]
    _synthesize_resilience_ops(plan, devices)
    return sorted({str(op["op"]) for op in plan.router_ops})


def test_plain_ipv6_is_a_capability() -> None:
    """`ipv6` on its own was only a network-style tag, so "ipv6 olsun" reached
    the planner with nothing attached to it."""
    assert "ipv6" in parse_intent("2 router 2 switch 6 pc qur ipv6 olsun").capabilities
    assert "ipv6" in parse_intent("1 router 1 switch 3 pc qur dual stack olsun").capabilities


def test_ipv6_brings_addressing_and_routing_together() -> None:
    assert _resilience("2 router 2 switch 6 pc qur ipv6 olsun") == [
        "enable_ipv6_unicast_routing",
        "set_ipv6_address",
    ]
    assert "set_ospfv3_interface" in _resilience("2 router 2 switch 6 pc qur ipv6 ospfv3 olsun")
    assert "set_ipv6_slaac" in _resilience("2 router 2 switch 6 pc qur ipv6 slaac olsun")


def test_hsrp_carries_a_virtual_address() -> None:
    """Without one the standby group configures nothing, and the missing field
    surfaced as a donor-compatibility failure rather than an operation error."""
    from generate_pkt import _synthesize_resilience_ops

    plan = parse_intent("2 router 2 switch 6 pc qur hsrp olsun")
    _synthesize_resilience_ops(
        plan,
        [
            {"name": "R1", "type": "Router", "model": "ISR4331"},
            {"name": "R2", "type": "Router", "model": "ISR4331"},
        ],
    )

    groups = [op for op in plan.router_ops if op["op"] == "set_hsrp_ipv6"]
    assert len(groups) == 2
    assert all(op["virtual_ipv6"] for op in groups)
    assert {op["priority"] for op in groups} == {110, 90}, "one router must win the election"


def test_hsrp_needs_two_routers_to_mean_anything() -> None:
    from generate_pkt import _synthesize_resilience_ops

    plan = parse_intent("1 router 1 switch 3 pc qur hsrp olsun")
    _synthesize_resilience_ops(plan, [{"name": "R1", "type": "Router", "model": "ISR4331"}])

    assert not [op for op in plan.router_ops if op["op"] == "set_hsrp_ipv6"]


def test_an_hsrp_op_without_an_address_is_skipped_not_raised() -> None:
    import xml.etree.ElementTree as ET

    from pkt_editor import _apply_router_op

    device = ET.fromstring("<DEVICE><ENGINE><NAME>R1</NAME></ENGINE></DEVICE>")
    _apply_router_op(device, {"op": "set_hsrp_ipv6", "group": 1, "interface": "Gi0/0", "priority": 100})


def test_voice_devices_can_be_asked_for() -> None:
    """"4 ip phone qur" parsed the count and dropped it: no alias matched."""
    assert parse_intent("1 router 2 switch 4 ip phone qur").device_counts["IPPhone"] == 4
    assert parse_intent("1 switch 3 kamera qur").device_counts["CCTVCamera"] == 3
    assert parse_intent("1 switch 5 sensor qur").device_counts["Thing"] == 5


def test_telephony_comes_with_directory_numbers() -> None:
    """A telephony service with no directory numbers rings nowhere."""
    from generate_pkt import _synthesize_voice_ops

    plan = parse_intent("1 router 2 switch 4 ip phone qur voip olsun")
    _synthesize_voice_ops(
        plan,
        [
            {"name": "R1", "type": "Router"},
            {"name": "Phone1", "type": "IPPhone"},
            {"name": "Phone2", "type": "IPPhone"},
        ],
    )

    ops = [str(op["op"]) for op in plan.router_ops]
    assert "set_telephony_service" in ops
    assert ops.count("set_ephone_dn") == 2
    assert ops.count("set_ephone") == 2

    numbers = [op["number"] for op in plan.router_ops if op["op"] == "set_ephone_dn"]
    assert numbers == [1001, 1002]


def test_phone_macs_are_stable_across_regeneration() -> None:
    """A random MAC would change the lab on every run for no reason."""
    from generate_pkt import _synthesize_voice_ops

    def macs() -> list[str]:
        plan = parse_intent("1 router 4 ip phone qur voip olsun")
        _synthesize_voice_ops(plan, [{"name": "R1", "type": "Router"}, {"name": "P1", "type": "IPPhone"}])
        return [str(op["mac"]) for op in plan.router_ops if op["op"] == "set_ephone"]

    assert macs() == macs()


def test_a_prompt_without_voice_gets_no_telephony() -> None:
    from generate_pkt import _synthesize_voice_ops

    plan = parse_intent("1 router 1 switch 3 pc qur")
    _synthesize_voice_ops(plan, [{"name": "R1", "type": "Router"}])

    assert not plan.router_ops


def test_the_wider_service_set_is_reachable() -> None:
    """Only five of the nine services the enable map knows were ever emitted."""
    from generate_pkt import _synthesize_service_ops

    plan = parse_intent("1 router 1 switch 1 server qur syslog ntp olsun")
    _synthesize_service_ops(plan, [{"name": "R1", "type": "Router"}, {"name": "SRV1", "type": "Server"}])

    enabled = {str(op["service"]) for op in plan.server_ops if op["op"] == "enable_server_service"}
    assert {"syslog", "ntp"} <= enabled


def test_an_aaa_server_gets_its_radius_port() -> None:
    from generate_pkt import _synthesize_service_ops

    plan = parse_intent("1 router 1 switch 1 server qur radius aaa olsun")
    _synthesize_service_ops(plan, [{"name": "R1", "type": "Router"}, {"name": "SRV1", "type": "Server"}])

    assert any(op["op"] == "set_server_aaa_auth_port" for op in plan.server_ops)


def test_synthesised_wiring_is_recorded_as_defaulted() -> None:
    """The donor's own wiring must win when the planner picked the ports.

    `_link_wiring_was_defaulted` looked for an assumption that nothing recorded,
    so a prompt naming no ports was treated as demanding exact ones. The donor's
    router uses `GigabitEthernet0/0/1`; the planner had picked `0/0/0`; the link
    was rejected for disagreeing with a choice nobody made. That one mismatch
    refused ntp, syslog, snmp and aaa.
    """
    from generate_pkt import (
        DEFAULTED_LINK_WIRING_ASSUMPTIONS,
        _link_wiring_was_defaulted,
        _synthesize_links,
    )

    plan = parse_intent("1 router 1 switch 1 server qur ntp olsun")
    devices = [
        {"name": "R1", "type": "Router", "model": "ISR4331"},
        {"name": "SW1", "type": "Switch", "model": "2960-24TT"},
        {"name": "Server1", "type": "Server"},
    ]

    assert not _link_wiring_was_defaulted(plan)
    _synthesize_links(plan, devices)

    assert _link_wiring_was_defaulted(plan)
    assert set(DEFAULTED_LINK_WIRING_ASSUMPTIONS) <= set(plan.assumptions_used)


def test_explicit_links_are_not_marked_defaulted() -> None:
    """A user who named ports has a preference the donor must not override."""
    from generate_pkt import _link_wiring_was_defaulted, _synthesize_links

    plan = parse_intent("1 router 1 switch 3 pc qur")
    plan.links = [{"a": {"dev": "PC1", "port": "FastEthernet0"}, "b": {"dev": "SW1", "port": "FastEthernet0/9"}}]

    _synthesize_links(plan, [{"name": "SW1", "type": "Switch"}])

    assert not _link_wiring_was_defaulted(plan)


def test_cable_names_from_both_vocabularies_compare_equal() -> None:
    """The donor says `eStraightThrough`, the planner says `straight-through`."""
    from generate_pkt import _same_media

    assert _same_media("eStraightThrough", "straight-through")
    assert _same_media("eCrossOver", "crossover")
    assert _same_media("eSerial", "serial")
    assert not _same_media("eStraightThrough", "eCrossOver")
