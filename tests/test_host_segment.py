"""Hosts must land in one segment that actually carries traffic.

Every check here comes from a live Packet Tracer session, not from reading the
file. A generated lab passed `structural_check`, opened cleanly and reported
`healthy: true` -- no down links, no duplicate addresses -- while not one host
could reach another. "Opens" is not "works", and neither is "healthy".

Three separate defects hid behind that green result:

* hosts were left as DHCP clients at 0.0.0.0 with no server on the lab;
* a static address written onto a port still marked `PORT_DHCP_ENABLE=true` is
  ignored, so the interface keeps reporting 0.0.0.0;
* the switch inherited the donor's six VLANs, leaving three PCs split across
  VLAN 11, 11 and 20 -- a silent partition that no file-level check can see.

Fixing the first two was not enough, and the first attempt at the third made
things worse: addressing and VLAN were derived independently and disagreed,
putting hosts in 192.168.1.0/24 behind an SVI that only routes 192.168.20.0/24.
Both now come from one place, the donor's routed VLAN interface.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_pkt import _donor_service_segment, _unify_host_segment  # noqa: E402
from intent_parser import parse_intent  # noqa: E402
from pkt_editor import _set_config_block  # noqa: E402


def _donor(*configs: list[str]) -> ET.Element:
    """A donor holding one switch whose config is the given lines."""
    root = ET.Element("PACKETTRACER5")
    devices = ET.SubElement(root, "DEVICES")
    for lines in configs:
        device = ET.SubElement(devices, "DEVICE")
        engine = ET.SubElement(device, "ENGINE")
        ET.SubElement(engine, "NAME").text = "SW1"
        config = ET.SubElement(engine, "RUNNINGCONFIG")
        for line in lines:
            ET.SubElement(config, "LINE").text = line
    return root


def _lab() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    devices = [
        {"name": "R1", "type": "Router"},
        {"name": "SW1", "type": "Switch"},
        {"name": "PC1", "type": "PC"},
        {"name": "PC2", "type": "PC"},
    ]
    links = [
        {"a": {"dev": "PC1", "port": "FastEthernet0"}, "b": {"dev": "SW1", "port": "FastEthernet0/1"}},
        {"a": {"dev": "PC2", "port": "FastEthernet0"}, "b": {"dev": "SW1", "port": "FastEthernet0/2"}},
        {"a": {"dev": "R1", "port": "GigabitEthernet0/0/1"}, "b": {"dev": "SW1", "port": "GigabitEthernet0/1"}},
    ]
    return devices, links


ROUTED_SVI = [
    "interface Vlan1",
    " no ip address",
    " shutdown",
    "interface Vlan20",
    " ip address 192.168.20.100 255.255.255.0",
]


def test_the_segment_comes_from_the_vlan_the_donor_actually_routes() -> None:
    assert _donor_service_segment(_donor(ROUTED_SVI)) == (20, "192.168.20", "192.168.20.100")


def test_a_shut_vlan_interface_is_not_a_segment() -> None:
    """Vlan1 held an address on the measured donor but was down.

    Choosing it put every host on a segment with no gateway.
    """
    donor = _donor(["interface Vlan1", " ip address 10.0.0.1 255.255.255.0", " shutdown"])

    assert _donor_service_segment(donor) is None


def test_hosts_share_one_vlan_and_its_subnet() -> None:
    """The partition and the addressing are fixed by the same decision."""
    plan = parse_intent("1 router 1 switch ve 2 komputer qur")
    devices, links = _lab()

    _unify_host_segment(plan, devices, links, _donor(ROUTED_SVI))

    access = [op for op in plan.switch_ops if op["op"] == "set_access_port"]
    assert {op["port"] for op in access} == {"FastEthernet0/1", "FastEthernet0/2"}
    assert {op["vlan"] for op in access} == {20}

    addresses = [op for op in plan.end_device_ops if op["op"] == "set_host_ip"]
    assert len(addresses) == 2
    assert all(op["ip"].startswith("192.168.20.") for op in addresses)
    assert all(op["gw"] == "192.168.20.1" for op in addresses)
    assert all(op["ip_mode"] == "static" for op in addresses)
    assert len({op["ip"] for op in addresses}) == 2


def test_the_uplink_is_left_alone() -> None:
    """Forcing the router-facing port into an access VLAN cuts the gateway off."""
    plan = parse_intent("1 router 1 switch ve 2 komputer qur")
    devices, links = _lab()

    _unify_host_segment(plan, devices, links, _donor(ROUTED_SVI))

    ports = {op["port"] for op in plan.switch_ops if op["op"] == "set_access_port"}
    assert "GigabitEthernet0/1" not in ports


def test_a_prompt_that_asks_for_vlans_keeps_its_own_layout() -> None:
    """Unifying a deliberately segmented network would defeat the request."""
    plan = parse_intent("2 vlan qur, vlan 10 ve vlan 20, her birinde 2 komputer")
    devices, links = _lab()
    before = list(plan.switch_ops)

    _unify_host_segment(plan, devices, links, _donor(ROUTED_SVI))

    assert plan.switch_ops == before
    assert not [op for op in plan.end_device_ops if op["op"] == "set_host_ip"]


def test_restating_a_setting_replaces_it_instead_of_stacking_a_second_block() -> None:
    """Appending left the donor's value in place, and the donor's value won.

    The generated lab then carried `access vlan 11` and `access vlan 20` for the
    same port. It opened, and the host stayed on the donor's VLAN.
    """
    config = ET.Element("RUNNINGCONFIG")
    for line in (
        "interface FastEthernet0/1",
        " switchport access vlan 11",
        " switchport mode access",
        "interface FastEthernet0/2",
        " switchport access vlan 11",
    ):
        ET.SubElement(config, "LINE").text = line

    _set_config_block(
        config,
        "interface FastEthernet0/1",
        [" switchport mode access", " switchport access vlan 20"],
    )

    lines = [line.text for line in config.findall("LINE")]
    assert lines.count("interface FastEthernet0/1") == 1
    assert " switchport access vlan 11" in lines  # Fa0/2 untouched
    assert lines[:3] == [
        "interface FastEthernet0/1",
        " switchport access vlan 20",
        " switchport mode access",
    ]


def test_settings_that_share_a_prefix_stay_separate() -> None:
    """`trunk allowed` and `trunk native` are two settings, not one.

    Keying replacement on the first two words merged them, so writing a trunk
    port dropped its allowed-VLAN list -- a regression the editor's own
    round-trip test caught before this shipped.
    """
    config = ET.Element("RUNNINGCONFIG")
    for line in ("interface FastEthernet0/24", "!"):
        ET.SubElement(config, "LINE").text = line

    _set_config_block(
        config,
        "interface FastEthernet0/24",
        [
            " switchport mode trunk",
            " switchport trunk allowed vlan 10,99",
            " switchport trunk native vlan 99",
        ],
    )

    lines = [line.text for line in config.findall("LINE")]
    assert " switchport trunk allowed vlan 10,99" in lines
    assert " switchport trunk native vlan 99" in lines


def test_a_setting_whose_value_is_a_word_still_replaces_itself() -> None:
    """`switchport mode access` and `... trunk` carry no digits to strip."""
    config = ET.Element("RUNNINGCONFIG")
    for line in ("interface FastEthernet0/24", " switchport mode access"):
        ET.SubElement(config, "LINE").text = line

    _set_config_block(config, "interface FastEthernet0/24", [" switchport mode trunk"])

    lines = [line.text for line in config.findall("LINE")]
    assert " switchport mode access" not in lines
    assert lines.count(" switchport mode trunk") == 1


def test_an_absent_interface_block_is_still_written() -> None:
    config = ET.Element("RUNNINGCONFIG")
    ET.SubElement(config, "LINE").text = "hostname SW1"

    _set_config_block(config, "interface FastEthernet0/9", [" switchport access vlan 20"])

    assert [line.text for line in config.findall("LINE")] == [
        "hostname SW1",
        "interface FastEthernet0/9",
        " switchport access vlan 20",
    ]


def test_a_segmented_lab_addresses_each_vlan_in_its_own_subnet() -> None:
    """VLAN labs emitted VLANs and access ports but no addressing at all.

    Their hosts kept the donor's addresses, so two of four PCs shared
    192.168.20.10 on ports the generator had just moved to VLAN 10.
    """
    from generate_pkt import _address_hosts_per_vlan

    plan = parse_intent("1 router 1 switch 4 komputer vlan 10 ve vlan 20 qur")
    devices = [
        {"name": "SW1", "type": "Switch"},
        *({"name": f"PC{index}", "type": "PC"} for index in range(1, 5)),
    ]
    links = [
        {
            "a": {"dev": f"PC{index}", "port": "FastEthernet0"},
            "b": {"dev": "SW1", "port": f"FastEthernet0/{index}"},
        }
        for index in range(1, 5)
    ]
    for index in range(1, 5):
        plan.switch_ops.append(
            {
                "op": "set_access_port",
                "device": "SW1",
                "port": f"FastEthernet0/{index}",
                "vlan": 10 if index <= 2 else 20,
            }
        )

    _address_hosts_per_vlan(plan, devices, links)

    addressed = {
        op["device"]: (op["ip"], op["gw"])
        for op in plan.end_device_ops
        if op["op"] == "set_host_ip"
    }
    assert addressed["PC1"] == ("192.168.10.10", "192.168.10.1")
    assert addressed["PC2"] == ("192.168.10.11", "192.168.10.1")
    assert addressed["PC3"] == ("192.168.20.10", "192.168.20.1")
    assert len({ip for ip, _ in addressed.values()}) == 4


def test_a_prompt_asking_for_dhcp_is_left_to_its_pool() -> None:
    """A static address would race the lease the prompt asked for."""
    from generate_pkt import _address_hosts_per_vlan

    plan = parse_intent("1 router 1 switch 4 komputer vlan 10 ve vlan 20 qur")
    plan.router_ops.append({"op": "set_router_dhcp_pool", "device": "R1"})
    plan.switch_ops.append(
        {"op": "set_access_port", "device": "SW1", "port": "FastEthernet0/1", "vlan": 10}
    )

    _address_hosts_per_vlan(
        plan,
        [{"name": "PC1", "type": "PC"}, {"name": "SW1", "type": "Switch"}],
        [{"a": {"dev": "PC1", "port": "FastEthernet0"}, "b": {"dev": "SW1", "port": "FastEthernet0/1"}}],
    )

    assert not [op for op in plan.end_device_ops if op["op"] == "set_host_ip"]


def test_hosts_are_split_evenly_when_the_prompt_only_lists_vlans() -> None:
    """`4 komputer vlan 10 ve vlan 20` is a list, not "4 hosts in VLAN 10".

    Read literally it gave {10: 4}, which suppressed the even split and left
    VLAN 20 with no hosts at all.
    """
    plan = parse_intent("1 router 1 switch 4 komputer vlan 10 ve vlan 20 qur")

    assert plan.host_vlan_assignment == {10: 2, 20: 2}


def test_a_genuine_per_vlan_count_still_parses() -> None:
    from intent_parser import _extract_host_vlan_assignment

    assert _extract_host_vlan_assignment("2 komputer vlan 10 ve 3 komputer vlan 20") == {10: 2, 20: 3}
    assert _extract_host_vlan_assignment("4 komputer vlan 10 qur") == {10: 4}


def test_cloned_devices_get_their_own_mac_address() -> None:
    """A clone is a deep copy, and that included the prototype's MAC.

    Three PCs cloned from one donor PC all carried 0060.5C02.3E05, and two
    hosts with the same MAC cannot talk through a switch. Packet Tracer's own
    packet trace showed the mechanism: PC2 answers PC1's ARP request, the switch
    reports "The old entry in the MAC table is on a different port than the
    receiving port", moves the entry, then drops the reply "because outgoing
    port and incoming port are the same".

    Nothing static could catch it. The file opened, pt_health_check reported
    healthy, no IP was duplicated, and every host reached its gateway -- the
    gateway has a MAC of its own. Only host-to-host traffic died.
    """
    from generate_pkt import _assign_unique_macs

    root = ET.Element("PACKETTRACER5")
    devices = ET.SubElement(root, "DEVICES")
    for name in ("PC1", "PC2", "PC3"):
        device = ET.SubElement(devices, "DEVICE")
        engine = ET.SubElement(device, "ENGINE")
        ET.SubElement(engine, "NAME").text = name
        port = ET.SubElement(engine, "PORT")
        ET.SubElement(port, "MACADDRESS").text = "0060.5C02.3E05"
        ET.SubElement(port, "BIA").text = "0060.5C02.3E05"

    renamed = _assign_unique_macs(root)

    addresses = [node.text for node in root.iter("MACADDRESS")]
    assert len(set(addresses)) == 3, addresses
    assert addresses[0] == "0060.5C02.3E05"  # the first keeps what it had
    assert all(address.startswith("0060.") for address in addresses)
    assert len(renamed) == 2
    # The burned-in address has to follow, or the two disagree on the device.
    for device in root.findall(".//DEVICES/DEVICE"):
        port = device.find("./ENGINE/PORT")
        assert port.findtext("MACADDRESS") == port.findtext("BIA")


def test_addresses_that_are_already_unique_are_left_alone() -> None:
    from generate_pkt import _assign_unique_macs

    root = ET.Element("PACKETTRACER5")
    devices = ET.SubElement(root, "DEVICES")
    for name, mac in (("PC1", "0060.5C02.3E05"), ("PC2", "0090.0C87.7BE8")):
        device = ET.SubElement(devices, "DEVICE")
        engine = ET.SubElement(device, "ENGINE")
        ET.SubElement(engine, "NAME").text = name
        port = ET.SubElement(engine, "PORT")
        ET.SubElement(port, "MACADDRESS").text = mac

    assert _assign_unique_macs(root) == []
    assert [node.text for node in root.iter("MACADDRESS")] == ["0060.5C02.3E05", "0090.0C87.7BE8"]


def test_new_global_configuration_lands_before_end() -> None:
    """Everything after `end` is ignored, and that is where it used to go.

    Measured live: a generated lab carried `ip dhcp pool LAN` after `end`, and
    its hosts sat on APIPA addresses because the router had no pool at all. The
    file looked configured; the device was not.

    Interface settings were never affected -- those are written into a block
    that already exists, ahead of `end` -- which is why the fault looked
    intermittent rather than total.
    """
    from pkt_editor import _splice_into_config

    existing = ["hostname R1", "!", "line vty 0 4", " login", "!", "end"]

    spliced = _splice_into_config(existing, ["ip dhcp pool LAN", " network 192.168.1.0 255.255.255.0"])

    assert spliced[-1] == "end"
    assert spliced.index("ip dhcp pool LAN") < spliced.index("end")
    assert spliced[:5] == existing[:5]


def test_a_config_without_end_still_receives_the_lines() -> None:
    from pkt_editor import _splice_into_config

    assert _splice_into_config(["hostname R1"], ["ip routing"]) == ["hostname R1", "ip routing"]


def test_splicing_nothing_changes_nothing() -> None:
    from pkt_editor import _splice_into_config

    existing = ["hostname R1", "end"]
    assert _splice_into_config(existing, []) == existing


def test_only_the_last_end_is_treated_as_the_terminator() -> None:
    """`end` can appear inside a banner; the real one is the last."""
    from pkt_editor import _splice_into_config

    existing = ["banner motd ^", "the end", "^", "end"]

    spliced = _splice_into_config(existing, ["ip routing"])

    assert spliced == ["banner motd ^", "the end", "^", "ip routing", "end"]


def test_an_empty_startup_config_is_left_empty() -> None:
    """Writing into it produced a router whose saved config was three lines.

    A donor can ship a device with no startup config -- Cisco's own labs do,
    including the DHCP ones -- and appending to it left the router's startup
    config holding nothing but the DHCP pool that had just been added. A reload
    would have come back with no interfaces at all. Leaving it as the donor had
    it matches every real lab measured.
    """
    from pkt_editor import _config_targets

    device = ET.Element("DEVICE")
    engine = ET.SubElement(device, "ENGINE")
    running = ET.SubElement(engine, "RUNNINGCONFIG")
    ET.SubElement(running, "LINE").text = "hostname R1"
    ET.SubElement(engine, "STARTUPCONFIG")  # present but empty

    targets = _config_targets(device)

    assert targets == [running]


def test_a_startup_config_with_content_is_still_written() -> None:
    from pkt_editor import _config_targets

    device = ET.Element("DEVICE")
    engine = ET.SubElement(device, "ENGINE")
    running = ET.SubElement(engine, "RUNNINGCONFIG")
    ET.SubElement(running, "LINE").text = "hostname R1"
    startup = ET.SubElement(engine, "STARTUPCONFIG")
    ET.SubElement(startup, "LINE").text = "hostname R1"

    assert _config_targets(device) == [running, startup]


def test_global_configuration_lands_ahead_of_the_interfaces() -> None:
    """Cisco writes global config near the top, before any interface block.

    Splicing merely before `end` put it after `line vty 0 4 / login`, which is
    not where any real config keeps it.
    """
    from pkt_editor import _splice_into_config

    existing = ["hostname R1", "!", "interface GigabitEthernet0/0/0", " ip address 10.0.0.1 255.255.255.0", "!", "line vty 0 4", " login", "end"]

    spliced = _splice_into_config(existing, ["ip dhcp pool LAN"])

    assert spliced.index("ip dhcp pool LAN") < spliced.index("interface GigabitEthernet0/0/0")
