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
