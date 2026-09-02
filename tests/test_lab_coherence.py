"""The checker has to find the contradictions that actually cost us a network.

Each case below is a defect that was measured in a generated lab, opened
cleanly in Packet Tracer, passed every static check, and left something unable
to reach anything.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from lab_coherence import check_lab_coherence, summarise  # noqa: E402


def _device(name: str, kind: str, config: list[str], ports: list[tuple[str, str, str]] | None = None) -> ET.Element:
    device = ET.fromstring(
        "<DEVICE><ENGINE><NAME/><TYPE/><SAVE_REF_ID/><RUNNINGCONFIG/></ENGINE></DEVICE>"
    )
    device.find("./ENGINE/NAME").text = name
    device.find("./ENGINE/TYPE").text = kind
    device.find("./ENGINE/SAVE_REF_ID").text = f"ref-{name}"
    lines = device.find("./ENGINE/RUNNINGCONFIG")
    for line in config:
        ET.SubElement(lines, "LINE").text = line
    for port_name, address, mask in ports or []:
        port = ET.SubElement(device, "PORT")
        ET.SubElement(port, "NAME").text = port_name
        ET.SubElement(port, "IP").text = address
        ET.SubElement(port, "SUBNET").text = mask
    return device


def _lab(devices: list[ET.Element], cables: list[tuple[str, str, str, str]] = ()) -> ET.Element:
    root = ET.fromstring("<PACKETTRACER5><NETWORK><DEVICES/><LINKS/></NETWORK></PACKETTRACER5>")
    for device in devices:
        root.find(".//DEVICES").append(device)
    links = root.find(".//LINKS")
    for left, left_port, right, right_port in cables:
        cable = ET.SubElement(ET.SubElement(links, "LINK"), "CABLE")
        ET.SubElement(cable, "FROM").text = f"ref-{left}"
        ET.SubElement(cable, "PORT").text = left_port
        ET.SubElement(cable, "TO").text = f"ref-{right}"
        ET.SubElement(cable, "PORT").text = right_port
    return root


def _kinds(root: ET.Element) -> set[str]:
    return {finding.kind for finding in check_lab_coherence(root)}


def _host(name: str, address: str, gateway: str, mask: str = "255.255.255.0") -> ET.Element:
    device = _device(name, "Pc", [], [("FastEthernet0", address, mask)])
    ET.SubElement(device, "GATEWAY").text = gateway
    return device


ROUTER = ["interface GigabitEthernet0/1.10", " encapsulation dot1Q 10", " ip address 10.10.10.1 255.255.255.0", "!"]


def test_a_coherent_lab_reports_nothing() -> None:
    root = _lab([_device("R1", "Router", ROUTER), _host("PC1", "10.10.10.20", "10.10.10.1")])
    assert check_lab_coherence(root) == []
    assert summarise([]) == "coherent: no contradictions found"


def test_the_gateway_no_interface_answers_for() -> None:
    """82 hosts in the enterprise lab pointed at a 192.168.x.1 nothing held."""
    root = _lab([_device("R1", "Router", ROUTER), _host("PC1", "192.168.10.20", "192.168.10.1")])
    assert "gateway_answers_for_nobody" in _kinds(root)


def test_a_host_addressed_off_its_own_gateway_subnet() -> None:
    """A port in VLAN 200 carrying a 192.168.110.x address, from two plans."""
    root = _lab([_device("R1", "Router", ROUTER), _host("PC1", "192.168.110.12", "10.10.10.1")])
    assert "gateway_off_host_subnet" in _kinds(root)


def test_a_real_address_that_is_also_someone_s_virtual_one() -> None:
    """R4 through R8 each held 10.10.10.1 while R1 offered it as HSRP virtual."""
    spare = ["interface GigabitEthernet0/1.10", " ip address 10.10.10.2 255.255.255.0", " standby 10 ip 10.10.10.1", "!"]
    root = _lab([_device("R1", "Router", ROUTER), _device("R2", "Router", spare)])
    assert "real_address_is_also_virtual" in _kinds(root)


def test_an_interface_declared_more_than_once() -> None:
    """Five builds, five blocks, and IOS keeps the last one."""
    twice = ROUTER + ["interface GigabitEthernet0/1.10", " ip address 10.10.10.9 255.255.255.0", "!"]
    root = _lab([_device("R1", "Router", twice)])
    assert "interface_declared_twice" in _kinds(root)


def test_two_cables_on_one_socket() -> None:
    devices = [_device(name, "Switch", []) for name in ("SW1", "SW2", "SW3")]
    root = _lab(devices, [("SW1", "FastEthernet0/1", "SW2", "FastEthernet0/1"),
                          ("SW1", "FastEthernet0/1", "SW3", "FastEthernet0/1")])
    assert "port_double_booked" in _kinds(root)


def test_a_trunk_whose_ends_name_different_native_vlans() -> None:
    left = ["interface GigabitEthernet0/1", " switchport mode trunk", " switchport trunk native vlan 99", "!"]
    right = ["interface GigabitEthernet0/1", " switchport mode trunk", "!"]
    root = _lab([_device("SW1", "Switch", left), _device("SW2", "Switch", right)],
                [("SW1", "GigabitEthernet0/1", "SW2", "GigabitEthernet0/1")])
    assert "native_vlan_mismatch" in _kinds(root)


def test_a_bundled_port_whose_peer_does_not_bundle() -> None:
    """The line that took SW2 off the network."""
    left = ["interface GigabitEthernet0/1", " switchport mode trunk", " channel-group 1 mode on", "!"]
    right = ["interface GigabitEthernet0/1", " switchport mode trunk", "!"]
    root = _lab([_device("SW1", "Switch", left), _device("SW2", "Switch", right)],
                [("SW1", "GigabitEthernet0/1", "SW2", "GigabitEthernet0/1")])
    assert "etherchannel_peer_does_not_bundle" in _kinds(root)


def test_a_pool_for_a_network_no_interface_serves() -> None:
    config = ROUTER + ["ip dhcp pool VLAN20", " network 192.168.20.0 255.255.255.0", " default-router 192.168.20.1"]
    root = _lab([_device("R1", "Router", config)])
    assert "pool_without_interface" in _kinds(root)


def test_the_summary_counts_each_kind() -> None:
    root = _lab([_device("R1", "Router", ROUTER), _host("PC1", "192.168.10.20", "192.168.10.1")])
    text = summarise(check_lab_coherence(root))
    assert "contradiction(s)" in text and "gateway_answers_for_nobody" in text


def test_a_dhcp_client_is_not_judged_on_the_address_it_is_about_to_replace() -> None:
    """78 of the enterprise lab's 82 "unreachable gateway" hosts were leasing.

    `PORT_DHCP_ENABLE` means Packet Tracer ignores the address and gateway the
    file still carries. Reading them anyway is the same defect the checker
    exists to find, committed by the checker.
    """
    device = _device("PC1", "Pc", [], [("FastEthernet0", "192.168.1.23", "255.255.255.0")])
    device.find("./PORT/IP")  # the stale address stays in the file
    ET.SubElement(device.find("./PORT"), "PORT_DHCP_ENABLE").text = "true"
    ET.SubElement(device, "GATEWAY").text = "192.168.1.1"
    root = _lab([_device("R1", "Router", ROUTER), device])
    assert check_lab_coherence(root) == []


def test_a_static_host_pointing_at_nothing_is_still_reported() -> None:
    device = _device("PC1", "Pc", [], [("FastEthernet0", "192.168.1.23", "255.255.255.0")])
    ET.SubElement(device.find("./PORT"), "PORT_DHCP_ENABLE").text = "false"
    ET.SubElement(device, "GATEWAY").text = "192.168.1.1"
    root = _lab([_device("R1", "Router", ROUTER), device])
    assert "gateway_answers_for_nobody" in _kinds(root)
