"""Three repairs for contradictions the coherence checker found in a real lab.

The lab was 153 devices and it opened cleanly. It also declared one interface
five times, served DHCP for networks nothing routed, gave four routers the
gateway address a fifth was offering as its HSRP virtual, and left nineteen
servers and printers pointing at a gateway no interface answered for.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_pkt import (  # noqa: E402
    _drop_cables_the_plan_did_not_ask_for,
    _drop_config_for_absent_interfaces,
    _drop_vlan_subinterfaces_off_router_links,
    _merge_repeated_interface_blocks,
    _move_static_hosts_onto_their_vlan_network,
)


def _device(name: str, kind: str, config: list[str]) -> ET.Element:
    device = ET.fromstring(
        "<DEVICE><ENGINE><NAME/><TYPE/><SAVE_REF_ID/><RUNNINGCONFIG/></ENGINE></DEVICE>"
    )
    device.find("./ENGINE/NAME").text = name
    device.find("./ENGINE/TYPE").text = kind
    device.find("./ENGINE/SAVE_REF_ID").text = f"ref-{name}"
    lines = device.find("./ENGINE/RUNNINGCONFIG")
    for line in config:
        ET.SubElement(lines, "LINE").text = line
    return device


def _host(name: str, kind: str, address: str, mask: str, gateway: str, dhcp: str = "false") -> ET.Element:
    device = _device(name, kind, [])
    port = ET.SubElement(device, "PORT")
    ET.SubElement(port, "NAME").text = "FastEthernet0"
    ET.SubElement(port, "IP").text = address
    ET.SubElement(port, "SUBNET").text = mask
    ET.SubElement(port, "PORT_DHCP_ENABLE").text = dhcp
    ET.SubElement(device, "GATEWAY").text = gateway
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


def _lines(root: ET.Element, name: str) -> list[str]:
    for device in root.findall(".//DEVICES/DEVICE"):
        if (device.findtext("./ENGINE/NAME") or "") == name:
            return [(node.text or "").strip() for node in device.findall("./ENGINE/RUNNINGCONFIG/LINE")]
    return []


def _address(root: ET.Element, name: str) -> tuple[str, str]:
    for device in root.findall(".//DEVICES/DEVICE"):
        if (device.findtext("./ENGINE/NAME") or "") == name:
            return ((device.findtext(".//PORT/IP") or ""), (device.findtext(".//GATEWAY") or ""))
    return ("", "")


TRUNK = [
    "interface GigabitEthernet0/1.10",
    " description Idare",
    " encapsulation dot1Q 10",
    " ip address 10.10.10.1 255.255.255.0",
    "!",
]

ACCESS = ["interface FastEthernet0/1", " switchport mode access", " switchport access vlan 10", "!"]


def test_five_blocks_become_the_one_the_device_would_end_up_with() -> None:
    config = TRUNK + [
        "interface GigabitEthernet0/1.10",
        " description VLAN10 standby",
        " ip address 10.10.10.3 255.255.255.0",
        " standby 10 ip 10.10.10.1",
        "!",
    ]
    root = _lab([_device("R1", "Router", config)])
    assert _merge_repeated_interface_blocks(root)
    lines = _lines(root, "R1")
    assert lines.count("interface GigabitEthernet0/1.10") == 1
    # IOS keeps the last value of each setting, and one description.
    assert "ip address 10.10.10.3 255.255.255.0" in lines
    assert "ip address 10.10.10.1 255.255.255.0" not in lines
    assert lines.count("description VLAN10 standby") == 1
    assert "description Idare" not in lines
    assert "standby 10 ip 10.10.10.1" in lines
    assert "encapsulation dot1Q 10" in lines


def test_merging_twice_changes_nothing_the_second_time() -> None:
    config = TRUNK + ["interface GigabitEthernet0/1.10", " ip address 10.10.10.3 255.255.255.0", "!"]
    root = _lab([_device("R1", "Router", config)])
    _merge_repeated_interface_blocks(root)
    once = _lines(root, "R1")
    assert not _merge_repeated_interface_blocks(root)
    assert _lines(root, "R1") == once


def test_a_vlan_subinterface_facing_another_router_goes() -> None:
    """It cannot carry the VLAN, and it claims the gateway address anyway."""
    root = _lab(
        [_device("R5", "Router", TRUNK), _device("R6", "Router", [])],
        [("R5", "GigabitEthernet0/1", "R6", "GigabitEthernet0/1")],
    )
    assert _drop_vlan_subinterfaces_off_router_links(root)
    assert "interface GigabitEthernet0/1.10" not in _lines(root, "R5")


def test_a_vlan_subinterface_facing_a_switch_stays() -> None:
    root = _lab(
        [_device("R1", "Router", TRUNK), _device("SW1", "Switch", [])],
        [("R1", "GigabitEthernet0/1", "SW1", "GigabitEthernet0/1")],
    )
    assert _drop_vlan_subinterfaces_off_router_links(root) == []
    assert "interface GigabitEthernet0/1.10" in _lines(root, "R1")


def test_a_static_host_moves_onto_the_network_its_vlan_is_routed_on() -> None:
    """Server6 held 192.168.10.13 in a VLAN routed on 10.10.10.0/24."""
    root = _lab(
        [
            _device("R1", "Router", TRUNK),
            _device("SW1", "Switch", ACCESS),
            _host("Server6", "Server", "192.168.10.13", "255.255.255.0", "192.168.10.1"),
        ],
        [
            ("R1", "GigabitEthernet0/1", "SW1", "GigabitEthernet0/1"),
            ("SW1", "FastEthernet0/1", "Server6", "FastEthernet0"),
        ],
    )
    assert _move_static_hosts_onto_their_vlan_network(root)
    # The host part is kept, so the lab still reads the way it was asked for.
    assert _address(root, "Server6") == ("10.10.10.13", "10.10.10.1")


def test_a_host_already_on_its_vlan_network_is_left_alone() -> None:
    root = _lab(
        [
            _device("R1", "Router", TRUNK),
            _device("SW1", "Switch", ACCESS),
            _host("PC1", "Pc", "10.10.10.20", "255.255.255.0", "10.10.10.1"),
        ],
        [
            ("R1", "GigabitEthernet0/1", "SW1", "GigabitEthernet0/1"),
            ("SW1", "FastEthernet0/1", "PC1", "FastEthernet0"),
        ],
    )
    assert _move_static_hosts_onto_their_vlan_network(root) == []
    assert _address(root, "PC1") == ("10.10.10.20", "10.10.10.1")


def test_a_dhcp_client_is_left_alone() -> None:
    root = _lab(
        [
            _device("R1", "Router", TRUNK),
            _device("SW1", "Switch", ACCESS),
            _host("PC1", "Pc", "192.168.1.5", "255.255.255.0", "192.168.1.1", dhcp="true"),
        ],
        [
            ("R1", "GigabitEthernet0/1", "SW1", "GigabitEthernet0/1"),
            ("SW1", "FastEthernet0/1", "PC1", "FastEthernet0"),
        ],
    )
    assert _move_static_hosts_onto_their_vlan_network(root) == []


def test_a_router_on_an_access_port_is_not_a_host() -> None:
    """The first version rewrote a router WAN address from 200.10.0.2."""
    router = _device("R2", "Router", [])
    port = ET.SubElement(router, "PORT")
    ET.SubElement(port, "NAME").text = "GigabitEthernet0/0"
    ET.SubElement(port, "IP").text = "200.10.0.2"
    ET.SubElement(port, "SUBNET").text = "255.255.255.252"
    root = _lab(
        [_device("R1", "Router", TRUNK), _device("SW1", "Switch", ACCESS), router],
        [
            ("R1", "GigabitEthernet0/1", "SW1", "GigabitEthernet0/1"),
            ("SW1", "FastEthernet0/1", "R2", "GigabitEthernet0/0"),
        ],
    )
    assert _move_static_hosts_onto_their_vlan_network(root) == []
    assert root.findall(".//DEVICES/DEVICE")[2].findtext(".//PORT/IP") == "200.10.0.2"


def _switch_with_ports(name: str, config: list[str], ports: int = 4) -> ET.Element:
    device = _device(name, "Switch", config)
    engine = device.find("./ENGINE")
    slot = ET.SubElement(ET.SubElement(engine, "MODULE"), "SLOT")
    for _ in range(ports):
        socket = ET.SubElement(ET.SubElement(slot, "MODULE"), "PORT")
        ET.SubElement(socket, "TYPE").text = "eCopperFastEthernet"
    return device


def test_a_management_svi_is_not_hardware_and_is_not_deleted() -> None:
    """"management vlan 99 ve telnet olsun" produced a lab with nothing to telnet into.

    `port_exists` says a VLAN interface is not a socket, which is true and is
    the wrong question: an SVI is configuration. Reading it as "the device does
    not have this interface" deleted the management address while leaving VLAN
    99 declared, assigned to ports and allowed on every trunk.
    """
    config = [
        "interface FastEthernet0/1",
        " switchport access vlan 99",
        "!",
        "interface Vlan99",
        " ip address 10.10.99.2 255.255.255.0",
        "!",
    ]
    root = _lab([_switch_with_ports("SW1", config)])
    _drop_config_for_absent_interfaces(root)
    lines = _lines(root, "SW1")
    assert "interface Vlan99" in lines
    assert "ip address 10.10.99.2 255.255.255.0" in lines


def test_configuration_for_hardware_that_really_is_absent_still_goes() -> None:
    root = _lab([_switch_with_ports("SW1", ["interface GigabitEthernet9/9", " shutdown", "!"])])
    assert _drop_config_for_absent_interfaces(root)
    assert "interface GigabitEthernet9/9" not in _lines(root, "SW1")


def test_a_host_keeps_the_cable_the_plan_chose() -> None:
    """A device held back for a planned name brings its donor cabling with it."""
    root = _lab(
        [_device("SW1", "Switch", []), _device("SW2", "Switch", []), _device("PC3", "Pc", [])],
        [
            ("SW1", "FastEthernet0/3", "PC3", "FastEthernet0"),
            ("PC3", "FastEthernet0", "SW2", "FastEthernet0/7"),
        ],
    )
    blueprint = {"links": [{"a": {"dev": "PC3", "port": "FastEthernet0"}, "b": {"dev": "SW2", "port": "FastEthernet0/7"}}]}
    assert _drop_cables_the_plan_did_not_ask_for(root, blueprint)
    remaining = [
        (cable.findtext("FROM"), cable.findtext("TO"))
        for cable in root.findall(".//LINKS/LINK/CABLE")
    ]
    assert remaining == [("ref-PC3", "ref-SW2")], remaining


def test_a_host_with_one_cable_is_left_alone() -> None:
    root = _lab(
        [_device("SW1", "Switch", []), _device("PC1", "Pc", [])],
        [("SW1", "FastEthernet0/1", "PC1", "FastEthernet0")],
    )
    assert _drop_cables_the_plan_did_not_ask_for(root, {"links": []}) == []
    assert len(root.findall(".//LINKS/LINK")) == 1


def test_a_lab_with_no_vlans_still_puts_hosts_on_the_router_segment() -> None:
    """Six workstations, three address plans, and one router interface."""
    router = _device("R1", "Router", ["interface GigabitEthernet0/0", " ip address 192.168.3.254 255.255.255.0", "!"])
    switch = _device("SW1", "Switch", ["interface FastEthernet0/1", " switchport access vlan 1", "!"])
    host = _host("PC1", "Pc", "192.168.1.20", "255.255.255.0", "192.168.1.1")
    root = _lab(
        [router, switch, host],
        [
            ("R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1"),
            ("SW1", "FastEthernet0/1", "PC1", "FastEthernet0"),
        ],
    )
    assert _move_static_hosts_onto_their_vlan_network(root)
    assert _address(root, "PC1") == ("192.168.3.20", "192.168.3.254")
