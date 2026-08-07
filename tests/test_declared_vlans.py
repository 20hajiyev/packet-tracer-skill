"""A port assigned to a VLAN the switch never created forwards nothing.

Real IOS creates the VLAN for you. Packet Tracer does not: the VLAN has to be
in the switch's own database, or every port assigned to it stays inactive.

Nothing in the file betrays it. Measured on `corpus_server_lan`: SW1's four
cabled ports -- PC1, PC2, Server1 and the router uplink -- all correctly
`switchport access vlan 20`, all four hosts in 192.168.20.0/24, the lab opening
and Packet Tracer loading every link. PC1 to PC2 was 0/4, PC1 to its gateway
0/4. The switch's configuration contained no `vlan` line at all. Declaring the
two VLANs its ports referenced, and changing nothing else, took both to 4/4.

Which is the fourth step of a lesson this project keeps relearning: passing the
static checks is not opening, opening is not Packet Tracer having loaded what
was written, and that is still not the network working.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_pkt import _declare_referenced_vlans  # noqa: E402

# What SW1 carried when it could not pass a packet, and what its ports asked for.
MEASURED_ASSIGNED_VLANS = ["11", "20"]


def _switch(config_lines: list[str], device_type: str = "Switch") -> ET.Element:
    device = ET.fromstring(
        f"<DEVICE><ENGINE><NAME>SW1</NAME><TYPE>{device_type}</TYPE>"
        "<RUNNINGCONFIG/></ENGINE></DEVICE>"
    )
    config = device.find("./ENGINE/RUNNINGCONFIG")
    assert config is not None
    for line in config_lines:
        ET.SubElement(config, "LINE").text = line
    return device


def _lab(*devices: ET.Element) -> ET.Element:
    root = ET.fromstring("<PACKETTRACER5><NETWORK><DEVICES/></NETWORK></PACKETTRACER5>")
    container = root.find(".//DEVICES")
    assert container is not None
    for device in devices:
        container.append(device)
    return root


def _lines(root: ET.Element) -> list[str]:
    return [node.text or "" for node in root.findall(".//RUNNINGCONFIG/LINE")]


def _access_port(port: str, vlan: str) -> list[str]:
    return [f"interface {port}", " switchport mode access", f" switchport access vlan {vlan}"]


def test_the_vlan_a_port_asks_for_is_created() -> None:
    lab = _lab(_switch(_access_port("FastEthernet0/3", "20")))
    assert _declare_referenced_vlans(lab) == ["SW1: declared VLAN 20"]
    assert "vlan 20" in _lines(lab)


def test_the_server_lan_switch_gets_both_of_its_vlans() -> None:
    """The lab that measured 0/4 before this pass and 4/4 after."""
    lab = _lab(
        _switch(
            _access_port("GigabitEthernet0/1", "20")
            + _access_port("FastEthernet0/2", "20")
            + _access_port("FastEthernet0/9", "11")
        )
    )
    _declare_referenced_vlans(lab)
    declared = [line for line in _lines(lab) if line.startswith("vlan ")]
    assert declared == [f"vlan {vlan}" for vlan in MEASURED_ASSIGNED_VLANS]


def test_a_declaration_goes_in_before_the_ports_that_use_it() -> None:
    lab = _lab(_switch(["hostname SW1"] + _access_port("FastEthernet0/1", "20")))
    _declare_referenced_vlans(lab)
    lines = _lines(lab)
    assert lines.index("vlan 20") < lines.index("interface FastEthernet0/1")
    # And after the global settings that precede any interface.
    assert lines.index("hostname SW1") < lines.index("vlan 20")


def test_a_vlan_already_declared_is_not_declared_twice() -> None:
    lab = _lab(_switch(["vlan 20"] + _access_port("FastEthernet0/1", "20")))
    assert _declare_referenced_vlans(lab) == []
    assert _lines(lab).count("vlan 20") == 1


def test_vlan_one_is_left_alone() -> None:
    """It always exists; declaring it is noise in a configuration a student reads."""
    lab = _lab(_switch(_access_port("FastEthernet0/1", "1")))
    assert _declare_referenced_vlans(lab) == []
    assert "vlan 1" not in _lines(lab)


def test_a_management_interface_needs_its_vlan_too() -> None:
    lab = _lab(_switch(["interface Vlan20", " ip address 192.168.20.100 255.255.255.0"]))
    _declare_referenced_vlans(lab)
    assert "vlan 20" in _lines(lab)


def test_a_voice_vlan_counts_as_a_reference() -> None:
    lab = _lab(_switch(["interface FastEthernet0/1", " switchport voice vlan 150"]))
    _declare_referenced_vlans(lab)
    assert "vlan 150" in _lines(lab)


def test_an_indented_line_is_not_a_declaration() -> None:
    """` vlan 20` inside an interface body creates nothing."""
    lab = _lab(_switch(["interface Vlan20", " vlan 20", " ip address 10.0.0.1 255.255.255.0"]))
    _declare_referenced_vlans(lab)
    assert "vlan 20" in _lines(lab)


def test_a_router_is_not_touched() -> None:
    """Subinterface encapsulation is not a switch VLAN database."""
    router = _switch(
        ["interface GigabitEthernet0/0/1.20", " encapsulation dot1Q 20"], device_type="Router"
    )
    lab = _lab(router)
    assert _declare_referenced_vlans(lab) == []
    assert "vlan 20" not in _lines(lab)


def test_the_saved_configuration_is_declared_as_well() -> None:
    """Two models of one switch that disagree is how this project's defects look."""
    device = _switch(_access_port("FastEthernet0/1", "20"))
    startup = ET.SubElement(device.find("./ENGINE"), "STARTUPCONFIG")
    for line in _access_port("FastEthernet0/1", "20"):
        ET.SubElement(startup, "LINE").text = line
    _declare_referenced_vlans(_lab(device))
    saved = [node.text or "" for node in device.findall("./ENGINE/STARTUPCONFIG/LINE")]
    assert "vlan 20" in saved
