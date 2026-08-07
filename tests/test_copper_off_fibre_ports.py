"""A copper cable in a fibre socket is dropped by Packet Tracer, quietly.

Not refused. The file opens, and the cable is simply not there. Measured on a
three-switch lab: sixteen links in the file, thirteen in the running topology,
and all three missing ones landed on `GigabitEthernet1/0/1` or `1/0/2` of an
IE-9320 -- that switch's only two fibre ports. One was the router uplink, so
nothing could reach the DHCP pool and every host fell back to an APIPA address
while the open check reported `opened` throughout.

Which is worth stating on its own: a lab opening is not the same as Packet
Tracer having loaded the topology that was written.

Reading the media off a port name needs care. Zipping `donor_interface_names`
against the PORT nodes is the obvious approach and it slips: a twenty-eight
port switch returns twenty-nine names, because a configuration also mentions
interfaces the hardware does not have, and every entry after the extra one is
wrong. Grouping the nodes by kind and counting within the kind matches Packet
Tracer's own numbering, verified against the live device listing for an
IE-9320, a 2960-24TT and an ISR4331.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_pkt import _move_copper_cables_off_fibre_ports, _port_is_fiber  # noqa: E402


def _switch(name: str, fibre_first: int, copper: int) -> ET.Element:
    """A switch whose first `fibre_first` gigabit ports are fibre, like an IE-9320."""
    device = ET.fromstring(
        "<DEVICE><ENGINE><NAME/><TYPE>MultiLayerSwitch</TYPE><SAVE_REF_ID/>"
        "<MODULE><SLOT/></MODULE><RUNNINGCONFIG/></ENGINE></DEVICE>"
    )
    device.find("./ENGINE/NAME").text = name
    device.find("./ENGINE/SAVE_REF_ID").text = f"ref-{name}"
    slot = device.find("./ENGINE/MODULE/SLOT")
    config = device.find("./ENGINE/RUNNINGCONFIG")
    for index in range(1, fibre_first + copper + 1):
        module = ET.SubElement(slot, "MODULE")
        port = ET.SubElement(module, "PORT")
        media = "eFiberGigabitEthernet" if index <= fibre_first else "eCopperGigabitEthernet"
        ET.SubElement(port, "TYPE").text = media
        ET.SubElement(config, "LINE").text = f"interface GigabitEthernet1/0/{index}"
    return device


def _lab(cables: list[tuple[str, str, str, str]], link_type: str = "eCopper") -> ET.Element:
    root = ET.fromstring("<PACKETTRACER5><NETWORK><DEVICES/><LINKS/></NETWORK></PACKETTRACER5>")
    devices = root.find(".//DEVICES")
    assert devices is not None
    for name in ("SW1", "SW2"):
        devices.append(_switch(name, fibre_first=2, copper=6))
    links = root.find(".//LINKS")
    assert links is not None
    for left, left_port, right, right_port in cables:
        link = ET.SubElement(links, "LINK")
        ET.SubElement(link, "TYPE").text = link_type
        cable = ET.SubElement(link, "CABLE")
        ET.SubElement(cable, "FROM").text = f"ref-{left}"
        ET.SubElement(cable, "PORT").text = left_port
        ET.SubElement(cable, "TO").text = f"ref-{right}"
        ET.SubElement(cable, "PORT").text = right_port
    return root


def _ports(root: ET.Element) -> list[str]:
    return [node.text or "" for node in root.findall(".//LINKS/LINK/CABLE/PORT")]


def test_the_first_ports_of_this_switch_are_fibre() -> None:
    switch = _switch("SW1", fibre_first=2, copper=6)
    assert _port_is_fiber(switch, "GigabitEthernet1/0/1") is True
    assert _port_is_fiber(switch, "GigabitEthernet1/0/2") is True
    assert _port_is_fiber(switch, "GigabitEthernet1/0/3") is False


def test_a_copper_cable_is_moved_off_a_fibre_socket() -> None:
    lab = _lab([("SW1", "GigabitEthernet1/0/1", "SW2", "GigabitEthernet1/0/5")])
    assert _move_copper_cables_off_fibre_ports(lab)
    moved, kept = _ports(lab)
    assert moved != "GigabitEthernet1/0/1"
    assert _port_is_fiber(lab.findall(".//DEVICES/DEVICE")[0], moved) is False
    # The end that was already fine is left alone.
    assert kept == "GigabitEthernet1/0/5"


def test_a_copper_socket_is_left_alone() -> None:
    lab = _lab([("SW1", "GigabitEthernet1/0/4", "SW2", "GigabitEthernet1/0/5")])
    assert _move_copper_cables_off_fibre_ports(lab) == []


def test_the_replacement_does_not_take_a_port_another_cable_holds() -> None:
    lab = _lab(
        [
            ("SW1", "GigabitEthernet1/0/1", "SW2", "GigabitEthernet1/0/5"),
            ("SW1", "GigabitEthernet1/0/3", "SW2", "GigabitEthernet1/0/6"),
        ]
    )
    _move_copper_cables_off_fibre_ports(lab)
    left_ends = [_ports(lab)[0], _ports(lab)[2]]
    assert len(set(left_ends)) == 2


def test_a_fibre_cable_stays_in_its_fibre_socket() -> None:
    """Only copper is out of place there."""
    lab = _lab([("SW1", "GigabitEthernet1/0/1", "SW2", "GigabitEthernet1/0/1")], link_type="eFiber")
    assert _move_copper_cables_off_fibre_ports(lab) == []
