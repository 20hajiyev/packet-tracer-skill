"""A home router's sockets are named, not numbered, and the names differ by model.

`port_exists` checked only the trailing index, so `FastEthernet0/1` passed on a
device whose sockets are `Ethernet 1` .. `4`. Right index, wrong name -- and
Packet Tracer refuses to open a lab that names an interface a device does not
have. The permissive fall-through was just as wrong in the other direction:
`Ethernet 99` passed on a router with four LAN ports, because a device that
lists no interfaces in its configuration is given the benefit of the doubt.

Tightening the check alone would have made the repair pass drop those cables,
since every name it probes is slotted and a home router has no slotted ports.
So the repair reads the same list. Both halves are tested here together.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_pkt import _repair_invalid_link_ports  # noqa: E402
from pkt_transformer import port_exists, wireless_router_port_names  # noqa: E402

# Measured on the saved labs: five copper ports on both models, the fifth being
# the uplink, and the older model's copper reports FastEthernet while its
# sockets are still named plain `Ethernet`.
COPPER = {"WirelessRouter": "eCopperFastEthernet", "WirelessRouterNewGeneration": "eCopperGigabitEthernet"}


def _home_router(name: str, engine_type: str, copper_ports: int = 5) -> ET.Element:
    device = ET.fromstring(
        "<DEVICE><ENGINE><TYPE/><NAME/><SAVE_REF_ID/><RUNNINGCONFIG/></ENGINE></DEVICE>"
    )
    device.find("./ENGINE/TYPE").text = engine_type
    device.find("./ENGINE/NAME").text = name
    device.find("./ENGINE/SAVE_REF_ID").text = f"ref-{name}"
    for _ in range(copper_ports):
        ET.SubElement(ET.SubElement(device, "PORT"), "TYPE").text = COPPER[engine_type]
    ET.SubElement(ET.SubElement(device, "PORT"), "TYPE").text = "eAccessPointWirelessN"
    return device


def _switch(name: str, ports: int = 4) -> ET.Element:
    device = ET.fromstring(
        "<DEVICE><ENGINE><TYPE>Switch</TYPE><NAME/><SAVE_REF_ID/><RUNNINGCONFIG/></ENGINE></DEVICE>"
    )
    device.find("./ENGINE/NAME").text = name
    device.find("./ENGINE/SAVE_REF_ID").text = f"ref-{name}"
    config = device.find("./ENGINE/RUNNINGCONFIG")
    for index in range(1, ports + 1):
        ET.SubElement(config, "LINE").text = f"interface FastEthernet0/{index}"
        ET.SubElement(config, "LINE").text = "!"
        ET.SubElement(ET.SubElement(device, "PORT"), "TYPE").text = "eCopperFastEthernet"
    return device


def _lab(devices: list[ET.Element], cables: list[tuple[str, str, str, str]]) -> ET.Element:
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


def _ports_on(root: ET.Element, ref: str) -> list[str]:
    found = []
    for cable in root.findall(".//LINKS/LINK/CABLE"):
        refs = [(cable.findtext("FROM") or ""), (cable.findtext("TO") or "")]
        for side, node in zip(refs, cable.findall("PORT")):
            if side == f"ref-{ref}":
                found.append(node.text or "")
    return found


@pytest.mark.parametrize(
    "engine_type,lan,other",
    [
        ("WirelessRouter", "Ethernet 1", "GigabitEthernet 1"),
        ("WirelessRouterNewGeneration", "GigabitEthernet 1", "Ethernet 1"),
    ],
)
def test_each_model_answers_to_its_own_names_and_no_others(engine_type: str, lan: str, other: str) -> None:
    device = _home_router("WR1", engine_type)
    assert port_exists(device, lan)
    assert port_exists(device, "Internet")
    assert not port_exists(device, other), "the other model's spelling is not this model's socket"


@pytest.mark.parametrize("engine_type", sorted(COPPER))
def test_the_fifth_copper_port_is_the_uplink_not_a_fifth_lan_port(engine_type: str) -> None:
    """Five sockets, four LAN ports. Counting them all put a cable on one that is not there."""
    device = _home_router("WR1", engine_type)
    names = wireless_router_port_names(device)
    prefix = names[0].rsplit(" ", 1)[0]
    lan = [name for name in names if name.startswith(prefix)]
    assert len(lan) == 4, f"five copper sockets, four LAN ports: {names}"
    assert "Internet" in names
    assert not port_exists(device, f"{prefix} 5")


@pytest.mark.parametrize("engine_type", sorted(COPPER))
def test_an_index_that_is_in_range_is_still_wrong_under_the_wrong_name(engine_type: str) -> None:
    device = _home_router("WR1", engine_type)
    assert not port_exists(device, "FastEthernet0/1")
    assert not port_exists(device, "GigabitEthernet0/1")


@pytest.mark.parametrize("engine_type", sorted(COPPER))
def test_a_name_past_the_last_lan_port_is_refused(engine_type: str) -> None:
    """The permissive branch used to wave these through for want of a config."""
    device = _home_router("WR1", engine_type)
    prefix = wireless_router_port_names(device)[0].rsplit(" ", 1)[0]
    assert not port_exists(device, f"{prefix} 99")


@pytest.mark.parametrize(
    "engine_type,expected",
    [("WirelessRouter", "Ethernet 1"), ("WirelessRouterNewGeneration", "GigabitEthernet 1")],
)
def test_a_wrongly_named_cable_is_renamed_rather_than_removed(engine_type: str, expected: str) -> None:
    """The half that makes tightening safe: the repair must have a name to offer."""
    root = _lab(
        [_home_router("WR1", engine_type), _switch("SW1")],
        [("WR1", "FastEthernet0/1", "SW1", "FastEthernet0/1")],
    )
    repairs = _repair_invalid_link_ports(root)
    assert repairs, "a nonexistent interface should have been repaired"
    assert len(root.findall(".//LINKS/LINK")) == 1, "the cable was dropped instead of renamed"
    assert _ports_on(root, "WR1") == [expected]


@pytest.mark.parametrize("engine_type", sorted(COPPER))
def test_a_correctly_named_cable_is_left_alone(engine_type: str) -> None:
    good = wireless_router_port_names(_home_router("WR1", engine_type))[0]
    root = _lab(
        [_home_router("WR1", engine_type), _switch("SW1")],
        [("WR1", good, "SW1", "FastEthernet0/1")],
    )
    assert _repair_invalid_link_ports(root) == []
    assert _ports_on(root, "WR1") == [good]


@pytest.mark.parametrize("engine_type", sorted(COPPER))
def test_the_uplink_is_offered_only_once_the_lan_ports_are_taken(engine_type: str) -> None:
    """`Internet` is a WAN socket; a LAN cable should not be sent there while a LAN port is free."""
    router = _home_router("WR1", engine_type)
    lan = [name for name in wireless_router_port_names(router) if name != "Internet"]
    root = _lab(
        [router, _switch("SW1", ports=6)],
        [("WR1", "FastEthernet0/9", "SW1", f"FastEthernet0/{index}") for index in range(1, 3)],
    )
    _repair_invalid_link_ports(root)
    assert _ports_on(root, "WR1") == lan[:2]


@pytest.mark.parametrize("engine_type", sorted(COPPER))
def test_the_radios_are_ports_too(engine_type: str) -> None:
    """Read off the live devices: one radio is bare `Wireless`, several are numbered.

    They are listed so a wireless link is never read as a cable on a port that
    is not there and quietly removed.
    """
    device = _home_router("WR1", engine_type)
    assert port_exists(device, "Wireless")

    many = _home_router("WR2", engine_type)
    radio = many.findall(".//PORT/TYPE")[-1]
    assert radio.text == "eAccessPointWirelessN"
    for _ in range(5):
        ET.SubElement(ET.SubElement(many, "PORT"), "TYPE").text = "eAccessPointWirelessAC"
    assert port_exists(many, "Wireless 6")
    assert not port_exists(many, "Wireless 7")
    assert not port_exists(many, "Wireless"), "numbered radios are not also bare"
