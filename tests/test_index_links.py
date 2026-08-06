"""Positional link endpoints must follow the devices they point at.

Not every donor gives its devices a `SAVE_REF_ID`. Where they do not, a link
addresses its endpoints by position in the DEVICES list -- so removing a device
silently re-points every cable that referred to a later one.

Measured on `1 router 1 switch 2 komputer 2 ip phone 1 home voip qur`: the
generated lab carried a cable from the switch to the Power Distribution Device,
which has no ports at all. The link had meant PC1. Packet Tracer refused the
file, and nothing static objected: every index was still inside the list, just
pointing one device to the left.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from pkt_editor import _prune_device  # noqa: E402


def _lab(names: list[str], links: list[tuple[int, int]]) -> ET.Element:
    root = ET.Element("PACKETTRACER5")
    network = ET.SubElement(root, "NETWORK")
    devices = ET.SubElement(network, "DEVICES")
    for name in names:
        device = ET.SubElement(devices, "DEVICE")
        engine = ET.SubElement(device, "ENGINE")
        ET.SubElement(engine, "NAME").text = name
        ET.SubElement(engine, "TYPE").text = "Pc"
        workspace = ET.SubElement(device, "WORKSPACE")
        logical = ET.SubElement(workspace, "LOGICAL")
        ET.SubElement(logical, "X").text = "10"
        ET.SubElement(logical, "Y").text = "10"
    link_parent = ET.SubElement(network, "LINKS")
    for left, right in links:
        link = ET.SubElement(link_parent, "LINK")
        cable = ET.SubElement(link, "CABLE")
        ET.SubElement(cable, "FROM").text = str(left)
        ET.SubElement(cable, "TO").text = str(right)
        ET.SubElement(cable, "PORT").text = "FastEthernet0"
        ET.SubElement(cable, "PORT").text = "FastEthernet0"
    return root


def _endpoints(root: ET.Element) -> list[tuple[str, str]]:
    order = [(device.findtext("./ENGINE/NAME") or "") for device in root.findall(".//DEVICES/DEVICE")]
    pairs: list[tuple[str, str]] = []
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        left = int(cable.findtext("FROM", default="0"))
        right = int(cable.findtext("TO", default="0"))
        pairs.append((order[left], order[right]))
    return pairs


def test_pruning_keeps_positional_links_on_the_same_devices() -> None:
    root = _lab(["SW1", "SPARE", "PC1", "PC2"], [(0, 2), (0, 3)])
    assert _endpoints(root) == [("SW1", "PC1"), ("SW1", "PC2")]

    _prune_device(root, "SPARE")

    assert _endpoints(root) == [("SW1", "PC1"), ("SW1", "PC2")], (
        "removing a device must not slide the cables onto its neighbours"
    )


def test_links_before_the_removed_device_are_untouched() -> None:
    root = _lab(["SW1", "PC1", "SPARE", "PC2"], [(0, 1), (0, 3)])

    _prune_device(root, "SPARE")

    assert _endpoints(root) == [("SW1", "PC1"), ("SW1", "PC2")]


def test_a_links_own_device_going_takes_the_link_with_it() -> None:
    root = _lab(["SW1", "PC1", "PC2"], [(0, 1), (0, 2)])

    _prune_device(root, "PC1")

    assert _endpoints(root) == [("SW1", "PC2")]


def test_the_port_repair_runs_on_positional_links_too() -> None:
    """The repair looked devices up by `SAVE_REF_ID` alone, so on a donor whose
    devices have none it skipped every link and reported no work to do.

    Measured on a sniffer lab: four devices, not one with a save ref, three
    positional links, and a cable sitting on `Port-channel 5` -- a logical
    interface nothing can plug into. The repair walked straight past it and
    Packet Tracer refused the file.
    """
    import xml.etree.ElementTree as ET

    from generate_pkt import _repair_invalid_link_ports

    root = ET.Element("PACKETTRACER5")
    network = ET.SubElement(root, "NETWORK")
    devices = ET.SubElement(network, "DEVICES")
    for name, kind, port_count in (("SW1", "Switch", 24), ("PC1", "Pc", 1)):
        device = ET.SubElement(devices, "DEVICE")
        engine = ET.SubElement(device, "ENGINE")
        ET.SubElement(engine, "NAME").text = name
        ET.SubElement(engine, "TYPE").text = kind
        # Deliberately no SAVE_REF_ID: that is the shape this pass ignored.
        ports = ET.SubElement(device, "PORTS")
        for _ in range(port_count):
            port = ET.SubElement(ports, "PORT")
            ET.SubElement(port, "TYPE").text = "eCopperFastEthernet"

    links = ET.SubElement(network, "LINKS")
    link = ET.SubElement(links, "LINK")
    cable = ET.SubElement(link, "CABLE")
    ET.SubElement(cable, "FROM").text = "0"
    ET.SubElement(cable, "TO").text = "1"
    ET.SubElement(cable, "PORT").text = "Port-channel 5"
    ET.SubElement(cable, "PORT").text = "FastEthernet0"

    repairs = _repair_invalid_link_ports(root)

    assert repairs, "a cable on a logical interface must be repaired, not skipped"
    ports = [(node.text or "") for node in cable.findall("PORT")]
    assert not ports[0].startswith("Port-channel"), ports
