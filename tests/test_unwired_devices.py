"""A lab whose firewall is unplugged should say so.

`1 router 1 switch 3 komputer ve 1 firewall qur` produces a lab holding an ASA,
Packet Tracer opens it, and the ASA is connected to nothing. A requested patch
panel arrives the same way. The device count is right, the file is valid, and
the thing the prompt asked for does not participate in the network.

Wiring these kinds needs a port name per kind, and the project's rule is that
such names come from real donor cables rather than the device palette. The
measurement says the evidence is not there yet: across 150 labs, ASA cables use
`Ethernet0/0` on a 5505 while the palette reports `GigabitEthernet1/1` for the
5506-X, and patch panels, bridges, repeaters and wired end devices carry no
cable in any of them. So the gap is reported rather than guessed at.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_pkt import _report_unwired_devices  # noqa: E402


def _lab(devices: list[str], cables: list[tuple[str, str]]) -> ET.Element:
    root = ET.fromstring("<PACKETTRACER5><NETWORK><DEVICES/><LINKS/></NETWORK></PACKETTRACER5>")
    devices_node = root.find(".//DEVICES")
    assert devices_node is not None
    for name in devices:
        device = ET.fromstring("<DEVICE><ENGINE><NAME/><SAVE_REF_ID/></ENGINE></DEVICE>")
        device.find("./ENGINE/NAME").text = name
        device.find("./ENGINE/SAVE_REF_ID").text = f"ref-{name}"
        devices_node.append(device)
    links = root.find(".//LINKS")
    assert links is not None
    for left, right in cables:
        link = ET.SubElement(links, "LINK")
        ET.SubElement(link, "TYPE").text = "eCopper"
        cable = ET.SubElement(link, "CABLE")
        ET.SubElement(cable, "FROM").text = f"ref-{left}"
        ET.SubElement(cable, "PORT").text = "FastEthernet0"
        ET.SubElement(cable, "TO").text = f"ref-{right}"
        ET.SubElement(cable, "PORT").text = "FastEthernet0/1"
    return root


def _blueprint(entries: list[tuple[str, str]]) -> dict[str, object]:
    return {"devices": [{"name": name, "type": kind} for name, kind in entries]}


def test_a_stranded_firewall_is_named_with_its_kind() -> None:
    lab = _lab(["R1", "SW1", "PC1", "ASA1"], [("PC1", "SW1"), ("SW1", "R1")])
    notes = _report_unwired_devices(
        lab, _blueprint([("R1", "Router"), ("SW1", "Switch"), ("PC1", "PC"), ("ASA1", "ASA")])
    )
    assert len(notes) == 1
    assert "1 requested device(s) have no cable" in notes[0]
    assert "ASA1 (ASA)" in notes[0]


def test_a_fully_cabled_lab_says_nothing() -> None:
    lab = _lab(["R1", "SW1", "PC1"], [("PC1", "SW1"), ("SW1", "R1")])
    assert _report_unwired_devices(
        lab, _blueprint([("R1", "Router"), ("SW1", "Switch"), ("PC1", "PC")])
    ) == []


def test_a_lab_with_no_cables_is_not_a_wiring_failure() -> None:
    """The wireless scenarios have no cables by design."""
    lab = _lab(["AP1", "L1"], [])
    assert _report_unwired_devices(lab, _blueprint([("AP1", "AccessPoint"), ("L1", "Laptop")])) == []


def test_a_donor_leftover_is_not_a_requested_device() -> None:
    lab = _lab(["R1", "SW1", "PC1", "Power Distribution Device0"], [("PC1", "SW1"), ("SW1", "R1")])
    assert _report_unwired_devices(
        lab, _blueprint([("R1", "Router"), ("SW1", "Switch"), ("PC1", "PC")])
    ) == []


def test_a_device_missing_from_the_file_is_not_reported_here() -> None:
    """That is the shortfall report's job; this one is about cables."""
    lab = _lab(["R1", "SW1"], [("SW1", "R1")])
    assert _report_unwired_devices(
        lab, _blueprint([("R1", "Router"), ("SW1", "Switch"), ("PC1", "PC")])
    ) == []
