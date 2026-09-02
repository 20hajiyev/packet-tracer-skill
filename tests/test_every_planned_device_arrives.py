"""Asking for six workstations and getting four is the plainest failure there is.

Measured on "2 switch, 1 router, 6 PC": the donor holds eight PCs across three
switches, the plan keeps two switches, and PC4 and PC5 went out with the switch
they hung off -- while PC7 and PC8, cabled to a switch that survived, were
deleted as spares. Six were asked for, four arrived, out of eight that were
there. `_adopt_planned_names` already hands a missing planned name to a cabled
device with one to spare; it ran after the spares were gone.
"""

from __future__ import annotations

import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_pkt import _drop_stale_point_to_point_addresses  # noqa: E402


def _router(name: str, blocks: list[tuple[str, str]]) -> ET.Element:
    device = ET.fromstring(
        "<DEVICE><ENGINE><NAME/><TYPE>Router</TYPE><SAVE_REF_ID/><RUNNINGCONFIG/></ENGINE></DEVICE>"
    )
    device.find("./ENGINE/NAME").text = name
    device.find("./ENGINE/SAVE_REF_ID").text = f"ref-{name}"
    config = device.find("./ENGINE/RUNNINGCONFIG")
    for port, address in blocks:
        ET.SubElement(config, "LINE").text = f"interface {port}"
        ET.SubElement(config, "LINE").text = f" ip address {address} 255.255.255.252"
        ET.SubElement(config, "LINE").text = "!"
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


def _lines(root: ET.Element, name: str) -> list[str]:
    for device in root.findall(".//DEVICES/DEVICE"):
        if (device.findtext("./ENGINE/NAME") or "") == name:
            return [(node.text or "").strip() for node in device.findall("./ENGINE/RUNNINGCONFIG/LINE")]
    return []


def test_a_point_to_point_address_without_its_cable_is_dropped() -> None:
    """R1 held 10.255.0.2 on two interfaces, one cabled and one not."""
    root = _lab(
        [
            _router("R1", [("GigabitEthernet0/1", "10.255.0.2"), ("GigabitEthernet0/2", "10.255.0.2")]),
            _router("R2", [("GigabitEthernet0/1", "10.255.0.1")]),
        ],
        [("R1", "GigabitEthernet0/2", "R2", "GigabitEthernet0/1")],
    )
    assert _drop_stale_point_to_point_addresses(root)
    lines = _lines(root, "R1")
    assert lines.count("ip address 10.255.0.2 255.255.255.252") == 1


def test_a_cabled_point_to_point_address_stays() -> None:
    root = _lab(
        [
            _router("R1", [("GigabitEthernet0/1", "10.255.0.2")]),
            _router("R2", [("GigabitEthernet0/1", "10.255.0.1")]),
        ],
        [("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1")],
    )
    assert _drop_stale_point_to_point_addresses(root) == []
    assert "ip address 10.255.0.2 255.255.255.252" in _lines(root, "R1")


def test_an_address_outside_the_range_this_file_hands_out_is_left_alone() -> None:
    """A donor's own addressing is not ours to tidy."""
    root = _lab([_router("R1", [("GigabitEthernet0/1", "192.168.9.1")])], [])
    assert _drop_stale_point_to_point_addresses(root) == []
    assert "ip address 192.168.9.1 255.255.255.252" in _lines(root, "R1")


@pytest.mark.requires_donors
def test_six_workstations_asked_for_are_six_workstations_delivered(tmp_path: Path) -> None:
    output = tmp_path / "six.pkt"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "generate_pkt.py"),
            "--prompt",
            "2 switch, 1 router, 6 PC, VLAN 10 ve 20, dhcp olsun",
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        timeout=1800,
    )
    if not output.exists():
        pytest.skip(f"generation needs a local donor lab: {result.stdout[-400:]}")

    from generate_pkt import decode_pkt_to_root

    root = decode_pkt_to_root(output)
    names = {(device.findtext("./ENGINE/NAME") or "") for device in root.findall(".//DEVICES/DEVICE")}
    missing = sorted({f"PC{index}" for index in range(1, 7)} - names)
    assert not missing, f"asked for six workstations, {missing} did not arrive"
    assert "not in the file" not in result.stdout, result.stdout[-400:]
