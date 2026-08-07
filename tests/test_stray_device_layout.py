"""A lab should not open on an empty patch of canvas.

Every corpus lab measured between 2440 and 2550 units wide, including
`minimal`, which is one router, one switch and three PCs. Those five sit inside
340 units. The width came from two `Power Distribution Device` nodes left at
their donor coordinates, x=2620 and x=2730, about 2100 units to the right of
anything cabled. Packet Tracer shows roughly 1500 units at the default zoom, so
the lab opened showing nothing and the real topology was off to the left.

Measured after pulling them in: `minimal` 2550 -> 600 wide, `two_switch_chain`
2550 -> 650, `four_switch` 2230 -> 1180.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_pkt import _compact_stray_devices  # noqa: E402


def _lab(devices: list[tuple[str, float, float]], cables: list[tuple[str, str]]) -> ET.Element:
    root = ET.fromstring(
        """
        <PACKETTRACER5>
          <NETWORK>
            <DEVICES/>
            <LINKS/>
          </NETWORK>
        </PACKETTRACER5>
        """
    )
    devices_node = root.find(".//DEVICES")
    assert devices_node is not None
    for name, x, y in devices:
        device = ET.fromstring(
            """
            <DEVICE>
              <ENGINE><NAME/><TYPE>Pc</TYPE><SAVE_REF_ID/></ENGINE>
              <WORKSPACE><LOGICAL><X/><Y/></LOGICAL></WORKSPACE>
            </DEVICE>
            """
        )
        device.find("./ENGINE/NAME").text = name
        device.find("./ENGINE/SAVE_REF_ID").text = f"ref-{name}"
        device.find("./WORKSPACE/LOGICAL/X").text = str(x)
        device.find("./WORKSPACE/LOGICAL/Y").text = str(y)
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


def _width(root: ET.Element) -> float:
    xs = [float(node.text or 0) for node in root.findall(".//WORKSPACE/LOGICAL/X")]
    return max(xs) - min(xs)


def test_a_leftover_far_from_the_lab_is_pulled_in() -> None:
    lab = _lab(
        [("R1", 520, 110), ("SW1", 440, 460), ("PC1", 180, 600), ("PDU0", 2620, 120)],
        [("PC1", "SW1"), ("SW1", "R1")],
    )
    assert _width(lab) == 2440
    assert _compact_stray_devices(lab)
    assert _width(lab) < 700


def test_a_cabled_device_is_never_moved() -> None:
    lab = _lab(
        [("R1", 520, 110), ("SW1", 440, 460), ("PC1", 2600, 600)],
        [("PC1", "SW1"), ("SW1", "R1")],
    )
    before = {
        node.find("./ENGINE/NAME").text: node.find("./WORKSPACE/LOGICAL/X").text
        for node in lab.findall(".//DEVICES/DEVICE")
    }
    _compact_stray_devices(lab)
    after = {
        node.find("./ENGINE/NAME").text: node.find("./WORKSPACE/LOGICAL/X").text
        for node in lab.findall(".//DEVICES/DEVICE")
    }
    assert before == after


def test_a_leftover_already_beside_the_lab_is_left_alone() -> None:
    lab = _lab(
        [("R1", 520, 110), ("SW1", 440, 460), ("PC1", 180, 600), ("PDU0", 700, 120)],
        [("PC1", "SW1"), ("SW1", "R1")],
    )
    assert _compact_stray_devices(lab) == []


def test_a_lab_with_no_cables_is_left_alone() -> None:
    """The wireless scenarios have no cables, so there is no box to pull toward."""
    lab = _lab([("AP", 200, 200), ("L1", 2400, 300), ("L2", 2500, 300)], [])
    assert _compact_stray_devices(lab) == []
    assert _width(lab) == 2300


def test_running_it_twice_changes_nothing_the_second_time() -> None:
    lab = _lab(
        [("R1", 520, 110), ("SW1", 440, 460), ("PC1", 180, 600), ("PDU0", 2620, 120)],
        [("PC1", "SW1"), ("SW1", "R1")],
    )
    _compact_stray_devices(lab)
    settled = _width(lab)
    assert _compact_stray_devices(lab) == []
    assert _width(lab) == settled
