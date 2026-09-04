"""A device doing the plan's job should answer to the plan's name.

Four corpus labs came out one device short of their blueprint, always the last
switch, and the device was never missing. `hosts_across_switches` planned
`SW1, SW2, SW3`; the file held `SW1`, `SW2` and `MultiLayerSwitch1`, and that
third switch is the core of the topology -- the router connects to it and it
connects to the other two. It had kept the donor's name.

Whether the rename lands depends on the donor: applying the same plan against
the saved floor-switch lab by hand produced `SW3` correctly, while the donor the corpus
picked supplied its own `MultiLayerSwitch` devices and one was reused as-is.

Being cabled is the test for "doing the job". An idle spare parked to one side
would otherwise be handed the name, and the lab would ship an `SW3` connected
to nothing -- which reads as success and is not.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_pkt import _adopt_planned_names  # noqa: E402


def _lab(devices: list[tuple[str, str]], cables: list[tuple[str, str]]) -> ET.Element:
    root = ET.fromstring("<PACKETTRACER5><NETWORK><DEVICES/><LINKS/></NETWORK></PACKETTRACER5>")
    devices_node = root.find(".//DEVICES")
    assert devices_node is not None
    for name, kind in devices:
        device = ET.fromstring(
            "<DEVICE><ENGINE><NAME/><TYPE/><SAVE_REF_ID/><RUNNINGCONFIG/></ENGINE></DEVICE>"
        )
        device.find("./ENGINE/NAME").text = name
        device.find("./ENGINE/TYPE").text = kind
        device.find("./ENGINE/SAVE_REF_ID").text = f"ref-{name}"
        ET.SubElement(device.find("./ENGINE/RUNNINGCONFIG"), "LINE").text = "hostname Switch"
        devices_node.append(device)
    links = root.find(".//LINKS")
    assert links is not None
    for left, right in cables:
        link = ET.SubElement(links, "LINK")
        ET.SubElement(link, "TYPE").text = "eCopper"
        cable = ET.SubElement(link, "CABLE")
        ET.SubElement(cable, "FROM").text = f"ref-{left}"
        ET.SubElement(cable, "PORT").text = "GigabitEthernet0/1"
        ET.SubElement(cable, "TO").text = f"ref-{right}"
        ET.SubElement(cable, "PORT").text = "GigabitEthernet0/2"
    return root


def _blueprint(names: list[str], model: str = "2960-24TT") -> dict[str, object]:
    return {"devices": [{"name": name, "model": model, "type": "Switch"} for name in names]}


def _names(root: ET.Element) -> set[str]:
    return {(node.findtext("./ENGINE/NAME") or "").strip() for node in root.findall(".//DEVICES/DEVICE")}


def test_a_cabled_donor_switch_takes_the_missing_name() -> None:
    lab = _lab(
        [("SW1", "MultiLayerSwitch"), ("SW2", "MultiLayerSwitch"), ("MultiLayerSwitch1", "MultiLayerSwitch")],
        [("SW1", "MultiLayerSwitch1"), ("MultiLayerSwitch1", "SW2")],
    )
    assert _adopt_planned_names(lab, _blueprint(["SW1", "SW2", "SW3"]))
    assert "SW3" in _names(lab)
    assert "MultiLayerSwitch1" not in _names(lab)


def test_the_adopted_device_announces_the_new_name() -> None:
    lab = _lab(
        [("SW1", "MultiLayerSwitch"), ("MultiLayerSwitch1", "MultiLayerSwitch")],
        [("SW1", "MultiLayerSwitch1")],
    )
    _adopt_planned_names(lab, _blueprint(["SW1", "SW2"]))
    adopted = next(
        node
        for node in lab.findall(".//DEVICES/DEVICE")
        if (node.findtext("./ENGINE/NAME") or "") == "SW2"
    )
    assert "hostname SW2" in [
        (line.text or "").strip() for line in adopted.findall("./ENGINE/RUNNINGCONFIG/LINE")
    ]


def test_an_uncabled_spare_is_not_given_the_name() -> None:
    """An `SW3` wired to nothing reads as success and is not."""
    lab = _lab(
        [("SW1", "MultiLayerSwitch"), ("SW2", "MultiLayerSwitch"), ("Switch9", "Switch")],
        [("SW1", "SW2")],
    )
    assert _adopt_planned_names(lab, _blueprint(["SW1", "SW2", "SW3"])) == []
    assert "SW3" not in _names(lab)


def test_a_router_does_not_take_a_switch_name() -> None:
    lab = _lab(
        [("SW1", "MultiLayerSwitch"), ("Router7", "Router")],
        [("SW1", "Router7")],
    )
    assert _adopt_planned_names(lab, _blueprint(["SW1", "SW2"])) == []


def test_a_complete_lab_is_left_alone() -> None:
    lab = _lab([("SW1", "MultiLayerSwitch"), ("SW2", "MultiLayerSwitch")], [("SW1", "SW2")])
    assert _adopt_planned_names(lab, _blueprint(["SW1", "SW2"])) == []
