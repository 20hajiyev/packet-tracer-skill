"""A generated lab becomes the donor for the next one, so a pass sees its own work.

The HSRP pass wrote the standby router's blocks by appending lines. Run once
that is correct; run again over the previous build and the file gains a second
copy of every subinterface. Measured on the enterprise lab after five builds:
`GigabitEthernet0/1.40` declared five times, holding `10.10.40.1`, then
`10.10.40.3`, then `10.10.40.1` again. IOS applies them in order and keeps the
last; every reader that scans for the first sees a different address, which is
how a router can be correct and unreachable at once.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_pkt import _add_hsrp_gateway_redundancy  # noqa: E402


def _router(name: str, subinterfaces: bool) -> ET.Element:
    device = ET.fromstring(
        "<DEVICE><ENGINE><NAME/><TYPE>Router</TYPE><SAVE_REF_ID/>"
        "<MODULE><SLOT/></MODULE><RUNNINGCONFIG/></ENGINE>"
        "<WORKSPACE><LOGICAL><X>0</X><Y>0</Y><MEM_ADDR>1</MEM_ADDR></LOGICAL></WORKSPACE></DEVICE>"
    )
    device.find("./ENGINE/NAME").text = name
    device.find("./ENGINE/SAVE_REF_ID").text = f"ref-{name}"
    slot = device.find("./ENGINE/MODULE/SLOT")
    config = device.find("./ENGINE/RUNNINGCONFIG")
    for index in (0, 1, 2):
        port = ET.SubElement(ET.SubElement(slot, "MODULE"), "PORT")
        ET.SubElement(port, "TYPE").text = "eCopperGigabitEthernet"
        ET.SubElement(config, "LINE").text = f"interface GigabitEthernet0/{index}"
        ET.SubElement(config, "LINE").text = "!"
    if subinterfaces:
        for line in (
            "interface GigabitEthernet0/1.10",
            " encapsulation dot1Q 10",
            " ip address 10.10.10.1 255.255.255.0",
            "!",
        ):
            ET.SubElement(config, "LINE").text = line
    return device


def _switch(name: str) -> ET.Element:
    device = ET.fromstring(
        "<DEVICE><ENGINE><NAME/><TYPE>Switch</TYPE><SAVE_REF_ID/>"
        "<MODULE><SLOT/></MODULE><RUNNINGCONFIG/></ENGINE>"
        "<WORKSPACE><LOGICAL><X>0</X><Y>0</Y><MEM_ADDR>2</MEM_ADDR></LOGICAL></WORKSPACE></DEVICE>"
    )
    device.find("./ENGINE/NAME").text = name
    device.find("./ENGINE/SAVE_REF_ID").text = f"ref-{name}"
    slot = device.find("./ENGINE/MODULE/SLOT")
    config = device.find("./ENGINE/RUNNINGCONFIG")
    # The standby router is trunked onto a spare FastEthernet port of the same
    # switch, so the fixture needs the access ports a real 2960 has, not only
    # the gigabit uplinks.
    for index in range(1, 5):
        port = ET.SubElement(ET.SubElement(slot, "MODULE"), "PORT")
        ET.SubElement(port, "TYPE").text = "eCopperFastEthernet"
        ET.SubElement(config, "LINE").text = f"interface FastEthernet0/{index}"
        ET.SubElement(config, "LINE").text = "!"
    for index in (1, 2):
        port = ET.SubElement(ET.SubElement(slot, "MODULE"), "PORT")
        ET.SubElement(port, "TYPE").text = "eCopperGigabitEthernet"
        ET.SubElement(config, "LINE").text = f"interface GigabitEthernet0/{index}"
        ET.SubElement(config, "LINE").text = "!"
    return device


def _lab() -> ET.Element:
    root = ET.fromstring("<PACKETTRACER5><NETWORK><DEVICES/><LINKS/></NETWORK></PACKETTRACER5>")
    devices = root.find(".//DEVICES")
    devices.append(_router("R1", subinterfaces=True))
    devices.append(_switch("SW1"))
    devices.append(_router("R2", subinterfaces=False))
    cable = ET.SubElement(ET.SubElement(root.find(".//LINKS"), "LINK"), "CABLE")
    ET.SubElement(cable, "FROM").text = "ref-R1"
    ET.SubElement(cable, "PORT").text = "GigabitEthernet0/1"
    ET.SubElement(cable, "TO").text = "ref-SW1"
    ET.SubElement(cable, "PORT").text = "GigabitEthernet0/1"
    return root


def _config(root: ET.Element, name: str) -> list[str]:
    for device in root.findall(".//DEVICES/DEVICE"):
        if (device.findtext("./ENGINE/NAME") or "") == name:
            return [(node.text or "") for node in device.findall("./ENGINE/RUNNINGCONFIG/LINE")]
    return []


def test_the_standby_router_is_configured_once_however_often_the_pass_runs() -> None:
    root = _lab()
    assert _add_hsrp_gateway_redundancy(root), "the fixture must reach the standby branch"

    after_first = _config(root, "R2")
    assert after_first.count("interface GigabitEthernet0/1.10") == 1

    for _ in range(3):
        _add_hsrp_gateway_redundancy(root)

    assert _config(root, "R2") == after_first, "the pass rewrote its own output"
    assert _config(root, "R2").count("interface GigabitEthernet0/1.10") == 1


def test_the_primary_router_is_configured_once_too() -> None:
    root = _lab()
    assert _add_hsrp_gateway_redundancy(root), "the fixture must reach the standby branch"
    after_first = _config(root, "R1")
    _add_hsrp_gateway_redundancy(root)
    assert _config(root, "R1") == after_first
