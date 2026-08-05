"""A duplicated switch must not inherit the prototype's management address.

Measured on `4 switch 1 router 8 komputer qur`: SW1, SW3 and MultiLayerSwitch1
all answered to 2.1.1.6, and Packet Tracer's own health check reported the
collision. Cloning is a deep copy, so the `Vlan1` address comes along with
everything else -- the same way MAC addresses did before they were made unique.

Nothing else catches it. The lab opens and every host reaches every other host;
only management traffic is ambiguous, which is the kind of fault a green suite
keeps.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_pkt import _assign_unique_switch_management_ips  # noqa: E402


def _lab(switch_addresses: list[str], host_addresses: list[str]) -> ET.Element:
    root = ET.Element("PACKETTRACER5")
    devices = ET.SubElement(ET.SubElement(root, "NETWORK"), "DEVICES")
    for index, address in enumerate(switch_addresses):
        device = ET.SubElement(devices, "DEVICE")
        engine = ET.SubElement(device, "ENGINE")
        ET.SubElement(engine, "NAME").text = f"SW{index + 1}"
        ET.SubElement(engine, "TYPE").text = "Switch"
        config = ET.SubElement(engine, "RUNNINGCONFIG")
        ET.SubElement(config, "LINE").text = "interface Vlan1"
        ET.SubElement(config, "LINE").text = f"ip address {address} 255.0.0.0"
        ET.SubElement(config, "LINE").text = "no shutdown"
    for index, address in enumerate(host_addresses):
        device = ET.SubElement(devices, "DEVICE")
        engine = ET.SubElement(device, "ENGINE")
        ET.SubElement(engine, "NAME").text = f"PC{index + 1}"
        ET.SubElement(engine, "TYPE").text = "Pc"
        ports = ET.SubElement(device, "PORTS")
        port = ET.SubElement(ports, "PORT")
        ET.SubElement(port, "TYPE").text = "eCopperFastEthernet"
        ET.SubElement(port, "IP").text = address
    return root


def _svi_addresses(root: ET.Element) -> list[str]:
    found: list[str] = []
    for device in root.findall(".//DEVICES/DEVICE"):
        config = device.find("./ENGINE/RUNNINGCONFIG")
        if config is None:
            continue
        lines = [(line.text or "").strip() for line in config.findall("LINE")]
        for index, text in enumerate(lines):
            if text.startswith("ip address") and index and lines[index - 1].lower().startswith("interface vlan"):
                found.append(text.split()[2])
    return found


def test_cloned_switches_get_their_own_management_address() -> None:
    root = _lab(["2.1.1.6", "2.1.1.6", "2.1.1.6"], ["2.1.1.20", "2.1.1.21"])

    changed = _assign_unique_switch_management_ips(root)

    addresses = _svi_addresses(root)
    assert len(set(addresses)) == 3, addresses
    assert addresses[0] == "2.1.1.6", "the first switch keeps the address the donor gave it"
    assert len(changed) == 2


def test_a_renumbered_switch_avoids_the_hosts() -> None:
    """The hosts sit in the same range, so a naive increment would land on one."""
    root = _lab(["2.1.1.20", "2.1.1.20"], ["2.1.1.21", "2.1.1.22", "2.1.1.23"])

    _assign_unique_switch_management_ips(root)

    addresses = _svi_addresses(root)
    assert addresses[1] not in {"2.1.1.20", "2.1.1.21", "2.1.1.22", "2.1.1.23"}, addresses
    assert addresses[1].startswith("2.1.1."), "the address must stay on its own subnet"


def test_addresses_that_are_already_distinct_are_left_alone() -> None:
    root = _lab(["1.1.1.5", "2.1.1.6"], [])

    assert _assign_unique_switch_management_ips(root) == []
    assert _svi_addresses(root) == ["1.1.1.5", "2.1.1.6"]
