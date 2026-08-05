"""No two devices may answer to the same address.

A cloned device is a deep copy, so it arrives holding the prototype's interface
addresses. Measured across the corpus: 7 of 32 labs carried a duplicate.
`multiarea_ospf` had R1, R2 and R3 all on 192.168.1.1, .2.1 and .3.1;
`router_dhcp` had three PCs all on 1.1.1.3.

The address lives in two places at once -- the PORT node and the `ip address`
line -- so a fix that moves only one leaves the device disagreeing with itself,
and `show running-config` stops describing the interface.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_pkt import _assign_unique_interface_addresses  # noqa: E402


def _device(name: str, addresses: list[str], with_config: bool = True) -> ET.Element:
    device = ET.Element("DEVICE")
    engine = ET.SubElement(device, "ENGINE")
    ET.SubElement(engine, "NAME").text = name
    ET.SubElement(engine, "TYPE").text = "Router"
    if with_config:
        config = ET.SubElement(engine, "RUNNINGCONFIG")
        for address in addresses:
            ET.SubElement(config, "LINE").text = f"interface GigabitEthernet0/{addresses.index(address)}"
            ET.SubElement(config, "LINE").text = f"ip address {address} 255.255.255.0"
    ports = ET.SubElement(device, "PORTS")
    for address in addresses:
        port = ET.SubElement(ports, "PORT")
        ET.SubElement(port, "TYPE").text = "eCopperGigabitEthernet"
        ET.SubElement(port, "IP").text = address
    return device


def _lab(devices: list[ET.Element]) -> ET.Element:
    root = ET.Element("PACKETTRACER5")
    holder = ET.SubElement(ET.SubElement(root, "NETWORK"), "DEVICES")
    for device in devices:
        holder.append(device)
    return root


def _addresses(root: ET.Element) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME") or ""
        found[name] = [
            (port.findtext("IP") or "").strip()
            for port in device.iter("PORT")
            if (port.findtext("IP") or "").strip()
        ]
    return found


def _config_addresses(root: ET.Element, name: str) -> list[str]:
    for device in root.findall(".//DEVICES/DEVICE"):
        if (device.findtext("./ENGINE/NAME") or "") != name:
            continue
        config = device.find("./ENGINE/RUNNINGCONFIG")
        if config is None:
            return []
        return [
            (line.text or "").strip().split()[2]
            for line in config.findall("LINE")
            if (line.text or "").strip().startswith("ip address")
        ]
    return []


def test_a_cloned_router_is_moved_off_the_prototypes_addresses() -> None:
    root = _lab([
        _device("R1", ["192.168.1.1", "192.168.2.1"]),
        _device("R2", ["192.168.1.1", "192.168.2.1"]),
    ])

    changed = _assign_unique_interface_addresses(root)

    addresses = _addresses(root)
    assert addresses["R1"] == ["192.168.1.1", "192.168.2.1"], "the first holder keeps its address"
    assert addresses["R2"] == ["192.168.1.2", "192.168.2.2"]
    assert len(changed) == 2


def test_the_configuration_moves_with_the_interface() -> None:
    root = _lab([
        _device("R1", ["10.0.0.1"]),
        _device("R2", ["10.0.0.1"]),
    ])

    _assign_unique_interface_addresses(root)

    assert _addresses(root)["R2"] == _config_addresses(root, "R2"), (
        "a device whose port and running-config disagree describes an interface it does not have"
    )


def test_hosts_sharing_a_cloned_address_are_separated() -> None:
    root = _lab([
        _device("PC1", ["1.1.1.3"], with_config=False),
        _device("PC2", ["1.1.1.3"], with_config=False),
        _device("PC3", ["1.1.1.3"], with_config=False),
    ])

    _assign_unique_interface_addresses(root)

    flat = [address for addresses in _addresses(root).values() for address in addresses]
    assert len(set(flat)) == 3, flat


def test_addresses_that_are_already_distinct_are_left_alone() -> None:
    root = _lab([_device("R1", ["192.168.1.1"]), _device("R2", ["192.168.1.2"])])

    assert _assign_unique_interface_addresses(root) == []
