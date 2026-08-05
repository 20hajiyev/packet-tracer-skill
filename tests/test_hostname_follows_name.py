"""A device's CLI prompt should be the name the topology calls it.

Measured across the corpus: 84 of 90 configured devices carried a hostname that
was not their name. In a two-switch lab both prompts read `Switch`, which makes
the two indistinguishable from the console -- and a lab is mostly read through
that console.

The rename matched on the old *device* name, which never fired: a donor switch
called `Multilayer Switch0` carries `hostname Switch`, so the two never agreed
and the line was left behind.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from pkt_editor import _set_device_name  # noqa: E402


def _device(name: str, hostname: str) -> tuple[ET.Element, ET.Element]:
    root = ET.Element("PACKETTRACER5")
    devices = ET.SubElement(ET.SubElement(root, "NETWORK"), "DEVICES")
    device = ET.SubElement(devices, "DEVICE")
    engine = ET.SubElement(device, "ENGINE")
    ET.SubElement(engine, "NAME").text = name
    ET.SubElement(engine, "TYPE").text = "Switch"
    for tag in ("RUNNINGCONFIG", "STARTUPCONFIG"):
        config = ET.SubElement(engine, tag)
        ET.SubElement(config, "LINE").text = "!"
        ET.SubElement(config, "LINE").text = f"hostname {hostname}"
        ET.SubElement(config, "LINE").text = "spanning-tree mode pvst"
    return root, device


def _hostnames(device: ET.Element) -> list[str]:
    found: list[str] = []
    for tag in ("RUNNINGCONFIG", "STARTUPCONFIG"):
        config = device.find(f"./ENGINE/{tag}")
        if config is None:
            continue
        found.extend(
            (line.text or "").strip()
            for line in config.findall("LINE")
            if (line.text or "").startswith("hostname ")
        )
    return found


def test_the_hostname_follows_the_new_name_even_when_it_did_not_match() -> None:
    root, device = _device("Multilayer Switch0", "Switch")

    _set_device_name(root, device, "SW1")

    assert _hostnames(device) == ["hostname SW1", "hostname SW1"]


def test_only_one_hostname_line_is_written_per_config() -> None:
    root, device = _device("Switch0", "Switch")

    _set_device_name(root, device, "SW2")

    for tag in ("RUNNINGCONFIG", "STARTUPCONFIG"):
        config = device.find(f"./ENGINE/{tag}")
        assert config is not None
        lines = [(line.text or "") for line in config.findall("LINE")]
        assert sum(1 for line in lines if line.startswith("hostname ")) == 1, lines


def test_a_name_that_is_not_a_valid_hostname_is_left_alone() -> None:
    """`Patch Panel1` and `Power Distribution Device0` have spaces. Those
    devices carry no configuration, but the guard keeps the invariant local."""
    root, device = _device("PatchPanel0", "Switch")

    _set_device_name(root, device, "Patch Panel1")

    assert _hostnames(device) == ["hostname Switch", "hostname Switch"]
