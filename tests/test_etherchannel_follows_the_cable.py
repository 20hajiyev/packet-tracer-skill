"""A `channel-group` on a port the cable never bundled isolates the switch.

`_synthesize_security_ops` names `GigabitEthernet0/1` and `GigabitEthernet0/2`
of the first two switches, chosen before any cable exists. Measured on the
153-device enterprise lab: SW2's `Gi0/1` was its only uplink to the core and
`Gi0/2` had no cable at all, so a live trunk was bundled with a dead port
towards SW18, which was not bundling. Nothing in the file configured the
resulting `Port-channel1`, the trunk settings stopped applying, and SW2 fell
off the network -- Printer6 behind it could not reach even the real address of
its own gateway on VLAN 50, while identical hosts behind SW3 and SW4, neither
given a channel-group, answered normally.

Two facts about the same bundle -- which ports it holds, and whether the peer
holds them too -- were derived in different places with nothing comparing them.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_pkt import _align_etherchannels_with_cabling  # noqa: E402

TRUNK = ["switchport mode trunk", "switchport trunk native vlan 99"]


def _switch(name: str, ports: dict[str, list[str]]) -> ET.Element:
    device = ET.fromstring(
        "<DEVICE><ENGINE><NAME/><TYPE>Switch</TYPE><SAVE_REF_ID/><RUNNINGCONFIG/></ENGINE></DEVICE>"
    )
    device.find("./ENGINE/NAME").text = name
    device.find("./ENGINE/SAVE_REF_ID").text = f"ref-{name}"
    config = device.find("./ENGINE/RUNNINGCONFIG")
    for port, body in ports.items():
        ET.SubElement(config, "LINE").text = f"interface {port}"
        for line in body:
            ET.SubElement(config, "LINE").text = f" {line}"
        ET.SubElement(config, "LINE").text = "!"
    return device


def _lab(switches: list[ET.Element], cables: list[tuple[str, str, str, str]]) -> ET.Element:
    root = ET.fromstring("<PACKETTRACER5><NETWORK><DEVICES/><LINKS/></NETWORK></PACKETTRACER5>")
    for switch in switches:
        root.find(".//DEVICES").append(switch)
    links = root.find(".//LINKS")
    for left, left_port, right, right_port in cables:
        link = ET.SubElement(links, "LINK")
        cable = ET.SubElement(link, "CABLE")
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


def test_the_uplink_that_cost_sw2_its_network() -> None:
    """One end bundles, the other does not: the line goes, the trunk stays."""
    root = _lab(
        [
            _switch("SW2", {"GigabitEthernet0/1": TRUNK + ["channel-group 1 mode on"]}),
            _switch("SW18", {"FastEthernet0/5": TRUNK}),
        ],
        [("SW2", "GigabitEthernet0/1", "SW18", "FastEthernet0/5")],
    )
    _align_etherchannels_with_cabling(root)
    assert not any(line.startswith("channel-group") for line in _lines(root, "SW2"))
    assert "switchport mode trunk" in _lines(root, "SW2")


def test_a_channel_group_on_a_port_with_no_cable_goes() -> None:
    root = _lab(
        [_switch("SW2", {"GigabitEthernet0/2": ["channel-group 1 mode on"]})],
        [],
    )
    _align_etherchannels_with_cabling(root)
    assert not any(line.startswith("channel-group") for line in _lines(root, "SW2"))


def test_a_bundle_of_one_cable_is_not_a_bundle() -> None:
    """Both ends agree, but one cable cannot be an EtherChannel."""
    root = _lab(
        [
            _switch("SW1", {"GigabitEthernet0/1": TRUNK + ["channel-group 1 mode on"]}),
            _switch("SW2", {"GigabitEthernet0/1": TRUNK + ["channel-group 1 mode on"]}),
        ],
        [("SW1", "GigabitEthernet0/1", "SW2", "GigabitEthernet0/1")],
    )
    _align_etherchannels_with_cabling(root)
    for name in ("SW1", "SW2"):
        assert not any(line.startswith("channel-group") for line in _lines(root, name))


def test_two_parallel_cables_keep_the_bundle_and_gain_a_port_channel() -> None:
    root = _lab(
        [
            _switch(
                "SW1",
                {
                    "GigabitEthernet0/1": TRUNK + ["channel-group 1 mode on"],
                    "GigabitEthernet0/2": TRUNK + ["channel-group 1 mode on"],
                },
            ),
            _switch(
                "SW2",
                {
                    "GigabitEthernet0/1": TRUNK + ["channel-group 1 mode on"],
                    "GigabitEthernet0/2": TRUNK + ["channel-group 1 mode on"],
                },
            ),
        ],
        [
            ("SW1", "GigabitEthernet0/1", "SW2", "GigabitEthernet0/1"),
            ("SW1", "GigabitEthernet0/2", "SW2", "GigabitEthernet0/2"),
        ],
    )
    notes = _align_etherchannels_with_cabling(root)
    for name in ("SW1", "SW2"):
        lines = _lines(root, name)
        assert lines.count("channel-group 1 mode on") == 2
        assert "interface Port-channel1" in lines, f"{name} has no Port-channel interface"
        start = lines.index("interface Port-channel1")
        assert "switchport mode trunk" in lines[start : start + 4]
    assert any("bundled on Port-channel1" in note for note in notes)


def test_a_lab_with_no_etherchannel_is_left_alone() -> None:
    root = _lab([_switch("SW1", {"GigabitEthernet0/1": TRUNK})], [])
    assert _align_etherchannels_with_cabling(root) == []
    assert _lines(root, "SW1") == ["interface GigabitEthernet0/1"] + TRUNK + ["!"]
