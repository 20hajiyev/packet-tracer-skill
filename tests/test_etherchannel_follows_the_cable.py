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
        "<DEVICE><ENGINE><NAME/><TYPE>Switch</TYPE><SAVE_REF_ID/>"
        "<MODULE><SLOT/></MODULE><RUNNINGCONFIG/></ENGINE>"
        "<WORKSPACE><LOGICAL><X>0</X><Y>0</Y></LOGICAL></WORKSPACE></DEVICE>"
    )
    device.find("./ENGINE/NAME").text = name
    device.find("./ENGINE/SAVE_REF_ID").text = f"ref-{name}"
    slot = device.find("./ENGINE/MODULE/SLOT")
    config = device.find("./ENGINE/RUNNINGCONFIG")
    for port, body in ports.items():
        module = ET.SubElement(slot, "MODULE")
        socket = ET.SubElement(module, "PORT")
        kind = "eCopperGigabitEthernet" if port.startswith("Gigabit") else "eCopperFastEthernet"
        ET.SubElement(socket, "TYPE").text = kind
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


def _cables(root: ET.Element) -> list[tuple[str, str, str, str]]:
    found = []
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        ports = [node.text or "" for node in cable.findall("PORT")]
        found.append(
            (
                (cable.findtext("FROM") or "").replace("ref-", ""),
                ports[0],
                (cable.findtext("TO") or "").replace("ref-", ""),
                ports[1],
            )
        )
    return found


def test_the_uplink_that_cost_sw2_its_network() -> None:
    """One end bundles, the other does not, and neither has a spare port."""
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
    assert len(_cables(root)) == 1, "no spare port, so no second cable"


def test_a_channel_group_on_a_port_with_no_cable_goes() -> None:
    root = _lab(
        [_switch("SW2", {"GigabitEthernet0/2": ["channel-group 1 mode on"]})],
        [],
    )
    _align_etherchannels_with_cabling(root)
    assert not any(line.startswith("channel-group") for line in _lines(root, "SW2"))


def test_one_cable_and_a_spare_port_each_gets_the_second_cable() -> None:
    """The bundle the plan asked for is completed rather than thrown away."""
    root = _lab(
        [
            _switch(
                "SW1",
                {
                    "GigabitEthernet0/1": TRUNK + ["channel-group 1 mode on"],
                    "GigabitEthernet0/2": [],
                },
            ),
            _switch("SW2", {"GigabitEthernet0/1": TRUNK, "GigabitEthernet0/2": []}),
        ],
        [("SW1", "GigabitEthernet0/1", "SW2", "GigabitEthernet0/1")],
    )
    notes = _align_etherchannels_with_cabling(root)
    cables = _cables(root)
    assert len(cables) == 2, f"expected a second cable, got {cables}"
    assert ("SW1", "GigabitEthernet0/2", "SW2", "GigabitEthernet0/2") in cables
    for name in ("SW1", "SW2"):
        lines = _lines(root, name)
        assert lines.count("channel-group 1 mode on") == 2, f"{name}: {lines}"
        assert "interface Port-channel1" in lines
        assert "switchport mode trunk" in lines
    assert any("2 cables" in note for note in notes)


def test_the_second_cable_is_not_laid_over_a_port_already_in_use() -> None:
    """A spare port carrying a host is not spare."""
    root = _lab(
        [
            _switch(
                "SW1",
                {
                    "GigabitEthernet0/1": TRUNK + ["channel-group 1 mode on"],
                    "GigabitEthernet0/2": [],
                },
            ),
            _switch("SW2", {"GigabitEthernet0/1": TRUNK, "GigabitEthernet0/2": []}),
            _switch("SW3", {"GigabitEthernet0/1": TRUNK}),
        ],
        [
            ("SW1", "GigabitEthernet0/1", "SW2", "GigabitEthernet0/1"),
            ("SW2", "GigabitEthernet0/2", "SW3", "GigabitEthernet0/1"),
        ],
    )
    _align_etherchannels_with_cabling(root)
    for left, left_port, right, right_port in _cables(root):
        assert (right, right_port) != ("SW3", "GigabitEthernet0/1") or left == "SW2"
    assert not any(line.startswith("channel-group") for line in _lines(root, "SW1")), (
        "SW2 had no free port left, so the bundle cannot be completed"
    )


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


def test_the_second_cable_matches_the_speed_of_the_member_it_joins() -> None:
    """Gigabit bundled with FastEthernet is a speed mismatch, and refused."""
    root = _lab(
        [
            _switch(
                "SW1",
                {
                    "FastEthernet0/1": [],
                    "GigabitEthernet0/1": TRUNK + ["channel-group 1 mode on"],
                    "GigabitEthernet0/2": [],
                },
            ),
            _switch(
                "SW2",
                {
                    "FastEthernet0/1": [],
                    "GigabitEthernet0/1": TRUNK,
                    "GigabitEthernet0/2": [],
                },
            ),
        ],
        [("SW1", "GigabitEthernet0/1", "SW2", "GigabitEthernet0/1")],
    )
    _align_etherchannels_with_cabling(root)
    added = [cable for cable in _cables(root) if "GigabitEthernet0/2" in cable]
    assert added == [("SW1", "GigabitEthernet0/2", "SW2", "GigabitEthernet0/2")], _cables(root)
    for _, left_port, _, right_port in _cables(root):
        assert left_port.startswith("Gigabit") and right_port.startswith("Gigabit")


def test_a_switch_in_two_bundles_gets_two_channel_numbers() -> None:
    """Members facing different neighbours cannot share one Port-channel."""
    ports = {f"GigabitEthernet0/{index}": [] for index in range(1, 6)}
    ports["GigabitEthernet0/1"] = TRUNK + ["channel-group 1 mode on"]
    ports["GigabitEthernet0/2"] = TRUNK + ["channel-group 1 mode on"]
    root = _lab(
        [
            _switch("SW3", ports),
            _switch("SW1", {f"GigabitEthernet0/{i}": TRUNK for i in (1, 2)}),
            _switch("SW2", {f"GigabitEthernet0/{i}": TRUNK for i in (1, 2)}),
        ],
        [
            ("SW3", "GigabitEthernet0/1", "SW1", "GigabitEthernet0/1"),
            ("SW3", "GigabitEthernet0/2", "SW2", "GigabitEthernet0/1"),
        ],
    )
    _align_etherchannels_with_cabling(root)
    lines = _lines(root, "SW3")
    numbers = {line.split()[1] for line in lines if line.startswith("channel-group")}
    assert numbers == {"1", "2"}, f"SW3 bundles two neighbours as {numbers}"
    assert "interface Port-channel1" in lines and "interface Port-channel2" in lines


def test_a_lab_with_no_etherchannel_is_left_alone() -> None:
    root = _lab([_switch("SW1", {"GigabitEthernet0/1": TRUNK})], [])
    assert _align_etherchannels_with_cabling(root) == []
    assert _lines(root, "SW1") == ["interface GigabitEthernet0/1"] + TRUNK + ["!"]
