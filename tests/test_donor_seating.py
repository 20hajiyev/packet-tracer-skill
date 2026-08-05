"""Regression tests for seating a target on a donor switch group that fits.

All three defects here were found by one prompt: `1 router 1 switch 1 patch
panel 2 komputer`, against a donor holding two switches -- one carrying the
exotic devices and no hosts, one carrying the PCs. They surfaced in sequence,
each hidden behind the one before it, and they share the shape this repo keeps
running into: a device name is treated as an identity while the plan is busy
reassigning names.

1. Seating went by distance from the router, so the target landed on the
   host-less switch and the request was refused as impossible.
2. With the right group seated, the plan renamed the second switch to `SW1`
   while the donor's own `SW1` was still present, then pruned "SW1" by name.
   The wrong device's cables went, leaving hosts with none and a link pointing
   at a device that no longer existed.
3. The planner read the pruned switch's router cable as proof that `R1 <-> SW1`
   was already wired, so it created nothing -- and the prune took that cable
   away. The lab generated and opened with its router connected to nothing.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_pkt import _seat_surplus_donor_groups  # noqa: E402
from intent_parser import IntentPlan  # noqa: E402
from pkt_editor import apply_plan_operations  # noqa: E402


def _donor_group(name: str, members_by_type: dict[str, list[str]]) -> dict[str, object]:
    return {
        "group_name": name,
        "switch": {"name": name, "x": 0, "y": 0},
        "members_by_type": {
            kind: [{"name": member, "type": kind} for member in members]
            for kind, members in members_by_type.items()
        },
        "members": [
            {"name": member, "type": kind}
            for kind, members in members_by_type.items()
            for member in members
        ],
    }


def _target_group(name: str, members: list[tuple[str, str]]) -> dict[str, object]:
    return {
        "group_name": name,
        "switch": {"name": name, "x": 0, "y": 0},
        "members": [{"name": member, "type": kind} for member, kind in members],
    }


def test_surplus_seating_prefers_the_group_that_can_supply_the_hosts() -> None:
    exotic = _donor_group("SW1", {"Patch Panel": ["PatchPanel1"]})
    populated = _donor_group("SWP1", {"PC": ["PCP1", "PCP2"]})
    target = _target_group("SW1", [("PC1", "PC"), ("PC2", "PC")])

    seated = _seat_surplus_donor_groups([exotic, populated], [target], ["SW1"])

    assert seated[0] is populated, "a target needing two PCs must not be seated on the empty switch"
    assert set(id(group) for group in seated) == {id(exotic), id(populated)}


def test_surplus_seating_keeps_hop_order_when_nothing_covers() -> None:
    first = _donor_group("SW1", {})
    second = _donor_group("SW2", {})
    target = _target_group("SW1", [("PC1", "PC")])

    seated = _seat_surplus_donor_groups([first, second], [target], ["SW1"])

    assert seated[0] is first, "with no group able to cover, the incoming order stands"


def _root_with(devices: list[tuple[str, str]], links: list[tuple[str, str]]) -> ET.Element:
    root = ET.Element("PACKETTRACER5")
    network = ET.SubElement(root, "NETWORK")
    devices_node = ET.SubElement(network, "DEVICES")
    refs: dict[str, str] = {}
    for index, (name, kind) in enumerate(devices):
        device = ET.SubElement(devices_node, "DEVICE")
        engine = ET.SubElement(device, "ENGINE")
        ET.SubElement(engine, "NAME").text = name
        ET.SubElement(engine, "TYPE").text = kind
        ref = f"save-ref-id:{index + 100}"
        ET.SubElement(engine, "SAVE_REF_ID").text = ref
        refs[name] = ref
        workspace = ET.SubElement(device, "WORKSPACE")
        logical = ET.SubElement(workspace, "LOGICAL")
        ET.SubElement(logical, "X").text = "100"
        ET.SubElement(logical, "Y").text = "100"
    links_node = ET.SubElement(network, "LINKS")
    for left, right in links:
        link = ET.SubElement(links_node, "LINK")
        cable = ET.SubElement(link, "CABLE")
        ET.SubElement(cable, "FROM").text = refs[left]
        ET.SubElement(cable, "TO").text = refs[right]
        ET.SubElement(cable, "PORT").text = "FastEthernet0/1"
        ET.SubElement(cable, "PORT").text = "FastEthernet0"
    return root


def _surviving_links(root: ET.Element) -> set[tuple[str, str]]:
    by_ref = {
        (device.findtext("./ENGINE/SAVE_REF_ID") or ""): (device.findtext("./ENGINE/NAME") or "")
        for device in root.findall(".//DEVICES/DEVICE")
    }
    pairs: set[tuple[str, str]] = set()
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        left = by_ref.get(cable.findtext("FROM", default=""), "?")
        right = by_ref.get(cable.findtext("TO", default=""), "?")
        pairs.add(tuple(sorted((left, right))))
    return pairs


def test_rename_into_a_pruned_name_keeps_the_new_device_cabled() -> None:
    root = _root_with(
        [("SW1", "Switch"), ("SWP1", "Switch"), ("PC1", "PC")],
        [("SW1", "PC1"), ("SWP1", "PC1")],
    )
    plan = IntentPlan(goal="generate", prompt="test")
    # The order that broke: the rename lands first, so two devices answer to
    # `SW1` by the time the prune runs.
    plan.edit_operations = [
        {"op": "rename_device", "device": "SWP1", "new_name": "SW1"},
        {"op": "prune_device", "device": "SW1"},
    ]

    updated = apply_plan_operations(root, plan)

    names = [(device.findtext("./ENGINE/NAME") or "") for device in updated.findall(".//DEVICES/DEVICE")]
    assert names.count("SW1") == 1, "exactly one device may answer to the renamed name"
    assert ("PC1", "SW1") in _surviving_links(updated), "the surviving switch must keep its host cable"
    assert "?" not in {end for pair in _surviving_links(updated) for end in pair}, (
        "no link may reference a device that was pruned"
    )
