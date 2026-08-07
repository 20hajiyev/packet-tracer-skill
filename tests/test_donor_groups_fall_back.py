"""Prefix grouping only counts when the prefixes actually gather hosts.

Donor switch groups are found by name prefix: a switch named `IDR-SW` anchors
the group `IDR`, and `IDR-PC1` joins it. A donor named the other way round --
switches `SW-IDR`, `SW-MUH`, `SW-IT`, `SW-SAT`, `SW-ANB`, hosts `PC-IDR1` and
`SRV-IDR` -- collapses all five switches into one group called `SW` that holds
nothing at all, because the hosts' prefixes are `PC` and `SRV`.

That empty group then counted as a result, so the link-based fallback below it
never ran, and it is the fallback that groups such a donor correctly. Measured
on a 48-device lab built for exactly this purpose: every request for five
switch groups was refused with "no ranked donor candidate passed donor-prune
compatibility validation ... group 'SW' has 0 PC device(s)", while the donor on
disk had five groups carrying three PCs and a server each. With the fallback
reached, the same donor yields seven groups.

Only the all-empty case falls through. A donor with a spare switch alongside
populated groups keeps every group it had, because a topology may need that
switch.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_pkt import _collect_donor_groups  # noqa: E402


def _lab(devices: list[tuple[str, str]], cables: list[tuple[str, str]]) -> ET.Element:
    root = ET.fromstring("<PACKETTRACER5><NETWORK><DEVICES/><LINKS/></NETWORK></PACKETTRACER5>")
    container = root.find(".//DEVICES")
    assert container is not None
    for name, kind in devices:
        device = ET.fromstring(
            "<DEVICE><ENGINE><NAME/><TYPE/><SAVE_REF_ID/><MODULE><SLOT/></MODULE>"
            "<RUNNINGCONFIG/></ENGINE></DEVICE>"
        )
        device.find("./ENGINE/NAME").text = name
        device.find("./ENGINE/TYPE").text = kind
        device.find("./ENGINE/SAVE_REF_ID").text = f"ref-{name}"
        container.append(device)
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


def _department_first_lab() -> ET.Element:
    """The convention that already worked: `IDR-SW` with `IDR-PC1`."""
    return _lab(
        [("IDR-SW", "Switch"), ("IDR-PC1", "PC"), ("IDR-PC2", "PC"), ("IDR-SRV1", "Server")],
        [("IDR-PC1", "IDR-SW"), ("IDR-PC2", "IDR-SW"), ("IDR-SRV1", "IDR-SW")],
    )


def _switch_first_lab() -> ET.Element:
    """The naming that produced one empty group named `SW`."""
    devices = [("SW-IDR", "Switch"), ("SW-MUH", "Switch")]
    cables = []
    for department in ("IDR", "MUH"):
        for index in (1, 2, 3):
            devices.append((f"PC-{department}{index}", "PC"))
            cables.append((f"PC-{department}{index}", f"SW-{department}"))
        devices.append((f"SRV-{department}", "Server"))
        cables.append((f"SRV-{department}", f"SW-{department}"))
    return _lab(devices, cables)


def _members_by_type(group: dict) -> dict[str, int]:
    counted: dict[str, int] = {}
    for member in group["members"]:
        counted[str(member["type"])] = counted.get(str(member["type"]), 0) + 1
    return counted


def test_switch_first_naming_yields_a_group_per_switch() -> None:
    groups = _collect_donor_groups(_switch_first_lab())
    assert len(groups) == 2, "all five switches used to collapse into one empty group"
    assert {str(group["group_name"]) for group in groups} == {"SW-IDR", "SW-MUH"}


def test_each_of_those_groups_carries_its_own_hosts() -> None:
    groups = _collect_donor_groups(_switch_first_lab())
    for group in groups:
        assert _members_by_type(group) == {"PC": 3, "Server": 1}


def test_the_working_convention_is_untouched() -> None:
    groups = _collect_donor_groups(_department_first_lab())
    assert [str(group["group_name"]) for group in groups] == ["IDR"]
    assert _members_by_type(groups[0]) == {"PC": 2, "Server": 1}


def test_a_spare_switch_alongside_a_populated_group_is_kept() -> None:
    """Only the all-empty case falls through; a topology may need that switch."""
    lab = _lab(
        [("IDR-SW", "Switch"), ("IDR-PC1", "PC"), ("SPARE-SW", "Switch")],
        [("IDR-PC1", "IDR-SW")],
    )
    names = {str(group["group_name"]) for group in _collect_donor_groups(lab)}
    assert names == {"IDR", "SPARE"}
