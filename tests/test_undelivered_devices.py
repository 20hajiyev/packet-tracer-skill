"""Generation must say when the file is short of what the plan asked for.

`2 router serial WAN, 2 switch, 8 komputer, 1 server, VLAN ve DHCP ile` was
parsed correctly and planned correctly: thirteen devices in the blueprint. The
written file held three -- two routers and one switch -- with the eight PCs and
the server absent, and generation reported success.

Of the three possible outcomes that is the worst. A refusal explains itself. A
working lab needs no explanation. A lab quietly missing most of the request
looks like the tool worked.

Auditing the corpus found four labs short by one device each, always a switch
that kept its donor name instead of being renamed, and that number moves with
donor selection. So this reports rather than refuses: failing labs that open
and mostly serve the prompt would cost more than it saves.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_pkt import _report_undelivered_devices  # noqa: E402


def _file_with(names: list[str]) -> ET.Element:
    root = ET.fromstring("<PACKETTRACER5><NETWORK><DEVICES/></NETWORK></PACKETTRACER5>")
    devices = root.find(".//DEVICES")
    assert devices is not None
    for name in names:
        device = ET.fromstring("<DEVICE><ENGINE><NAME/></ENGINE></DEVICE>")
        device.find("./ENGINE/NAME").text = name
        devices.append(device)
    return root


def _blueprint(names: list[str]) -> dict[str, object]:
    return {"devices": [{"name": name, "kind": "PC"} for name in names]}


def test_a_complete_lab_says_nothing() -> None:
    assert _report_undelivered_devices(_file_with(["R1", "SW1"]), _blueprint(["R1", "SW1"])) == []


def test_the_missing_devices_are_named() -> None:
    notes = _report_undelivered_devices(
        _file_with(["R1", "R2", "SW1"]),
        _blueprint(["R1", "R2", "SW1", "SW2", "PC1", "SERVER1"]),
    )
    assert len(notes) == 1
    assert "3 of 6 planned device(s)" in notes[0]
    assert "PC1" in notes[0] and "SW2" in notes[0] and "SERVER1" in notes[0]


def test_a_long_list_is_cut_short_but_counted() -> None:
    planned = ["R1"] + [f"PC{index}" for index in range(1, 13)]
    notes = _report_undelivered_devices(_file_with(["R1"]), _blueprint(planned))
    assert "12 of 13 planned device(s)" in notes[0]
    assert "and 4 more" in notes[0]


def test_extra_devices_in_the_file_are_not_a_shortfall() -> None:
    """Donor leftovers stay in the file on purpose; they are not a missing device."""
    notes = _report_undelivered_devices(
        _file_with(["R1", "SW1", "Power Distribution Device0"]),
        _blueprint(["R1", "SW1"]),
    )
    assert notes == []


def test_a_blueprint_with_no_devices_reports_nothing() -> None:
    assert _report_undelivered_devices(_file_with(["R1"]), {"devices": []}) == []
