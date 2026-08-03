"""Notes, frames and shapes on the logical workspace.

Formats are measured from Cisco's own bundled labs, not guessed: a rectangle in
`Ipsec2.pkt` and an ellipse in `Outside_Nat.pkt` gave the field names and the
`Color`/`Filled` shape.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from pkt_annotate import (  # noqa: E402
    add_ellipse,
    add_line,
    add_note,
    add_rectangle,
    clear_annotations,
    resolve_color,
)


def _root() -> ET.Element:
    return ET.Element("PACKETTRACER5")


def test_a_rectangle_matches_the_shape_cisco_writes() -> None:
    root = _root()
    add_rectangle(root, (64, 174), (546, 397), color="black")

    rectangle = root.find("RECTANGLES/RECTANGLE")
    assert rectangle is not None
    assert rectangle.findtext("TopLeftX") == "64"
    assert rectangle.findtext("BottomRightY") == "397"
    assert rectangle.findtext("Color/Red") == "0"
    assert rectangle.findtext("Filled") == "0"
    assert rectangle.findtext("RECTCLUSTERID") == "1-1"


def test_filled_paints_the_interior() -> None:
    """`Filled` is what separates a frame from a coloured panel."""
    root = _root()
    add_rectangle(root, (0, 0), (10, 10), color="red", filled=True)
    add_rectangle(root, (20, 0), (30, 10), color="red", filled=False)

    flags = [node.findtext("Filled") for node in root.findall("RECTANGLES/RECTANGLE")]
    assert flags == ["1", "0"]


def test_an_ellipse_uses_its_own_cluster_tag() -> None:
    root = _root()
    add_ellipse(root, (395, 202), (462, 240), color="lightblue", filled=True)

    ellipse = root.find("ELLIPSES/ELLIPSE")
    assert ellipse is not None
    assert ellipse.findtext("ELLIPSECLUSTERID") == "1-1"
    assert ellipse.findtext("Color/Blue") == "255"


def test_a_note_carries_its_text_and_sits_above_the_devices() -> None:
    """Notes live under PHYSICALWORKSPACE despite showing on the logical view.

    Written at the document root, Packet Tracer moved them and emptied the text,
    parking each one at the 50000,50000 sentinel -- which is why none of
    thirteen notes appeared in the first attempt.
    """
    root = _root()
    add_note(root, (150, 170), "Ofis sebekesi\nVLAN 10")

    note = root.find("PHYSICALWORKSPACE/NOTES/NOTE")
    assert note is not None
    assert note.findtext("TEXT") == "Ofis sebekesi\nVLAN 10"
    assert note.find("TEXT").get("translate") == "true"
    assert int(note.findtext("Z") or 0) > 40000


def test_lines_use_start_and_end_not_corners() -> None:
    """A line is not a rectangle.

    Written with the rectangle's corner fields, Packet Tracer read the file,
    rewrote every line into Start/End and dropped them from the view.
    """
    root = _root()
    add_line(root, (10, 20), (300, 40), color="red")

    line = root.find("LINES/LINE")
    assert line is not None
    assert line.findtext("StartX") == "10"
    assert line.findtext("EndY") == "40"
    assert line.find("TopLeftX") is None
    assert line.find("Filled") is None
    assert line.findtext("LINECLUSTERID") == "1-1"


def test_a_filled_shape_can_carry_a_separate_outline_colour() -> None:
    """`Filled` holds the border as attributes, which the first version missed."""
    root = _root()
    add_rectangle(root, (0, 0), (10, 10), color="lightblue", filled=True, outline="blue")

    filled = root.find("RECTANGLES/RECTANGLE/Filled")
    assert filled is not None
    assert filled.text == "1"
    assert filled.get("OUTLINED") == "true"
    assert filled.get("OUTLINECOLOR") == "#4678dc"


def test_an_unoutlined_shape_says_so_explicitly() -> None:
    root = _root()
    add_rectangle(root, (0, 0), (10, 10), color="red", filled=True)

    filled = root.find("RECTANGLES/RECTANGLE/Filled")
    assert filled.get("OUTLINED") == "false"


def test_colours_can_be_named_in_either_language_or_given_as_rgb() -> None:
    assert resolve_color("red") == resolve_color("qirmizi")
    assert resolve_color("mavi") == resolve_color("blue")
    assert resolve_color((12, 34, 56)) == (12, 34, 56)
    assert resolve_color("no-such-colour") == (0, 0, 0)


def test_clearing_removes_inherited_drawings() -> None:
    """A donor's frames were drawn for the donor's layout.

    Keeping them boxes the wrong devices, so a regenerated lab starts clean.
    """
    root = _root()
    add_rectangle(root, (0, 0), (10, 10))
    add_ellipse(root, (0, 0), (10, 10))
    add_note(root, (0, 0), "stale")

    clear_annotations(root)

    assert root.find("RECTANGLES") is None
    assert root.find("ELLIPSES") is None
    assert root.find("PHYSICALWORKSPACE/NOTES") is None


def test_annotation_failure_never_stops_generation() -> None:
    """A wireless lab has no switches, and dividing by that emptiness took the
    whole generation down. Decoration is not worth a refusal."""
    from generate_pkt import _annotate_generated_lab
    from intent_parser import parse_intent

    plan = parse_intent("1 wireless router 2 laptop qur")
    # No devices carry coordinates, and there are no switches to group by.
    _annotate_generated_lab(_root(), {"devices": []}, plan)
