#!/usr/bin/env python3
"""Notes, frames and shapes on the logical workspace.

Packet Tracer's drawing tools are part of what makes a large lab readable: a
labelled frame around each building, a coloured box behind the server farm, a
note explaining what the topology demonstrates. None of that was reachable from
this skill.

Formats measured from Cisco's own bundled labs rather than guessed:

    <RECTANGLE>                       <NOTE>
      <TopLeftX>64</TopLeftX>           <X>547</X>
      <TopLeftY>174</TopLeftY>          <Y>329</Y>
      <BottomRightX>546</BottomRightX>  <Z>40001</Z>
      <BottomRightY>397</BottomRightY>  <TEXT translate="true">...</TEXT>
      <Color>                           <NOTECLUSTERID>1-1</NOTECLUSTERID>
        <Red>0</Red>                  </NOTE>
        <Green>0</Green>
        <Blue>0</Blue>
      </Color>
      <Filled>0</Filled>
      <RECTCLUSTERID>1-1</RECTCLUSTERID>
    </RECTANGLE>

`Color` is the outline; `Filled` decides whether the interior is painted with
it. Ellipses share the shape exactly, with `ELLIPSECLUSTERID`. The containers --
`RECTANGLES`, `ELLIPSES`, `LINES`, `NOTES` -- sit directly under the document
root, not inside a device.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

# Cluster ids group annotations with a logical-workspace cluster. `1-1` is the
# root cluster, which is what an unclustered lab uses throughout.
ROOT_CLUSTER = "1-1"

# A small named palette, because "qirmizi" is easier to write than an RGB triple.
COLORS: dict[str, tuple[int, int, int]] = {
    "black": (0, 0, 0),
    "white": (255, 255, 255),
    "red": (220, 60, 60),
    "green": (60, 180, 90),
    "blue": (70, 120, 220),
    "yellow": (250, 215, 80),
    "orange": (245, 150, 60),
    "purple": (160, 100, 210),
    "grey": (150, 150, 150),
    "gray": (150, 150, 150),
    "lightblue": (170, 170, 255),
    "lightgreen": (190, 235, 200),
    "lightyellow": (255, 245, 190),
}
# Azerbaijani names for the same palette, so a prompt can say `qirmizi cerceve`.
COLORS.update({
    "qara": COLORS["black"], "ag": COLORS["white"], "qirmizi": COLORS["red"],
    "yasil": COLORS["green"], "mavi": COLORS["blue"], "sari": COLORS["yellow"],
    "narinci": COLORS["orange"], "benovseyi": COLORS["purple"], "boz": COLORS["grey"],
})


def resolve_color(name: str | tuple[int, int, int] | None) -> tuple[int, int, int]:
    """A colour name, an RGB triple, or black."""
    if isinstance(name, (tuple, list)) and len(name) == 3:
        return tuple(max(0, min(255, int(part))) for part in name)  # type: ignore[return-value]
    return COLORS.get(str(name or "").strip().lower(), COLORS["black"])


def _container(root: ET.Element, tag: str) -> ET.Element:
    """The document-level container for a kind of annotation, created if absent."""
    node = root.find(tag)
    if node is None:
        node = ET.SubElement(root, tag)
    return node


def _color_node(parent: ET.Element, color: tuple[int, int, int]) -> None:
    node = ET.SubElement(parent, "Color")
    for channel, value in zip(("Red", "Green", "Blue"), color):
        ET.SubElement(node, channel).text = str(int(value))


def add_rectangle(
    root: ET.Element,
    top_left: tuple[float, float],
    bottom_right: tuple[float, float],
    *,
    color: str | tuple[int, int, int] = "black",
    filled: bool = False,
) -> ET.Element:
    """A frame. `filled` paints the interior in the same colour."""
    rectangles = _container(root, "RECTANGLES")
    rectangle = ET.SubElement(rectangles, "RECTANGLE")
    ET.SubElement(rectangle, "TopLeftX").text = str(top_left[0])
    ET.SubElement(rectangle, "TopLeftY").text = str(top_left[1])
    ET.SubElement(rectangle, "BottomRightX").text = str(bottom_right[0])
    ET.SubElement(rectangle, "BottomRightY").text = str(bottom_right[1])
    _color_node(rectangle, resolve_color(color))
    ET.SubElement(rectangle, "Filled").text = "1" if filled else "0"
    ET.SubElement(rectangle, "RECTCLUSTERID").text = ROOT_CLUSTER
    return rectangle


def add_ellipse(
    root: ET.Element,
    top_left: tuple[float, float],
    bottom_right: tuple[float, float],
    *,
    color: str | tuple[int, int, int] = "black",
    filled: bool = False,
) -> ET.Element:
    ellipses = _container(root, "ELLIPSES")
    ellipse = ET.SubElement(ellipses, "ELLIPSE")
    ET.SubElement(ellipse, "TopLeftX").text = str(top_left[0])
    ET.SubElement(ellipse, "TopLeftY").text = str(top_left[1])
    ET.SubElement(ellipse, "BottomRightX").text = str(bottom_right[0])
    ET.SubElement(ellipse, "BottomRightY").text = str(bottom_right[1])
    _color_node(ellipse, resolve_color(color))
    ET.SubElement(ellipse, "Filled").text = "1" if filled else "0"
    ET.SubElement(ellipse, "ELLIPSECLUSTERID").text = ROOT_CLUSTER
    return ellipse


def add_line(
    root: ET.Element,
    start: tuple[float, float],
    end: tuple[float, float],
    *,
    color: str | tuple[int, int, int] = "black",
) -> ET.Element:
    """A straight line. Stored with the same corner fields as a rectangle."""
    lines = _container(root, "LINES")
    line = ET.SubElement(lines, "LINE")
    ET.SubElement(line, "TopLeftX").text = str(start[0])
    ET.SubElement(line, "TopLeftY").text = str(start[1])
    ET.SubElement(line, "BottomRightX").text = str(end[0])
    ET.SubElement(line, "BottomRightY").text = str(end[1])
    _color_node(line, resolve_color(color))
    ET.SubElement(line, "Filled").text = "0"
    ET.SubElement(line, "LINECLUSTERID").text = ROOT_CLUSTER
    return line


def add_note(root: ET.Element, position: tuple[float, float], text: str, *, z: int = 40001) -> ET.Element:
    """A text note. `Z` sits above the devices so the note stays readable."""
    notes = _container(root, "NOTES")
    note = ET.SubElement(notes, "NOTE")
    ET.SubElement(note, "X").text = str(position[0])
    ET.SubElement(note, "Y").text = str(position[1])
    ET.SubElement(note, "Z").text = str(z)
    text_node = ET.SubElement(note, "TEXT")
    text_node.set("translate", "true")
    text_node.text = text
    ET.SubElement(note, "NOTECLUSTERID").text = ROOT_CLUSTER
    return note


def clear_annotations(root: ET.Element) -> None:
    """Drop every annotation, so a regenerated lab does not inherit stale ones."""
    for tag in ("RECTANGLES", "ELLIPSES", "LINES", "POLYGONS"):
        node = root.find(tag)
        if node is not None:
            root.remove(node)
    notes = root.find("NOTES")
    if notes is not None:
        root.remove(notes)
