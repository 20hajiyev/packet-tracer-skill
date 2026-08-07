"""A new cable is cloned from one the file already has -- unless it has none.

`_ensure_link` copies an existing link and rewrites its endpoints. When the
file has no link to copy, the fallback was a cable from the bundled `FTP.pkt`,
and that sample predates the fields a 9.x cable carries: it names its devices
by index rather than by `save-ref-id`, and has no `FUNCTIONAL`,
`GEO_VIEW_COLOR` or `IS_MANAGED_IN_RACK_VIEW`.

Measured, with the same writer, the same ports and the same devices, the only
difference being which cable was cloned:

  minimal        4 links -> 5   opened     (a cable to copy)
  wireless_home  0 links -> 1   refused    (no cable to copy)
  wireless_home  0 links -> 2   opened     (with a modern prototype)

and the repaired lab pings: Laptop1 to Laptop2 4/4, after the first ping loses
its packets to cold ARP.

This is what made both wireless labs ship uncabled, and it cost a false lead
first: a hand-built LINK element was refused everywhere it was added, including
in `minimal`, which opens -- so that bisect was only ever measuring its own XML.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import pkt_editor  # noqa: E402
from pkt_editor import _fallback_link_prototype, _first_link_prototype  # noqa: E402

MODERN_CABLE_FIELDS = ("FUNCTIONAL", "GEO_VIEW_COLOR", "IS_MANAGED_IN_RACK_VIEW")


def _cable(link: ET.Element) -> ET.Element:
    cable = link.find("./CABLE")
    assert cable is not None
    return cable


def test_the_fallback_carries_what_a_modern_cable_carries() -> None:
    prototype = _fallback_link_prototype()
    assert prototype is not None
    cable = _cable(prototype)
    missing = [field for field in MODERN_CABLE_FIELDS if cable.find(field) is None]
    assert not missing, f"the cloned cable would be missing {missing}"


def test_the_fallback_refers_to_devices_the_way_a_saved_lab_does() -> None:
    """The old sample used bare indices; `save-ref-id` is what 9.x writes."""
    cable = _cable(_fallback_link_prototype())
    assert (cable.findtext("FROM") or "").startswith("save-ref-id:")


def test_a_file_with_its_own_cable_is_still_preferred() -> None:
    """The fallback is for files with nothing to copy, not a replacement."""
    root = ET.fromstring(
        "<PACKETTRACER5><NETWORK><LINKS><LINK><CABLE>"
        "<FROM>save-ref-id:1</FROM><PORT>FastEthernet0</PORT>"
        "<TO>save-ref-id:2</TO><PORT>FastEthernet0/1</PORT>"
        "<FUNCTIONAL>true</FUNCTIONAL><GEO_VIEW_COLOR>#000000</GEO_VIEW_COLOR>"
        "<IS_MANAGED_IN_RACK_VIEW>false</IS_MANAGED_IN_RACK_VIEW>"
        "</CABLE></LINK></LINKS></NETWORK></PACKETTRACER5>"
    )
    assert _first_link_prototype(root) is not None


def test_an_empty_file_has_nothing_to_copy() -> None:
    """Which is the case the fallback exists for."""
    root = ET.fromstring("<PACKETTRACER5><NETWORK><LINKS/></NETWORK></PACKETTRACER5>")
    assert _first_link_prototype(root) is None


def test_the_prototype_is_read_once() -> None:
    """Decoding a donor per link would cost a lab with sixty of them dearly."""
    assert hasattr(pkt_editor._modern_link_prototype_xml, "cache_info")


def test_each_caller_gets_its_own_copy() -> None:
    """It is cloned and then mutated, so a shared element would corrupt the next."""
    first = _fallback_link_prototype()
    _cable(first).find("FROM").text = "save-ref-id:changed"
    second = _fallback_link_prototype()
    assert (_cable(second).findtext("FROM") or "") != "save-ref-id:changed"
