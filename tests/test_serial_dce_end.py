"""A serial cable has a clocking end, and the file has to say which.

Packet Tracer records it as `DCEDEV` and `DCEPORT` on the cable. Every serial
link in every donor carries both; links this generator built carried neither.

That was the whole reason a lab with a WAN was refused. Measured by holding the
topology fixed and changing one thing at a time against the same base:

    control: no second cable   -> opened
    serial 2/0 <-> 2/0         -> refused
    serial 3/0 <-> 3/0         -> refused
    serial 2/0 <-> 3/0         -> refused
    copper R1 <-> R2           -> opened
    copper R1 <-> SW1          -> opened

So not the ports -- all three serial pairs refuse -- and not the second router
being cabled, since the identical topology over copper opens. The medium was
the only variable left. Adding `DCEDEV` and `DCEPORT` to the refused file opens
it, and the lab that had been refused since this work began now opens with
`Serial3/0 <-> Serial2/0` carrying its WAN.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_pkt import _declare_serial_dce_ends  # noqa: E402


def _lab(link_type: str, *, dce: tuple[str, str] | None = None) -> ET.Element:
    root = ET.fromstring(
        """
        <PACKETTRACER5>
          <NETWORK>
            <DEVICES/>
            <LINKS>
              <LINK>
                <TYPE/>
                <CABLE>
                  <FROM>ref-r1</FROM>
                  <PORT>Serial3/0</PORT>
                  <TO>ref-r2</TO>
                  <PORT>Serial2/0</PORT>
                  <TO_PORT_MEM_ADDR>123</TO_PORT_MEM_ADDR>
                  <GEO_VIEW_COLOR>#6ba72e</GEO_VIEW_COLOR>
                </CABLE>
              </LINK>
            </LINKS>
          </NETWORK>
        </PACKETTRACER5>
        """
    )
    root.find(".//LINK/TYPE").text = link_type
    if dce is not None:
        cable = root.find(".//LINK/CABLE")
        ET.SubElement(cable, "DCEDEV").text = dce[0]
        ET.SubElement(cable, "DCEPORT").text = dce[1]
    return root


def _cable(root: ET.Element) -> ET.Element:
    cable = root.find(".//LINK/CABLE")
    assert cable is not None
    return cable


def test_a_serial_cable_gets_a_clocking_end() -> None:
    root = _lab("eSerial")
    assert _declare_serial_dce_ends(root)
    cable = _cable(root)
    # The FROM end, which is what every donor serial link names.
    assert cable.findtext("DCEDEV") == "ref-r1"
    assert cable.findtext("DCEPORT") == "Serial3/0"


def test_the_clocking_end_lands_where_donors_put_it() -> None:
    """Position matters: donors carry it after the memory-address fields."""
    root = _lab("eSerial")
    _declare_serial_dce_ends(root)
    tags = [child.tag for child in _cable(root)]
    assert tags.index("TO_PORT_MEM_ADDR") < tags.index("DCEDEV") < tags.index("DCEPORT")


def test_a_copper_cable_is_left_without_one() -> None:
    root = _lab("eCopper")
    assert _declare_serial_dce_ends(root) == []
    cable = _cable(root)
    assert cable.find("DCEDEV") is None
    assert cable.find("DCEPORT") is None


def test_a_cable_demoted_to_copper_loses_its_clocking_end() -> None:
    """`_reconcile_cable_media` can turn a serial cable into a copper one."""
    root = _lab("eCopper", dce=("ref-r1", "Serial3/0"))
    assert _declare_serial_dce_ends(root)
    cable = _cable(root)
    assert cable.find("DCEDEV") is None
    assert cable.find("DCEPORT") is None


def test_an_existing_clocking_end_is_left_alone() -> None:
    root = _lab("eSerial", dce=("ref-r2", "Serial2/0"))
    assert _declare_serial_dce_ends(root) == []
    cable = _cable(root)
    assert cable.findtext("DCEDEV") == "ref-r2"
    assert cable.findtext("DCEPORT") == "Serial2/0"


def test_running_it_twice_changes_nothing_the_second_time() -> None:
    root = _lab("eSerial")
    _declare_serial_dce_ends(root)
    before = ET.tostring(_cable(root))
    assert _declare_serial_dce_ends(root) == []
    assert ET.tostring(_cable(root)) == before
