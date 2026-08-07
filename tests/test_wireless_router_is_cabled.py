"""A home router's LAN ports stop before its socket count says they do.

The device carries five copper gigabit PORT nodes and Packet Tracer names four
of them: `GigabitEthernet 1` .. `GigabitEthernet 4`, plus `Internet` for the
WAN. Counting the sockets and numbering them all put a cable on
`GigabitEthernet 5`, and Packet Tracer refused the file.

Nothing else could have caught it. The device lists no interfaces in its own
configuration, so the naming-shape check had nothing to compare against and the
count said five ports, index five, yes. This is the same defect shape as every
other one here: two models of one concept, the socket count and the port names,
disagreeing where nothing looks.

Port evidence comes from 348 saved labs -- twenty cables on `GigabitEthernet 1`
.. `4` of the new-generation model, two on `Ethernet 1` .. `4` of the older
Linksys, and fourteen on `Internet`, every one of those an uplink.

The labs that motivated this are still uncabled: `wireless_home` and
`wireless_ssid` ship two laptops and a router with no path between them, 0/4
twice over. Cabling them live in Packet Tracer takes Laptop1 to Laptop2 to 3/4,
so the topology is right, but writing those links from the generator produces a
lab Packet Tracer refuses -- see `_synthesize_links` for where that stopped.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from pkt_transformer import port_exists  # noqa: E402


def _home_router(sockets: int = 5) -> ET.Element:
    """A home router as its file records it: `sockets` copper gigabit PORT nodes.

    One of them is the WAN port. Nothing in the device says which, and the
    device lists no interfaces in its configuration at all.
    """
    device = ET.fromstring(
        "<DEVICE><ENGINE><NAME>WRT1</NAME><TYPE>WirelessRouterNewGeneration</TYPE>"
        "<MODULE><SLOT/></MODULE><RUNNINGCONFIG/></ENGINE></DEVICE>"
    )
    slot = device.find("./ENGINE/MODULE/SLOT")
    assert slot is not None
    for _ in range(sockets):
        module = ET.SubElement(slot, "MODULE")
        port = ET.SubElement(module, "PORT")
        ET.SubElement(port, "TYPE").text = "eCopperGigabitEthernet"
    return device


def test_the_lan_ports_stop_where_the_hardware_does() -> None:
    """Five sockets, four LAN ports -- `GigabitEthernet 5` is the refusal."""
    router = _home_router()
    assert port_exists(router, "GigabitEthernet 1") is True
    assert port_exists(router, "GigabitEthernet 4") is True
    assert port_exists(router, "GigabitEthernet 5") is False


def test_the_lan_ports_do_not_start_at_zero() -> None:
    """Unlike a hub, this device counts from one."""
    assert port_exists(_home_router(), "GigabitEthernet 0") is False


def test_the_wan_port_is_still_a_real_port() -> None:
    """It exists; it is only the wrong place for a host."""
    assert port_exists(_home_router(), "Internet") is True


def test_the_older_model_numbers_its_ports_the_same_way() -> None:
    router = _home_router()
    router.find("./ENGINE/TYPE").text = "WirelessRouter"
    assert port_exists(router, "GigabitEthernet 4") is True
    assert port_exists(router, "GigabitEthernet 5") is False


def test_a_router_with_one_socket_has_no_lan_port_at_all() -> None:
    """The WAN port takes the only one, and `max()` keeps the range empty."""
    assert port_exists(_home_router(sockets=1), "GigabitEthernet 1") is False
