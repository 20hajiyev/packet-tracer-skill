"""A donor owning serial routers is not the same as a lab carrying serial.

Five donors were probed by generating a leased-line lab from each and opening
the result in Packet Tracer. Two of the five owned serial-capable routers and
still came out entirely over copper, because pruning dropped the cable that
used the serial ports. Every count taken from the donor -- serial routers,
serial routers also facing a switch, router-to-router serial pairs -- was
identical between the donor that produced a serial WAN and the ones that did
not, so the donor cannot be asked. The built lab can.

Asking it takes care. A lab pruned from the saved six-department lab was measured holding
an `eSerial` cable whose ends were `GigabitEthernet0/0/1` and
`GigabitEthernet0/0/0`. `_reconcile_cable_media` demoted it to copper further
down the pipeline -- correctly, since Packet Tracer will not open a serial
cable in an Ethernet socket -- so counting the `eSerial` tag alone reported a
WAN that no longer existed by the time the file was written.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_pkt import _reconcile_cable_media, _root_has_serial_link  # noqa: E402
from pkt_transformer import port_capacity  # noqa: E402


def _lab(cables: list[tuple[str, str, str]]) -> ET.Element:
    """Two routers whose serial interfaces are `Serial2/0` and `Serial3/0`.

    Each cable is `(link type, port on one end, port on the other)`, joining
    the two routers.
    """
    root = ET.fromstring(
        """
        <PACKETTRACER5>
          <NETWORK>
            <DEVICES/>
            <LINKS/>
          </NETWORK>
        </PACKETTRACER5>
        """
    )
    devices = root.find(".//DEVICES")
    assert devices is not None
    for index, name in enumerate(("R1", "R2")):
        device = ET.fromstring(
            """
            <DEVICE>
              <ENGINE>
                <NAME/>
                <TYPE>Router</TYPE>
                <SAVE_REF_ID/>
                <SLOT>
                  <MODULE>
                    <PORT><TYPE>eSerial</TYPE><NAME>Serial2/0</NAME></PORT>
                  </MODULE>
                  <MODULE>
                    <PORT><TYPE>eSerial</TYPE><NAME>Serial3/0</NAME></PORT>
                  </MODULE>
                </SLOT>
                <RUNNINGCONFIG>
                  <LINE>interface Serial2/0</LINE>
                  <LINE>interface Serial3/0</LINE>
                </RUNNINGCONFIG>
              </ENGINE>
            </DEVICE>
            """
        )
        device.find("./ENGINE/NAME").text = name
        device.find("./ENGINE/SAVE_REF_ID").text = f"ref-{index}"
        devices.append(device)

    links = root.find(".//LINKS")
    assert links is not None
    for link_type, port_a, port_b in cables:
        link = ET.SubElement(links, "LINK")
        ET.SubElement(link, "TYPE").text = link_type
        cable = ET.SubElement(link, "CABLE")
        ET.SubElement(cable, "FROM").text = "ref-0"
        ET.SubElement(cable, "PORT").text = port_a
        ET.SubElement(cable, "TO").text = "ref-1"
        ET.SubElement(cable, "PORT").text = port_b
    return root


def test_serial_hardware_does_not_count_as_a_serial_link() -> None:
    router = _lab([]).find(".//DEVICES/DEVICE")
    assert router is not None
    # The router really can carry serial -- this is the signal the selector
    # used to trust.
    assert port_capacity(router).get("Serial", 0) > 0
    # And the lab built around it still has no serial cable in it.
    copper_only = _lab(
        [
            ("eCopper", "GigabitEthernet0/0/0", "GigabitEthernet0/1"),
            ("eCopper", "GigabitEthernet0/0/1", "FastEthernet0"),
        ]
    )
    assert _root_has_serial_link(copper_only) is False


def test_a_serial_cable_between_serial_ports_counts() -> None:
    lab = _lab(
        [
            ("eCopper", "GigabitEthernet0/0/0", "GigabitEthernet0/1"),
            ("eSerial", "Serial2/0", "Serial3/0"),
        ]
    )
    assert _root_has_serial_link(lab) is True


def test_a_serial_cable_on_ports_the_routers_do_not_have_does_not_count() -> None:
    """Measured on a lab pruned from the saved serial-WAN lab.

    The cable read `Serial0/0/0 <-> Serial0/0/0` while both routers owned only
    `Serial2/0` and `Serial3/0`. `port_exists` accepts the name, so counting it
    let the selector commit to a donor whose WAN was wired to nothing.
    """
    lab = _lab([("eSerial", "Serial0/0/0", "Serial0/0/0")])
    assert _root_has_serial_link(lab) is False


def test_a_serial_cable_in_an_ethernet_socket_does_not_count() -> None:
    """The case that made the first version of this check report a phantom WAN.

    Counting it would let the selector settle on a donor whose serial link is
    about to be demoted to copper by media reconciliation.
    """
    lab = _lab([("eSerial", "GigabitEthernet0/0/1", "GigabitEthernet0/0/0")])
    assert _root_has_serial_link(lab) is False
    # And reconciliation is what removes it, so the check agrees with the file
    # that eventually gets written.
    assert _reconcile_cable_media(lab) == [
        "GigabitEthernet0/0/1 <-> GigabitEthernet0/0/0: eSerial -> eCopper"
    ]
    assert _root_has_serial_link(lab) is False


def test_a_lab_with_no_links_at_all_carries_no_serial() -> None:
    assert _root_has_serial_link(_lab([])) is False
