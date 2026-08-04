"""Tests for real interface counting.

A generated link that names a port the device does not have makes Packet Tracer
reject the entire file with "not compatible with this version" — observed when
an allocator incremented past `GigabitEthernet0/2` on a 2960-24TT, which has
exactly two gigabit interfaces.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from pkt_transformer import port_capacity, port_exists  # noqa: E402


def _device(device_type: str, fast: int, gig: int, serial: int = 0) -> ET.Element:
    device = ET.Element("DEVICE")
    engine = ET.SubElement(device, "ENGINE")
    ET.SubElement(engine, "NAME").text = "D1"
    ET.SubElement(engine, "TYPE").text = device_type
    modules = ET.SubElement(engine, "MODULE")
    slot = ET.SubElement(modules, "SLOT")
    for _ in range(fast):
        port = ET.SubElement(slot, "PORT")
        ET.SubElement(port, "TYPE").text = "eCopperFastEthernet"
    for _ in range(gig):
        port = ET.SubElement(slot, "PORT")
        ET.SubElement(port, "TYPE").text = "eCopperGigabitEthernet"
    for _ in range(serial):
        port = ET.SubElement(slot, "PORT")
        ET.SubElement(port, "TYPE").text = "eSerial"
    return device


def test_capacity_counts_each_interface_kind() -> None:
    # `Serial` joined the count when serial links needed a real answer.
    assert port_capacity(_device("Switch", fast=24, gig=2)) == {
        "Serial": 0,
        "FastEthernet": 24,
        "GigabitEthernet": 2,
    }


@pytest.mark.parametrize(
    "port_name,expected",
    [
        ("FastEthernet0/1", True),
        ("FastEthernet0/24", True),
        ("FastEthernet0/25", False),
        ("GigabitEthernet0/1", True),
        ("GigabitEthernet0/2", True),
        ("GigabitEthernet0/3", False),
    ],
)
def test_switch_ports_are_one_indexed(port_name: str, expected: bool) -> None:
    assert port_exists(_device("Switch", fast=24, gig=2), port_name) is expected


@pytest.mark.parametrize(
    "port_name,expected",
    [
        ("GigabitEthernet0/0", True),
        ("GigabitEthernet0/1", True),
        ("GigabitEthernet0/2", False),
    ],
)
def test_router_ports_are_zero_indexed(port_name: str, expected: bool) -> None:
    assert port_exists(_device("Router", fast=0, gig=2), port_name) is expected


def test_a_device_with_no_gigabit_has_none() -> None:
    device = _device("Switch", fast=24, gig=0)

    assert port_capacity(device)["GigabitEthernet"] == 0
    assert not port_exists(device, "GigabitEthernet0/1")


def test_unmodelled_port_kinds_are_not_refuted() -> None:
    """Serial, wireless and vendor-specific names are outside this module.

    Measured across the local labs: 33 of 782 real link endpoints used names
    this file does not model -- `Serial2/0` on a router, `Port 0` on an access
    point, `RS 232` on a laptop, the `Switch` pass-through on an IP phone.
    Calling those missing is the damaging direction, because a legitimate link
    then gets dropped. Only the two Ethernet families are judged; anything else
    is reported as not refuted.
    """
    device = _device("Switch", fast=24, gig=2)

    # Serial is modelled now, so a device with no serial card gets a real "no".
    # Letting it through produced a WAN lab whose PPP configuration sat on an
    # interface that was never cabled.
    assert not port_exists(device, "Serial2/0")
    assert port_exists(_device("Router", fast=0, gig=2, serial=2), "Serial0/0/0")
    # Families this module does not model stay "not refuted".
    assert port_exists(device, "Port 0")
    # The Ethernet families are still checked strictly.
    assert not port_exists(device, "FastEthernet0/99")

def test_a_full_interface_name_survives_canonicalisation() -> None:
    """`_canonical_port_name` sliced two characters off unconditionally.

    It assumed the abbreviated form, so `FastEthernet0` came back as
    `FastEthernetstEthernet0`, and every caller passing the full name -- which
    is the form a saved lab stores -- got nonsense. `port_exists` then reported
    real interfaces as missing.
    """
    from pkt_transformer import _canonical_port_name

    assert _canonical_port_name("FastEthernet0") == "FastEthernet0"
    assert _canonical_port_name("GigabitEthernet0/0/1") == "GigabitEthernet0/0/1"
    assert _canonical_port_name("Fa0/1") == "FastEthernet0/1"
    assert _canonical_port_name("Gi0/2") == "GigabitEthernet0/2"


def test_a_host_interface_is_unslotted() -> None:
    """Every lab on disk links its PCs on `FastEthernet0`.

    The switch rule was being applied to hosts, which accepted the slotted
    `FastEthernet0/1` that no PC has and rejected the name they all use.
    """
    import xml.etree.ElementTree as ET

    from pkt_transformer import port_exists

    host = ET.fromstring(
        "<DEVICE><ENGINE><TYPE>Pc</TYPE>"
        "<PORT><TYPE>eCopperFastEthernet</TYPE></PORT></ENGINE></DEVICE>"
    )

    assert port_exists(host, "FastEthernet0")
    assert not port_exists(host, "FastEthernet0/1")


def test_a_multi_slot_router_interface_is_accepted() -> None:
    """An ISR spells interfaces `GigabitEthernet0/0/1`, where the last number is
    a position within a slot rather than an index into the whole card."""
    import xml.etree.ElementTree as ET

    from pkt_transformer import port_exists

    router = ET.fromstring(
        "<DEVICE><ENGINE><TYPE>Router</TYPE>"
        + "<PORT><TYPE>eCopperGigabitEthernet</TYPE></PORT>" * 4
        + "</ENGINE></DEVICE>"
    )

    assert port_exists(router, "GigabitEthernet0/0/1")
    assert port_exists(router, "GigabitEthernet0/0/2")


def test_uplink_names_stay_inside_the_model_s_gigabit_count() -> None:
    """A 2960 has two gigabit interfaces, not twenty.

    `_switch_uplink_port` returned `GigabitEthernet0/{index}` for any index, so a
    core switch fanning out to twenty-two access switches asked for
    `GigabitEthernet0/20`. Packet Tracer rejects a lab naming an interface the
    device does not have -- which is why a 62-device lab opened and a 64-device
    one did not. The size was never the problem; the twentieth uplink was.
    """
    from generate_pkt import _switch_uplink_port

    access = {"name": "SW1", "model": "2960-24TT"}

    assert _switch_uplink_port(access, 1) == "GigabitEthernet0/1"
    assert _switch_uplink_port(access, 2) == "GigabitEthernet0/2"
    # Past the gigabit interfaces, a copper port from the top of the range.
    assert _switch_uplink_port(access, 3).startswith("FastEthernet0/")
    assert "GigabitEthernet0/20" not in {_switch_uplink_port(access, i) for i in range(1, 25)}


def test_a_multilayer_switch_keeps_its_wider_uplink_range() -> None:
    from generate_pkt import _switch_uplink_port

    assert _switch_uplink_port({"name": "CORE", "model": "3650-24PS"}, 8) == "GigabitEthernet1/0/8"
    assert _switch_uplink_port({"name": "DIST", "model": "3560-24PS"}, 8) == "GigabitEthernet0/8"


def test_a_router_without_a_serial_card_cannot_take_a_serial_link() -> None:
    """The donor's router has four gigabit interfaces and no serial card.

    Letting `Serial0/0/0` through produced a WAN lab with `encapsulation ppp`
    configured on an interface that was never cabled -- the link was emitted,
    the editor silently did nothing with it, and the file looked fine.
    """
    from pkt_transformer import port_exists

    assert not port_exists(_device("Router", fast=0, gig=4), "Serial0/0/0")
    assert port_exists(_device("Router", fast=0, gig=4, serial=2), "Serial0/0/0")


def test_real_link_endpoints_all_validate() -> None:
    """Saved labs are the oracle: if a lab links on port P, P must exist.

    Across twelve local labs that is 782 endpoints, and it was 33 short before
    serial, fibre and wireless families were counted.
    """
    import sys as _sys
    from collections import Counter

    _sys.path.insert(0, str(ROOT / "scripts"))
    from local_donors import discover_local_donors
    from pkt_codec import decode_pkt_auto, parse_pkt_xml
    from pkt_transformer import port_exists

    donors = discover_local_donors()[:4]
    if not donors:
        pytest.skip("no local labs to check against")

    missing: Counter[tuple[str, str]] = Counter()
    checked = 0
    for donor in donors:
        try:
            xml, _container = decode_pkt_auto(donor.path.read_bytes(), verify=False)
        except Exception:  # noqa: BLE001
            continue
        root = parse_pkt_xml(xml)
        devices = {
            device.findtext("./ENGINE/SAVE_REF_ID") or "": device
            for device in root.findall(".//DEVICES/DEVICE")
        }
        for link in root.findall(".//LINKS/LINK"):
            cable = link.find("./CABLE")
            if cable is None:
                continue
            refs = [cable.findtext(tag) or "" for tag in ("FROM", "TO")]
            ports = [port.text or "" for port in cable.findall("PORT")]
            for ref, port in zip(refs, ports):
                device = devices.get(ref)
                if device is None or not port:
                    continue
                checked += 1
                if not port_exists(device, port):
                    missing[(device.findtext("./ENGINE/TYPE") or "?", port)] += 1

    assert checked > 100, "expected a meaningful number of endpoints"
    assert not missing, f"real interfaces reported as missing: {missing.most_common(3)}"


def test_logical_interfaces_cannot_take_a_cable() -> None:
    """Nothing plugs into a channel, a VLAN interface or a subinterface.

    `port_exists` answers True for anything outside its Fast/Gigabit/Serial
    rules, deliberately: reporting a real link as invalid is the damaging
    direction. Logical interfaces fell through that branch and were treated as
    sockets, so wiring a multilayer switch from an industrial donor put a cable
    on `PRP-channel 1` -- and Packet Tracer refused to open the lab.
    """
    import xml.etree.ElementTree as ET

    from pkt_transformer import port_exists

    device = ET.Element("DEVICE")
    engine = ET.SubElement(device, "ENGINE")
    ET.SubElement(engine, "TYPE").text = "MultiLayerSwitch"

    assert not port_exists(device, "PRP-channel 1")
    assert not port_exists(device, "Port-channel1")
    assert not port_exists(device, "Vlan10")
    assert not port_exists(device, "GigabitEthernet0/0/1.20")


def test_ports_outside_the_modelled_families_are_still_accepted() -> None:
    """`Port 0` on an access point and `RS 232` on a laptop are real sockets."""
    import xml.etree.ElementTree as ET

    from pkt_transformer import port_exists

    device = ET.Element("DEVICE")
    engine = ET.SubElement(device, "ENGINE")
    ET.SubElement(engine, "TYPE").text = "AccessPoint"

    assert port_exists(device, "Port 0")
    assert port_exists(device, "RS 232")
