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


def _device(device_type: str, fast: int, gig: int) -> ET.Element:
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
    return device


def test_capacity_counts_each_interface_kind() -> None:
    assert port_capacity(_device("Switch", fast=24, gig=2)) == {
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


def test_unknown_port_kinds_are_rejected() -> None:
    device = _device("Switch", fast=24, gig=2)

    assert not port_exists(device, "Serial0/0")
    assert not port_exists(device, "")


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
