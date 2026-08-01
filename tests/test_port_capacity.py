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
