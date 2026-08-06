"""Regression tests for the three port checks that made labs unopenable.

Every generated lab in this repo was refused by Packet Tracer with
"Incompatible File" -- including ones generated months earlier. Nothing caught
it: the structural check passed, donor coherence passed, and the corpus reported
`generated_unverified`, a status nobody had ever resolved because the `--open`
tier had not been run.

Bisecting the plan one operation at a time found it in `port_exists`, three
times over, each an instance of the same mistake: judging an interface by how
many ports the device has instead of by what those ports are called.

Each test below fails on the code as it was, with the exact device shapes
measured from the donors involved.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from pkt_transformer import port_exists  # noqa: E402


def _device(kind: str, port_types: list[str], interfaces: list[str] | None = None) -> ET.Element:
    device = ET.Element("DEVICE")
    engine = ET.SubElement(device, "ENGINE")
    ET.SubElement(engine, "TYPE").text = kind
    ET.SubElement(engine, "NAME").text = "D1"
    config = ET.SubElement(engine, "RUNNINGCONFIG")
    for name in interfaces or []:
        ET.SubElement(config, "LINE").text = f"interface {name}"
    ports = ET.SubElement(device, "PORTS")
    for port_type in port_types:
        port = ET.SubElement(ports, "PORT")
        ET.SubElement(port, "TYPE").text = port_type
    return device


def test_a_kind_the_device_has_none_of_is_not_present() -> None:
    """A 2811 with two FastEthernet ports and no gigabit at all.

    `port_capacity` reports every kind it models, so `GigabitEthernet` was
    present as a key with the value zero. The multi-slot router branch then
    answered `0 <= 0 <= 0` and called `GigabitEthernet0/0/0` a real interface.
    """
    router = _device(
        "Router",
        ["eCopperFastEthernet", "eCopperFastEthernet"],
        ["FastEthernet0/0", "FastEthernet0/1"],
    )

    assert port_exists(router, "FastEthernet0/0") is True
    assert port_exists(router, "GigabitEthernet0/0/0") is False
    assert port_exists(router, "GigabitEthernet0/1") is False


def test_the_devices_own_naming_shape_decides() -> None:
    """A stacked switch numbers uplinks `GigabitEthernet1/0/N`.

    Asking for `GigabitEthernet0/1` passed on count alone -- the switch has
    twenty-eight gigabit ports and one is well inside that -- while naming an
    interface it does not have.
    """
    stacked = _device(
        "MultiLayerSwitch",
        ["eCopperGigabitEthernet"] * 28,
        ["GigabitEthernet1/0/1", "GigabitEthernet1/0/2"],
    )

    assert port_exists(stacked, "GigabitEthernet1/0/5") is True
    assert port_exists(stacked, "GigabitEthernet0/1") is False


def test_a_multi_slot_router_stops_one_short_of_its_port_count() -> None:
    """An ISR4331 with three gigabit ports has `0/0/0` through `0/0/2`.

    The bound was inclusive, so `GigabitEthernet0/0/3` was accepted as a fourth
    interface that does not exist.
    """
    isr = _device(
        "Router",
        ["eCopperGigabitEthernet"] * 3,
        ["GigabitEthernet0/0/0", "GigabitEthernet0/0/1", "GigabitEthernet0/0/2"],
    )

    assert port_exists(isr, "GigabitEthernet0/0/0") is True
    assert port_exists(isr, "GigabitEthernet0/0/2") is True
    assert port_exists(isr, "GigabitEthernet0/0/3") is False


def test_a_device_with_no_configuration_still_answers_on_count() -> None:
    """The naming-shape rule needs the device's own configuration, and a host
    has none. Falling back to the count keeps hosts working."""
    host = _device("PC", ["eCopperFastEthernet"])

    assert port_exists(host, "FastEthernet0") is True
    assert port_exists(host, "FastEthernet0/1") is False


def test_a_stale_configuration_line_does_not_make_a_port_real() -> None:
    """The last corpus lab Packet Tracer refused turned on one link out of
    twelve: a cable on `GigabitEthernet0/1` of a stacked switch whose sockets
    are all `GigabitEthernet1/0/N`. The name was accepted because the device's
    configuration still carried a stale `interface GigabitEthernet0/1` line, and
    the rule at the time took membership in that list as proof.

    The shape a device really uses is the one most of its interfaces share.
    """
    stacked = _device(
        "MultiLayerSwitch",
        ["eCopperGigabitEthernet"] * 28,
        [
            "GigabitEthernet0/1",  # left over from an earlier configuration
            "GigabitEthernet1/0/1",
            "GigabitEthernet1/0/2",
            "GigabitEthernet1/0/3",
        ],
    )

    assert port_exists(stacked, "GigabitEthernet1/0/2") is True
    assert port_exists(stacked, "GigabitEthernet0/1") is False

    # A plain 2960 really does have `GigabitEthernet0/1`, and must keep it.
    access = _device(
        "Switch",
        ["eCopperFastEthernet"] * 24 + ["eCopperGigabitEthernet"] * 2,
        ["FastEthernet0/1", "FastEthernet0/2", "GigabitEthernet0/1"],
    )
    assert port_exists(access, "GigabitEthernet0/1") is True
    assert port_exists(access, "FastEthernet0/5") is True


def test_a_device_with_unslotted_ports_numbers_from_zero() -> None:
    """An access point carries a single `GigabitEthernet0`. Falling to the
    slotted rule, `0 < index <= count`, rejected index 0 and accepted index 1 --
    so the real port was reported absent and `GigabitEthernet0/1`, which the
    device does not have, was reported present.

    That is worse than a wrong answer: the port repair trusts this, so it
    replaced the good name with the invented one and Packet Tracer refused the
    lab. Wiring an access point had to be reverted until this was fixed.
    """
    access_point = _device("LightWeightAccessPoint", ["eCopperGigabitEthernet"])

    assert port_exists(access_point, "GigabitEthernet0") is True
    assert port_exists(access_point, "GigabitEthernet0/1") is False
    assert port_exists(access_point, "GigabitEthernet1") is False

    meraki = _device("MerakiServer", ["eCopperFastEthernet"])
    assert port_exists(meraki, "FastEthernet0") is True
    assert port_exists(meraki, "FastEthernet0/1") is False

    # A switch still numbers from one, and a bare name is not a port on it.
    switch = _device("Switch", ["eCopperFastEthernet"] * 24, ["FastEthernet0/1"])
    assert port_exists(switch, "FastEthernet0/1") is True
    assert port_exists(switch, "FastEthernet0") is False
