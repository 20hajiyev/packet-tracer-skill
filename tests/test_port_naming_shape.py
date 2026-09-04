"""A device's own interfaces say how it numbers them; counting ports does not.

Two spellings have the same slot depth and mean opposite things. A 2960 numbers
within one slot -- `FastEthernet0/1` .. `0/24` -- while a modular switch numbers
by slot: `FastEthernet0/1`, `1/1`, ... `9/1`. The generator composes
`FastEthernet0/{index}`, so it asked such a switch for `FastEthernet0/2`.

Measured on a lab built from the saved serial-WAN lab: that one link is why
Packet Tracer refused the file. The same file with its uplink on
`FastEthernet2/1` opens. And the routers in it own two serial ports, so
`port_exists` answered yes to `Serial0/0/0` on hardware whose only serial
interfaces are `Serial2/0` and `Serial3/0` -- owning serial is not owning that
interface.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from pkt_transformer import port_exists  # noqa: E402


def _device(device_type: str, port_types: list[str], interfaces: list[str]) -> ET.Element:
    """A device with the given hardware and the given interfaces in its config."""
    device = ET.fromstring(
        f"""
        <DEVICE>
          <ENGINE>
            <NAME>D1</NAME>
            <TYPE>{device_type}</TYPE>
            <MODULE><SLOT/></MODULE>
            <RUNNINGCONFIG/>
          </ENGINE>
        </DEVICE>
        """
    )
    slot = device.find("./ENGINE/MODULE/SLOT")
    assert slot is not None
    for port_type in port_types:
        module = ET.SubElement(slot, "MODULE")
        port = ET.SubElement(module, "PORT")
        ET.SubElement(port, "TYPE").text = port_type
    config = device.find("./ENGINE/RUNNINGCONFIG")
    assert config is not None
    for name in interfaces:
        ET.SubElement(config, "LINE").text = f"interface {name}"
    return device


def _modular_switch() -> ET.Element:
    """Ten copper ports, numbered by slot: `FastEthernet0/1` .. `9/1`."""
    return _device(
        "Switch",
        ["eCopperFastEthernet"] * 10,
        [f"FastEthernet{slot}/1" for slot in range(10)],
    )


def _fixed_switch() -> ET.Element:
    """A 2960-shaped switch: one slot, ports numbered inside it."""
    return _device(
        "Switch",
        ["eCopperFastEthernet"] * 24,
        [f"FastEthernet0/{index}" for index in range(1, 25)],
    )


def test_a_slot_numbered_switch_rejects_the_2960_spelling() -> None:
    switch = _modular_switch()
    assert port_exists(switch, "FastEthernet0/1") is True
    assert port_exists(switch, "FastEthernet2/1") is True
    assert port_exists(switch, "FastEthernet9/1") is True
    # The name the generator composes, and the reason the lab was refused.
    assert port_exists(switch, "FastEthernet0/2") is False
    assert port_exists(switch, "FastEthernet0/24") is False


def test_a_fixed_switch_still_accepts_its_own_spelling() -> None:
    """The new rule must not fire on the common case it looks similar to."""
    switch = _fixed_switch()
    for index in (1, 2, 5, 24):
        assert port_exists(switch, f"FastEthernet0/{index}") is True


def test_one_configured_interface_is_not_enough_to_infer_a_shape() -> None:
    """A single sample says nothing about which component varies."""
    switch = _device("Switch", ["eCopperFastEthernet"] * 24, ["FastEthernet0/1"])
    assert port_exists(switch, "FastEthernet0/2") is True


def test_serial_hardware_is_not_the_same_as_that_serial_interface() -> None:
    router = _device("Router", ["eSerial", "eSerial"], ["Serial2/0", "Serial3/0"])
    assert port_exists(router, "Serial2/0") is True
    assert port_exists(router, "Serial3/0") is True
    # Two serial ports exist, so the old count-only test said yes to this.
    assert port_exists(router, "Serial0/0/0") is False


def test_a_router_with_no_serial_card_still_has_no_serial_port() -> None:
    router = _device("Router", ["eCopperFastEthernet"], ["FastEthernet0/0"])
    assert port_exists(router, "Serial0/0/0") is False


def test_a_name_absent_from_the_device_own_interfaces_is_rejected() -> None:
    """The branch for names this module does not model is permissive, not blind.

    An ASA 5506-X whose interfaces are `GigabitEthernet1/1` .. `1/8` answered
    yes to `Ethernet0/0`: the name starts with neither modelled prefix, so it
    fell through to "outside this module, assume it is real". The port repair
    then saw nothing to fix and Packet Tracer refused the lab. With the name
    checked against the device's own list, the repair moves the cable to
    `GigabitEthernet1/2` and the lab opens.
    """
    asa = _device(
        "SecurityAppliance",
        ["eCopperGigabitEthernet"] * 8,
        [f"GigabitEthernet1/{index}" for index in range(1, 9)],
    )
    assert port_exists(asa, "GigabitEthernet1/2") is True
    assert port_exists(asa, "Ethernet0/0") is False


def test_a_device_that_lists_no_interfaces_keeps_the_benefit_of_the_doubt() -> None:
    """Access points, phones and laptops carry no interface lines at all."""
    access_point = _device("LightWeightAccessPoint", ["eCopperGigabitEthernet"], [])
    assert port_exists(access_point, "Port 0") is True
    assert port_exists(access_point, "GigabitEthernet0") is True
