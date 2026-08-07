"""Which kinds get a cable, and which port each one uses.

A device the prompt asked for used to arrive in the file with nothing plugged
into it: present, valid, and taking no part in the network. The link
synthesiser cables the kinds in `HOST_DEVICE_KINDS`, and these six were not
among them.

Every port name here was read off real cables in 200 saved labs rather than
from the device palette, which reports names that appear on no cable at all --
`FastEthernet0` for a sniffer, `Port 0`/`PC Port` for an IP phone,
`GigabitEthernet1/1` for the 5506-X whose saved links all use `Ethernet0/N`.

`Wall Mount` is deliberately absent. Not one of the 200 labs cables it, so
there is no name to take, and inventing one is how a hardcoded port gets back
into the file.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_pkt import HOST_DEVICE_KINDS, _host_port  # noqa: E402

# kind -> the port its cables use in saved labs, and how many labs showed it
MEASURED_PORTS = {
    "Hub": ("FastEthernet0", 6),
    "WiredEndDevice": ("FastEthernet0", 1),
    "Patch Panel": ("PunchDown1", 1),
    "Bridge": ("Ethernet0/1", 1),
    "Repeater": ("Ethernet0", 1),
    "TV": ("Port 0", 1),
}


def test_each_measured_kind_is_cabled() -> None:
    for kind in MEASURED_PORTS:
        assert kind in HOST_DEVICE_KINDS, f"{kind} would arrive with no cable"


def test_each_kind_uses_the_port_its_cables_use() -> None:
    for kind, (port, _labs) in MEASURED_PORTS.items():
        assert _host_port({"name": "D1", "type": kind}) == port


def test_a_kind_with_no_cable_evidence_is_not_guessed_at() -> None:
    """`Wall Mount` appears in donors and is cabled in none of them."""
    assert "Wall Mount" not in HOST_DEVICE_KINDS


def test_the_firewall_starts_on_the_port_its_saved_cables_use() -> None:
    assert "ASA" in HOST_DEVICE_KINDS
    assert _host_port({"name": "ASA1", "type": "ASA"}) == "Ethernet0/0"


def test_the_ordinary_hosts_are_unchanged() -> None:
    assert _host_port({"name": "PC1", "type": "PC"}) == "FastEthernet0"
    assert _host_port({"name": "SRV1", "type": "Server"}) == "FastEthernet0"
    assert _host_port({"name": "IP1", "type": "IpPhone"}) == "Switch"
