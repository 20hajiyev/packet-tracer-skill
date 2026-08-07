"""The planner has to name a router interface the router actually has.

`_router_port` knew `2901` and `ISR` and answered `FastEthernet0/0` for
everything else. A 2911 has `GigabitEthernet0/0` .. `0/2` and no FastEthernet
at all, so every 2911 lab asked for an interface that does not exist.

What makes this expensive is what happens next. An invalid name does not stop
generation: the port repair relocates the cable to the first free valid
interface, which is `GigabitEthernet0/0` -- the one addressing had already
made the WAN uplink. The lab's router-on-a-stick subinterfaces stayed on
`GigabitEthernet0/1`, where no cable reached them.

Measured on the company lab the skill generated: Packet Tracer reported one
linked port on R1 and ten subinterfaces protocol-down. No VLAN had a gateway,
nothing crossed a VLAN boundary, and the lab opened with every static check
passing and a configuration that reads correctly line by line.

Port names below come from Packet Tracer's own device list.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_pkt import _router_port  # noqa: E402

# model -> the first two interfaces Packet Tracer lists for it
CATALOGUE = {
    "1841": ["FastEthernet0/0", "FastEthernet0/1"],
    "1941": ["GigabitEthernet0/0", "GigabitEthernet0/1"],
    "2620XM": ["FastEthernet0/0", "FastEthernet0/1"],
    "2621XM": ["FastEthernet0/0", "FastEthernet0/1"],
    "2811": ["FastEthernet0/0", "FastEthernet0/1"],
    "2901": ["GigabitEthernet0/0", "GigabitEthernet0/1"],
    "2911": ["GigabitEthernet0/0", "GigabitEthernet0/1"],
    "CGR1240": ["GigabitEthernet0/0", "GigabitEthernet0/1"],
    "ISR4321": ["GigabitEthernet0/0/0", "GigabitEthernet0/0/1"],
    "ISR4331": ["GigabitEthernet0/0/0", "GigabitEthernet0/0/1"],
    "829": ["GigabitEthernet0", "GigabitEthernet1"],
    "Router-PT": ["FastEthernet0/0", "FastEthernet0/1"],
}


def test_every_catalogued_model_gets_a_name_it_owns() -> None:
    for model, interfaces in CATALOGUE.items():
        named = [_router_port({"model": model}, index) for index in (1, 2)]
        assert named == interfaces, f"{model}: asked for {named}, has {interfaces}"


def test_the_model_that_broke_the_company_lab() -> None:
    """A 2911 has no FastEthernet, and that is what it used to be given."""
    assert _router_port({"model": "2911"}, 1) == "GigabitEthernet0/0"
    assert not _router_port({"model": "2911"}, 1).startswith("FastEthernet")


def test_an_unknown_model_still_gets_the_old_answer() -> None:
    """The fallback is unchanged, so nothing that worked starts failing."""
    assert _router_port({"model": "SomeFutureRouter"}, 1) == "FastEthernet0/0"
    assert _router_port({}, 2) == "FastEthernet0/1"
