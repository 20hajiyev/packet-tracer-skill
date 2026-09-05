"""The home router kept the donor's network while its clients were addressed on another.

`wireless_home` and `wireless_ssid` both shipped two laptops on
`192.168.10.20` and `.21`, pointing at `192.168.10.1`, and a router whose LAN
was `192.168.0.1/24` handing out `192.168.0.100` .. `.149`. The lab opened, the
laptops associated, every static check passed, and the gateway they pointed at
did not exist. The coherence report said so twice --
`gateway_answers_for_nobody` -- and it was right.

Two places decide the network and neither reads the other. The router moves,
because its LAN address is a setting and the hosts' addresses are the plan.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_pkt import _align_home_router_lan_with_its_clients  # noqa: E402


def _home_router(name: str = "WRT1", lan: str = "192.168.0.1") -> ET.Element:
    device = ET.fromstring(
        "<DEVICE><ENGINE><TYPE>WirelessRouterNewGeneration</TYPE><NAME/>"
        "<START_IP></START_IP>"
        "<LAN_IP_ADDRESS/><LAN_SUBNET_MASK>255.255.255.0</LAN_SUBNET_MASK>"
        "<DHCP_SERVER><POOLS><POOL>"
        "<NETWORK>192.168.0.0</NETWORK><MASK>255.255.255.0</MASK>"
        "<DEFAULT_ROUTER>192.168.0.1</DEFAULT_ROUTER>"
        "<START_IP>192.168.0.100</START_IP><END_IP>192.168.0.149</END_IP>"
        "<DHCP_POOL_LEASES>"
        "<DHCP_POOL_LEASE><MAC_ADDRESS>0001.42AA.65C4</MAC_ADDRESS>"
        "<CLIENT_ID>0001.42AA.65C4</CLIENT_ID><HOST_PORT>Vlan1</HOST_PORT>"
        "<IP_ADDRESS>192.168.0.100</IP_ADDRESS><LEASE_TIME>86400000</LEASE_TIME></DHCP_POOL_LEASE>"
        "<DHCP_POOL_LEASE><MAC_ADDRESS>000A.F309.D80E</MAC_ADDRESS>"
        "<CLIENT_ID>000A.F309.D80E</CLIENT_ID><HOST_PORT>Vlan1</HOST_PORT>"
        "<IP_ADDRESS>192.168.0.101</IP_ADDRESS><LEASE_TIME>86400000</LEASE_TIME></DHCP_POOL_LEASE>"
        "</DHCP_POOL_LEASES>"
        "</POOL></POOLS></DHCP_SERVER></ENGINE></DEVICE>"
    )
    device.find("./ENGINE/NAME").text = name
    device.find("./ENGINE/LAN_IP_ADDRESS").text = lan
    return device


def _host(name: str, address: str, gateway: str, dhcp: str = "false", mac: str = "0001.42AA.65C4") -> ET.Element:
    device = ET.fromstring("<DEVICE><ENGINE><TYPE>Laptop</TYPE><NAME/></ENGINE></DEVICE>")
    device.find("./ENGINE/NAME").text = name
    port = ET.SubElement(device, "PORT")
    ET.SubElement(port, "MACADDRESS").text = mac
    ET.SubElement(port, "TYPE").text = "eHostWirelessN"
    ET.SubElement(port, "IP").text = address
    ET.SubElement(port, "SUBNET").text = "255.255.255.0"
    ET.SubElement(port, "PORT_GATEWAY").text = gateway
    ET.SubElement(port, "PORT_DHCP_ENABLE").text = dhcp
    return device


def _lab(devices: list[ET.Element]) -> ET.Element:
    root = ET.fromstring("<PACKETTRACER5><NETWORK><DEVICES/><LINKS/></NETWORK></PACKETTRACER5>")
    for device in devices:
        root.find(".//DEVICES").append(device)
    return root


def _pool(root: ET.Element, tag: str) -> str:
    return root.findtext(f".//ENGINE/DHCP_SERVER/POOLS/POOL/{tag}") or ""


def test_the_router_moves_onto_the_network_its_clients_are_on() -> None:
    root = _lab([_home_router(), _host("Laptop1", "192.168.10.20", "192.168.10.1")])
    assert _align_home_router_lan_with_its_clients(root)
    assert root.findtext(".//ENGINE/LAN_IP_ADDRESS") == "192.168.10.1"
    assert _pool(root, "NETWORK") == "192.168.10.0"
    assert _pool(root, "DEFAULT_ROUTER") == "192.168.10.1"
    assert _pool(root, "START_IP") == "192.168.10.100"
    assert _pool(root, "END_IP") == "192.168.10.149"


def test_running_it_again_changes_nothing() -> None:
    """A generated lab becomes the next build's donor, so every pass runs over its own output."""
    root = _lab([_home_router(), _host("Laptop1", "192.168.10.20", "192.168.10.1")])
    assert _align_home_router_lan_with_its_clients(root)
    assert _align_home_router_lan_with_its_clients(root) == []


def test_a_router_whose_clients_already_point_at_it_is_left_alone() -> None:
    root = _lab([_home_router(lan="192.168.0.1"), _host("Laptop1", "192.168.0.20", "192.168.0.1")])
    assert _align_home_router_lan_with_its_clients(root) == []
    assert _pool(root, "START_IP") == "192.168.0.100"


def test_a_dhcp_client_is_not_evidence_of_anything() -> None:
    """Its address comes from this router at runtime, so it can never disagree with it."""
    root = _lab([_home_router(), _host("Laptop1", "192.168.10.20", "192.168.10.1", dhcp="true")])
    assert _align_home_router_lan_with_its_clients(root) == []
    assert root.findtext(".//ENGINE/LAN_IP_ADDRESS") == "192.168.0.1"


def test_a_gateway_some_interface_really_answers_for_is_not_a_gap() -> None:
    """A wired lab's hosts point at a router interface; nothing here should move."""
    router = ET.fromstring(
        "<DEVICE><ENGINE><TYPE>Router</TYPE><NAME>R1</NAME><RUNNINGCONFIG>"
        "<LINE>interface GigabitEthernet0/0</LINE>"
        "<LINE> ip address 192.168.10.1 255.255.255.0</LINE>"
        "<LINE>!</LINE></RUNNINGCONFIG></ENGINE></DEVICE>"
    )
    root = _lab([_home_router(), router, _host("Laptop1", "192.168.10.20", "192.168.10.1")])
    assert _align_home_router_lan_with_its_clients(root) == []


def test_two_orphaned_gateways_are_more_than_this_pass_can_attribute() -> None:
    """Guessing which router owns which would be the same mistake over again."""
    root = _lab(
        [
            _home_router(),
            _host("Laptop1", "192.168.10.20", "192.168.10.1"),
            _host("Laptop2", "192.168.20.20", "192.168.20.1"),
        ]
    )
    assert _align_home_router_lan_with_its_clients(root) == []


def test_the_stray_empty_field_beside_the_pool_stays_empty() -> None:
    """`ENGINE` carries its own blank `START_IP`; filling it by tag name wrote to both."""
    root = _lab([_home_router(), _host("Laptop1", "192.168.10.20", "192.168.10.1")])
    _align_home_router_lan_with_its_clients(root)
    engine = root.find(".//DEVICES/DEVICE/ENGINE")
    assert (engine.findtext("START_IP") or "") == ""


def test_a_lab_with_no_home_router_is_untouched() -> None:
    root = _lab([_host("PC1", "192.168.10.20", "192.168.10.1")])
    assert _align_home_router_lan_with_its_clients(root) == []


def _leases(root: ET.Element) -> list[tuple[str, str]]:
    return [
        ((lease.findtext("MAC_ADDRESS") or ""), (lease.findtext("IP_ADDRESS") or ""))
        for lease in root.findall(".//DHCP_POOL_LEASES/DHCP_POOL_LEASE")
    ]


def test_a_lease_is_renumbered_onto_the_new_network_not_deleted() -> None:
    """Deleting them is what left a wireless client holding nothing on load.

    Packet Tracer restores a client's address from the lease record when the
    file opens. Without one it would have to associate and ask again, which
    opening a file does not make it do. The donor's router carries a lease
    against the very MAC our laptop has, and its client pings 4/4.
    """
    root = _lab([_home_router(), _host("Laptop1", "192.168.10.20", "192.168.10.1")])
    assert _align_home_router_lan_with_its_clients(root)
    assert _leases(root) == [("0001.42AA.65C4", "192.168.10.100")]


def test_a_lease_for_a_device_the_prune_removed_is_dropped() -> None:
    """A lease naming a client that is not in the lab is a record of nothing."""
    root = _lab([_home_router(), _host("Laptop1", "192.168.10.20", "192.168.10.1")])
    _align_home_router_lan_with_its_clients(root)
    assert "000A.F309.D80E" not in {mac for mac, _ in _leases(root)}


def test_the_lease_keeps_the_client_it_was_written_for() -> None:
    root = _lab([_home_router(), _host("Laptop1", "192.168.10.20", "192.168.10.1")])
    _align_home_router_lan_with_its_clients(root)
    lease = root.find(".//DHCP_POOL_LEASES/DHCP_POOL_LEASE")
    assert lease.findtext("CLIENT_ID") == "0001.42AA.65C4"
    assert lease.findtext("HOST_PORT") == "Vlan1"
    assert lease.findtext("LEASE_TIME") == "86400000"


def test_renumbering_the_leases_twice_changes_nothing() -> None:
    root = _lab([_home_router(), _host("Laptop1", "192.168.10.20", "192.168.10.1")])
    assert _align_home_router_lan_with_its_clients(root)
    before = _leases(root)
    assert _align_home_router_lan_with_its_clients(root) == []
    assert _leases(root) == before


def test_leases_stay_inside_the_pool() -> None:
    root = _lab([_home_router(), _host("Laptop1", "192.168.10.20", "192.168.10.1")])
    _align_home_router_lan_with_its_clients(root)
    start = _pool(root, "START_IP")
    end = _pool(root, "END_IP")
    for _mac, address in _leases(root):
        assert start <= address <= end or address == start
