"""Association is not connectivity, and the file said nothing about the difference.

Built from "1 wireless router 2 laptop qur ssid EvSebeke wpa2 sifre Gizli123",
the generated lab put WPA2 on the router and left the laptops on the donor's
WEP with the donor's key, and a second profile on an open network -- three
answers on one client, none of them the network's. Packet Tracer reported the
radio up and linked and passed no packet.

The donor it is pruned from settles what "working" looks like. `Laptop3` sits
on that lab's Linksys as a DHCP client, is leased `192.168.0.100` out of the
router's own pool, and pings the router 4/4 -- measured. So a home router's
client takes a lease; writing a static address onto its port and profile does
not stick, because Packet Tracer re-asserts DHCP for this kind of client.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_pkt import (  # noqa: E402
    _let_the_home_router_address_its_own_clients,
    _make_the_wireless_profile_agree_with_the_port,
    _match_wireless_security_to_the_access_point,
)

PROFILE = (
    "<WIRELESS_PROFILE><NAME>{ssid}</NAME><SSID>{ssid}</SSID>"
    "<AUTHEN_TYPE>{auth}</AUTHEN_TYPE><ENCRYPT_TYPE>{auth}</ENCRYPT_TYPE>"
    "<WEP_KEY>{key}</WEP_KEY><DHCP_ENABLED>1</DHCP_ENABLED>"
    "<IP_ADDRESS/><SUBNET_MASK/><DEFAULT_GATEWAY/></WIRELESS_PROFILE>"
)


def _client(name: str, ssid: str, auth: str = "1", key: str = "1234567890", address: str = "192.168.10.20") -> ET.Element:
    device = ET.fromstring(
        "<DEVICE><ENGINE><TYPE>Laptop</TYPE><NAME/><WIRELESS_CLIENT>"
        f"<WIRELESS_COMMON><SSID>{ssid}</SSID><AUTHEN_TYPE>{auth}</AUTHEN_TYPE>"
        f"<ENCRYPT_TYPE>{auth}</ENCRYPT_TYPE>"
        f"<WEP_PROCESS><KEY>{key}</KEY><ENCRYPTION>{auth}</ENCRYPTION></WEP_PROCESS></WIRELESS_COMMON>"
        f"<PROFILES>{PROFILE.format(ssid=ssid, auth=auth, key=key)}</PROFILES>"
        f"<CURRENT_PROFILE>{PROFILE.format(ssid=ssid, auth=auth, key=key)}</CURRENT_PROFILE>"
        "</WIRELESS_CLIENT></ENGINE></DEVICE>"
    )
    device.find("./ENGINE/NAME").text = name
    port = ET.SubElement(device, "PORT")
    ET.SubElement(port, "TYPE").text = "eHostWirelessN"
    ET.SubElement(port, "IP").text = address
    ET.SubElement(port, "SUBNET").text = "255.255.255.0"
    ET.SubElement(port, "PORT_GATEWAY").text = "192.168.10.1"
    ET.SubElement(port, "PORT_DHCP_ENABLE").text = "false"
    return device


def _router(name: str = "WRT1", ssid: str = "EvSebeke", dhcp: str = "1") -> ET.Element:
    device = ET.fromstring(
        "<DEVICE><ENGINE><TYPE>WirelessRouterNewGeneration</TYPE><NAME/>"
        "<LAN_IP_ADDRESS>192.168.10.1</LAN_IP_ADDRESS>"
        f"<DHCP_SERVER><ENABLED>{dhcp}</ENABLED><POOLS><POOL>"
        "<START_IP>192.168.10.100</START_IP><END_IP>192.168.10.149</END_IP>"
        "</POOL></POOLS></DHCP_SERVER>"
        f"<WIRELESS_SERVER><WIRELESS_COMMON><SSID>{ssid}</SSID>"
        "<AUTHEN_TYPE>4</AUTHEN_TYPE><ENCRYPT_TYPE>4</ENCRYPT_TYPE>"
        "<WPA_PASSPHRASE>Gizli123</WPA_PASSPHRASE></WIRELESS_COMMON></WIRELESS_SERVER>"
        "</ENGINE></DEVICE>"
    )
    device.find("./ENGINE/NAME").text = name
    return device


def _lab(devices: list[ET.Element]) -> ET.Element:
    root = ET.fromstring("<PACKETTRACER5><NETWORK><DEVICES/><LINKS/></NETWORK></PACKETTRACER5>")
    for device in devices:
        root.find(".//DEVICES").append(device)
    return root


def _laptop(root: ET.Element) -> ET.Element:
    return [d for d in root.findall(".//DEVICES/DEVICE") if (d.findtext("./ENGINE/NAME") or "") == "Laptop1"][0]


def test_the_client_is_put_on_the_security_the_network_is_running() -> None:
    root = _lab([_router(), _client("Laptop1", "EvSebeke")])
    assert _match_wireless_security_to_the_access_point(root)
    laptop = _laptop(root)
    common = laptop.find("./ENGINE/WIRELESS_CLIENT/WIRELESS_COMMON")
    assert common.findtext("AUTHEN_TYPE") == "4"
    assert common.findtext("ENCRYPT_TYPE") == "4"
    assert common.findtext("./WEP_PROCESS/KEY") == "Gizli123"


def test_every_profile_gets_the_key_not_just_the_current_one() -> None:
    """One client carried a WEP profile and an open profile beside it."""
    root = _lab([_router(), _client("Laptop1", "EvSebeke")])
    _match_wireless_security_to_the_access_point(root)
    laptop = _laptop(root)
    keys = {(node.text or "") for node in laptop.iter("WEP_KEY")}
    auths = {(node.text or "") for node in laptop.iter("AUTHEN_TYPE")}
    assert keys == {"Gizli123"}
    assert auths == {"4"}


def test_a_client_on_another_network_is_not_touched() -> None:
    root = _lab([_router(), _client("Laptop1", "SomewhereElse")])
    assert _match_wireless_security_to_the_access_point(root) == []


def test_matching_security_twice_changes_nothing() -> None:
    root = _lab([_router(), _client("Laptop1", "EvSebeke")])
    assert _match_wireless_security_to_the_access_point(root)
    assert _match_wireless_security_to_the_access_point(root) == []


def test_the_client_takes_a_lease_from_the_router_that_serves_it() -> None:
    """The donor's working client does exactly this: DHCP, leased out of the router's pool."""
    root = _lab([_router(), _client("Laptop1", "EvSebeke")])
    assert _let_the_home_router_address_its_own_clients(root)
    port = _laptop(root).find(".//PORT")
    assert port.findtext("PORT_DHCP_ENABLE") == "true"
    assert (port.findtext("IP") or "") == ""
    assert (port.findtext("PORT_GATEWAY") or "") == ""


def test_a_router_with_its_dhcp_server_off_leaves_the_static_address_alone() -> None:
    """Switching to DHCP there would leave the client with no address at all."""
    root = _lab([_router(dhcp="0"), _client("Laptop1", "EvSebeke")])
    assert _let_the_home_router_address_its_own_clients(root) == []
    assert _laptop(root).find(".//PORT").findtext("IP") == "192.168.10.20"


def test_taking_the_lease_twice_changes_nothing() -> None:
    root = _lab([_router(), _client("Laptop1", "EvSebeke")])
    assert _let_the_home_router_address_its_own_clients(root)
    assert _let_the_home_router_address_its_own_clients(root) == []


def test_the_profile_ends_up_saying_what_the_port_says() -> None:
    """Two records of one fact; Packet Tracer reads the profile."""
    root = _lab([_router(), _client("Laptop1", "EvSebeke")])
    _let_the_home_router_address_its_own_clients(root)
    _make_the_wireless_profile_agree_with_the_port(root)
    laptop = _laptop(root)
    assert {(node.text or "") for node in laptop.iter("DHCP_ENABLED")} == {"1"}
    assert {(node.text or "") for node in laptop.iter("IP_ADDRESS")} == {""}


def test_a_static_port_makes_the_profile_static_too() -> None:
    """Without a home router to lease from, the port's address is the answer."""
    root = _lab([_client("Laptop1", "EvSebeke")])
    assert _make_the_wireless_profile_agree_with_the_port(root)
    laptop = _laptop(root)
    assert {(node.text or "") for node in laptop.iter("DHCP_ENABLED")} == {"0"}
    assert {(node.text or "") for node in laptop.iter("IP_ADDRESS")} == {"192.168.10.20"}
    assert {(node.text or "") for node in laptop.iter("DEFAULT_GATEWAY")} == {"192.168.10.1"}
