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
        "<WEP_PROCESS><KEY>Gizli123</KEY><ENCRYPTION>4</ENCRYPTION></WEP_PROCESS>"
        "</WIRELESS_COMMON></WIRELESS_SERVER>"
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


def test_only_the_live_profile_is_rewritten_not_the_saved_list() -> None:
    """This asserted the opposite, and the labs that work say otherwise.

    `hr-guest` has its client on `home`/WPA2 in `CURRENT_PROFILE` while
    `PROFILES` still holds the untouched `Default`/open boilerplate, and the
    donor's own access-point clients are the same. Not one working client has
    its saved list rewritten -- and rewriting ours was why a generated lab
    matched its network in every visible field and still passed no packet.
    """
    root = _lab([_router(), _client("Laptop1", "EvSebeke")])
    _match_wireless_security_to_the_access_point(root)
    engine = _laptop(root).find("./ENGINE")

    live = engine.find("./WIRELESS_CLIENT/CURRENT_PROFILE/WIRELESS_PROFILE")
    assert live.findtext("AUTHEN_TYPE") == "4"
    assert live.findtext("WEP_KEY") == "Gizli123"

    saved = engine.find("./WIRELESS_CLIENT/PROFILES/WIRELESS_PROFILE")
    assert saved.findtext("AUTHEN_TYPE") == "1", "the saved list is boilerplate, not ours to rewrite"
    assert saved.findtext("WEP_KEY") == "1234567890"


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
    live = _laptop(root).find("./ENGINE/WIRELESS_CLIENT/CURRENT_PROFILE/WIRELESS_PROFILE")
    assert live.findtext("DHCP_ENABLED") == "1"
    assert (live.findtext("IP_ADDRESS") or "") == ""


def test_a_static_port_makes_the_profile_static_too() -> None:
    """Without a home router to lease from, the port's address is the answer."""
    root = _lab([_client("Laptop1", "EvSebeke")])
    assert _make_the_wireless_profile_agree_with_the_port(root)
    live = _laptop(root).find("./ENGINE/WIRELESS_CLIENT/CURRENT_PROFILE/WIRELESS_PROFILE")
    assert live.findtext("DHCP_ENABLED") == "0"
    assert live.findtext("IP_ADDRESS") == "192.168.10.20"
    assert live.findtext("DEFAULT_GATEWAY") == "192.168.10.1"


def test_the_access_point_key_is_written_where_packet_tracer_reads_it() -> None:
    """`WPA_PASSPHRASE` is not that place, and putting it there cost the whole lab.

    A working WPA2 home router keeps `WIRELESS_COMMON/WEP_PROCESS/KEY` with
    `WEP_PROCESS/ENCRYPTION` set to the encryption type, and carries no
    `WPA_PASSPHRASE` at all -- measured on `hr-guest`, which associates and
    pings. The names are legacy; WPA2 uses them, and the client side already
    used the same shape.

    Choosing the field by authentication type put the passphrase somewhere
    Packet Tracer does not read, so the access point ran WPA2 with no key while
    its clients had one. The lab opened, both sides looked right in every field
    anyone was reading, and nothing associated: 0/4 to the gateway.
    """
    from pkt_editor import _apply_wireless_op

    device = ET.fromstring(
        "<DEVICE><ENGINE><TYPE>WirelessRouterNewGeneration</TYPE><NAME>WRT1</NAME>"
        "<WIRELESS_SERVER><WIRELESS_COMMON><SSID>Default</SSID>"
        "<AUTHEN_TYPE>0</AUTHEN_TYPE><ENCRYPT_TYPE>0</ENCRYPT_TYPE>"
        "<STANDARD_CHANNEL>0</STANDARD_CHANNEL></WIRELESS_COMMON></WIRELESS_SERVER>"
        "</ENGINE></DEVICE>"
    )
    _apply_wireless_op(
        device,
        {
            "op": "set_wireless_ssid",
            "ssid": "EvSebeke",
            "auth_type": "4",
            "encrypt_type": "4",
            "channel": "1",
            "passphrase": "Gizli123",
        },
    )
    common = device.find("./ENGINE/WIRELESS_SERVER/WIRELESS_COMMON")
    assert common.findtext("./WEP_PROCESS/KEY") == "Gizli123"
    assert common.findtext("./WEP_PROCESS/ENCRYPTION") == "4"
    assert common.findtext("WPA_PASSPHRASE") is None


def test_a_donor_running_an_open_network_still_gets_the_key() -> None:
    """The element has to be created; guarding on its existence swallowed the passphrase."""
    from pkt_editor import _apply_wireless_op

    device = ET.fromstring(
        "<DEVICE><ENGINE><TYPE>WirelessRouter</TYPE><NAME>WRT1</NAME>"
        "<WIRELESS_SERVER><WIRELESS_COMMON><SSID>Default</SSID>"
        "<AUTHEN_TYPE>0</AUTHEN_TYPE><ENCRYPT_TYPE>0</ENCRYPT_TYPE>"
        "</WIRELESS_COMMON></WIRELESS_SERVER></ENGINE></DEVICE>"
    )
    assert device.find(".//WEP_PROCESS") is None
    _apply_wireless_op(
        device,
        {
            "op": "set_wireless_ssid",
            "ssid": "EvSebeke",
            "auth_type": "4",
            "encrypt_type": "4",
            "channel": "6",
            "passphrase": "Gizli123",
        },
    )
    assert device.findtext(".//WEP_PROCESS/KEY") == "Gizli123"


def test_the_client_finds_the_key_wherever_the_access_point_keeps_it() -> None:
    """The repair pass read only the old spellings, so the clients came out keyless."""
    root = _lab([_router(), _client("Laptop1", "EvSebeke")])
    _match_wireless_security_to_the_access_point(root)
    common = _laptop(root).find("./ENGINE/WIRELESS_CLIENT/WIRELESS_COMMON")
    assert common.findtext("./WEP_PROCESS/KEY") == "Gizli123"
