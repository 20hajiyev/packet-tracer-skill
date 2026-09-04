"""Two donors, two network names, and nothing comparing them.

`wireless_home` is built from "1 wireless router 2 laptop qur" -- the prompt
names no network, so nobody set one, and each side kept the residue it arrived
with: the laptops asking for `TestNetwork`, the router broadcasting `Default`.
The lab opened, every static check passed, and no laptop could associate.

`wireless_ssid` names the network in the prompt, both ends are written from it,
and it was never broken. That is the tell: the fault was in the case where
nothing wrote the name, not in the writing.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_pkt import _join_wireless_clients_to_the_network_that_exists  # noqa: E402

CLIENT = (
    "<WIRELESS_CLIENT><WIRELESS_COMMON><SSID>{ssid}</SSID></WIRELESS_COMMON>"
    "<PROFILES><WIRELESS_PROFILE><NAME>{ssid}</NAME><SSID>{ssid}</SSID></WIRELESS_PROFILE></PROFILES>"
    "<CURRENT_PROFILE><WIRELESS_PROFILE><NAME>{ssid}</NAME><SSID>{ssid}</SSID></WIRELESS_PROFILE></CURRENT_PROFILE>"
    "</WIRELESS_CLIENT>"
)


def _laptop(name: str, ssid: str, cellular: str = "ptcellular") -> ET.Element:
    device = ET.fromstring(
        "<DEVICE><ENGINE><TYPE>Laptop</TYPE><NAME/>"
        + CLIENT.format(ssid=ssid)
        + "<CELLULAR_CLIENT>"
        + CLIENT.format(ssid=cellular)
        + "</CELLULAR_CLIENT></ENGINE></DEVICE>"
    )
    device.find("./ENGINE/NAME").text = name
    return device


def _router(name: str, ssid: str) -> ET.Element:
    device = ET.fromstring(
        "<DEVICE><ENGINE><TYPE>WirelessRouterNewGeneration</TYPE><NAME/>"
        "<WIRELESS_SERVER><WIRELESS_COMMON><SSID/></WIRELESS_COMMON></WIRELESS_SERVER>"
        "</ENGINE></DEVICE>"
    )
    device.find("./ENGINE/NAME").text = name
    device.find("./ENGINE/WIRELESS_SERVER/WIRELESS_COMMON/SSID").text = ssid
    return device


def _lab(devices: list[ET.Element]) -> ET.Element:
    root = ET.fromstring("<PACKETTRACER5><NETWORK><DEVICES/><LINKS/></NETWORK></PACKETTRACER5>")
    for device in devices:
        root.find(".//DEVICES").append(device)
    return root


def _lab_device(root: ET.Element, name: str) -> ET.Element:
    return [d for d in root.findall(".//DEVICES/DEVICE") if (d.findtext("./ENGINE/NAME") or "") == name][0]


def _ssids(root: ET.Element, name: str) -> list[str]:
    for device in root.findall(".//DEVICES/DEVICE"):
        if (device.findtext("./ENGINE/NAME") or "") == name:
            return [(node.text or "").strip() for node in device.iter("SSID")]
    return []


def test_a_client_asking_for_a_network_nobody_broadcasts_is_moved_onto_the_one_that_exists() -> None:
    root = _lab([_router("WRT1", "Default"), _laptop("Laptop1", "TestNetwork")])
    assert _join_wireless_clients_to_the_network_that_exists(root)
    engine = _lab_device(root, "Laptop1").find("./ENGINE")
    assert engine.findtext("./WIRELESS_CLIENT/WIRELESS_COMMON/SSID") == "Default"
    assert engine.findtext("./WIRELESS_CLIENT/CURRENT_PROFILE/WIRELESS_PROFILE/SSID") == "Default"


def test_the_saved_profile_list_is_left_as_it_was() -> None:
    """Every client that works leaves its saved list alone; ours has to as well."""
    root = _lab([_router("WRT1", "Default"), _laptop("Laptop1", "TestNetwork")])
    _join_wireless_clients_to_the_network_that_exists(root)
    engine = _lab_device(root, "Laptop1").find("./ENGINE")
    assert engine.findtext("./WIRELESS_CLIENT/PROFILES/WIRELESS_PROFILE/SSID") == "TestNetwork"


def test_the_cellular_radio_is_left_on_its_own_network() -> None:
    """`ptcellular` is not Wi-Fi and has no business following the router."""
    root = _lab([_router("WRT1", "Default"), _laptop("Laptop1", "TestNetwork")])
    _join_wireless_clients_to_the_network_that_exists(root)
    assert "ptcellular" in _ssids(root, "Laptop1")


def test_the_broadcaster_keeps_its_own_name() -> None:
    root = _lab([_router("WRT1", "Default"), _laptop("Laptop1", "TestNetwork")])
    _join_wireless_clients_to_the_network_that_exists(root)
    assert _ssids(root, "WRT1") == ["Default"]


def test_a_client_already_on_the_air_is_left_alone() -> None:
    """`wireless_ssid` names the network in the prompt and was never broken."""
    root = _lab([_router("WRT1", "EvSebeke"), _laptop("Laptop1", "EvSebeke")])
    assert _join_wireless_clients_to_the_network_that_exists(root) == []


def test_running_it_again_changes_nothing() -> None:
    root = _lab([_router("WRT1", "Default"), _laptop("Laptop1", "TestNetwork")])
    assert _join_wireless_clients_to_the_network_that_exists(root)
    assert _join_wireless_clients_to_the_network_that_exists(root) == []


def test_two_networks_on_the_air_is_more_than_this_pass_can_infer() -> None:
    root = _lab([_router("WRT1", "Default"), _router("WRT2", "Other"), _laptop("Laptop1", "TestNetwork")])
    assert _join_wireless_clients_to_the_network_that_exists(root) == []
    assert "TestNetwork" in _ssids(root, "Laptop1")


def test_a_lab_with_nothing_broadcasting_is_untouched() -> None:
    root = _lab([_laptop("Laptop1", "TestNetwork")])
    assert _join_wireless_clients_to_the_network_that_exists(root) == []
