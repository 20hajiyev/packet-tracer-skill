from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from intent_parser import parse_intent  # noqa: E402
from packet_tracer_env import get_packet_tracer_saves_root  # noqa: E402
from pkt_editor import apply_plan_operations, decode_pkt_to_root, inventory_root  # noqa: E402


def _require_saves_root() -> Path:
    saves_root = get_packet_tracer_saves_root()
    if saves_root is None:
        pytest.skip("Packet Tracer sample saves not found")
    return saves_root


def test_inventory_root_lists_devices_and_links() -> None:
    root = decode_pkt_to_root(_require_saves_root() / r"01 Networking\FTP\FTP.pkt")
    inventory = inventory_root(root)
    assert inventory["devices"]
    assert inventory["links"]


def test_apply_plan_operations_updates_server_and_wireless_fields() -> None:
    root = decode_pkt_to_root(_require_saves_root() / r"01 Networking\DHCP\dhcp_reservation.pkt")
    plan = parse_intent(
        "set Wireless Router0 ssid FIN_WIFI security wpa2-psk passphrase fin12345 channel 6 "
        "associate PC0 to Wireless Router0 ssid FIN_WIFI dhcp"
    )
    updated = apply_plan_operations(root, plan)
    wireless_router = None
    wireless_client = None
    for device in updated.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME", default="")
        if name == "Wireless Router0":
            wireless_router = device
        if name == "PC0":
            wireless_client = device
    assert wireless_router is not None
    assert wireless_router.findtext("./ENGINE/WIRELESS_SERVER/WIRELESS_COMMON/SSID") == "FIN_WIFI"
    assert wireless_client is not None
    assert wireless_client.findtext("./ENGINE/WIRELESS_CLIENT/WIRELESS_COMMON/SSID") == "FIN_WIFI"


def test_apply_plan_operations_updates_acl_and_dns() -> None:
    root = decode_pkt_to_root(_require_saves_root() / r"01 Networking\FTP\FTP.pkt")
    plan = parse_intent(
        "set Router0 acl standard BLOCK_V20 "
        "acl BLOCK_V20 deny host 192.168.20.250 "
        "acl BLOCK_V20 permit 192.168.20.0 0.0.0.255 "
        "apply acl BLOCK_V20 out on Router0 FastEthernet0/0 "
        "enable dns on Server0 "
        "set PC0 dns 192.168.10.20"
    )
    updated = apply_plan_operations(root, plan)
    router = None
    server = None
    pc = None
    for device in updated.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME", default="")
        if name == "Router0":
            router = device
        if name == "Server0":
            server = device
        if name == "PC0":
            pc = device
    assert router is not None
    router_text = "\n".join(line.text or "" for line in router.findall("./ENGINE/RUNNINGCONFIG/LINE"))
    assert "ip access-list standard BLOCK_V20" in router_text
    assert "deny host 192.168.20.250" in router_text
    assert "ip access-group BLOCK_V20 out" in router_text
    assert server is not None
    assert server.findtext("./ENGINE/DNS_SERVER/ENABLED") == "1"
    assert pc is not None
    assert pc.findtext("./ENGINE/DNS_CLIENT/SERVER_IP") == "192.168.10.20"
