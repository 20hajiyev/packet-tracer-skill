from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from intent_parser import parse_intent  # noqa: E402


def test_parse_generate_intent() -> None:
    plan = parse_intent("2 router, 3 switch, VLAN 10 ve 20, DHCP pool, OSPF")
    assert plan.goal == "generate"
    assert plan.device_requirements["Router"] == 2
    assert plan.device_requirements["Switch"] == 3
    assert "ospf" in plan.capabilities
    assert "dhcp_pool" in plan.capabilities
    assert plan.topology_requirements["vlan_ids"] == [10, 20]


def test_parse_edit_intent() -> None:
    plan = parse_intent(r"change PC1 ip 192.168.10.10 mask 255.255.255.0 gw 192.168.10.1 in C:\tmp\demo.pkt")
    assert plan.goal == "edit"
    assert plan.pkt_path == r"C:\tmp\demo.pkt"
    assert any(op["op"] == "set_host_ip" for op in plan.end_device_ops)


def test_parse_explicit_devices_and_links() -> None:
    plan = parse_intent(
        "device R1 type router model 1841 "
        "device S1 type switch model 2960-24TT "
        "connect R1:FastEthernet0/0 to S1:FastEthernet0/24 with crossover"
    )
    assert len(plan.devices) == 2
    assert plan.devices[0]["model"] == "1841"
    assert len(plan.links) == 1
    assert plan.links[0]["media"] == "crossover"


def test_parse_hybrid_operations() -> None:
    plan = parse_intent(
        "device AP1 type access-point model LAP-PT "
        "set SW1 vlan 10 name Finance "
        "set SW1 access-port Fa0/1 vlan 10 "
        "set SW1 trunk-port Gi0/1 allowed 10,20,99 native 99 "
        "set R1 subinterface Fa0/0.10 encapsulation dot1Q 10 ip 192.168.10.1/24 "
        "set R1 dhcp pool FIN network 192.168.10.0/24 gateway 192.168.10.1 dns 192.168.10.2 start 192.168.10.100 "
        "set R1 acl standard BLOCK_V20 "
        "acl BLOCK_V20 deny host 192.168.20.250 "
        "acl BLOCK_V20 permit 192.168.20.0 0.0.0.255 "
        "apply acl BLOCK_V20 out on R1 GigabitEthernet0/0/0.10 "
        "set SW1 management vlan 99 ip 192.168.99.11/24 gateway 192.168.99.1 "
        "enable telnet on SW1 username admin password 1234 "
        "set AP1 ssid FIN_WIFI security wpa2-psk passphrase fin12345 channel 6 "
        "associate Tablet0 to AP1 ssid FIN_WIFI dhcp "
        "set Server1 dns A www.example.local 192.168.10.20 "
        "enable dns on Server1 "
        "set PC1 dns 192.168.10.20"
    )
    assert any(op["op"] == "set_vlan" for op in plan.switch_ops)
    assert any(op["op"] == "set_trunk_port" for op in plan.switch_ops)
    assert any(op["op"] == "set_subinterface" for op in plan.router_ops)
    assert any(op["op"] == "set_router_dhcp_pool" for op in plan.router_ops)
    assert any(op["op"] == "set_acl" for op in plan.router_ops)
    assert any(op["op"] == "add_acl_rule" for op in plan.router_ops)
    assert any(op["op"] == "apply_acl" for op in plan.router_ops)
    assert any(op["op"] == "set_management_vlan" for op in plan.management_ops)
    assert any(op["op"] == "enable_telnet" for op in plan.management_ops)
    assert any(op["op"] == "set_wireless_ssid" for op in plan.wireless_ops)
    assert any(op["op"] == "associate_wireless_client" for op in plan.wireless_ops)
    assert any(op["op"] == "set_server_dns_record" for op in plan.server_ops)
    assert any(op["op"] == "enable_server_service" and op["service"] == "dns" for op in plan.server_ops)
    assert any(op["op"] == "set_host_dns" for op in plan.end_device_ops)


def test_parse_server_dhcp_pool_as_server_op() -> None:
    plan = parse_intent(
        "set Server0 dhcp pool VLAN10 network 192.168.10.0/24 gateway 192.168.10.1 dns 192.168.99.20 start 192.168.10.100 max 50"
    )
    assert any(op["op"] == "set_server_dhcp_pool" for op in plan.server_ops)
    assert not any(op["op"] == "set_router_dhcp_pool" and op["device"] == "Server0" for op in plan.router_ops)


def test_parse_azerbaijani_natural_prompt_and_blocking_gap() -> None:
    plan = parse_intent(
        "3 dene switch ve 6 komputer ve 1 router "
        "vlanlarda 10,20,30 "
        "switchlerin oz aralarinda ve routerle aralarinda gig portuna qosulsun "
        "komputerler ise fa portlarla qosulsun"
    )
    assert plan.device_requirements["Switch"] == 3
    assert plan.device_requirements["PC"] == 6
    assert plan.device_requirements["Router"] == 1
    assert plan.vlan_ids == [10, 20, 30]
    assert plan.uplink_intent == "gigabit"
    assert plan.host_link_intent == "fastethernet"
    assert plan.blocking_gaps


def test_parse_department_prompt_builds_groups_and_assumptions() -> None:
    plan = parse_intent(
        "6 sobeli kampus sebekesi qur her sobede 2 pc 1 printer 1 ap 2 tablet olsun "
        "router-on-a-stick, dhcp, telnet, wifi"
    )
    assert plan.network_style == "campus"
    assert len(plan.department_groups) == 6
    assert plan.device_requirements["Switch"] == 6
    assert plan.device_requirements["PC"] == 12
    assert plan.device_requirements["Printer"] == 6
    assert plan.device_requirements["LightWeightAccessPoint"] == 6
    assert plan.device_requirements["Tablet"] == 12
    assert plan.service_requirements["services"]
    assert plan.confidence_score > 0.4
