from __future__ import annotations

import sys
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from intent_parser import IntentPlan, parse_intent  # noqa: E402
from packet_tracer_env import get_packet_tracer_saves_root  # noqa: E402
from pkt_editor import apply_plan_operations, decode_pkt_to_root, edit_pkt_file, inventory_root  # noqa: E402


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


def test_inventory_root_lists_advanced_server_services_from_ftp_sample() -> None:
    root = decode_pkt_to_root(_require_saves_root() / r"01 Networking\FTP\FTP.pkt")
    inventory = inventory_root(root)
    services = set(inventory["services"].get("Server0", []))
    assert {"ftp_server", "email_server", "syslog_server", "acs_server"} <= services
    assert inventory["service_details"]["Server0"]["aaa_auth_port"] == "1645"


def test_inventory_root_lists_wlc_wireless_and_iot_roles() -> None:
    wlc_root = decode_pkt_to_root(
        _require_saves_root() / r"01 Networking\Wireless\Wireless LAN\WLC\wlc_2504_simple_wlan_dhcp.pkt"
    )
    wlc_inventory = inventory_root(wlc_root)
    assert wlc_inventory["wireless"]["Wireless LAN Controller1"]["mode"] == "controller"
    assert wlc_inventory["wireless"]["Wireless LAN Controller1"]["ssid"] == "ssid1"

    iot_root = decode_pkt_to_root(_require_saves_root() / r"04 IoT\Solution Examples\iot_home_gateway.pkt")
    iot_inventory = inventory_root(iot_root)
    assert iot_inventory["iot"]["Home Gateway0"]["role"] == "gateway"
    assert iot_inventory["iot"]["door0"]["role"] == "thing"
    assert iot_inventory["iot"]["door0"]["client_mode"] == "LAN_SERVER"

    registration_root = decode_pkt_to_root(_require_saves_root() / r"04 IoT\Solution Examples\iot_registration_server.pkt")
    registration_inventory = inventory_root(registration_root)
    rule_names = {rule["name"] for rule in registration_inventory["iot"]["Server0"]["rules"]}
    assert {"open garage", "close garage"} <= rule_names


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


def test_edit_pkt_file_roundtrip_preserves_wireless_mutation_and_association(tmp_path: Path) -> None:
    source = _require_saves_root() / r"01 Networking\DHCP\dhcp_reservation.pkt"
    output = tmp_path / "wireless_edit_roundtrip.pkt"
    xml_out = tmp_path / "wireless_edit_roundtrip.xml"
    plan = parse_intent(
        "set Wireless Router0 ssid FIN_WIFI security wpa2-psk passphrase fin12345 channel 6 "
        "associate PC0 to Wireless Router0 ssid FIN_WIFI dhcp"
    )
    edit_pkt_file(source, plan, output, xml_out)

    assert output.exists()
    assert xml_out.exists()

    updated = decode_pkt_to_root(output)
    inventory = inventory_root(updated)
    wireless = inventory["wireless"]
    assert wireless["Wireless Router0"]["ssid"] == "FIN_WIFI"
    assert wireless["PC0"]["ssid"] == "FIN_WIFI"


def test_edit_pkt_file_roundtrip_preserves_wlc_wireless_mutation(tmp_path: Path) -> None:
    source = _require_saves_root() / r"01 Networking\Wireless\Wireless LAN\WLC\wlc_2504_simple_wlan_dhcp.pkt"
    output = tmp_path / "wlc_wireless_edit_roundtrip.pkt"
    xml_out = tmp_path / "wlc_wireless_edit_roundtrip.xml"
    plan = parse_intent("set Wireless LAN Controller1 ssid CAMPUS_WLAN security wpa2-psk passphrase campus123 channel 11")
    edit_pkt_file(source, plan, output, xml_out)

    assert output.exists()
    assert xml_out.exists()

    updated = decode_pkt_to_root(output)
    inventory = inventory_root(updated)
    assert inventory["wireless"]["Wireless LAN Controller1"]["ssid"] == "CAMPUS_WLAN"


def test_edit_pkt_file_roundtrip_preserves_iot_registration_server_mutation(tmp_path: Path) -> None:
    source = _require_saves_root() / r"04 IoT\Solution Examples\iot_registration_server.pkt"
    output = tmp_path / "iot_registration_roundtrip.pkt"
    xml_out = tmp_path / "iot_registration_roundtrip.xml"
    plan = parse_intent("register CO2 to Server0 mode remote_server server-address 1.0.0.10 username netadmin password iot123")
    edit_pkt_file(source, plan, output, xml_out)

    assert output.exists()
    assert xml_out.exists()

    updated = decode_pkt_to_root(output)
    inventory = inventory_root(updated)
    assert inventory["iot"]["CO2"]["client_mode"] == "REMOTE_SERVER"
    assert inventory["iot"]["CO2"]["server_address"] == "1.0.0.10"
    assert inventory["iot"]["CO2"]["username"] == "netadmin"


def test_edit_pkt_file_roundtrip_preserves_iot_home_gateway_registration_mutation(tmp_path: Path) -> None:
    source = _require_saves_root() / r"04 IoT\Solution Examples\iot_home_gateway.pkt"
    output = tmp_path / "iot_home_gateway_roundtrip.pkt"
    xml_out = tmp_path / "iot_home_gateway_roundtrip.xml"
    plan = parse_intent("register door0 to Home Gateway0 mode lan_server server-address 192.168.25.1 username admin password admin")
    edit_pkt_file(source, plan, output, xml_out)

    assert output.exists()
    assert xml_out.exists()

    updated = decode_pkt_to_root(output)
    inventory = inventory_root(updated)
    assert inventory["iot"]["door0"]["client_mode"] == "LAN_SERVER"
    assert inventory["iot"]["door0"]["server_address"] == "192.168.25.1"
    assert inventory["iot"]["door0"]["username"] == "admin"


def test_edit_pkt_file_roundtrip_preserves_iot_rule_state_mutation(tmp_path: Path) -> None:
    source = _require_saves_root() / r"04 IoT\Solution Examples\iot_registration_server.pkt"
    output = tmp_path / "iot_rule_state_roundtrip.pkt"
    xml_out = tmp_path / "iot_rule_state_roundtrip.xml"
    plan = parse_intent('disable iot rule "open garage" on Server0')
    edit_pkt_file(source, plan, output, xml_out)

    assert output.exists()
    assert xml_out.exists()

    updated = decode_pkt_to_root(output)
    inventory = inventory_root(updated)
    rules = {rule["name"]: rule["enabled"] for rule in inventory["iot"]["Server0"]["rules"]}
    assert rules["open garage"] is False
    assert rules["close garage"] is True


def test_edit_pkt_file_roundtrip_preserves_server_service_and_end_device_mutation(tmp_path: Path) -> None:
    source = _require_saves_root() / r"01 Networking\FTP\FTP.pkt"
    output = tmp_path / "server_end_device_roundtrip.pkt"
    xml_out = tmp_path / "server_end_device_roundtrip.xml"
    plan = parse_intent(
        "enable dns on Server0 "
        "set Server0 dns A www.example.local 192.168.10.20 "
        "set PC0 dns 192.168.10.20"
    )
    edit_pkt_file(source, plan, output, xml_out)

    assert output.exists()
    assert xml_out.exists()

    updated = decode_pkt_to_root(output)
    server = None
    pc = None
    for device in updated.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME", default="")
        if name == "Server0":
            server = device
        if name == "PC0":
            pc = device

    assert server is not None
    assert server.findtext("./ENGINE/DNS_SERVER/ENABLED") == "1"
    record_names = [
        record.findtext("NAME", default="")
        for record in server.findall(".//ENGINE/DNS_SERVER/NAMESERVER-DATABASE/RESOURCE-RECORD")
    ]
    assert "www.example.local" in record_names
    assert pc is not None
    assert pc.findtext("./ENGINE/DNS_CLIENT/SERVER_IP") == "192.168.10.20"


def test_edit_pkt_file_roundtrip_preserves_router_dhcp_and_acl_mutation(tmp_path: Path) -> None:
    source = _require_saves_root() / r"01 Networking\FTP\FTP.pkt"
    output = tmp_path / "router_dhcp_acl_roundtrip.pkt"
    xml_out = tmp_path / "router_dhcp_acl_roundtrip.xml"
    plan = parse_intent(
        "set Router0 dhcp pool BRANCH50 network 192.168.50.0/24 gateway 192.168.50.1 dns 192.168.0.2 start 192.168.50.100 "
        "set Router0 acl standard BRANCH50_OUT "
        "acl BRANCH50_OUT deny host 192.168.50.200 "
        "acl BRANCH50_OUT permit 192.168.50.0 0.0.0.255 "
        "apply acl BRANCH50_OUT out on Router0 FastEthernet0/0"
    )
    edit_pkt_file(source, plan, output, xml_out)

    assert output.exists()
    assert xml_out.exists()

    updated = decode_pkt_to_root(output)
    inventory = inventory_root(updated)
    assert "BRANCH50" in inventory["dhcp_pools"].get("Router0", [])
    assert "BRANCH50_OUT" in inventory["acl_names"].get("Router0", [])

    router = next(
        device
        for device in updated.findall(".//DEVICES/DEVICE")
        if device.findtext("./ENGINE/NAME", default="") == "Router0"
    )
    router_text = "\n".join(line.text or "" for line in router.findall("./ENGINE/RUNNINGCONFIG/LINE"))
    assert "ip dhcp pool BRANCH50" in router_text
    assert "network 192.168.50.0 255.255.255.0" in router_text
    assert "default-router 192.168.50.1" in router_text
    assert "ip access-list standard BRANCH50_OUT" in router_text
    assert "deny host 192.168.50.200" in router_text
    assert "ip access-group BRANCH50_OUT out" in router_text


def test_edit_pkt_file_roundtrip_preserves_management_vlan_and_telnet_mutation(tmp_path: Path) -> None:
    source = _require_saves_root() / r"01 Networking\FTP\FTP.pkt"
    output = tmp_path / "management_telnet_roundtrip.pkt"
    xml_out = tmp_path / "management_telnet_roundtrip.xml"
    plan = parse_intent(
        "set Switch0 management vlan 99 ip 192.168.99.10/24 gateway 192.168.99.1 "
        "enable telnet on Switch0 username admin password 123456"
    )
    edit_pkt_file(source, plan, output, xml_out)

    assert output.exists()
    assert xml_out.exists()

    updated = decode_pkt_to_root(output)
    inventory = inventory_root(updated)
    management = inventory["management"].get("Switch0")
    assert management is not None
    assert "99" in management["management_vlans"]
    assert management["default_gateway"] == "192.168.99.1"
    assert management["telnet_enabled"] is True
    assert "admin" in management["usernames"]
    assert management["enable_secret_present"] is True

    switch = next(
        device
        for device in updated.findall(".//DEVICES/DEVICE")
        if device.findtext("./ENGINE/NAME", default="") == "Switch0"
    )
    switch_text = "\n".join(line.text or "" for line in switch.findall("./ENGINE/RUNNINGCONFIG/LINE"))
    assert "interface Vlan99" in switch_text
    assert "ip address 192.168.99.10 255.255.255.0" in switch_text
    assert "ip default-gateway 192.168.99.1" in switch_text
    assert "username admin secret 123456" in switch_text
    assert "enable secret 123456" in switch_text
    assert "transport input telnet" in switch_text


def test_edit_pkt_file_roundtrip_enables_advanced_server_services(tmp_path: Path) -> None:
    source = _require_saves_root() / r"01 Networking\FTP\FTP.pkt"
    output = tmp_path / "advanced_services_roundtrip.pkt"
    xml_out = tmp_path / "advanced_services_roundtrip.xml"
    plan = parse_intent("enable ftp on Server0 enable email on Server0 enable syslog on Server0 enable aaa on Server0")
    edit_pkt_file(source, plan, output, xml_out)

    assert output.exists()
    assert xml_out.exists()

    updated = decode_pkt_to_root(output)
    inventory = inventory_root(updated)
    services = set(inventory["services"].get("Server0", []))
    assert {"ftp_server", "email_server", "syslog_server", "acs_server"} <= services


def test_edit_pkt_file_roundtrip_preserves_advanced_server_service_details(tmp_path: Path) -> None:
    source = _require_saves_root() / r"01 Networking\FTP\FTP.pkt"
    output = tmp_path / "advanced_service_details_roundtrip.pkt"
    xml_out = tmp_path / "advanced_service_details_roundtrip.xml"
    plan = parse_intent("set Server0 email domain example.local set Server0 aaa auth-port 1812")
    edit_pkt_file(source, plan, output, xml_out)

    assert output.exists()
    assert xml_out.exists()

    updated = decode_pkt_to_root(output)
    inventory = inventory_root(updated)
    assert inventory["service_details"]["Server0"]["email_domain"] == "example.local"
    assert inventory["service_details"]["Server0"]["aaa_auth_port"] == "1812"


def test_edit_pkt_file_roundtrip_preserves_combined_advanced_server_service_mutation(tmp_path: Path) -> None:
    source = _require_saves_root() / r"01 Networking\FTP\FTP.pkt"
    output = tmp_path / "advanced_service_combined_roundtrip.pkt"
    xml_out = tmp_path / "advanced_service_combined_roundtrip.xml"
    plan = parse_intent(
        "enable email on Server0 "
        "enable aaa on Server0 "
        "set Server0 email domain example.local "
        "set Server0 aaa auth-port 1812"
    )
    edit_pkt_file(source, plan, output, xml_out)

    updated = decode_pkt_to_root(output)
    inventory = inventory_root(updated)
    services = set(inventory["services"].get("Server0", []))
    assert {"email_server", "acs_server"} <= services
    assert inventory["service_details"]["Server0"]["email_domain"] == "example.local"
    assert inventory["service_details"]["Server0"]["aaa_auth_port"] == "1812"


def test_edit_pkt_file_roundtrip_preserves_router_on_a_stick_and_switching_mutation(tmp_path: Path) -> None:
    source = _require_saves_root() / r"01 Networking\FTP\FTP.pkt"
    output = tmp_path / "router_switching_roundtrip.pkt"
    xml_out = tmp_path / "router_switching_roundtrip.xml"
    plan = parse_intent(
        "set Switch0 vlan 10 name Finance "
        "set Switch0 access-port FastEthernet0/1 vlan 10 "
        "set Switch0 trunk-port FastEthernet0/24 allowed 10,99 native 99 "
        "set Router0 subinterface FastEthernet0/0.10 encapsulation dot1Q 10 ip 192.168.10.1/24 "
        "show vlan brief show interfaces trunk show ip interface brief"
    )
    edit_pkt_file(source, plan, output, xml_out)

    assert output.exists()
    assert xml_out.exists()

    updated = decode_pkt_to_root(output)
    inventory = inventory_root(updated)
    assert any(vlan["id"] == "10" and vlan["name"] == "Finance" for vlan in inventory["vlans"].get("Switch0", []))

    switch = next(
        device
        for device in updated.findall(".//DEVICES/DEVICE")
        if device.findtext("./ENGINE/NAME", default="") == "Switch0"
    )
    router = next(
        device
        for device in updated.findall(".//DEVICES/DEVICE")
        if device.findtext("./ENGINE/NAME", default="") == "Router0"
    )
    switch_text = "\n".join(line.text or "" for line in switch.findall("./ENGINE/RUNNINGCONFIG/LINE"))
    router_text = "\n".join(line.text or "" for line in router.findall("./ENGINE/RUNNINGCONFIG/LINE"))
    assert "vlan 10" in switch_text
    assert "name Finance" in switch_text
    assert "interface FastEthernet0/1" in switch_text
    assert "switchport mode access" in switch_text
    assert "switchport access vlan 10" in switch_text
    assert "interface FastEthernet0/24" in switch_text
    assert "switchport mode trunk" in switch_text
    assert "switchport trunk allowed vlan 10,99" in switch_text
    assert "switchport trunk native vlan 99" in switch_text
    assert "interface FastEthernet0/0.10" in router_text
    assert "encapsulation dot1Q 10" in router_text
    assert "ip address 192.168.10.1 255.255.255.0" in router_text


def test_edit_pkt_file_roundtrip_preserves_ipv6_routing_mutations(tmp_path: Path) -> None:
    source = _require_saves_root() / r"01 Networking\FTP\FTP.pkt"
    output = tmp_path / "ipv6_routing_roundtrip.pkt"
    xml_out = tmp_path / "ipv6_routing_roundtrip.xml"
    plan = parse_intent(
        "set Router0 ipv6 unicast-routing "
        "set Router0 interface FastEthernet0/0 ipv6 2001:db8:10::1/64 "
        "set Router0 slaac on FastEthernet0/0 prefix 2001:db8:10::/64 "
        "set Router0 dhcpv6 pool V6POOL prefix 2001:db8:10::/64 interface FastEthernet0/0 dns 2001:4860:4860::8888 domain atlas.local "
        "set Router0 ospfv3 1 area 0 interface FastEthernet0/0 "
        "set Router0 eigrp ipv6 100 interface FastEthernet0/0 "
        "set Router0 ripng RIPNG interface FastEthernet0/0 "
        "set Router0 hsrp 10 ipv6 2001:db8:10::fe interface FastEthernet0/0 priority 110"
    )
    edit_pkt_file(source, plan, output, xml_out)

    assert output.exists()
    assert xml_out.exists()

    updated = decode_pkt_to_root(output)
    inventory = inventory_root(updated)
    assert inventory["routing"]["Router0"]["capabilities"] == [
        "dhcpv6_stateful",
        "eigrp_ipv6",
        "hsrp",
        "ipv6_slaac",
        "ospfv3",
        "ripng",
    ]
    router = next(
        device
        for device in updated.findall(".//DEVICES/DEVICE")
        if device.findtext("./ENGINE/NAME", default="") == "Router0"
    )
    router_text = "\n".join(line.text or "" for line in router.findall("./ENGINE/RUNNINGCONFIG/LINE"))
    assert "ipv6 unicast-routing" in router_text
    assert "ipv6 address 2001:db8:10::1/64" in router_text
    assert "ipv6 nd prefix 2001:db8:10::/64" in router_text
    assert "ipv6 dhcp pool V6POOL" in router_text
    assert "address prefix 2001:db8:10::/64" in router_text
    assert "ipv6 dhcp server V6POOL" in router_text
    assert "ipv6 ospf 1 area 0" in router_text
    assert "ipv6 router ospf 1" in router_text
    assert "ipv6 eigrp 100" in router_text
    assert "ipv6 router eigrp 100" in router_text
    assert "ipv6 rip RIPNG enable" in router_text
    assert "standby 10 ipv6 2001:db8:10::fe" in router_text


def test_edit_pkt_file_roundtrip_preserves_l2_security_monitoring_mutations(tmp_path: Path) -> None:
    source = _require_saves_root() / r"01 Networking\FTP\FTP.pkt"
    output = tmp_path / "l2_security_monitoring_roundtrip.pkt"
    xml_out = tmp_path / "l2_security_monitoring_roundtrip.xml"
    plan = parse_intent(
        "set Switch0 dhcp snooping vlan 10 trust FastEthernet0/1 "
        "set Switch0 dai vlan 10 trust FastEthernet0/1 "
        "set Switch0 port-security FastEthernet0/2 max 2 violation restrict "
        "set Switch0 lldp enable "
        "set Switch0 rep segment 1 interface FastEthernet0/3 "
        "set Switch0 span 1 source FastEthernet0/10 destination FastEthernet0/5 "
        "set Router0 snmp community public ro "
        "set Router0 netflow destination 13.1.1.2 9996 version 9 interface FastEthernet0/0 ingress"
    )
    edit_pkt_file(source, plan, output, xml_out)

    assert output.exists()
    assert xml_out.exists()

    updated = decode_pkt_to_root(output)
    inventory = inventory_root(updated)
    assert inventory["l2_security_monitoring"]["Switch0"]["capabilities"] == [
        "dai",
        "dhcp_snooping",
        "lldp",
        "port_security",
        "rep",
        "span",
    ]
    assert inventory["l2_security_monitoring"]["Router0"]["capabilities"] == ["netflow", "snmp"]
    switch = next(
        device
        for device in updated.findall(".//DEVICES/DEVICE")
        if device.findtext("./ENGINE/NAME", default="") == "Switch0"
    )
    router = next(
        device
        for device in updated.findall(".//DEVICES/DEVICE")
        if device.findtext("./ENGINE/NAME", default="") == "Router0"
    )
    switch_text = "\n".join(line.text or "" for line in switch.findall("./ENGINE/RUNNINGCONFIG/LINE"))
    router_text = "\n".join(line.text or "" for line in router.findall("./ENGINE/RUNNINGCONFIG/LINE"))
    assert "ip dhcp snooping" in switch_text
    assert "ip dhcp snooping vlan 10" in switch_text
    assert "ip arp inspection vlan 10" in switch_text
    assert "ip arp inspection trust" in switch_text
    assert "switchport port-security maximum 2" in switch_text
    assert "switchport port-security violation restrict" in switch_text
    assert "lldp run" in switch_text
    assert "rep segment 1" in switch_text
    assert "monitor session 1 source interface FastEthernet0/10" in switch_text
    assert "monitor session 1 destination interface FastEthernet0/5" in switch_text
    assert "snmp-server community public ro" in router_text
    assert "ip flow-export destination 13.1.1.2 9996" in router_text
    assert "ip flow-export version 9" in router_text
    assert "ip flow ingress" in router_text


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


def test_apply_plan_operations_prunes_scenario_references() -> None:
    root = ET.Element("PACKETTRACER5")
    scenario_set = ET.SubElement(root, "SCENARIOSET")
    scenario = ET.SubElement(scenario_set, "SCENARIO")
    stale_pdu = ET.SubElement(scenario, "PDU")
    ET.SubElement(stale_pdu, "SOURCE").text = "save-ref-id:1"
    destination = ET.SubElement(stale_pdu, "DESTINATION")
    destination.set("device", "save-ref-id:1")
    keep_pdu = ET.SubElement(scenario, "PDU")
    ET.SubElement(keep_pdu, "SOURCE").text = "save-ref-id:2"
    keep_destination = ET.SubElement(keep_pdu, "DESTINATION")
    keep_destination.set("device", "save-ref-id:3")
    network = ET.SubElement(root, "NETWORK")
    devices = ET.SubElement(network, "DEVICES")
    device = ET.SubElement(devices, "DEVICE")
    engine = ET.SubElement(device, "ENGINE")
    ET.SubElement(engine, "TYPE").text = "PC"
    ET.SubElement(engine, "NAME").text = "PC0"
    ET.SubElement(engine, "SAVE_REF_ID").text = "save-ref-id:1"
    ET.SubElement(engine, "ORIGINAL_DEVICE_UUID").text = "{orig-uuid}"
    workspace = ET.SubElement(device, "WORKSPACE")
    physical = ET.SubElement(workspace, "PHYSICAL")
    physical.text = "{root},{city},{building},{closet},{leaf-uuid}"
    logical = ET.SubElement(workspace, "LOGICAL")
    ET.SubElement(logical, "MEM_ADDR").text = "100"
    ET.SubElement(network, "LINKS")

    plan = IntentPlan(goal="prune smoke", prompt="prune smoke", edit_operations=[{"op": "prune_device", "device": "PC0"}])
    updated = apply_plan_operations(root, plan)

    assert updated.find(".//DEVICES/DEVICE") is None
    scenario_xml = ET.tostring(updated.find("./SCENARIOSET"), encoding="unicode")
    assert "save-ref-id:1" not in scenario_xml
    assert "save-ref-id:2" in scenario_xml


def test_apply_plan_operations_reuses_port_mem_addr_from_existing_links() -> None:
    root = ET.Element("PACKETTRACER5")
    network = ET.SubElement(root, "NETWORK")
    devices = ET.SubElement(network, "DEVICES")
    for name, save_ref, mem_addr in [
        ("SW1", "save-ref-id:1", "100"),
        ("SW2", "save-ref-id:2", "200"),
    ]:
        device = ET.SubElement(devices, "DEVICE")
        engine = ET.SubElement(device, "ENGINE")
        ET.SubElement(engine, "TYPE").text = "Switch"
        ET.SubElement(engine, "NAME").text = name
        ET.SubElement(engine, "SAVE_REF_ID").text = save_ref
        workspace = ET.SubElement(device, "WORKSPACE")
        logical = ET.SubElement(workspace, "LOGICAL")
        ET.SubElement(logical, "MEM_ADDR").text = mem_addr
    links = ET.SubElement(network, "LINKS")
    link = ET.SubElement(links, "LINK")
    cable = ET.SubElement(link, "CABLE")
    ET.SubElement(cable, "FROM").text = "save-ref-id:1"
    ET.SubElement(cable, "PORT").text = "GigabitEthernet0/1"
    ET.SubElement(cable, "TO").text = "save-ref-id:2"
    ET.SubElement(cable, "PORT").text = "GigabitEthernet0/2"
    ET.SubElement(cable, "FROM_DEVICE_MEM_ADDR").text = "100"
    ET.SubElement(cable, "TO_DEVICE_MEM_ADDR").text = "200"
    ET.SubElement(cable, "FROM_PORT_MEM_ADDR").text = "1111"
    ET.SubElement(cable, "TO_PORT_MEM_ADDR").text = "2222"
    ET.SubElement(cable, "FUNCTIONAL").text = "true"
    ET.SubElement(cable, "GEO_VIEW_COLOR").text = "#6ba72e"
    ET.SubElement(cable, "IS_MANAGED_IN_RACK_VIEW").text = "false"
    ET.SubElement(cable, "TYPE").text = "eStraightThrough"

    plan = IntentPlan(
        goal="link smoke",
        prompt="link smoke",
        edit_operations=[
            {
                "op": "set_link",
                "a": {"dev": "SW1", "port": "GigabitEthernet0/1"},
                "b": {"dev": "SW2", "port": "GigabitEthernet0/2"},
                "media": "copper",
            }
        ],
    )
    updated = apply_plan_operations(root, plan)
    updated_cable = updated.find(".//LINKS/LINK/CABLE")
    assert updated_cable is not None
    assert updated_cable.findtext("FROM_PORT_MEM_ADDR") == "1111"
    assert updated_cable.findtext("TO_PORT_MEM_ADDR") == "2222"
    assert updated_cable.findtext("FUNCTIONAL") == "true"
    assert updated_cable.findtext("GEO_VIEW_COLOR") == "#6ba72e"
    assert updated_cable.findtext("IS_MANAGED_IN_RACK_VIEW") == "false"
