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
    trunk_op = next(op for op in plan.switch_ops if op["op"] == "set_trunk_port")
    assert trunk_op["native"] == 99
    assert "wireless_client_association" in plan.capabilities
    assert "wireless_mutation" in plan.capabilities
    assert "end_device_mutation" in plan.capabilities


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
    assert plan.wireless_mode == "ap_bridge"


def test_parse_small_office_nat_prompt_prefers_home_router_wireless_mode() -> None:
    plan = parse_intent("small office wifi nat qur 1 home router 2 pc 1 tablet olsun")
    assert plan.wireless_mode == "home_router_edge"


def test_parse_explicit_wireless_association_and_end_device_mutation_capabilities() -> None:
    plan = parse_intent(
        "associate Tablet0 to AP1 ssid FIN_WIFI dhcp "
        "set Tablet0 dns 192.168.10.20 "
        "set PC1 ipv4 dhcp"
    )
    assert "wireless_client_association" in plan.capabilities
    assert "wireless_client" in plan.capabilities
    assert "end_device_mutation" in plan.capabilities
    assert any(op["op"] == "associate_wireless_client" for op in plan.wireless_ops)
    assert any(op["op"] == "set_host_dns" for op in plan.end_device_ops)
    assert any(op["op"] == "set_host_dhcp" for op in plan.end_device_ops)


def test_parse_explicit_wireless_mutation_capability() -> None:
    plan = parse_intent("set AP1 ssid FIN_WIFI security wpa2-psk passphrase fin12345 channel 6")
    assert "wireless_ap" in plan.capabilities
    assert "wireless_mutation" in plan.capabilities
    assert any(op["op"] == "set_wireless_ssid" for op in plan.wireless_ops)


def test_parse_advanced_server_service_capabilities() -> None:
    plan = parse_intent("enable email on Server0 enable syslog on Server0 enable aaa on Server0")
    assert "server_email" in plan.capabilities
    assert "server_syslog" in plan.capabilities
    assert "server_aaa" in plan.capabilities
    assert any(op["op"] == "enable_server_service" and op["service"] == "email" for op in plan.server_ops)
    assert any(op["op"] == "enable_server_service" and op["service"] == "syslog" for op in plan.server_ops)
    assert any(op["op"] == "enable_server_service" and op["service"] == "aaa" for op in plan.server_ops)
    assert {"email", "syslog", "aaa"} <= set(plan.service_requirements["services"])


def test_parse_advanced_server_service_detail_operations() -> None:
    plan = parse_intent("set Server0 email domain example.local set Server0 aaa auth-port 1812")
    assert any(op["op"] == "set_server_email_domain" and op["domain"] == "example.local" for op in plan.server_ops)
    assert any(op["op"] == "set_server_aaa_auth_port" and op["auth_port"] == 1812 for op in plan.server_ops)


def test_parse_iot_registration_and_control_capabilities() -> None:
    plan = parse_intent("iot smart home qur register CO2 to Server0 and control Garage through Home Gateway0")
    assert "iot" in plan.capabilities
    assert "iot_registration" in plan.capabilities
    assert "iot_control" in plan.capabilities


def test_parse_explicit_iot_registration_operation() -> None:
    plan = parse_intent("register CO2 to Server0 mode remote_server server-address 1.0.0.10 username netadmin password iot123")
    assert any(op["op"] == "set_iot_registration" for op in plan.iot_ops)
    op = next(op for op in plan.iot_ops if op["op"] == "set_iot_registration")
    assert op["device"] == "CO2"
    assert op["target"] == "Server0"
    assert op["mode"] == "REMOTE_SERVER"
    assert op["server_address"] == "1.0.0.10"
    assert op["username"] == "netadmin"
    assert op["password"] == "iot123"


def test_parse_explicit_iot_rule_state_operation() -> None:
    plan = parse_intent('disable iot rule "open garage" on Server0')
    op = next(op for op in plan.iot_ops if op["op"] == "set_iot_rule_state")
    assert op["device"] == "Server0"
    assert op["rule_name"] == "open garage"
    assert op["enabled"] is False


def test_parse_wan_security_prompt_recognizes_phase_d_intent() -> None:
    plan = parse_intent("wan security edge qur gre tunnel ve ipsec vpn ppp olsun 1 multilayer switch 1 asa 1 cloud")
    assert plan.network_style == "wan_security"
    assert {"gre", "ipsec", "vpn", "ppp", "security_edge", "multilayer_switching"} <= set(plan.capabilities)
    assert plan.device_requirements["MultiLayerSwitch"] == 1
    assert plan.device_requirements["ASA"] == 1
    assert plan.device_requirements["Cloud"] == 1


def test_parse_explicit_wan_security_edit_operations() -> None:
    plan = parse_intent(
        "set R1 gre tunnel Tunnel0 source 10.0.0.1 destination 10.0.0.2 ip 172.16.0.1/30 "
        "set R1 ppp interface Serial0/0/0 authentication chap "
        "set R1 ipsec transform-set TS esp-aes esp-sha-hmac "
        "set R1 crypto map VPNMAP 10 peer 203.0.113.2 transform-set TS match ACL_VPN interface Serial0/0/0"
    )

    assert plan.network_style == "wan_security"
    assert {"gre", "ppp", "ipsec", "vpn"} <= set(plan.capabilities)
    assert any(op["op"] == "set_gre_tunnel" and op["interface"] == "Tunnel0" for op in plan.router_ops)
    assert any(op["op"] == "set_ppp_interface" and op["authentication"] == "chap" for op in plan.router_ops)
    assert any(op["op"] == "set_ipsec_transform_set" and op["name"] == "TS" for op in plan.router_ops)
    assert any(op["op"] == "set_crypto_map" and op["map_name"] == "VPNMAP" for op in plan.router_ops)


def test_parse_l2_resiliency_routing_prompt_without_span_drift() -> None:
    plan = parse_intent("bgp stp rstp etherchannel lacp pagp vtp dtp")

    assert plan.network_style == "l2_resiliency_routing"
    assert {"bgp", "stp", "rstp", "etherchannel", "lacp", "pagp", "vtp", "dtp"} <= set(plan.capabilities)
    assert "span" not in plan.capabilities


def test_parse_spanning_tree_does_not_create_span_capability() -> None:
    plan = parse_intent("spanning tree rapid pvst")

    assert plan.network_style == "l2_resiliency_routing"
    assert {"stp", "rstp"} <= set(plan.capabilities)
    assert "span" not in plan.capabilities


def test_parse_explicit_bgp_and_l2_resiliency_edit_operations() -> None:
    plan = parse_intent(
        "set R1 bgp 65001 neighbor 10.0.0.2 remote-as 65002 network 192.168.1.0 mask 255.255.255.0 "
        "set SW1 stp mode rapid-pvst vlan 10 root primary "
        "set SW1 etherchannel 1 mode active interfaces FastEthernet0/1 FastEthernet0/2 "
        "set SW1 etherchannel 2 mode desirable interfaces FastEthernet0/3 FastEthernet0/4 "
        "set SW1 vtp domain CAMPUS mode server version 2 "
        "set SW1 dtp interface FastEthernet0/1 mode dynamic desirable"
    )

    assert plan.network_style == "l2_resiliency_routing"
    assert {"bgp", "stp", "rstp", "etherchannel", "lacp", "pagp", "vtp", "dtp"} <= set(plan.capabilities)
    assert any(op["op"] == "set_bgp_neighbor" and op["asn"] == 65001 for op in plan.router_ops)
    assert any(op["op"] == "set_stp" and op["mode"] == "rapid-pvst" for op in plan.switch_ops)
    assert any(op["op"] == "set_etherchannel" and op["interfaces"] == ["FastEthernet0/1", "FastEthernet0/2"] for op in plan.switch_ops)
    assert any(op["op"] == "set_etherchannel" and op["mode"] == "desirable" for op in plan.switch_ops)
    assert any(op["op"] == "set_vtp" and op["domain"] == "CAMPUS" for op in plan.switch_ops)
    assert any(op["op"] == "set_dtp" and op["mode"] == "dynamic desirable" for op in plan.switch_ops)


def test_parse_ipv4_routing_management_prompt_without_service_heavy_drift() -> None:
    plan = parse_intent("ospf eigrp rip static default route dhcp relay nat pat ssh ntp syslog")

    assert plan.network_style == "ipv4_routing_management"
    assert {
        "ospfv2",
        "eigrp_ipv4",
        "ripv2",
        "static_route",
        "default_route",
        "dhcp_relay",
        "nat_static",
        "nat_dynamic",
        "pat",
        "ssh_ios",
        "ntp_ios",
        "syslog_ios",
    } <= set(plan.capabilities)
    assert plan.network_style != "service_heavy"


def test_parse_explicit_ipv4_routing_management_edit_operations() -> None:
    plan = parse_intent(
        "set R1 ospfv2 1 network 10.0.0.0 wildcard 0.0.0.255 area 0 "
        "set R1 eigrp ipv4 100 network 10.0.0.0 wildcard 0.0.0.255 no-auto-summary "
        "set R1 rip version 2 network 10.0.0.0 no-auto-summary "
        "set R1 static-route 0.0.0.0/0 via 10.0.0.1 "
        "set R1 dhcp-relay interface GigabitEthernet0/0 helper 192.168.1.10 "
        "set R1 nat inside interface GigabitEthernet0/0 "
        "set R1 nat outside interface Serial0/0/0 "
        "set R1 nat static 192.168.1.10 203.0.113.10 "
        "set R1 pat acl 1 interface Serial0/0/0 overload "
        "set R1 ssh domain lab.local username admin password cisco123 modulus 1024 "
        "set R1 ntp server 192.168.1.20 "
        "set R1 syslog server 192.168.1.30"
    )

    assert plan.network_style == "ipv4_routing_management"
    assert any(op["op"] == "set_ospfv2_network" and op["process_id"] == 1 for op in plan.router_ops)
    assert any(op["op"] == "set_eigrp_ipv4_network" and op["asn"] == 100 for op in plan.router_ops)
    assert any(op["op"] == "set_ripv2_network" and op["no_auto_summary"] is True for op in plan.router_ops)
    assert any(op["op"] == "set_static_route" and op["prefix"] == 0 for op in plan.router_ops)
    assert any(op["op"] == "set_dhcp_relay" and op["helper"] == "192.168.1.10" for op in plan.router_ops)
    assert any(op["op"] == "set_nat_interface" and op["role"] == "inside" for op in plan.router_ops)
    assert any(op["op"] == "set_nat_static" and op["inside_global"] == "203.0.113.10" for op in plan.router_ops)
    assert any(op["op"] == "set_pat_overload" and op["overload"] is True for op in plan.router_ops)
    assert any(op["op"] == "set_ssh_ios" and op["domain"] == "lab.local" for op in plan.router_ops)
    assert any(op["op"] == "set_ntp_server" and op["server"] == "192.168.1.20" for op in plan.router_ops)
    assert any(op["op"] == "set_syslog_server" and op["server"] == "192.168.1.30" for op in plan.router_ops)


def test_parse_explicit_programming_script_edit_operation() -> None:
    plan = parse_intent(
        'set "Py: real http server 2" script app "New Project (Python)" file "main.py" '
        'content "from realhttp import *\\nprint(\\"ok\\")"'
    )

    assert plan.network_style == "industrial_iot"
    assert {"real_http", "python_programming"} <= set(plan.capabilities)
    assert plan.programming_ops == [
        {
            "op": "set_script_file_content",
            "device": "Py: real http server 2",
            "app_name": "New Project (Python)",
            "file_name": "main.py",
            "content": 'from realhttp import *\nprint("ok")',
        }
    ]


def test_parse_explicit_automation_script_edit_operation() -> None:
    plan = parse_intent(
        'set "python" script app "New Project (Python)" file "main.py" '
        'content "print(\\"automation\\")"'
    )

    assert plan.network_style == "automation_controller"
    assert {"python_programming"} <= set(plan.capabilities)
    assert "real_http" not in plan.capabilities
    assert "real_websocket" not in plan.capabilities
    assert "mqtt" not in plan.capabilities


def test_parse_feature_atlas_prompts_without_service_heavy_drift() -> None:
    cases = [
        ("ipv6 ospf dhcpv6 slaac hsrp", "ipv6_routing", {"ipv6_slaac", "dhcpv6_stateful", "hsrp"}),
        ("snmp netflow span qos dhcp snooping dai dot1x port security", "l2_security_monitoring", {"snmp", "netflow", "span", "qos", "dhcp_snooping", "dai", "dot1x", "port_security"}),
        ("lldp rep span rspan", "l2_security_monitoring", {"lldp", "rep", "span"}),
        ("voip phones with call manager", "voice_collaboration", {"voip", "call_manager"}),
        ("mqtt iot with websocket", "industrial_iot", {"mqtt", "real_websocket"}),
        ("wlc bluetooth meraki 5g cellular wpa enterprise", "wireless_advanced", {"wlc", "bluetooth", "meraki", "cellular_5g", "wpa_enterprise"}),
        ("wep guest wifi beamforming", "wireless_advanced", {"wep", "guest_wifi", "beamforming"}),
        ("network controller python javascript blockly tcp udp app vm iox", "automation_controller", {"network_controller", "python_programming", "javascript_programming", "blockly_programming", "tcp_udp_app", "vm_iox"}),
        ("coaxial cable dsl central office cell tower power distribution hot swappable ios license", "physical_media_device", {"coaxial", "cable_dsl", "central_office", "cell_tower", "power_distribution", "hot_swappable", "ios_license"}),
    ]
    for prompt, family, capabilities in cases:
        plan = parse_intent(prompt)
        assert plan.network_style == family
        assert capabilities <= set(plan.capabilities)
        assert plan.network_style != "service_heavy"


def test_parse_industrial_real_http_does_not_drift_to_generic_http_generate_signal() -> None:
    plan = parse_intent("mqtt real http websocket industrial iot")

    assert plan.network_style == "industrial_iot"
    assert {"mqtt", "real_http", "real_websocket"} <= set(plan.capabilities)


def test_parse_explicit_voice_edit_commands() -> None:
    plan = parse_intent(
        'set "Router0" telephony service source-address 192.168.10.1 port 2000 max-ephones 4 max-dn 4 '
        'set "Router0" ephone-dn 1 number 1001 '
        'set "Router0" ephone 1 mac 0001.42AA.BBCC button 1:1 '
        'set "Router0" dial-peer voice 10 destination-pattern 2... session-target ipv4:10.0.0.2'
    )

    assert plan.network_style == "voice_collaboration"
    assert {"voip", "ip_phone", "call_manager"} <= set(plan.capabilities)
    assert any(op["op"] == "set_telephony_service" and op["source_address"] == "192.168.10.1" for op in plan.router_ops)
    assert any(op["op"] == "set_ephone_dn" and op["number"] == "1001" for op in plan.router_ops)
    assert any(op["op"] == "set_ephone" and op["mac"] == "0001.42AA.BBCC" for op in plan.router_ops)
    assert any(op["op"] == "set_dial_peer_voice" and op["session_target"] == "10.0.0.2" for op in plan.router_ops)
    assert "server_http" not in plan.capabilities
    assert "iot" not in plan.capabilities


def test_parse_explicit_ipv6_routing_operations() -> None:
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

    assert plan.network_style == "ipv6_routing"
    assert {"ipv6_slaac", "dhcpv6_stateful", "ospfv3", "eigrp_ipv6", "ripng", "hsrp"} <= set(plan.capabilities)
    assert any(op["op"] == "enable_ipv6_unicast_routing" for op in plan.router_ops)
    assert any(op["op"] == "set_ipv6_address" and op["address"] == "2001:db8:10::1" for op in plan.router_ops)
    assert any(op["op"] == "set_ipv6_slaac" and op["prefix"] == "2001:db8:10::" for op in plan.router_ops)
    assert any(op["op"] == "set_dhcpv6_pool" and op["name"] == "V6POOL" for op in plan.router_ops)
    assert any(op["op"] == "set_ospfv3_interface" and op["process_id"] == 1 for op in plan.router_ops)
    assert any(op["op"] == "set_eigrp_ipv6_interface" and op["asn"] == 100 for op in plan.router_ops)
    assert any(op["op"] == "set_ripng_interface" and op["process_name"] == "RIPNG" for op in plan.router_ops)
    assert any(op["op"] == "set_hsrp_ipv6" and op["priority"] == 110 for op in plan.router_ops)


def test_parse_explicit_l2_security_monitoring_operations() -> None:
    plan = parse_intent(
        "set SW1 dhcp snooping vlan 10 trust GigabitEthernet0/1 "
        "set SW1 dai vlan 10 trust GigabitEthernet0/1 "
        "set SW1 port-security FastEthernet0/2 max 2 violation restrict "
        "set SW1 lldp enable "
        "set SW1 rep segment 1 interface GigabitEthernet0/3 "
        "set SW1 span 1 source FastEthernet0/10 destination FastEthernet0/5 "
        "set R1 snmp community public ro "
        "set R1 netflow destination 13.1.1.2 9996 version 9 interface FastEthernet0/0 ingress"
    )

    assert plan.network_style == "l2_security_monitoring"
    assert {"dhcp_snooping", "dai", "port_security", "lldp", "rep", "span", "snmp", "netflow"} <= set(plan.capabilities)
    assert any(op["op"] == "set_dhcp_snooping" and op["vlan"] == 10 for op in plan.switch_ops)
    assert any(op["op"] == "set_dai" and op["trust_port"] == "GigabitEthernet0/1" for op in plan.switch_ops)
    assert any(op["op"] == "set_port_security" and op["maximum"] == 2 for op in plan.switch_ops)
    assert any(op["op"] == "set_lldp" for op in plan.switch_ops)
    assert any(op["op"] == "set_rep" and op["segment"] == 1 for op in plan.switch_ops)
    assert any(op["op"] == "set_span" and op["source"] == "FastEthernet0/10" for op in plan.switch_ops)
    assert any(op["op"] == "set_snmp_community" and op["community"] == "public" for op in plan.router_ops)
    assert any(op["op"] == "set_netflow" and op["destination"] == "13.1.1.2" for op in plan.router_ops)


def test_parse_explicit_dot1x_and_qos_edit_operations() -> None:
    plan = parse_intent(
        "set SW1 dot1x interface FastEthernet0/1 mode auto radius 192.168.1.10 key radius123 "
        "set SW1 qos class-map VOICE match dscp ef policy-map QOS_POLICY class VOICE priority service-policy output FastEthernet0/1"
    )

    assert plan.network_style == "l2_security_monitoring"
    assert {"dot1x", "qos"} <= set(plan.capabilities)
    assert any(
        op["op"] == "set_dot1x"
        and op["interface"] == "FastEthernet0/1"
        and op["radius_host"] == "192.168.1.10"
        for op in plan.switch_ops
    )
    assert any(
        op["op"] == "set_qos_policy"
        and op["class_map"] == "VOICE"
        and op["policy_map"] == "QOS_POLICY"
        and op["direction"] == "output"
        for op in plan.switch_ops
    )


def test_parse_explicit_cbac_and_zfw_edit_operations() -> None:
    plan = parse_intent(
        "set R1 cbac inspect FIREWALL protocol tcp interface FastEthernet0/0 direction in "
        "set R1 zfw zone inside interface FastEthernet0/0 "
        "set R1 zfw zone-pair INSIDE_OUT source inside destination outside policy POLICY1 "
        "set R1 zfw class-map CM_WEB match protocol http policy-map POLICY1 action inspect"
    )

    assert plan.network_style == "wan_security"
    assert {"cbac", "zfw", "security_edge"} <= set(plan.capabilities)
    assert any(op["op"] == "set_cbac_inspect" and op["name"] == "FIREWALL" for op in plan.router_ops)
    assert any(op["op"] == "set_zfw_zone_interface" and op["zone"] == "inside" for op in plan.router_ops)
    assert any(op["op"] == "set_zfw_zone_pair" and op["pair_name"] == "INSIDE_OUT" for op in plan.router_ops)
    assert any(op["op"] == "set_zfw_policy" and op["policy_map"] == "POLICY1" for op in plan.router_ops)


def test_parse_explicit_advanced_wireless_edit_operations() -> None:
    plan = parse_intent(
        "set AP1 ssid LEGACY security wep passphrase abc12345 channel 6 "
        "set WLC1 ssid CORP security wpa-enterprise radius 192.168.1.10 secret radius123 channel 11"
    )

    assert plan.network_style == "wireless_advanced"
    assert {"wireless_ap", "wireless_mutation", "wep", "wpa_enterprise"} <= set(plan.capabilities)
    wep_op = next(op for op in plan.wireless_ops if op["ssid"] == "LEGACY")
    enterprise_op = next(op for op in plan.wireless_ops if op["ssid"] == "CORP")
    assert wep_op["security"] == "wep"
    assert enterprise_op["security"] == "wpa-enterprise"
    assert enterprise_op["radius_server"] == "192.168.1.10"


def test_parse_management_ops_with_spaced_device_name() -> None:
    plan = parse_intent(
        "set Switch Management management vlan 99 ip 192.168.99.2/24 gateway 192.168.99.1 "
        "enable telnet on Switch Management username admin password 123456"
    )
    assert any(op["op"] == "set_management_vlan" and op["device"] == "Switch Management" for op in plan.management_ops)
    assert any(op["op"] == "enable_telnet" and op["device"] == "Switch Management" for op in plan.management_ops)


def test_parse_natural_acl_create_and_apply_with_spaced_device_name() -> None:
    plan = parse_intent(
        "create acl MGMT_ONLY on Router0 "
        "acl MGMT_ONLY permit host 192.168.20.100 "
        "apply acl MGMT_ONLY out on Router0 interface FastEthernet0/0"
    )
    assert any(op["op"] == "set_acl" and op["acl_name"] == "MGMT_ONLY" and op["device"] == "Router0" for op in plan.router_ops)
    assert any(op["op"] == "add_acl_rule" and op["acl_name"] == "MGMT_ONLY" for op in plan.router_ops)
    assert any(
        op["op"] == "apply_acl"
        and op["acl_name"] == "MGMT_ONLY"
        and op["device"] == "Router0"
        and op["interface"] == "FastEthernet0/0"
        for op in plan.router_ops
    )
