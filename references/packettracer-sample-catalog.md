# Packet Tracer Installed Sample Catalog

Source root: `<PACKET_TRACER_SAVES_ROOT>`

- `01 Networking\3650\HotSwappablePower.pkt`
  version: `7.1.0.0000`, devices: `2`, links: `0`
  tags: switching
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Multilayer Switch0 (MultiLayerSwitch/3650-24PS)
- `01 Networking\8200\8200.pkt`
  version: `9.0.0.0000`, devices: `8`, links: `6`
  tags: host_server, multi_router, switching
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Router0 (Router/2811), Switch0 (Switch/2960-24TT), PC0 (Pc/PC-PT), netcon (NetworkController/NetworkController), Router4 (Router/2901), Router2 (Router/PT8200), Router1 (Router/IR1101)
- `01 Networking\Cisco Application Management\tcp_test_app.pkt`
  version: `7.0.0.0000`, devices: `5`, links: `4`
  tags: host_server, management_vlan, switching
  devices: PC0 (Pc/PC-PT), Router0 (Router/1841), Switch0 (Switch/2950-24), Server0 (Server/Server-PT), Server1 (Server/Server-PT)
- `01 Networking\Cisco Application Management\udp_test_app.pkt`
  version: `7.0.0.0000`, devices: `4`, links: `3`
  tags: host_server, management_vlan, switching
  devices: Switch0 (Switch/2950-24), Server0 (Server/Server-PT), Server1 (Server/Server-PT), PC0 (Pc/PC-PT)
- `01 Networking\Cisco Application Management\uploading_and_running_vm.pkt`
  version: `7.0.0.0000`, devices: `2`, links: `1`
  tags: host_server, management_vlan
  devices: PC0 (Pc/PC-PT), Server0 (Server/Server-PT)
- `01 Networking\Coaxial Splitter\tvcoaxiatpcserver.pkt`
  decode error: `ValueError: EAX authentication tag verification failed`
- `01 Networking\DHCP\autoconfig_ipv6_router_to_router_other_config_flag.pkt`
  version: `6.1.0.0026`, devices: `2`, links: `1`
  tags: dhcp_pool, multi_router, router_dhcp, server_dhcp
  devices: Server (Router/1841), Client (Router/1841)
- `01 Networking\DHCP\dhcp_apipa.pkt`
  version: `6.1.0.0073`, devices: `5`, links: `4`
  tags: dhcp_pool, host_server, router_dhcp, server_dhcp, switching
  devices: PC0 (Pc/PC-PT), Server0 (Server/Server-PT), Switch0 (Switch/2950-24), PC1 (Pc/PC-PT), Router1 (Router/1841)
- `01 Networking\DHCP\dhcp_conflict.pkt`
  version: `6.1.0.0026`, devices: `6`, links: `5`
  tags: dhcp_pool, host_server, multi_router, router_dhcp, server_dhcp, switching
  devices: Router0 (Router/1841), Switch0 (Switch/2950-24), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), PC2 (Pc/PC-PT), Router1 (Router/1841)
- `01 Networking\DHCP\dhcp_port_based_address_allocation.pkt`
  version: `7.0.0.0000`, devices: `7`, links: `4`
  tags: dhcp_pool, host_server, router_dhcp, server_dhcp, switching
  devices: Switch0 (Switch/2960-24TT), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), PC2 (Pc/PC-PT), Router0 (Router/1841), PC3 (Pc/PC-PT), PC4 (Pc/PC-PT)
- `01 Networking\DHCP\dhcp_port_based_address_allocation_ie2000.pkt`
  version: `7.0.0.0000`, devices: `7`, links: `4`
  tags: dhcp_pool, host_server, router_dhcp, server_dhcp, switching
  devices: PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), PC2 (Pc/PC-PT), Router0 (Router/1841), PC3 (Pc/PC-PT), PC4 (Pc/PC-PT), Switch1 (Switch/IE-2000)
- `01 Networking\DHCP\dhcp_reservation.pkt`
  version: `7.0.0.0000`, devices: `9`, links: `4`
  tags: dhcp_pool, host_server, router_dhcp, server_dhcp, switching, wireless, wireless_ap
  devices: Wireless Router0 (WirelessRouter/Linksys-WRT300N), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Switch1 (Switch/2960-24TT), PC4 (Pc/PC-PT), PC5 (Pc/PC-PT), PC2 (Pc/PC-PT), PC3 (Pc/PC-PT), Switch0 (Switch/2960-24TT)
- `01 Networking\DHCP\dhcp_snooping_attacker.pkt`
  version: `9.0.0.0000`, devices: `6`, links: `4`
  tags: dhcp_pool, host_server, router_dhcp, server_dhcp, switching
  devices: DHCP Server (Router/1841), DHCP Snooper (Switch/2960-24TT), DHCP Client (Pc/PC-PT), Attacker (Server/Server-PT), Switch0 (Switch/2960-24TT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\DHCP\dhcp_snooping_db_saved_in_flash.pkt`
  version: `9.0.0.0000`, devices: `5`, links: `3`
  tags: dhcp_pool, host_server, multi_router, router_dhcp, server_dhcp, switching
  devices: DHCP Server (Router/1841), DHCP Client (Pc/PC-PT), Router0 (Router/1841), DHCP Snooper (Switch/2960-24TT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\DHCP\dhcp_snooping_limit_rate.pkt`
  version: `9.0.0.0000`, devices: `4`, links: `2`
  tags: dhcp_pool, host_server, router_dhcp, server_dhcp, switching
  devices: DHCP Server (Router/1841), DHCP Snooper (Switch/2960-24TT), DHCP Client (Pc/PC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\DHCP\dhcp_snooping_option_82.pkt`
  version: `9.0.0.0000`, devices: `10`, links: `6`
  tags: dhcp_pool, dhcp_snooping, host_server, router_dhcp, server_dhcp, switching
  devices: Cisco DHCP Server (Router/1841), DHCP Snooper 2 (Switch/2960-24TT), DHCP Client (Pc/PC-PT), DHCP Snooper (Switch/2960-24TT), DHCP Client 2 (Pc/PC-PT), DHCP Snooper 4 (Switch/2960-24TT), DHCP Snooper 3 (Switch/2960-24TT), Server0 (Server/Server-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Power Distribution Device1 (Power Distribution Device/Power Distribution Device)
- `01 Networking\DHCP\dhcp_snooping_trusted_untrusted_gigabit_ports.pkt`
  version: `9.0.0.0000`, devices: `8`, links: `5`
  tags: dhcp_pool, dhcp_snooping, host_server, multi_router, router_dhcp, server_dhcp, switching
  devices: DHCP Server (Router/1841), DHCP Snooper (Switch/2960-24TT), DHCP Client (Pc/PC-PT), DHCP Client 2 (Pc/PC-PT), DHCP Server 2 (Router/1841), Router0 (Router/1841), DHCP Snooper 2 (Switch/2960-24TT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\DHCP\dhcp_snooping_trusted_untrusted_ports.pkt`
  version: `9.0.0.0000`, devices: `8`, links: `5`
  tags: dhcp_pool, dhcp_snooping, host_server, multi_router, router_dhcp, server_dhcp, switching
  devices: DHCP Server (Router/1841), DHCP Snooper (Switch/2960-24TT), DHCP Client (Pc/PC-PT), DHCP Snooper 2 (Switch/2960-24TT), DHCP Client 2 (Pc/PC-PT), DHCP Server 2 (Router/1841), Router0 (Router/1841), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\DHCP\dhcpv6_router_as_client.pkt`
  version: `6.1.0.0026`, devices: `2`, links: `1`
  tags: dhcp_pool, host_server, multi_router, router_dhcp, server_dhcp
  devices: DHCPv6Server (Router/1841), DHCPv6Client (Router/1841)
- `01 Networking\DHCP\ipv6_address_prefix.pkt`
  version: `7.3.1.0000`, devices: `3`, links: `1`
  tags: dhcp_pool, multi_router, router_dhcp, server_dhcp
  devices: DHCPv6Server (Router/1941), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), RouterClient (Router/1941)
- `01 Networking\DNS\Multilevel_DNS.pkt`
  version: `5.2.0.0068`, devices: `10`, links: `9`
  tags: dns, host_server, multi_router, server_dns, switching
  devices: Client (Pc/PC-PT), Local DNS Server (Server/Server-PT), Internet (Router/1841), Switch0 (Switch/2950-24), Root DNS Server (Server/Server-PT), Example (Router/1841), Company (Router/1841), Switch1 (Switch/2950-24), server.example.com (Server/Server-PT), authority.example.com (Server/Server-PT)
- `01 Networking\EIGRP\baseEigrpAuth_packet.pkt`
  version: `6.1.0.0092`, devices: `3`, links: `2`
  tags: eigrp, multi_router
  devices: Router0 (Router/2811), Router1 (Router/2811), Router2 (Router/2811)
- `01 Networking\EIGRP\eigrp_fr_no_broadcast.pkt`
  version: `6.1.0.0026`, devices: `3`, links: `2`
  tags: eigrp, multi_router
  devices: Router0 (Router/1841), Router1 (Router/1841), Cloud0 (Cloud/Cloud-PT)
- `01 Networking\EIGRP\eigrp_fr_no_broadcast_no_network.pkt`
  version: `6.1.0.0026`, devices: `3`, links: `2`
  tags: eigrp, multi_router
  devices: Router0 (Router/1841), Router1 (Router/1841), Cloud0 (Cloud/Cloud-PT)
- `01 Networking\EIGRP\eigrp_fr_no_broadcast_preconfigured.pkt`
  version: `6.1.0.0026`, devices: `3`, links: `2`
  tags: eigrp, multi_router
  devices: Router0 (Router/1841), Router1 (Router/1841), Cloud0 (Cloud/Cloud-PT)
- `01 Networking\EIGRP\eigrp_neighbor_hdlc.pkt`
  version: `6.1.0.0026`, devices: `3`, links: `2`
  tags: eigrp, multi_router
  devices: Router0 (Router/1841), Router1 (Router/1841), Router2 (Router/1841)
- `01 Networking\EIGRP\eigrp_neighbor_hdlc_preconfigured.pkt`
  version: `6.1.0.0026`, devices: `3`, links: `2`
  tags: eigrp, multi_router
  devices: Router0 (Router/1841), Router1 (Router/1841), Router2 (Router/1841)
- `01 Networking\EIGRP\ipv6_eigrp_fr_no_broadcast.pkt`
  version: `6.1.0.0026`, devices: `3`, links: `2`
  tags: eigrp, multi_router
  devices: Router0 (Router/1841), Router1 (Router/1841), Cloud0 (Cloud/Cloud-PT)
- `01 Networking\EIGRP\ipv6_eigrp_neighbor.pkt`
  version: `6.1.0.0026`, devices: `2`, links: `1`
  tags: eigrp, multi_router
  devices: Router0 (Router/1841), Router1 (Router/1841)
- `01 Networking\FTP\FTP.pkt`
  version: `5.3.0.0011`, devices: `5`, links: `4`
  tags: ftp_http_https, host_server, server_ftp, switching
  devices: PC0 (Pc/PC-PT), Server0 (Server/Server-PT), Router0 (Router/1841), Switch0 (Switch/2950-24), PC1 (Pc/PC-PT)
- `01 Networking\HomeRouter\hr-beamforming.pkt`
  version: `7.2.0.0071`, devices: `2`, links: `0`
  tags: host_server
  devices: PC1 (Pc/PC-PT), Wireless Router0 (WirelessRouterNewGeneration/HomeRouter-PT-AC)
- `01 Networking\HomeRouter\hr-guest.pkt`
  version: `7.2.0.0000`, devices: `3`, links: `0`
  tags: host_server
  devices: HOME ROUTER (WirelessRouterNewGeneration/HomeRouter-PT-AC), OWNER (Pc/PC-PT), GUEST (Pc/PC-PT)
- `01 Networking\HomeRouter\hr-isp-vlans-ip-dhcp.pkt`
  version: `7.2.0.0000`, devices: `13`, links: `8`
  tags: dhcp_pool, host_server, router_dhcp, server_dhcp, vlan, wireless_client
  devices: HOME ROUTER (WirelessRouterNewGeneration/HomeRouter-PT-AC), ISP ROUTER (Router/Router-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), PC2 (Pc/PC-PT), PC3 (Pc/PC-PT), PC4 (Pc/PC-PT), WEB SERVER (Server/Server-PT), PC5 (Pc/PC-PT), PC6 (Pc/PC-PT), Hub0 (Hub/Hub-PT), Laptop0 (Laptop/Laptop-PT)
- `01 Networking\HomeRouter\hr-isp-vlans-ip-static.pkt`
  version: `7.2.0.0000`, devices: `13`, links: `8`
  tags: host_server, vlan, wireless_client
  devices: HOME ROUTER (WirelessRouterNewGeneration/HomeRouter-PT-AC), ISP ROUTER (Router/Router-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), PC2 (Pc/PC-PT), PC3 (Pc/PC-PT), PC4 (Pc/PC-PT), WEB SERVER (Server/Server-PT), PC5 (Pc/PC-PT), PC6 (Pc/PC-PT), Hub0 (Hub/Hub-PT), Laptop0 (Laptop/Laptop-PT)
- `01 Networking\HomeRouter\hr-wireless-ap.pkt`
  version: `7.2.0.0000`, devices: `9`, links: `6`
  tags: host_server, wireless, wireless_ap, wireless_client
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), ISP ROUTER (Router/Router-PT), PC7 (Pc/PC-PT), PC9 (Pc/PC-PT), WEB SERVER (Server/Server-PT), WIRELESS AP (WirelessRouterNewGeneration/HomeRouter-PT-AC), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), MAIN ROUTER (WirelessRouterNewGeneration/HomeRouter-PT-AC)
- `01 Networking\HomeRouter\hr-wireless-media-bridge.pkt`
  version: `7.2.0.0000`, devices: `10`, links: `6`
  tags: host_server, wireless, wireless_ap, wireless_client
  devices: WIRELESS MEDIA BRIDGE 1 (WirelessRouterNewGeneration/HomeRouter-PT-AC), MAIN ROUTER (WirelessRouter/Linksys-WRT300N), PC0 (Pc/PC-PT), Laptop0 (Laptop/Laptop-PT), PC1 (Pc/PC-PT), ISP ROUTER (Router/Router-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), WEB SERVER (Server/Server-PT), WIRELESS MEDIA BRIDGE 2 (WirelessRouterNewGeneration/HomeRouter-PT-AC), PC2 (Pc/PC-PT)
- `01 Networking\HSRP\Hsrp_Ping_When_Router_Priority_Is_Higher.pkt`
  version: `6.0.0.0002`, devices: `7`, links: `7`
  tags: host_server, multi_router, switching
  devices: Router0 (Router/1841), Router1 (Router/1841), Switch1 (Switch/2950T-24), Switch2 (Switch/2950T-24), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Router2 (Router/1841)
- `01 Networking\HSRP\Hsrp_Simple_Ping_With_Same_Priority.pkt`
  version: `6.0.0.0002`, devices: `7`, links: `7`
  tags: host_server, multi_router, switching
  devices: Router0 (Router/1841), Router1 (Router/1841), Switch1 (Switch/2950T-24), Switch2 (Switch/2950T-24), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Router2 (Router/1841)
- `01 Networking\HSRP\Hsrp_Test_Track_Interface_Command.pkt`
  version: `6.0.0.0002`, devices: `7`, links: `7`
  tags: host_server, multi_router, switching
  devices: Router0 (Router/1841), Router1 (Router/1841), Switch1 (Switch/2950T-24), Switch2 (Switch/2950T-24), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Router2 (Router/1841)
- `01 Networking\HTTPS\HTTPS.pkt`
  decode error: `ValueError: EAX authentication tag verification failed`
- `01 Networking\IOS_15\isrg2_devices_licenses.pkt`
  version: `6.0.0.0002`, devices: `3`, links: `0`
  tags: multi_router
  devices: Router1 (Router/1941), Router2 (Router/2901), Router3 (Router/2911)
- `01 Networking\IOS_15\upgrading_2811_to_ios15.pkt`
  version: `6.1.0.0026`, devices: `2`, links: `1`
  tags: host_server
  devices: Server0 (Server/Server-PT), Router2 (Router/2811)
- `01 Networking\IOS_15\upgrading_2960_to_ios15.pkt`
  version: `6.1.0.0026`, devices: `2`, links: `1`
  tags: host_server, switching
  devices: Server0 (Server/Server-PT), Switch0 (Switch/2960-24TT)
- `01 Networking\IOS_15\upgrading_to_ios15_3.pkt`
  version: `7.1.0.0000`, devices: `6`, links: `4`
  tags: host_server, multi_router, switching
  devices: Switch1 (Switch/2960-24TT), Router0 (Router/1941), Router1 (Router/2901), Router2 (Router/2911), TFTP Server (Server/Server-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\IPv4\IP fragmentation.pkt`
  decode error: `ValueError: EAX authentication tag verification failed`
- `01 Networking\IPv6\dhcpv6_pt_server.pkt`
  version: `7.3.1.0000`, devices: `6`, links: `3`
  tags: dhcp_pool, host_server, router_dhcp, server_dhcp, switching
  devices: PC0 (Pc/PC-PT), Router0 (Router/1841), Switch0 (Switch/2950-24), DHCPv6 Server (Server/Server-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Power Distribution Device1 (Power Distribution Device/Power Distribution Device)
- `01 Networking\IPv6\DNS-A-and-AAAA-records.pkt`
  version: `8.0.0.0000`, devices: `8`, links: `6`
  tags: dns, host_server, server_dns, switching
  devices: PC0 (Pc/PC-PT), DNS Server (Server/Server-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Switch0 (Switch/2960-24TT), PC1 (Pc/PC-PT), PC2 (Pc/PC-PT), Server (Server/Server-PT), Router0 (Router/ISR4331)
- `01 Networking\IPv6\ipv6_nd_ra_dns_server.pkt`
  version: `8.1.0.0000`, devices: `5`, links: `3`
  tags: dns, host_server, multi_router, server_dns, switching
  devices: Router0 (Router/ISR4331), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PC0 (Pc/PC-PT), Switch0 (Switch/2960-24TT), Router1 (Router/ISR4331)
- `01 Networking\IPv6\ipv6_prefix_delegation.pkt`
  version: `7.3.1.0000`, devices: `5`, links: `3`
  tags: host_server, multi_router, switching
  devices: HOME-RR (Router/2901), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), ISP-DR (Router/2911), Switch0 (Switch/2960-24TT), PC0 (Pc/PC-PT)
- `01 Networking\IPv6\ipv6_slaac.pkt`
  decode error: `ParseError: not well-formed (invalid token): line 713, column 24`
- `01 Networking\IPv6\ipv6_stateful_dhcpv6.pkt`
  decode error: `ParseError: not well-formed (invalid token): line 712, column 24`
- `01 Networking\IPv6\ipv6_stateful_dhcpv6_prefixlength_80.pkt`
  decode error: `ParseError: not well-formed (invalid token): line 712, column 24`
- `01 Networking\IPv6\ipv6_stateless_dhcpv6.pkt`
  decode error: `ParseError: not well-formed (invalid token): line 712, column 24`
- `01 Networking\IPv6\Ipv6Ip Tunneling\ipv6ip_eigrp.pkt`
  version: `6.0.0.0018`, devices: `3`, links: `2`
  tags: eigrp, multi_router
  devices: R1 (Router/2811), R2 (Router/2811), R3 (Router/2811)
- `01 Networking\IPv6\Ipv6Ip Tunneling\ipv6ip_ospf.pkt`
  version: `6.0.0.0002`, devices: `3`, links: `2`
  tags: multi_router, ospf
  devices: R1 (Router/2811), R2 (Router/2811), R3 (Router/2811)
- `01 Networking\IPv6\Ipv6Ip Tunneling\ipv6ip_ospf_rip.pkt`
  version: `6.0.0.0002`, devices: `5`, links: `4`
  tags: multi_router, ospf, rip
  devices: R1 (Router/2811), R2 (Router/2811), R3 (Router/2811), R4 (Router/2811), R5 (Router/2811)
- `01 Networking\IPv6\Ipv6Ip Tunneling\IsatapPcClient.pkt`
  version: `6.0.0.0027`, devices: `6`, links: `5`
  tags: host_server, multi_router, switching
  devices: IsatapClient (Pc/PC-PT), Switch0 (Switch/2950-24), DNS Server (Server/Server-PT), IPv4 Network (Router/1841), IsatapServer (Router/1841), www.example.com (Server/Server-PT)
- `01 Networking\IPv6\netsh_interface_ipv6_show_neighbors.pkt`
  version: `7.3.1.0000`, devices: `7`, links: `3`
  tags: host_server, multi_router
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Power Distribution Device1 (Power Distribution Device/Power Distribution Device), PC1 (Pc/PC-PT), Router0 (Router/2901), PC2 (Pc/PC-PT), Server0 (Server/Server-PT), Router1 (Router/2901)
- `01 Networking\IPv6\switch2960_slaac.pkt`
  version: `8.1.0.0000`, devices: `3`, links: `1`
  tags: switching
  devices: Switch0 (Switch/2960-24TT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Switch1 (Switch/2960-24TT)
- `01 Networking\Linksys\dhcp_linksys_server.pkt`
  decode error: `ValueError: EAX authentication tag verification failed`
- `01 Networking\Linksys\Linksys_Access_Restriction.pkt`
  version: `5.2.0.0068`, devices: `8`, links: `6`
  tags: access_port, host_server, multi_router, vlan, wireless, wireless_ap, wireless_client
  devices: Wireless Router0 (WirelessRouter/Linksys-WRT300N), Server0 (Server/Server-PT), SNMP Server (Router/1841), PC0 (Pc/PC-PT), Laptop0 (Laptop/Laptop-PT), PC1 (Pc/PC-PT), LANRouter (Router/1841), www.example.com (Server/Server-PT)
- `01 Networking\LLDP\lldp_sample.pkt`
  version: `7.1.0.0000`, devices: `8`, links: `5`
  tags: multi_router, switching
  devices: Switch0 (Switch/2950-24), Switch1 (Switch/2960-24TT), Router0 (Router/2911), Hub0 (Hub/Hub-PT), Router1 (Router/1841), Router2 (Router/1841), Switch2 (Switch/2960-24TT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\Mail\mail_2Server_2PC.pkt`
  version: `7.0.0.0000`, devices: `5`, links: `4`
  tags: host_server
  devices: deepak@cisco.com (Pc/PC-PT), jitu@example.com (Pc/PC-PT), cisco.com (Server/Server-PT), example.com (Server/Server-PT), Hub0 (Hub/Hub-PT)
- `01 Networking\Meraki\meraki_SA_firewall.pkt`
  version: `8.2.1.0106`, devices: `10`, links: `6`
  tags: host_server, multi_router, switching
  devices: Security Appliance0 (SecurityAppliance/Meraki-MX65W), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PC0 (Pc/PC-PT), Router0 (Router/2901), Router1 (Router/2901), Switch0 (Switch/2960-24TT), Meraki Server0 (MerakiServer/Meraki-Server), PC1 (Pc/PC-PT), PC2 (Pc/PC-PT), PC3 (Pc/PC-PT)
- `01 Networking\Meraki\meraki_SA_pppoe.pkt`
  version: `7.2.0.0000`, devices: `8`, links: `6`
  tags: host_server, multi_router, switching
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PppoeServer (Router/2811), Security Appliance0 (SecurityAppliance/Meraki-MX65W), PC0 (Pc/PC-PT), Router0 (Router/1941), Switch0 (Switch/2960-24TT), Meraki Server0 (MerakiServer/Meraki-Server), PC1 (Pc/PC-PT)
- `01 Networking\Meraki\meraki_SA_sample.pkt`
  version: `7.2.0.0000`, devices: `8`, links: `6`
  tags: host_server, multi_router, switching
  devices: Security Appliance0 (SecurityAppliance/Meraki-MX65W), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PC0 (Pc/PC-PT), Router0 (Router/2901), Router1 (Router/2901), Switch0 (Switch/2960-24TT), Meraki Server0 (MerakiServer/Meraki-Server), PC1 (Pc/PC-PT)
- `01 Networking\Meraki\meraki_SA_wireless.pkt`
  version: `7.2.0.0000`, devices: `10`, links: `6`
  tags: host_server, multi_router, switching, wireless, wireless_ap, wireless_client
  devices: Security Appliance0 (SecurityAppliance/Meraki-MX65W), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PC0 (Pc/PC-PT), Router0 (Router/2901), Router1 (Router/2901), Switch0 (Switch/2960-24TT), Meraki Server0 (MerakiServer/Meraki-Server), PC1 (Pc/PC-PT), PC2 (Pc/PC-PT), PC3 (Pc/PC-PT)
- `01 Networking\Meraki\meraki_SA_wireless_wep.pkt`
  version: `7.2.0.0000`, devices: `10`, links: `6`
  tags: host_server, multi_router, switching, wireless, wireless_ap, wireless_client
  devices: Security Appliance0 (SecurityAppliance/Meraki-MX65W), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PC0 (Pc/PC-PT), Router0 (Router/2901), Router1 (Router/2901), Switch0 (Switch/2960-24TT), Meraki Server0 (MerakiServer/Meraki-Server), PC1 (Pc/PC-PT), PC2 (Pc/PC-PT), PC3 (Pc/PC-PT)
- `01 Networking\Meraki\meraki_SA_wireless_wpa2_enterprise.pkt`
  version: `7.2.0.0000`, devices: `11`, links: `7`
  tags: host_server, multi_router, switching, wireless, wireless_ap, wireless_client
  devices: Security Appliance0 (SecurityAppliance/Meraki-MX65W), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PC0 (Pc/PC-PT), Router0 (Router/2901), Router1 (Router/2901), Switch0 (Switch/2960-24TT), Meraki Server0 (MerakiServer/Meraki-Server), PC1 (Pc/PC-PT), PC2 (Pc/PC-PT), PC3 (Pc/PC-PT), RadiusServer0 (Server/Server-PT)
- `01 Networking\Meraki\meraki_SA_wireless_wpa2_psk.pkt`
  version: `7.2.0.0000`, devices: `10`, links: `6`
  tags: host_server, multi_router, switching, wireless, wireless_ap, wireless_client
  devices: Security Appliance0 (SecurityAppliance/Meraki-MX65W), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PC0 (Pc/PC-PT), Router0 (Router/2901), Router1 (Router/2901), Switch0 (Switch/2960-24TT), Meraki Server0 (MerakiServer/Meraki-Server), PC1 (Pc/PC-PT), PC2 (Pc/PC-PT), PC3 (Pc/PC-PT)
- `01 Networking\NAT\Outside_Nat.pkt`
  decode error: `ValueError: EAX authentication tag verification failed`
- `01 Networking\Netflow\flexible_netflow.pkt`
  version: `6.1.0.0026`, devices: `5`, links: `4`
  tags: host_server, multi_router
  devices: Router0 (Router/1841), Router1 (Router/1841), PC0 (Pc/PC-PT), Router2 (Router/1841), PC1 (Pc/PC-PT)
- `01 Networking\Netflow\traditional_netflow.pkt`
  version: `6.1.0.0026`, devices: `3`, links: `2`
  tags: host_server, multi_router
  devices: NFCollector (Server/Server-PT), R1 (Router/2811), NFExporter (Router/2811)
- `01 Networking\NTP\chained_ntp_network.pkt`
  version: `7.2.0.0000`, devices: `4`, links: `2`
  tags: multi_router, ntp
  devices: Ntp Client 1 (Router/1941), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Ntp Client 2 (Router/1941), Primary Server (Router/1941)
- `01 Networking\NTP\ntp_router.pkt`
  version: `7.2.0.0000`, devices: `3`, links: `1`
  tags: multi_router, ntp
  devices: Router0 (Router/1941), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Router1 (Router/1941)
- `01 Networking\NTP\ntp_switch.pkt`
  version: `7.2.0.0000`, devices: `3`, links: `1`
  tags: ntp, switching
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Switch0 (Switch/2960-24TT), Switch1 (Switch/2960-24TT)
- `01 Networking\OSPF\ipv6_ospf_area_range.pkt`
  version: `6.1.0.0026`, devices: `3`, links: `2`
  tags: multi_router, ospf
  devices: Router0 (Router/1841), Router1 (Router/1841), Router2 (Router/1841)
- `01 Networking\OSPF\ipv6_ospf_network_p2p.pkt`
  version: `6.1.0.0026`, devices: `2`, links: `1`
  tags: multi_router, ospf
  devices: Router0 (Router/1841), Router1 (Router/1841)
- `01 Networking\OSPF\ipv6_ospf_network_p2p_configured.pkt`
  version: `6.1.0.0026`, devices: `2`, links: `1`
  tags: multi_router, ospf
  devices: Router0 (Router/1841), Router1 (Router/1841)
- `01 Networking\OSPF\ospf_area_range.pkt`
  version: `6.1.0.0092`, devices: `3`, links: `2`
  tags: multi_router, ospf
  devices: Router0 (Router/1841), Router1 (Router/1841), Router2 (Router/1841)
- `01 Networking\OSPF\ospf_auto_cost.pkt`
  version: `6.0.0.0002`, devices: `4`, links: `3`
  tags: multi_router, ospf
  devices: Router0 (Router/1841), Router1 (Router/1841), Router2 (Router/1841), Router3 (Router/1841)
- `01 Networking\OSPF\ospf_distance_update.pkt`
  version: `6.0.0.0002`, devices: `3`, links: `2`
  tags: multi_router, ospf, tablet
  devices: Router0 (Router/1841), Router1 (Router/1841), Router2 (Router/1841)
- `01 Networking\OSPF\ospf_neighbor_with_framerelay.pkt`
  version: `6.1.0.0026`, devices: `4`, links: `3`
  tags: multi_router, ospf
  devices: Router0 (Router/1841), Router1 (Router/1841), Cloud0 (Cloud/Cloud-PT), Router2 (Router/1841)
- `01 Networking\OSPF\ospf_network_lo_p2p.pkt`
  version: `6.1.0.0026`, devices: `2`, links: `1`
  tags: multi_router, ospf
  devices: Router0 (Router/1841), Router1 (Router/1841)
- `01 Networking\OSPF\ospf_networkbroadcast_with_framerelay.pkt`
  version: `6.1.0.0026`, devices: `3`, links: `2`
  tags: multi_router, ospf
  devices: Router0 (Router/1841), Router1 (Router/1841), Cloud0 (Cloud/Cloud-PT)
- `01 Networking\OSPF\ospf_range_cost.pkt`
  version: `6.1.0.0092`, devices: `3`, links: `2`
  tags: multi_router, ospf
  devices: Router0 (Router/1841), Router1 (Router/1841), Router2 (Router/1841)
- `01 Networking\OSPF\ospfv3_neighbor_with_framerelay.pkt`
  version: `6.1.0.0026`, devices: `4`, links: `3`
  tags: multi_router, ospf
  devices: Router0 (Router/1841), Router1 (Router/1841), Cloud0 (Cloud/Cloud-PT), Router2 (Router/1841)
- `01 Networking\OSPF\ospfv3_neighbor_with_framerelay_configured.pkt`
  version: `6.1.0.0026`, devices: `4`, links: `3`
  tags: multi_router, ospf
  devices: Router0 (Router/1841), Router1 (Router/1841), Cloud0 (Cloud/Cloud-PT), Router2 (Router/1841)
- `01 Networking\OSPF\show_ip_ospf_database.pkt`
  version: `6.2.0.0000`, devices: `3`, links: `2`
  tags: multi_router, ospf
  devices: Router0 (Router/1841), Router1 (Router/1841), Router2 (Router/1841)
- `01 Networking\OSPF\show_ip_ospf_database_virtual.pkt`
  version: `6.2.0.0000`, devices: `3`, links: `2`
  tags: multi_router, ospf
  devices: Router0 (Router/1841), Router1 (Router/1841), Router2 (Router/1841)
- `01 Networking\OSPF\show_ipv6_ospf_database.pkt`
  version: `6.2.0.0000`, devices: `3`, links: `2`
  tags: multi_router, ospf
  devices: R1 (Router/1841), R2 (Router/1841), R3 (Router/1841)
- `01 Networking\OSPF\show_ipv6_ospf_database_virtual.pkt`
  version: `6.2.0.0000`, devices: `3`, links: `2`
  tags: multi_router, ospf
  devices: 2.2.2.2 (Router/1841), 1.1.1.1 (Router/1841), Router2 (Router/1841)
- `01 Networking\PPPOE\client.server.aaa.pkt`
  version: `7.2.0.0000`, devices: `4`, links: `2`
  tags: host_server
  devices: PC0 (Pc/PC-PT), PppoeServer (Router/2811), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Radius AAA Server (Server/Server-PT)
- `01 Networking\PPPOE\client.server.modem.pppoe.pkt`
  version: `7.2.0.0000`, devices: `5`, links: `3`
  tags: host_server
  devices: PC0 (Pc/PC-PT), DSL Modem0 (DslModem/DSL-Modem-PT), Cloud0 (Cloud/Cloud-PT), Router0 (Router/2811), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\PPPOE\pppoe_ipv4_ipv6_dual.pkt`
  version: `8.2.0.0000`, devices: `3`, links: `1`
  tags: multi_router
  devices: R2-Client (Router/1941), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), R1-Server (Router/1941)
- `01 Networking\PPPOE\pppoe_ipv6.pkt`
  version: `8.2.1.0000`, devices: `3`, links: `1`
  tags: multi_router
  devices: R2-Client (Router/1941), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), R1-Server (Router/1941)
- `01 Networking\PPPOE\pppoe_multipleClients.pkt`
  version: `7.2.0.0000`, devices: `5`, links: `3`
  tags: host_server, multi_router, wireless, wireless_ap
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PppoeClient1 (Router/1941), PppoeClient2 (WirelessRouter/Linksys-WRT300N), PppoeClient3 (Pc/PC-PT), Router2 (Router/2811)
- `01 Networking\PPPOE\wireless.pppoe.pkt`
  version: `7.1.0.0000`, devices: `4`, links: `2`
  tags: host_server, wireless, wireless_ap, wireless_client
  devices: Router0 (Router/2811), Wireless Router0 (WirelessRouter/Linksys-WRT300N), PC0 (Pc/PC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\QoS\QoS.pkt`
  decode error: `ValueError: EAX authentication tag verification failed`
- `01 Networking\REP\rep_four_devices.pkt`
  version: `8.2.1.0000`, devices: `13`, links: `12`
  tags: host_server, switching
  devices: Switch0 (MultiLayerSwitch/IE-2000), Switch1 (MultiLayerSwitch/IE-2000), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), PC2 (Pc/PC-PT), Switch2 (MultiLayerSwitch/IE-2000), PC4 (Pc/PC-PT), PC5 (Pc/PC-PT), PC6 (Pc/PC-PT), PC7 (Pc/PC-PT), PC8 (Pc/PC-PT), Switch3 (MultiLayerSwitch/IE-2000), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\REP\rep_two_devices.pkt`
  version: `8.2.1.0000`, devices: `5`, links: `3`
  tags: host_server, switching
  devices: Switch0 (MultiLayerSwitch/IE-2000), Switch1 (MultiLayerSwitch/IE-2000), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT)
- `01 Networking\RIP\rip_default_information_originate_ipv4_ipv6.pkt`
  version: `6.1.0.0026`, devices: `3`, links: `2`
  tags: multi_router, nat, rip
  devices: R1 (Router/1841), R2 (Router/1841), R3 (Router/1841)
- `01 Networking\SNMP\SNMP_Router.pkt`
  decode error: `ValueError: EAX authentication tag verification failed`
- `01 Networking\SNMP\wlc_3504_snmp.pkt`
  version: `8.2.1.0106`, devices: `11`, links: `5`
  tags: host_server, switching, wireless, wireless_ap
  devices: Multilayer Switch0 (MultiLayerSwitch/3560-24PS), Light Weight Access Point0 (LightWeightAccessPoint/LAP-PT), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Router0 (Router/1941), Light Weight Access Point1 (LightWeightAccessPoint/LAP-PT), PC2 (Pc/PC-PT), PC3 (Pc/PC-PT), AdminPC (Pc/PC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Wireless LAN Controller0 (WirelessLanController/WLC-3504)
- `01 Networking\SPAN\span_local_and_remote.pkt`
  version: `7.0.0.0000`, devices: `7`, links: `7`
  tags: host_server, switching
  devices: RSPAN SRC (Switch/2950-24), RSPAN DEST (Switch/2950-24), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Sniffer0 (Sniffer/Sniffer), Sniffer1 (Sniffer/Sniffer), Sniffer2 (Sniffer/Sniffer)
- `01 Networking\Terminal Server\cable_test.pkt`
  version: `5.4.0.0002`, devices: `9`, links: `8`
  tags: host_server, multi_router, telnet
  devices: Router0 (Router/1841), Router1 (Router/1841), Router2 (Router/2620XM), Router3 (Router/2621XM), Router4 (Router/1841), Router5 (Router/1941), Router6 (Router/2901), Router7 (Router/2911), Router8 (Router/Router-PT)
- `01 Networking\Terminal Server\ssh_test.pkt`
  decode error: `ParseError: not well-formed (invalid token): line 175, column 24`
- `01 Networking\Terminal Server\telnet_test.pkt`
  decode error: `ParseError: not well-formed (invalid token): line 176, column 24`
- `01 Networking\TFTP\TFTP.pkt`
  decode error: `ValueError: EAX authentication tag verification failed`
- `01 Networking\VoIP\VoIP Linksys.pkt`
  decode error: `ValueError: EAX authentication tag verification failed`
- `01 Networking\VoIP\voip_local_all_phone_devices.pkt`
  version: `7.1.0.0000`, devices: `8`, links: `6`
  tags: host_server, switching
  devices: Router0 (Router/2811), Multilayer Switch0 (MultiLayerSwitch/3560-24PS), IP Phone0 (IpPhone/7960), IP Phone1 (IpPhone/7960), Home VoIP0 (HomeVoip/Home-VoIP-PT), Analog Phone0 (AnalogPhone/Analog-Phone-PT), PC0 (Pc/PC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\VoIP\voip_remote.pkt`
  decode error: `ValueError: EAX authentication tag verification failed`
- `01 Networking\VPN\Tunnel_No_Ipsec.pkt`
  decode error: `ValueError: EAX authentication tag verification failed`
- `01 Networking\VPN\Vpn_Easy.pkt`
  version: `8.1.0.0000`, devices: `7`, links: `5`
  tags: host_server, multi_router, switching, vpn
  devices: VPN_Server (Router/1841), Router1 (Router/1841), PC0 (Pc/PC-PT), AAA_Server (Server/Server-PT), Switch0 (Switch/2950-24), PC1 (Pc/PC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\Wireless\5G\5G.pkt`
  version: `9.0.0.0000`, devices: `5`, links: `0`
  tags: host_server, tablet, wireless, wireless_ap, wireless_client
  devices: Cell Tower0 (CellTower/Cell-Tower), Smartphone0 (Pda/SMARTPHONE-PT), IoT0 (MCUComponent/Thing), Tablet PC0 (TabletPC/TabletPC-PT), PC0 (Pc/PC-PT)
- `01 Networking\Wireless\5G\5G_IR8340_IR1101.pkt`
  version: `9.0.0.0000`, devices: `5`, links: `1`
  tags: multi_router, wireless, wireless_ap, wireless_client
  devices: Central Office Server0 (CentralOfficeServer/Central-Office-Server), Cell Tower1 (CellTower/Cell-Tower), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Router1 (Router/IR1101), Router0 (Router/IR8340)
- `01 Networking\Wireless\Bluetooth\bluetooth tethering.pkt`
  version: `7.2.0.0000`, devices: `7`, links: `2`
  tags: tablet, wireless, wireless_ap, wireless_client
  devices: Smartphone0 (Pda/SMARTPHONE-PT), Cell Tower0 (CellTower/Cell-Tower), Central Office Server0 (CentralOfficeServer/Central-Office-Server), Router0 (Router/2911), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Laptop0 (Laptop/Laptop-PT), Tablet PC0 (TabletPC/TabletPC-PT)
- `01 Networking\Wireless\Cell and Wireless Path.pkt`
  version: `7.0.0.0000`, devices: `6`, links: `4`
  tags: tablet, wireless, wireless_ap, wireless_client
  devices: Wireless Router1 (WirelessRouter/Linksys-WRT300N), Smartphone0 (Pda/SMARTPHONE-PT), Cell Tower0 (CellTower/Cell-Tower), Central Office Server0 (CentralOfficeServer/Central-Office-Server), Hub0 (Hub/Hub-PT), Router0 (Router/1841)
- `01 Networking\Wireless\Cellular\Cell and Wireless Path.pkt`
  version: `7.0.0.0000`, devices: `6`, links: `4`
  tags: tablet, wireless, wireless_ap, wireless_client
  devices: Wireless Router1 (WirelessRouter/Linksys-WRT300N), Smartphone0 (Pda/SMARTPHONE-PT), Cell Tower0 (CellTower/Cell-Tower), Central Office Server0 (CentralOfficeServer/Central-Office-Server), Hub0 (Hub/Hub-PT), Router0 (Router/1841)
- `01 Networking\Wireless\Cellular\Cell Tower Service.pkt`
  version: `7.0.0.0000`, devices: `8`, links: `2`
  tags: tablet, wireless, wireless_ap, wireless_client
  devices: Central Office Server0 (CentralOfficeServer/Central-Office-Server), Cell Tower0 (CellTower/Cell-Tower), Cell Tower1 (CellTower/Cell-Tower), Smartphone0 (Pda/SMARTPHONE-PT), Smartphone1 (Pda/SMARTPHONE-PT), Smartphone2 (Pda/SMARTPHONE-PT), Smartphone3 (Pda/SMARTPHONE-PT), Smartphone4 (Pda/SMARTPHONE-PT)
- `01 Networking\Wireless\Cellular\CentralOfficeExternalAccess.pkt`
  version: `7.1.0.0000`, devices: `5`, links: `2`
  tags: access_port, tablet, vlan, wireless, wireless_ap, wireless_client
  devices: Central Office Server0 (CentralOfficeServer/Central-Office-Server), Cell Tower1 (CellTower/Cell-Tower), Smartphone1 (Pda/SMARTPHONE-PT), Router0 (Router/1841), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\Wireless\Cellular\IPv6 Cellular.pkt`
  version: `7.1.0.0000`, devices: `4`, links: `2`
  tags: host_server, tablet, wireless, wireless_ap, wireless_client
  devices: Central Office Server0 (CentralOfficeServer/Central-Office-Server), Smartphone0 (Pda/SMARTPHONE-PT), Cell Tower0 (CellTower/Cell-Tower), PC0 (Pc/PC-PT)
- `01 Networking\Wireless\Wireless LAN\802_11a_b_g_n.pkt`
  version: `8.2.1.4208`, devices: `8`, links: `0`
  tags: host_server, wireless, wireless_ap, wireless_client
  devices: Access PointA (AccessPoint/AccessPoint-PT-A), Access PointN (AccessPoint/AccessPoint-PT-N), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Server0 (Server/Server-PT), Laptop0 (Laptop/Laptop-PT), Access Point_B_G (AccessPoint/AccessPoint-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\Wireless\Wireless LAN\WLC\remote WLC and two AP groups.pkt`
  version: `8.2.1.4208`, devices: `10`, links: `4`
  tags: host_server, switching, wireless, wireless_ap, wireless_client
  devices: Multilayer Switch0 (MultiLayerSwitch/3560-24PS), AP0 (LightWeightAccessPoint/LAP-PT), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Wireless LAN Controller0 (WirelessLanController/WLC-PT), Router0 (Router/1941), AP1 (LightWeightAccessPoint/LAP-PT), PC2 (Pc/PC-PT), PC3 (Pc/PC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\Wireless\Wireless LAN\WLC\simple wlan.pkt`
  version: `8.2.1.4208`, devices: `7`, links: `3`
  tags: host_server, switching, wireless, wireless_ap, wireless_client
  devices: Multilayer Switch0 (MultiLayerSwitch/3560-24PS), Light Weight Access Point0 (LightWeightAccessPoint/LAP-PT), Server0 (Server/Server-PT), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Wireless LAN Controller0 (WirelessLanController/WLC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\Wireless\Wireless LAN\WLC\two wlans.pkt`
  version: `8.2.1.4208`, devices: `10`, links: `4`
  tags: host_server, switching, wireless, wireless_ap, wireless_client
  devices: Multilayer Switch0 (MultiLayerSwitch/3560-24PS), Light Weight Access Point0 (LightWeightAccessPoint/LAP-PT), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Wireless LAN Controller0 (WirelessLanController/WLC-PT), Router0 (Router/1941), Light Weight Access Point1 (LightWeightAccessPoint/LAP-PT), PC2 (Pc/PC-PT), PC3 (Pc/PC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\Wireless\Wireless LAN\WLC\wlc_2504_simple_wlan.pkt`
  version: `9.0.0.0000`, devices: `8`, links: `4`
  tags: host_server, switching, wireless, wireless_ap, wireless_client
  devices: Multilayer Switch0 (MultiLayerSwitch/3560-24PS), Light Weight Access Point0 (LightWeightAccessPoint/LAP-PT), Server0 (Server/Server-PT), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Wireless LAN Controller1 (WirelessLanController/WLC-2504), PC2 (Pc/PC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\Wireless\Wireless LAN\WLC\wlc_2504_simple_wlan_dhcp.pkt`
  version: `8.2.1.4208`, devices: `7`, links: `3`
  tags: dhcp_pool, host_server, router_dhcp, server_dhcp, switching, wireless, wireless_ap, wireless_client
  devices: Multilayer Switch0 (MultiLayerSwitch/3560-24PS), Light Weight Access Point0 (LightWeightAccessPoint/LAP-PT), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Wireless LAN Controller1 (WirelessLanController/WLC-2504), Admin (Pc/PC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\Wireless\Wireless LAN\WLC\wlc_2504_simple_wlan_wpa_radius.pkt`
  version: `9.0.0.0000`, devices: `8`, links: `4`
  tags: host_server, switching, wireless, wireless_ap, wireless_client
  devices: Multilayer Switch0 (MultiLayerSwitch/3560-24PS), Light Weight Access Point0 (LightWeightAccessPoint/LAP-PT), RadiusServer0 (Server/Server-PT), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Wireless LAN Controller0 (WirelessLanController/WLC-2504), PC2 (Pc/PC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\Wireless\Wireless LAN\WLC\wlc_2504_startup_wizard.pkt`
  version: `7.1.0.0000`, devices: `4`, links: `2`
  tags: host_server, switching, wireless, wireless_ap, wireless_client
  devices: Multilayer Switch0 (MultiLayerSwitch/3560-24PS), PC0 (Pc/PC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Wireless LAN Controller0 (WirelessLanController/WLC-2504)
- `01 Networking\Wireless\Wireless LAN\WLC\wlc_2504_two_wlans.pkt`
  version: `7.1.0.0000`, devices: `10`, links: `5`
  tags: host_server, switching, wireless, wireless_ap, wireless_client
  devices: Multilayer Switch0 (MultiLayerSwitch/3560-24PS), Light Weight Access Point0 (LightWeightAccessPoint/LAP-PT), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Router0 (Router/1941), Light Weight Access Point1 (LightWeightAccessPoint/LAP-PT), PC2 (Pc/PC-PT), PC3 (Pc/PC-PT), Wireless LAN Controller1 (WirelessLanController/WLC-2504), AdminPC (Pc/PC-PT)
- `01 Networking\Wireless\Wireless LAN\WLC\wlc_3504_simple_wlan.pkt`
  version: `7.3.0.0902`, devices: `8`, links: `4`
  tags: host_server, switching, wireless, wireless_ap, wireless_client
  devices: Multilayer Switch0 (MultiLayerSwitch/3560-24PS), Light Weight Access Point0 (LightWeightAccessPoint/LAP-PT), Server0 (Server/Server-PT), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), PC2 (Pc/PC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Wireless LAN Controller0 (WirelessLanController/WLC-3504)
- `01 Networking\Wireless\Wireless LAN\WLC\wlc_3504_startup_wizard.pkt`
  version: `7.3.0.0902`, devices: `4`, links: `2`
  tags: host_server, switching, wireless, wireless_ap, wireless_client
  devices: Multilayer Switch0 (MultiLayerSwitch/3560-24PS), PC0 (Pc/PC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Wireless LAN Controller1 (WirelessLanController/WLC-3504)
- `01 Networking\Wireless\Wireless LAN\WLC\wlc_3504_two_wlans.pkt`
  version: `7.3.0.0902`, devices: `10`, links: `4`
  tags: host_server, switching, wireless, wireless_ap, wireless_client
  devices: Multilayer Switch0 (MultiLayerSwitch/3560-24PS), Light Weight Access Point0 (LightWeightAccessPoint/LAP-PT), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Light Weight Access Point1 (LightWeightAccessPoint/LAP-PT), PC2 (Pc/PC-PT), PC3 (Pc/PC-PT), AdminPC (Pc/PC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Wireless LAN Controller0 (WirelessLanController/WLC-3504)
- `01 Networking\Wireless\Wireless LAN\WLC\wlc_3504_two_wlans_external_dhcp.pkt`
  version: `7.3.0.0902`, devices: `11`, links: `5`
  tags: dhcp_pool, host_server, router_dhcp, server_dhcp, switching, wireless, wireless_ap, wireless_client
  devices: Multilayer Switch0 (MultiLayerSwitch/3560-24PS), Light Weight Access Point0 (LightWeightAccessPoint/LAP-PT), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Router0 (Router/1941), Light Weight Access Point1 (LightWeightAccessPoint/LAP-PT), PC2 (Pc/PC-PT), PC3 (Pc/PC-PT), AdminPC (Pc/PC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Wireless LAN Controller0 (WirelessLanController/WLC-3504)
- `01 Networking\Wireless\Wireless LAN\WLC\wlc_pt_simple_wlan_wep_authen.pkt`
  version: `7.1.0.0000`, devices: `7`, links: `3`
  tags: host_server, switching, wireless, wireless_ap, wireless_client
  devices: Multilayer Switch0 (MultiLayerSwitch/3560-24PS), Light Weight Access Point0 (LightWeightAccessPoint/LAP-PT), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Wireless LAN Controller0 (WirelessLanController/WLC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PC2 (Pc/PC-PT)
- `01 Networking\Wireless\Wireless LAN\WLC\wlc_pt_simple_wlan_wpa_radius.pkt`
  version: `7.1.0.0000`, devices: `7`, links: `3`
  tags: host_server, switching, wireless, wireless_ap, wireless_client
  devices: Multilayer Switch0 (MultiLayerSwitch/3560-24PS), Light Weight Access Point0 (LightWeightAccessPoint/LAP-PT), RadiusServer0 (Server/Server-PT), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Wireless LAN Controller0 (WirelessLanController/WLC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `01 Networking\Wireless\Wireless LAN\WLC\wlc_pt_two_wlans_wpa_radius.pkt`
  version: `7.1.0.0000`, devices: `11`, links: `6`
  tags: host_server, switching, wireless, wireless_ap, wireless_client
  devices: Multilayer Switch0 (MultiLayerSwitch/3560-24PS), Light Weight Access Point0 (LightWeightAccessPoint/LAP-PT), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Wireless LAN Controller0 (WirelessLanController/WLC-PT), Router0 (Router/1941), Light Weight Access Point1 (LightWeightAccessPoint/LAP-PT), PC2 (Pc/PC-PT), PC3 (Pc/PC-PT), RadiusServer0_Wlan1 (Server/Server-PT), RadiusServer1_Wlan2 (Server/Server-PT)
- `02 Infrastructure Automation\Network Controller\netcon.pkt`
  version: `7.4.0.0000`, devices: `15`, links: `10`
  tags: host_server, multi_router, switching, tablet, wireless, wireless_ap, wireless_client
  devices: Router1 (Router/ISR4331), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Router0 (Router/2811), Switch0 (Switch/2960-24TT), PC0 (Pc/PC-PT), Router2 (Router/ISR4321), Router3 (Router/ISR4321), netcon (NetworkController/NetworkController), Router4 (Router/2901), Wireless Router0 (WirelessRouter/Linksys-WRT300N), PC1 (Pc/PC-PT), Central Office Server0 (CentralOfficeServer/Central-Office-Server), Cell Tower0 (CellTower/Cell-Tower), Smartphone0 (Pda/SMARTPHONE-PT), Smartphone1 (Pda/SMARTPHONE-PT)
- `02 Infrastructure Automation\Network Controller\netcon_initial_setup.pkt`
  version: `7.4.0.0000`, devices: `3`, links: `1`
  tags: host_server
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PC0 (Pc/PC-PT), netcon (NetworkController/NetworkController)
- `02 Infrastructure Automation\Network Controller\programming.pkt`
  version: `7.4.0.0000`, devices: `7`, links: `5`
  tags: host_server, switching
  devices: javascript (Pc/PC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PT-Controller0 (NetworkController/NetworkController), Router0 (Router/1941), python (Pc/PC-PT), Switch0 (Switch/2960-24TT), blockly (Pc/PC-PT)
- `02 Infrastructure Automation\Network Controller\programming_with_python_requests.pkt`
  version: `7.4.0.0000`, devices: `5`, links: `3`
  tags: host_server, switching
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PT-Controller0 (NetworkController/NetworkController), Router0 (Router/1941), python (Pc/PC-PT), Switch0 (Switch/2960-24TT)
- `03 Cybersecurity\AAA\AAA_Radius_2Server.pkt`
  version: `6.1.0.0026`, devices: `5`, links: `4`
  tags: host_server, switching
  devices: R1 (Router/1841), Switch0 (Switch/2950-24), PC1 (Pc/PC-PT), Radius_Server (Server/Server-PT), Server0 (Server/Server-PT)
- `03 Cybersecurity\AAA\AAA_Radius_2Server_Telnet.pkt`
  version: `6.1.0.0026`, devices: `5`, links: `4`
  tags: host_server, management_vlan, switching, telnet
  devices: R1 (Router/1841), Switch0 (Switch/2950-24), PC1 (Pc/PC-PT), Radius_Server (Server/Server-PT), Server0 (Server/Server-PT)
- `03 Cybersecurity\AAA\AAA_Radius_Server.pkt`
  version: `6.1.0.0026`, devices: `4`, links: `3`
  tags: host_server, switching
  devices: R1 (Router/1841), Switch0 (Switch/2950-24), PC1 (Pc/PC-PT), Radius_Server (Server/Server-PT)
- `03 Cybersecurity\AAA\AAA_Simple_Authentication.pkt`
  decode error: `ValueError: EAX authentication tag verification failed`
- `03 Cybersecurity\AAA\AAA_Tacas_2Server.pkt`
  version: `6.1.0.0120`, devices: `5`, links: `4`
  tags: host_server, switching
  devices: R1 (Router/1841), Switch0 (Switch/2950-24), PC1 (Pc/PC-PT), Tacas_Server (Server/Server-PT), Server0 (Server/Server-PT)
- `03 Cybersecurity\AAA\AAA_Tacas_2Server_Telnet.pkt`
  version: `6.1.0.0120`, devices: `5`, links: `4`
  tags: host_server, management_vlan, switching, telnet
  devices: R1 (Router/1841), Switch0 (Switch/2950-24), PC1 (Pc/PC-PT), Tacas_Server (Server/Server-PT), Server0 (Server/Server-PT)
- `03 Cybersecurity\AAA\AAA_Tacas_Server.pkt`
  decode error: `ValueError: EAX authentication tag verification failed`
- `03 Cybersecurity\ASA\ASA security plus license.pkt`
  version: `7.1.0.0000`, devices: `14`, links: `10`
  tags: host_server, multi_router, switching
  devices: R1 (Router/2811), ASA0 (ASA/5505), DMZ_Server (Server/Server-PT), Switch0 (Switch/2950-24), Switch1 (Switch/2950-24), Switch2 (Switch/2950-24), Internal_Host (Server/Server-PT), External_Host (Server/Server-PT), DMZ_Router (Router/1841), Internal_Router (Router/1841), External_Router (Router/1841), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Power Distribution Device1 (Power Distribution Device/Power Distribution Device), Power Distribution Device2 (Power Distribution Device/Power Distribution Device)
- `03 Cybersecurity\ASA\asa_acl_nat.pkt`
  version: `6.1.0.0026`, devices: `13`, links: `12`
  tags: acl, host_server, multi_router, nat, switching
  devices: R1 (Router/2811), ASA0 (ASA/5505), DMZ_Server (Server/Server-PT), R2 (Router/2811), R3 (Router/2811), Switch0 (Switch/2950-24), Switch1 (Switch/2950-24), Switch2 (Switch/2950-24), Internal_Host (Server/Server-PT), External_Host (Server/Server-PT), DMZ_Router (Router/1841), Internal_Router (Router/1841), External_Router (Router/1841)
- `03 Cybersecurity\ASA\asa_clientless_vpn.pkt`
  version: `6.1.0.0092`, devices: `5`, links: `4`
  tags: host_server, switching, vpn
  devices: PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Switch0 (Switch/2950-24), Server0 (Server/Server-PT), ASA0 (ASA/5505)
- `03 Cybersecurity\ASA\asa_service_policy.pkt`
  version: `6.1.0.0026`, devices: `13`, links: `12`
  tags: host_server, multi_router, switching
  devices: R1 (Router/2811), ASA0 (ASA/5505), DMZ_Server (Server/Server-PT), R2 (Router/2811), R3 (Router/2811), Switch0 (Switch/2950-24), Switch1 (Switch/2950-24), Switch2 (Switch/2950-24), Internal_Host (Server/Server-PT), External_Host (Server/Server-PT), DMZ_Router (Router/1841), Internal_Router (Router/1841), External_Router (Router/1841)
- `03 Cybersecurity\ASA\enable outside to inside.pkt`
  version: `6.1.0.0026`, devices: `11`, links: `10`
  tags: host_server, multi_router, switching
  devices: R1 (Router/2811), ASA0 (ASA/5505), DMZ_Server (Server/Server-PT), Switch0 (Switch/2950-24), Switch1 (Switch/2950-24), Switch2 (Switch/2950-24), Internal_Host (Server/Server-PT), External_Host (Server/Server-PT), DMZ_Router (Router/1841), Internal_Router (Router/1841), External_Router (Router/1841)
- `03 Cybersecurity\CBAC\CBAC_3Interface.pkt`
  decode error: `ValueError: EAX authentication tag verification failed`
- `03 Cybersecurity\CBAC\CBAC_3Routers.pkt`
  decode error: `ValueError: EAX authentication tag verification failed`
- `03 Cybersecurity\DAI\dai_sample.pkt`
  version: `7.3.0.0902`, devices: `5`, links: `3`
  tags: host_server, switching
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), DHCP Server (Router/ISR4331), Switch0 (Switch/2960-24TT)
- `03 Cybersecurity\IPSec\GRE_Over_IPSec_EIGRP.pkt`
  version: `6.0.0.0002`, devices: `3`, links: `2`
  tags: eigrp, multi_router, vpn
  devices: R1 (Router/1841), CO (Router/1841), R2 (Router/1841)
- `03 Cybersecurity\IPSec\Ipsec.pkt`
  decode error: `ValueError: EAX authentication tag verification failed`
- `03 Cybersecurity\IPSec\Ipsec2.pkt`
  decode error: `ValueError: EAX authentication tag verification failed`
- `03 Cybersecurity\Port-Based NAC\wired dot1x.pkt`
  version: `7.2.0.0071`, devices: `5`, links: `3`
  tags: host_server, switching
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Switch0 (Switch/2960-24TT), Server1 (Server/Server-PT), PC1 (Pc/PC-PT), PC2 (Pc/PC-PT)
- `03 Cybersecurity\Sniffer\sniffer_test.pkt`
  version: `6.2.0.0000`, devices: `3`, links: `2`
  tags: host_server
  devices: Sniffer0 (Sniffer/Sniffer), PC0 (Pc/PC-PT), Server0 (Server/Server-PT)
- `03 Cybersecurity\Wireless LAN Security\wpa_eap_test.pkt`
  version: `7.0.0.0000`, devices: `3`, links: `1`
  tags: host_server, wireless, wireless_ap, wireless_client
  devices: Router0 (Router/2811), PC0 (Pc/PC-PT), Server0 (Server/Server-PT)
- `03 Cybersecurity\Wireless LAN Security\wpa_psk_test.pkt`
  version: `7.0.0.0000`, devices: `2`, links: `0`
  tags: host_server, wireless, wireless_ap, wireless_client
  devices: Router0 (Router/2811), PC0 (Pc/PC-PT)
- `03 Cybersecurity\Wireless LAN Security\wpa_psk_test_with_dhcp.pkt`
  version: `6.2.0.0000`, devices: `2`, links: `0`
  tags: dhcp_pool, host_server, router_dhcp, server_dhcp, wireless, wireless_ap, wireless_client
  devices: Router0 (Router/2811), PC0 (Pc/PC-PT)
- `03 Cybersecurity\Zone Based Firewall (ZFW)\ZFW.pkt`
  decode error: `ValueError: EAX authentication tag verification failed`
- `03 Cybersecurity\Zone Based Firewall (ZFW)\zfwIPv4Test.pkt`
  version: `6.1.0.0026`, devices: `10`, links: `9`
  tags: host_server, multi_router, switching
  devices: Zfw (Router/2811), Public Router (Router/2811), Internet1 (Router/2811), Internet2 (Router/2811), cisco.com (Server/Server-PT), Private Lan (Switch/2950-24), Private PC0 (Pc/PC-PT), Private PC1 (Pc/PC-PT), Private PC2 (Pc/PC-PT), Private PC3 (Pc/PC-PT)
- `03 Cybersecurity\Zone Based Firewall (ZFW)\ZfwIpv6.pkt`
  version: `6.1.0.0026`, devices: `3`, links: `2`
  tags: multi_router
  devices: Zfw (Router/1941), Public (Router/2811), Private (Router/2811)
- `04 IoT\819HG_4G_IOX\basic_configuration.pkt`
  version: `7.0.0.0000`, devices: `2`, links: `1`
  tags: host_server, iot
  devices: PC0 (Pc/PC-PT), Router0 (Router/819HG-4G-IOX)
- `04 IoT\819HG_4G_IOX\basic_configuration_outside_nat.pkt`
  version: `7.0.0.0000`, devices: `4`, links: `3`
  tags: host_server, iot, multi_router, nat, switching
  devices: Switch0 (Switch/2950-24), Router0 (Router/819HG-4G-IOX), PC0 (Pc/PC-PT), DHCP Server (Router/1841)
- `04 IoT\819HG_4G_IOX\tcp_client_app_on_819.pkt`
  version: `7.0.0.0000`, devices: `6`, links: `5`
  tags: host_server, iot, multi_router, switching
  devices: PC0 (Pc/PC-PT), TCP Client 2 (Router/819HG-4G-IOX), Switch0 (Switch/2950-24), Router1 (Router/1841), TCP Server (Server/Server-PT), TCP Client 1 (Server/Server-PT)
- `04 IoT\819HG_4G_IOX\udp_test_app_on_819.pkt`
  version: `9.0.0.0000`, devices: `6`, links: `4`
  tags: host_server, iot, multi_router, switching
  devices: Switch0 (Switch/2950-24), PC0 (Pc/PC-PT), Server0 (Server/Server-PT), Router0 (Router/819HG-4G-IOX), Router1 (Router/819HG-4G-IOX), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `04 IoT\819HG_4G_IOX\uploading_and_running_vm_on_819.pkt`
  version: `7.0.0.0000`, devices: `2`, links: `1`
  tags: host_server, iot
  devices: PC0 (Pc/PC-PT), Router0 (Router/819HG-4G-IOX)
- `04 IoT\819HGW\819HGW_cell_nat_configuration.pkt`
  version: `7.0.0.0000`, devices: `10`, links: `4`
  tags: host_server, iot, multi_router, nat, switching, tablet, wireless_client
  devices: Cell Tower0 (CellTower/Cell-Tower), Central Office Server0 (CentralOfficeServer/Central-Office-Server), Cell Tower1 (CellTower/Cell-Tower), Switch0 (Switch/2950-24), 15.0.0.1 (Router/1841), Smartphone0 (Pda/SMARTPHONE-PT), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), Router0 (Router/819HGW), Router1 (Router/819HGW)
- `04 IoT\819HGW\819HGW_cellular_activation.pkt`
  version: `7.0.0.0000`, devices: `3`, links: `1`
  tags: iot, wireless
  devices: Central Office Server0 (CentralOfficeServer/Central-Office-Server), Cell Tower1 (CellTower/Cell-Tower), Router1 (Router/819HGW)
- `04 IoT\819HGW\819HGW_nat_configuration.pkt`
  version: `7.0.0.0000`, devices: `6`, links: `3`
  tags: host_server, iot, multi_router, nat
  devices: Router0 (Router/819HGW), Router1 (Router/819HGW), Router2 (Router/1841), Router3 (Router/1841), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT)
- `04 IoT\819HGW\wpa_psk_authentication.pkt`
  version: `7.0.0.0000`, devices: `3`, links: `0`
  tags: host_server, iot, wireless, wireless_ap
  devices: Router0 (Router/819HGW), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT)
- `04 IoT\829\829_IoX.pkt`
  version: `7.2.0.0000`, devices: `4`, links: `4`
  tags: host_server, iot
  devices: Router0 (Router/829), PC0 (Pc/PC-PT), MCU0 (MCU/MCU-PT), IoE1 (MCUComponent/RGB LED)
- `04 IoT\Bluetooth\beacons.pkt`
  version: `7.1.0.0000`, devices: `3`, links: `0`
  tags: iot, wireless
  devices: SBC0 (SBC/SBC-PT), Beacon0 (MCUComponent/Beacon), Custom Beacon1 (MCUComponent/Beacon)
- `04 IoT\Bluetooth\Bluetooth Audio.pkt`
  version: `7.1.0.0000`, devices: `2`, links: `0`
  tags: iot, wireless
  devices: IoT0 (MCUComponent/Portable Music Player), IoT1 (MCUComponent/Bluetooth Speaker)
- `04 IoT\Bluetooth\paired connections.pkt`
  version: `7.0.1.0000`, devices: `2`, links: `0`
  tags: iot, wireless
  devices: SBC0 (SBC/SBC-PT), SBC1 (SBC/SBC-PT)
- `04 IoT\CGR1240\SFP_Module.pkt`
  version: `7.1.0.0000`, devices: `2`, links: `0`
  tags: iot, multi_router
  devices: Router0 (Router/CGR1240), Router1 (Router/CGR1240)
- `04 IoT\Environment\doors.pkt`
  version: `7.2.0.0000`, devices: `6`, links: `0`
  tags: iot
  devices: IoE6 (MCUComponent/Window), IoE7 (MCUComponent/Door), IoE8 (MCUComponent/Garage Door), IoE9 (MCUComponent/Door), IoE10 (MCUComponent/Door), IoE11 (MCUComponent/Door)
- `04 IoT\Environment\firesprinkler.pkt`
  version: `7.2.0.0000`, devices: `1`, links: `0`
  tags: iot
  devices: IoE1 (MCUComponent/Fire Sprinkler)
- `04 IoT\Environment\humidifier.pkt`
  version: `7.2.0.0000`, devices: `8`, links: `0`
  tags: iot
  devices: IoE0 (MCUComponent/Door), IoE1 (MCUComponent/Door), IoE2 (MCUComponent/Door), IoE3 (MCUComponent/Door), IoE4 (MCUComponent/Garage Door), IoE8 (MCUComponent/Humidity Monitor), IoE9 (MCUComponent/Humidifier), IoE10 (MCUComponent/Humidifier)
- `04 IoT\Environment\lights.pkt`
  version: `7.2.0.0000`, devices: `9`, links: `5`
  tags: iot
  devices: IoE1 (MCUComponent/RGB LED), IoE2 (MCUComponent/Smart LED), IoE3 (MCUComponent/Light), IoE4 (MCUComponent/Potentiometer), IoE5 (MCUComponent/Potentiometer), IoE6 (MCUComponent/Potentiometer), IoE7 (MCUComponent/Potentiometer), IoE8 (MCUComponent/Potentiometer), IoE0 (MCUComponent/LED)
- `04 IoT\Environment\speakers.pkt`
  version: `7.2.0.0000`, devices: `2`, links: `1`
  tags: iot
  devices: IoE0 (MCUComponent/Home Speaker), IoE1 (MCUComponent/Potentiometer)
- `04 IoT\Environment\thermostat.pkt`
  version: `7.2.0.0000`, devices: `3`, links: `2`
  tags: iot
  devices: IoE3 (MCUComponent/Thermostat), IoE4 (MCUComponent/Furnace), IoE5 (MCUComponent/Air Conditioner)
- `04 IoT\IE_2000\l2nat_basic_inside-to-outside.pkt`
  version: `7.0.0.0000`, devices: `3`, links: `2`
  tags: host_server, iot, nat, switching
  devices: Switch0 (MultiLayerSwitch/IE-2000), PC0 (Pc/PC-PT), Server0 (Server/Server-PT)
- `04 IoT\IE_2000\l2nat_duplicateIpAddress.pkt`
  version: `7.0.0.0000`, devices: `11`, links: `10`
  tags: host_server, iot, nat, switching
  devices: A1_192.168.1.1 (Server/Server-PT), A2_192.168.1.2 (Server/Server-PT), A3_192.168.1.3 (Server/Server-PT), B1_192.168.1.1 (Server/Server-PT), B2_192.168.1.2 (Server/Server-PT), B3_192.168.1.3 (Server/Server-PT), SwitchB (MultiLayerSwitch/IE-2000), Switch6 (Switch/2950-24), Switch7 (Switch/2950-24), Switch8 (Switch/2950-24), SwitchA (MultiLayerSwitch/IE-2000)
- `04 IoT\IE_2000\l2nat_portChannel.pkt`
  version: `9.0.0.0000`, devices: `5`, links: `4`
  tags: host_server, iot, nat, switching
  devices: Switch0 (MultiLayerSwitch/IE-2000), PC0 (Pc/PC-PT), Server0 (Server/Server-PT), Switch1 (Switch/2960-24TT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `04 IoT\IE_2000\l2nat_vlan.pkt`
  version: `7.0.0.0000`, devices: `4`, links: `3`
  tags: host_server, iot, nat, switching, vlan
  devices: Switch0 (MultiLayerSwitch/IE-2000), PC0 (Pc/PC-PT), Server0 (Server/Server-PT), Switch1 (Switch/2960-24TT)
- `04 IoT\IE_2000\ptp_boundary_clock_loop.pkt`
  version: `7.0.0.0000`, devices: `3`, links: `3`
  tags: iot, switching
  devices: Switch0 (MultiLayerSwitch/IE-2000), Switch1 (MultiLayerSwitch/IE-2000), GrandMaster (MultiLayerSwitch/IE-2000)
- `04 IoT\IE_2000\ptp_forward_transparent_boundary_clock.pkt`
  version: `9.0.0.0000`, devices: `7`, links: `4`
  tags: iot, switching
  devices: Boundary_1 (MultiLayerSwitch/IE-2000), Forward_1 (MultiLayerSwitch/IE-2000), Boundary_2 (MultiLayerSwitch/IE-2000), Transparent_2 (MultiLayerSwitch/IE-2000), Transparent_1 (MultiLayerSwitch/IE-2000), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Power Distribution Device1 (Power Distribution Device/Power Distribution Device)
- `04 IoT\IE_2000\ptp_simple_boundary_clock.pkt`
  version: `7.0.0.0306`, devices: `3`, links: `1`
  tags: iot, switching
  devices: Slave (MultiLayerSwitch/IE-2000), Old Master (MultiLayerSwitch/IE-2000), New Master (MultiLayerSwitch/IE-2000)
- `04 IoT\IE_2000\upgrade_downgrade_license_on_ie2000.pkt`
  version: `7.1.0.0000`, devices: `1`, links: `0`
  tags: iot, switching
  devices: Switch0 (MultiLayerSwitch/IE-2000)
- `04 IoT\MQTT\mqttdemo.pkt`
  version: `9.0.0.4178`, devices: `3`, links: `0`
  tags: iot
  devices: Home Gateway0 (HomeGateway/DLC100), MQTT Broker (SBC/SBC-PT), MQTT Client (SBC/SBC-PT)
- `04 IoT\Real HTTP\real-http-server-js.pkt`
  version: `7.2.0.0000`, devices: `2`, links: `0`
  tags: ftp_http_https, host_server, iot, server_http
  devices: real http client (MCU/MCU-PT), real http server (SBC/SBC-PT)
- `04 IoT\Real HTTP\real-http-server-py.pkt`
  version: `7.2.0.0000`, devices: `2`, links: `0`
  tags: ftp_http_https, host_server, iot, server_http
  devices: Py: real http client (MCU/MCU-PT), Py: real http server 2 (SBC/SBC-PT)
- `04 IoT\Real HTTP\real-http-server-vis.pkt`
  version: `7.2.0.0000`, devices: `3`, links: `0`
  tags: ftp_http_https, host_server, iot, server_http
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), real http server (SBC/SBC-PT), real http client (MCU/MCU-PT)
- `04 IoT\Real WebSocket\real-websocket.pkt`
  version: `7.2.0.0000`, devices: `2`, links: `0`
  tags: ftp_http_https, iot, server_http
  devices: WebSockets HTTP Server (SBC/SBC-PT), WebSockets Client (SBC/SBC-PT)
- `04 IoT\Solution Examples\appliance.pkt`
  version: `8.2.1.0106`, devices: `9`, links: `5`
  tags: host_server, iot, switching
  devices: Custom SBC (SBC/SBC-PT), Switch0 (Switch/2950-24), Server0 (Server/Server-PT), PC0 (Pc/PC-PT), IoT4 (MCUComponent/Rocker Switch), IoT3 (MCUComponent/Appliance(0)), IoT2 (MCUComponent/Appliance(0)), IoT1 (MCUComponent/Appliance(0)), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `04 IoT\Solution Examples\atm_pressure.pkt`
  version: `7.3.1.0000`, devices: `5`, links: `3`
  tags: host_server, iot, switching
  devices: PC0 (Pc/PC-PT), Switch0 (Switch/Switch-PT), IoT0 (MCUComponent/Atm Pressure Monitor(0)), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Server0 (Server/Server-PT)
- `04 IoT\Solution Examples\basic_io.pkt`
  version: `7.1.0.0000`, devices: `16`, links: `8`
  tags: iot
  devices: IoT0 (MCUComponent/Push Button), IoT1 (MCUComponent/Push Button), IoT2 (MCUComponent/Push Button), IoT3 (MCUComponent/Push Button), IoT4 (MCUComponent/Potentiometer), IoT5 (MCUComponent/Potentiometer), IoT6 (MCUComponent/Potentiometer), IoT7 (MCUComponent/Potentiometer), LED1 (Customized) (MCUComponent/LED), LED5 (Customized) (MCUComponent/LED), LED2 (Customized) (MCUComponent/LED), LED6 (Customized) (MCUComponent/LED), LED3 (Default) (MCUComponent/LED), LED7 (Default) (MCUComponent/LED), LED4 (Customized) (MCUComponent/LED), LED8 (Customized) (MCUComponent/LED)
- `04 IoT\Solution Examples\battery-solar_panel-power_meter.pkt`
  version: `9.0.0.0000`, devices: `11`, links: `11`
  tags: host_server, iot, switching
  devices: PC0 (Pc/PC-PT), Server0 (Server/Server-PT), Switch0 (Switch/2960-24TT), IoT2 (MCUComponent/Power Meter), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Custom LED 1 (MCUComponent/Thing), Custom LED 2 (MCUComponent/Thing), Custom LED 4 (MCUComponent/Thing), Custom LED 3 (MCUComponent/Thing), IoT1 (MCUComponent/Solar Panel), IoT3 (MCUComponent/Battery)
- `04 IoT\Solution Examples\car.pkt`
  version: `8.2.0.0162`, devices: `6`, links: `3`
  tags: host_server, iot, switching
  devices: Switch0 (Switch/2960-24TT), 1.1.1.2 (MCUComponent/Garage Door), 1.1.1.3 (MCUComponent/CO Detector), IoT0 (MCUComponent/Old Car), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), 1.1.1.1 (Server/Server-PT)
- `04 IoT\Solution Examples\CO2_detector.pkt`
  version: `7.3.0.0000`, devices: `6`, links: `3`
  tags: host_server, iot, switching
  devices: Server0 (Server/Server-PT), PC0 (Pc/PC-PT), Switch0 (Switch/2960-24TT), IoT2 (MCUComponent/Old Car), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), IoT0 (MCUComponent/Carbon Dioxide Detector)
- `04 IoT\Solution Examples\CO_detector.pkt`
  version: `7.3.0.0000`, devices: `6`, links: `3`
  tags: host_server, iot, switching
  devices: Server0 (Server/Server-PT), PC0 (Pc/PC-PT), Switch0 (Switch/2960-24TT), IoT1 (MCUComponent/Old Car), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), IoT2 (MCUComponent/Carbon Monoxide Detector)
- `04 IoT\Solution Examples\door.pkt`
  version: `8.1.0.0432`, devices: `6`, links: `4`
  tags: host_server, iot, switching
  devices: Switch (Switch/2950-24), PC (Pc/PC-PT), SBC0 (SBC/SBC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), IoT1 (MCUComponent/Door), Server (Server/Server-PT)
- `04 IoT\Solution Examples\fan.pkt`
  version: `8.1.0.0432`, devices: `7`, links: `5`
  tags: host_server, iot, switching
  devices: Server (Server/Server-PT), Switch (Switch/2950-24), PC (Pc/PC-PT), SBC0 (SBC/SBC-PT), IoT1 (MCUComponent/Rocker Switch(0)), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), IoT2 (MCUComponent/Fan)
- `04 IoT\Solution Examples\fire_monitor_sprinkler.pkt`
  version: `9.0.0.0000`, devices: `4`, links: `2`
  tags: iot
  devices: CustomMCU (MCU/MCU-PT), IoT1 (MCUComponent/Thing), IoT0 (MCUComponent/Fire Sprinkler), IoT2 (MCUComponent/Fire Monitor)
- `04 IoT\Solution Examples\flex_sensor.pkt`
  version: `7.1.0.0000`, devices: `3`, links: `2`
  tags: iot
  devices: CustomMCU (MCU/MCU-PT), IoT1 (MCUComponent/Flex Sensor), IoT0 (MCUComponent/LCD)
- `04 IoT\Solution Examples\garage_door.pkt`
  version: `7.3.1.0000`, devices: `6`, links: `4`
  tags: host_server, iot, switching
  devices: Switch (Switch/2950-24), PC (Pc/PC-PT), Local Door Control (MCU/MCU-PT), IoT0 (MCUComponent/Garage Door), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Server (Server/Server-PT)
- `04 IoT\Solution Examples\graphing.pkt`
  version: `8.1.0.0432`, devices: `6`, links: `3`
  tags: host_server, iot, switching
  devices: SBC0 (SBC/SBC-PT), PC0 (Pc/PC-PT), Switch0 (Switch/2950-24), function generator (MCUComponent/Thing), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), IoT0 (Customized) (MCUComponent/Potentiometer)
- `04 IoT\Solution Examples\home_speaker.pkt`
  version: `7.3.0.0000`, devices: `6`, links: `4`
  tags: host_server, iot, switching
  devices: PC0 (Pc/PC-PT), Switch0 (Switch/2960-24TT), Server (Server/Server-PT), IoT0 (MCUComponent/Potentiometer), IoT1 (MCUComponent/Home Speaker), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `04 IoT\Solution Examples\humidifier_and_monitor.pkt`
  version: `7.3.1.0000`, devices: `6`, links: `4`
  tags: host_server, iot, switching
  devices: PC0 (Pc/PC-PT), Switch0 (Switch/2960-24TT), IoE2 (MCUComponent/Humidifier), IoT0 (MCUComponent/Humidity Monitor), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Server0 (Server/Server-PT)
- `04 IoT\Solution Examples\humiture_sensor.pkt`
  version: `7.3.1.0000`, devices: `8`, links: `5`
  tags: host_server, iot, switching
  devices: PC0 (Pc/PC-PT), Switch0 (Switch/2960-24TT), MCU0 (MCU/MCU-PT), IoT2 (MCUComponent/LCD), IoT0 (MCUComponent/Humiture Sensor), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), IoT1 (MCUComponent/Humiture Monitor), Server0 (Server/Server-PT)
- `04 IoT\Solution Examples\iot_email.pkt`
  version: `7.3.0.0000`, devices: `4`, links: `3`
  tags: host_server, iot, switching
  devices: Server0 (Server/Server-PT), MCU0 (MCU/MCU-PT), Switch0 (Switch/2950-24), PC0 (Pc/PC-PT)
- `04 IoT\Solution Examples\iot_home_gateway.pkt`
  version: `8.2.0.0000`, devices: `4`, links: `3`
  tags: host_server, iot
  devices: Home Gateway0 (HomeGateway/DLC100), PC0 (Pc/PC-PT), door0 (MCUComponent/Door), door1 (MCUComponent/Door)
- `04 IoT\Solution Examples\iot_http.pkt`
  version: `7.3.0.0000`, devices: `5`, links: `4`
  tags: ftp_http_https, host_server, iot, server_http, switching
  devices: MCU0 (MCU/MCU-PT), SBC0 (SBC/SBC-PT), PC0 (Pc/PC-PT), Server0 (Server/Server-PT), Switch0 (Switch/2950-24)
- `04 IoT\Solution Examples\iot_registration_server.pkt`
  version: `8.2.1.0000`, devices: `8`, links: `5`
  tags: host_server, iot, switching
  devices: Switch0 (Switch/2960-24TT), Server0 (Server/Server-PT), PC0 (Pc/PC-PT), CO2 (MCUComponent/CO2 Detector), Garage (MCUComponent/Garage Door), Window (MCUComponent/Window), Car (MCUComponent/Old Car), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `04 IoT\Solution Examples\iot_remote_server.pkt`
  version: `8.1.0.0432`, devices: `9`, links: `7`
  tags: host_server, iot, switching
  devices: PC0 (Pc/PC-PT), Switch0 (Switch/2950-24), Server0 (Server/Server-PT), SBC0 (SBC/SBC-PT), SBC1 (SBC/SBC-PT), MCU0 (MCU/MCU-PT), IoE0 (MCUComponent/LED), IoE1 (MCUComponent/LED), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `04 IoT\Solution Examples\iot_street_data_collector.pkt`
  version: `8.1.0.0432`, devices: `7`, links: `0`
  tags: iot, wireless, wireless_ap
  devices: SERVER (SBC/SBC-PT), Street Lamp1 (MCUComponent/Street Lamp), Street Lamp2 (MCUComponent/Street Lamp), Street Lamp3 (MCUComponent/Street Lamp), Street Lamp4 (MCUComponent/Street Lamp), Wireless Router0 (WirelessRouter/Linksys-WRT300N), IoE4 (MCUComponent/Old Car)
- `04 IoT\Solution Examples\iot_with_iox.pkt`
  version: `7.3.0.0000`, devices: `8`, links: `6`
  tags: host_server, iot, switching
  devices: 172.1.1.1 (Router/819HG-4G-IOX), Switch0 (Switch/2950-24), 172.1.1.2 (Pc/PC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), customized garage button (MCUComponent/Push Button), customized window button (MCUComponent/Push Button), customized garage-192.168.25.2 (MCUComponent/Garage Door), customized window - 192.168.25.3 (MCUComponent/Window)
- `04 IoT\Solution Examples\lawn_sprinkler.pkt`
  version: `7.3.1.0000`, devices: `6`, links: `4`
  tags: host_server, iot, switching
  devices: Switch (Switch/2950-24), PC (Pc/PC-PT), Controller (MCU/MCU-PT), IoT0 (MCUComponent/Lawn Sprinkler), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Server (Server/Server-PT)
- `04 IoT\Solution Examples\lcd-with-visual-scripting.pkt`
  version: `7.1.0.0000`, devices: `2`, links: `1`
  tags: iot, rip
  devices: IoT0 (MCUComponent/Signal Generator), Customized with Visual Programming (MCUComponent/LCD)
- `04 IoT\Solution Examples\lcd.pkt`
  version: `7.1.0.0000`, devices: `4`, links: `2`
  tags: iot
  devices: CustomMCU1 (MCU/MCU-PT), IoT0 (MCUComponent/LCD), IoT1 (MCUComponent/LCD), IoT2 (MCUComponent/Potentiometer)
- `04 IoT\Solution Examples\LED.pkt`
  version: `7.1.0.0000`, devices: `2`, links: `1`
  tags: iot
  devices: IoT0 (MCUComponent/LED), IoT1 (MCUComponent/Potentiometer)
- `04 IoT\Solution Examples\light-photo_sensor.pkt`
  version: `7.3.0.0000`, devices: `8`, links: `6`
  tags: host_server, iot, switching
  devices: Switch0 (Switch/2950-24), Registration Server (Server/Server-PT), MCU0 (MCU/MCU-PT), SBC0 (SBC/SBC-PT), PC0 (Pc/PC-PT), IoT0 (MCUComponent/Light), IoT1 (MCUComponent/Photo Sensor), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `04 IoT\Solution Examples\membrane_sensor.pkt`
  version: `7.1.0.0000`, devices: `3`, links: `2`
  tags: iot
  devices: MCU0 (MCU/MCU-PT), IoT2 (MCUComponent/LCD), IoT3 (MCUComponent/Membrane Potentiometer)
- `04 IoT\Solution Examples\metal_sensor.pkt`
  version: `7.1.0.0000`, devices: `4`, links: `2`
  tags: iot
  devices: CustomMCU (MCU/MCU-PT), IoT1 (MCUComponent/Metal Sensor), CustomizedWithAlloyProperty (MCUComponent/Motor), IoT0 (MCUComponent/LCD)
- `04 IoT\Solution Examples\motion_detector.pkt`
  version: `7.3.0.0000`, devices: `10`, links: `7`
  tags: host_server, iot, switching
  devices: Switch0 (Switch/2950-24), 1.1.1.1 (Server/Server-PT), MCU0 (MCU/MCU-PT), IP Phone0 (IpPhone/7960), Multilayer Switch0 (MultiLayerSwitch/3560-24PS), 1.1.1.2 (MCUComponent/Motion Detector), 1.1.1.3 (MCUComponent/Webcam), IoT0 (MCUComponent/Motion Sensor), IoT1 (MCUComponent/LED), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `04 IoT\Solution Examples\motor.pkt`
  version: `7.1.0.0000`, devices: `2`, links: `1`
  tags: iot
  devices: IoT1 (MCUComponent/Motor), IoT2 (MCUComponent/Potentiometer)
- `04 IoT\Solution Examples\piezo_speaker.pkt`
  version: `7.1.0.0000`, devices: `3`, links: `2`
  tags: iot
  devices: CustomMCU (MCU/MCU-PT), IoT1 (MCUComponent/Piezo Speaker), IoT0 (MCUComponent/Push Button)
- `04 IoT\Solution Examples\power-grid-log-power.pkt`
  version: `7.2.0.0000`, devices: `6`, links: `4`
  tags: iot
  devices: IoT0 (MCUComponent/Battery), IoT3 (MCUComponent/Battery), IoT1 (MCUComponent/Power Meter), IoT4 (MCUComponent/Power Meter), IoT2 (MCUComponent/Wind Turbine), IoT5 (MCUComponent/Solar Panel)
- `04 IoT\Solution Examples\push_button.pkt`
  version: `7.1.0.0000`, devices: `2`, links: `1`
  tags: iot
  devices: IoT0 (MCUComponent/LED), IoT2 (MCUComponent/Push Button)
- `04 IoT\Solution Examples\remote-lamp-dimmer.pkt`
  version: `7.3.0.0000`, devices: `7`, links: `7`
  tags: host_server, iot, switching
  devices: Analog Input Collector (AIC) (MCU/MCU-PT), Registration Server (RS) (Server/Server-PT), Lamp Controller (LC) (SBC/SBC-PT), SW1 (Switch/2950-24), Lamp Dimmer (LD) (MCUComponent/Potentiometer), Lamp (LA) (MCUComponent/Light), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `04 IoT\Solution Examples\remote_control_car.pkt`
  version: `7.3.0.0000`, devices: `11`, links: `8`
  tags: host_server, iot, switching
  devices: MCU0 (MCU/MCU-PT), SBC0 (SBC/SBC-PT), Switch0 (Switch/2950-24), Server0 (Server/Server-PT), Router1 (Router/819HGW), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Left (MCUComponent/Push Button), Up (MCUComponent/Push Button), Down (MCUComponent/Push Button), Right (MCUComponent/Push Button), Customized remote control car (MCUComponent/Old Car)
- `04 IoT\Solution Examples\remote_trigger_over_http.pkt`
  version: `7.1.0.0000`, devices: `5`, links: `3`
  tags: ftp_http_https, host_server, iot, server_http, switching
  devices: PC0 (Pc/PC-PT), Switch0 (Switch/2950-24), CustomSBC (SBC/SBC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), IoT0 (MCUComponent/LED)
- `04 IoT\Solution Examples\rfid_reader.pkt`
  version: `7.3.0.0000`, devices: `7`, links: `3`
  tags: host_server, iot, switching
  devices: Switch0 (Switch/2960-24TT), Server0 (Server/Server-PT), PC0 (Pc/PC-PT), Reader (MCUComponent/RFID Reader), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), VALID Card (MCUComponent/RFID Card), INVALID Card (MCUComponent/RFID Card)
- `04 IoT\Solution Examples\rgb_led.pkt`
  version: `7.1.0.0000`, devices: `4`, links: `3`
  tags: iot
  devices: Red (MCUComponent/Potentiometer), Green (MCUComponent/Potentiometer), Blue (MCUComponent/Potentiometer), IoT1 (MCUComponent/RGB LED)
- `04 IoT\Solution Examples\servo.pkt`
  version: `7.1.0.0000`, devices: `3`, links: `2`
  tags: iot
  devices: MCU0 (MCU/MCU-PT), IoE1 (MCUComponent/Potentiometer), IoE2 (MCUComponent/Servo)
- `04 IoT\Solution Examples\signal-generator.pkt`
  version: `7.1.0.0000`, devices: `2`, links: `1`
  tags: iot
  devices: Customized LCD (MCUComponent/LCD), IoT0 (MCUComponent/Signal Generator)
- `04 IoT\Solution Examples\siren.pkt`
  version: `7.3.1.0000`, devices: `6`, links: `4`
  tags: host_server, iot, switching
  devices: Switch0 (Switch/2950-24), PC0 (Pc/PC-PT), Siren (MCUComponent/Siren), Trip Sensor (MCUComponent/Trip Sensor), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Registration Server (Server/Server-PT)
- `04 IoT\Solution Examples\smart_LED.pkt`
  version: `7.3.0.0000`, devices: `6`, links: `4`
  tags: host_server, iot, switching
  devices: PC (Pc/PC-PT), Registration Server (Server/Server-PT), Switch1 (Switch/2950-24), IoT0 (MCUComponent/Smart LED), IoT1 (MCUComponent/Potentiometer), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `04 IoT\Solution Examples\smoke_detector.pkt`
  version: `7.3.0.0000`, devices: `9`, links: `5`
  tags: host_server, iot, switching
  devices: Switch0 (Switch/2950-24), Registration Server (Server/Server-PT), PC0 (Pc/PC-PT), MCU0 (MCU/MCU-PT), IoT0 (MCUComponent/Smoke Detector), IoT1 (MCUComponent/Old Car), IoT6 (MCUComponent/LED), IoT7 (MCUComponent/Smoke Sensor), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `04 IoT\Solution Examples\sound_frequency_detector.pkt`
  version: `7.1.0.0000`, devices: `4`, links: `2`
  tags: iot
  devices: IoT0 (MCUComponent/Sound Frequency Detector), IoT1 (MCUComponent/LCD), IoT2 (MCUComponent/Potentiometer), IoT3 (MCUComponent/Home Speaker)
- `04 IoT\Solution Examples\sound_sensor.pkt`
  version: `7.2.0.0000`, devices: `5`, links: `3`
  tags: iot
  devices: MCU0 (MCU/MCU-PT), IoT4 (MCUComponent/Sound Sensor), IoT5 (MCUComponent/LCD), IoT6 (MCUComponent/Home Speaker), IoT0 (MCUComponent/Potentiometer)
- `04 IoT\Solution Examples\speaker.pkt`
  version: `7.1.0.0000`, devices: `3`, links: `2`
  tags: iot
  devices: CustomMCU (MCU/MCU-PT), IoT1 (MCUComponent/Push Button), IoT0 (MCUComponent/Speaker)
- `04 IoT\Solution Examples\switch.pkt`
  version: `7.1.0.0000`, devices: `3`, links: `2`
  tags: iot, switching
  devices: MCU0 (MCU/MCU-PT), IoT1 (MCUComponent/Air Cooler), IoT0 (MCUComponent/Rocker Switch(0))
- `04 IoT\Solution Examples\temperature.pkt`
  version: `7.3.0.0000`, devices: `9`, links: `7`
  tags: iot, wireless_client
  devices: Home Gateway0 (HomeGateway/DLC100), Laptop0 (Laptop/Laptop-PT), CustomMCU (MCU/MCU-PT), IoT0 (MCUComponent/LCD), IoT1 (MCUComponent/Temperature Sensor), IoT2 (MCUComponent/Temperature Monitor), IoT3 (MCUComponent/Heating Element), IoT4 (MCUComponent/Air Cooler), thermostat (MCUComponent/Thermostat)
- `04 IoT\Solution Examples\temperature_monitor.pkt`
  version: `7.3.1.0000`, devices: `8`, links: `6`
  tags: host_server, iot, switching
  devices: Switch (Switch/2950-24), PC (Pc/PC-PT), IoT2 (MCUComponent/Temperature Monitor), IoT5 (MCUComponent/Thermostat), IoT7 (MCUComponent/Air Cooler), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), IoT0 (MCUComponent/Heating Element), Server (Server/Server-PT)
- `04 IoT\Solution Examples\temperature_sensor.pkt`
  version: `7.1.0.0000`, devices: `3`, links: `1`
  tags: iot
  devices: TS (MCUComponent/Temperature Sensor), TM (MCUComponent/Temperature Monitor), IoT0 (MCUComponent/LCD)
- `04 IoT\Solution Examples\toggle_push_button.pkt`
  version: `7.1.0.0000`, devices: `2`, links: `1`
  tags: iot
  devices: IoT0 (MCUComponent/Toggle Push Button), IoT1 (MCUComponent/LED)
- `04 IoT\Solution Examples\toggle_switch.pkt`
  version: `7.1.0.0000`, devices: `5`, links: `4`
  tags: iot, switching
  devices: L1 (MCUComponent/LED), L2 (MCUComponent/LED), POT (MCUComponent/Potentiometer), TSW (MCUComponent/Push Button Toggle Switch), IoT0 (MCUComponent/LCD)
- `04 IoT\Solution Examples\trip_sensor.pkt`
  version: `9.0.0.4178`, devices: `9`, links: `6`
  tags: host_server, iot, rip, switching
  devices: Registration Server (Server/Server-PT), Switch0 (Switch/2950-24), PC0 (Pc/PC-PT), MCU0 (MCU/MCU-PT), IoT1 (MCUComponent/Trip Sensor), IoT2 (MCUComponent/Trip Wire), IoT3 (MCUComponent/LED), IoT0 (MCUComponent/Light(0)), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `04 IoT\Solution Examples\water_drain.pkt`
  version: `7.1.0.0000`, devices: `5`, links: `2`
  tags: iot
  devices: IoT2 (MCUComponent/Water Level Monitor), IoT1 (MCUComponent/Fire Sprinkler), IoT0 (MCUComponent/Water Drain), Customized for water level (MCUComponent/Generic Environment Sensor), MCU0 (MCU/MCU-PT)
- `04 IoT\Solution Examples\water_level_monitor.pkt`
  version: `9.0.0.4178`, devices: `10`, links: `6`
  tags: host_server, iot, switching
  devices: Switch0 (Switch/2950-24), Switch1 (Switch/2960-24TT), PC0 (Pc/PC-PT), Server0 (Server/Server-PT), MCU0 (MCU/MCU-PT), IoT3 (MCUComponent/Water Level Monitor), IoT4 (MCUComponent/Lawn Sprinkler), IoT2 (MCUComponent/Water Sensor), IoT1 (MCUComponent/LED), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `04 IoT\Solution Examples\wind_sensor.pkt`
  version: `9.0.0.4178`, devices: `8`, links: `5`
  tags: host_server, iot, switching
  devices: Switch0 (Switch/2960-24TT), PC0 (Pc/PC-PT), MCU0 (MCU/MCU-PT), Home Gateway0 (HomeGateway/DLC100), IoT2 (MCUComponent/LED), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), IoT0 (MCUComponent/Wind Detector), IoT3 (MCUComponent/Wind Sensor)
- `04 IoT\Solution Examples\wind_turbine.pkt`
  version: `9.0.0.4178`, devices: `8`, links: `5`
  tags: host_server, iot, switching
  devices: Switch (Switch/2950-24), PC (Pc/PC-PT), IoT5 (MCUComponent/Power Meter), IoT6 (MCUComponent/Battery), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), IoT0 (MCUComponent/Wind Detector), IoT1 (MCUComponent/Wind Turbine), Server (Server/Server-PT)
- `04 IoT\Solution Examples\window.pkt`
  version: `9.0.0.4178`, devices: `9`, links: `6`
  tags: host_server, iot, switching
  devices: Server0 (Server/Server-PT), PC0 (Pc/PC-PT), Switch0 (Switch/2950-24), Stove (MCUComponent/Thing), IoT2 (MCUComponent/Window), IoT6 (MCUComponent/Rocker Switch), IoT0 (MCUComponent/Carbon Dioxide Detector), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), IoT4 (MCUComponent/Carbon Monoxide Detector)
- `05 Programming\bluetooth music player.pkt`
  version: `7.1.0.0000`, devices: `2`, links: `0`
  tags: tablet, wireless, wireless_client
  devices: IoT0 (MCUComponent/Bluetooth Speaker), Smartphone0 (Pda/SMARTPHONE-PT)
- `05 Programming\desktop user gui.pkt`
  version: `7.3.0.0902`, devices: `1`, links: `0`
  tags: host_server
  devices: PC0 (Pc/PC-PT)
- `05 Programming\HTML\html_javascript_stylesheet.pkt`
  version: `6.2.0.0000`, devices: `2`, links: `1`
  tags: host_server, rip
  devices: Server0 (Server/Server-PT), PC0 (Pc/PC-PT)
- `05 Programming\HTML\import files and ftp to server.pkt`
  version: `8.0.0.0000`, devices: `4`, links: `2`
  tags: ftp_http_https, host_server, server_ftp
  devices: PC0 (Pc/PC-PT), Server0 (Server/Server-PT), Router0 (Router/1841), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `05 Programming\piano\piano.pkt`
  version: `7.1.0.0000`, devices: `1`, links: `0`
  tags: switching
  devices: piano (MCUComponent/Thing)
- `06 Industrial -  OT\Industrial Communication and Protocols\CIP\cip-identity.pkt`
  version: `9.0.0.0000`, devices: `5`, links: `3`
  tags: switching
  devices: PLC (SBC/SBC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), IO1 (SBC/SBC-PT), Switch0 (Switch/2960-24TT), SBC2 (SBC/SBC-PT)
- `06 Industrial -  OT\Industrial Communication and Protocols\CIP\cip-implicit.pkt`
  version: `9.0.0.0000`, devices: `5`, links: `3`
  tags: switching
  devices: PLC (SBC/SBC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), IO1 (SBC/SBC-PT), Switch0 (Switch/2960-24TT), SBC2 (SBC/SBC-PT)
- `06 Industrial -  OT\Industrial Communication and Protocols\CIP\cip-object.pkt`
  version: `9.0.0.0000`, devices: `5`, links: `3`
  tags: switching
  devices: PLC (SBC/SBC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), IO1 (SBC/SBC-PT), Switch0 (Switch/2960-24TT), SBC2 (SBC/SBC-PT)
- `06 Industrial -  OT\Industrial Communication and Protocols\IEC-61850\Goose.pkt`
  version: `9.0.0.0000`, devices: `2`, links: `1`
  tags: switching
  devices: GoosePublisher (MCUComponent/Thing), GooseSubscriber (MCUComponent/Thing)
- `06 Industrial -  OT\Industrial Communication and Protocols\IEC-61850\MMS.pkt`
  version: `9.0.0.0000`, devices: `2`, links: `1`
  tags: switching
  devices: MMSServer (MCUComponent/Thing), MMSClient (MCUComponent/Thing)
- `06 Industrial -  OT\Industrial Communication and Protocols\IEC-61850\SV.pkt`
  version: `9.0.0.0000`, devices: `2`, links: `1`
  tags: switching
  devices: SvPublisher (MCUComponent/Thing), SvSubscriber (MCUComponent/Thing)
- `06 Industrial -  OT\Industrial Communication and Protocols\Modbus\modbus.pkt`
  version: `9.0.0.0000`, devices: `2`, links: `1`
  tags: host_server
  devices: ModbusServer (Pc/PC-PT), ModbusClient (Pc/PC-PT)
- `06 Industrial -  OT\Industrial Communication and Protocols\OPC-UA\hmi-arm-opc.pkt`
  version: `9.0.0.0000`, devices: `7`, links: `2`
  tags: host_server
  devices: Conveyor Belt (MCUComponent/Thing), car (MCUComponent/Thing), simulation controls (MCUComponent/Thing), hmi (MCUComponent/Thing), arm (MCUComponent/Thing), IoT1 (MCUComponent/Thing), Hub0 (Hub/Hub-PT)
- `06 Industrial -  OT\Industrial Communication and Protocols\OPC-UA\opc-script.pkt`
  version: `9.0.0.0000`, devices: `5`, links: `3`
  tags: host_server, rip, switching
  devices: PC0 (Pc/PC-PT), MCU0 (MCU/MCU-PT), Switch0 (Switch/2960-24TT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PC1 (Pc/PC-PT)
- `06 Industrial -  OT\Industrial Communication and Protocols\Profinet\hmi-arm-profinet.pkt`
  version: `9.0.0.0000`, devices: `12`, links: `10`
  tags: host_server, switching
  devices: shoulder-rot (MCUComponent/Thing), simulation controls (MCUComponent/Thing), hmi (MCUComponent/Thing), car (MCUComponent/Thing), forearm-rot (MCUComponent/Thing), forearm-rpm (MCUComponent/Thing), shoulder-rpm (MCUComponent/Thing), arm (MCUComponent/Thing), Conveyor Belt (MCUComponent/Thing), Engineer Station (Pc/PC-PT), Switch1 (MultiLayerSwitch/IE-3400), Power Distribution Device0 (Power Distribution Device/Power Distribution Device)
- `06 Industrial -  OT\Industrial Communication and Protocols\Profinet\profinet.pkt`
  version: `9.0.0.0000`, devices: `9`, links: `7`
  tags: host_server, switching
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Engineer Station (Pc/PC-PT), Profinet IO1 (MCUComponent/Thing), Profinet IO0 (MCUComponent/Thing), Multilayer Switch0 (MultiLayerSwitch/IE-3400), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), PLC0 (PLC/PLC-PT), Profinet IO2 (MCUComponent/Thing)
- `06 Industrial -  OT\Industrial Communication and Protocols\PRP\prp_scenario3_layer2.pkt`
  version: `9.0.0.0000`, devices: `18`, links: `20`
  tags: host_server, switching
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), SAN2 (Pc/PC-PT), SAN1 (Pc/PC-PT), SAN3 (Pc/PC-PT), SAN4 (Pc/PC-PT), DAN2 (Server/Server-PT), DAN1 (Server/Server-PT), Power Distribution Device1 (Power Distribution Device/Power Distribution Device), PC4 (Pc/PC-PT), VDAN (Pc/PC-PT), Router2 (Router/ISR4331), Redbox1 (MultiLayerSwitch/IE-9320), Redbox2 (MultiLayerSwitch/IE-9320), Redbox3 (MultiLayerSwitch/IE-3400), Switch0 (Switch/2960-24TT), Switch1 (Switch/2960-24TT), Switch2 (Switch/2960-24TT), Switch3 (Switch/2960-24TT)
- `06 Industrial -  OT\Industrial Communication and Protocols\PRP\prp_scenario3_layer2_vlan.pkt`
  version: `9.0.0.0000`, devices: `18`, links: `20`
  tags: host_server, switching, vlan
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), SAN2 (Pc/PC-PT), SAN1 (Pc/PC-PT), SAN3 (Pc/PC-PT), SAN4 (Pc/PC-PT), DAN2 (Server/Server-PT), DAN1 (Server/Server-PT), Power Distribution Device1 (Power Distribution Device/Power Distribution Device), PC4 (Pc/PC-PT), VDAN (Pc/PC-PT), Router2 (Router/ISR4331), Redbox1 (MultiLayerSwitch/IE-9320), Redbox2 (MultiLayerSwitch/IE-9320), Switch0 (Switch/2960-24TT), Switch1 (Switch/2960-24TT), Switch2 (Switch/2960-24TT), Switch3 (Switch/2960-24TT), Redbox3 (MultiLayerSwitch/IE-3400)
- `06 Industrial -  OT\Industrial Communication and Protocols\PRP\prp_scenario3_layer3.pkt`
  version: `9.0.0.0000`, devices: `18`, links: `20`
  tags: host_server, switching
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), SAN2 (Pc/PC-PT), SAN1 (Pc/PC-PT), SAN3 (Pc/PC-PT), SAN4 (Pc/PC-PT), DAN2 (Server/Server-PT), DAN1 (Server/Server-PT), Power Distribution Device1 (Power Distribution Device/Power Distribution Device), PC4 (Pc/PC-PT), VDAN (Pc/PC-PT), Router2 (Router/ISR4331), Switch3 (Switch/2960-24TT), Switch1 (Switch/2960-24TT), Switch0 (Switch/2960-24TT), Switch2 (Switch/2960-24TT), Redbox1 (MultiLayerSwitch/IE-9320), Redbox3 (MultiLayerSwitch/IE-3400), Redbox2 (MultiLayerSwitch/IE-9320)
- `06 Industrial -  OT\Industrial Communication and Protocols\PRP\prp_scenario3_layer3_prp_int.pkt`
  version: `9.0.0.0000`, devices: `18`, links: `20`
  tags: host_server, switching
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), SAN2 (Pc/PC-PT), SAN1 (Pc/PC-PT), SAN3 (Pc/PC-PT), SAN4 (Pc/PC-PT), DAN2 (Server/Server-PT), DAN1 (Server/Server-PT), Power Distribution Device1 (Power Distribution Device/Power Distribution Device), PC4 (Pc/PC-PT), VDAN (Pc/PC-PT), Router2 (Router/ISR4331), Switch3 (Switch/2960-24TT), Switch1 (Switch/2960-24TT), Switch0 (Switch/2960-24TT), Switch2 (Switch/2960-24TT), Redbox1 (MultiLayerSwitch/IE-9320), Redbox3 (MultiLayerSwitch/IE-3400), Redbox2 (MultiLayerSwitch/IE-9320)
- `06 Industrial -  OT\Industrial Communication and Protocols\PRP\prp_scenario3_layer3_prp_int_group_2.pkt`
  version: `9.0.0.0000`, devices: `20`, links: `20`
  tags: host_server, switching
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), SAN2 (Pc/PC-PT), SAN1 (Pc/PC-PT), SAN3 (Pc/PC-PT), SAN4 (Pc/PC-PT), DAN2 (Server/Server-PT), DAN1 (Server/Server-PT), Power Distribution Device1 (Power Distribution Device/Power Distribution Device), PC4 (Pc/PC-PT), VDAN (Pc/PC-PT), Router2 (Router/ISR4331), Switch3 (Switch/2960-24TT), Switch1 (Switch/2960-24TT), Switch0 (Switch/2960-24TT), Switch2 (Switch/2960-24TT), Redbox1 (MultiLayerSwitch/IE-9320), Redbox3 (MultiLayerSwitch/IE-3400), Redbox2 (MultiLayerSwitch/IE-9320), Multilayer Switch0 (MultiLayerSwitch/IE-9320), Multilayer Switch1 (MultiLayerSwitch/IE-9320)
- `06 Industrial -  OT\Industrial Communication and Protocols\PTP\ptp_IR8340.pkt`
  version: `9.0.0.0000`, devices: `6`, links: `4`
  tags: multi_router, switching
  devices: OrdinaryClock (Router/IR8340), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), BoundaryClock1 (Router/IR8340), BoundaryClock2 (Router/IR8340), P2pTransparent1 (MultiLayerSwitch/IE-9320), P2pTransparent2 (MultiLayerSwitch/IE-9320)
- `06 Industrial -  OT\Industrial Communication and Protocols\PTP\ptp_ot_network.pkt`
  version: `9.0.0.0112`, devices: `12`, links: `10`
  tags: switching
  devices: PMU (MCUComponent/Thing), By Controller (PLC/PLC-PT), PLC0 (PLC/PLC-PT), RTU (MCUComponent/Thing), Relay (MCU/MCU-PT), SBC0 (SBC/SBC-PT), RTU with Serial (MCUComponent/Thing), PTP_Master_Clock (Router/IR8340), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PTP_TC1 (MultiLayerSwitch/IE-9320-26S2C), PTP_TC3 (MultiLayerSwitch/IE-9320-26S2C), PTP_TC2 (MultiLayerSwitch/IE-9320-26S2C)
- `06 Industrial -  OT\Industrial Communication and Protocols\PTP\ptp_power2007Profile.pkt`
  version: `9.0.0.0112`, devices: `6`, links: `3`
  tags: switching
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Ordinary (MultiLayerSwitch/IE-9320-26S2C), P2pTransparent1 (MultiLayerSwitch/IE-9320-26S2C), P2pTransparent2 (MultiLayerSwitch/IE-9320-26S2C), NewSlave (MultiLayerSwitch/IE-9320-26S2C), GrandMaster (MultiLayerSwitch/IE-9320-26S2C)
- `06 Industrial -  OT\Industrial Communication and Protocols\REP\rep_four_devices_ie2000_ring_topology.pkt`
  version: `9.0.0.0000`, devices: `14`, links: `12`
  tags: host_server, switching
  devices: Switch0 (MultiLayerSwitch/IE-2000), Switch1 (MultiLayerSwitch/IE-2000), PC0 (Pc/PC-PT), PC1 (Pc/PC-PT), PC2 (Pc/PC-PT), Switch2 (MultiLayerSwitch/IE-2000), PC4 (Pc/PC-PT), PC5 (Pc/PC-PT), PC6 (Pc/PC-PT), PC7 (Pc/PC-PT), PC8 (Pc/PC-PT), Switch3 (MultiLayerSwitch/IE-2000), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Power Distribution Device1 (Power Distribution Device/Power Distribution Device)
- `06 Industrial -  OT\Industrial Communication and Protocols\REP\rep_four_devices_ie3400_ring_topology.pkt`
  version: `9.0.0.0000`, devices: `14`, links: `12`
  tags: host_server, switching
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), PC6 (Pc/PC-PT), PC0 (Pc/PC-PT), PC4 (Pc/PC-PT), PC1 (Pc/PC-PT), PC5 (Pc/PC-PT), PC8 (Pc/PC-PT), PC2 (Pc/PC-PT), PC7 (Pc/PC-PT), MLS-3 (MultiLayerSwitch/IE-3400), MLS-0 (MultiLayerSwitch/IE-3400), Power Distribution Device1 (Power Distribution Device/Power Distribution Device), MLS-1 (MultiLayerSwitch/IE-3400), MLS-2 (MultiLayerSwitch/IE-3400)
- `06 Industrial -  OT\Industrial Control Systems\DataHistorian\data_historian.pkt`
  version: `9.0.0.0000`, devices: `13`, links: `11`
  tags: host_server, switching
  devices: GoosePublisher (MCU/MCU-PT), CIP (SBC/SBC-PT), Profinet IO1 (MCUComponent/Thing), Data Historian0 (DataHistorian/DataHistorianServer), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), ModbusDevice (MCUComponent/Thing), OPCUA (MCU/MCU-PT), MMSServer (MCU/MCU-PT), CIPClient (SBC/SBC-PT), PLC_Collector (PLC/PLC-PT), Supervisory Workstation (Pc/PC-PT), SvPublisher (MCU/MCU-PT), Multilayer Switch0 (MultiLayerSwitch/IE-9320-26S2C)
- `06 Industrial -  OT\Industrial Cybersecurity and Monitoring\CyberObserver\CyberObserver.pkt`
  version: `9.0.0.0172`, devices: `9`, links: `7`
  tags: host_server, switching
  devices: Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Multilayer Switch0 (MultiLayerSwitch/IE-9320), Admin (Pc/PC-PT), PC1 (Pc/PC-PT), PT-CyberObserver0 (CyberObserver/CyberObserver), Server0 (Server/Server-PT), Switch1 (Switch/2960-24TT), Router0 (Router/ISR4331), PLC0 (PLC/PLC-PT)
- `06 Industrial -  OT\Industrial Cybersecurity and Monitoring\CyberObserver\CyberObserver_Threat_Mitigation.pkt`
  version: `9.0.0.0000`, devices: `9`, links: `6`
  tags: host_server, switching
  devices: PT-CyberObserver0 (CyberObserver/CyberObserver), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Router0 (Router/ISR4331), Switch0 (Switch/2960-24TT), Admin (Pc/PC-PT), Switch1 (Switch/2960-24TT), PC1 (Pc/PC-PT), Server0 (Server/Server-PT), Rogue (Pc/PC-PT)
- `06 Industrial -  OT\Industrial Cybersecurity and Monitoring\CyberObserver\CyberObserver_UpgradeFirmware.pkt`
  version: `9.0.0.0000`, devices: `9`, links: `7`
  tags: host_server, switching
  devices: Admin (Pc/PC-PT), PT-CyberObserver0 (CyberObserver/CyberObserver), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Server0 (Server/Server-PT), Multilayer Switch0 (MultiLayerSwitch/3560-24PS), PLC1 (PLC/PLC-PT), Profinet IO (MCU/MCU-PT), Multilayer Switch1 (MultiLayerSwitch/IE-3400), Multilayer Switch2 (MultiLayerSwitch/IE-9320)
- `06 Industrial -  OT\Industrial Cybersecurity and Monitoring\Firewall\isa3000_dmz.pkt`
  version: `9.0.0.0000`, devices: `36`, links: `32`
  tags: host_server, multi_router, switching
  devices: Good-User (Pc/PC-PT), Power Distribution Device0 (Power Distribution Device/Power Distribution Device), Modbus Server (Server/Server-PT), Malicious-User (Pc/PC-PT), Web Server (Server/Server-PT), Remote-User (Pc/PC-PT), AAA Server (Server/Server-PT), VPN Server Outside (Router/1841), Switch0(1) (Switch/2960-24TT), PLC-Inside-1 (SBC/SBC-PT), SBC2-1 (SBC/SBC-PT), IO1-1 (SBC/SBC-PT), MMS Server (MCUComponent/Thing), MMSClient (MCUComponent/Thing), Router0 (Router/ISR4321), Power Distribution Device1 (Power Distribution Device/Power Distribution Device), Mobus-Client (Pc/PC-PT), Power Distribution Device2 (Power Distribution Device/Power Distribution Device), Admin (Pc/PC-PT), Switch0(1)(1) (Switch/2960-24TT), SBC2-2 (SBC/SBC-PT), IO1-2 (SBC/SBC-PT), PLC-Inside-2 (SBC/SBC-PT), PLC-Outside (SBC/SBC-PT), GooseSubscriber (MCUComponent/Thing), GoosePublisher (MCUComponent/Thing), Local DNS Server (Server/Server-PT), DNS Server (Server/Server-PT), VPN Server Inside (Router/1841), Switch2 (Switch/2960-24TT), Multilayer Switch0 (MultiLayerSwitch/IE-3400), Multilayer Switch1 (MultiLayerSwitch/IE-3400), Multilayer Switch2 (MultiLayerSwitch/IE-3400), ASA3 (ASA/ISA-3000), ASA4 (ASA/ISA-3000), ASA5 (ASA/ISA-3000)
