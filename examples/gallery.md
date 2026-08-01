## Showcase Examples

These examples are public, text-first proof artifacts derived from donor-backed workflows and aligned with the scenario fixture corpus.

`0.2.4` candidate examples surface, built on the published `0.2.3` capability release:

- `campus`
- `home_iot`
- `service_heavy`

Hero visual:

- [complex campus screenshot](screenshots/complex_campus_master_edit_v4.png)

Canonical donor proof:

- [campus donor proof](../docs/campus-donor-proof.md)
- [home IoT donor proof](../docs/home-iot-donor-proof.md)
- [WAN/security donor proof](../docs/wan-security-donor-proof.md)

Support truth:

- showcase examples are screenshot + inventory artifacts for known working donor-backed workflows
- proof cards are text-only evidence for explicit edit paths and donor-backed readiness
- atlas `generate_ready=0` remains intentional; these examples do not claim broad generation support

| Title | Family | Capabilities | Image | Inventory |
| --- | --- | --- | --- | --- |
| Complex Campus | `campus` | management_vlan, telnet, acl, server_dns, server_email, server_aaa, wireless_mutation | [screenshot](screenshots/complex_campus_master_edit_v4.png) | [manifest](complex_campus_master_edit_v4.inventory.json) |
|  |  | Management VLAN, Telnet, ACL, DNS, email, AAA, and multi-SSID wireless campus edit. |  |  |
|  |  | `known_working_example | donor=donor-backed | capabilities=management_vlan, telnet, acl` |  |  |
|  |  | `campus_core_complex | known_working_example | family=campus` |  |  |
|  |  | `management_vlan=known_working_example, telnet=known_working_example, acl=known_working_example` |  |  |
|  |  | `decision=known_working_example | donor_origin=donor-backed` |  |  |
|  |  | `runtime=donor-backed example artifact` |  |  |
| Home IoT | `home_iot` | iot, iot_registration, wireless_ap | [screenshot](screenshots/home_iot_cli_edit_v1.png) | [manifest](home_iot_cli_edit_v1.inventory.json) |
|  |  | Home gateway and IoT device onboarding with donor-backed registration state and constrained wireless readiness. |  |  |
|  |  | `known_working_example | donor=donor-backed | capabilities=iot, iot_registration, wireless_ap | mode=donor-backed constrained edit` |  |  |
|  |  | `home_iot_complex | known_working_example | family=home_iot` |  |  |
|  |  | `iot=known_working_example, iot_registration=donor_backed_ready, wireless_ap=known_working_example` |  |  |
|  |  | `decision=known_working_example | donor_origin=donor-backed` |  |  |
|  |  | `runtime=donor-backed example artifact` |  |  |
| Service Heavy | `service_heavy` | server_dns, server_dhcp, server_ftp, server_email, server_syslog, server_aaa | [screenshot](screenshots/service_heavy_cli_edit_v1.png) | [manifest](service_heavy_cli_edit_v1.inventory.json) |
|  |  | Service-rich server lab with DNS, DHCP, FTP, email, syslog, AAA, and detailed service metadata. |  |  |
|  |  | `known_working_example | donor=donor-backed | capabilities=server_dns, server_dhcp, server_ftp` |  |  |
|  |  | `service_heavy_complex | known_working_example | family=service_heavy` |  |  |
|  |  | `server_dns=known_working_example, server_dhcp=known_working_example, server_ftp=known_working_example` |  |  |
|  |  | `decision=known_working_example | donor_origin=donor-backed` |  |  |
|  |  | `runtime=donor-backed example artifact` |  |  |
|  |  | extra visuals: [detail 1](screenshots/service_heavy_cli_edit_v1_dhcp.png); [detail 2](screenshots/service_heavy_cli_edit_v1_dns.png); [detail 3](screenshots/service_heavy_cli_edit_v1_ftp.png) |  |  |

## 0.2.4 Candidate Proof Cards

| Title | Family | Support | Proof | Boundary |
| --- | --- | --- | --- | --- |
| IPv4 Routing / NAT / IOS Management | `ipv4_routing_management` | `edit_proven` | [proof](../docs/ipv4-routing-management-proof.md) | No topology synthesis, route convergence proof, ACL object inference, or broad NAT design generation. |
|  |  | `explicit IPv4 routing/NAT/IOS-management commands are edit_proven; generate_ready=false` |  |  |
|  |  | try this command: `set R1 ospfv2 1 network 10.0.0.0 wildcard 0.0.0.255 area 0` |  |  |
|  |  | does not claim: No topology synthesis, route convergence proof, ACL object inference, or broad NAT design generation. |  |  |
| L2 Resiliency + BGP | `l2_resiliency_routing` | `edit_proven` | [proof](../docs/l2-resiliency-bgp-proof.md) | No redundant link creation, STP state validation, BGP convergence proof, or topology generation. |
|  |  | `explicit BGP/STP/EtherChannel/VTP/DTP IOS commands are edit_proven; generate_ready=false` |  |  |
|  |  | try this command: `set SW1 etherchannel 1 mode active interfaces FastEthernet0/1 FastEthernet0/2` |  |  |
|  |  | does not claim: No redundant link creation, STP state validation, BGP convergence proof, or topology generation. |  |  |
| L2 Security + QoS | `l2_security_monitoring` | `donor_backed_ready` | [proof](../docs/l2-security-qos-proof.md) | No broad NAC design, RADIUS user synthesis, certificate workflow, or end-to-end QoS policy inference. |
|  |  | `dot1x is donor_backed_ready; QoS remains edit_proven; generate_ready=false` |  |  |
|  |  | try this command: `set SW1 dot1x interface FastEthernet0/1 mode auto radius 192.168.1.10 key radius123` |  |  |
|  |  | does not claim: No broad NAC design, RADIUS user synthesis, certificate workflow, or end-to-end QoS policy inference. |  |  |
| Security Edge CBAC/ZFW | `wan_security_edge` | `donor_backed_ready` | [proof](../docs/security-edge-deepening-proof.md) | No ASA GUI/internal mutation, clientless VPN, service-policy synthesis, or broad security topology generation. |
|  |  | `ZFW is donor_backed_ready; CBAC remains edit_proven; generate_ready=false` |  |  |
|  |  | try this command: `set R1 zfw zone-pair INSIDE_OUT source inside destination outside policy POLICY1` |  |  |
|  |  | does not claim: No ASA GUI/internal mutation, clientless VPN, service-policy synthesis, or broad security topology generation. |  |  |
| Voice / Collaboration | `voice_collaboration` | `donor_backed_ready` | [proof](../docs/voice-collaboration-proof.md) | No Call Manager GUI synthesis, Linksys voice mutation, phone GUI internals, or broad VoIP topology generation. |
|  |  | `IOS telephony-service, ephone, and dial-peer paths are donor_backed_ready; generate_ready=false` |  |  |
|  |  | try this command: `set "Router0" telephony service source-address 192.168.10.1 port 2000 max-ephones 4 max-dn 4` |  |  |
|  |  | does not claim: No Call Manager GUI synthesis, Linksys voice mutation, phone GUI internals, or broad VoIP topology generation. |  |  |
| Automation / Controller Scripts | `automation_controller` | `donor_backed_ready` | [proof](../docs/automation-controller-proof.md) | No Network Controller GUI synthesis, Blockly graph mutation, VM/IOx workflow generation, or new app/file creation. |
|  |  | `existing Python, JavaScript, and TCP/UDP script files are donor_backed_ready; generate_ready=false` |  |  |
|  |  | try this command: `set "Device" script app "App Name" file "main.py" content "print('hello')"` |  |  |
|  |  | does not claim: No Network Controller GUI synthesis, Blockly graph mutation, VM/IOx workflow generation, or new app/file creation. |  |  |
| Industrial Programming | `industrial_iot` | `donor_backed_ready` | [proof](../docs/industrial-programming-proof.md) | No MQTT broker generation, Profinet/PTP/L2NAT mutation, CyberObserver workflow, or industrial topology generation. |
|  |  | `Real HTTP and Real WebSocket script-file edits are donor_backed_ready; generate_ready=false` |  |  |
|  |  | try this command: `set "Py: real http server 2" script app "Real HTTP Server" file "main.py" content "print('updated')"` |  |  |
|  |  | does not claim: No MQTT broker generation, Profinet/PTP/L2NAT mutation, CyberObserver workflow, or industrial topology generation. |  |  |

## Local Sample Evidence Board

Local audit source: `examples/local-sample-evidence.json`.

Audit summary: `367` files, `366` decode successes, `1` decode failures.

This is local evidence only. It does not make user-supplied `.pkt/.pka` files public curated donors, and it does not enter the npm package.

| Capability | Sample Count | Example Paths |
| --- | --- | --- |
| `stp` | 348 | 09. 2Switches_3Routers_Rime_New.pkt; 1-Securing Network Devices and Establish a SSH Session.pkt; 10-IPv4 Static and Default Routes.pkt |
| `static_route` | 87 | 09. 2Switches_3Routers_Rime_New.pkt; 10-IPv4 Static and Default Routes.pkt; 13.3.2 lab.pkt |
| `ripv2` | 61 | 10routerEGIRP.pkt; 10RouterRIP.pkt; 13.3.2 lab.pkt |
| `default_route` | 56 | 10-IPv4 Static and Default Routes.pkt; 13.3.2 lab.pkt; 23i2110.pkt |
| `ospfv2` | 50 | 11-Single-Area OSPFv2.pkt; 13routerOSPF.pkt; 2020-06-18 OSPF.pkt |
| `dhcp_pool` | 48 | 10PORTDHCP.pkt; 20211220 VoIP, PortSec, DHCP - finished.pkt; 6-DHCPv4.pkt |
| `acl` | 40 | 13.3.2 lab.pkt; 2020-06-18 OSPF.pkt; 23i2110.pkt |
| `ssh_ios` | 27 | 1-Securing Network Devices and Establish a SSH Session.pkt; 16.4.7 lab.pkt; 2020-05-16 AAA NTP For Learnersv3.pkt |
| `dhcp_relay` | 24 | 2020-04-19 HSRP OGIT PT Lab.pkt; 2020-05-16 AAA NTP For Learnersv3.pkt; 2020-05-20 Routing  NTP and more WTW.pkt |
| `eigrp_ipv4` | 22 | 10routerEGIRP.pkt; 13routerEigrp.pkt; 13routerEigrpFINALIZED.pkt |
| `etherchannel` | 7 | 20211124 L2 EtherChannel, HSRP, OSPF - empty.pkt; 20211124 L2 EtherChannel, HSRP, OSPF - finished.pkt; 5-Implement Inter-VLAN Routing and Etherchannel.pkt |
| `bgp` | 2 | Cisco-networking-projects-main\BGP\BGP_3_Router\BGP_3_ROUTERS.pkt; Cisco-networking-projects-main\BGP\BGP_Class_C\BGP_Class_C.pkt |

## Proof-Readiness Promotion Queue

This queue connects proof cards, feature atlas status, and local sample evidence. It is a planning artifact, not a `generate_ready` claim.

Dashboard: [proof-readiness dashboard](../docs/proof-readiness-dashboard.md)

| Priority | Capability | Family | Current Status | Explicit Command | Next Safe Action | Blocker |
| --- | --- | --- | --- | --- | --- | --- |
| `primary` | `ospfv2` | `ipv4_routing_management` | `edit_proven` | `set R1 ospfv2 1 network 10.0.0.0 wildcard 0.0.0.255 area 0` | Add proof-linked selected-donor readiness for explicit OSPFv2 IOS network commands. | `blocked_by_no_deterministic_target` |
| `primary` | `eigrp_ipv4` | `ipv4_routing_management` | `edit_proven` | `set R1 eigrp ipv4 100 network 10.0.0.0 wildcard 0.0.0.255 no-auto-summary` | Add proof-linked readiness for explicit EIGRP IPv4 network commands with router target validation. | `blocked_by_no_deterministic_target` |
| `primary` | `ripv2` | `ipv4_routing_management` | `edit_proven` | `set R1 rip version 2 network 10.0.0.0 no-auto-summary` | Promote explicit RIPv2 IOS commands after selected donor and interface scope are locked. | `blocked_by_no_deterministic_target` |
| `primary` | `static_route` | `ipv4_routing_management` | `edit_proven` | `set R1 static-route 192.168.10.0/24 via 10.0.0.1` | Promote explicit static/default route commands where gateway and router target are deterministic. | `blocked_by_no_deterministic_target` |
| `primary` | `default_route` | `ipv4_routing_management` | `edit_proven` | `set R1 static-route 0.0.0.0/0 via 10.0.0.1` | Use the same selected-donor proof path as static_route, but keep broad routing design blocked. | `blocked_by_no_deterministic_target` |
| `primary` | `dhcp_relay` | `ipv4_routing_management` | `edit_proven` | `set R1 dhcp-relay interface GigabitEthernet0/0 helper 192.168.1.10` | Promote explicit helper-address edits only when interface and relay server are named or uniquely resolved. | `blocked_by_no_deterministic_target` |
| `primary` | `ssh_ios` | `ipv4_routing_management` | `edit_proven` | `set R1 ssh domain lab.local username admin password cisco123 modulus 1024` | Promote explicit IOS SSH setup when router target, domain, username, and modulus are deterministic. | `blocked_by_no_deterministic_target` |
| `primary` | `ntp_ios` | `ipv4_routing_management` | `edit_proven` | `set R1 ntp server 192.168.1.20` | Promote explicit NTP server edits after selected-donor proof confirms config persistence. | `blocked_by_no_deterministic_target` |
| `primary` | `syslog_ios` | `ipv4_routing_management` | `edit_proven` | `set R1 syslog server 192.168.1.30` | Keep edit-proven until local decode-backed sample evidence exists for logging host lines. | `blocked_by_missing_decode_evidence` |
| `secondary` | `stp` | `l2_resiliency_routing` | `edit_proven` | `set SW1 stp mode rapid-pvst vlan 10 root primary` | Promote explicit STP mode/root commands after switch target and VLAN scope are deterministic. | `blocked_by_no_deterministic_target` |
| `secondary` | `rstp` | `l2_resiliency_routing` | `edit_proven` | `set SW1 stp mode rapid-pvst vlan 10 root primary` | Use STP selected-donor proof path for rapid-pvst command shape. | `blocked_by_no_deterministic_target` |
| `secondary` | `etherchannel` | `l2_resiliency_routing` | `edit_proven` | `set SW1 etherchannel 1 mode active interfaces FastEthernet0/1 FastEthernet0/2` | Promote explicit channel-group edits only when every interface target is named and unique. | `blocked_by_no_deterministic_target` |
| `secondary` | `lacp` | `l2_resiliency_routing` | `edit_proven` | `set SW1 etherchannel 1 mode active interfaces FastEthernet0/1 FastEthernet0/2` | Promote active/passive LACP modes through the EtherChannel proof gate. | `blocked_by_no_deterministic_target` |
| `secondary` | `pagp` | `l2_resiliency_routing` | `edit_proven` | `set SW1 etherchannel 1 mode desirable interfaces FastEthernet0/1 FastEthernet0/2` | Promote desirable/auto PAgP modes only after selected-donor interface validation. | `blocked_by_no_deterministic_target` |
| `secondary` | `vtp` | `l2_resiliency_routing` | `edit_proven` | `set SW1 vtp domain CAMPUS mode server version 2` | Promote explicit VTP domain/mode/version edits when switch target is deterministic. | `blocked_by_no_deterministic_target` |
| `secondary` | `dtp` | `l2_resiliency_routing` | `edit_proven` | `set SW1 dtp interface FastEthernet0/1 mode dynamic desirable` | Keep edit-proven until local decode-backed DTP sample evidence is found. | `blocked_by_missing_decode_evidence` |
| `secondary` | `bgp` | `l2_resiliency_routing` | `edit_proven` | `set R1 bgp 65001 neighbor 10.0.0.2 remote-as 65002 network 192.168.1.0 mask 255.255.255.0` | Promote explicit BGP neighbor/network edits only after ASN, neighbor, and network target validation are proof-linked. | `blocked_by_no_deterministic_target` |

