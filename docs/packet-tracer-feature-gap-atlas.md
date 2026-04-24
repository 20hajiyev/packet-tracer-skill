# Packet Tracer Feature Gap Atlas

This atlas is the public truth source for Packet Tracer 9.0 features that exist in local Cisco samples but are not yet fully productized by this skill.

It is intentionally conservative:

- `inventory_known` means a Packet Tracer sample or path proves the feature exists.
- `report_supported` means the skill can recognize and report the feature without claiming mutation support.
- `edit_proven` requires a roundtrip editor test.
- `donor_backed_ready` requires selected-donor evidence.
- `generate_ready` requires acceptance-backed generate behavior.

The atlas does not claim that every Packet Tracer feature is generate-ready. It turns missing or under-modelled Packet Tracer features into an auditable backlog before any broad config mutation is opened.

## Current Feature Families

- `ipv6_routing`: SLAAC, DHCPv6, prefix delegation, AAAA DNS, IPv6 tunneling, ISATAP, OSPFv3, EIGRP IPv6, RIPng, HSRP.
- `l2_security_monitoring`: DHCP snooping, DAI, 802.1X/NAC, LLDP, REP, SNMP, NetFlow, SPAN/RSPAN, QoS, port security.
- `wan_security_edge`: ASA ACL/NAT, ASA service policy, clientless VPN, CBAC, ZFW, sniffer, IPSec variants.
- `wireless_advanced`: WLC, WPA Enterprise/RADIUS, WEP/WPA modes, guest Wi-Fi, beamforming, Meraki, 5G/cellular, Bluetooth.
- `automation_controller`: Network Controller, Python, JavaScript, Blockly, TCP/UDP test apps, VM/IOx samples.
- `voice_collaboration`: VoIP, IP phones, Call Manager-style telephony, Linksys voice.
- `industrial_iot`: MQTT, Real HTTP, Real WebSocket, visual scripting, PTP, Profinet, L2NAT, CyberObserver, industrial firewall.
- `physical_media_device`: coaxial, cable/DSL, central office, cell tower, power distribution, hot-swappable modules, IOS/license workflows.

## CLI

```powershell
python .\scripts\generate_pkt.py --feature-gap-report
```

The report includes:

- total Packet Tracer feature groups tracked
- mapped and unmapped feature counts
- status counts by support level
- sample-backed feature counts
- top missing feature families
- per-feature evidence from parser, catalog, coverage, editor tests, and Packet Tracer sample paths

## Product Rule

Feature atlas support is not the same as generation support. A feature can be visible in `--feature-gap-report` and still remain blocked in `--explain-plan`, `--compare-scenarios`, or `--parity-report` until donor-backed proof exists.
