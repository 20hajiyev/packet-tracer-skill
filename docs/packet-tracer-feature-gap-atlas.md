# Packet Tracer Feature Gap Atlas

This atlas is the public truth source for Packet Tracer 9.0 features that exist in local Cisco samples but are not yet fully productized by this skill.

It is intentionally conservative:

- `inventory_known` means a Packet Tracer sample or path proves the feature exists.
- `report_supported` means the skill can recognize and report the feature without claiming mutation support.
- `edit_proven` requires a roundtrip editor test.
- `donor_backed_ready` requires selected-donor evidence or a validated proof-linked explicit edit gate with sample, decode, and roundtrip evidence.
- `generate_ready` requires acceptance-backed generate behavior.

The atlas does not claim that every Packet Tracer feature is generate-ready. It turns missing or under-modelled Packet Tracer features into an auditable backlog before any broad config mutation is opened.

## Remote Sample Evidence

GitHub `.pkt` repositories can add discovery evidence, but they do not automatically change feature maturity.

Remote sample evidence is treated in three layers:

- sample-path evidence: a public repo path suggests a Packet Tracer feature exists, but the file may still fail decode or validation
- decode/inventory evidence: a locally cached sample opens through the decoder and produces feature tags
- proof evidence: an explicit editor roundtrip or acceptance fixture proves a safe operation shape

`output/remote-import-cache/remote-sample-audit.json` records repo URL, license metadata, imported file counts, decode success/failure counts, detected feature tags, license-based candidate promotion status, and decode-gated validation status. Unknown-license repositories remain `reference_only`. Permissive-license repositories only become curated candidates after local decode and inventory validation. Raw remote `.pkt` files are never a checked-in truth source.

## First Donor-Backed Edit Readiness Wave

The first promotion wave is `ipv6_routing`. The following subset can move beyond report-only when explicit router/interface targets or proof-linked IPv6/routing edit evidence exists:

- IPv6 interface/SLAAC config remains edit-proven.
- DHCPv6 stateful pool binding remains edit-proven until decode-verified sample evidence is available.
- OSPFv3 interface routing is donor-backed ready for explicit edit paths.
- EIGRP IPv6 interface routing is donor-backed ready for explicit edit paths.
- RIPng interface routing is donor-backed ready for explicit edit paths.
- IPv6 HSRP virtual address is donor-backed ready for explicit edit paths.

IPv6 tunneling, ISATAP, prefix delegation, and AAAA DNS remain report-first until separate donor-backed editor proof exists.

## Second Edit-Proven Wave

The second promotion wave is `l2_security_monitoring`. The following subset is edit-proven for explicit commands, but still not broad generate-ready:

- DHCP snooping
- Dynamic ARP Inspection
- LLDP
- REP
- SNMP community
- NetFlow export
- SPAN/RSPAN
- Port security

802.1X/NAC and QoS remain report-first in this wave. Decode-fail Packet Tracer samples can prove that a feature exists by path/catalog evidence, but they do not create edit or generate readiness by themselves.

## Third Edit-Proven Wave

The third promotion wave is `wireless_advanced`. This wave deliberately promotes
only the safest explicit wireless edit subset:

- WEP SSID/security mutation
- WPA Enterprise/RADIUS SSID/security intent

These capabilities can report `edit_supported=true` only when the prompt is an
explicit wireless edit command with a deterministic AP/router/WLC target and
SSID. They still report `generate_supported=false` and
`generate_mismatch_reason=supported_in_edit_only`.

WLC/controller workflows, Meraki, cellular/5G, Bluetooth, beamforming, and
guest Wi-Fi remain report-only until separate donor-backed editor proof exists.

## Fourth Edit-Proven Wave

The fourth promotion wave is `wan_security_edge`. This wave promotes only
explicit, deterministic router edit commands:

- GRE tunnel basics
- PPP serial encapsulation
- IPSec transform-set lines
- site-to-site VPN crypto-map skeleton binding

These capabilities can report `edit_supported=true` only when the prompt names
the router, interface or tunnel, peer/source/destination, and required crypto
objects. They still report `generate_supported=false` and
`generate_mismatch_reason=supported_in_edit_only`.

ASA ACL/NAT, service policies, clientless VPN, CBAC, ZFW, security-edge device
mutation, and multilayer switching remain report-only in this wave until separate
donor-backed editor proof exists.

## Fifth Donor-Backed Edit Readiness Wave

The fifth promotion wave is `industrial_iot` programming. This wave promotes
only existing script-file replacement for Real HTTP and Real WebSocket samples:

- Real HTTP Python script file replacement
- Real WebSocket Python/JavaScript script file replacement
- programming inventory with hashes and lengths instead of source dumps

These capabilities can report `edit_supported=true` and
`donor_backed_ready=true` only when the prompt quotes the device name, app name,
and existing file name. They still report `generate_supported=false` and
`generate_mismatch_reason=supported_in_edit_only`.

MQTT protocol mutation, visual scripting generation, PTP, Profinet, L2NAT,
CyberObserver, and industrial firewall workflows remain report-only until
separate donor-backed editor proof exists.

## Sixth Donor-Backed Edit Readiness Wave

The sixth promotion wave is `voice_collaboration`. This wave promotes only
explicit IOS voice configuration lines on an existing router config surface:

- `telephony-service` source address, SCCP port, max ephones, and max DNs
- `ephone-dn` extension number lines
- `ephone` MAC and button assignment lines
- `dial-peer voice` destination-pattern and session-target lines

These capabilities can report `edit_supported=true` and
`donor_backed_ready=true` only when the prompt names the router and the voice
object identifiers or values. They still report `generate_supported=false` and
`generate_mismatch_reason=supported_in_edit_only`.

IP phone GUI internals, Linksys voice GUI mutation, Call Manager synthesis, and
broad VoIP topology generation remain report-only until separate donor-backed
editor proof exists.

## Seventh Donor-Backed Edit Readiness Wave

The seventh promotion wave is `automation_controller`. This wave promotes only
existing script-file replacement on Packet Tracer programming samples:

- Python app file replacement
- JavaScript app file replacement
- TCP/UDP test app JavaScript file replacement
- programming inventory with hashes and lengths instead of source dumps

These capabilities can report `edit_supported=true` and
`donor_backed_ready=true` only when the prompt quotes the device name, app name,
and existing file name. They still report `generate_supported=false` and
`generate_mismatch_reason=supported_in_edit_only`.

Network Controller GUI workflows, Blockly visual graph mutation, VM/IOx runtime
creation, and broad controller/application generation remain report-only until
separate donor-backed editor proof exists.

## Eighth Donor-Backed Edit Readiness Wave

The eighth promotion wave is the `0.2.3` candidate L2/security proof hardening.
This wave promotes only deterministic IOS line edits:

- 802.1X/NAC switch config using `aaa new-model`, `dot1x system-auth-control`,
  `authentication port-control`, and optional `radius-server host`
- QoS switch config using explicit `class-map`, `policy-map`, and
  `service-policy input/output`
- router CBAC using `ip inspect name` plus interface-level `ip inspect`
- router ZFW using `zone security`, `zone-pair security`, and
  `policy-map type inspect`

These capabilities can report `edit_supported=true` only for explicit commands
with deterministic device/interface/object names. Dot1x and ZFW can also report
`donor_backed_ready=true` because they have decode-verified sample evidence.
QoS and CBAC remain `edit_proven` until decode-verified sample evidence is added.
All four still report `generate_supported=false` and
`generate_mismatch_reason=supported_in_edit_only`.

ASA ACL/NAT, ASA service-policy, clientless VPN, sniffer workflows, broad NAC,
and broad QoS design remain report-only until separate donor-backed editor proof
exists.

## Ninth Edit-Proven Wave

The ninth promotion wave is `l2_resiliency_routing`. This wave uses the local
user-supplied `pkt_examples` corpus as evidence input and promotes only explicit
IOS line edits:

- BGP `router bgp`, `neighbor remote-as`, and optional `network mask` lines
- STP/RSTP `spanning-tree mode` and VLAN root lines
- EtherChannel `channel-group` and `Port-channel` lines
- LACP/PAgP mode derivation from explicit EtherChannel modes
- VTP domain/mode/version lines
- DTP dynamic switchport mode lines

These capabilities can report `edit_supported=true` only for explicit commands
with deterministic router/switch/interface names. They do not report
`donor_backed_ready=true` yet, because this wave does not add selected-donor
acceptance proof. They still report `generate_supported=false` and
`generate_mismatch_reason=supported_in_edit_only`.

`spanning-tree` evidence is intentionally separated from SPAN/RSPAN. STP/RSTP
must not create the `span` capability; SPAN remains tied to monitor-session style
config or explicit SPAN/RSPAN prompts.

## Tenth Edit-Proven Wave

The tenth promotion wave is `ipv4_routing_management`. This wave also uses the
local user-supplied `pkt_examples` corpus as evidence input and promotes only
explicit IOS line edits:

- OSPFv2, EIGRP IPv4, and RIPv2 router process/network lines
- static and default IPv4 routes
- DHCP relay `ip helper-address`
- NAT inside/outside markers, static NAT, and PAT overload skeletons
- IOS SSH, NTP client, and syslog client lines

These capabilities can report `edit_supported=true` only for explicit commands
with deterministic router and interface names. They remain
`donor_backed_ready=false` and `generate_supported=false`; the local sample corpus
is evidence input, not a public curated donor registry.

## Current Feature Families

- `ipv6_routing`: SLAAC, DHCPv6, prefix delegation, AAAA DNS, IPv6 tunneling, ISATAP, OSPFv3, EIGRP IPv6, RIPng, HSRP; OSPFv3, EIGRP IPv6, RIPng, and HSRP are donor-backed ready for explicit edit paths.
- `ipv4_routing_management`: OSPFv2, EIGRP IPv4, RIPv2, static/default routes, DHCP relay, static/dynamic NAT, PAT, SSH, NTP, and syslog; explicit IOS text edits are edit-proven, but not donor-backed-ready or generate-ready.
- `l2_resiliency_routing`: BGP, STP/RSTP, EtherChannel, LACP/PAgP, VTP, and DTP; explicit IOS text edits are edit-proven, but not donor-backed-ready or generate-ready.
- `l2_security_monitoring`: DHCP snooping, DAI, 802.1X/NAC, LLDP, REP, SNMP, NetFlow, SPAN/RSPAN, QoS, port security; dot1x is donor-backed ready for explicit IOS line edits, while QoS is edit-proven.
- `wan_security_edge`: VPN crypto-map skeleton, IPSec transform-set, GRE tunnel basics, PPP serial encapsulation, CBAC/ZFW router IOS edits, security-edge evidence, multilayer evidence.
- `security_edge_deepening`: ASA ACL/NAT, ASA service policy, clientless VPN, CBAC, ZFW, sniffer, IPSec variants; router ZFW is donor-backed ready, while CBAC is edit-proven.
- `wireless_advanced`: WLC, WPA Enterprise/RADIUS, WEP/WPA modes, guest Wi-Fi, beamforming, Meraki, 5G/cellular, Bluetooth.
- `automation_controller`: Network Controller, Python, JavaScript, Blockly, TCP/UDP test apps, VM/IOx samples; existing Python, JavaScript, and TCP/UDP script-file edits are donor-backed ready.
- `voice_collaboration`: VoIP, IP phones, Call Manager-style IOS telephony, Linksys voice; explicit IOS voice edits are donor-backed ready.
- `industrial_iot`: MQTT, Real HTTP, Real WebSocket, visual scripting, PTP, Profinet, L2NAT, CyberObserver, industrial firewall; only Real HTTP/WebSocket existing script-file edits are donor-backed ready.
- `physical_media_device`: coaxial, cable/DSL, central office, cell tower, power distribution, hot-swappable modules, IOS/license workflows.

## CLI

```powershell
python .\scripts\generate_pkt.py --feature-gap-report
python .\scripts\generate_pkt.py --local-sample-audit-root "C:\path\to\pkt_examples"
```

The default local audit artifact is `output/local-sample-audit.json`. It is ignored by git and excluded from npm packaging. Local `pkt_examples` evidence does not promote a sample into curated public truth by itself.

The report includes:

- total Packet Tracer feature groups tracked
- mapped and unmapped feature counts
- status counts by support level
- sample-backed feature counts
- top missing feature families
- per-feature evidence from parser, catalog, coverage, editor tests, and Packet Tracer sample paths

## Product Rule

Feature atlas support is not the same as generation support. A feature can be visible in `--feature-gap-report` and still remain blocked in `--explain-plan`, `--compare-scenarios`, or `--parity-report` until donor-backed proof exists.
