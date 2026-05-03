# IPv4 Routing and IOS Management Proof

This proof wave uses the local user-supplied `pkt_examples` corpus as evidence input, not as public package content. The corpus contains many decodeable Packet Tracer labs with IPv4 routing, NAT/PAT, SSH, NTP, syslog, DHCP relay, and classic CCNA management patterns.

## What Is Edit-Proven

The supported subset is explicit IOS `RUNNINGCONFIG` mutation only:

- OSPFv2 via `router ospf <process>` with `network <network> <wildcard> area <area>`
- `router eigrp <asn>` with IPv4 `network` and optional `no auto-summary`
- `router rip` with `version 2`, IPv4 `network`, and optional `no auto-summary`
- `ip route <network> <mask> <next-hop>` including default route
- interface-level `ip helper-address`
- interface-level `ip nat inside` and `ip nat outside`
- `ip nat inside source static <inside-local> <inside-global>`
- PAT overload with `ip nat inside source list <acl> interface <interface> overload`
- IOS SSH setup with domain, username/password, RSA modulus, and `ip ssh version 2`
- IOS `ntp server` and `logging host`

## What This Proves

- The parser can classify IPv4 routing and management prompts as `ipv4_routing_management`.
- Explicit commands produce deterministic router operations.
- Existing IOS text config surfaces can roundtrip these command shapes.
- Parity can show these capabilities as `edit_supported=true`, `generate_supported=false`, and `generate_mismatch_reason=supported_in_edit_only`.
- Local sample audit can summarize user-supplied `.pkt/.pka` evidence without committing raw Packet Tracer files.

## What This Does Not Prove

- It does not make any IPv4 routing, NAT, or IOS management capability `generate_ready`.
- It does not synthesize topology, links, ACL objects, NAT pools, route convergence, or lab scoring.
- It does not promote local `pkt_examples` files into curated public donors.
- It does not mutate GUI/internal Packet Tracer state.

## Safe Next Step

The next promotion step is donor-backed readiness for a narrow single-donor IPv4 routing fixture, only after selected-donor evidence, deterministic targets, and acceptance JSON prove the resulting `.pkt` opens and matches expected inventory/parity.
