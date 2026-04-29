# WAN/Security Edge Donor Proof

## Proof Goal
This proof records the current `wan_security_edge` truth after the Home IoT internal gate. It is a report/selection and donor-backed readiness proof, not a broad synthetic WAN/security generator claim.

## Current Inventory And Report Proof
- The fixture prompt `wan security edge, multilayer switch, cloud, firewall/ASA, GRE, PPP, site-to-site VPN, IPsec, ACL, NAT` maps to `wan_security_edge`.
- The planner recognizes `vpn`, `ipsec`, `gre`, `ppp`, `multilayer_switching`, and `security_edge` as the expected capability family.
- Static Packet Tracer samples with VPN/IPSec/GRE/PPP, ASA/security, WAN/cloud, and multilayer switch evidence are treated as `WAN/security edge` donors.
- Capability parity remains conservative when no selected donor is available: the planner reports donor-limited readiness instead of guessing a final `.pkt`.

## Donor-Backed Readiness Interpretation
WAN/security readiness can only rise when a selected donor is already aligned with `WAN/security edge` and contains the requested capability evidence plus the required runtime feature:

- `vpn`, `ipsec`, `gre`: tunnel-capable donor evidence
- `ppp`: WAN/PPP donor evidence
- `security_edge`: ASA/security donor evidence
- `multilayer_switching`: multilayer switch donor evidence

The prompt must explicitly request WAN/security intent, such as VPN, IPsec, GRE, PPP, ASA/firewall, cloud, multilayer, or site-to-site wording.

## What This Proves
- WAN/security prompts are family-correct and do not drift into `service_heavy`.
- Packet Tracer sample inventory can identify WAN/security donor candidates.
- Selected-donor readiness can be represented without changing the public JSON contract.
- Refusal and remediation now point toward reusable ASA/cloud/serial/tunnel donor skeletons.
- Explicit router edit commands can roundtrip a narrow WAN/security subset:
  - GRE tunnel interface basics
  - PPP serial encapsulation
  - IPSec transform-set lines
  - site-to-site VPN crypto-map skeleton binding

## What This Does Not Prove
- It does not claim full synthetic VPN/IPSec/GRE/PPP configuration generation.
- It does not claim that every ASA/firewall or multilayer switch feature is editable.
- It does not claim ASA ACL/NAT, ASA service policy, CBAC, ZFW, or multilayer switching edit support.
- It does not allow `reference_only` donors as final apply donors.
- It does not change the `single-donor` final `.pkt` apply rule.

## Edit-Proven Commands

```text
set R1 gre tunnel Tunnel0 source 10.0.0.1 destination 10.0.0.2 ip 172.16.0.1/30
set R1 ppp interface Serial0/0/0 authentication chap
set R1 ipsec transform-set TS esp-aes esp-sha-hmac
set R1 crypto map VPNMAP 10 peer 203.0.113.2 transform-set TS match ACL_VPN interface Serial0/0/0
```

These commands are edit-proven only. They intentionally report
`generate_supported=false` and `generate_mismatch_reason=supported_in_edit_only`
until selected-donor acceptance evidence exists.

## Next Constrained Edit Candidates
- ASA ACL/NAT mutation on an existing security-edge donor.
- SVI/routed-port mutation on an existing multilayer switch donor.
- CBAC/ZFW policy mutation on an existing routed security donor.

These candidates need separate roundtrip proof before they become release claims.
