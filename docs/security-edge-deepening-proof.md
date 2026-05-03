# Security Edge Deepening Proof

This proof records the `0.2.3` candidate router-based security edge edit-proven subset. The supported surface is IOS line-based CBAC/ZFW configuration on an explicitly named router. ASA GUI/internal mutation, clientless VPN, and broad security topology generation remain blocked.

## Explicit Commands

Supported CBAC shape:

```text
set R1 cbac inspect FIREWALL protocol tcp interface FastEthernet0/0 direction in
```

This writes:

```text
ip inspect name FIREWALL tcp
interface FastEthernet0/0
 ip inspect FIREWALL in
```

Supported ZFW shapes:

```text
set R1 zfw zone inside interface FastEthernet0/0
set R1 zfw zone-pair INSIDE_OUT source inside destination outside policy POLICY1
set R1 zfw class-map CM_WEB match protocol http policy-map POLICY1 action inspect
```

These write:

```text
zone security inside
interface FastEthernet0/0
 zone-member security inside
zone-pair security INSIDE_OUT source inside destination outside
 service-policy type inspect POLICY1
class-map type inspect match-any CM_WEB
 match protocol http
policy-map type inspect POLICY1
 class type inspect CM_WEB
  inspect
```

## Donor-Backed Readiness

- `zfw` is `donor_backed_ready` because it has parser, catalog, decode-verified sample, and editor roundtrip evidence.
- `cbac` remains `edit_proven` rather than `donor_backed_ready` because the current CBAC sample evidence is path-backed but not decode-verified in the atlas gate.

## What This Proves

- `cbac` and `zfw` are parser-recognized under the WAN/security edge family.
- Explicit router IOS commands roundtrip through Packet Tracer XML config text.
- Parity reports mark CBAC/ZFW as `edit_supported=true`, `generate_supported=false`, and `generate_mismatch_reason=supported_in_edit_only` for explicit commands.
- The feature atlas can classify ZFW as `donor_backed_ready` and CBAC as `edit_proven` when the proof gate is evaluated.

## What This Does Not Prove

- This does not make CBAC, ZFW, ASA ACL/NAT, ASA service policy, or clientless VPN `generate_ready`.
- This does not mutate ASA GUI/internal security appliance state.
- This does not synthesize zones, trust boundaries, NAT, VPN peers, or firewall policy from a broad prompt.
- ASA service-policy and clientless VPN remain report-only until exact donor-backed XML surfaces are proven.

## Safe Next Step

The next promotion should prefer router IOS CBAC/ZFW donor-backed fixtures before touching ASA internals. ASA ACL/NAT, service policy, and clientless VPN should stay report-only until a decode-backed sample and deterministic roundtrip mutation exist.
