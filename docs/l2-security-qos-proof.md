# L2 Security and QoS Proof

This proof records the `0.2.3` candidate L2 security/QoS edit-proven subset. It is intentionally narrow: the skill can append deterministic IOS-style switch configuration lines for explicitly named targets, but it does not synthesize a full NAC or QoS design from a broad prompt.

## Explicit Commands

Supported explicit edit shapes:

```text
set SW1 dot1x interface FastEthernet0/1 mode auto radius 192.168.1.10 key radius123
set SW1 qos class-map VOICE match dscp ef policy-map QOS_POLICY class VOICE priority service-policy output FastEthernet0/1
```

The dot1x command writes:

```text
aaa new-model
dot1x system-auth-control
radius-server host 192.168.1.10 key radius123
interface FastEthernet0/1
 authentication port-control auto
 dot1x pae authenticator
```

The QoS command writes:

```text
mls qos
class-map match-any VOICE
 match dscp ef
policy-map QOS_POLICY
 class VOICE
  priority
interface FastEthernet0/1
 service-policy output QOS_POLICY
```

## Donor-Backed Readiness

- `dot1x` is `donor_backed_ready` because it has parser, catalog, decode-verified sample, and editor roundtrip evidence.
- `qos` remains `edit_proven` rather than `donor_backed_ready` because the current QoS sample evidence is path-backed but not decode-verified in the atlas gate.

## What This Proves

- `dot1x` and `qos` are parser-recognized as `l2_security_monitoring`.
- Explicit dot1x and QoS commands roundtrip through Packet Tracer XML config text.
- Parity reports mark these capabilities as `edit_supported=true`, `generate_supported=false`, and `generate_mismatch_reason=supported_in_edit_only`.
- The feature atlas can classify dot1x as `donor_backed_ready` and QoS as `edit_proven` when the proof gate is evaluated.

## What This Does Not Prove

- This does not make dot1x or QoS `generate_ready`.
- This does not create RADIUS server users, certificates, supplicant profiles, policy discovery, or end-to-end NAC validation.
- This does not generate QoS classes from traffic intent; class-map, policy-map, direction, and interface must be explicit.
- This does not prove every Packet Tracer switch model accepts every IOS line.

## Safe Next Step

The next promotion would require selected-donor proof with a reusable L2 security/monitoring skeleton and acceptance fixtures. Until then, broad prompts such as `dot1x qos policy class-map policy-map` remain report/plan evidence, while explicit commands use the edit-only path.
