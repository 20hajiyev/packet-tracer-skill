# Voice Collaboration Proof

This proof covers a narrow Packet Tracer voice/collaboration wave. It is explicit-edit proof, not broad VoIP topology generation.

## What This Proves

- The Cisco `voip_local_all_phone_devices.pkt` sample exposes IP Phone, Home VoIP, Analog Phone, and router telephony evidence.
- Inventory can report voice devices and IOS telephony config without mutating phone GUI internals.
- Explicit IOS voice commands can roundtrip through Packet Tracer XML:
  - `telephony-service`
  - `ephone-dn`
  - `ephone`
  - `dial-peer voice`
- `voip`, `ip_phone`, and `call_manager` can be treated as `edit_proven` for explicit IOS voice edits.
- `voip`, `ip_phone`, and `call_manager` are `donor_backed_ready` for explicit IOS voice edits because the proof gate has sample, decode, parser, and editor roundtrip evidence.

## What This Does Not Prove

- It does not claim full Call Manager or VoIP topology generation.
- It does not mutate IP Phone GUI internals.
- It does not claim Linksys voice mutation.
- It does not make any voice/collaboration feature `generate_ready`.

## Explicit Edit Command Shape

```text
set "Router0" telephony service source-address 192.168.10.1 port 2000 max-ephones 4 max-dn 4
set "Router0" ephone-dn 1 number 1001
set "Router0" ephone 1 mac 0001.42AA.BBCC button 1:1
set "Router0" dial-peer voice 10 destination-pattern 2... session-target ipv4:10.0.0.2
```

## Public Contract

- `voip`, `ip_phone`, and `call_manager` can report `edit_supported=true` and `donor_backed_ready=true` only for explicit IOS voice edit commands.
- `generate_supported=false` remains the expected result.
- `generate_mismatch_reason=supported_in_edit_only` is the intended parity wording.
- `linksys_voice` remains report-only until separate decode and editor proof exists.
