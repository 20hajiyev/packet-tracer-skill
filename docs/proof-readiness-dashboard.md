# Proof Readiness Dashboard

This dashboard is the `0.2.4` candidate planning surface for moving features from `edit_proven` toward `donor_backed_ready`.

It combines three sources:

- proof cards in `examples/proof-cards.json`
- feature support ceilings in `references/packettracer-feature-atlas.json`
- local sample evidence summarized in `examples/local-sample-evidence.json`

It does not enable broad generation. The current product truth remains `generate_ready=0`.

## Status Contract

- `report_supported`: the feature is recognized and can be reported, but no edit claim is made.
- `edit_proven`: explicit command or script-file roundtrip has evidence.
- `donor_backed_ready`: selected donor or proof-linked explicit edit path is safe for a narrow prompt-scoped workflow.
- `blocked_by_missing_decode_evidence`: sample-path evidence exists, but decode-backed evidence is not sufficient.
- `blocked_by_missing_roundtrip`: inventory or parser truth exists, but editor roundtrip proof is missing.
- `blocked_by_no_deterministic_target`: edit proof exists, but selected donor / device / interface / object resolution is not yet locked.

## Primary Queue

Primary candidates are the highest-value next promotion targets because local evidence is strong and the edit surface is IOS text only:

- `ospfv2`
- `eigrp_ipv4`
- `ripv2`
- `static_route`
- `default_route`
- `dhcp_relay`
- `ssh_ios`
- `ntp_ios`
- `syslog_ios`

These remain `edit_proven` until selected-donor evidence and deterministic target resolution are proof-linked. Broad routing, NAT, and management design generation stays blocked.

## Secondary Queue

Secondary candidates are L2 resiliency and BGP features with strong local sample evidence but more topology-sensitive safety requirements:

- `stp`
- `rstp`
- `etherchannel`
- `lacp`
- `pagp`
- `vtp`
- `dtp`
- `bgp`

These features should not inherit donor readiness from generic sample counts. Promotion requires explicit command shape, decode-backed sample evidence, editor roundtrip, deterministic target resolution, and clean refusal on ambiguous targets.

## Promotion Rule

A candidate can be promoted only when all of these are true:

- an explicit command shape exists
- parser and parity recognize the capability without family drift
- sample evidence exists
- decode evidence exists
- editor roundtrip test exists
- device/interface/object targets are deterministic
- ambiguity produces a clean refusal

If any item is missing, the feature stays `edit_proven` or `report_supported`.

## Next Safe Action

Use `references/proof-readiness-candidates.json` as the implementation queue. Do not add new random capability names until the primary queue either promotes or records a concrete blocker.
