# packet-tracer-skill v0.2.3

`0.2.3` is a capability proof and readiness release. It expands the set of Packet Tracer features that the skill can recognize, inventory, edit with explicit deterministic commands, and report through the feature atlas without claiming broad synthetic generation.

## Highlights

- Added voice/collaboration edit proof for IOS `telephony-service`, `ephone-dn`, `ephone`, and `dial-peer voice` command shapes.
- Added automation/controller script-file edit proof for existing Python, JavaScript, and TCP/UDP app files.
- Added L2 security/QoS proof for explicit dot1x and QoS IOS switch commands.
- Added router security-edge proof for explicit CBAC and ZFW IOS command shapes.
- Added BGP + L2 resiliency proof for BGP, STP/RSTP, EtherChannel/LACP/PAgP, VTP, and DTP IOS commands.
- Added IPv4 routing/NAT/IOS-management proof for OSPFv2, EIGRP IPv4, RIPv2, static/default routes, DHCP relay, NAT/PAT, SSH, NTP, and syslog.
- Added local user-supplied Packet Tracer corpus audit with `--local-sample-audit-root`, storing audit output under ignored `output/` paths.
- Hardened donor-backed readiness gates so proof-linked decode, sample, parser, and editor evidence are required before readiness promotion.

## Runtime Truth

Windows-first runtime remains the supported validation posture. This release was validated with an external Twofish bridge override, but it does not claim repo-local self-contained runtime readiness.

Use:

```powershell
npx packet-tracer-skill --doctor
python .\scripts\runtime_doctor.py
```

The doctor output remains the authority for Packet Tracer install state, donor path, bridge resolution, ready operations, blocked operations, and the recommended next fix.

## Feature Atlas Truth

`generate_ready=0` remains intentional. The release improves report, edit, and donor-backed edit readiness coverage, but broad generation stays blocked until a future single-donor acceptance-backed pilot proves deterministic target inventory and acceptance JSON.

Support levels should be read in this order:

- `report_supported`: the feature is recognized and can be explained in reports.
- `edit_proven`: explicit command shapes have editor roundtrip evidence.
- `donor_backed_ready`: a proof-linked donor or selected-donor path can safely carry a narrow explicit workflow.
- `generate_ready`: strict scenario generation is acceptance-backed. This remains closed in `0.2.3`.

## Safety Boundaries

- No raw `.pkt` or `.pka` labs are added to the repo or npm tarball.
- Local `pkt_examples` evidence and remote GitHub sample imports remain evidence-only workflows.
- Unknown-license remote samples stay `reference_only`.
- ASA GUI/internal mutation, WLC/controller synthesis, broad physical/media workflows, and broad topology generation remain blocked.

## Verification

Release verification includes:

```powershell
python .\scripts\build_examples_index.py
python -m pytest tests -q
node --check .\bin\packet-tracer-skill.js
python .\scripts\generate_pkt.py --feature-gap-report
python .\scripts\generate_pkt.py --parity-report "campus with VLAN DHCP ACL"
python .\scripts\generate_pkt.py --parity-report "ospf eigrp rip static default route dhcp relay nat pat ssh ntp syslog"
npm pack --dry-run --json
```
