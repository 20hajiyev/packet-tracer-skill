## Examples Truth 2.0

The `examples/` directory is the public proof surface for the published `0.2.3` capability release and the next `0.2.4` candidate hardening batch. It is not a raw Packet Tracer lab dump and it is not a claim that broad `.pkt` generation is solved.

Global truth:

- atlas `generate_ready=0` remains intentional
- raw `.pkt` and `.pka` files stay out of git and npm
- local `pkt_examples` audits are evidence inputs only
- examples are either `showcase_example` artifacts or text-only `proof_card` artifacts

## Artifact Types

`showcase_example` means:

- there is a screenshot and committed inventory manifest
- the source workflow is donor-backed or acceptance-backed as an example artifact
- the binary `.pkt` is not committed
- the example can be used in README/npm/GitHub proof surfaces

`proof_card` means:

- there is no raw `.pkt` and no screenshot requirement
- the card points to a proof doc
- it records the explicit command shape, scenario family, support level, parity excerpt, and refusal boundary
- it proves a narrow edit/readiness path, not broad topology generation

## Current Showcase Examples

- `complex_campus_master_edit_v4`
  Donor-backed complex campus edit showing management VLAN, Telnet, ACL, server services, and wireless updates without publishing the binary `.pkt`.
  Screenshot: `screenshots/complex_campus_master_edit_v4.png`.
- `home_iot_cli_edit_v1`
  Home gateway and IoT registration example focused on donor-backed, constrained gateway device onboarding.
  Screenshot: `screenshots/home_iot_cli_edit_v1.png`.
- `service_heavy_cli_edit_v1`
  Service-heavy server example focused on DNS, DHCP, FTP, email, syslog, AAA, and related service metadata.
  Screenshot: `screenshots/service_heavy_cli_edit_v1.png`.

## Current Proof Cards

The proof cards make the `0.2.3` capability waves discoverable from the examples gallery and feed the `0.2.4` proof-readiness dashboard:

- IPv4 routing / NAT / IOS management
- L2 resiliency + BGP
- L2 security + QoS
- security-edge CBAC/ZFW
- voice/collaboration
- automation/controller
- industrial programming

The source file is `proof-cards.json`. It is text-only and diff-friendly.

## Proof-Readiness Queue

The `0.2.4` candidate adds a promotion queue for deciding which edit-proven features can safely move toward `donor_backed_ready`.

- source artifact: `..\references\proof-readiness-candidates.json`
- dashboard: `..\docs\proof-readiness-dashboard.md`
- current primary queue: IPv4 routing, NAT, DHCP relay, SSH, NTP, and syslog IOS management
- current secondary queue: STP/RSTP, EtherChannel/LACP/PAgP, VTP/DTP, and BGP

The queue is intentionally conservative. Local sample counts are not enough by themselves; each promotion still needs explicit command shape, decode evidence, editor roundtrip, deterministic target resolution, and clean refusal behavior.

## Local Sample Evidence

The local audit command can summarize user-supplied Packet Tracer labs:

```powershell
python .\scripts\generate_pkt.py --local-sample-audit-root "C:\path\to\pkt_examples"
```

The default output is `output/local-sample-audit.json`. That file is ignored by git and npm packaging. It can show evidence such as STP, static routes, RIPv2, OSPFv2, DHCP, ACL, SSH, NAT, HSRP, EtherChannel, and BGP counts, but it does not promote those local files into curated public donors.

## Rebuild

Rebuild the generated index and gallery:

```powershell
python .\scripts\build_examples_index.py
```

Generated outputs:

- `index.json`: machine-readable combined showcase/proof-card index
- `gallery.md`: human-readable examples and evidence gallery
- `previews/*.svg`: generated fallback preview images for showcase examples without screenshots

Launch references:

- `..\docs\hero-demo-plan.md`
- `..\docs\release-notes-0.2.3.md`
- `..\docs\release-notes-0.2.4.md`
- `..\docs\proof-readiness-dashboard.md`
- `..\docs\campus-donor-proof.md`
- `..\docs\home-iot-donor-proof.md`
- `..\docs\wan-security-donor-proof.md`
- `..\docs\ipv4-routing-management-proof.md`
- `..\docs\l2-resiliency-bgp-proof.md`
- `..\docs\l2-security-qos-proof.md`
- `..\docs\security-edge-deepening-proof.md`
- `..\docs\voice-collaboration-proof.md`
- `..\docs\automation-controller-proof.md`
- `..\docs\industrial-programming-proof.md`
