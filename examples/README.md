## Known Working Scenario Set

This repo keeps text-based example artifacts under `examples/` and treats them as a known working scenario set, not just a screenshot folder.

For the `0.2.1` public preview surface, the canonical public set is:

- `complex_campus_master_edit_v4`
- `home_iot_cli_edit_v1`
- `service_heavy_cli_edit_v1`

Hero visual:

- `screenshots/complex_campus_master_edit_v4.png`

Policy:
- generated `.pkt` and `.xml` files stay gitignored
- public examples should be sanitized JSON or markdown summaries
- if you want to publish a lab sample, prefer `--inventory --inventory-out` and commit the resulting JSON
- real Packet Tracer screenshots can be committed under `examples/screenshots/`
- examples may have one primary screenshot plus additional detail screenshots

Example command:

```powershell
python .\scripts\generate_pkt.py --inventory .\output\complex_campus_master_edit_v4.pkt --inventory-capabilities --inventory-out .\examples\complex_campus_master_edit_v4.inventory.json
```

Current curated example:
- `complex_campus_master_edit_v4.inventory.json`
  Donor-backed complex campus edit showing management VLAN, Telnet, ACL, server services, and wireless updates without publishing the binary `.pkt` itself.
- `screenshots/complex_campus_master_edit_v4.png`
  Visual snapshot of the same lab opened inside Cisco Packet Tracer.

Additional curated examples:
- `home_iot_cli_edit_v1.inventory.json`
  Home gateway and IoT registration example focused on gateway-backed device onboarding.
- `screenshots/home_iot_cli_edit_v1.png`
  Topology snapshot for the Home IoT example.
- `service_heavy_cli_edit_v1.inventory.json`
  Service-heavy server example focused on DNS, DHCP, FTP, email, syslog, AAA, and related service metadata.
- `screenshots/service_heavy_cli_edit_v1.png`
  Topology snapshot for the Service Heavy example.
- `screenshots/service_heavy_cli_edit_v1_*.png`
  Additional service detail screenshots for DHCP, DNS, and FTP views.
- `index.json`
  Lightweight gallery index for curated example artifacts.

Rebuild the gallery index:

```powershell
python .\scripts\build_examples_index.py
```

Generated outputs:
- `index.json`
  Machine-readable curated example index.
- `gallery.md`
  Human-readable markdown gallery generated from the same source, positioned as the known working scenario set.
- `previews/*.svg`
  Generated fallback preview images for examples that do not yet have real Packet Tracer screenshots.

Gallery families:
- `campus`
  VLAN, management, ACL, server services, and wireless edits.
- `home_iot`
  Home gateway, IoT things, and registration-focused examples.
- `service_heavy`
  Server-centric service labs with richer metadata.

Launch references:
- `..\docs\hero-demo-plan.md`
- `..\docs\release-notes-0.2.1.md`
- `..\docs\campus-donor-proof.md`
