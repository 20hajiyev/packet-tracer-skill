## Example Artifacts

This repo keeps text-based example artifacts under `examples/`.

Policy:
- generated `.pkt` and `.xml` files stay gitignored
- public examples should be sanitized JSON or markdown summaries
- if you want to publish a lab sample, prefer `--inventory --inventory-out` and commit the resulting JSON

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
- `service_heavy_cli_edit_v1.inventory.json`
  Service-heavy server example focused on DNS, DHCP, FTP, email, syslog, AAA, and related service metadata.
- `index.json`
  Lightweight gallery index for curated example artifacts.
