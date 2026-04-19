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
