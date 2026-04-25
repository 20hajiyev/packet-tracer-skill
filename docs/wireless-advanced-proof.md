# Advanced Wireless Proof

This proof records the current Packet Tracer 9.0 advanced wireless boundary.
It is intentionally narrower than a generic WLC or enterprise Wi-Fi generation
claim.

## Current Proof

The feature atlas recognizes advanced wireless sample families and prompt
signals for:

- `wlc`
- `wpa_enterprise`
- `wep`
- `guest_wifi`
- `beamforming`
- `meraki`
- `cellular_5g`
- `bluetooth`

The edit-proven subset is limited to explicit wireless SSID/security mutation
where the target device and SSID are deterministic:

```powershell
python .\scripts\generate_pkt.py --parity-report "set AP1 ssid LEGACY security wep passphrase abc12345 channel 6"
python .\scripts\generate_pkt.py --parity-report "set WLC1 ssid CORP security wpa-enterprise radius 192.168.1.10 secret radius123 channel 11"
```

Expected product interpretation:

- `wep` can report `edit_supported=true`.
- `wpa_enterprise` can report `edit_supported=true`.
- Both remain `generate_supported=false`.
- The deterministic mismatch reason is `supported_in_edit_only`.

## What This Proves

- The parser can classify advanced wireless prompts without drifting into
  `service_heavy`.
- WEP and WPA Enterprise/RADIUS can be represented as explicit edit intent.
- The atlas can promote a narrow advanced-wireless subset to `edit_proven`.
- WLC, Meraki, cellular, Bluetooth, beamforming, and guest Wi-Fi stay visible
  as report-level Packet Tracer features.

## What This Does Not Prove

- It does not prove broad WLC/controller configuration generation.
- It does not prove cellular, Bluetooth, Meraki, beamforming, or guest Wi-Fi edit
  mutations.
- It does not prove full WPA Enterprise AAA/RADIUS topology construction.
- It does not make any advanced wireless feature `generate_ready`.

## Next Safe Actions

- Add donor-backed inventory proof for WLC and Meraki samples before any edit
  promotion.
- Keep cellular and Bluetooth in report mode until target resolution and device
  runtime behavior are deterministic.
- Promote only one feature at a time from report-only to edit-proven, then to
  donor-backed readiness after acceptance evidence exists.
