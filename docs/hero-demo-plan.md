# Hero Demo Plan

## Goal

Prepare one conservative hero demo flow for the `0.2.0` public preview surface without implying self-contained runtime readiness.

## Prompt

Use this prompt:

```text
6 department campus with router-on-a-stick, VLAN, DHCP, management VLAN, Telnet, ACL
```

## CLI Flow

Run in this order:

```powershell
python .\scripts\generate_pkt.py --explain-plan "6 department campus with router-on-a-stick, VLAN, DHCP, management VLAN, Telnet, ACL"
python .\scripts\generate_pkt.py --parity-report "6 department campus with router-on-a-stick, VLAN, DHCP, management VLAN, Telnet, ACL"
python .\scripts\runtime_doctor.py
```

## Visual

- pinned image: `examples/screenshots/complex_campus_master_edit_v4.png`
- reuse the complex campus topology screenshot as the hero visual until a dedicated GIF is produced

## Claims To Make

- donor-backed
- open-first
- scenario-aware
- Windows-first runtime
- validated with external bridge override

## Claims Not To Make

- do not say the repo is self-contained runtime-ready
- do not claim full synthetic generate for WAN/security coverage
- do not imply unsupported or acceptance-gated mutations are generated anyway
