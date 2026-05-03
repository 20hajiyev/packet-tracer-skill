# L2 Resiliency + BGP Proof Wave

This proof wave uses the local user-supplied `pkt_examples` corpus as evidence input only. Raw `.pkt` files, imported caches, and `output/pkt_examples_audit.json` are not package or repository artifacts.

## What Is Covered

The wave adds parser, inventory, catalog, atlas, and parity truth for:

- `bgp`
- `stp`
- `rstp`
- `etherchannel`
- `lacp`
- `pagp`
- `vtp`
- `dtp`

These capabilities are constrained to IOS text configuration surfaces. They are not broad topology generation features.

## Explicit Edit Commands

Supported edit-proof command shapes:

```powershell
python scripts/generate_pkt.py --parity-report "set R1 bgp 65001 neighbor 10.0.0.2 remote-as 65002 network 192.168.1.0 mask 255.255.255.0"
python scripts/generate_pkt.py --parity-report "set SW1 stp mode rapid-pvst vlan 10 root primary"
python scripts/generate_pkt.py --parity-report "set SW1 etherchannel 1 mode active interfaces FastEthernet0/1 FastEthernet0/2"
python scripts/generate_pkt.py --parity-report "set SW1 etherchannel 2 mode desirable interfaces FastEthernet0/3 FastEthernet0/4"
python scripts/generate_pkt.py --parity-report "set SW1 vtp domain CAMPUS mode server version 2"
python scripts/generate_pkt.py --parity-report "set SW1 dtp interface FastEthernet0/1 mode dynamic desirable"
```

## Target Rules

- The target device name must be explicit.
- Interface names must be explicit where an interface command is used.
- Only existing device configuration text is mutated.
- No GUI/internal Packet Tracer state is guessed.
- No links, modules, devices, or topology shape are synthesized in this wave.

## What This Proves

- BGP neighbor/network IOS text can be parsed and written deterministically.
- The editor writes a `router bgp` block with explicit `neighbor ... remote-as` and optional `network ... mask` lines.
- STP/RSTP can be detected separately from SPAN/RSPAN through explicit `spanning-tree` lines.
- EtherChannel can be represented through explicit `channel-group` and `Port-channel` text.
- LACP/PAgP are derived from explicit EtherChannel modes.
- VTP and DTP line shapes can be parsed, inventoried, and roundtripped as IOS text.

## What This Does Not Prove

- It does not prove full BGP peering convergence.
- It does not prove STP state simulation correctness.
- It does not create or validate physical redundant links.
- It does not make these capabilities `donor_backed_ready`.
- It does not make any of these capabilities `generate_ready`.

## Current Product Status

The atlas status for this wave is `edit_proven` when roundtrip tests exist. `generate_ready=0` remains intentional until a single-donor acceptance fixture proves a strict safe-open generate path.
