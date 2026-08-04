# Donor-independent port naming

## Why

The skill cannot generate a lab unless the user has already saved one from their
own Packet Tracer install. The goal is to remove that requirement: Packet Tracer
ships hundreds of labs under its own `saves/`, and those should be enough.

What blocked it was believed to be the version gate. Measured against a running
9.0.0.0810, one file at a time, that turns out to be false:

| Lab | Result |
| --- | --- |
| 6.2.0.0000, 8.0.0.0000 (original, re-encoded, and relabelled) | opens |
| 9.0.0.0000 / .0112 / .0172 / .4178 / .9999 | opens |
| 9.1.0.0000 | refused |
| 99.9.9.9999 | refused |

The gate is an ordering on `major.minor.patch`; the build field is ignored. Two
controls make this trustworthy: an *untouched* 8.0.0.0000 sample opens, so
re-encoding was never the issue; and a file relabelled to a nonexistent build is
refused with the bridge reporting a timeout, so refusals are visible rather than
silently reported as success.

The real blocker is elsewhere. A lab generated from a bundled donor was refused,
and its `<VERSION>` was already the running build. It named
`R1:FastEthernet0/1` on a router whose real interfaces are
`GigabitEthernet0/0/0` … `0/0/2`. An invalid interface name stops Packet Tracer
opening a file; a double-booked interface does not.

## Root cause

Port names are decided before the hardware is known. The blueprint writes
concrete names such as `SW2:GigabitEthernet0/1`, and the donor — which carries
the actual interfaces — is chosen afterwards. `_router_port` guesses from a
model-name prefix table:

```python
if model.startswith("2901"):  return f"GigabitEthernet0/{index - 1}"
if model.startswith("ISR"):   return f"GigabitEthernet0/0/{index - 1}"
return f"FastEthernet0/{index - 1}"
```

A PT8200 matches neither prefix and falls through to the FastEthernet default.
`SWITCH_GIGABIT_UPLINKS` has the same shape. The catalogue has hundreds of
models, so the table cannot be completed — this is one model of the hardware
disagreeing with another.

## Interface source

A donor `PORT` element carries no name; names are positional and model-dependent.
The authoritative list is the device's own `RUNNINGCONFIG`, whose `interface X`
lines name every real interface. Subinterfaces (`.`) and `Vlan` interfaces are
excluded — they are configuration, not hardware. Hosts carry no config and keep
the existing `port_exists` rules.

## Design

Two parts, in this order.

### Part C — no invalid name reaches the file

`free_port` in `_resolve_port_conflicts` already relocates a port when another
cable claims it, validating alternatives with `port_exists`. It returns early
when the port is unclaimed, without checking that the port exists at all. That
early return is the hole every refusal came through.

The check becomes: relocate when the port is claimed **or** does not exist.
Nothing else changes, so the repair reuses machinery already covered by tests.

This is a guarantee rather than an improvement: with it, the one known cause of
a refused file cannot occur, whatever donor is used.

### Part A — name ports from the donor

`_router_port` and `_switch_uplink_port` take the donor device element and read
its interfaces, choosing by role: the fastest available interface for an uplink,
copper access ports for hosts. The prefix tables are deleted.

Donor fitness follows from the same list: a donor whose router has three
interfaces cannot serve a prompt needing six, and selection moves to the next
candidate. The interface list is cached per donor in the existing on-disk donor
index, so the cost is paid once rather than per generation.

## Error handling

- A donor that cannot supply the requested interfaces is skipped, and the next
  candidate is tried. This is the user's stated preference over substituting a
  model or wiring fewer cables.
- If no donor fits, generation refuses and names what was missing, rather than
  writing a lab that will not open.
- If a port cannot be repaired because the device has no free real interface,
  the existing reconciliation report records it; the file is still written,
  since a double-booked port opens and a missing one does not.

## Testing

- Unit: interface extraction from a `RUNNINGCONFIG`, including exclusion of
  subinterfaces and `Vlan` interfaces, and a device with no config.
- Unit: `free_port` relocates a port that is unclaimed but nonexistent.
- Regression: the 22-switch scale case keeps zero interfaces carrying two
  cables.
- Live: a lab generated from a bundled Cisco sample, with no downloaded donor,
  opens in Packet Tracer and its hosts ping each other. This is the acceptance
  criterion; `structural_check` and `pt_health_check` both pass on labs where
  nothing can ping, so neither is sufficient.

## Not in scope

- Loosening `DEFAULT_DONOR_POLICY`. That flips only after the live criterion
  above passes.
- The 62 planned links arriving as 43 in the file at scale — a separate defect
  that predates this work.
