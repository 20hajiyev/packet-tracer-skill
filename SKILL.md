---
name: pkt
description: >
  Create and edit Cisco Packet Tracer 9.0 `.pkt` files from hybrid natural-language
  requests and explicit commands. Use this skill for topology generation, VLAN/router-on-a-stick,
  DHCP, management VLAN, Telnet, wireless/AP-client setup, server services, and existing `.pkt` edits.
---

# Cisco Packet Tracer 9.0 `.pkt` Hybrid Generator/Editor

This skill targets whichever Packet Tracer release is installed (detected at runtime,
9.0 by default) and treats a `.pkt` file as a single binary blob, not a zip
container or folder tree.

The current builder/editor is Cisco-sample-centric:

- installed Packet Tracer sample saves are the primary prototype source
- bundled device templates are the secondary fallback for gaps such as missing
  device families in Cisco's own saves
- imported external labs are reference-only by default
- curated external donor roots can become donor-eligible after validation, but
  Cisco local donors still rank first

That is intentional: it avoids the invalid synthetic XML approach that Packet
Tracer rejects while still keeping the skill usable when Cisco's own sample set
does not cover a device family directly.

The prompt-first architecture now follows a planner/validator/autofix split:

1. intent extraction
2. topology/config planning
3. donor ranking
4. donor-prune mutation
5. compatibility validation

Useful ideas from `MCP-Packet-Tracer` were adopted only at the architecture
level. PTBuilder live deploy and external donor usage were intentionally not
adopted.

## Using This Skill Correctly

Read this before generating anything. Every rule below was learned by measuring
a lab that looked finished and was not.

### A lab that opens is not a lab that works

This is the single most expensive mistake available here. Generated labs have
passed every structural check, opened cleanly in Packet Tracer, read correctly
line by line, and been unable to pass a single packet. "It opened" tells you
the container is valid. It tells you nothing about the network.

Two things separate a finished lab from a plausible one:

```bash
python scripts/generate_pkt.py --coherence-report output/lab.pkt
```

and a live ping. Do both. `--coherence-report` exits non-zero when the lab
contradicts itself, and generation prints the same summary as a `WARNING:` line
when it hands the file over — never ignore that line.

### What the coherence report is telling you

Every defect this project has paid for has one shape: **a fact derived twice,
in two passes, with nothing comparing the derivations.** Each half reads
correctly on its own. The report is that comparison:

| Finding | What it means |
|---|---|
| `interface_declared_twice` | IOS keeps the last block; readers scan the first |
| `port_not_on_device` | Packet Tracer refuses to open the file |
| `port_double_booked` | two cables on one socket |
| `duplicate_address` | two interfaces claim one address |
| `real_address_is_also_virtual` | a router holds an address that is someone's HSRP virtual |
| `native_vlan_mismatch` | spanning tree blocks a cabled, configured port |
| `etherchannel_peer_does_not_bundle` | the switch behind it drops off the network |
| `gateway_answers_for_nobody` | a static host points at an address nothing holds |
| `pool_without_interface` | DHCP hands out addresses nothing can route |

The report never repairs. A checker that fixes what it finds stops being able
to tell you whether the thing it checks is working.

### Measuring in a live Packet Tracer

Three steps, in order, every time:

1. **Confirm which document is open.** With two windows open the bridge answers
   for the other one. A pass rate measured against the wrong lab is worse than
   no measurement, because it is believed. Check the device list first.
2. **Throw the first reading away.** Spanning tree has not converged; the first
   ping after opening a large lab reports 0/4 on a path that works. It is not a
   measurement, it is the lab starting up.
3. **Then measure.** A *failing* ping takes far longer than a passing one --
   each packet waits out its own timeout, about 13 seconds for four -- so
   budget 45-60s per call rather than reading a timeout as a failure.

Ping from a host. Routers and switches answer through a different bridge path
that is not reliable here.

### When two repairs in a row do not change the measurement

Stop repairing. The symptom is not where the defect is. Find the pass that
wrote the state, and fix it there. The fastest way in: **diff the broken device
against a working sibling.** One switch unreachable while identical ones work
has one extra line, and reading configuration top to bottom will not find it as
quickly as `diff` will.

### Facts about Packet Tracer that cost a lab each

- a copper cable in a fibre socket is **dropped in silence** -- the file opens,
  the cable is simply not there
- a duplicate `interface` block is applied last-wins, while readers scan the first
- a subinterface `ip address` before its `encapsulation dot1Q` is refused
  silently
- `PORT_DHCP_ENABLE=true` makes Packet Tracer ignore the static address in the
  file; a host with both is a DHCP client, and judging it on its stale address
  is a false reading
- DHCP snooping with no trusted uplink eats every offer the router sends
- port security on a trunk isolates the whole switch behind it
- a `channel-group` whose peer does not bundle takes that switch off the network
- an interface name the device does not own blocks the file from opening at all;
  a double-booked port does not
- a `vlan N` line in a switch's configuration does **not** create the VLAN --
  Packet Tracer keeps the database separately, and a port assigned to a VLAN
  that is not in it forwards nothing
- a top-level command written straight after an indented sub-block line is
  swallowed; the `!` between them is load-bearing
- a home router's sockets are named, not slotted, and the spelling is the
  model's: `Ethernet 1` .. `4` on `WirelessRouter`, `GigabitEthernet 1` .. `4`
  on `WirelessRouterNewGeneration`, and `Internet` for the uplink on both. It
  writes no interfaces into its configuration, so nothing else can tell you
- a home router's LAN address is a **setting**, not a config line, and lives in
  `ENGINE/LAN_IP_ADDRESS` with its pool under `ENGINE/DHCP_SERVER/POOLS/POOL`;
  a reader that only walks running configs cannot see it
- a wireless client's addressing comes from its `WIRELESS_PROFILE`, not from
  its port -- both record it, and Packet Tracer obeys the profile
- a radio link is made by **distance**. A client outside the access point's
  `COVERAGERANGE` reports its port `up` and `linked` and passes nothing
- the builder MCP's device table is not authoritative about port names; it
  gives the AC home router `Ethernet 1` .. `4`, and the device itself says
  `GigabitEthernet 1` .. `4`. `pt_inspect_ports` answers at the IOS layer,
  where those sockets are bridged into `Vlan1` and do not appear at all --
  `pt_query_topology` is the one that lists them

### Drawing the topology yourself

The generator packs switch blocks into a roughly square grid, which is fine for
a lab nobody planned. When you have already decided the shape -- which
department sits where, which switch faces which, where the core belongs -- say
so in the blueprint and set `PACKET_TRACER_LAYOUT=keep`. Every `x`/`y` in the
blueprint is then left exactly as given, and the frames are drawn around the
devices where they land.

Sketch first, build second, is the better order for anything a person will
look at: you can see the whole diagram before a single cable exists, and the
skill's job narrows to making the file match the drawing.

Without the knob the packing applies, and it is deterministic: the same
blueprint gives the same coordinates every time, so a regenerated lab does not
drift.

### Scale

There is no artificial device limit. The only ceiling is physical: a switch has
the ports it has, and the generator says so plainly when it runs out. Ask for
more switches, not fewer hosts.

### A generated lab becomes the next build's donor

Donor selection can pick a lab this skill produced, so every repair pass
eventually runs over its own output. Write interface configuration with
`_set_config_block`, never by appending, and check a new pass by running it
three times and asserting the document stops changing after the first.

### The palette is not the vocabulary

Packet Tracer's device palette lists more kinds than a saved lab distinguishes:
`SMARTPHONE-PT` saves as `Pda`, `Fiber Patch Panel` saves as `Patch Panel`.
Adding an askable kind with no donor behind it produces a request that can only
come back as an undelivered device. `tests/test_askable_kinds_have_donors.py`
holds the vocabulary to what real labs actually contain, in both directions.

### When generation refuses

A refusal returns `blocking_gaps` together with a `blueprint_plan`. That is not
a failure to work around by loosening a policy -- it is the skill saying no
donor can serve the request. Read the gaps, adjust the request or supply a
donor, and try again.

### What works without Packet Tracer installed

Decode, inventory, edit, generate and structural verification all work from the
donor cache with no install and no environment variables -- the Twofish engine
is vendored pure Python. Only `--validate-open` and live pings need the
application itself. Tests that build a lab are marked `requires_donors` and skip
where there is nothing to build from.

## How `.pkt` Files Work

For the modern format targeted by this skill, the pipeline is:

1. Build a Packet Tracer XML document rooted at `<PACKETTRACER5>`
2. qCompress the UTF-8 XML bytes using:
   - 4-byte big-endian uncompressed length
   - raw zlib payload
3. Apply Stage-2 XOR obfuscation
4. Encrypt with Twofish in EAX mode and append the 16-byte authentication tag
5. Apply Stage-1 reverse/XOR obfuscation

The XML includes a `<VERSION>` value such as `9.0.0.0810`. This skill targets the
9.0 line.

Packet Tracer 5.x and 6.x wrote a simpler container: qCompress output XORed
byte-wise with `(length - index)`, with no cipher and no tag. 18 of the 292
bundled samples are still in that format. `decode_pkt_auto` reads both and
reports which one matched.

Packet Tracer also writes raw control bytes into element text — a Cisco banner
delimiter is literally `banner motd `, which XML 1.0 forbids. Use
`parse_pkt_xml` / `serialize_pkt_xml` rather than `ET.fromstring` / `ET.tostring`
so those bytes survive a round trip.

The Twofish step needs no compiled binary. `scripts/vendor/twofish_pure.py` is a
vendored pure-Python implementation verified against the official Twofish test
vectors, so decode/edit/generate work on a clean checkout with no environment
variables. A compiled `_twofish` bridge is optional: when `PKT_TWOFISH_LIBRARY`
or `PKT_TWOFISH_SEARCH_ROOTS` resolves one, it is used automatically as a ~12x
accelerator for large labs.

### Donor Version Compatibility

The build field in a `<VERSION>` string is not a schema identifier — it changes
on every point release and re-save. None of the 292 sample saves bundled with
Packet Tracer 9.0.0 carry `9.0.0.0810`; 48 are `9.0.0.x` with other builds and
the rest span 5.x through 8.x. Donors are therefore classified into tiers:

| Tier | Meaning |
|---|---|
| `exact` | build strings identical |
| `same_minor` | same `major.minor`, e.g. any `9.0.0.x` |
| `same_major` | same major, different minor |
| `upgradeable` | 6.x–8.x; Packet Tracer upgrades these on open |
| `incompatible` | 5.x and older |

`PACKET_TRACER_DONOR_POLICY` names the loosest acceptable tier. The default is
`same_minor`. When several donors qualify, the strictest tier wins.

The target version is **detected**, not hardcoded. Resolution order:
`PACKET_TRACER_TARGET_VERSION` → the installed Packet Tracer's directory name →
the compatibility donor's own `<VERSION>` → the built-in default. Installing
Packet Tracer 8.2 makes the skill target 8.2 and accept 8.2.x donors; no
configuration is needed to follow a different release.

## Workflow

1. Parse the request into a hybrid intent plan:
   - topology, device models, links, cable types, ports
   - natural Azerbaijani or mixed-language counts such as `3 dene switch ve 6 komputer`
   - department/campus prompts such as `6 sobeli kampus sebekesi`
   - VLAN/trunk/access/router-on-a-stick intent
   - router DHCP or server DHCP/DNS intent
   - management VLAN / Telnet intent
   - AP SSID/security and wireless client association intent
   - existing `.pkt` edit operations when a source file is provided
2. Build an intent-first topology/config plan:
   - topology archetype
   - device list
   - port map
   - VLAN/service/config plan
   - assumptions and blocking gaps
3. Rank Cisco local donor candidates with capability, topology, and donor-graph scoring
4. Optionally search/import remote labs, then rank imported labs as curated donors or reference patterns
5. Apply donor-prune mutations on one working Cisco 9.0 donor lab
6. Validate workspace/runtime/scenario compatibility
7. Encode XML into a `.pkt` blob with `scripts/pkt_codec.py`
8. Save generated or edited output locally

Open-first rules remain strict:

- multi-source search and scoring is allowed
- final `.pkt` apply is still single-donor
- when no safe donor exists, return `blocking_gaps` plus a `blueprint_plan`

## Files

- `scripts/pkt_builder.py`
  Thin entrypoint: selects a sample and delegates to `pkt_transformer`
- `scripts/pkt_codec.py`
  Encodes and decodes the modern `.pkt` format
- `scripts/vendor/twofish_pure.py`
  Vendored pure-Python Twofish; the repo-local baseline engine
- `scripts/pkt_verify.py`
  Two-tier verification: headless structural checks, plus a real Packet Tracer
  open test that watches for the file's window
- `scripts/usage_ledger.py`
  Local, gitignored record of which donors actually worked, fed back into donor
  ranking so the skill improves with use
- `scripts/generate_pkt.py`
  CLI entrypoint for generate/edit/decode/inventory/explain-plan
- `scripts/intent_parser.py`
  Hybrid natural-language and mini-DSL parser
- `scripts/pkt_editor.py`
  Existing `.pkt` inventory and mutation engine
- `scripts/sample_catalog.py`
  Capability-tagged sample index and reference-pattern loader
- `scripts/sample_selector.py`
  Sample ranking by capability, topology, trust level, and prototype eligibility
- `scripts/packet_tracer_env.py`
  Resolves Packet Tracer install, saves root, and executable paths
- `scripts/runtime_doctor.py`
  Unified runtime diagnostics for host OS, donor, Packet Tracer paths, and Twofish readiness
- `templates/pt900/base_empty.xml`
  Base Packet Tracer 9.0 skeleton
- `templates/pt900/device_library/*.xml`
  Secondary fallback device XML templates for the first supported device set

The runtime builder currently prefers the installed FTP sample from the local
Packet Tracer `saves/` directory. The exact path is resolved at runtime from
the local Packet Tracer installation or the `PACKET_TRACER_*` environment
variables.

Prompt-driven donor-prune generation prefers an explicit
`PACKET_TRACER_COMPAT_DONOR`, but it can also auto-detect a working local
Packet Tracer 9.0 donor from common local locations when the environment
override is absent.

Strict compatibility rules:

- the target version is detected from the install; override with `PACKET_TRACER_TARGET_VERSION` only when you need to pin it
- never accept a `5.x` donor; Packet Tracer does not reliably upgrade those
- the donor tier that was accepted is recorded in `compatibility_tier` and
  reported as an assumption, never hidden
- if the donor is missing, undecodable, or below the active policy tier, stop
  with a blocking error that names the tier and the policy needed to accept it
- if `PACKET_TRACER_COMPAT_DONOR` is explicitly set and rejected, do not silently
  fall back to another donor
- `PACKET_TRACER_*` variables must be inherited by every host process;
  `PKT_TWOFISH_*` is optional and only selects the compiled accelerator

## Supported First Iteration

- `Router`, `Switch`, `PC`, `Server`
- `LightWeightAccessPoint` / `WirelessRouter` where sample prototypes exist
- natural prompt planning for device counts, VLAN IDs, `gig` uplinks, `fa` host links,
  department/campus prompts, and default `chain` / `core switch` topologies
- structured `blocking_gaps`, `assumptions_used`, and `confidence_score` reporting
- transparent `explain-plan` output with:
  - `intent_plan`
  - `topology_plan`
  - `config_plan`
  - `estimate_plan`
  - `preflight_validation`
  - `autofix_summary`
  - `cisco_sample_candidates`
  - `curated_external_donor_candidates`
  - `external_reference_patterns`
  - `validation_report`
- explicit port-to-port and cable/media mapping
- VLAN create, access port, trunk port, native VLAN
- router subinterfaces and router-on-a-stick
- named ACL create, permit/deny rule injection, and `ip access-group` interface binding
- router DHCP pool
- server DHCP pool, DNS enablement, and DNS records
- HTTP / HTTPS / FTP / TFTP / NTP service enable state
- end-device DNS client settings
- management VLAN SVI + default gateway
- Telnet enablement on switches/routers via config mutations
- wireless SSID/security/channel mutations
- wireless client association and DHCP/static mode where compatible prototypes exist
- existing `.pkt` inventory and edit flow

## Defaults

If the user does not specify details:

- Packet Tracer version: `9.0.0.0810`
- Subnet: `192.168.1.0/24`
- Default gateway: `192.168.1.1`
- PC addresses: `.10`, `.11`, `.12`, ...
- Layout:
  - router around `(400, 140)`
  - switch around `(400, 280)`
  - PCs along the bottom row

## Constraints

- The builder needs Packet Tracer's bundled sample saves as prototype sources,
  from a local installation on Windows, macOS or Linux **or** from the donor
  cache under `~/.pkt/saves`, which a single generate run on an installed
  machine populates and which can then be copied anywhere
- Donor devices the plan does not need are deleted. `PACKET_TRACER_SPARE_STRATEGY=park`
  restores the older behaviour of renaming them `UNUSED-*` / `*-SPARE-*` and
  moving them offscreen, if a donor turns out to depend on one staying present
- `--validate-open` needs Packet Tracer installed. Everything else — decode,
  inventory, edit, generate, structural verification — does not
- The bundled template library is intentionally minimal in v1
- Imported external sample roots are reference-only unless you explicitly promote them
- Prompt generation in the default path is donor-prune based, not full synthetic rebuild
- Host-to-VLAN distribution is defaulted to an even split when not given, and the
  split is reported as an assumption. `PACKET_TRACER_STRICT_VLAN_ASSIGNMENT=1`
  refuses instead
- Links the donor lacks are built rather than refused. `PACKET_TRACER_LINK_STRATEGY=reuse`
  restricts generation to the donor's own topology
- Manual validation in Packet Tracer is still required before claiming a topology
  is fully compatible with the Cisco application

## CLI Examples

Generate from a blueprint file:

```powershell
python scripts/generate_pkt.py --blueprint examples/blueprint_minimal.json --output output\minimal.pkt
```

Check what a finished lab contradicts about itself, and exit non-zero if it does:

```powershell
python scripts/generate_pkt.py --coherence-report output\campus.pkt
```

Generate from a hybrid prompt:

```powershell
python scripts/generate_pkt.py --prompt "6 şöbəli şəbəkə qur, VLAN 10 20 30 40 50 60 və management VLAN 99 yarat" --output output\campus.pkt
```

Explain the parsed plan before generation:

```powershell
python scripts/generate_pkt.py --explain-plan "set SW1 vlan 10 name Finance; enable telnet on SW1 username admin password 1234"
```

Explain a natural Azerbaijani prompt before generation:

```powershell
python scripts/generate_pkt.py --explain-plan "3 dene switch ve 6 komputer ve 1 router vlanlarda 10,20,30 switchlerin oz aralarinda ve routerle aralarinda gig portuna qosulsun komputerler ise fa portlarla qosulsun"
```

Inspect curated donor candidates from a local imported lab root:

```powershell
python scripts/generate_pkt.py --explain-plan "6 şöbəli şəbəkə qur, hər şöbədə 1 switch 1 AP 1 printer 2 PC 2 tablet olsun" --donor-root C:\labs\curated-pkt-donors --reference-root C:\labs\external-pkt-samples
```

Only external `9.0.0.0810` labs are promoted into the curated donor pool when
their workspace validation passes cleanly, or when they are `legacy_uuid_physical`
donors whose only logical warnings are repeated `MEM_ADDR` mismatch records.

Search GitHub first, then auto-import matching repos into a local cache:

```powershell
python scripts/generate_pkt.py --explain-plan "6 department campus with vlan dhcp dns ap" --search-remote --remote-provider github --import-cache-root output\remote-cache
```

Print the aggregated capability matrix:

```powershell
python scripts/generate_pkt.py --coverage-report
python scripts/generate_pkt.py --coverage-report --device-family "access points"
```

Inspect an existing `.pkt` inventory:

```powershell
python scripts/generate_pkt.py --inventory input\lab.pkt
python scripts/generate_pkt.py --inventory input\lab.pkt --inventory-capabilities
```

Edit an existing `.pkt` directly from a prompt:

```powershell
python scripts/generate_pkt.py --edit input\lab.pkt --prompt "set Wireless Router0 ssid FIN_WIFI security wpa2-psk passphrase fin12345 channel 6 associate PC0 to Wireless Router0 ssid FIN_WIFI dhcp" --output output\edited_lab.pkt --xml-out output\edited_lab.xml
python scripts/generate_pkt.py --edit input\lab.pkt --prompt "enable dns on Server0 set Server0 dns A www.example.local 192.168.10.20 set PC0 dns 192.168.10.20" --output output\edited_services.pkt
```

Decode a `.pkt` back to XML for inspection:

```powershell
python scripts/generate_pkt.py --decode output\minimal.pkt --xml-out output\minimal.xml
```

Verify a generated file. The structural tier is headless; `--open` launches
Packet Tracer and waits until the file's own window appears:

```powershell
python scripts/pkt_verify.py output\minimal.pkt
python scripts/pkt_verify.py output\minimal.pkt --open
python scripts/generate_pkt.py --validate-open output\minimal.pkt
```

A file that fails the structural tier is never handed to Packet Tracer.

Inspect what the skill has learned from previous runs:

```powershell
python scripts/usage_ledger.py
```

Learning is local and on by default. Prompts are stored only as a non-reversible
fingerprint, the ledger lives under gitignored `output/`, and it is never
committed or packaged. Set `PKT_USAGE_LEDGER=off` to disable it, or point it at
another path. Deleting the ledger changes results in no way except donor
ordering.
