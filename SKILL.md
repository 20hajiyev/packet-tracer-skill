---
name: pkt
description: >
  Create and edit Cisco Packet Tracer 9.0 `.pkt` files from hybrid natural-language
  requests and explicit commands. Use this skill for topology generation, VLAN/router-on-a-stick,
  DHCP, management VLAN, Telnet, wireless/AP-client setup, server services, and existing `.pkt` edits.
---

# Cisco Packet Tracer 9.0 `.pkt` Hybrid Generator/Editor

This skill targets Packet Tracer `9.0.0.0810` and treats a `.pkt` file as a single
binary blob, not a zip container or folder tree.

The current builder/editor is Cisco-sample-centric:

- installed Packet Tracer sample saves are the primary prototype source
- bundled device templates are the secondary fallback for gaps such as missing
  device families in Cisco's own saves
- imported external labs are reference-only by default and are not used as the
  default donor/prototype source

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

## How `.pkt` Files Work

For the modern format targeted by this skill, the pipeline is:

1. Build a Packet Tracer XML document rooted at `<PACKETTRACER5>`
2. qCompress the UTF-8 XML bytes using:
   - 4-byte big-endian uncompressed length
   - raw zlib payload
3. Apply Stage-2 XOR obfuscation
4. Encrypt with Twofish in EAX mode and append the 16-byte authentication tag
5. Apply Stage-1 reverse/XOR obfuscation

The XML includes a `<VERSION>` value. Compatibility is not guaranteed across Packet
Tracer releases, so this skill intentionally targets the 9.0 line.

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
3. Rank Cisco local donor candidates with capability and topology scoring
4. Optionally rank external imported labs as reference patterns only
5. Apply donor-prune mutations on a working Cisco 9.0 donor lab
6. Validate workspace/runtime/scenario compatibility
7. Encode XML into a `.pkt` blob with `scripts/pkt_codec.py`
8. Save generated or edited output locally

## Files

- `scripts/pkt_builder.py`
  Builds Packet Tracer XML from a blueprint
- `scripts/pkt_codec.py`
  Encodes and decodes the modern `.pkt` format
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
- `templates/pt900/base_empty.xml`
  Base Packet Tracer 9.0 skeleton
- `templates/pt900/device_library/*.xml`
  Secondary fallback device XML templates for the first supported device set

The runtime builder currently prefers the installed FTP sample from the local
Packet Tracer `saves/` directory. The exact path is resolved at runtime from
the local Packet Tracer installation or the `PACKET_TRACER_*` environment
variables.

Prompt-driven donor-prune generation also requires `PACKET_TRACER_COMPAT_DONOR`
to point at a working local Packet Tracer 9.0 donor lab with enough device
capacity for the requested topology.

Strict compatibility rules:

- keep `PACKET_TRACER_TARGET_VERSION` on `9.0.0.0810`
- do not downgrade prompt generation to `5.3.0.0011`
- do not use a legacy `5.3` donor/template fallback to bypass strict 9.0 mode
- if the donor is missing, undecodable, or version-mismatched, stop with a
  blocking error instead of switching versions
- every host process must inherit the same `PACKET_TRACER_*` and
  `PKT_TWOFISH_LIBRARY` environment variables; this is not host-specific

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

- This skill currently plans for Packet Tracer 9.0 only
- The builder currently depends on a local Packet Tracer installation with the bundled
  sample saves present
- The bundled template library is intentionally minimal in v1
- Imported external sample roots are reference-only unless you explicitly promote them
- Prompt generation in the default path is donor-prune based, not full synthetic rebuild
- If VLANs are requested for end hosts but host-to-VLAN distribution is not provided,
  the skill returns `blocking_gaps` instead of guessing and generating an unsafe `.pkt`
- Manual validation in Packet Tracer is still required before claiming a topology
  is fully compatible with the Cisco application

## CLI Examples

Generate from a blueprint file:

```powershell
python scripts/generate_pkt.py --blueprint examples/blueprint_minimal.json --output output\minimal.pkt
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

Inspect an existing `.pkt` inventory:

```powershell
python scripts/generate_pkt.py --inventory input\lab.pkt
```

Decode a `.pkt` back to XML for inspection:

```powershell
python scripts/generate_pkt.py --decode output\minimal.pkt --xml-out output\minimal.xml
```

Launch Packet Tracer for a smoke open test:

```powershell
python scripts/generate_pkt.py --validate-open output\minimal.pkt
```
