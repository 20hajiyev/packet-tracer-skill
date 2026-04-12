# pkt skill

Cisco Packet Tracer 9.0 `.pkt` generator and editor for Codex, Cursor, Claude Code,
Antigravity, and other skill-based hosts.

This repository is built for one specific goal: take a natural-language network
request, plan it explicitly, adapt a compatible local Cisco Packet Tracer donor
lab, and produce a Packet Tracer file that opens cleanly in Packet Tracer 9.x.

It is intentionally **Cisco-sample-centric**:

- Cisco Packet Tracer local sample saves are the primary donor source
- bundled templates are only secondary fallback helpers
- imported external labs are **reference-only**

It is also intentionally **intent-first**:

- prompt parsing happens before generation
- topology/config planning is explicit
- validation and autofix happen before write
- unsafe generation is blocked instead of guessed

## Host Support

Use the same repository, but install or invoke it in the way your host expects.

| Tool | Install | First Use |
| --- | --- | --- |
| Claude Code | `npx antigravity-awesome-skills --claude` or Claude plugin marketplace | `Use /pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Cursor | `npx antigravity-awesome-skills --cursor` | `@pkt build a Packet Tracer lab with VLAN and DHCP` |
| Gemini CLI | `npx antigravity-awesome-skills --gemini` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Codex CLI | `npx antigravity-awesome-skills --codex` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Antigravity | `npx antigravity-awesome-skills --antigravity` | `Use @pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Kiro CLI | `npx antigravity-awesome-skills --kiro` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Kiro IDE | `npx antigravity-awesome-skills --path ~/.kiro/skills` | `Use @pkt to build a Packet Tracer lab with VLAN and DHCP` |
| GitHub Copilot | No installer, paste skills or rules manually | `Ask Copilot to use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| OpenCode | `npx antigravity-awesome-skills --path .agents/skills --category development,backend --risk safe,none` | `opencode run @pkt build a Packet Tracer lab with VLAN and DHCP` |
| AdaL CLI | `npx antigravity-awesome-skills --path .adal/skills` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Custom path | `npx antigravity-awesome-skills --path ./my-skills` | Depends on your tool |

For path details, prompt examples, and setup caveats by host, go to:

- [ComposioHQ/awesome-claude-skills](https://github.com/ComposioHQ/awesome-claude-skills)
- [sickn33/antigravity-awesome-skills](https://github.com/sickn33/antigravity-awesome-skills)

## What This Repo Does

- Parses hybrid Azerbaijani + English prompts
- Builds explicit `IntentPlan`, `TopologyPlan`, and `ConfigPlan`
- Ranks Cisco local donors by capability and topology fit
- Uses donor-prune adaptation for Packet Tracer 9.0 compatibility
- Edits existing `.pkt` labs
- Supports VLAN, router-on-a-stick, DHCP, DNS, Telnet, ACL, wireless/AP-client, and department/campus layouts
- Explains its own plan before generation with `--explain-plan`

## Design Principles

### 1. Cisco local donors are primary

This repo does **not** try to synthesize Packet Tracer runtime state from scratch
for the main generation path. Instead, it adapts a working local Packet Tracer
9.0 donor lab.

That choice is deliberate. Packet Tracer compatibility failures are usually not
caused by high-level configs; they come from deeper runtime, workspace, physical,
scenario, and reference structures. Donor-preserving adaptation is the more
reliable path.

### 2. External labs are reference-only

Imported external `.pkt` collections can help with:

- topology motifs
- naming ideas
- config ideas
- capability hints

They do **not** become prototype donors by default.

### 3. Planning is explicit

Prompt generation follows this pipeline:

1. `Intent Extraction`
2. `TopologyPlan` and `ConfigPlan`
3. Cisco donor ranking
4. donor-prune mutation plan
5. validation and autofix
6. `.pkt` encoding

### 4. Unsafe prompts are blocked

If a prompt is incomplete or ambiguous, the tool should return structured
`blocking_gaps` instead of inventing risky topology/config decisions.

## Requirements

- Windows
- Cisco Packet Tracer 9.x installed locally
- local Cisco Packet Tracer sample saves available
- a local Packet Tracer 9.0 donor lab for prompt-driven donor-prune generation
- Python environment compatible with your local Twofish bridge

## Runtime Configuration

This repository does not ship Cisco sample `.pkt` files. It resolves them from
the local Packet Tracer installation.

### Environment variables

- `PACKET_TRACER_ROOT`
- `PACKET_TRACER_SAVES_ROOT`
- `PACKET_TRACER_EXE`
- `PACKET_TRACER_COMPAT_DONOR`
- `PACKET_TRACER_TARGET_VERSION`
- `PKT_TWOFISH_LIBRARY`

### Minimum recommended setup

```powershell
$env:PACKET_TRACER_ROOT='C:\Program Files\Cisco Packet Tracer 9.0.0'
$env:PACKET_TRACER_COMPAT_DONOR='C:\labs\campus_donor_9_0.pkt'
$env:PKT_TWOFISH_LIBRARY='C:\tools\pkt-twofish\_twofish.cp314-win_amd64.pyd'
```

### Sample-source policy

- `primary`: local Cisco Packet Tracer sample saves
- `secondary`: bundled device templates
- `reference-only`: imported external `.pkt` roots

### Generation policy

- prompt-driven generation runs in `donor_prune_strict_9_0`
- donor capacity must be large enough for the requested topology
- if donor capacity is not enough, generation stops with `blocking_gaps`

## Twofish Bridge

This public repo does **not** ship a prebuilt Twofish bridge by default.

That is intentional:

- no machine-specific binary is committed by default
- no unsigned local artifact is published by accident
- no private path/build residue is shared by default

Read [scripts/vendor/README.md](C:\Users\Sanan\Documents\New%20project\pkt-skill-github\scripts\vendor\README.md) for local setup.

## Repository Layout

- `scripts/generate_pkt.py`
  - CLI entrypoint
- `scripts/intent_parser.py`
  - natural-language + mini-DSL parsing
- `scripts/pkt_editor.py`
  - donor-preserving edit and mutation operations
- `scripts/pkt_transformer.py`
  - XML transformation helpers
- `scripts/sample_catalog.py`
  - local Cisco and external reference indexing
- `scripts/sample_selector.py`
  - donor/reference scoring
- `scripts/packet_tracer_env.py`
  - local environment and donor resolution
- `scripts/pkt_codec.py`
  - Packet Tracer modern codec
- `templates/pt900/`
  - secondary fallback XML templates
- `tests/`
  - parser, selector, transform, workspace, and generation tests

## Explain-Plan Output

`--explain-plan` exposes the planning pipeline rather than only the final guess.

It reports:

- `intent_plan`
- `topology_plan`
- `config_plan`
- `estimate_plan`
- `preflight_validation`
- `autofix_summary`
- `validation_report`
- `cisco_sample_candidates`
- `external_reference_patterns`
- `assumptions_used`

This is the main debugging surface for prompt quality.

## External Reference Workflow

External `.pkt` collections must be local first. The tool does not scrape the
internet and it does not use GitHub URLs directly as donors.

Workflow:

1. clone or copy the external repo locally
2. pass that folder with `--reference-root`
3. inspect `external_reference_patterns` in `--explain-plan`

Example:

```powershell
python .\scripts\generate_pkt.py --explain-plan "6 şöbəli şəbəkə qur, hər şöbədə 1 switch 1 AP 1 printer 2 PC 2 tablet olsun" --reference-root C:\labs\external-pkt-samples
```

## Common Commands

### Build the Cisco sample catalog

```powershell
python .\scripts\build_sample_catalog.py
```

### Explain a simple prompt

```powershell
python .\scripts\generate_pkt.py --explain-plan "3 dene switch ve 6 komputer"
```

### Explain a donor-prune campus prompt

```powershell
python .\scripts\generate_pkt.py --explain-plan "6 şöbəli şəbəkə qur, hər şöbədə 1 switch, 1 AP, 1 printer, 2 PC, 2 tablet olsun, router-on-a-stick olsun, DHCP routerdən verilsin, management VLAN və telnet olsun"
```

### Generate a `.pkt`

```powershell
python .\scripts\generate_pkt.py --prompt "6 şöbəli şəbəkə qur, hər şöbədə 1 switch, 1 AP, 1 printer, 2 PC, 2 tablet olsun, router-on-a-stick olsun, DHCP routerdən verilsin, management VLAN və telnet olsun" --output .\output\campus.pkt --xml-out .\output\campus.xml
```

### Inspect an existing `.pkt`

```powershell
python .\scripts\generate_pkt.py --inventory .\input\lab.pkt
```

### Decode a `.pkt`

```powershell
python .\scripts\generate_pkt.py --decode .\output\campus.pkt --xml-out .\output\campus.xml
```

## Security and Privacy

This repo is prepared to avoid accidental sharing of local private material:

- no hardcoded donor path is committed
- no `C:\Users\<name>\...` donor path is baked into config
- generated `.pkt` and `.xml` files are gitignored
- Python cache files are gitignored
- Twofish bridge binaries are gitignored

Still your responsibility before publishing:

- verify your own `PACKET_TRACER_COMPAT_DONOR` path is local-only
- do not commit generated labs unless you intend to share them
- do not commit locally built bridge binaries unless you reviewed them

## Current Limitations

- Packet Tracer 9.x only
- Windows-first workflow
- donor-prune generation is bounded by donor capacity
- external labs are not donors by default
- bundled template coverage is intentionally limited

## Recommended Public Repo Checklist

Before pushing publicly, confirm:

- `scripts/vendor/` contains no local prebuilt `_twofish` binary
- no generated `.pkt` or `.xml` outputs are staged
- your local donor path exists only in your shell env, not in committed files
- README examples match your intended public setup

## Status

This repo is now structured for public sharing with:

- env-based donor setup
- external-reference-only workflow
- explicit explain-plan output
- no machine-specific donor path committed
- no vendored private binary required in the repo by default
