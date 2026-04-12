# packet-tracer-skill

Cisco Packet Tracer 9.x `.pkt` generator and editor for skill-based coding hosts.

This repository is built for one specific job: take a natural-language network
request, plan it explicitly, adapt a compatible local Cisco Packet Tracer donor
lab, and produce a `.pkt` file that opens cleanly in Packet Tracer 9.x.

It is intentionally:

- Cisco-sample-centric
- intent-first
- donor-prune-based for compatibility
- reference-aware without trusting external labs as donors

## Host Support

Use the same repository, then install or point it to the skill path your host
expects.

| Tool | Install | First Use |
| --- | --- | --- |
| Claude Code | `npx github:20hajiyev/packet-tracer-skill --claude` | `Use /pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Cursor | `npx github:20hajiyev/packet-tracer-skill --cursor` | `@pkt build a Packet Tracer lab with VLAN and DHCP` |
| Gemini CLI | `npx github:20hajiyev/packet-tracer-skill --path <gemini-skills-dir>` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Codex CLI | `npx github:20hajiyev/packet-tracer-skill` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Antigravity | `npx github:20hajiyev/packet-tracer-skill --path <antigravity-skills-dir>` | `Use @pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Kiro CLI | `npx github:20hajiyev/packet-tracer-skill --kiro` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Kiro IDE | `npx github:20hajiyev/packet-tracer-skill --kiro` | `Use @pkt to build a Packet Tracer lab with VLAN and DHCP` |
| GitHub Copilot | Copy this repo into your local prompts/rules/skills docs | `Ask Copilot to use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| OpenCode | `npx github:20hajiyev/packet-tracer-skill --path .agents/skills` | `opencode run @pkt build a Packet Tracer lab with VLAN and DHCP` |
| AdaL CLI | `npx github:20hajiyev/packet-tracer-skill --adal` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Custom path | `npx github:20hajiyev/packet-tracer-skill --path ./my-skills` | Depends on your tool |

## Quick Start

```powershell
npx github:20hajiyev/packet-tracer-skill
```

That installs `pkt` into the default Codex skill path.

If you publish this package to npm later, the same command shape becomes:

```powershell
npx packet-tracer-skill
```

Other common targets:

```powershell
npx github:20hajiyev/packet-tracer-skill --cursor
npx github:20hajiyev/packet-tracer-skill --claude
npx github:20hajiyev/packet-tracer-skill --kiro
```

If you publish to npm later, those become:

```powershell
npx packet-tracer-skill --cursor
npx packet-tracer-skill --claude
```

If PowerShell blocks `npx.ps1` on your machine, use:

```powershell
cmd /c npx github:20hajiyev/packet-tracer-skill --cursor
```

If you want the local development setup for this repository itself:

```powershell
git clone https://github.com/20hajiyev/packet-tracer-skill.git
cd .\packet-tracer-skill
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -Dev
```

Then configure your local Packet Tracer environment:

```powershell
$env:PACKET_TRACER_ROOT='C:\Program Files\Cisco Packet Tracer 9.0.0'
$env:PACKET_TRACER_COMPAT_DONOR='C:\labs\campus_donor_9_0.pkt'
$env:PKT_TWOFISH_LIBRARY='C:\tools\pkt-twofish\_twofish.cp314-win_amd64.pyd'
```

## Verify the Install

Check that the skill was copied into the expected host directory:

```powershell
npx github:20hajiyev/packet-tracer-skill --verify
```

Examples:

```powershell
npx github:20hajiyev/packet-tracer-skill --verify --cursor
npx github:20hajiyev/packet-tracer-skill --verify --claude
npx github:20hajiyev/packet-tracer-skill --verify --path .agents/skills
```

If you are working from a local clone instead of `npx`, these also work:

```powershell
node .\bin\packet-tracer-skill.js --verify
python .\scripts\install_skill.py --host codex --force
```

## Screenshot

Generated campus topology opened in Cisco Packet Tracer:

![Packet Tracer topology](docs/screenshots/packet-tracer-topology-cropped.png)

## What This Repo Does

- Parses hybrid Azerbaijani + English prompts
- Builds explicit `IntentPlan`, `TopologyPlan`, and `ConfigPlan`
- Ranks Cisco local donors by capability and topology fit
- Uses donor-prune adaptation for Packet Tracer 9.x compatibility
- Edits existing `.pkt` labs
- Supports VLAN, router-on-a-stick, DHCP, DNS, Telnet, ACL, wireless/AP-client, and department/campus layouts
- Explains the plan before generation with `--explain-plan`

## Design Principles

### 1. Cisco local donors are primary

This repo does not try to fully synthesize Packet Tracer runtime state from
scratch on the main generation path. It adapts a working local Packet Tracer
9.x donor lab.

That choice is deliberate. Packet Tracer compatibility failures usually come
from deeper runtime, workspace, physical, scenario, and reference structures.
Donor-preserving adaptation is the more reliable path.

### 2. External labs are reference-only

Imported external `.pkt` collections can help with:

- topology motifs
- naming ideas
- config ideas
- capability hints

They do not become prototype donors by default.

### 3. Planning is explicit

Prompt generation follows this pipeline:

1. `Intent Extraction`
2. `TopologyPlan` and `ConfigPlan`
3. Cisco donor ranking
4. donor-prune mutation plan
5. validation and autofix
6. `.pkt` encoding

### 4. Unsafe prompts are blocked

If a prompt is incomplete or ambiguous, the tool returns structured
`blocking_gaps` instead of inventing risky topology or config decisions.

## Requirements

- Windows
- Cisco Packet Tracer 9.x installed locally
- local Cisco Packet Tracer sample saves available
- a local Packet Tracer 9.x donor lab for donor-prune generation
- a local Twofish bridge compatible with your Python runtime

### Python dependencies

- `requirements.txt`
  - runtime package list
- `requirements-dev.txt`
  - test and development extras such as `pytest`

Install them with:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -Dev
```

## Runtime Configuration

This repository does not ship Cisco sample `.pkt` files. It resolves them from
the local Packet Tracer installation and from your explicitly configured donor.

### Environment variables

- `PACKET_TRACER_ROOT`
- `PACKET_TRACER_SAVES_ROOT`
- `PACKET_TRACER_EXE`
- `PACKET_TRACER_COMPAT_DONOR`
- `PACKET_TRACER_TARGET_VERSION`
- `PKT_TWOFISH_LIBRARY`

### Sample-source policy

- `primary`: local Cisco Packet Tracer sample saves
- `secondary`: bundled device templates
- `reference-only`: imported external `.pkt` roots

### Generation policy

- prompt-driven generation runs in `donor_prune_strict_9_0`
- donor capacity must be large enough for the requested topology
- if donor capacity is not enough, generation stops with `blocking_gaps`

## Twofish Bridge

This public repo does not ship a prebuilt Twofish bridge binary by default.

That is intentional:

- no machine-specific binary is committed by default
- no unsigned local artifact is published by accident
- no private path or build residue is shared by default

Read `scripts/vendor/README.md` for local setup.

## Repository Layout

- `scripts/generate_pkt.py`
  - CLI entrypoint
- `scripts/intent_parser.py`
  - natural-language and mini-DSL parsing
- `scripts/pkt_editor.py`
  - donor-preserving edit and mutation operations
- `scripts/pkt_transformer.py`
  - XML transformation helpers
- `scripts/sample_catalog.py`
  - local Cisco and external reference indexing
- `scripts/sample_selector.py`
  - donor and reference scoring
- `scripts/packet_tracer_env.py`
  - local environment and donor resolution
- `scripts/pkt_codec.py`
  - Packet Tracer modern codec
- `scripts/install_skill.py`
  - host-path installer helper
- `scripts/setup.ps1`
  - virtual environment and dependency setup
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

## Suggested Screenshots

If you want a screenshot section in the repo, use screenshots that show the real
workflow and actual value of the skill:

1. `Explain Plan`
   - terminal screenshot of `--explain-plan`
   - show `intent_plan`, `topology_plan`, and `validation_report`
2. `Opened Packet Tracer Topology`
   - Packet Tracer logical view with a generated campus or department lab
   - labels readable, links visible, layout clean
3. `Existing .pkt Edit`
   - before and after pair or one screenshot showing renamed departments, VLAN changes, or updated SSIDs
4. `Services or Wireless`
   - a server DHCP/DNS screen, AP SSID/security screen, or router/switch CLI verification

Suggested save folder in this repo:

- `docs/screenshots/`

Avoid screenshots that expose:

- local usernames
- donor file paths
- private folders
- generated files you do not want to share publicly

## License

This project is licensed under the MIT License.

Third-party license notices can remain under `LICENSES/` when needed.
