# packet-tracer-skill

[![CI](https://github.com/20hajiyev/packet-tracer-skill/actions/workflows/ci.yml/badge.svg)](https://github.com/20hajiyev/packet-tracer-skill/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Packet Tracer 9.0](https://img.shields.io/badge/Packet%20Tracer-9.0.0.0810-blue.svg)](https://github.com/20hajiyev/packet-tracer-skill)

Cisco Packet Tracer 9.x `.pkt` generator and editor for skill-based coding hosts.

This repository is built for one job: take a natural-language network request, build an explicit scenario-aware plan, adapt a compatible donor lab, and produce a Packet Tracer 9.x workflow that stays open-first and compatibility-first.

Current publish-preview focus:

- release/readme/docs surface is being aligned to the actual runtime and donor truth
- curated donor evidence is explicit and registry-backed
- examples are treated as the known working scenario set

## Why This Repo Exists

`packet-tracer-skill` is not a generic topology sketcher. It is a donor-backed Packet Tracer workflow with strict refusal behavior:

- generation stays `single-donor apply`
- unsupported and acceptance-gated mutations do not fall back to guessed output
- `--explain-plan`, `--compare-scenarios`, `--parity-report`, and `--doctor` are first-class product surfaces
- curated donor evidence, fixture corpus checks, and runtime doctor output are part of the contract

Current product strengths:

- `open-first` generate guard
- donor-aware and scenario-aware decision layer
- `compare-scenarios`, `capability_parity`, curated donor registry
- runtime doctor contract with bridge resolution
- known working examples with screenshots and acceptance excerpts

## Host Support

Use the same repository, then install it into the skill path your host expects.

| Tool | Install | First Use |
| --- | --- | --- |
| Codex CLI | `npx packet-tracer-skill` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Cursor | `npx packet-tracer-skill --cursor` | `@pkt build a Packet Tracer lab with VLAN and DHCP` |
| Claude Code | `npx packet-tracer-skill --claude` | `Use /pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Claude Desktop | `npx packet-tracer-skill --path <claude-desktop-skills-dir>` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Gemini CLI | `npx packet-tracer-skill --path <gemini-skills-dir>` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| Kiro CLI / IDE | `npx packet-tracer-skill --kiro` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| AdaL CLI | `npx packet-tracer-skill --adal` | `Use pkt to build a Packet Tracer lab with VLAN and DHCP` |
| OpenCode | `npx packet-tracer-skill --path .agents/skills` | `opencode run @pkt build a Packet Tracer lab with VLAN and DHCP` |
| Custom path | `npx packet-tracer-skill --path ./my-skills` | depends on the host |

## Platform Support

The installer command can be used on more than one OS, but real `.pkt` decode/edit/generate runtime is still Windows-first.

| Platform | Installer / skill copy | Real `.pkt` runtime |
| --- | --- | --- |
| Windows | Supported | Acceptance-verified |
| macOS | Partially supported | Runtime contract defined, not acceptance-verified |
| Linux | Partially supported | Runtime contract defined, not acceptance-verified |

Important runtime rule:

- installer success is not the same thing as runtime readiness
- `--doctor` is the authority for whether real `.pkt` operations are ready
- repo-local bridge and external bridge are reported separately

## Quick Start

Default install for Codex:

```powershell
npx packet-tracer-skill
```

Bootstrap install:

```powershell
npx packet-tracer-skill --bootstrap
```

Verification:

```powershell
npx packet-tracer-skill --verify
npx packet-tracer-skill --verify --cursor
```

Runtime doctor:

```powershell
npx packet-tracer-skill --doctor
python .\scripts\runtime_doctor.py
```

Local development:

```powershell
git clone https://github.com/20hajiyev/packet-tracer-skill.git
cd .\packet-tracer-skill
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -Dev
```

## Runtime Doctor Contract

`--doctor` is a product surface, not a debug afterthought. It reports:

- `capability_impact`
- `runtime_blockers`
- `blocked_operations`
- `ready_operations`
- `recommended_next_steps`
- `doctor_summary`
- `runtime_grade`
- `bridge_resolution`
- `bridge_path_source`
- `bridge_recommendation`
- `runtime_contract_notes`

Bridge resolution states:

- `repo_local`
- `external_env`
- `missing`

Runtime grade states:

- `ready`
- `partially_ready`
- `blocked`

Important distinction:

- tests can pass with an external bridge override
- that does not mean the repo is self-contained runtime-ready
- the difference between repo-local readiness and external bridge fallback is part of the public contract

Runtime truth reference:

- [docs/runtime-truth.md](docs/runtime-truth.md)

## Runtime Configuration

Set the local Packet Tracer environment before real `.pkt` generation:

```powershell
$env:PACKET_TRACER_ROOT='C:\Program Files\Cisco Packet Tracer 9.0.0'
$env:PACKET_TRACER_COMPAT_DONOR='C:\path\to\your-working-9.0-donor.pkt'
$env:PKT_TWOFISH_LIBRARY="$env:USERPROFILE\.codex\skills\pkt\scripts\vendor\_twofish.cp314-win_amd64.pyd"
```

Important variables:

- `PACKET_TRACER_ROOT`
- `PACKET_TRACER_SAVES_ROOT`
- `PACKET_TRACER_EXE`
- `PACKET_TRACER_COMPAT_DONOR`
- `PACKET_TRACER_TARGET_VERSION`
- `PKT_TWOFISH_LIBRARY`
- `PKT_TWOFISH_SEARCH_ROOTS`

Required policy:

- keep `PACKET_TRACER_TARGET_VERSION` on `9.0.0.0810`
- do not downgrade the workflow to `5.3`
- if donor or bridge is missing, fix the runtime instead of weakening the compatibility profile

## Core Product Surfaces

### Planning and Scenario Comparison

Use `--explain-plan` when you need the full decision payload:

```powershell
python .\scripts\generate_pkt.py --explain-plan "6 department campus with router-on-a-stick, VLAN, DHCP, management VLAN, Telnet, ACL"
```

Use `--compare-scenarios` when you need scenario comparison instead of one-off debugging:

```powershell
python .\scripts\generate_pkt.py --compare-scenarios "campus with VLAN DHCP ACL" --compare-scenarios "smart home with IoT registration" --matrix-out .\output\compare.json
```

Use `--parity-report` for prompt-scoped capability readiness:

```powershell
python .\scripts\generate_pkt.py --parity-report "service-heavy lab with DNS DHCP FTP email syslog AAA"
```

Stable CLI surfaces:

- `--explain-plan`
- `--compare-scenarios`
- `--matrix-out`
- `--coverage-report`
- `--inventory-capabilities`
- `--doctor`
- `--parity-report`
- `--acceptance-json-out`

### Inventory and Edit

Inspect an existing `.pkt`:

```powershell
python .\scripts\generate_pkt.py --inventory .\input\lab.pkt
python .\scripts\generate_pkt.py --inventory .\input\lab.pkt --inventory-capabilities
python .\scripts\generate_pkt.py --inventory .\input\lab.pkt --inventory-capabilities --inventory-out .\examples\lab.inventory.json
```

Edit an existing `.pkt` from a prompt:

```powershell
python .\scripts\generate_pkt.py --edit .\input\lab.pkt --prompt "set Wireless Router0 ssid FIN_WIFI security wpa2-psk passphrase fin12345 channel 6 associate PC0 to Wireless Router0 ssid FIN_WIFI dhcp" --output .\output\edited_lab.pkt
```

### Generate

Generate a `.pkt` only when donor capacity and acceptance state allow it:

```powershell
python .\scripts\generate_pkt.py --prompt "6 department campus with router-on-a-stick, VLAN, DHCP, management VLAN, Telnet, ACL" --output .\output\campus.pkt --xml-out .\output\campus.xml
```

If no safe donor fits, the workflow refuses cleanly and can emit a blueprint instead of guessed output.

## Decision Layer

The repo is built around decision-complete output, not silent fallbacks.

Important public JSON contracts:

- `scenario_generate_decision`
- `scenario_acceptance_summary`
- `scenario_matrix_row`
- `capability_parity`
- `runtime_doctor`

Scenario families currently modeled:

- `campus`
- `service_heavy`
- `home_iot`
- `wan_security_edge`

## Capability Coverage

Current coverage focus:

- VLAN
- router-on-a-stick
- trunk / access
- management VLAN
- Telnet
- DHCP
- DNS
- ACL
- wireless/AP-client
- end-device mutation
- service-heavy server metadata
- IoT registration/control reporting
- WAN/security-edge inventory and donor-selection awareness

Important limit:

- Phase D coverage is currently inventory/selection/report focused
- WAN/security families do not yet imply full safe-open generate

## Curated Donor and Fixture Truth Sources

This repository keeps explicit truth sources for donor evidence and scenario regression:

- `references/curated-donor-registry.json`
- `references/scenario-fixture-corpus.json`

Those files are used to keep:

- curated donor promotion deterministic
- fixture expectations auditable
- example metadata aligned with scenario families and acceptance excerpts

Curated donor registry reference:

- [docs/curated-donor-registry.md](docs/curated-donor-registry.md)

## Known Working Scenario Set

Public examples stay text-first and review-friendly. Raw `.pkt` binaries are not committed.

Canonical examples:

- `complex_campus_master_edit_v4`
- `home_iot_cli_edit_v1`
- `service_heavy_cli_edit_v1`

Gallery and manifests:

```powershell
python .\scripts\build_examples_index.py
Get-Content .\examples\gallery.md
Get-Content .\examples\index.json
```

Primary screenshot:

![Packet Tracer topology](examples/screenshots/complex_campus_master_edit_v4.png)

The gallery is treated as a known working scenario set, not just a screenshot list.

## Security and Privacy

This repo is prepared to avoid accidental sharing of local private material:

- no hardcoded donor path is committed
- no `C:\Users\<name>\...` donor path is baked into config
- generated `.pkt` and `.xml` files are gitignored
- public sample labs should be committed as inventory JSON or blueprint JSON, not raw `.pkt` binaries
- Twofish bridge binaries are gitignored by default

Before publishing:

- verify your own `PACKET_TRACER_COMPAT_DONOR` path is local-only
- do not commit generated labs unless you intend to share them
- do not commit locally built bridge binaries unless you reviewed them

See also:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [docs/release-checklist.md](docs/release-checklist.md)
- [docs/github-discussions-setup.md](docs/github-discussions-setup.md)

## Release Readiness

This repo is being hardened toward a publish-ready and release-ready surface.

Current release engineering assets:

- CI workflow
- issue templates
- contributing guide
- citation metadata
- changelog
- release checklist
- example gallery index builder

Recommended local validation before release:

```powershell
python .\scripts\build_examples_index.py
python -m pytest tests -q
node --check .\bin\packet-tracer-skill.js
python .\scripts\generate_pkt.py --parity-report "campus with VLAN DHCP ACL"
python .\scripts\runtime_doctor.py
```

Publish-preview references:

- [docs/release-checklist.md](docs/release-checklist.md)
- [docs/publish-preview-roadmap.md](docs/publish-preview-roadmap.md)
- [docs/discovery-keywords.md](docs/discovery-keywords.md)
- [docs/github-metadata.md](docs/github-metadata.md)

## Current Limitations

- Packet Tracer 9.x only
- Windows-first real runtime
- donor-prune generation is bounded by donor capacity
- unsupported and acceptance-gated mutate does not fall back to guessed output
- external labs are not donors by default
- repo-local Twofish bridge is not shipped by default

## Azerbaijani Summary

Bu repo təbii dil ilə Packet Tracer `.pkt` generate və edit etmək üçündür, amma əsas fərqi ondadır ki, bunu donor-backed və open-first qayda ilə edir. Yəni donor, parity, acceptance və runtime hazır deyilsə, sistem guess etmir, refusal və remediation qaytarır.

Əsas public səthlər:

- `--explain-plan`
- `--compare-scenarios`
- `--parity-report`
- `--doctor`
- examples gallery və acceptance excerpt-lər

Hazırkı prioritet:

- release-ready və publish-ready surface
- README / npm / GitHub discoverability hizalanması
- scenario truth source, donor registry və runtime doctor contract consistency

## License

This project is licensed under the MIT License.
