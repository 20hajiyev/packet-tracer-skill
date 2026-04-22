# packet-tracer-skill

[![CI](https://github.com/20hajiyev/packet-tracer-skill/actions/workflows/ci.yml/badge.svg)](https://github.com/20hajiyev/packet-tracer-skill/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Packet Tracer 9.0](https://img.shields.io/badge/Packet%20Tracer-9.0.0.0810-blue.svg)](https://github.com/20hajiyev/packet-tracer-skill)

Cisco Packet Tracer 9.x `.pkt` generator and editor for skill-based coding hosts.

This repository is built for one job: take a natural-language network request, build an explicit scenario-aware plan, adapt a compatible donor lab, and produce a Packet Tracer 9.x workflow that stays open-first and compatibility-first.

`0.2.1` public preview hardening is focused on:

- donor-backed and scenario-aware public messaging
- conservative Windows-first runtime truth
- known working scenario set examples with acceptance-backed artifacts
- release-notes-ready and GitHub-metadata-ready launch surface

## Why It Is Different

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

## Runtime Reality

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

The installer can be used on multiple hosts, but real `.pkt` runtime remains Windows-first and doctor-governed.

| Platform | Installer / skill copy | Real `.pkt` runtime |
| --- | --- | --- |
| Windows | Supported | Acceptance-verified |
| macOS | Partially supported | Runtime contract defined, not acceptance-verified |
| Linux | Partially supported | Runtime contract defined, not acceptance-verified |

Important runtime rule:

- installer success is not the same thing as runtime readiness
- `--doctor` is the authority for whether real `.pkt` operations are ready
- repo-local bridge and external bridge are reported separately
- current strict validation is Windows-first and external-bridge-assisted

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

Launch-prep references:

- [docs/release-notes-0.2.1.md](docs/release-notes-0.2.1.md)
- [docs/hero-demo-plan.md](docs/hero-demo-plan.md)
- [docs/github-metadata.md](docs/github-metadata.md)
- [docs/release-checklist.md](docs/release-checklist.md)

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

Use `--explain-plan` when you need the full decision payload:

```powershell
python .\scripts\generate_pkt.py --explain-plan "6 department campus with router-on-a-stick, VLAN, DHCP, management VLAN, Telnet, ACL"
```

Use `--compare-scenarios` when you need scenario comparison:

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

## Curated Donor and Fixture Truth Sources

This repository keeps explicit truth sources for donor evidence and scenario regression:

- `references/curated-donor-registry.json`
- `references/scenario-fixture-corpus.json`

Curated donor registry reference:

- [docs/curated-donor-registry.md](docs/curated-donor-registry.md)

## Known Working Scenario Set

Public examples stay text-first and review-friendly. Raw `.pkt` binaries are not committed.

Canonical public examples:

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

Hero visual for the `0.2.1` public preview surface:

- `examples/screenshots/complex_campus_master_edit_v4.png`

The gallery is treated as a known working scenario set, not just a screenshot list, and the same canonical set feeds release notes and GitHub metadata.

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

## Azerbaijani Summary

Bu repo təbii dil ilə Packet Tracer `.pkt` generate və edit etmək üçündür, amma əsas fərqi ondadır ki, bunu donor-backed və open-first qayda ilə edir. Yəni donor, parity, acceptance və runtime hazır deyilsə, sistem guess etmir, refusal və remediation qaytarır.

Əsas public səthlər:

- `--explain-plan`
- `--compare-scenarios`
- `--parity-report`
- `--doctor`
- examples gallery və acceptance excerpt-lər

Hazırkı prioritet:

- `0.2.1` public preview hardening
- release-ready və publish-ready surface
- README / npm / GitHub discoverability hizalanması
- scenario truth source, donor registry və runtime doctor contract consistency

## License

This project is licensed under the MIT License.
