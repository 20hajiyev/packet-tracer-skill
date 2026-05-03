# packet-tracer-skill

[![CI](https://github.com/20hajiyev/packet-tracer-skill/actions/workflows/ci.yml/badge.svg)](https://github.com/20hajiyev/packet-tracer-skill/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Packet Tracer 9.0](https://img.shields.io/badge/Packet%20Tracer-9.0.0.0810-blue.svg)](https://github.com/20hajiyev/packet-tracer-skill)

Cisco Packet Tracer 9.x `.pkt` generator and editor for skill-based coding hosts.

This repository is built for one job: take a natural-language network request, build an explicit scenario-aware plan, adapt a compatible donor lab, and produce a Packet Tracer 9.x workflow that stays open-first and compatibility-first.

It is intended for networking labs where correctness matters more than producing a pretty but unverifiable diagram. The skill can plan, inspect, edit, compare, and explain Packet Tracer scenarios, but it deliberately separates "recognized by the parser", "visible in inventory", "edit-proven", "donor-backed ready", and "generate-ready" support.

`0.2.3` capability release is focused on:

- donor-backed and scenario-aware public messaging
- conservative Windows-first runtime truth
- known working scenario set examples with acceptance-backed artifacts
- expanded edit-proven capability proof across voice, automation, L2 security, WAN/security, BGP/L2 resiliency, IPv4 routing/NAT, IOS management, and local sample audit workflows

`0.2.3` freezes the voice/collaboration and automation/controller proof work, explicit L2 dot1x/QoS and router-based CBAC/ZFW proof, local-sample-driven BGP/L2 resiliency, IPv4 routing/NAT/IOS-management proof waves, and the first broader donor-backed edit readiness expansion. It remains conservative: `generate_ready=0` is intentional until a future single-donor acceptance-backed pilot is proven.

## What It Does

`packet-tracer-skill` turns network-lab requests into explicit Packet Tracer workflows. The core loop is:

1. parse the prompt into a scenario family and requested capabilities
2. compare those capabilities against the current support matrix
3. look for a compatible donor lab when strict `.pkt` work is required
4. refuse unsafe or unsupported changes instead of guessing
5. return a decision payload that explains what passed, what failed, and what would make it pass

The current public surface is strongest for these tasks:

- scenario-aware planning for campus, service-heavy, Home IoT, WAN/security edge, IPv6/routing, IPv4 routing/management, L2 security/monitoring, L2 resiliency/BGP, and advanced wireless prompts
- explicit `.pkt` edits for proven command shapes such as VLAN, DHCP, ACL, server services, IPv6/routing subsets, IPv4 routing/NAT/IOS-management subsets, L2 security/monitoring subsets, BGP/STP/EtherChannel/VTP/DTP IOS text edits, Home IoT constrained edits, and narrow advanced wireless edits
- capability parity reports that explain whether a prompt is inventory-known, edit-supported, donor-limited, acceptance-gated, or unsupported
- runtime diagnostics for Packet Tracer installation, donor path, Twofish bridge resolution, and blocked versus ready operations
- public proof artifacts through examples, inventory manifests, acceptance excerpts, and donor proof docs

## What It Does Not Claim

The project is intentionally conservative. It does not claim universal Packet Tracer automation.

- It does not claim every Packet Tracer feature is generate-ready.
- It does not synthesize arbitrary `.pkt` internals when donor or acceptance evidence is weak.
- It does not treat a successful skill install as proof that real `.pkt` decode/edit/generate is ready.
- It does not commit raw `.pkt` donor labs or local bridge binaries into the public package.
- It does not claim repo-local self-contained runtime readiness when validation depends on an external bridge override.

The feature atlas exists so unsupported and under-modelled Packet Tracer areas are visible instead of hidden. The intended path is: map the feature, prove inventory visibility, prove edit roundtrip, add donor-backed readiness, and only then consider generate readiness.

## Why It Is Different

`packet-tracer-skill` is not a generic topology sketcher. It is a donor-backed Packet Tracer workflow with strict refusal behavior:

- generation stays `single-donor apply`
- unsupported and acceptance-gated mutations do not fall back to guessed output
- `--explain-plan`, `--compare-scenarios`, `--parity-report`, and `--doctor` are first-class product surfaces
- curated donor evidence, fixture corpus checks, and runtime doctor output are part of the contract

In practice, that means the tool is trying to solve a narrower but more defensible problem than a prompt-to-diagram generator. It is designed to answer three questions in order:

1. what the prompt is actually asking for
2. whether the requested capability set is really supported for this scenario family
3. whether a compatible donor and runtime path exist to carry the request safely

If the answer to any of those is weak, the tool is expected to stop and explain why. That refusal behavior is part of the intended product quality, not a temporary limitation.

Current product strengths:

- `open-first` generate guard
- donor-aware and scenario-aware decision layer
- `compare-scenarios`, `capability_parity`, curated donor registry
- runtime doctor contract with bridge resolution
- known working examples with screenshots and acceptance excerpts

## Runtime Reality

Use the same repository, then install it into the skill path your host expects.

There are two separate installation stories:

- installing the skill package into Codex, Cursor, Claude, Gemini, Kiro, AdaL, OpenCode, or a custom skill directory
- making the local machine capable of opening, decoding, editing, and regenerating real Packet Tracer `.pkt` files

The first story is handled by the npm installer. The second story depends on Packet Tracer 9.0, a compatible donor lab, and a local Twofish bridge. This is why the README keeps repeating the runtime distinction: a host can install the skill successfully while strict `.pkt` operations are still blocked.

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

That distinction matters because this project has two different surfaces:

- installer or skill-copy success
- actual Packet Tracer decode/edit/generate readiness

The first one is relatively portable. The second one is not. README, npm text, release notes, and doctor output all need to preserve that difference or they become misleading.

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
- `validate_open` can be ready while strict decode/edit/generate are still blocked

The mixed case is especially important. If `validate_open` works, that only proves Packet Tracer can be launched. It does not prove the current checkout can decode or regenerate `.pkt` files safely. For strict work, donor availability and Twofish bridge resolution still decide the outcome.

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

Launch references:

- [docs/release-notes-0.2.3.md](docs/release-notes-0.2.3.md)
- [docs/release-notes-0.2.2.md](docs/release-notes-0.2.2.md)
- [docs/hero-demo-plan.md](docs/hero-demo-plan.md)
- [docs/github-metadata.md](docs/github-metadata.md)
- [docs/release-checklist.md](docs/release-checklist.md)
- [docs/github-launch-ops-0.2.2.md](docs/github-launch-ops-0.2.2.md)
- [docs/campus-donor-proof.md](docs/campus-donor-proof.md)
- [docs/home-iot-donor-proof.md](docs/home-iot-donor-proof.md)
- [docs/wan-security-donor-proof.md](docs/wan-security-donor-proof.md)
- [docs/wireless-advanced-proof.md](docs/wireless-advanced-proof.md)
- [docs/industrial-programming-proof.md](docs/industrial-programming-proof.md)
- [docs/automation-controller-proof.md](docs/automation-controller-proof.md)
- [docs/voice-collaboration-proof.md](docs/voice-collaboration-proof.md)
- [docs/l2-resiliency-bgp-proof.md](docs/l2-resiliency-bgp-proof.md)
- [docs/ipv4-routing-management-proof.md](docs/ipv4-routing-management-proof.md)
- [docs/l2-security-qos-proof.md](docs/l2-security-qos-proof.md)
- [docs/security-edge-deepening-proof.md](docs/security-edge-deepening-proof.md)
- [docs/packet-tracer-feature-gap-atlas.md](docs/packet-tracer-feature-gap-atlas.md)

## Runtime Doctor Contract

`--doctor` is a product surface, not a debug afterthought. It reports:

- `capability_impact`
- `runtime_blockers`
- `blocked_operations`
- `ready_operations`
- `what_currently_works`
- `what_is_blocked`
- `why_it_is_blocked`
- `best_next_fix`
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
- mixed states should still read like a decision guide, not a debug dump

Selector and runtime are intentionally kept separate:

- donor selection can still block a prompt even when runtime is healthy
- runtime can still block strict `.pkt` work even when a donor artifact exists
- campus donor proof currently shows the first case more clearly than the second

Runtime truth reference:

- [docs/runtime-truth.md](docs/runtime-truth.md)
- [docs/post-launch-follow-up.md](docs/post-launch-follow-up.md)

## Runtime Configuration

Set the local Packet Tracer environment before real `.pkt` generation:

```powershell
$env:PACKET_TRACER_ROOT='C:\Program Files\Cisco Packet Tracer 9.0.0'
$env:PACKET_TRACER_COMPAT_DONOR='C:\path\to\your-working-9.0-donor.pkt'
```

Important variables:

- `PACKET_TRACER_ROOT`
- `PACKET_TRACER_SAVES_ROOT`
- `PACKET_TRACER_EXE`
- `PACKET_TRACER_COMPAT_DONOR`
- `PACKET_TRACER_TARGET_VERSION`
- `PKT_TWOFISH_LIBRARY`
- `PKT_TWOFISH_SEARCH_ROOTS`

Twofish bridge setup is intentionally local-machine specific. Use a path that exists on your own machine.

Generic explicit bridge path:

```powershell
$env:PKT_TWOFISH_LIBRARY="C:\path\to\_twofish.cp314-win_amd64.pyd"
```

Repo-local bridge path, if you have placed a compatible bridge inside this
checkout:

```powershell
$env:PKT_TWOFISH_LIBRARY="$PWD\scripts\vendor\_twofish.cp314-win_amd64.pyd"
```

Search-root fallback, if you want the runtime to look inside a local bridge
folder:

```powershell
$env:PKT_TWOFISH_SEARCH_ROOTS="C:\path\to\bridge-folder"
```

Developer-local bridge paths are valid only for the person and host where that bridge exists. They are not the public setup contract.

Required policy:

- keep `PACKET_TRACER_TARGET_VERSION` on `9.0.0.0810`
- do not downgrade the workflow to `5.3`
- if donor or bridge is missing, fix the runtime instead of weakening the compatibility profile

Troubleshooting guide:

- `bridge_resolution=repo_local` means the checkout contains the bridge path the doctor resolved.
- `bridge_resolution=external_env` means an environment variable points to a bridge outside the repo. This can be valid for testing, but it is not repo self-contained readiness.
- `bridge_resolution=missing` means strict decode/edit/generate is blocked until `PKT_TWOFISH_LIBRARY` or `PKT_TWOFISH_SEARCH_ROOTS` resolves a compatible bridge.
- `validate_open` readiness only proves Packet Tracer can launch a file. Strict `.pkt` generation still depends on donor and bridge readiness.

## Core Product Surfaces

The CLI is not only a generator entrypoint. It is also the inspection surface for deciding whether a request is safe. In normal development, start with the reporting commands before expecting a final `.pkt` output.

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

Use `--feature-gap-report` for the Packet Tracer 9.0 feature atlas:

```powershell
python .\scripts\generate_pkt.py --feature-gap-report
```

## GitHub Sample Ingestion Is Local/Cache-Only

The skill can search GitHub for public Packet Tracer sample repositories when you explicitly opt in with `--search-remote`. This is a developer workflow for collecting evidence, not a promise that downloaded labs become trusted donors or package assets.

Remote ingestion rules:

- imported `.pkt` and `.pka` files stay under `output/remote-import-cache` by default
- `output/remote-import-cache` is local-only and is not included in the npm package
- unknown or missing license metadata is treated as `reference_only`
- permissive-license repositories, such as MIT, only become curated donor candidates after decode and inventory validation
- decode-fail samples can contribute sample-path evidence, but they never create edit, donor-backed, or generate-ready claims
- final `.pkt` apply still uses the same `single-donor` safety rule

Preview GitHub candidates without downloading archives:

```powershell
python .\scripts\generate_pkt.py --explain-plan "ipv6 ospf hsrp lab" --search-remote --remote-dry-run --max-remote-results 3
```

Import into the local cache and write the audit report:

```powershell
python .\scripts\generate_pkt.py --explain-plan "ipv6 ospf hsrp lab" --search-remote --max-remote-results 3 --remote-audit-out output\remote-import-cache\remote-sample-audit.json
```

## Local Sample Audit Is Evidence-Only

If you have your own Packet Tracer lab folder, audit it locally instead of copying raw `.pkt` files into this repo:

```powershell
python .\scripts\generate_pkt.py --local-sample-audit-root "C:\path\to\pkt_examples"
```

By default this writes `output/local-sample-audit.json`. That file is local-only and ignored by git/npm packaging. The audit reports total `.pkt/.pka` files, decode success/fail counts, detected config capabilities, top device types, and local promotion candidates. It is evidence for future proof waves, not a curated donor registry entry by itself.

Use an explicit output path when you want to compare audit snapshots:

```powershell
python .\scripts\generate_pkt.py --local-sample-audit-root "C:\path\to\pkt_examples" --local-sample-audit-out output\local-sample-audit.json
```

Local evidence still follows the same maturity ladder: sample path evidence, decode evidence, inventory proof, editor roundtrip proof, donor-backed readiness, then possible generate readiness. Raw user-supplied `.pkt/.pka` files are not committed or published.

The generated audit is local by design:

- `repo_url`, license, default branch, import status
- imported `.pkt` / `.pka` / README / LICENSE counts
- decode success and failure counts
- detected feature tags when decode succeeds
- license-based candidate promotion status and decode-gated validation status

The atlas now distinguishes report-only features, edit-proven features, and donor-backed edit readiness. IPv6/routing, IPv4 routing/NAT/IOS management, a constrained L2 security/monitoring subset, BGP + L2 resiliency IOS text edits, router-based CBAC/ZFW, a narrow WAN/security subset, and a narrow advanced-wireless subset can be edited with explicit commands. Real HTTP/WebSocket, OSPFv3, EIGRP IPv6, RIPng, HSRP, dot1x, ZFW, voice IOS, and selected programming script-file edits are donor-backed-ready proof paths. None of these are claimed as broad generate-ready without acceptance evidence.

Support levels used by the atlas:

- `not_mapped`: the feature is known as a Packet Tracer area, but this repo does not yet model it.
- `inventory_known`: the feature can be discovered or inferred from sample/catalog evidence.
- `report_supported`: prompts and reports can talk about the feature without claiming edits.
- `edit_proven`: explicit command shapes have editor roundtrip evidence.
- `donor_backed_ready`: a selected donor or proof-linked explicit edit path can safely carry the capability for a prompt-scoped workflow.
- `generate_ready`: strict generate support is acceptance-backed for that scenario.

Current feature-support truth:

| Area | Current status | Safe action |
| --- | --- | --- |
| Campus / service-heavy / Home IoT / WAN-security scenario families | Donor-aware planning and parity/report surfaces | Use `--explain-plan`, `--compare-scenarios`, and donor proof docs before strict generate claims |
| IPv6/routing | OSPFv3, EIGRP IPv6, RIPng, and HSRP are donor-backed ready for explicit edit paths; SLAAC and DHCPv6 stateful remain edit-proven; tunneling, ISATAP, prefix delegation, and AAAA DNS remain report-first | Use explicit router/interface commands; strict generate still needs selected-donor acceptance |
| IPv4 routing/management | OSPFv2, EIGRP IPv4, RIPv2, static/default route, DHCP relay, NAT/PAT, SSH, NTP, and syslog are edit-proven only for explicit IOS text commands | Use named router/interface commands; do not claim route convergence, NAT policy synthesis, or topology generation |
| L2 security/monitoring | Explicit dot1x is donor-backed ready; QoS and the rest of the explicit L2 subset remain edit-proven | Use explicit DHCP snooping, DAI, dot1x, QoS, LLDP, REP, SNMP, NetFlow, SPAN/RSPAN, and port-security commands |
| L2 resiliency + BGP | BGP, STP/RSTP, EtherChannel, LACP/PAgP, VTP, and DTP are edit-proven only for explicit IOS text commands | Use named router/switch/interface commands; do not claim topology/link synthesis or protocol convergence |
| WAN/security edge | Router ZFW is donor-backed ready; GRE, PPP, IPSec, VPN crypto-map, and CBAC are explicit-edit capable; ASA policies and multilayer switching remain report-only | Use explicit router edit commands; strict generate still needs selected-donor acceptance |
| Advanced wireless | WEP and WPA Enterprise/RADIUS are explicit-edit capable; WLC, Meraki, cellular, Bluetooth, beamforming, and guest Wi-Fi remain report-only | Keep controller/cellular/Bluetooth claims in atlas/report mode until donor-backed proof exists |
| Industrial programming | Real HTTP and Real WebSocket existing script files are donor-backed-ready for explicit edits; MQTT, Profinet, PTP, L2NAT, CyberObserver, and industrial firewall remain report-only | Use quoted device/app/file script edit commands only |
| Automation/controller | Python, JavaScript, and TCP/UDP app files are donor-backed ready through existing script-file replacement; Network Controller, Blockly, and VM/IOx remain report-only | Use quoted device/app/file script edit commands only |
| Voice/collaboration | IOS `telephony-service`, `ephone-dn`, `ephone`, and `dial-peer voice` commands are donor-backed ready; Linksys voice remains report-only | Use explicit router voice commands; do not claim broad Call Manager or phone GUI generation |
| Physical/media gaps | Report-supported atlas entries | Do not claim edit/generate support until a proof wave promotes them |

The important number is still `generate_ready=0` for the atlas gap families. That is deliberate: visibility comes first, then edit proof, then donor-backed readiness, and only then generate readiness. `donor_backed_ready` is now used for narrow explicit edit paths, not broad topology generation.

For `--parity-report`, prefer the critical parity counters when reading a scenario-level answer:
`critical_parity_donor_backed_ready_count` shows proof-linked donor readiness, while `critical_parity_generate_ready_count` only counts capabilities that are critical for the detected scenario family and generate-ready. Treat these `critical_*` counts as the release truth. The older total `parity_generate_ready_count` remains for backward compatibility, but it can include non-critical helper capabilities and should not be read as scenario-level generate readiness.

Stable CLI surfaces:

- `--explain-plan`
- `--compare-scenarios`
- `--matrix-out`
- `--coverage-report`
- `--feature-gap-report`
- `--inventory-capabilities`
- `--doctor`
- `--parity-report`
- `--acceptance-json-out`

## Curated Donor and Fixture Truth Sources

This repository keeps explicit truth sources for donor evidence and scenario regression:

- `references/curated-donor-registry.json`
- `references/scenario-fixture-corpus.json`
- `references/packettracer-feature-atlas.json`

Curated donor registry reference:

- [docs/curated-donor-registry.md](docs/curated-donor-registry.md)

The registry is not a marketing list. It is a control surface for deciding which donor classes can be trusted for which scenario families. A donor can be useful for inventory and proof while still being rejected for a larger prompt if the skeleton does not safely match the requested topology.

Current selector truth:

- a registry-backed donor can be inventory-proof without being prompt-selected
- selector output should explain the closest rejected donor class when generate is blocked
- `best_rejected_donor_class` and `primary_rejection_code` are intended to keep donor-limited refusals specific
- Home IoT readiness is only raised when the selected donor and prompt targets are both deterministic
- WAN/security readiness is only raised for explicit WAN/security intent when the selected donor carries matching WAN, security, tunnel, or multilayer runtime evidence
- Feature atlas entries are report-first; a feature can be visible in the atlas while still blocked for edit/generate.

## Known Working Scenario Set

Public examples stay text-first and review-friendly. Raw `.pkt` binaries are not committed.

These examples are not decorative screenshots. They are the public proof set for the current product contract. Each one is intended to show a scenario family that was actually exercised through donor-backed logic and then reduced into reviewable artifacts:

- screenshot
- inventory manifest
- acceptance excerpt
- parity excerpt
- decision excerpt
- runtime excerpt

This is why the examples surface matters so much in release work. It is the shortest path from a marketing claim to a falsifiable engineering artifact.

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

Hero visual for the `0.2.3` capability release surface:

- `examples/screenshots/complex_campus_master_edit_v4.png`

The gallery is treated as a known working scenario set, not just a screenshot list, and the same canonical set feeds release notes and GitHub metadata.

Canonical public proof:

- [docs/campus-donor-proof.md](docs/campus-donor-proof.md)
- [docs/home-iot-donor-proof.md](docs/home-iot-donor-proof.md)
- [docs/wan-security-donor-proof.md](docs/wan-security-donor-proof.md)
- [docs/l2-resiliency-bgp-proof.md](docs/l2-resiliency-bgp-proof.md)
- [docs/ipv4-routing-management-proof.md](docs/ipv4-routing-management-proof.md)
- [docs/l2-security-qos-proof.md](docs/l2-security-qos-proof.md)
- [docs/security-edge-deepening-proof.md](docs/security-edge-deepening-proof.md)

The campus donor proof is intentionally more specific than the gallery cards. It shows that a real donor artifact inventories correctly, but it also shows that a generalized campus prompt can still be donor-limited. That is exactly the kind of nuance the public docs should preserve.

The Home IoT donor proof is intentionally narrower than a generic smart-home claim. It shows that donor-backed registration, rule control, and wireless association are integrated only inside a constrained path with explicit targets and a selected donor.

The WAN/security donor proof is also conservative. It shows family-correct report/selection behavior, donor-backed readiness semantics, and a narrow explicit-edit subset for GRE, PPP, IPSec transform-set, and VPN crypto-map skeletons. It does not claim broad synthetic WAN/security configuration generation.

The L2 resiliency + BGP proof is IOS text only. It can append explicit `router bgp`, `spanning-tree`, `channel-group`, `vtp`, and `switchport mode dynamic` lines when the router/switch and interfaces are named. It does not create redundant links, validate STP state, prove BGP convergence, or make these capabilities donor-backed/generate-ready.

The IPv4 routing/management proof is IOS text only. It can append explicit `router ospf`, `router eigrp`, `router rip`, `ip route`, `ip helper-address`, `ip nat`, `ip ssh`, `ntp server`, and `logging host` lines when the router and interfaces are named. It does not synthesize routing designs, NAT pools, ACL policy, or convergence tests.

The L2 security/QoS proof is explicit-command only. It can append IOS-style dot1x and QoS lines when the switch, interface, class-map, policy-map, direction, and optional RADIUS target are explicit. It does not create a full NAC design, supplicant profiles, RADIUS users, or broad QoS policy from intent alone.

The security-edge deepening proof is router IOS only. It can append CBAC and ZFW line-based configuration for explicit targets. It does not mutate ASA GUI/internal state, clientless VPN, ASA service-policy, or broad security topology generation.

Generate-ready pilot design is intentionally separate from implementation:

- [docs/generate-ready-pilot-design.md](docs/generate-ready-pilot-design.md)

That document exists to define the first possible acceptance-backed `generate_ready` pilot without opening it in the current batch.

The advanced wireless proof is narrower again. It promotes only explicit WEP and WPA Enterprise/RADIUS edit semantics while keeping WLC, Meraki, cellular, Bluetooth, beamforming, and guest Wi-Fi in report-only atlas mode.

The industrial programming proof is explicit-file-edit only. It can replace an existing Real HTTP or Real WebSocket script file when the device, app, and file names are quoted and uniquely resolved. It does not create apps, files, MQTT brokers, Profinet/PTP/L2NAT workflows, or broad Industrial IoT topologies.

What the proof now tries to surface explicitly:

- a real donor exists
- inventory succeeds
- the larger generalized prompt is still refused
- the blocking layer is donor selection, not runtime
- the closest rejected donor class and rejection code should be visible in the decision payload

Classifier truth matters here too:

- shorthand campus prompts should still resolve to the `campus` family
- donor-limited campus refusal should be read as a campus selector result, not a service-heavy misclassification

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

## Release and Launch State

The npm package line is advancing to `packet-tracer-skill@0.2.3`. This release is a capability proof and readiness release, not a broad generate-ready release. The GitHub README, npm README, changelog, release notes, proof docs, and feature atlas should all say the same thing: the skill can recognize more Packet Tracer features, edit more explicit IOS/script surfaces, and report donor-backed readiness for more narrow paths, while still refusing broad unsupported generation.

So the current state is no longer "preparing an experiment." The package line is public and the `0.2.3` release freezes a real capability batch. The remaining launch ops are about making the public surface operationally complete:

- GitHub release object should match the published npm state
- About/Topics should match the README and launch wording
- Discussions should exist as the feedback intake surface
- donor proof should exist as the first post-launch technical evidence layer

That is the difference between "published" and "productized." The release can be installed from npm, but GitHub release notes, About/Topics, Discussions, and follow-up proof artifacts are what make it operationally coherent.

Recommended local validation before release:

```powershell
python .\scripts\build_examples_index.py
python -m pytest tests -q
node --check .\bin\packet-tracer-skill.js
python .\scripts\generate_pkt.py --parity-report "campus with VLAN DHCP ACL"
python .\scripts\runtime_doctor.py
```

Launch ops references:

- [docs/release-checklist.md](docs/release-checklist.md)
- [docs/publish-preview-roadmap.md](docs/publish-preview-roadmap.md)
- [docs/discovery-keywords.md](docs/discovery-keywords.md)
- [docs/github-metadata.md](docs/github-metadata.md)
- [docs/github-launch-ops-0.2.2.md](docs/github-launch-ops-0.2.2.md)
- [docs/post-launch-follow-up.md](docs/post-launch-follow-up.md)

## Azerbaijani Summary

Bu repo Cisco Packet Tracer 9.x `.pkt` faylları üçün təbii dilə əsaslanan planlama, analiz, edit, parity hesabatı və donor-backed workflow yaradır. Məqsəd sadəcə promptdan topologiya şəkli çıxarmaq deyil. Məqsəd Packet Tracer-in real fayl formatına uyğun, açılan, yoxlanıla bilən və səhv olanda səbəbini izah edən daha etibarlı skill təqdim etməkdir.

Skill promptu əvvəl scenario family və capability-lərə ayırır, sonra həmin tələbi feature atlas, curated donor registry, runtime doctor, parity report və proof docs ilə yoxlayır. Uyğun donor, runtime bridge, deterministic target və ya acceptance sübutu zəifdirsə, sistem final `.pkt` yaratmaq əvəzinə səbəbli refusal verir. Bu davranış qəsdəndir: faylı korlamaqdansa, nə çatışmadığını və növbəti ən doğru addımı göstərmək daha təhlükəsizdir.

Əsas public səthlər:

- `--explain-plan`: promptun hansı scenario family və capability-lərə çevrildiyini, hansı donor və readiness qərarlarının verildiyini göstərir.
- `--compare-scenarios`: bir neçə promptu eyni matrix üzərində müqayisə edir və hansı ailənin report-supported, edit-proven, donor-limited və ya unsupported olduğunu göstərir.
- `--parity-report`: tələb olunan capability-lərin inventory, edit, donor-backed readiness, generate və acceptance səviyyəsində vəziyyətini izah edir.
- `--feature-gap-report`: Packet Tracer 9.0-da mövcud olub skill-də hələ tam məhsullaşmamış sahələri atlas/backlog kimi göstərir.
- `--local-sample-audit-root`: istifadəçinin lokal `.pkt/.pka` nümunə qovluğunu audit edir, decode nəticələrini və capability evidence-ni çıxarır, amma raw faylları repo-ya və npm paketinə daxil etmir.
- `--doctor`: real `.pkt` runtime üçün Packet Tracer install, donor path, Twofish bridge və blocked/ready operations vəziyyətini yoxlayır.
- examples gallery və proof docs: screenshot, inventory manifest, acceptance excerpt və donor proof ilə public iddiaları yoxlanıla bilən artefaktlara bağlayır.

`0.2.3` release-in əsas dəyəri budur: skill Packet Tracer feature-lərini daha geniş tanıyır, daha çox explicit IOS/script edit path-i roundtrip proof ilə qoruyur və daha çox narrow path üçün donor-backed readiness göstərə bilir. Amma bu release hələ universal generate release deyil. `generate_ready=0` açıq saxlanılır, çünki geniş synthetic generation yalnız single-donor, deterministic inventory və acceptance JSON sübutu ilə açılmalıdır.

Hazırda ən güclü sahələr:

- campus və service-heavy lab planning, parity və reporting
- donor-backed Home IoT constrained edits
- WAN/security edge report və donor-backed readiness semantics
- WAN/security edge üçün GRE, PPP, IPSec transform-set, VPN crypto-map, router CBAC və ZFW explicit edit semantics
- IPv6/routing üçün OSPFv3, EIGRP IPv6, RIPng və HSRP donor-backed-ready subset
- IPv4 routing/NAT/IOS management üçün OSPFv2, EIGRP IPv4, RIPv2, static/default route, DHCP relay, NAT/PAT, SSH, NTP və syslog explicit edit-proven subset
- L2 security/monitoring üçün DHCP snooping, DAI, dot1x, QoS, SNMP, NetFlow və SPAN kimi explicit edit/report path-lər
- BGP və L2 resiliency üçün STP/RSTP, EtherChannel/LACP/PAgP, VTP və DTP explicit IOS edit semantics
- advanced wireless üçün WEP və WPA Enterprise/RADIUS explicit edit semantics
- automation/controller və industrial programming üçün Python, JavaScript, TCP/UDP, Real HTTP və Real WebSocket existing script-file explicit edits
- voice/collaboration üçün IOS telephony-service, ephone-dn/ephone və dial-peer voice explicit edit semantics

Hələ konservativ saxlanan sahələr:

- broad synthetic generate bütün Packet Tracer feature-ləri üçün açıq deyil
- BGP/STP/EtherChannel/VTP/DTP üçün link/topology synthesis və protocol convergence iddiası edilmir
- WLC, Meraki, cellular, Bluetooth, beamforming və guest Wi-Fi əsasən report-only qalır
- Linksys voice, Network Controller GUI, Blockly visual graph, VM/IOx və physical/media feature-lər atlasda görünür, amma edit/generate iddiası almır
- industrial MQTT, Profinet, PTP, L2NAT, CyberObserver və industrial firewall report-only qalır
- repo-local self-contained runtime readiness iddia edilmir; external bridge-assisted validation ayrıca göstərilir
- lokal `pkt_examples` və remote GitHub sample importları evidence source-dur, public curated truth və ya npm package content deyil

Hazırkı release prioriteti:

- `0.2.3` capability release-i dondurmaq və npm/GitHub ilə hizalamaq
- README, npm package, changelog, release notes və proof docs arasında terminologiya drift-ni bağlamaq
- scenario truth source, donor registry və runtime doctor contract consistency-ni qorumaq
- feature atlas üzərindən Packet Tracer-də qalan bütün boşluqları görünən backlog kimi saxlamaq
- yeni capability-ləri yalnız inventory proof, edit roundtrip proof, deterministic target resolution və donor-backed acceptance olduqda yüksəltmək

## License

This project is licensed under the MIT License.
