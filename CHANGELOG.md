# Changelog

All notable changes to this project should be recorded in this file.

The format is intentionally simple and release-oriented.

## [0.2.3] - 2026-05-03

### Added

- voice/collaboration edit-proven proof for IOS `telephony-service`, `ephone-dn`, `ephone`, and `dial-peer voice` command shapes
- automation/controller edit-proven proof for existing Python, JavaScript, and TCP/UDP script-file replacement
- L2 security/QoS edit-proven proof for explicit dot1x and QoS IOS switch commands
- security-edge deepening proof for explicit router CBAC and ZFW IOS commands
- L2 resiliency + BGP edit-proven proof for explicit BGP, STP/RSTP, EtherChannel/LACP/PAgP, VTP, and DTP IOS commands
- IPv4 routing/NAT/IOS-management edit-proven proof for explicit OSPFv2, EIGRP IPv4, RIPv2, static/default route, DHCP relay, NAT/PAT, SSH, NTP, and syslog IOS commands
- local user-supplied Packet Tracer corpus audit via `--local-sample-audit-root` and ignored `output/local-sample-audit.json`
- donor-backed readiness expansion for dot1x, ZFW, voice/collaboration IOS edits, and automation/controller script-file edits
- donor-backed readiness expansion for explicit OSPFv3, EIGRP IPv6, RIPng, and IPv6 HSRP edit paths
- generate-ready pilot design doc that defines the future acceptance gate without enabling broad generate
- local/cache-only GitHub sample ingestion audit for `.pkt`/`.pka` repositories, license status, decode evidence, and promotion status

### Changed

- feature atlas candidate status now promotes `ospfv3`, `eigrp_ipv6`, `ripng`, `hsrp`, `dot1x`, `qos`, `cbac`, and `zfw` only when editor roundtrip and decode-backed evidence exists
- donor-backed readiness now requires proof-linked sample, decode, parser, and editor roundtrip evidence
- remote samples with unknown license metadata now stay `reference_only`; permissive-license samples still require decode and inventory validation before curated donor eligibility
- local `pkt_examples` evidence is now separated from public curated truth; raw `.pkt/.pka` files remain excluded from git and npm
- README and proof docs now describe `0.2.3` as a capability release, not an unpublished candidate
- ASA service-policy, clientless VPN, Linksys voice, Network Controller GUI, Blockly, VM/IOx, and broad physical/media workflows remain report-only

### Notes

- `0.2.3` is a capability proof/readiness release, not a broad generation release
- `generate_ready=0` remains intentional until donor-backed acceptance evidence exists
- broad NAC, QoS, ASA, and security topology generation remains blocked

## [0.2.2]

### Added

- advanced wireless proof surface for WEP and WPA Enterprise/RADIUS edit-proven behavior
- wireless advanced feature atlas coverage for WLC, Meraki, cellular, Bluetooth, beamforming, guest Wi-Fi, WEP, and WPA Enterprise
- runtime README guidance for generic Twofish bridge paths and search-root fallback

### Changed

- package version advanced to `0.2.2` for the README/runtime cleanup and advanced wireless feature wave
- README runtime setup no longer presents a user-specific local path as the default bridge location
- advanced wireless prompts now classify into the `wireless_advanced` family without drifting into `service_heavy`
- WEP and WPA Enterprise/RADIUS are represented as edit-proven where explicit deterministic edit targets exist, while broader WLC/cellular/Bluetooth/Meraki scope remains report-only

### Notes

- `0.2.2` remains conservative: no broad synthetic advanced wireless generation is claimed
- runtime messaging remains Windows-first and explicit about external bridge-assisted validation

## [0.2.1]

### Added

- npm tarball hardening for the public package surface
- launch announcement draft aligned with the current public release wording

### Changed

- package version advanced to `0.2.1` because `0.2.0` is already published on npm
- npm package contents now exclude caches, generated previews, and non-essential screenshot payloads
- public release references now consistently point to the `0.2.1` patch release artifacts

### Notes

- `0.2.1` is the publishable patch release for the conservative public preview surface
- runtime messaging remains Windows-first and explicit about the external bridge-assisted validation path

## [0.2.0]

### Added

- release engineering surface for CI, contributing, issue templates, citation metadata, and release checklist
- keyword/discovery-oriented README rewrite aligned with current CLI and decision contracts
- known working scenario set positioning for public examples
- runtime truth, discovery keyword, GitHub metadata, publish-preview roadmap, and curated donor registry docs
- seeded curated donor registry entries derived from known working public example artifacts
- checked-in Packet Tracer template fallback assets for hermetic builder coverage
- hero demo plan and `0.2.0` release notes draft artifacts for conservative launch prep

### Changed

- package metadata expanded for publish-readiness and host/discovery coverage
- examples gallery language aligned with the scenario fixture corpus and acceptance excerpts
- CI now includes parity-report and runtime doctor smoke steps
- selected donor summaries now distinguish registry-backed versus inferred evidence
- CI now cancels superseded in-progress runs on the same ref
- placeholder-backed template devices are synthesized into Packet Tracer-native fallback nodes
- README, GitHub metadata, release checklist, and roadmap now align around the `0.2.0` public preview message

### Notes

- runtime doctor and scenario decision surfaces remain Windows-first for real `.pkt` runtime
- repo-local bridge is still intentionally not bundled by default
- `0.2.0` is a conservative launch-prep release surface; npm publish and GitHub release remain a short follow-up batch
