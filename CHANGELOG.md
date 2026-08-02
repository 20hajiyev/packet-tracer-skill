# Changelog

All notable changes to this project should be recorded in this file.

The format is intentionally simple and release-oriented.

## [0.3.0] - Unreleased candidate

### First verified generation

A prompt now produces a `.pkt` that Packet Tracer actually opens. Confirmed on
2026-08-02: `1 router 1 switch ve 3 komputer qur` produced a `9.0.0.0810` file
containing exactly `R1 <-> SW1` and `SW1 <-> PC1/PC2/PC3`, and Packet Tracer
loaded it in 40 seconds with the window title naming the file.

### Added

- `scripts/pkt_verify.py`: two-tier verification. `structural_check` is headless
  and catches dangling link endpoints, duplicate device names, undecodable
  bytes, wrong root elements and incompatible versions. `open_check` launches
  Packet Tracer and waits for the file's own window, reporting
  `opened` / `timeout` / `process_exited` / `packet_tracer_missing`.
- `scripts/usage_ledger.py`: a local, gitignored record of which donors actually
  worked, fed back into donor ranking so repeat requests try proven donors
  first. Prompts are stored as a non-reversible fingerprint, never verbatim.
  Bounded to 2000 entries, disabled with `PKT_USAGE_LEDGER=off`, and never
  load-bearing — deleting it changes nothing but donor order.
- `tests/test_pkt_verify.py`, `tests/test_usage_ledger.py`,
  `tests/test_donor_grouping.py`.

### Changed — limitations removed

- **The target version is detected, not hardcoded.** Resolution order:
  `PACKET_TRACER_TARGET_VERSION`, the installed Packet Tracer's directory name,
  the compatibility donor's `<VERSION>`, then the default. An 8.2 install now
  targets 8.2 with no configuration. The install-root name yields a three-field
  version deliberately, so a bundled sample carrying `9.0.0.0000` cannot
  outrank the user's own saves by matching a build number that was invented.
- **The Windows-only restriction is gone.** It existed because the codec needed
  a compiled bridge only ever built for Windows; the pure-Python engine removed
  that. `windows_first_runtime` is no longer raised, and a missing Packet Tracer
  executable is reported as exactly that.
- **Pruning is no longer an unsafe mutation.** `remove_link` was categorised as
  `port_reassignment` and, with `device_prune`, sat on the blocked list — so the
  safe-open profile forbade the two core operations of donor-prune generation.
  `remove_link` is now `link_prune`, and prune operations are allowed. Inventing
  structure the donor never had stays blocked.
- **The sample catalogue is version-gated.** Only the compatibility donor was
  checked before, so a 9.0-targeted run could select a 6.1 sample and emit a 6.1
  file. Observed and fixed.
- Donor groups are aligned to targets by router uplink instead of name order. A
  donor containing `Router <-> Switch` on its second switch was previously
  reported as not containing that link at all.
- `validate_open` verifies instead of announcing. It ran `subprocess.Popen` and
  printed `{"status": "launched"}` without observing anything, so a corrupt file
  reported the same result as a working one.
- `validate_external_sample_summary` uses the compatibility ladder rather than
  string equality.
- Python minimum is 3.10; the 3.14 pin applied only to the optional accelerator.

### Performance

Generation went from 200-250 s to **94 s** for a small lab. Profiling showed 340
of 349 seconds inside `decode_pkt_modern`, and 69 of the 82 calls came from
`_pkt_version` — full authenticated decrypts of entire multi-megabyte files
performed only to read `<VERSION>`.

- `pkt_codec.peek_pkt_header` decrypts only the front of a file. CTR mode is
  seekable and stage 1 reverses the buffer, so the needed plaintext prefix comes
  from the file's tail: the probe is now O(prefix), not O(file). Measured
  constant ~21 ms regardless of size, against 14.8 s for a full decode of the
  largest lab — 679x on that file, and byte-identical version strings.
  Tag verification is deliberately skipped; this is a read-only probe and
  anything that matters still goes through `decode_pkt_modern`.
- `_pkt_version` and `decode_pkt_to_root` cache on `(path, size, mtime_ns)`, so
  an edited file is re-read rather than served stale. Only immutable bytes are
  cached; callers still get their own tree to mutate.

### First open-verified generation set, and what it disproved

Running the corpus with real Packet Tracer opens produced the first evidence-backed
readiness numbers — and immediately contradicted two things this repo believed.

**Cross-group device borrowing does not work.** A target switch needing more
hosts than its aligned donor switch carries was allowed to borrow from other
donor groups. Every corpus case that borrowed failed to open (4, 5 and 7 hosts);
every case that stayed within its donor group's own hosts opened (2 and 3).
Moving a device between switch groups leaves state this code does not fix up.
Borrowing is off by default now; `PACKET_TRACER_CROSS_GROUP_BORROW=1` re-enables
it for experiments. A refusal beats a file that looks generated and will not open.

**Coverage reporting is not base-donor eligibility.** The version policy was
applied to `_existing_ranked_candidates`, which feeds both. Under the `exact`
default every bundled sample vanished and campus prompts started refusing with
"critical capability coverage is still missing" — for coverage sitting in the
catalogue all along. A sample proves a capability whether or not it can serve as
a generation base, so the policy now applies only in `_base_donor_candidates`.
Generation also got 4x faster as a side effect: 6-7 s per case instead of 24-50 s,
because the base pool is small while coverage still sees everything.

Refusal messages no longer suggest loosening the donor policy. Loosening was
measured to produce files Packet Tracer refuses, so the advice walked users into
a broken state that looked like progress. When the running build is unknown the
message asks for the one action that helps: save any lab from Packet Tracer once,
which is what teaches the skill its build.

Corpus now: **4 generate and open, 3 donor-limited, 1 correct refusal, 0
unexpected.** `refused_donor_limited` is a distinct status so a sound request the
local donor cannot serve stays countable without being mistaken for a defect.

### A corpus runner, and the five defects it found immediately

`scripts/corpus_runner.py` runs a set of prompts end to end and records what
happened: generated or refused, structural result, and optionally a real Packet
Tracer open. Its first run found five defects that 377 unit tests had not.

- **Device counts attached to the wrong device.** Two phrasings are supported,
  `3 switch` and `switch 3`, and both were pooled through `max`. The trailing
  form swallowed the next device's number, so `4 switch 1 router 8 komputer`
  asked for **eight routers** and `1 router 1 switch 2 komputer` asked for two
  switches. No test had ever asserted a multi-device count.
- **A prompt with no topology signal produced a lab.** "sebeke haqqinda melumat
  ver" — a request for information — generated a two-device file. Inventing a
  lab is worse than refusing: the user never sees that they were misread.
- **Host capacity was checked per donor switch group** rather than across the
  donor, so "1 switch and 5 PCs" was refused against a donor holding 11 PCs on
  three switches, every one of which was about to be pruned. Donor devices are
  pooled across groups now.
- **Two cables on one interface.** Ports are set from two independent places:
  surviving donor links keep their wiring, and `set_link` operations carry
  planner-chosen ports. Neither knew about the other, so `PC1` and `R1` both
  landed on `SW1 FastEthernet0/3`. `_resolve_port_conflicts` reconciles once
  over the links that will actually exist; surviving donor wiring wins because
  it is known-good.
- **Group alignment dropped donors.** With more targets than donor groups the
  reordering lost entries, and the caller then reported "supports only 0 switch
  groups" for a donor with three switches.

Refusals also name the layer that failed. When the intent plan has gaps, donor
evaluation never runs, so reporting "donor selection" with zero candidate counts
sent users to fix a donor that had never been consulted. That is
`blocked_by_intent` now, and donor messages name the donor.

Corpus: **6 of 8 generate, 1 refuses correctly, 1 known gap.** `four_switch`
needs a donor with four switch groups; none of the eligible donors has one, so
the refusal is real. Generation also got faster — the inflated device counts had
been driving much larger donor searches, and the minimal case went from 103 s to
24 s.

### Every bundled sample is readable now

18 of the 292 samples shipped with Packet Tracer 9.0 failed EAX tag
verification and were reported as undecodable. They are Packet Tracer 5.x
saves written before Twofish: qCompress output XORed byte-wise with
`(length - index)`, no cipher and no tag. `decode_pkt_legacy`,
`detect_pkt_format` and `decode_pkt_auto` handle both containers.

A further 6 decoded but would not parse. Packet Tracer writes raw control bytes
into element text — a Cisco banner delimiter is literally `banner motd ` —
which XML 1.0 forbids. `parse_pkt_xml` maps those into the Unicode private use
area and `serialize_pkt_xml` maps them back, so the round trip stays faithful
instead of silently dropping banner delimiters.

`build_sample_catalog.py` carried its own weaker `summarize_pkt` that omitted
link endpoints, which is why the committed catalogue had 1051 link records with
no `from`/`to` and the donor graph-fit filter was comparing empty strings. It
now calls `sample_catalog._summarize_pkt`.

Catalogue rebuild: **292 of 292 readable** (was 274) and **1126 links with
endpoints** (was 0). Reading those labs promoted `qos`, `cbac`, `real_http` and
`real_websocket` from report/edit level to `donor_backed_ready`. Those
capabilities were never missing — the labs proving them were unreadable.

### Topologies are no longer limited to the donor's own

Reuse-only wiring meant a chain donor could never satisfy a star request:
`3 switch, 6 PC, VLAN 10/20/30` was refused with "this donor does not contain
that device-to-device link". Missing links are now built with the same
`set_link` operation the edit path uses (`PACKET_TRACER_LINK_STRATEGY=reuse`
restores the old behaviour).

This needed three fixes, and the first attempt was rejected by Packet Tracer
outright — the two-tier verification caught it as `process_exited` rather than
reporting a false success:

- ports are claimed once. Adopting donor wiring for one link while planning
  another from the blueprint put two cables on `SW1 GigabitEthernet0/2`.
- alternatives are checked against the device's real interfaces. Incrementing
  the index invented `GigabitEthernet0/3` on a 2960-24TT, and Packet Tracer
  refused the whole file as "not compatible with this version".
- when gigabit is exhausted the allocator falls back to FastEthernet, which is
  what an engineer would do. A core switch with three uplinks and two gigabit
  ports is a real constraint, not an impossible topology.

`port_exists` and `port_capacity` count real interfaces. `_port_address_for_name`
could not serve as the existence test: it is a MEM_ADDR lookup that returns
None whenever the donor's port nodes carry no address, which made every port
look missing.

Verified: 3-switch VLAN star on a chain donor opened in 10.1 s; the simple case
still opens in 10.4 s. `structural_check` now also fails on duplicate port use.

### Host-to-VLAN distribution is defaulted, not refused

"3 switch, 6 PC, VLAN 10/20/30" reads as two hosts per VLAN. The planner refused
it while already defaulting port speeds, cable types, addressing and the VLAN IDs
themselves — and while the branch directly above already assigned department PCs
to VLANs by order. Hosts are now spread evenly with the split recorded as an
assumption. `PACKET_TRACER_STRICT_VLAN_ASSIGNMENT=1` restores the refusal.

The rule existed in both `intent_parser` and `generate_pkt`; it now lives only in
the parser.

### Leftover donor devices are now deleted

Spares were renamed `UNUSED-*` / `*-SPARE-*` and moved offscreen rather than
deleted, so a five-device request produced a twenty-device, 282 KB file. Parking
was a precaution, not a measured constraint — and with real verification in place
it could finally be tested instead of assumed.

Pruning verified against a real Packet Tracer open: **6 devices, 73 KB, opened in
17 s** (the parked equivalent took 40 s). `prune` is now the default;
`PACKET_TRACER_SPARE_STRATEGY=park` restores the old behaviour.

## [0.3.0-pre] - Runtime and donor gate

Removes the two mechanical defects that produced `generate_ready=0` for the
whole `0.2.x` line. See `docs/improvement-plan-0.3.0.md` for the audit.

### Added

- `scripts/vendor/twofish_pure.py`: vendored pure-Python Twofish, verified
  against the official 128/192/256-bit test vectors and cross-checked as
  bit-identical to the compiled bridge
- donor version compatibility ladder in `packet_tracer_env.py`
  (`exact` / `same_minor` / `same_major` / `upgradeable` / `incompatible`),
  selected by `PACKET_TRACER_DONOR_POLICY`, defaulting to `same_minor`
- `twofish_backend`, `donor_policy`, and `compatibility_tier` diagnostic fields
- `tests/test_twofish_pure.py` and `tests/test_donor_compatibility.py`

### Changed

- the compiled `_twofish` bridge is now an optional accelerator, not a
  prerequisite: `decode`, `inventory`, `edit`, and `generate` are all `ready` on
  a clean checkout with no binaries and no environment variables
- `bridge_resolution=external_env` no longer downgrades `runtime_grade` or
  raises a `using_external_bridge_only` blocker
- donor rejection messages now name the tier, the active policy, and the setting
  that would accept the donor
- minimum Python relaxed from exactly 3.14 to 3.10+; the 3.14 ABI requirement
  applied only to the compiled accelerator

### Fixed

- `tests/test_release_surface.py` referenced an undefined `readme` variable and
  failed under the strict profile; the assertions moved to the README test

### Notes

- eligible donors from a stock Packet Tracer 9.0.0 install go from **0 to 48**
  under the default policy (270 under `upgradeable`); none of the 292 bundled
  samples carry the previously-required exact build `9.0.0.0810`
- one test profile, zero skips: 306 passed without a bridge, 307 with one
  (previously 230 passed / 37 skipped, hiding one real failure)
- `generate_ready` is still `0`. The remaining blocker is now the donor
  graph-fit filter, which is reached and reports per-candidate rejection
  reasons instead of being skipped
- `package.json` stays at `0.2.3` until a publish decision is made

## [0.2.4] - Unreleased candidate

### Added

- Examples Truth 2.0 proof-card and showcase-example surface for the post-`0.2.3` capability release
- proof-readiness dashboard for ranking the next donor-backed promotion candidates
- promotion queue artifact for IPv4 routing/management and L2 resiliency/BGP readiness work
- local sample evidence board that summarizes user-supplied `.pkt/.pka` audit counts without committing raw samples
- `0.2.4` release notes draft for the next product-hardening patch

### Changed

- examples gallery and examples index now distinguish showcase examples, proof cards, local evidence, and promotion candidates
- current launch wording is being separated from historical `0.2.1`/`0.2.2` runbooks

### Notes

- this candidate does not enable broad generation
- `generate_ready=0` remains intentional
- `package.json` stays at `0.2.3` until a publish decision is made

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
