# `packet-tracer-skill` 0.3.0 Improvement Plan — Unblock the Product

> Written 2026-08-01 after a fresh empirical audit of the repo, the local Packet
> Tracer 9.0.0 install, and the full bundled sample corpus. This plan supersedes
> the `0.2.4` "UX freeze + guided proof workflow" direction.
>
> **Status: Phases 0, 1 and 2 are implemented and verified.** Phase 1.2 (the 18
> undecodable samples) and Phases 3–5 remain open. See §8 for what landed.

---

## 1. Executive Summary

The repo is 22,875 lines of Python with 267 tests, 14 proof documents, a feature
atlas of 87 features, a proof-readiness dashboard, and a curated donor registry.

And `generate_ready` is `0`. It has been `0` for the entire `0.2.x` line.

The `0.2.x` work assumed that was a *capability* problem — that more donors, more
proof cards, more readiness waves, and better refusal messaging would eventually
move features up the support ladder. **That assumption is wrong.** The audit below
shows `generate_ready=0` is produced by two mechanical defects, both fixable in
days, not quarters:

1. The runtime depends on a **compiled C binary that is not in the repo and cannot
   be shipped on npm**. Every operation except `validate_open` reports `blocked`
   on a clean checkout — including on this machine, which has a working Packet
   Tracer 9.0 install.
2. The donor version gate is an **exact build-string equality check** against
   `9.0.0.0810`. Zero of the 292 Cisco sample saves bundled with Packet Tracer 9.0
   carry that build string. The gate is arithmetically unsatisfiable against the
   corpus the architecture is designed to consume.

Neither defect is visible from inside the current test suite, because the tests
that would catch them are skipped by default, and a large share of the remaining
tests assert on **prose strings inside markdown files** rather than behavior.

`0.3.0` should stop adding surface and start removing the blockers.

---

## 2. Evidence

Everything in this section was executed against this checkout on 2026-08-01.

### 2.1 The runtime is blocked by a misplaced file, not by a missing capability

Clean checkout, no environment overrides:

```
runtime_grade      : partially_ready
capability_impact  : inventory=blocked  decode=blocked  edit=blocked
                     generate=blocked   validate_open=ready
twofish_load_status: missing
donor_status       : missing  ("candidates found, but none could be decoded")
```

The same command, with `PKT_TWOFISH_LIBRARY` pointed at a `_twofish.cp314-win_amd64.pyd`
that already exists in a sibling scratch folder (`tmp_twofish/`):

```
twofish_load_status: ok
donor_status       : ok        donor_version = 9.0.0.0810
capability_impact  : inventory=ready  decode=ready  edit=ready
                     generate=ready   validate_open=ready
runtime_grade      : partially_ready   <-- unchanged, by policy only
```

Every capability flips to `ready`. `runtime_grade` stays `partially_ready`
**solely** because `bridge_resolution == "external_env"`, which is a rule the repo
imposes on itself in `docs/runtime-truth.md` — not a technical limitation.

The implication: `docs/runtime-truth.md`, the `bridge_resolution` field, the
`default gate` / `strict gate` split in `tests/conftest.py`, and a meaningful part
of the README exist to *narrate* a blocker whose entire cause is that a 100 KB
compiled artifact lives in the wrong directory and cannot legally ride along in an
npm tarball.

### 2.2 The donor version gate cannot be satisfied

Decoded all 292 `.pkt` files under
`C:\Program Files\Cisco Packet Tracer 9.0.0\saves` and extracted `<VERSION>`:

| Version family | Count |
|---|---:|
| 7.x | 137 |
| 6.x | 58 |
| **9.0.0.x** | **48** |
| 8.x | 27 |
| 5.x | 4 |
| decode failure | 18 |
| **9.0.0.0810 (the required build)** | **0** |

The 48 files in the 9.0 family carry `9.0.0.0000`, `9.0.0.4178`, `9.0.0.0112`, and
`9.0.0.0172`. **None** carry `9.0.0.0810`.

`9.0.0.0810` appears only in files *saved by this machine's own Packet Tracer*
(the seven labs in `~/Downloads` all report `9.0.0.0810`).

The gate itself is a single string comparison, in exactly two places:

```python
# scripts/packet_tracer_env.py:310 and :339
if donor_version != target_version:
    ...  status="version_mismatch"
```

So the documented architecture — *"installed Packet Tracer sample saves are the
primary prototype source"* (`SKILL.md`) — is wired to a donor pool that its own
gate rejects 100% of. `SKILL.md` even names the FTP sample as the preferred donor;
that file is `5.3.0.0011`.

This is the actual reason `generate_ready=0`. No amount of donor curation, proof
cards, or promotion queues can move it while this gate stands.

### 2.3 The test suite is currently red, and nobody knows

Strict profile with the bridge resolved:

```
PKT_REQUIRE_TWOFISH_TESTS=1 python -m pytest tests -q
→ 1 failed, 266 passed
```

```
tests/test_release_surface.py:311: NameError: name 'readme' is not defined
```

This was introduced in the last `0.2.4` batch. It shipped because that session
could not run `pytest` and validated with syntax checks and CLI smokes instead.
The default profile hides it: without the bridge the suite reports green with 37
skips, and this particular test is inside the skipped-adjacent surface.

### 2.4 A large share of the test suite tests prose, not behavior

`tests/test_release_surface.py` is 436 lines and reads largely like this:

```python
assert "Fifth Donor-Backed Edit Readiness Wave" in feature_gap_atlas
assert "closest rejected donor class" in follow_up
assert "try this command: `set R1 ospfv2 1 network" in gallery
assert "does not make dot1x or QoS `generate_ready`" in l2_security_qos_proof
```

These assert that specific marketing sentences exist in specific markdown files.
They cannot fail when the product breaks and cannot pass when the product is
fixed — they only fail when someone edits prose. They are the reason the docs
have calcified into 14 near-duplicate "proof" files that no one can safely
consolidate.

### 2.5 The codec cannot read 6% of the corpus

18 of 292 bundled samples fail with `EAX authentication tag verification failed`,
across all version families (`HTTPS.pkt`, `TFTP.pkt`, `QoS.pkt`, `SNMP_Router.pkt`,
`Outside_Nat.pkt`, …). `pkt_codec.py` implements only `*_pkt_modern`. There is at
least one additional container variant in the wild that the codec does not model —
and several of those files cover exactly the capabilities the feature atlas lists
as unproven (QoS, SNMP, NAT, TFTP).

### 2.6 Structural debt

| File | Lines | Note |
|---|---:|---|
| `scripts/generate_pkt.py` | 4,361 | CLI + planner + validator + reporter + 40-key JSON assembly |
| `scripts/coverage_matrix.py` | 1,812 | |
| `scripts/pkt_editor.py` | 1,703 | |
| `scripts/intent_parser.py` | 1,657 | |
| `scripts/pkt_builder.py` | **15** | `SKILL.md` presents this as "builds Packet Tracer XML from a blueprint" |

`--explain-plan` returns a **40-key** top-level JSON object. `user_summary` was
added in `0.2.4` to make that legible, which is treating the symptom.

Outside the repo, the working directory holds 22 abandoned scratch directories
(`pkt_impl`, `pkt_skill_work`, `pkt_skill_test3`, `tmp-skill-bootstrap-2`, …)
totalling ~160 MB, three of which contain the only copies of the Twofish binary
the product needs.

---

## 3. Diagnosis

> The `0.2.x` line optimized **honesty about being blocked** instead of
> **being unblocked**. Every mechanism added — runtime grades, proof cards,
> readiness waves, refusal messaging, the promotion queue — is a high-quality
> answer to "why can't I generate?" None of them change the answer.

Three false blockers, in dependency order:

| # | False blocker | Real cause | Cost to fix |
|---|---|---|---|
| B1 | "Runtime is not repo-local ready" | ctypes dependency on an unshippable C extension | ~1 day |
| B2 | "No compatible donor exists" | exact-build string equality on `<VERSION>` | ~1 day |
| B3 | "Features are not proven" | tests assert prose; no behavioral acceptance corpus | ~3 days |

B1 gates B2 (you cannot read a donor's version without the codec). B2 gates B3
(you cannot prove generation without an eligible donor). All three gate every
feature in the atlas.

---

## 4. Plan

### Phase 0 — Stop the bleeding *(half a day)*

- **P0.1** Fix `tests/test_release_surface.py:311` (`readme` undefined). Repo is red.
- **P0.2** Add a CI job that runs the **strict** profile with a resolved bridge, so
  a red suite can never again be reported as green.
- **P0.3** Move the workspace scratch directories under a single ignored
  `.scratch/` root, or delete them. Preserve `tmp_twofish/` until Phase 1 lands —
  it currently holds a load-bearing artifact.

Exit: `pytest -q` green in both profiles; `git status` clean.

### Phase 1 — Make the runtime self-contained *(1–2 days)*

**P1.1 Vendor a pure-Python Twofish.**
Twofish is unpatented and public-domain by design; a correct pure-Python
implementation is ~250 lines (key schedule + MDS/RS matrices + h-function + 16
Feistel rounds). Ship it as `scripts/vendor/twofish_pure.py`, verified against the
three official Twofish book vectors (128/192/256-bit) already present in
`vendor_twofish.py::self_test`.

`pkt_codec._twofish_cls()` becomes: try the compiled bridge (fast path, keep it if
present) → fall back to pure Python. No environment variable required for
correctness; the binary becomes an optional accelerator.

Performance is the only real risk. A 2.5 MB lab decodes to ~2.5 MB of XML ≈ 160k
blocks; EAX costs roughly 2 block-ops per block (CTR + OMAC), so ~320k Twofish
block encryptions. Budget: pure Python at ~20–40 µs/block ⇒ 6–13 s per file.
Mitigations, in order: precompute the key-dependent S-box as four 256-entry
`int` tables at key-schedule time (the key is a constant `0x89 * 16`, so this can
be computed **once, ever, and frozen into the module as a literal table**); operate
on `int.from_bytes` words rather than per-byte; keep the compiled bridge as the
opt-in fast path for bulk corpus scans.

**P1.2 Model the second container variant.**
Investigate the 18 EAX failures. Hypothesis order: (a) a different key/IV for
pre-8.x saves, (b) a stage-2 variant, (c) `.pka`-style activity wrapper. Add
`decode_pkt_auto()` that tries known variants and reports which matched.

**P1.3 Delete the ceremony that B1 created.**
Once the codec always works: remove `bridge_resolution`, collapse the default/strict
test profiles into one, and reduce `docs/runtime-truth.md` to a short note about
Packet Tracer installation requirements. This deletes code, docs, and test surface.

Exit: `python scripts/runtime_doctor.py` on a clean checkout with no env vars set
reports `decode=ready`, `inventory=ready`, `edit=ready`. Zero skipped tests.

### Phase 2 — Make the donor gate satisfiable *(1 day)*

**P2.1 Replace exact-build equality with a compatibility ladder.**
Introduce one function, used by both call sites in `packet_tracer_env.py`:

```python
def donor_compatibility(donor_version: str, target_version: str) -> Compatibility:
    """exact | same_minor | same_major | upgradeable | incompatible"""
```

Policy proposal (configurable via `PACKET_TRACER_DONOR_POLICY`):

| Tier | Meaning | Default |
|---|---|---|
| `exact` | build strings identical | accept |
| `same_minor` | `9.0.0.*` — same schema generation, different build | **accept (new)** |
| `same_major` | `9.*` | accept with a recorded assumption |
| `upgradeable` | `6.x`–`8.x`; Packet Tracer upgrades these on open | accept only behind `--allow-legacy-donor` |
| `incompatible` | `5.x` and below | reject |

Effect on this machine: eligible bundled donors go **0 → 48** immediately, with no
new donor curation and no external downloads.

**P2.2 Validate the policy empirically, not by assertion.**
Round-trip each of the 48 `9.0.0.x` donors: decode → re-encode → byte-compare, then
decode → mutate → encode → open in Packet Tracer via the existing `--validate-open`
path. A donor is *eligible* only if Packet Tracer actually opens the mutated output.
That replaces the current curated-registry-by-declaration with measurement.

**P2.3 Retire the version-freeze language.**
`SKILL.md`'s "do not downgrade", "do not use a legacy fallback", "stop with a
blocking error instead of switching versions" rules were correct defenses against
the 5.3 fallback bug. With a real compatibility ladder they become
counterproductive. Rewrite as: *donor tier is chosen by policy, recorded in the
plan output, and surfaced as an assumption.*

Exit: `--explain-plan` for the standard campus prompt selects a donor and reports
`allow_generate: true` for at least one scenario family.

### Phase 3 — Prove generation with a real acceptance corpus *(3–4 days)*

**P3.1 Build a golden corpus.** 12–15 prompts spanning the archetypes the atlas
already names (campus/core, router-on-a-stick, DHCP, wireless, home IoT, service
heavy). For each: prompt → generated `.pkt` → decoded XML snapshot → an
`--validate-open` result.

**P3.2 Replace prose assertions with corpus assertions.** Delete the ~200
`assert "<sentence>" in <markdown>` checks in `test_release_surface.py` and friends.
Keep only structural doc checks (links resolve, no absolute user paths, no
mojibake). Every deleted prose assertion is replaced, where it mattered, by a
corpus case.

**P3.3 Promote features on evidence.** A feature reaches `generate_ready` when a
corpus case that exercises it opens cleanly in Packet Tracer. `feature_atlas.py`
reads corpus results instead of hand-maintained JSON status fields.

Exit: `generate_ready > 0`, backed by files that Packet Tracer opens.

### Phase 4 — Shrink the surface *(2–3 days, can run parallel to Phase 3)*

- **P4.1** Split `generate_pkt.py` (4,361 lines) into `cli.py` (argparse + dispatch
  only), `planner.py`, `donor_selection.py`, `reporting.py`. No behavior change; the
  40-key JSON contract is preserved verbatim and locked by a schema test.
- **P4.2** Either implement `pkt_builder.py` as `SKILL.md` describes, or delete it
  and correct `SKILL.md`. Right now the documented "XML builder" is a 15-line
  passthrough to `pkt_transformer`.
- **P4.3** Collapse the 14 `docs/*-proof.md` files into one generated
  `docs/capability-evidence.md`, emitted by the corpus runner. Proof documents
  should be *output*, not hand-written input.
- **P4.4** Nest the JSON contract: `{plan, donor, decision, diagnostics, guidance}`
  instead of 40 flat keys. Keep a flat view behind `--flat-json` for one release.

### Phase 5 — Make it pleasant to use *(2 days)*

The user-facing complaint underneath all of this is *"I don't know what to type,
and I don't know why it said no."*

- **P5.1** One verb-first CLI: `pkt doctor`, `pkt plan "<prompt>"`,
  `pkt build "<prompt>" -o lab.pkt`, `pkt edit lab.pkt "<prompt>"`,
  `pkt inspect lab.pkt`. The current interface is a single script with ~30 flags.
- **P5.2** Human output by default, `--json` for machines. Today it is the reverse,
  which is why `user_summary` had to be bolted onto the JSON.
- **P5.3** First-run bootstrap: on first invocation, detect Packet Tracer, pick a
  donor, cache the choice in `~/.pkt/config.json`, and print what it found. No
  environment variables in the happy path.
- **P5.4** Refusals become actionable: not *"blocked by runtime, donor, or bridge
  readiness"* (three possibilities), but *"Donor `FTP.pkt` is version 5.3.0.0011.
  Run `pkt doctor --list-donors` — 48 compatible donors are available."*

---

## 5. Sequencing and Risk

```
P0 ──► P1 ──► P2 ──► P3 ──► generate_ready > 0
              │
              └────► P4 (parallel, mechanical)
                     P5 (parallel, after P2)
```

| Risk | Likelihood | Mitigation |
|---|---|---|
| Pure-Python Twofish too slow for 6 MB labs | medium | frozen S-box tables; keep compiled bridge as opt-in accelerator; measure before committing |
| `9.0.0.x` donors are not actually schema-compatible | medium | P2.2 measures with real Packet Tracer opens instead of assuming |
| Deleting prose tests loses a real invariant | low | replace with structural link/encoding checks; the behavioral ones move to the corpus |
| `generate_pkt.py` split breaks a consumer | low | JSON schema test locks the contract before the split |

## 6. What This Plan Deliberately Does Not Do

- Does not add a new Packet Tracer capability wave.
- Does not add proof documents, dashboards, or readiness queues — it removes them.
- Does not publish to npm. Publishing is a separate decision after Phase 3.
- Does not adopt PTBuilder live deploy or external donor imports.

## 7. Success Criteria for `0.3.0` (targets)

<a id="section-8"></a>

## 8. Implementation Log

### Landed

**P0.1** — `tests/test_release_surface.py:311` referenced an undefined `readme`.
The three assertions moved into the README test, where the variable exists.

**P1.1** — `scripts/vendor/twofish_pure.py`: pure-Python Twofish, ~300 lines.
Key-dependent S-box and MDS multiply folded into four 256-entry word tables at
key-schedule time; round function written longhand to avoid CPython call
overhead; `g(rol32(r1,8))` folded into permuted lookups so the rotate never
happens. Measured 20.4 → 13.8 µs/block after inlining.

Verification: all three official test vectors pass, and 300 random
key/block pairs across 128/192/256-bit keys are bit-identical to the compiled
bridge. Real labs round-trip semantically (`decode(encode(decode(x))) == decode(x)`):
a 279 KB lab in 0.65 s, a 2.8 MB lab in 12.6 s.

`pkt_codec._twofish_cls()` now prefers the compiled bridge and falls back to the
pure engine, exposing the choice through `twofish_backend()`.

Note: the cipher runs over the *qCompressed* payload, not the raw XML, so the
runtime cost is far below the estimate in §5 — a 6.2 MB XML lab is only a 2.8 MB
cipher input.

**P1.3** — `bridge_resolution=external_env` no longer downgrades `runtime_grade`
or raises `using_external_bridge_only`. Python minimum relaxed from exactly 3.14
to 3.10+, since the ABI pin belonged to the accelerator alone. `runtime-truth.md`
rewritten around `twofish_backend`. The two test profiles collapsed into one:
nothing is skipped for lack of a bridge.

**P2.1** — `donor_compatibility()` / `donor_tier_is_accepted()` /
`get_donor_policy()` in `packet_tracer_env.py` replace the two exact-equality
checks. Candidate scanning now prefers the strictest qualifying tier rather than
the first match, and rejection messages name the tier, the policy, and the
setting that would accept the donor.

### Measured Effect

| | Before | After |
|---|---|---|
| Clean checkout, no env vars | `decode/inventory/edit/generate` all **blocked** | all **ready**, `runtime_grade=ready` |
| Eligible bundled donors (default policy) | **0** of 292 | **48** of 292 (270 under `upgradeable`) |
| Test suite, no bridge | 230 passed, 37 skipped, 1 hidden failure | **306 passed, 1 skipped** |
| Test suite, with bridge | 266 passed, 1 failed | **307 passed, 0 skipped** |
| Required setup | compiled `.pyd` + 2 env vars | none |

### Still Open

- **P1.2** — 18 of 292 bundled samples still fail EAX tag verification. A second
  container variant is unmodelled.
- **P3–P5** — unchanged from the plan above.
- **The real blocker is now visible.** With a compatible donor resolved and no
  intent gaps, `--explain-plan` reaches donor selection and reports
  `filtered: 19` with concrete reasons: *"donor graph has no reusable link pairs
  for the requested topology"*, *"sample reuses too little of the requested link
  skeleton"*. Before these changes that layer was never reached. The graph-fit
  heuristics in `_filter_candidates_for_blueprint` are the next thing to fix.
- **A reporting bug worth fixing early.** When the intent plan has blocking gaps,
  donor evaluation is skipped entirely, but `scenario_generate_decision` still
  reports `what_failed: "donor selection"` with `candidate_counts` all zero. The
  user is told the donor failed when the prompt was actually incomplete.

## 9. Original Success Criteria

1. Clean checkout, no environment variables, no compiled binary: `decode`,
   `inventory`, and `edit` all report `ready`.
2. One test profile. Zero skipped tests. Green.
3. At least 40 eligible donors discovered from a stock Packet Tracer 9.0 install.
4. `generate_ready >= 5`, each backed by a `.pkt` that Packet Tracer opens.
5. `generate_pkt.py` under 1,000 lines.
6. `docs/` under 8 hand-written files.
7. A new user reaches a generated, opening `.pkt` in **one** command.


---

## Open investigation: why cross-group borrowing breaks a file

**Isolated, mechanism unknown.** Letting a target switch take hosts from another
donor switch group produces files Packet Tracer rejects with the generic "not
compatible with this version". Borrowing is disabled by default
(`PACKET_TRACER_CROSS_GROUP_BORROW=1` re-enables it for experiments).

The cause is isolated rather than merely correlated. A control lab with **no
router and no borrowing** (1 switch, 3 PCs) opens, so pruning the router is safe;
the variable that matters is the borrow.

| Case | Hosts on one switch | Borrowed | Opens |
|---|---:|---|---|
| minimal (router + 3 PCs) | 3 | no | yes |
| campus star (6 PCs / 3 switches) | 2 | no | yes |
| server lan | 3 | no | yes |
| no-router control (3 PCs) | 3 | no | yes |
| hc4 | 4 | yes | no |
| hosts_only | 5 | yes | no |
| vlan_uneven | 4 | yes | no |

Ruled out so far, by comparing a borrowing file against a working one:

- **link `MEM_ADDR` mismatch** — present in *working* files too, so Packet Tracer
  does not require link memory addresses to resolve to a device
- **orphaned `save-ref-id` references** — none in either file
- **devices missing from `PHYSICALWORKSPACE`** — every device appears in both
- **physical container hierarchy** — a borrowed PC sits under the same
  `Corporate Office` node as a native one
- **dangling link endpoints and duplicate ports** — the structural checker passes

### Resolved: the boundary is created *host* links

Diffing a borrowed host against its donor original showed the device subtree is
mutated identically to a native host — name and X/Y only. The corruption is not
in the device.

Classifying every generated link as donor-original or created gave a clean split:

| File | Created links | Opens |
|---|---|---|
| minimal, two_switch_chain, server_lan, no-router control | none | yes |
| campus_star_vlan | `Switch+Switch` | yes |
| borrowing case | `Pc+Switch` x2 | no |

**A link between infrastructure devices can be created; a host's connection
cannot.** `_link_may_be_created` enforces that, so `PACKET_TRACER_LINK_STRATEGY=create`
can still build switch uplinks while a topology needing a new host connection is
refused with a specific reason instead of producing a file that will not open.

This also explains borrowing: a borrowed host always needs a created connection
to its new switch, so borrowing can never work as long as this holds. It stays
disabled, but the general rule is the useful artefact — any prompt needing a new
host link was previously getting a broken file, not just borrowing ones.

Still unexplained is *why* Packet Tracer treats host connections differently.
The link XML written for a created host link is structurally the same as for a
created switch link, and the stale `FROM_DEVICE_MEM_ADDR` values are mismatched
in working files too, so that is not the discriminator.


---

## Verified: the donor does not cap topology size

Two experiments at the XML level, each confirmed by a real Packet Tracer open:

| Experiment | Result |
|---|---|
| Duplicate a switch (fresh `SAVE_REF_ID`, `MEM_ADDR`, name, position) + a created switch-to-switch link | **opens**, 16.7 s |
| Duplicate a whole group: switch + 4 hosts + the donor links joining them | **opens**, 16.5 s |

Together with the earlier finding on created links, a consistent rule emerges:

> Packet Tracer accepts structures that **replicate** an arrangement the donor
> already has, and rejects **novel host attachments**.

| Operation | Safe |
|---|---|
| copy a working unit (switch + hosts + their links) | yes |
| create a link between infrastructure devices | yes |
| move a host onto a different switch | no |
| create a link to a host | no |

### Implementation status

`duplicate_device` and `duplicate_group` exist in `pkt_editor` and are emitted by
the planner when the topology needs more switch groups than the donor has. The
end-to-end path is **not finished**: after cloning, workspace validation reports
`Generated device SW1 physical leaf name is SW4`, so the rename step and the
cloned physical leaf are still not agreeing.

The additions are inert for topologies that already worked — they only fire on
the shortfall branch, which previously refused outright — and the corpus is
unchanged at 4 generated, 3 donor-limited, 0 unexpected.

### Physical workspace: resolved

The clone's physical leaf now survives the rename, and Packet Tracer stopped
reporting corrupted workspace data. Three separate defects, each found by
reading the error Packet Tracer actually gave:

1. `_duplicate_device` never called `_clone_physical_leaf`, so the clone kept
   pointing at the original's leaf. Renaming the clone then renamed the
   original's leaf — exactly what `Generated device SW1 physical leaf name is
   SW4` was reporting.
2. Nested `UUID_STR` values inside the copied subtree were reused verbatim, and
   the new identifier was a bare hash rather than a braced GUID. Packet Tracer
   answered with "File contains corrupted Physical Workspace data".
3. `WORKSPACE/PHYSICAL` is a comma-separated list written **without a space**
   after the comma. Joining with `", "` made the leaf token parse as `" {uuid}"`.
   The identifier also has to be a real version-4 GUID: the donor's all carry
   the `4` version nibble and an `8`-`b` variant nibble.

After those, the physical workspace validates and the error returns to the
generic "not compatible with this version".

### Resolved: operation order

The generator's duplicate differed from the working experiment in *when* it ran.
The experiment duplicated a group after every other mutation, from a device
already carrying its final name. The generator duplicated first, from donor
names, and renamed the copy afterwards — which Packet Tracer refused.

Moving duplication to the end exposed three further mismatches, each visible
once the order was right:

1. The hosts being cloned were chosen by donor name, and those particular hosts
   were on the same plan's prune list. The clone copied devices about to be
   deleted.
2. The seed was picked as the donor group with the most members, which maps onto
   the core switch — the one that ends up carrying no hosts at all. The seed has
   to be chosen by *surviving* hosts, at emit time.
3. The clone's uplink was emitted by the earlier link pass, so it ran before the
   clone existed and did nothing. The new switch had hosts and no path to the
   rest of the topology.

**`four_switch` now opens in 10.4 s** — four switches built on a three-switch
donor, 14 devices, 12 links, fully connected. Group duplication is on by
default; `PACKET_TRACER_GROUP_DUPLICATION=off` restricts topologies to the
donor's own switch count.

Corpus: 5 generated, 2 donor-limited, 1 correct refusal, 0 unexpected.


---

## Two plausible improvements, both reverted

Both changes below looked like clear wins, both passed the structural checker,
and both stopped files opening in Packet Tracer. Only the open test caught them.

**Hosts on the core switch.** With two switches the planner put every host on
the access switch and left the core empty — wasteful, and no donor switch can
supply seven hosts. Letting the core carry hosts too gave a tidy 4/3 split.
`two_switch_chain`, which had been opening, stopped opening. A hostless core is
apparently the arrangement Packet Tracer accepts.

**Kind-aware group matching.** Alignment ranked donor groups by distance from
the router, so a target needing four PCs could land on the donor's three-PC
switch while two four-PC groups sat unused. Matching by device kind fixed
`vlan_uneven` — and `four_switch` stopped opening.

Both are reverted. `vlan_uneven` is donor-limited again, which is the honest
state: a case that opens outranks a case that merely generates.

### Verified baseline

Every generated file opens:

| Case | Result |
|---|---|
| minimal, two_switch_chain, campus_star_vlan, four_switch, server_lan | **opened** |
| hosts_only | donor-limited: 5 hosts on one switch, the donor's richest group has 4 |
| vlan_uneven | donor-limited: 4 hosts land on a switch the donor gives 3 |
| no_devices | correctly refused |

5 generated, **5 opened**, 2 donor-limited, 0 unexpected.

### What this says about the remaining gaps

`hosts_only` is a real limit under the measured rule: a host cannot take a
created connection, so a target switch cannot carry more hosts than its donor
group has. Group duplication adds switches, not hosts to an existing switch.

Closing it needs either a donor whose richest group is large enough, or an
understanding of *why* Packet Tracer rejects a created host link — which is
still unexplained and is the highest-value thing left to learn.


---

## Solved: why a created host link was rejected

It was never the endpoint kind. Rebuilding an *existing*, working host link with
the same devices and the same ports left exactly five fields different from the
original — `LENGTH` and the four `*_MEM_ADDR` values. Building the same link
with those four **omitted** opens in Packet Tracer (13.4 s).

Link MEM_ADDRs are runtime pointers from the session that saved the file. In
working donors they resolve to no device at all. Writing invented values into a
*new* link is what Packet Tracer rejects; leaving the fields out is fine.

`_ensure_link` no longer writes them on a newly created link, and the
infrastructure-only restriction on link creation is gone.

The repo's own workspace validator had to be corrected too: it required
`FROM_DEVICE_MEM_ADDR` and `TO_DEVICE_MEM_ADDR` on every link and so rejected
files Packet Tracer accepts. It now only objects to a reference present on one
end and missing on the other.

Baseline holds after the change: 5 generated, **5 opened**, 2 donor-limited,
0 unexpected.

### What this opens up

The two remaining gaps are host-capacity limits — a target switch wanting more
hosts than its donor group has. With host links now creatable, the path is
duplicating a host and linking it, the same way group duplication already adds
switches. That is the next step, and it should close `hosts_only` and
`vlan_uneven` together.

It also means the two changes reverted earlier may be worth retrying, since both
failed while `_ensure_link` was still inventing MEM_ADDRs — but only with an
open test, one at a time.


---

## Corpus complete

Every case now behaves correctly, and every generated file opens in Packet
Tracer:

| Case | Devices | Links | Result |
|---|---:|---:|---|
| minimal | 6 | 4 | opened |
| two_switch_chain | 8 | 6 | opened |
| campus_star_vlan | 11 | 9 | opened |
| four_switch | 14 | 12 | opened |
| server_lan | 6 | 4 | opened |
| hosts_only | 7 | 5 | opened |
| vlan_uneven | 11 | 9 | opened |
| no_devices | — | — | correctly refused |

**7 generated, 7 opened, 0 unexpected.**

The last two gaps closed with `duplicate_host`: when a target switch needs more
hosts than its donor group has, a host is cloned from that group and linked to
the switch. It only works because new links no longer carry invented MEM_ADDR
values — the same finding that removed the infrastructure-only restriction.

Three duplication operations now exist, each verified against a real open:

| Operation | Adds |
|---|---|
| `duplicate_device` | a bare infrastructure device |
| `duplicate_group` | a switch with its hosts and their links |
| `duplicate_host` | one host attached to an existing switch |

All three must be emitted **after** the rename and prune pass, from devices
already carrying their final names. That ordering is not incidental: emitting
them first and renaming the copies afterwards produces files Packet Tracer
refuses.

The donor now constrains which device *models* are available, not how large a
topology can be.


---

## Corpus widened to the capability surface

Five cases added beyond plain topology, covering what the skill advertises but
had never been run end to end.

| Case | Result |
|---|---|
| vlan_explicit_split | opened — explicit per-VLAN host counts |
| router_dhcp | opened — router DHCP pool |
| server_services | opened — DNS and HTTP on a server |
| management_telnet | capability gap |
| wireless_home | donor-limited |

**10 generated, 10 opened, 0 unexpected.**

### Two new gaps, correctly separated

`wireless_home` is **donor-limited**: the local donor is a wired campus lab with
no wireless router, and a device model the donor lacks cannot be cloned into
existence. A richer donor fixes it.

`management_telnet` is a **capability gap**, which is a different thing: the
parser recognises `management_vlan` and `telnet` and produces no operations for
them, so generation has nothing to apply. A richer donor would not help. The
corpus reports it as `refused_capability_gap` so the two never get confused.

The refusal used to read "critical capability coverage is still missing", which
sent people looking for donor or runtime problems. It now names the capabilities.

### Also fixed

Host duplication reached only devices attached to a switch group. Devices that
hang off no switch took a different path and still refused — "1 wireless router
2 laptop" failed on the donor's single laptop. Standalone targets now clone too.


---

## Dependency and limitation audit

Re-measured what the skill actually requires. Three findings, all fixed.

### The one-time bootstrap is gone

The target build was read from a lab the install had already saved. A user who
had never saved anything got a three-field release (`9.0.0`) from the install
directory name -- and under the `exact` policy a three-field target matches
**nothing**, not even a genuine lab written by that very install. A fresh
machine could not generate at all.

The binary knows its own build. Measured on 9.0.0: `PacketTracer.exe` reports
`9.0.0.0810` in its version resource, the same string it stamps into saves.
`_build_from_executable()` reads it via `version.dll` -- stdlib ctypes, no
subprocess, no new dependency. Resolution order is now env, executable, local
save, install root; the local-save scan still covers Linux and macOS, which
carry no version resource.

Side effect: generation dropped from 10-16s to 6-7s per case, because the probe
no longer decodes saved labs looking for a build string.

This was the same defect shape as every previous one -- `_version_from_install_root`
returned a release on the assumption that the tier ladder would *rank* donors,
while `_base_donor_candidates` under `exact` *filters* them. Two models of one
concept, disagreeing.

### Two refusal messages contradicted each other

`describe_donor_rejection` deliberately withholds "set a looser policy" under
`exact`, because loosening was measured to produce files Packet Tracer refuses
to open. The donor resolver's own blocking reason handed that suggestion out
anyway. It now gives the same advice as the other path: save one lab.

The generation refusal was worse -- a fixed string telling users to "let the
repo auto-detect one" when auto-detection had already run and rejected all 16
candidates. It now reports the real reason, naming the bundled-sample trap.

### The README documented requirements that no longer exist

It said `bridge_resolution=missing` blocks decode, edit and generate. Nothing is
blocked: the vendored pure-Python Twofish has been the default since `0.3.0` and
a compiled bridge is only an accelerator. It also instructed users to pin
`PACKET_TRACER_TARGET_VERSION=9.0.0.0810`, which would break every machine on a
different build. Both rewritten.

### Actual requirements, measured

Python 3.9+ syntax throughout, standard library only, `pytest` for tests alone.
Node is needed only for the npm wrapper. Install discovery already covers
Windows, macOS and Linux. Packet Tracer is needed to *verify* opens and, once,
to supply a donor -- after that `donor_cache` serves generation on its own.


## Prompt parsing: three silent misreads

Fuzzing the parser over ordinary phrasings found three defects, all of which
produced a *wrong topology* rather than an error.

| Prompt | Was | Now |
|---|---|---|
| `2 switches 1 router 4 computers` | Router 1, PC 4 -- switches lost | Router 1, Switch 2, PC 4 |
| `bir router iki switch uc komputer qur` | nothing at all | Router 1, Switch 2, PC 3 |
| `5 kompyuter 1 komutator qur` | PC 5 -- switch lost | Switch 1, PC 5 |

Plural forms had been listed by hand, so the table disagreed with itself: `PC`
carried `computers` and `pcs` while `Switch` and `Router` had no English plural
at all. Aliases now match a plural suffix rather than enumerating one, so every
device type is on the same footing.

Spelled-out counts were not handled anywhere, and every downstream extractor
matches `\d+` -- so a perfectly ordinary Azerbaijani sentence parsed as an empty
topology. They are converted once during normalisation rather than in each
extractor, keeping one model of what a count is.

### One number word had to be left out

`on` is ten in Azerbaijani and a preposition in English, and it sits directly in
front of the words that identify a device: `dhcp on router`, `telnet on switch`.
Requiring a device alias after the number word does not separate the readings --
`router` is a device alias. Reading it as a count silently ordered ten routers,
so it is excluded. `10 komputer` still works; a misparse would not have been
noticed until Packet Tracer opened the wrong lab.
