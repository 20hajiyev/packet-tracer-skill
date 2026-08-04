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


## "Verified" was measuring the wrong thing

Two corpus cases added in the previous pass -- `router_dhcp` and
`server_services` -- were reported as verified. They were not. The corpus proved
only that Packet Tracer opened the file, and a pruned donor opens whether or not
the prompt's capability was ever applied.

Measured against the donor:

| marker | donor | router_dhcp | server_services |
|---|---|---|---|
| `ip dhcp pool` | 0 | **0** | 0 |
| `dns` | 223 | 52 | 62 |
| `http` | 72 | 2 | **25** |

Every hit is inherited donor content, thinned by pruning. Nothing was added.
`ip dhcp pool` is absent everywhere, including from the case whose whole purpose
was to request one.

`CorpusCase.requires_content` now names the markers a lab must contain for the
request to count as honoured, checked against the decoded XML. The two cases are
reclassified as capability gaps, which is what they always were.

The same check was applied to the VLAN cases as a control, and they pass: VLAN
configuration is genuinely emitted, so the gap is specific to DHCP and server
services rather than general.

Honest corpus standing: **8 verified, 3 capability gaps, 1 donor-limited, 1
correct refusal, 0 unexpected.**

This is the recurring defect shape once more, now in the measuring instrument
itself: "the file opens" and "the file does what was asked" were two models of
one concept, and the weaker one was doing the reporting.


## Three capability gaps closed

None of these needed new capability. `pkt_editor` already implemented
`set_router_dhcp_pool`, `enable_server_service`, `set_server_dns_record`,
`set_management_vlan` and `enable_telnet` -- 70+ operations in total, nearly all
of them unreachable. The planner simply never emitted them.

### Router DHCP was coupled to VLANs

`_synthesize_vlan_and_link_ops` returns immediately when the prompt names no
VLAN, and it was the only place that built a DHCP pool. So "dhcp routerden
verilsin" on a flat network produced a lab with no pool -- which opened, so
nothing complained. `_synthesize_service_ops` now emits the VLAN-independent
operations.

Putting hosts on the pool with `set_host_dhcp` is the natural next step, but
that is an `end_device_mutation`, which open-first mode blocks; adding it
refused every DHCP prompt outright. Whether that block is measured or merely
cautious is its own question and belongs in its own verified step.

### Capabilities were detected from file names

`infer_capability_tags` matches every keyword against the sample's *path*. A lab
called `telnet.pkt` counted as having telnet; the local campus donor, with
nineteen `line vty` blocks and nineteen `interface Vlan` blocks, was credited
with no capabilities at all -- so management prompts were refused as "missing
critical capability coverage".

Reading the running-config as evidence changed the bundled corpus from **5
telnet samples to 230**, and management_vlan from **6 to 226**.

### A service name in the wrong case

`_set_enabled_service` keys on lowercase names, and `DNS` raised `KeyError` out
of the middle of donor validation. It surfaced as "no ranked donor candidate
passed compatibility validation: 'DNS'", pointing at the donor rather than at
the service name. The helper now ignores unknown services instead of raising.

### Standing

**11/13 generated, 11 opened in Packet Tracer, 0 unexpected** -- and every one
now verified by content, not just by opening. Up from 8 under the stricter
standard. The single remaining gap is `wireless_home`, which is a genuine donor
limit: a device model the donor lacks cannot be cloned into existence.


## The end-device block was unmeasured caution

`end_device_mutation` sat on `SAFE_OPEN_BLOCKED_MUTATIONS` with nothing in the
repo recording why. That is the third time this exact shape has appeared:
`device_prune` and `remove_link` were both on that list too, both forbade
operations the architecture depends on, and both proved safe the moment anyone
opened a file.

Measured with `PACKET_TRACER_HOST_CONFIG`, control and experiment:

| lab | hosts on DHCP | opens |
|---|---|---|
| flat router DHCP, knob off | 2 of 10 ports | -- |
| flat router DHCP, knob on | 6 of 10 ports | yes, 10.1s |
| three VLANs, pool per VLAN, knob on | -- | yes, 10.2s |

Both opened, so the default is now on. `PACKET_TRACER_HOST_CONFIG=0` restores
the old behaviour. Wireless mutation stays blocked -- it has not been measured,
and this pass does not guess about it.

Two tests asserted the block as though it were a requirement. They now assert
what was actually measured: wireless blocked, end-device allowed.

Corpus holds at **11/13 generated, 11 opened, 0 unexpected**, and DHCP labs now
hand addresses to their hosts instead of offering a pool nobody asks from.


## Two theories, stated first and then measured

### T1: the corpus is biased toward what already works

The 13 cases were written by the same process that fixed the bugs, so they
cannot be evidence that the skill handles what users actually type. Tested
against ten out-of-corpus Azerbaijani prompts of the kind a student would write.

Eight of ten generated. But generation is not correctness, so the topologies
were compared against what was asked -- and **`2 router 2 switch 4 pc` produced
one router**. The file opened, the structural check passed, nothing reported the
loss.

Routers were matched singularly, `next(...)` on both the target and the donor
side, and `standalone_targets` excludes `Router` by kind. Every router past the
first belonged to no code path at all. They are now mapped to donor routers in
order, and the shortfall is cloned with `duplicate_device` -- already verified
for bare infrastructure devices. A two-router lab opens in 13.5s, and
`two_routers` is now a corpus case pinned by device name.

The two remaining refusals are honest: `router switch pc qur` names no counts,
and `bir sebeke lazimdir 10 kompyuter ucun` names no switch.

### T2: filename-based capability detection is pervasive, not a one-off

Confirmed. Of 116 capabilities, **91 rested on the file path alone**. Measured
across all 292 bundled samples:

| capability | credited by name | actually configured | missed entirely |
|---|---|---|---|
| rip | 5 | 1 | **36** |
| static_route | 0 | 0 | **22** |
| acl | 5 | 1 | **18** |
| nat | 6 | 4 | 7 |
| hsrp | 3 | **0** | 0 |

Both directions are wrong: every `hsrp` credit was a filename coincidence, and
36 labs that configure RIP were invisible. Config evidence now covers 30+
capabilities, added to the filename tags rather than replacing them -- a
capability the config proves is never wrong to record, whereas withdrawing
credit is a larger change that needs its own measurement.

Catalogue gains: vlan 6 → 227, rip 6 → 42, dhcp_pool 23 → 53, static_route
0 → 22, access_port 2 → 21, acl 6 → 24, trunk 0 → 16.

**Corpus: 12/14 generated, 12 opened, 0 unexpected.**


## The two refusals T1 turned up

Both were sound prompts the skill declined, and neither refusal was honest about
why.

### A device named with no number

`router switch pc qur` was refused with "This prompt does not describe a
topology. Say which devices you want" -- a message the prompt itself
contradicts, since it names three devices. Only the count was missing, and a
device named without a number means one of it.

Applied per device type, and only when that type carries no count anywhere, so
`2 switch ve router qur` still reads as two switches and one router.

One guard was needed: `wireless router` contains `router`, so the bare scan
credited a wireless router *and* a plain one. Counted matches never had this
problem because the digit anchors them; only the fallback needs longer names
masked out first.

### Hosts with nothing to plug into

`bir sebeke lazimdir 10 kompyuter ucun` named ten PCs and no switch. All ten
became standalone targets, the donor ran out of spare PCs, and the refusal
blamed the donor -- when the real problem was a topology with nothing to connect
to. One switch is now inferred, recorded in `assumptions_used` rather than done
silently. A wireless router counts as something to connect to, so the home-lab
shape is untouched.

Both open: one-of-each in 10.2s, ten PCs on an inferred switch in 13.6s.

**Corpus: 14/16 generated, 14 opened, 0 unexpected.**


## The last "donor limitation" was a selection bug

`wireless_home` had been classified donor-limited: "the local donor is a wired
campus lab and carries no wireless router; a model the donor lacks cannot be
cloned into existence." The first clause was true. The conclusion was not.

Measured: **143 local labs carry the running build**, several with wireless
routers, access points, laptops and IP phones. The skill never looked at them.
The base-donor pool is one file -- `_compat_donor_candidate()` resolves a single
lab, bundled samples fail the exact-build policy, and curated roots are empty
unless `--donor-root` is passed. Whatever that one lab lacked was declared
impossible.

### Indexing without paying for it

A full lab summary costs ~770 ms, so summarising 143 labs would cost ~110 s
against a 5-7 s generation. Three things keep it cheap:

- **Version comes from the header.** `peek_pkt_header` is ~13 ms, so labs on the
  wrong build are never decoded.
- **The index is on disk**, keyed by size and mtime, so a warm run is little more
  than a `stat` per file: 2.4 s cold, 0.4 s warm.
- **The walk is bounded.** `Documents` holds 414,000 entries and takes 12 s to
  traverse fully -- twice a whole generation -- almost all of it inside
  checkouts and dependency trees. Depth is capped and code directories skipped.

Widening runs **only on the failure path**, after the ranked pool has already
been tried, so the common case is untouched.

### Two more defects fell out of it

The skill was selecting **its own generated output** as a donor -- a lab derived
from a lab, carrying every simplification the first pass made. `output/`,
`scratchpad/` and friends are now excluded, which took the local pool from 117
entries to 16 real ones.

And widening alone still failed: the donor holds `WirelessRouterNewGeneration`
and `WirelessEndDevice`, while the planner matched device types by exact string
and reported "no spare WirelessRouter". Selection understood the equivalences
and the planner did not -- the same two-models split as every other defect here.

**Corpus: 15/16 generated, 15 opened, 0 unexpected.** Every case except the
deliberate refusal now works. No capability gaps and no donor limitations
remain.


## The blocked list is now entirely measured

`wireless_mutation` and `wireless_client_association` were the last two entries
with nothing recording why they were there. They could not be tested before,
because until the donor pool was widened there was no wireless donor to test
against.

Two labs generated with them allowed opened in Packet Tracer: a home network
with a named WPA2 network and two laptops (13.5 s, SSID present 16 times), and
one with three laptops, two tablets and an explicit channel (10.1 s, SSID
present 31 times). Both carry the passphrase in the saved file. The default is
on; `PACKET_TRACER_WIRELESS_CONFIG=0` restores the old behaviour.

That closes the pattern. Five categories sat on `SAFE_OPEN_BLOCKED_MUTATIONS`
with no evidence -- `device_prune`, `remove_link`, `end_device_mutation`,
`wireless_mutation`, `wireless_client_association` -- and every one proved safe
the moment a file was actually opened. Two of them forbade operations the
donor-prune architecture depends on. What remains blocked is what remains
untested: `port_reassignment` and `workspace_physical_mutation`.

### Wireless configuration had to be emitted first

The block was only half the problem. `pkt_editor` has implemented
`set_wireless_ssid` and `associate_wireless_client` all along, and
`_extract_wireless_ops` reads them from the command form
`set AP1 ssid TEST security wpa2-psk passphrase test12345`. Nobody writes a
prompt that way, so "ssid EvSebeke wpa2 sifre Gizli123" produced a wireless lab
still carrying the donor's own network name -- the same gap shape as router
DHCP and telnet.

One detail worth keeping: normalisation lowercases the whole prompt so the
patterns can stay simple, but an SSID is user-visible and a lowercased
passphrase is not even the same secret. Both are restored to the capitalisation
the user typed.

**Corpus: 16/17 generated, 16 opened, 0 unexpected.**


## Chasing the slow path found a privacy leak

The wireless cases took 27 s against 4 s for everything else. Profiling the
decode rather than guessing at it turned up three separate things.

### The codec spent most of its time not doing cryptography

`twofish_pure.encrypt` is 13.9 us per block, which accounts for 5 s of an 11.4 s
decode of a 2.8 MB lab. The other 6 s went on byte-at-a-time comprehensions in
the stage masks, the CTR loop and CMAC.

Both stage masks are 256-periodic -- stage 2 masks byte `i` with
`(length - i) & 0xFF`, stage 1 with `(length - i * length) & 0xFF`, and stepping
`i` by 256 adds `256 * length`, which is zero modulo 256 whatever the length. So
one period can be built and tiled, and the whole payload XORed as a single
big integer, which runs in C.

**11.43 s to 6.02 s, bit-identical output**, pinned against the original
definitions in a test because getting a mask wrong would corrupt every file
silently.

### Half the remaining work was authentication nobody needed

EAX runs the cipher twice: once for CTR, once for the CMAC behind the tag.
Inventory, version probes and donor indexing parse the result as XML
immediately, so corruption surfaces there regardless. `verify=False` on those
paths takes decode to **3.05 s** -- 3.7x the original. Every path that writes a
file keeps verification, and a damaged tag is still rejected.

### The output was 98% someone else's holiday photos

A four-device home network came out at **2.8 MB**: 3.6 MB of `PIXMAPBANK`
against 58 KB of devices. Thirty-five JPEGs, none referenced by anything in the
lab -- every image slot was empty.

Size was the smaller problem. The bank stores the paths those images came from,
`../../../Users/78-USER/Downloads/...`, so every lab generated from that donor
republished a stranger's photos and their account name. Anyone sharing a
generated lab shared those too.

`prune_unused_images` drops orphans and keeps anything still referenced:

| | before | after |
|---|---|---|
| file size | 2772 KB | **51 KB** |
| embedded images | 35 | 1 |
| foreign account paths | 51 | **0** |

Generation of that case went 39 s to 15 s, and the corpus median from 5 s to
3.6 s. **16/17 generated, 16 opened, 0 unexpected.**


## What Packet Tracer and NetPilot actually offer

Researched the simulator's own documentation and the nearest comparable product
before continuing, because both bear on whether the donor-prune architecture is
the right one.

### Packet Tracer's programmatic surfaces

The install ships two APIs, and they are not what their names suggest.

**NetconRestAPI** is not a way to control Packet Tracer. It is a simulated Cisco
DNA-Center-style northbound controller that runs *inside* a topology -- tickets,
inventory, discovery, flow analysis -- for teaching network automation.

**IpcAPI** is the real external surface: 2758 documented classes, used by ExApps
that connect to a running Packet Tracer. It exposes inspection and configuration
of existing objects, plus `fileNew`, `fileOpen`, `getActiveFile` and
`Options.saveFile`. What it does **not** expose is topology construction:
`Network` has `getDevice`, `getDeviceCount`, `getLinkAt` and no `addDevice`; the
`addDevice*` methods on `Device` turn out to be `addDeviceExternalAttributes`,
which set attribute values.

So IPC is not an alternative generation path. It is a possible future
verification channel -- worth remembering that it can open and save files.

### NetPilot

The closest comparable product. Vendor claims, not measured here: plain-English
or assignment-PDF in, configured `.pkt` out in about two minutes, with VLANs,
OSPF, ACLs, NAT, ASA rules, wireless and IoT; can import a broken `.pkt`,
diagnose it and hand back a working one; runs entirely in a browser with no
Packet Tracer installed; free tier plus a paid tier; scoped to CCNA/CCNP, with
CCIE-scale topics explicitly out.

The interesting part is the architecture that implies. Running with no Packet
Tracer means no donor lab to prune, so device prototypes must come from a
library extracted in advance. Our equivalent of that library is the donor, which
is why `generate_from_blueprint` -- the supposedly from-scratch path -- still
fails with "donor has only 0 prototype(s) for Router with model 2911".

### Two defects that came out of testing that path

`2911 router qur` parsed as **two thousand nine hundred and eleven routers**.
Model designations sit exactly where a count goes, and the planner worked on it
for over ten minutes before failing. Known model numbers and any count above 200
are no longer read as counts.

And a named model was silently ignored: asking for a 2911 produced a PT8200
because that is what the donor carries, with nothing said about it. The
substitution is now recorded in `assumptions_used`.

**Corpus: 17/18 generated, 17 opened, 0 unexpected.**


## The edit surface was silently doing nothing

`--edit` is advertised and had never been run end to end. Three realistic
requests against a real lab, each opened in Packet Tracer:

| request | opened | actually applied |
|---|---|---|
| `PC1 adini PC-Ofis et` | yes | **no** |
| `SW1 de vlan 20 yarat` | yes | yes |
| `PC1 ve SW1 arasinda link qur` | yes | **no** |

All three opened. Two had done nothing at all -- the file opened because it was
an unchanged copy of the input. The same trap the corpus fell into, in a
different surface: "it opened" read as "it worked".

Two causes, both familiar.

Edit requests were only understood in the English command form,
`rename PC1 to PC-Ofis`. The natural phrasings -- `PC1 adini PC-Ofis et`,
`SW1 in adi CORE olsun`, `SW1 adını Core-SW elə` -- matched nothing, exactly as
with the wireless SSID.

And when nothing matched, `goal` fell back to `generate`, so `--edit` wrote the
original back out and reported success. It now refuses and says what it would
accept. The refusal is reported as JSON like every other refusal instead of as a
traceback.

One detail: `dəyiş` has to read as `deyis`, but device names carry their
capitalisation into the lab, so the rename patterns run on a transliterated but
not lowercased prompt rather than the fully normalised one.

### Packet Tracer's undocumented command-line flags

The binary carries `--no-gui`, `--ipc-port`, `--pt-ipc-port`, `--ipc-arg` and
`--autoloadptsa`. `--no-gui` looked like a cheap verification channel, so it was
measured: run against a good lab and one stamped with a wrong build, it behaves
identically, never exits, and reports nothing to the console. It is not an
oracle without an IPC client. Recorded so nobody spends the afternoon twice.


## Natural edit phrasings, and the port bug underneath them

Nine of eleven realistic edit requests produced no operations at all, though
`pkt_editor` implements every one. Only the command form was parsed. Natural
phrasings now reach the editor for VLAN creation, linking, deletion and link
removal, and all of them were verified by opening the result.

Adding link edits exposed a chain of defects, each found by opening a file
rather than by reasoning about it.

**Empty ports.** `SW1 ve SW2 arasinda link qur` names no interface, so the
operation carried empty port names. Packet Tracer rejected the lab -- naming an
interface a device does not have is a measured way to break a file, and an empty
name is exactly that.

**Guessed ports.** Resolving them by assembling a name pattern produced
`FastEthernet0` for a switch, then `FastEthernet0/1` for a PC, then
`GigabitEthernet0/1` for an ISR router that numbers its interfaces
`GigabitEthernet0/0/x`. Each guess produced a file that would not open. Port
shapes are now taken from interfaces the device is already using **in the file
being edited**, and only the trailing number varies.

**And the validator was broken.** `_canonical_port_name` sliced two characters
off its input unconditionally, assuming the abbreviated `Fa0/1` form. Given the
full name a saved lab actually stores, `FastEthernet0` came back as
`FastEthernetstEthernet0`. So `port_exists` -- the helper whose entire job is to
stop invalid interfaces reaching a lab -- reported real interfaces as missing
for every caller that passed a full name.

Its host rule was wrong too: it applied the switch numbering to PCs, accepting
the slotted `FastEthernet0/1` that no PC has and rejecting `FastEthernet0`,
which is what every lab on disk uses.

Measured after the fix: PC `FastEthernet0` true and `FastEthernet0/1` false,
switch the reverse, ISR `GigabitEthernet0/0/1` true. A created link now opens in
13.4 s.

**Corpus: 17/18 generated, 17 opened, 0 unexpected. 517 tests.**


## An invariant test against real labs

Rather than reasoning about the port helpers again, real saves were used as
ground truth: **if a lab links a device on port P, then `port_exists` must
report P as existing.** Across 12 local labs that is 782 endpoints.

**33 failed.** `Serial2/0`, `Serial3/0` and `Serial6/0` on routers, `Port 0` on
six access points, `RS 232` on a laptop, the `Switch` pass-through on an IP
phone, `Console` on a switch, `FastEthernet0` on a hub.

The cause was narrower than it looked: `_port_nodes` matches only `eCopper*`, so
serial, fibre and wireless interfaces were invisible. Counted across the local
collection the real values are `eCopperFastEthernet` 1148, `eBluetooth` 291,
`eCopperGigabitEthernet` 116, `eHostWirelessN` 51, `eAccessPointWirelessAC` 20,
`eAccessPointWirelessG` 18, `eSerial` 12, `eFiberFastEthernet` 10.

Names outside the two Ethernet families are now reported as *not refuted* rather
than missing, because calling a real interface missing is the damaging
direction -- a legitimate link gets dropped. The Ethernet families are still
judged strictly, which is where the measured breakage was. Hubs number their
ports unslotted from zero, like a host but many, and now have their own rule.

**33 to 0 of 782.**


## Enterprise scale, and the routing that was gated behind a table

### 500 computers now open

A 530-device lab -- 500 PCs, 25 switches, 4 routers, VLANs 10/20/30/40/99, ten
DHCP pools -- generates in about four and a half minutes and opens in Packet
Tracer in 16.7 s.

Two defects stood between us and that, and neither was about size.

**Cloned hosts were wired twice.** The blueprint already plans a connection for
every host with a port of its own; the clone path allocated a second one by
scanning ports already in the blueprint, which for a host whose own link was in
that list always fell through to `FastEthernet0/1`. Sixteen cables on one
interface per switch. A 100-host lab produced 68 hosts and would not open; it
now produces all 100 and opens in 13.4 s.

**Uplink names ran past the model.** Bisecting found a 62-device lab opening and
a 64-device one failing -- then isolating the variables showed the difference
was the switch count, not the device count: 400 hosts on 20 switches opened, 400
hosts on 25 switches did not. `_switch_uplink_port` returned
`GigabitEthernet0/{index}` for any index, so a core switch fanning out to
twenty-two access switches asked a 2960 for `GigabitEthernet0/20` when it has
two. Uplinks past the gigabit range now take a copper port counted down from the
top.

One useful thing fell out of the bisection: **a double-booked port does not stop
Packet Tracer opening a file. An invalid port name does.** The structural check
treats both as failures, which is right, but only one is fatal.

### Routing was refused by a table, not by a failure

`ospf olsun` came back with "scenario is still acceptance-gated". That gate is
computed from a hand-maintained maturity table -- the same kind of unmeasured
claim this repo has spent its history unwinding.

So it was measured. An OSPF lab built through the normal path carries
`router ospf` with its network statements and opens in 13.4 s. `_synthesize_routing_ops`
now emits OSPF, EIGRP, RIPv2 and static/default routes -- all of which
`pkt_editor` had implemented all along -- and the gate is advisory: generation
proceeds and records that the configuration is unreviewed rather than
unsupported.

Two tests asserted the old refusal. They now assert the measured behaviour, and
`ospf_routing` and `eigrp_routing` joined the corpus so a regression fails
loudly, which a table cannot.

**Corpus: 19/20 generated, 19 opened, 0 unexpected. 521 tests.**


## Large labs have to be readable

A 500-host lab was structurally correct and impossible to follow. Hosts were
dealt into one global six-wide grid regardless of which switch they belonged to,
so the canvas ran **y 110..10570** -- ten thousand units of vertical scroll --
with a host and the switch it plugs into hundreds of units apart.

Each access switch now owns a block: the switch on top, its hosts in a compact
grid beneath it, blocks laid left to right and wrapped into rows. Hosts are
dealt round-robin across switches, matching how the link planner assigns them,
so the picture agrees with the wiring.

| | before | after |
|---|---|---|
| canvas (500 hosts) | x 180..5550, y 110..10570 | x 180..3910, y 110..3290 |
| shape | narrow column | roughly square |
| open time | 16.7 s | 13.4 s |

The same layout applies at every size, so a four-switch lab now fits in
x 180..2620, y 110..820 instead of sprawling.


## Security and switching capabilities

ACL, NAT/PAT, STP, EtherChannel and port security were all recognised by the
parser and emitted by nobody -- the fifth appearance of that gap after DHCP,
telnet, wireless and routing. `pkt_editor` had implemented every operation.

Verified against real opens: `nat olsun` writes `ip nat` twice, `acl olsun`
writes four `access-list` lines, `stp olsun` writes twenty-two `spanning-tree`
lines. NAT emits the ACL that feeds it, because overload without a matching list
configures nothing.

The last producer bypassing the port allocator is also gone: a cloned switch's
uplink wrote its blueprint port straight out, so the core could hand
`FastEthernet0/7` to both SW3 and SW21. The 500-host lab now passes the
structural check with no failures.

**Corpus: 23 cases, 22 generated, 22 opened, 0 unexpected.**


## Redundancy and IPv6

HSRP, IPv6 addressing, SLAAC and OSPFv3 join the emitted set. `pkt_editor` had
all of them; nothing built the operations.

Two defects surfaced on the way.

**`ipv6` was not a capability.** It existed only as a network-style tag, so
"ipv6 olsun" reached the planner with nothing attached and produced a v4-only
lab. Verified after the fix: 330 `ipv6` lines in the saved file, opens in 10.1 s.

**HSRP failed as a donor problem.** `set_hsrp_ipv6` requires a `virtual_ipv6`
field, and the missing key surfaced as "no ranked donor candidate passed
compatibility validation: 'virtual_ipv6'" -- pointing at the donor rather than
the operation, exactly as the `DNS` service-name failure did. The field is
supplied now (both routers share the virtual address, one takes priority 110 and
the other 90), and the editor skips a standby group with no address instead of
raising.

**Corpus: 25 cases, 24 generated, 24 opened, 0 unexpected. 536 tests.**


## Drawing on the workspace

Packet Tracer's annotation tools -- notes, rectangles, ellipses, lines, and the
colours that go with them -- were not reachable from this skill at all.

The formats were measured, not guessed. A rectangle in `Ipsec2.pkt` and an
ellipse in `Outside_Nat.pkt` gave the field names; the tag vocabulary
(`RECTANGLES`, `ELLIPSES`, `LINES`, `POLYGONS`, `NOTES`, `FILL_COLOR`,
`FILL_FLAG`) came out of the binary itself. `Color` is the outline and `Filled`
decides whether the interior is painted with it. The containers sit directly
under the document root.

`pkt_annotate` exposes all of it, with a palette named in English and
Azerbaijani so a prompt can ask for a `qirmizi cerceve`. Verified against real
opens: twenty rectangles (ten filled, ten outline), four ellipses, six lines and
thirteen notes in one lab, which opens in 10.1 s.

Generated labs now draw themselves: each switch block gets a coloured frame and
a `SW2 - VLAN 10` label, with a title note above the topology. Inherited
annotations are cleared first, because the donor's frames were drawn for the
donor's layout and would box the wrong devices.

**One thing this got wrong first.** The block grouping divided by the number of
access switches, and a wireless home lab has none -- so `wireless_ssid` and
`wireless_home` stopped generating entirely. Decoration must never be what stops
a lab being produced, so the whole annotation pass is now guarded: if anything
inside it fails, the lab is written without drawings.


## Voice, IoT devices and the rest of the server farm

Three gaps, all the familiar shape.

**Voice and IoT devices could not be asked for at all.** `4 ip phone qur` parsed
the count and then dropped it, because no alias matched. IP phones, cameras,
sensors, home gateways, hubs and repeaters are nameable now.

**Call Manager Express.** `set_telephony_service`, `set_ephone_dn` and
`set_ephone` existed; nothing built them. They are emitted together, because a
telephony service with no directory numbers rings nowhere. Extensions start at
1001 and each phone gets a MAC derived from its index -- a random one would
change the lab on every regeneration for no reason.

**Four of nine services were unreachable.** `_set_enabled_service` knows dns,
http, https, ftp, tftp, ntp, syslog, aaa and email; only the first five were
emitted, so a prompt asking for a syslog or RADIUS server got a plain server
with nothing running on it. An AAA server also gets its RADIUS port set, since
nothing authenticates against a server that is not listening.

**Corpus: 27 cases, 26 generated, 26 opened, 0 unexpected. 550 tests.**


## Three annotation formats, corrected by one saved file

The first drawing pass shipped rectangles and ellipses that rendered, and lines
and notes that did not. A screenshot showed the gap immediately: twenty
rectangles and four ellipses on screen, and nothing of the six lines or thirteen
notes.

No bundled Cisco sample contains a drawing-palette line or a logical note, so
there was nothing to measure against -- both had been written by analogy with
the rectangle, and both were wrong. The user drew one line and three notes in
Packet Tracer and saved. That file settled all three questions at once, because
Packet Tracer rewrites what it loads into its own form:

**Lines are not rectangles.** They use `StartX/StartY/EndX/EndY` and carry no
`Filled`. Written with corner fields, Packet Tracer read them, converted them,
and dropped them from the view.

**Notes live under `PHYSICALWORKSPACE/NOTES`** even though they show on the
logical workspace. Written at the document root, Packet Tracer moved them and
emptied the text, leaving each parked at the 50000,50000 sentinel.

**A filled shape can have its own outline colour.** Packet Tracer writes
`<Filled OUTLINECOLOR="#000000" OUTLINED="false">1</Filled>`, so a pale panel
can carry a strong border -- something the first version had no way to express.

Verified on screen after the fix: seven notes with their text, eight lines
including a diagonal and a vertical, and five filled panels each with a
contrasting border.

Also settled while looking: Cisco's own help says the Drawing Palette creates
**lines, rectangles and ellipses** -- that is the whole palette, so nothing is
missing. `POLYGON` in the binary belongs to the physical-workspace geo view.
Note styling does not exist at all: across 150 samples every note has exactly
five fields and no font, size or colour.


## Cable types

A cable has two halves in the file and they are not interchangeable. Measured
across 140 bundled labs:

| element | values |
|---|---|
| `LINK/TYPE` | eCopper 393, eSerial 55, eCoaxial 12, eOctal 11, ePhoneLine 3 |
| `CABLE/TYPE` | eStraightThrough 274, eCrossOver 119, absent 81 |

`LINK/TYPE` is the family; `CABLE/TYPE` is only the copper sub-type and is
absent for everything else. `apply_cable_type` was writing `eSerialDCE` and
`eFiber` into `CABLE/TYPE` -- the wrong element, and never setting the family --
so asking for a serial or fibre cable produced plain copper. All seven families
map correctly now, and a non-copper link drops the sub-type element as a real
save does.

`port_capacity` also counts serial interfaces now, so `port_exists` gives a real
answer for `Serial0/0/0` instead of the "not refuted" it returns for families
this module does not model. The real-lab invariant still holds: 782 endpoints
across twelve labs, none reported missing, and it is a test now rather than a
one-off script.

### What still does not work, and why

A two-router PPP lab gets `encapsulation ppp` on both routers and **no cable
between them**. The link is planned and emitted; the editor silently does
nothing with it, because the donor's router has four gigabit interfaces and no
serial card. That is a genuine donor limitation rather than a bug in the
planner -- but it is currently silent, which is the part that needs fixing.

One attempt at fixing it -- validating the requested port inside `claim_port`
rather than only the alternatives -- turned six links into thirteen and produced
a file Packet Tracer refused. Reverted rather than shipped half-understood.


## A capability audit, and what it found

Rather than trusting memory about what works, every capability the enterprise
document asks for was run end to end and the generated file inspected for the
configuration it should contain.

**23 of 32 produced configuration.** The nine failures fell into three groups,
and the first group turned out to be one defect wearing four masks.

### Four capabilities blocked by a preference nobody expressed

`ntp`, `syslog`, `snmp` and `aaa` were all refused with "Open-first mode
requires donor link reuse for SW1 <-> R1". Two separate causes, both the same
shape -- comparing things that were never the same kind.

The donor describes a cable as `eStraightThrough`; the planner asks for
`straight-through`. One cable, two vocabularies, compared as raw strings, so
every identical cable looked like a mismatch.

And `_link_wiring_was_defaulted` looked for an assumption string that nothing
ever recorded, so a prompt naming no ports at all was treated as demanding
exact ones. The donor's router uses `GigabitEthernet0/0/1`, the planner had
picked `0/0/0`, and the link was rejected for disagreeing with a choice nobody
made. `_synthesize_links` records the assumption now, where the wiring is
actually invented.

All four generate and open: ntp writes 11 lines, syslog 3, snmp 5, and the AAA
server gets its `ACS_SERVER` block.

### Still open

| capability | why |
|---|---|
| slaac | generates, emits nothing |
| dhcp_snooping | generates, emits nothing |
| multi-area OSPF | generates, single area only |
| gre | refused: `vpn` coverage gate |
| iot | refused: donor has no `Thing` device |

**Corpus: 28 cases, 27 generated, 27 opened, 0 unexpected. 557 tests.**


## Closing the audit's remaining five

**One was the audit's own fault.** `slaac` was recorded as producing nothing
because the marker looked for `ipv6 address autoconfig` -- the client side. The
router writes `ipv6 nd prefix`, four of them, and always had. A measurement is
only as good as what it measures for.

**Multi-area OSPF** was single-area whatever the prompt asked, because `multi
area` was not a capability at all and the routing synthesiser had nothing to
branch on. The backbone now takes the first network and each further one gets
its own area.

**DHCP snooping** was recognised by the parser and emitted by nobody. It comes
with the uplink as the trusted port -- snooping with nothing trusted drops the
real server's offers along with the rogue's.

**GRE** was refused as "missing critical capability coverage: vpn" while a GRE
lab built through the same path carried `interface Tunnel0` with its source and
destination and opened in 10.2 s. Coverage now treats a capability the planner
emits as covered by construction; the donor's own feature list is beside the
point when the configuration is written rather than inherited.

**IoT** remains open: the donor carries no `Thing` device, and a model the donor
lacks cannot be cloned into existence.

**Corpus: 31 cases, 30 generated, 30 opened, 0 unexpected. 561 tests.**


## A device library, and the last audit gap

The user assembled a lab holding **208 devices across 43 types** on the running
build -- 25 router models, ASA, ISA, WLC, Meraki, cloud, cable and DSL modems,
IP and analog phones, hub, repeater, coaxial splitter, sniffer, and 112 IoT
components spanning 78 models from `Air Conditioner` to `Smoke Detector`.

That is a far better donor than any single lab, and it closed the last gap the
capability audit left open. IoT devices now generate and open.

Getting there needed one more instance of the recurring defect. Device aliases
were keyed on the raw XML type, but the planner works in *normalised* kinds:
`normalize_device_type` folds `MCUComponent` to `IoT`, and a phone is `IpPhone`
rather than `IPPhone`. Asking for `MCUComponent` looked for a kind the planner
never produces, so a donor holding 112 of them still reported "no spare device".

### Found while testing, not yet fixed

Generating against a 208-device library leaves the donor's own devices in place:
a one-router prompt produced twenty-five routers and a file Packet Tracer
refused. Pruning copes with a small donor and not with a large one.

Cloned hosts can come out wireless. Generating `1 router 1 switch 3 komputer`
against `01 Networking/Meraki/meraki_SA_firewall.pkt` gives PC1 an
`eCopperFastEthernet` interface while PC2 and PC3 get `eHostWirelessN` and no
Ethernet at all — yet all three are cabled to the switch on `FastEthernet0`.
One root cause behind several symptoms: an interface name the device does not
have, a port repair with nothing to offer, and APIPA addresses (169.254.x.x) on
hosts meant to be wired.

Four attempts to fix it had no effect on the output and were reverted rather
than kept, so the next attempt should start by *measuring which code path
creates PC2* rather than assuming. Ruled out already:

* `build_device_library` in `pkt_transformer.py` — sorting its buckets
  wired-first changed nothing; the donor-prune path does not use it.
* `spare_candidates_by_type` / `_spare_pool_for_type` — filtering to wired
  spares changed nothing.
* the standalone-target clone fallback in `_build_donor_prune_plan_for_donor`.
* the switch-group member handout (`donor_members_by_type`).
* `GENERIC_COPPER_HOST_TYPES` — used only by template synthesis and link-type
  mapping, not by donor selection.

Instrumenting the assignment (wrap the candidate functions and print what is
chosen for `PC2`) is the cheap way in; the same technique found the write path
for the duplicated-port bug in one run.

Hosts on different access switches cannot reach each other. Within one switch
they can: in the 22-switch lab PC1 -> PC22 (both on SW2) is 0% loss, while
PC1 -> PC3 (SW2 to SW4, across the core) is 100%, on every attempt and long
after STP would have converged.

Ruled out by measurement, so the next attempt should not revisit these:

* the cable. Crossover and straight-through fail identically, and a control run
  on the pre-crossover build failed the same way;
* missing links. All 62 planned links are in the file and every one is up;
* the access VLAN. All 40 hosts sit in one segment now;
* the uplinks being access ports. All 42 switch-to-switch port ends carry
  `switchport mode trunk` and `switchport trunk allowed vlan all`, written from
  the finished file so the port names are the real ones;
* duplicate MACs and duplicate addresses -- none of either.

Worth trying next: read the switch MAC address table live, or step the
simulation on a *small* multi-switch lab where the event list is not swamped,
since the 64-device one reports zero frames. A two-switch lab with hosts on
both switches is the smallest case that should reproduce it, and none of the
corpus cases currently place hosts on more than one switch -- which is why this
went unnoticed. Adding that case to the corpus is probably the first move.
