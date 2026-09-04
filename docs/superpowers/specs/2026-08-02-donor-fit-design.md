# Donor Fit and Generation Verification — Design

Date: 2026-08-02
Status: partially implemented. See §Implementation Log.
Supersedes the donor graph-fit filter introduced in the `0.2.x` line.

> **Correction (recorded during implementation).** The problem analysis in
> "Problem" below is accurate, but the module plan under "Architecture" was built
> on a wrong model of the code. It assumed `transform_from_blueprint` was the
> generation path; the path that actually runs for prompt generation is
> **donor-prune** (`_build_donor_prune_plan_for_donor` → `apply_plan_operations`).
> Removing the filter's veto exposed three further defects, all with the same
> shape as the original. Those were fixed instead of building the planned
> `donor_requirements` / `donor_fit` modules, which are no longer the next thing
> that matters. The log at the end records what actually landed.

## Problem

`generate_ready` is 0. With the Twofish and donor-version blockers removed
(see `docs/improvement-plan-0.3.0.md`), the remaining blocker is
`_filter_candidates_for_blueprint`, which rejects every donor candidate for
every prompt.

Three compounding defects, all verified against this checkout:

1. **The committed sample catalog has no link endpoints.** All 1051 link records
   in `references/packettracer-sample-catalog.json` carry only
   `('cable_type', 'ports', 'type')`. Two divergent extractors exist:
   `build_sample_catalog.py` (which produced the committed file) drops `from`/`to`;
   `sample_catalog.py::_summarize_pkt` extracts them correctly — verified live at
   6/6 endpoints resolved on `8200.pkt`.

2. **`build_donor_graph_fit` therefore sees one degenerate pair per sample**
   (`' <-> '`), so `matched_pairs` is mathematically always empty.

3. **Even with correct data the match would fail.** `_pair_key` compares device
   *names*. Donors carry `Router0 <-> Switch0`; blueprints carry `R1 <-> SW1`.

The consequence is measurable and total:

```
Prompt: "1 router 1 switch ve 3 komputer qur"
Filter verdict:            0 selected, 0 rejected, 19 filtered
Transformer preconditions: 19/19 satisfied
```

The filter is perfectly anti-correlated with the thing it exists to predict.

### Root cause

The filter was written as an independent heuristic rather than derived from its
consumer's contract. `pkt_transformer.py` takes donor devices **by type**,
deep-copies them, and **renames them** to blueprint names (`_set_device_name`),
building links from prototype links looked up **by device-type pair**. It never
needs donor names to match. Two independent models of "what works" existed, and
they diverged completely.

A second, subtler defect: missing data was read as a negative signal. Empty
`matched_pairs` meant "donor is unsuitable" rather than "I have no measurement".

## Decisions

| Decision | Choice |
|---|---|
| Risk posture | Generate when preconditions pass, then verify automatically |
| Verification | Two tiers: structural (always, headless) + real Packet Tracer open (opt-in) |
| Donor ranking | Hybrid: closest size wins; capability coverage breaks ties |
| Gate authority | The cheap gate may rank but **never reject** |

## Architecture

Current flow:

```
candidates → _filter_candidates_for_blueprint   VETO: rejects 100%
           → _rerank_candidates_for_blueprint   primary sort key is always 0
           → _evaluate_donor_prune_candidates   the real oracle, never reached
```

Target flow:

```
candidates → donor_requirements.assess()   cheap gate, ranking only, no veto
           → donor_fit.rank()              size distance, then coverage
           → _evaluate_donor_prune_candidates   sole decision authority
           → pkt_verify.structural_check()  always, headless
           → pkt_verify.open_check()        opt-in, --verify-open
```

### Modules

| Module | Responsibility | Depends on |
|---|---|---|
| `scripts/donor_requirements.py` | The transformer's preconditions, in one place: device-type capacity and link type-pair coverage. Returns `DonorAssessment`. | blueprint, sample descriptor |
| `scripts/donor_fit.py` | Ranking. `size_distance` primary, `capability_coverage` tiebreak. Handles `unknown`. | `donor_requirements` |
| `scripts/pkt_verify.py` | `structural_check()` and `open_check()`. | `pkt_codec`, `packet_tracer_env` |
| `scripts/pkt_transformer.py` (changed) | Calls `donor_requirements` instead of restating preconditions inline. | `donor_requirements` |

### Governing rules

1. **The cheap gate cannot reject.** `_filter_candidates_for_blueprint` stops
   emitting `status: "filtered"` as a terminal verdict. Candidates are annotated
   and ordered; only `_evaluate_donor_prune_candidates` rejects, because only it
   actually executes the transform. Measured cost of letting all candidates
   through: 110 ms per donor decode, ~2.1 s for a 19-candidate pool.

2. **Missing data is never negative.** `donor_requirements.assess()` returns
   `satisfied` / `unsatisfied` / `unknown`. `unsatisfied` lowers rank;
   `unknown` is neutral. Neither removes a candidate.

3. **One source of truth for preconditions.** The transformer and the gate call
   the same predicate. Drift is structurally prevented rather than monitored.

4. **Name matching is removed entirely.** `build_donor_graph_fit`'s name-based
   `_pair_key` comparison is deleted. Topology comparison is by device *type*.

## Components

### `donor_requirements.py`

```python
@dataclass(frozen=True)
class DonorAssessment:
    status: str                      # satisfied | unsatisfied | unknown
    type_capacity: dict[str, tuple[int, int]]   # type -> (needed, available)
    missing_capacity: dict[str, int]            # type -> shortfall
    required_type_pairs: list[tuple[str, str]]
    missing_type_pairs: list[tuple[str, str]]
    excess_device_count: int         # donor devices beyond what the plan needs
    unknown_reasons: list[str]       # why a dimension could not be measured
```

`assess(blueprint, sample) -> DonorAssessment`

- `satisfied`: every requested type has enough donor prototypes, and every
  requested device-type pair has at least one donor link.
- `unsatisfied`: a measurable shortfall exists.
- `unknown`: link endpoints are absent from the catalog record, so type-pair
  coverage could not be computed. Capacity may still be reported.

Device types are normalised through one shared function so `Pc`, `PC-PT`, and
`pc` collapse, and `MultiLayerSwitch` counts as a switch prototype source.

### `donor_fit.py`

`rank(candidates, blueprint) -> list[RankedCandidate]`

Sort key, descending preference:

1. `status` order: `satisfied` > `unknown` > `unsatisfied`
2. `-size_distance` — `excess_device_count`, so the closest-sized donor wins
3. `capability_coverage` — tiebreak, the existing candidate score
4. `-len(missing_type_pairs)`
5. `relative_path` — deterministic final tiebreak

Rationale for size distance as primary: fewer devices to prune means fewer
mutations, which means less opportunity to corrupt the donor. For
`1 router / 1 switch / 3 PC`, this promotes `dhcp_conflict.pkt`
(Router 2, Switch 1, PC 3) over a 33-device industrial OT lab.

### `pkt_verify.py`

**Tier 1 — `structural_check(pkt_path, donor_root) -> StructuralReport`**

Always runs after generation. Headless, deterministic, CI-safe:

- the written bytes decode through `decode_pkt_modern`
- the decoded XML parses and is rooted at `PACKETTRACER5`
- `<VERSION>` is present and within the active donor policy tier
- device and link counts match the plan
- every link endpoint resolves to a device that exists
- the donor's required runtime subtrees survived (reuses
  `_unexpected_workspace_issues` and `validate_donor_coherence`)

**Tier 2 — `open_check(pkt_path, timeout) -> OpenReport`**

Opt-in via `--verify-open`. Replaces today's fire-and-forget
`subprocess.Popen` + `{"status": "launched"}`, which never observes anything.

- launch Packet Tracer with the file
- poll for a main window whose title contains the file stem, until timeout
  (window titles are readable on this host — verified)
- report `opened` / `timeout` / `process_exited` / `packet_tracer_missing`
- terminate the process it started; never leave a stray GUI

### Support level semantics

`generate_ready` is granted to a scenario only when a corpus case for it passes
**Tier 2**. Tier 1 alone yields `generated_unverified`, which is reported to the
user as exactly that.

## Data flow

```
prompt
  → intent plan ──(blocking gaps? → refuse, and say the gap is in the PROMPT)
  → blueprint (devices, links, capabilities)
  → candidate pool
  → donor_requirements.assess()  per candidate     [annotate, never drop]
  → donor_fit.rank()                                [order]
  → _evaluate_donor_prune_candidates                [decode → mutate → validate]
       ├─ first success → selected donor
       └─ all fail      → refuse, with per-candidate reasons
  → encode .pkt
  → pkt_verify.structural_check()                   [always]
  → pkt_verify.open_check()                         [if --verify-open]
  → result: generated_verified | generated_unverified | refused
```

## Error handling

| Condition | Behaviour |
|---|---|
| Intent plan has blocking gaps | Refuse. `what_failed` must say `intent` — **not** `donor selection`. This is a current reporting bug: donor evaluation is skipped entirely, yet the output blames the donor and reports zero candidate counts. |
| No donor satisfies preconditions | Still attempt the best-ranked candidates; only refuse after the transformer rejects them all. |
| Every candidate rejected by the transformer | Refuse, listing per-candidate rejection reasons and the closest-miss candidate. |
| Structural check fails | Do not return the file as usable. Report `structural_check_failed` with the failing invariant. Keep the artifact for inspection. |
| Open check times out | `generated_unverified` — the file exists and is structurally sound but unproven. Never claim `generate_ready`. |
| Packet Tracer not installed | `open_check` returns `packet_tracer_missing`. Not an error; Tier 1 still applies. |
| Catalog lacks link endpoints | `unknown`, neutral ranking, and a one-line warning naming the regeneration command. |

## Testing

**Unit**

- `donor_requirements`: capacity satisfied / short by one / exact; type-pair
  present / missing; `unknown` when link endpoints are absent; type normalisation
  across `Pc` / `PC-PT` / `MultiLayerSwitch`.
- `donor_fit`: size distance beats capability coverage; coverage breaks ties;
  `unsatisfied` ranks below `unknown`; ordering is deterministic.
- `pkt_verify.structural_check`: passes on a known-good round-trip; fails on
  truncated bytes, a dangling link endpoint, and a stripped runtime subtree.

**Contract**

- The gate never removes a candidate: for a pool where every assessment is
  `unsatisfied`, the pool passed to `_evaluate_donor_prune_candidates` is
  unchanged in length.
- `donor_requirements.assess()` agrees with the transformer: for a sample of
  donors, `satisfied` implies the transform does not raise a capacity or
  prototype-link error.

**Regression (the bug that motivated this)**

- For `1 router 1 switch ve 3 komputer qur` against the Cisco catalog, at least
  one candidate is assessed `satisfied` and the ranked head is a donor whose
  excess device count is in single digits.

**Integration**

- End-to-end: prompt → `.pkt` → `structural_check` passes.
- `--verify-open` is exercised manually, not in CI.

**Deleted**

- All assertions that depend on `build_donor_graph_fit`'s name matching.

## Scope

In scope: the four modules above, catalog regeneration with link endpoints, the
`what_failed` reporting fix, and the tests listed.

Out of scope: splitting `generate_pkt.py`, consolidating the proof documents,
the verb-first CLI, and the 18 undecodable samples. Those remain in
`docs/improvement-plan-0.3.0.md` phases 3–5.

The JSON contract is preserved: `donor_graph_fit` and `donor_selection_summary`
keep their keys, populated from the new computation.

---

## Implementation Log

Removing the veto turned the pipeline into an experiment: every candidate now
reaches the real transformer, so its rejection messages became the diagnostic.
Three further defects surfaced, each an instance of the same root cause.

### Landed

**1. The gate lost its veto.** `_filter_candidates_for_blueprint` now returns the
whole pool, heuristic-preferred candidates first, and records
`status: "deprioritized"` instead of `"filtered"`. Only
`_evaluate_donor_prune_candidates` rejects. `_summarize_candidate_pool` gained a
`deprioritized` counter.

**2. Grouping predicate mismatch.** `_target_groups_from_blueprint` treated any
non-switch device linked to a switch as a group member, so a router became a
member of its switch's group. `_collect_donor_groups` uses
`_fallback_group_member_type`, which excludes routers by design, because routers
are matched separately against the donor router (`target_router` / `donor_router`).
Every target group therefore demanded a router that no donor group could supply.

Symptom: all 19 candidates rejected with the identical message
`Compatibility donor group Switch0 has only 0 Router device(s); requested 1 for SW1`.
Note `SW1` is a switch — the group was named after its switch while asking for a
router. Both target-side code paths now use `_fallback_group_member_type`.

**3. A defaulted assumption acted as a hard requirement.** For
`1 router 1 switch ve 3 komputer qur` the planner records
`Defaulted switch uplinks to GigabitEthernet` — the user never asked for gigabit.
The open-first link check then compared that defaulted port against the donor's
actual wiring and rejected on mismatch. Now, when the wiring was defaulted, the
donor's own ports and media are adopted and the adaptation is recorded in
`assumptions_used`. Endpoint order is aligned by device name after renaming,
because the donor's `from`/`to` order need not match the blueprint's `a`/`b`.

### Measured effect

| Stage | Before | After |
|---|---|---|
| Candidates reaching the transformer | 0 of 19 | 19 of 19 |
| Rejection reasons | 1 identical, spurious | 3 distinct, candidate-specific, real |
| Donor selected | never | **yes** — `zfwIPv4Test.pkt`, after 7 genuine capacity rejections |
| Test suite | 306 passed | **312 passed, 1 skipped** |

Oracle cost measured at ~4.3 s per candidate end-to-end (82 s for 19), well above
the 110 ms decode-only figure quoted earlier in this document. Still acceptable,
but worth a cheap pre-rank if the pool grows much larger.

### Open: the next blocker, and it needs a product decision

Generation now selects a donor and then stops here:

```
Prompt plan requires unsafe donor mutations; generation was skipped in open-first mode.
Open-first mode blocked unsafe mutation: port_reassignment.
```

`_operation_category` maps `remove_link` to `port_reassignment`, and both
`port_reassignment` and `device_prune` are in `SAFE_OPEN_BLOCKED_MUTATIONS`.

But removing links and pruning devices *is* donor-prune generation. The
safe-open profile forbids the architecture's two core operations, so prompt
generation can never complete under it. The profile and the architecture
contradict each other.

Two coherent resolutions, and choosing between them is a product decision about
what `safe_open_strict_9_0` promises, not a defect fix:

- **Rename and reclassify.** `remove_link` is not a port reassignment. Give it a
  `link_prune` category and allow `link_prune` and `device_prune` inside the
  donor-prune pipeline, keeping `port_reassignment` for genuine port changes on
  retained links. Safe-open then means "no unreviewed rewrites", not "no prune".
- **Use a different profile for generation.** Keep safe-open as the strict
  edit-time profile and give prompt generation its own profile that permits
  prune, with the two-tier verification in this spec as the safety net.

The first is recommended: the current mapping is simply wrong, and the blocked
list was almost certainly written for the edit path and then inherited by
generation.

### Second wave: generation completed and verified

**4. Pruning was classified as an unsafe mutation.** `_operation_category` mapped
`remove_link` to `port_reassignment`; that and `device_prune` were on
`SAFE_OPEN_BLOCKED_MUTATIONS`, whose only consumers are the three prompt-generation
paths. The safe-open profile forbade the two core operations of donor-prune
generation. `remove_link` is now `link_prune`, and prune operations are allowed;
inventing structure the donor never had stays blocked.

**5. The sample catalogue was not version-gated.** Only the compatibility donor
was version-checked. Donor-prune builds on the *selected sample*, so the output
inherits its `<VERSION>` — the first file ever generated claimed `6.1.0.0026`
while the skill advertised 9.0. `_existing_ranked_candidates` now applies the
compatibility ladder.

**6. Donor groups were zipped in name order.** The saved floor-switch lab contains
`DIA-RS <-> Mertebe 3`, a real Router-Switch link, but `SW1` was assigned to
`Mertebe 1`, so the plan reported the donor "does not contain that
device-to-device link". `_align_donor_groups_to_targets` now places the donor's
router-facing switch where the target expects it.

**Result, verified on 2026-08-02:**

```
prompt : "1 router 1 switch ve 3 komputer qur"
output : 9.0.0.0810, 282 KB
links  : R1 <-> SW1 [Gig0/0/1, Gig0/1]
         SW1 <-> PC1/PC2/PC3 [Fa0/1..3, Fa0]
open   : status=opened, 40.0s
         title "Cisco Packet Tracer - ...\output\gen1.pkt"
```

A truncated copy of the same file is caught by the structural tier
(`decode failed: EAX authentication tag verification failed`) and Packet Tracer
is never launched, so the check discriminates rather than always passing.

### Built after all: verification and learning

`pkt_verify.py` was built as specified. `donor_requirements.py` and
`donor_fit.py` were not, and should not be: the defects were in the prune
planner, not in a missing ranking model.

`usage_ledger.py` is new scope, added on request: a local gitignored record of
which donors actually worked, fed back into donor ranking. Its measured value is
currently unproven — in the case tested, the winning donor was already ranked
first, so learning had nothing to improve. It should pay off when the first-ranked
donor fails and a later one succeeds, at roughly 4.3 s per skipped attempt.

### Open

- **Generation takes 200-250 s.** Not decode-bound: only 10 `decode_pkt_to_root`
  calls happen per run, and `load_catalog()` is 0.2 s and cached. The cost is
  elsewhere in ranking and support-report construction and has not been profiled.
- **Leftover donor devices.** A five-device request yields a twenty-device file.
  Spares are renamed `UNUSED-*` / `*-SPARE-*`, unlinked and parked offscreen
  rather than deleted. Parking is safer; deleting is future work.
- The `what_failed: "donor selection"` mislabel when the intent plan has gaps.

### Not built

`donor_requirements.py`, `donor_fit.py`, and `pkt_verify.py` were not created.
The first two addressed a model of the code that turned out not to be the live
path. `pkt_verify` remains wanted and unchanged in scope — `validate_open` still
launches Packet Tracer and reports `{"status": "launched"}` without observing
anything — but it is only worth building once generation can actually produce a
file to verify.
