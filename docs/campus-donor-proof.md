# Campus Donor Proof

## Proof Goal

Show one honest public proof artifact for the canonical `campus` family without claiming full synthetic generation.

## Real Donor Artifact

- registry entry: `complex_campus_master_edit_v4.pkt`
- proof source: a local donor file matching that registry entry name in the ignored working `output/` area
- runtime mode used for the proof: Windows Packet Tracer 9.0 with an external bridge override

## Inventory Smoke Result

The matched donor file decoded and inventoried successfully.

Observed topology summary:

- `6` switches
- `1` router
- `2` servers
- `5` printers
- `5` wireless routers
- `40` PCs
- `58` links
- services present
- wireless present
- VLANs present

Observed management and security details:

- management VLANs are present on the campus switches
- Telnet is enabled on the campus switches
- ACL `MGMT_ONLY` is present on the router
- DHCP pools, DNS, email, syslog, AAA, and wireless service state are visible in inventory

## Planner Result for a Generalized Campus Prompt

Prompt used for the public proof check:

`6 sobeli kampus sebekesi qur, VLAN 10 20 30 40 50 60 ve management VLAN 99 yarat, telnet, acl, nat, wireless ap ve printer elave et`

Observed decision result:

- `family=campus`
- `status=blocked_by_donor_selection`
- `selection_failure_type=viable_donor_found_but_acceptance_weak`
- `best_available_donor_class=campus/core`
- `best_rejected_donor_class=campus/core`
- `primary_rejection_layer=donor`
- `primary_rejection_code=layout_reuse_too_weak`
- `candidate_counts.selected=0`
- `candidate_counts.filtered=269`

Top rejection reasons:

- donor graph has no reusable link pairs for the requested topology
- sample reuses too little of the requested link skeleton
- `missing_link_pairs:6`

Closest rejected donor summary:

- the closest donor class is still `campus/core`
- registry-backed donor evidence exists for that class
- prompt-level selection still refuses it because reusable link skeleton quality is too weak

## What This Proves

- a real donor path exists for the canonical campus proof artifact
- donor inventory works
- planner refusal is still explicit and deterministic
- the blocker for the generalized campus prompt is donor selection quality

## What This Does Not Prove

- it does not prove synthetic campus generation is solved
- it does not prove every campus prompt is generate-ready
- it does not prove runtime was the blocker for this prompt
- it does not make registry-backed donor evidence equivalent to prompt-level donor selection

## Interpretation

This proof means two different things at once:

- a real campus donor artifact exists and inventories correctly
- the current planner still refuses to select a donor for the larger six-department campus prompt when the reusable link skeleton is too weak

That refusal is the correct product behavior. In this proof run, runtime was not the blocking layer. Donor selection quality was.

The shorthand campus classifier should still resolve this prompt family as `campus`; the refusal should be read as donor-limited campus semantics, not as a service-heavy family drift.

## Public Message Guardrail

Say:

- donor-backed campus donor proof exists
- real donor inventory works
- generalized campus generation can still be donor-limited

Do not say:

- the campus prompt is fully generate-ready
- the donor proof implies synthetic topology generation is solved
