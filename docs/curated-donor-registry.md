# Curated Donor Registry

## Purpose

The curated donor registry is the explicit truth source for donor promotion metadata that should not be guessed from filenames alone.

Registry file:

- `references/curated-donor-registry.json`

## Entry Contract

Each entry should define:

- `relative_path`
- `promotion_status`
- `packet_tracer_version`
- `workspace_validation`
- `apply_safety_level`
- `archetype_tags`
- `validated_edit_capabilities`
- `acceptance_fixtures`
- `acceptance_notes`
- `provenance`

## Current Seeded Entries

The current seeded entries are based on known working example artifacts:

- `complex_campus_master_edit_v4.pkt`
- `home_iot_cli_edit_v1.pkt`
- `service_heavy_cli_edit_v1.pkt`

These entries become active when a donor root contains matching relative paths or filenames.

Current public proof reference:

- `docs/campus-donor-proof.md`
- `docs/home-iot-donor-proof.md`

This is intentionally separate from the registry file. A registry-backed donor may still be refused for a generalized prompt if the reusable link skeleton is too weak.

Important proof semantics:

- registry entry exists
  Means the donor metadata is explicit and checked in.
- inventory-proof donor exists
  Means a real donor artifact matched that entry and passed inventory smoke.
- selected donor exists
  Means prompt-level selector and runtime constraints both accepted it for the current request.

Those are related, but they are not the same claim.

## Promotion Rules

- `reference_only` never becomes the final selected donor
- `acceptance_verified_curated` requires explicit `acceptance_fixtures`
- registry-backed metadata overrides inferred metadata where the registry is more explicit
- validation can still demote a registry entry if the actual donor is blocked or incompatible

## Evidence Sources

Selected donor summaries distinguish:

- registry-backed evidence
- inferred evidence
- mixed `registry+inferred` evidence

This is important for auditability and release messaging.

Rejected donor summaries should preserve the same distinction. A closest rejected donor class can still be registry-backed while prompt-level donor selection remains blocked by:

- `layout_reuse_too_weak`
- `acceptance_evidence_too_weak`
- `archetype_misaligned`
- `runtime_subtree_missing`
