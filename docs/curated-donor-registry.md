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

This is intentionally separate from the registry file. A registry-backed donor may still be refused for a generalized prompt if the reusable link skeleton is too weak.

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
