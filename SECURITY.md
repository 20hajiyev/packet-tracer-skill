# Security Policy

## Supported Security Posture

This repository is intended to avoid accidental publication of private local Packet Tracer material.

Protected areas:

- local donor paths
- generated `.pkt` binaries
- generated `.xml` outputs
- locally built bridge binaries

## Reporting a Vulnerability

If you find a security or privacy issue, open a private report through the repository security reporting flow if available. If private reporting is unavailable, open a minimal public issue without sharing:

- donor paths
- generated labs
- locally built bridge binaries
- personal filesystem layout

## What Not to Publish

Do not publish:

- `PACKET_TRACER_COMPAT_DONOR` paths containing personal directories
- raw `.pkt` artifacts unless intentionally public and reviewed
- unsigned bridge binaries without review
- screenshots containing sensitive local paths if avoidable

## Current Security Boundaries

- raw `.pkt` and `.xml` outputs remain gitignored
- public examples should be inventory JSON and screenshots
- repo-local runtime readiness is intentionally separated from external bridge fallback
