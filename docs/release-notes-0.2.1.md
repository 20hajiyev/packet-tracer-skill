# `packet-tracer-skill` `0.2.1` Release Notes Draft

## Summary

`0.2.1` is a conservative public preview patch release for `packet-tracer-skill`. It hardens the npm package surface around donor-backed planning, open-first generation rules, scenario-aware reporting, and Windows-first runtime truth.

## Highlights

- donor-backed and scenario-aware Packet Tracer 9.x workflow
- explicit product surfaces: `--explain-plan`, `--compare-scenarios`, `--parity-report`, `--doctor`
- curated donor registry and scenario fixture corpus are checked-in truth sources
- known working scenario set examples are positioned as public proof artifacts
- release/readme/docs wording is aligned to runtime and donor reality

## Runtime Notes

- real `.pkt` runtime remains Windows-first
- strict validation is currently performed with an external bridge override when repo-local bridge assets are not bundled
- public docs intentionally preserve the distinction between repo-local readiness and external bridge fallback

## Public Preview Intent

- this release prepares the repo for npm publish and GitHub release
- it does not change the product contract to imply `1.0.0` stability
- publish should happen only after the short follow-up batch that applies the prepared metadata and release steps
