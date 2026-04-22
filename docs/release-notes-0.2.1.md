# `packet-tracer-skill` `0.2.1` Release Notes Source

## Summary

`0.2.1` is a conservative public preview patch release for `packet-tracer-skill`. The npm package is already live, and this file is the source text for the GitHub release body.

## Highlights

- donor-backed and scenario-aware Packet Tracer 9.x workflow
- explicit product surfaces: `--explain-plan`, `--compare-scenarios`, `--parity-report`, `--doctor`
- curated donor registry and scenario fixture corpus are checked-in truth sources
- known working scenario set examples are positioned as public proof artifacts
- release/readme/docs wording is aligned to runtime and donor reality

## Runtime Notes

- real `.pkt` runtime remains Windows-first runtime
- strict validation is currently performed with an external bridge override when repo-local bridge assets are not bundled
- public docs intentionally preserve the distinction between repo-local readiness and external bridge fallback

## Public Preview Intent

- `packet-tracer-skill@0.2.1` is already published on npm
- GitHub release, About/Topics application, and Discussions setup still follow the prepared manual launch ops flow
- it does not change the product contract to imply `1.0.0` stability
- the next public-facing technical step is a canonical campus donor proof artifact, not broader synthetic scope
