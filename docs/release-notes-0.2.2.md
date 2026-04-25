# `packet-tracer-skill` `0.2.2` Release Notes Source

## Summary

`0.2.2` is a conservative patch release for the public preview line. It publishes the README runtime cleanup and the advanced wireless feature wave without changing the core safety posture.

## Highlights

- README runtime instructions now use generic Twofish bridge examples instead of a user-specific local path as the default
- `PKT_TWOFISH_LIBRARY` and `PKT_TWOFISH_SEARCH_ROOTS` setup paths are documented separately
- advanced wireless prompts classify into the `wireless_advanced` family
- WEP and WPA Enterprise/RADIUS are represented as edit-proven only for explicit deterministic edit targets
- WLC, Meraki, cellular, Bluetooth, beamforming, and guest Wi-Fi remain report-only unless future donor-backed edit proof is added
- feature atlas and release-surface tests protect the conservative support claims

## Runtime Notes

- real `.pkt` runtime remains Windows-first runtime
- strict validation is currently performed with an external bridge override when repo-local bridge assets are not bundled
- public docs intentionally preserve the distinction between repo-local readiness and external bridge fallback

## Public Preview Intent

- `packet-tracer-skill@0.2.2` is the patch release for README cleanup and advanced wireless report/edit truth
- this release does not claim `generate_ready` support for broad advanced wireless controller, cellular, Bluetooth, or Meraki scenarios
- unsupported and acceptance-gated mutations still refuse instead of guessing
