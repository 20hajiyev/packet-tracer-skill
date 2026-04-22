# Runtime Truth

## Why This Exists

This repo makes a strict distinction between:

- passing tests with an external bridge override
- being self-contained and repo-local runtime ready

That distinction is part of the public product contract.

## Runtime Grades

- `ready`
  Repo-local runtime pieces are available and the doctor sees a complete decode/edit/generate path.
- `partially_ready`
  Some operations work, but strict `.pkt` generation is still blocked.
- `blocked`
  Required donor, bridge, or Packet Tracer runtime pieces are missing.

## How To Read `--doctor`

- if `runtime_grade=ready`, strict decode/edit/generate and `validate_open` are available from the current checkout
- if `runtime_grade=partially_ready`, at least one operation still works, but the product contract is not fully satisfied
- if `runtime_grade=blocked`, no critical runtime path is ready enough to claim strict `.pkt` support

High-signal mixed case:

- `validate_open` can be `ready` while `inventory`, `decode`, `edit`, and `generate` are blocked
- this means Packet Tracer is installed, but the donor and/or bridge path is still not sufficient for strict `.pkt` work

## Bridge Resolution

- `repo_local`
  A repo-local vendor bridge is resolved.
- `external_env`
  A bridge is only available through an external environment path.
- `missing`
  No usable bridge is resolved.

## Publish-Preview Policy

For `0.2.x` publish-preview:

- external bridge assisted testing is acceptable
- docs must say this explicitly
- README must not imply the repo is self-contained if it is not

For `1.0.0`:

- either repo-local readiness improves
- or the Windows-first external-bridge-assisted contract remains explicit and stable

## Required Messaging

If tests pass only with an external bridge:

- do not say "runtime ready" without qualification
- do say "validated with external bridge override"
- do preserve the difference between repo-local readiness and external fallback
- do say when `validate_open` is ready but strict decode/edit/generate are still blocked
