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

High-signal fields:

- `what_currently_works`
  Short sentence for the operations that are usable right now.
- `what_is_blocked`
  Short sentence for the operations that are still blocked.
- `why_it_is_blocked`
  Product-facing reason for the current blocker set.
- `best_next_fix`
  The single next fix that should be done first.

High-signal mixed case:

- `validate_open` can be `ready` while `inventory`, `decode`, `edit`, and `generate` are blocked
- this means Packet Tracer is installed, but the donor and/or bridge path is still not sufficient for strict `.pkt` work
- in that state, `best_next_fix` should point at donor or bridge remediation before anything else

Another mixed case:

- all listed operations can be operationally ready while `bridge_resolution=external_env`
- that still means the checkout is only partially ready as a packaged repo surface
- docs should continue saying `validated with external bridge override` rather than implying repo-local readiness

## Twofish Engine

The cipher is no longer a runtime blocker. `scripts/vendor/twofish_pure.py` is a
vendored pure-Python Twofish, verified against the official test vectors at
diagnostic time, so `decode`, `inventory`, `edit`, and `generate` are available
on a clean checkout with no binaries and no environment variables.

`twofish_backend` reports which engine is active:

- `pure_python`
  The vendored repo-local engine. Always available. This is the baseline.
- `compiled`
  A `_twofish` C bridge resolved from `PKT_TWOFISH_LIBRARY`,
  `PKT_TWOFISH_SEARCH_ROOTS`, or `scripts/vendor/`. Optional, roughly 12x faster
  on large labs, and bit-identical to the pure engine.

`bridge_resolution` describes only where the *optional accelerator* came from.
It no longer downgrades `runtime_grade`, and `external_env` is not a blocker.

## Test Profiles

There is one gate. The suite runs the same way with or without a compiled
bridge, and nothing is skipped for lack of one:

```
python -m pytest tests -q
```

`PKT_REQUIRE_TWOFISH_TESTS=1` is still honoured for hosts that want to assert a
compiled accelerator is present, but it is no longer needed to prove real
`.pkt` decode/edit works.

The doctor payload exposes this as `runtime_gate_status` and repeats the most useful user-facing answer in `user_summary`. Consumers should show `user_summary.status`, `user_summary.message`, and `user_summary.next_best_action` before dumping the full diagnostic JSON.

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
- do keep `what_currently_works`, `what_is_blocked`, and `best_next_fix` aligned with `doctor_summary`
