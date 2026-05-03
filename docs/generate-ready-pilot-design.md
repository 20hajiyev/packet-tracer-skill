# Generate-Ready Pilot Design

This is a design artifact only. It does not enable `generate_ready`.

## Candidate

The first safe pilot should use a narrow campus or service-heavy flow that already has fixture and donor evidence. The preferred pilot is `campus_core_complex` with a single `campus/core` donor class.

## Required Gate

The pilot can only move to implementation when all of these are true:

- exactly one scenario family is in scope
- exactly one donor class is allowed
- exactly one fixture name is used as the regression truth source
- target inventory is deterministic
- final `.pkt` apply remains `single-donor`
- acceptance JSON proves openability, inventory expectations, parity expectations, and decision status

## Explicit Non-Goals

- no L2/QoS generate-ready pilot
- no ASA/security generate-ready pilot
- no WLC/controller generate-ready pilot
- no broad topology synthesis
- no fallback guessed output when donor selection or acceptance is weak

## Next Step

Before implementation, add a short acceptance fixture proposal that names the donor path, expected inventory excerpt, expected parity excerpt, and the refusal condition when that donor is absent.
