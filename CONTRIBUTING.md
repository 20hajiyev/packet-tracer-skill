# Contributing

## What This Repo Optimizes For

This project is not a generic Packet Tracer exporter. It is a strict, donor-backed, open-first workflow for Cisco Packet Tracer 9.0.0.0810.

When contributing, preserve these rules:

- final `.pkt` apply stays `single-donor`
- unsupported and acceptance-gated mutate must refuse cleanly
- `reference_only` donors must not become final donors
- release/readme/docs claims must match actual runtime and acceptance state

## Recommended Contribution Order

Contributions are preferred in this order:

1. contract consistency
2. tests and regression coverage
3. donor evidence and fixture corpus quality
4. docs and release surface
5. new capability expansion

Do not lead with new mutation behavior if parity, donor evidence, or acceptance truth is still unclear.

## Local Setup

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -Dev
```

Recommended validation:

```powershell
python .\scripts\build_examples_index.py
python -m pytest tests -q
node --check .\bin\packet-tracer-skill.js
python .\scripts\generate_pkt.py --parity-report "campus with VLAN DHCP ACL"
python .\scripts\runtime_doctor.py
```

## Change Types

### Product Contract Changes

If you change:

- `scenario_generate_decision`
- `scenario_acceptance_summary`
- `scenario_matrix_row`
- `capability_parity`
- runtime doctor payload

then update:

- tests
- README
- example/gallery derivation if affected

### Curated Donor Changes

If you add or promote a curated donor:

- update `references/curated-donor-registry.json`
- keep provenance explicit
- include promotion status and evidence
- do not mark a donor as acceptance-verified without explicit fixture evidence

### Scenario Fixture Changes

If you add or modify a scenario fixture:

- update `references/scenario-fixture-corpus.json`
- keep canonical prompt text and expectations aligned
- update docs/examples language if the fixture is public-facing

### Example Artifact Changes

Public examples are text-first:

- commit inventory JSON
- commit screenshots if intended for public docs
- do not commit raw `.pkt` binaries
- rebuild `examples/index.json` and `examples/gallery.md`

## Pull Request Expectations

A good change should answer:

- what contract changed
- why it changed
- what tests prove it
- what docs or examples were updated

If the change affects runtime behavior, explicitly say whether it changes:

- repo-local readiness
- external bridge fallback
- donor eligibility
- acceptance gating

## Release Surface Rules

Do not make public README or npm claims that exceed actual tested behavior.

Current high-sensitivity claims:

- Windows-first runtime
- Packet Tracer `9.0.0.0810`
- donor-backed safe-open generate behavior
- curated donor and fixture corpus semantics

## Security and Privacy

Never commit:

- personal donor paths
- generated labs unless intentionally public
- private or unsigned bridge binaries
- local Packet Tracer install paths baked into tracked files
