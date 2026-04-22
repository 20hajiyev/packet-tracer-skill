# Release Checklist

## Product Contract

- `scenario_generate_decision`, `scenario_acceptance_summary`, `scenario_matrix_row`, `capability_parity`, and runtime doctor wording are internally consistent
- curated donor registry and scenario fixture corpus reflect current behavior
- README claims do not exceed tested behavior

## Validation

Run:

```powershell
python .\scripts\build_examples_index.py
python -m pytest tests -q
node --check .\bin\packet-tracer-skill.js
python .\scripts\generate_pkt.py --parity-report "campus with VLAN DHCP ACL"
python .\scripts\runtime_doctor.py
```

## Package Audit

- `package.json` description matches current product scope
- keyword clusters cover Packet Tracer, networking labs, AI/natural language, and host ecosystems
- `files` includes docs and runtime assets needed by consumers
- version bump matches semver intent

## Public Artifacts

- raw `.pkt` binaries are not committed
- examples index and gallery were rebuilt
- screenshots are intentional and non-sensitive
- changelog entry is updated
- runtime truth docs match current `runtime_grade` and `bridge_resolution` semantics
- curated donor registry entries are reviewed for promotion status and provenance

## GitHub Surface

- CI workflow is green
- issue templates are present
- contributing and security docs exist
- citation metadata exists
- About/Topics are ready to be updated in GitHub UI

## Publish Gate

Only publish when:

- CI is green
- README renders cleanly
- doctor wording matches current runtime reality
- no accidental local paths leaked into tracked files
