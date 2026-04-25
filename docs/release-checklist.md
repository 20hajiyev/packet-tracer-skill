# Release Checklist

Target release surface: `0.2.2` conservative public preview.

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
- changelog entry is updated for `0.2.2`
- release notes source exists: `docs/release-notes-0.2.2.md`
- hero demo plan exists: `docs/hero-demo-plan.md`
- GitHub launch ops runbook exists: `docs/github-launch-ops-0.2.2.md`
- canonical donor proof exists: `docs/campus-donor-proof.md`
- hero visual is selected: `examples/screenshots/complex_campus_master_edit_v4.png`
- runtime truth docs match current `runtime_grade` and `bridge_resolution` semantics
- curated donor registry entries are reviewed for promotion status and provenance

## GitHub Surface

- CI workflow is green
- issue templates are present
- contributing and security docs exist
- citation metadata exists
- About/Topics are ready to be updated in GitHub UI
- release body source is ready for direct paste into GitHub Releases
- Discussions categories are decision-complete in docs

## Publish Gate

Only publish when:

- CI is green
- README renders cleanly
- `package.json` version is final for the publish-preview batch
- doctor wording matches current runtime reality
- no accidental local paths leaked into tracked files
- GitHub metadata doc is final and matches README wording
- hero visual and release notes are ready for direct reuse

## Post-Publish Follow-Up

- apply GitHub launch ops if they were not automated
- publish one canonical donor proof note
- use `docs/post-launch-follow-up.md` as the source for the next patch trigger conditions
