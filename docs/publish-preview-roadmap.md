# Publish-Preview Roadmap

## Step A: Internal Freeze

- completed
- release surface is commit-ready
- checklist dry run passes
- changelog reflects the current batch
- docs and runtime wording match actual behavior
- template fallback assets are checked in and release-surface tests protect them

## Step B: Public `0.2.x` Publish-Preview

- `package.json` is versioned at `0.2.2`
- npm publish target is `packet-tracer-skill@0.2.2`
- release notes source is ready: `docs/release-notes-0.2.2.md`
- hero visual is locked to `examples/screenshots/complex_campus_master_edit_v4.png`
- hero demo execution plan is ready: `docs/hero-demo-plan.md`
- GitHub About/Topics text is finalized in `docs/github-metadata.md`
- launch ops runbook is ready: `docs/github-launch-ops-0.2.2.md`
- npm publish checklist is complete and conservative runtime wording is preserved
- remaining public launch ops are:
  - GitHub release creation
  - About/Topics update in GitHub UI
  - Discussions opening
  - release announcement application

## Step C: `1.0.0` Preparation

- at least one populated curated donor path is publicly proven in practice
- runtime messaging remains conservative and stable
- one richer example family or improved `wan_security_edge` reporting/proof is added
- publish-preview feedback is folded back into docs and trust surface
- post-launch follow-up is tracked in `docs/post-launch-follow-up.md`
