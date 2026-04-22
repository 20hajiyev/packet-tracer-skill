# Publish-Preview Roadmap

## Step A: Internal Freeze

- completed
- release surface is commit-ready
- checklist dry run passes
- changelog reflects the current batch
- docs and runtime wording match actual behavior
- template fallback assets are checked in and release-surface tests protect them

## Step B: Public `0.2.x` Publish-Preview

- `package.json` is versioned at `0.2.1`
- release notes draft is ready: `docs/release-notes-0.2.1.md`
- hero visual is locked to `examples/screenshots/complex_campus_master_edit_v4.png`
- hero demo execution plan is ready: `docs/hero-demo-plan.md`
- GitHub About/Topics text is finalized in `docs/github-metadata.md`
- npm publish checklist is complete and conservative runtime wording is preserved
- final publish batch should only do:
  - npm publish
  - GitHub release creation
  - About/Topics update in GitHub UI
  - Discussions opening and release announcement

## Step C: `1.0.0` Preparation

- at least one populated curated donor path is actively used in practice
- runtime messaging remains conservative and stable
- one richer example family or improved `wan_security_edge` reporting is added
- publish-preview feedback is folded back into docs and trust surface
