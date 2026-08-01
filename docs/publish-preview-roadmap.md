# Publish-Preview Roadmap

## Step A: Internal Freeze

- completed
- release surface is commit-ready
- checklist dry run passes
- changelog reflects the current batch
- docs and runtime wording match actual behavior
- template fallback assets are checked in and release-surface tests protect them

## Step B: Public `0.2.x` Publish-Preview

- `packet-tracer-skill@0.2.3` is the current published capability release
- next candidate line is `0.2.4`, with notes drafted in `docs/release-notes-0.2.4.md`
- package version remains `0.2.3` until a `0.2.4` publish decision is made
- hero visual is locked to `examples/screenshots/complex_campus_master_edit_v4.png`
- hero demo execution plan is ready: `docs/hero-demo-plan.md`
- GitHub About/Topics text is finalized in `docs/github-metadata.md`
- active launch ops source is `docs/github-launch-ops-0.2.3.md`
- historical `0.2.1` and `0.2.2` launch ops runbooks remain archived
- npm publish checklist is complete and conservative runtime wording is preserved
- remaining public launch ops are:
  - GitHub release object verification for the current published tag
  - About/Topics update in GitHub UI
  - Discussions opening
  - release announcement application

## Step C: `1.0.0` Preparation

- at least one populated curated donor path is publicly proven in practice
- runtime messaging remains conservative and stable
- one richer example family or improved `wan_security_edge` reporting/proof is added
- publish-preview feedback is folded back into docs and trust surface
- post-launch follow-up is tracked in `docs/post-launch-follow-up.md`
