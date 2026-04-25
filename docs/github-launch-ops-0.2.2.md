# GitHub Launch Ops for `v0.2.2`

## Current Status

- npm package target is `packet-tracer-skill@0.2.2`
- release body source is ready: `docs/release-notes-0.2.2.md`
- launch wording source is ready: `docs/launch-announcement-0.2.2.md`
- About text and Topics source remain: `docs/github-metadata.md`
- hero visual remains fixed: `examples/screenshots/complex_campus_master_edit_v4.png`

## Exact GitHub Release Steps

1. Ensure tag `v0.2.2` exists and points to the publish commit.
2. Open GitHub Releases for `20hajiyev/packet-tracer-skill`.
3. Create a new release from tag `v0.2.2`.
4. Use title `v0.2.2`.
5. Paste the body from `docs/release-notes-0.2.2.md`.
6. Do not upload raw `.pkt` binaries or local bridge artifacts.
7. Keep the first visual aligned with `examples/screenshots/complex_campus_master_edit_v4.png`.

## About and Topics

Apply the exact text from `docs/github-metadata.md`.

Do not rewrite these ad hoc in the UI. The doc is the source of truth.

## Discussions

If Discussions are not already enabled, enable them and create these categories:

- `Showcase`
- `Q&A`
- `Donor Requests`
- `Capability Roadmap`

## Launch Message Sources

Use:

- `docs/release-notes-0.2.2.md` for the release body
- `docs/launch-announcement-0.2.2.md` for the npm/GitHub/social wording
- `docs/hero-demo-plan.md` for the screenshot caption and demo claim guardrails
