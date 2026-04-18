# Twofish Bridge Setup

This repository does not ship a prebuilt Twofish bridge binary by default.

The Packet Tracer `.pkt` codec needs a local Twofish bridge at runtime for
modern Packet Tracer 9.x encode/decode operations.

## Supported loading paths

The wrapper in `twofish.py` loads the bridge from one of these locations:

1. `PKT_TWOFISH_LIBRARY`
2. directories listed in `PKT_TWOFISH_SEARCH_ROOTS`
3. a sibling file in this folder named like:
   - `_twofish*.pyd`
   - `_twofish*.so`
   - `_twofish*.dylib`
   - `_twofish*.dll`

## Recommended public-repo workflow

- keep this repository free of prebuilt machine-specific binaries
- keep the bridge local to your machine
- preferred: place the bridge next to `scripts/vendor/twofish.py` inside the installed skill folder
- optional: store the bridge elsewhere and point `PKT_TWOFISH_LIBRARY` at that local file
- optional: store bridges in one or more local directories and set `PKT_TWOFISH_SEARCH_ROOTS`

Example on Windows:

```powershell
$env:PKT_TWOFISH_LIBRARY="$env:USERPROFILE\.codex\skills\pkt\scripts\vendor\_twofish.cp314-win_amd64.pyd"
```

Example for multiple local search roots:

```powershell
$env:PKT_TWOFISH_SEARCH_ROOTS="$env:USERPROFILE\.codex\skills\pkt\scripts\vendor;$env:USERPROFILE\pkt-bridges"
```

## Supported runtime

- supported Python runtime: `3.14.x`
- current bridge filename: `_twofish.cp314-win_amd64.pyd`
- recommended non-Windows naming contract:
  - macOS: `_twofish.cp314-macos*.dylib`
  - Linux: `_twofish.cp314-linux*.so`
- other Python ABIs are not considered supported by this public setup

## Security and privacy

- do not commit machine-specific binaries unless you have reviewed them
- do not commit binaries that embed private paths, usernames, or internal build metadata
- prefer rebuilding or sourcing the bridge in a reproducible way for your own machine

## Failure mode

If the bridge is missing, the wrapper raises an `ImportError` with setup guidance
instead of silently loading a repo-shipped binary.
