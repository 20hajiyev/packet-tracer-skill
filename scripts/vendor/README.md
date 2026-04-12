# Twofish Bridge Setup

This repository does not ship a prebuilt Twofish bridge binary by default.

The Packet Tracer `.pkt` codec needs a local Twofish bridge at runtime for
modern Packet Tracer 9.x encode/decode operations.

## Supported loading paths

The wrapper in `twofish.py` loads the bridge from one of these locations:

1. `PKT_TWOFISH_LIBRARY`
2. a sibling file in this folder named like:
   - `_twofish*.pyd`
   - `_twofish*.so`
   - `_twofish*.dll`

## Recommended public-repo workflow

- keep this repository free of prebuilt machine-specific binaries
- store the bridge locally outside the repo when possible
- point `PKT_TWOFISH_LIBRARY` at that local file

Example on Windows:

```powershell
$env:PKT_TWOFISH_LIBRARY='C:\tools\pkt-twofish\_twofish.cp314-win_amd64.pyd'
```

## Security and privacy

- do not commit machine-specific binaries unless you have reviewed them
- do not commit binaries that embed private paths, usernames, or internal build metadata
- prefer rebuilding or sourcing the bridge in a reproducible way for your own machine

## Failure mode

If the bridge is missing, the wrapper raises an `ImportError` with setup guidance
instead of silently loading a repo-shipped binary.
