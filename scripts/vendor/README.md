# Twofish Engines

The Packet Tracer `.pkt` codec uses Twofish in EAX mode. Two engines live here.

## `twofish_pure.py` — the baseline (always available)

A vendored pure-Python Twofish. Twofish is unpatented and uncopyrighted by
design, so it can be implemented and shipped directly.

- no compiled artifacts, no environment variables, no per-host setup
- works on any supported Python (3.10+) and any OS
- verified at import-time diagnostics against the three official test vectors
  from section B.2 of the Twofish book (128/192/256-bit)
- bit-identical to the compiled bridge; `tests/test_twofish_pure.py` asserts
  this whenever both are present

This is what `pkt_codec` uses unless a compiled bridge is found. Nothing has to
be installed for `decode`, `inventory`, `edit`, or `generate` to work.

Cost: roughly 14 µs per block. A typical 280 KB lab decodes in under a second;
the largest labs seen so far (~2.8 MB) take about 12 seconds.

## `twofish.py` — the optional accelerator

A ctypes wrapper around a compiled `_twofish` C library. Roughly 12x faster than
the pure engine, and worth setting up if you routinely process large labs or
scan the whole sample corpus. It is never required.

The wrapper loads the bridge from, in order:

1. `PKT_TWOFISH_LIBRARY`
2. directories listed in `PKT_TWOFISH_SEARCH_ROOTS`
3. a sibling file in this folder named like `_twofish*.pyd` / `.so` / `.dylib` / `.dll`

Example on Windows:

```powershell
$env:PKT_TWOFISH_LIBRARY="C:\path\to\_twofish.cp314-win_amd64.pyd"
```

The compiled bridge is ABI-locked to one Python version. The current filename
contract is `_twofish.cp314-win_amd64.pyd` (macOS `_twofish.cp314-macos*.dylib`,
Linux `_twofish.cp314-linux*.so`). On any other Python version the accelerator is
skipped and the pure engine is used instead — this is not an error.

## Which engine am I using?

```bash
python scripts/runtime_doctor.py
```

Read `twofish_backend`: `pure_python` or `compiled`.

## Security and privacy

- this repository ships no prebuilt machine-specific binaries
- do not commit binaries that embed private paths, usernames, or build metadata
- prefer rebuilding the bridge reproducibly for your own machine

## Licensing

`twofish_pure.py` is original work implemented from the published Twofish
specification and is covered by this repository's licence. `twofish.py` derives
from the BSD-3-Clause Python Twofish ctypes bindings; see
`LICENSES/LICENSE.Twofish-BSD-3-Clause.txt`.
