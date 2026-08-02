# Removing the Packet Tracer Install Requirement — Design

Date: 2026-08-02
Status: implemented and verified. See §Correction, which overturns a decision this document originally made.

## Problem

Generation needs a local Packet Tracer installation, which rules out CI, a
server, or any machine other than the one where labs are authored. The codec no
longer needs anything (the vendored pure-Python Twofish removed that), so the
remaining dependency is entirely about *content*: the device XML subtrees that
Packet Tracer expects.

Measured on this checkout:

| Component | Needs Packet Tracer? |
|---|---|
| decode / encode | no |
| structural verification | no |
| generation | yes — a donor `.pkt` for device and link prototypes |
| `validate_open` | yes — `PacketTracer.exe`, unavoidably |
| sample catalogue enrichment | yes — the `saves/` tree |

The exact file set generation reaches for on a machine without the install:

| Path | Used for |
|---|---|
| the resolved compatibility donor | device and link prototypes |
| `01 Networking\FTP\FTP.pkt` | link prototype fallback, FTP service prototype |
| `01 Networking\DNS\Multilevel_DNS.pkt` | server prototype |
| `01 Networking\DHCP\dhcp_reservation.pkt` | wireless prototype |

All four go through `resolve_sample_path()`, which calls
`require_packet_tracer_saves_root()` and raises `FileNotFoundError` when Packet
Tracer is absent.

Device XML is not large: Router 24 KB, Switch 47 KB, PC 16 KB, Server 65 KB. A
whole donor lab compresses to ~280 KB. Size was never the obstacle.

## Decisions

| Decision | Choice |
|---|---|
| What independence means | Generation works on a machine with no Packet Tracer, after one bootstrap on a machine that has it |
| What gets cached | Whole real labs, several of them, chosen for device-family coverage |
| When bootstrap runs | Automatically, the first time a donor is needed |
| Redistribution | None. Cisco content never leaves the licensed machine |

Synthesising device XML from scratch would remove the requirement entirely and
is the only route to *zero* Packet Tracer involvement. The repo asserts Packet
Tracer rejects synthetic XML but never measured it. That is tested separately;
it does not gate this work.

## Architecture

The cache is shaped like a Packet Tracer `saves/` tree, using the same relative
paths:

```
~/.pkt/saves/
  01 Networking/FTP/FTP.pkt
  01 Networking/DNS/Multilevel_DNS.pkt
  01 Networking/DHCP/dhcp_reservation.pkt
  _donors/<coverage-donor>.pkt        1-3 labs chosen for device coverage
  manifest.json
```

Shaping it this way is the whole point. `resolve_sample_path()` and
`require_packet_tracer_saves_root()` are already the single seams every consumer
goes through, so a cache that answers those seams needs **no changes in
`pkt_editor`, `pkt_transformer`, `sample_catalog` or `generate_pkt`**. The
alternative — a `donor_cache` module every consumer must know about — would add
a second model of "where samples live", which is the defect shape this repo has
hit repeatedly.

### Resolution order

`get_packet_tracer_saves_root()`:

1. `PACKET_TRACER_SAVES_ROOT` / `PACKET_TRACER_ROOT`
2. a live Packet Tracer install
3. the cache

When a live install is found and the cache is empty or stale, bootstrap runs:
copy the named prototype samples plus the coverage donors, write the manifest,
print one line saying what was cached and where.

### Coverage selection

Coverage donors come from the sample catalogue, which already records `devices`,
`version` and `capability_tags`. For each device family not covered by the
prototype samples, take the smallest lab that is version-compatible under the
active donor policy and contains that family. Cap at three donors.

## Components

`scripts/donor_cache.py`

```python
cache_root() -> Path                       # ~/.pkt/saves, or PKT_DONOR_CACHE
cache_enabled() -> bool                    # PKT_DONOR_CACHE=off disables
REQUIRED_PROTOTYPE_SAMPLES: tuple[str, ...]
manifest_path() -> Path
read_manifest() -> dict | None
cache_is_usable() -> bool                  # manifest valid and every file present
bootstrap(saves_root, catalog, limit=3) -> BootstrapReport
```

`BootstrapReport` records `cached_paths`, `coverage_families`, `skipped`,
`bytes_written` and `source_root`, so the one-line message and the tests read
the same data.

`scripts/packet_tracer_env.py` gains the cache tier in
`get_packet_tracer_saves_root()`. Nothing else changes.

## Data flow

```
generate
  → resolve_sample_path(...)
      → require_packet_tracer_saves_root()
          → env override            → use it
          → live Packet Tracer      → use it; bootstrap cache if stale
          → cache is usable         → use the cache
          → nothing                 → FileNotFoundError naming the missing files
  → donor prototypes read from whichever root answered
```

## Error handling

| Condition | Behaviour |
|---|---|
| No Packet Tracer, usable cache | Generation proceeds from the cache |
| No Packet Tracer, no cache | Refuse, naming the four required files and how to populate the cache from a machine that has Packet Tracer |
| Manifest missing, unreadable, or referencing absent files | Treat the cache as unusable; rebuild if a live install is present |
| Manifest target version differs from the active target | Rebuild rather than serve a mismatched donor |
| Cache directory not writable | Warn once and continue using the live install; never fail generation because caching failed |
| `PKT_DONOR_CACHE=off` | Cache tier is skipped entirely |

Bootstrap failure must never fail a generation that would otherwise succeed.
The cache is an optimisation of availability, not a correctness dependency.

## Testing

**Unit** — cache root honours `PKT_DONOR_CACHE`; `cache_is_usable` is false for
a missing manifest, a manifest listing an absent file, and a version mismatch;
bootstrap copies exactly the required prototype samples; coverage selection
picks version-compatible donors and respects the cap; an unwritable cache
degrades instead of raising.

**Integration** — with `get_packet_tracer_root` patched to `None` and a
populated cache, `require_packet_tracer_saves_root()` returns the cache and a
prompt still generates a structurally valid `.pkt`. With neither, the refusal
names the missing files.

**Corpus** — run `corpus_runner.py` with the live install hidden. That is the
real proof: same results from the cache alone.

## Scope

In scope: `donor_cache.py`, the resolver tier, the tests above, and a `--doctor`
line reporting cache state.

Out of scope: synthesising device XML, bundling Cisco content, and removing the
`validate_open` dependency, which is irreducible — only Packet Tracer can say a
file opens.


---

## Correction: what the open test overturned

The design assumed the donor compatibility ladder's `same_minor` tier was safe
for a generation base. A real Packet Tracer open test contradicted it twice.

**First attempt.** Generating from a cached `9.0.0.0000` bundled sample produced
a file Packet Tracer refused with a precise message:

> This file requires Cisco Packet Tracer version 9.0.0.0000. Your current
> version is 9.0.0.0810.

So Packet Tracer enforces the build, not just the release line. Donor-prune
inherits the donor's `<VERSION>`, and nothing was stamping the output.

**Second attempt.** Stamping the running build onto the output changed the error
but not the outcome — Packet Tracer then reported the generic "not compatible
with this version". Relabelling does not migrate the donor's internal
structures.

**Conclusion, now measured rather than assumed:** a generation base must be a lab
the running install actually wrote. None of the 292 bundled Cisco samples
qualifies. This inverts the earlier `0 → 48 eligible donors` result: those 48
are classifiable as `same_minor`, but they are not usable as bases.

### What changed as a result

- `DEFAULT_DONOR_POLICY` is `exact`. Looser tiers remain available for
  inspection and for `--explain-plan`, and via `PACKET_TRACER_DONOR_POLICY`.
- The generated file is stamped with the running build
  (`_stamp_target_version`), which is detected by reading a lab the local
  install saved rather than the install directory name — the directory gives
  `9.0.0`, which is a release, not a build.
- The cache stores **locally saved labs at the running build**, ranked by access
  structure, not bundled samples.
- `cache_is_usable` compares release lines directly instead of deferring to the
  donor policy. Those are different questions, and reusing the policy for both
  would have discarded a good cache on the machine it exists to serve.

### Verified

With `get_packet_tracer_root` and `get_packet_tracer_exe` patched to `None` and
the user's lab directories emptied from the search path:

```
saves  -> ~/.pkt/saves
donor  -> ~/.pkt/saves/_donors/Yusif_K231.pkt
output -> 6 devices, VERSION 9.0.0.0810, structural check passes
open   -> opened, 13.3 s
```

Generation no longer requires a Packet Tracer installation. `validate_open`
still does, irreducibly: only Packet Tracer can say a file opens.
