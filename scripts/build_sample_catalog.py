#!/usr/bin/env python3
"""Rebuild the installed-sample catalogue from the local Packet Tracer saves.

This used to carry its own `summarize_pkt`, which omitted link endpoints. The
committed catalogue was therefore written with 1051 link records that had no
`from`/`to`, and every downstream check that reasoned about donor topology was
comparing empty strings against each other. `sample_catalog._summarize_pkt`
extracts endpoints correctly and reads both container variants, so the builder
now calls it rather than keeping a second, weaker copy.
"""

from __future__ import annotations

from pathlib import Path

from packet_tracer_env import require_packet_tracer_saves_root
from sample_catalog import _summarize_pkt, write_catalog_outputs


def _local_donor_items(catalogued: set[str]) -> list[dict]:
    """Labs the user saved outside the Packet Tracer installation.

    Donor selection ranks candidates from this catalogue, and the catalogue
    only ever held the installed samples. So a lab saved specifically to serve
    as a donor was discovered by `discover_local_donors`, reported as present,
    and never ranked -- generation for a five-switch topology stayed blocked
    with "no ranked donor candidate passed validation" while a donor that fit
    sat on disk.

    These entries carry an absolute `path` rather than one relative to the
    saves root, which is why `_catalog_item_path` has to keep it.
    """
    try:
        from local_donors import discover_local_donors
    except ImportError:  # pragma: no cover - discovery is optional
        return []

    items: list[dict] = []
    for donor in discover_local_donors():
        path = Path(donor.path)
        if str(path) in catalogued or not path.is_file():
            continue
        try:
            item = _summarize_pkt(path, path.name, "user-local", True)
        except Exception as exc:
            items.append(
                {"relative_path": path.name, "source_path": str(path), "error": f"{type(exc).__name__}: {exc}"}
            )
            continue
        # `source_path`, not `path`: the writer drops `path` so the committed
        # catalogue does not depend on whose machine built it.
        item["source_path"] = str(path)
        items.append(item)
    return items


def build_catalog() -> list[dict]:
    saves_root = require_packet_tracer_saves_root()
    items: list[dict] = []
    catalogued: set[str] = set()
    for path in sorted(saves_root.rglob("*.pkt")):
        relative_path = str(path.relative_to(saves_root))
        catalogued.add(str(path))
        try:
            items.append(_summarize_pkt(path, relative_path, "cisco-local", True))
        except Exception as exc:
            items.append({"relative_path": relative_path, "error": f"{type(exc).__name__}: {exc}"})
    items.extend(_local_donor_items(catalogued))
    return items


def main() -> None:
    require_packet_tracer_saves_root()
    items = build_catalog()
    write_catalog_outputs(items)
    readable = sum(1 for item in items if "error" not in item)
    with_endpoints = sum(
        1
        for item in items
        for link in item.get("links", [])
        if str(link.get("from") or "") and str(link.get("to") or "")
    )
    print(f"Wrote {len(items)} entries ({readable} readable, {with_endpoints} links with endpoints)")


if __name__ == "__main__":
    main()
