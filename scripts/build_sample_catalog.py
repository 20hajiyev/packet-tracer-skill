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

from packet_tracer_env import require_packet_tracer_saves_root
from sample_catalog import _summarize_pkt, write_catalog_outputs


def build_catalog() -> list[dict]:
    saves_root = require_packet_tracer_saves_root()
    items: list[dict] = []
    for path in sorted(saves_root.rglob("*.pkt")):
        relative_path = str(path.relative_to(saves_root))
        try:
            items.append(_summarize_pkt(path, relative_path, "cisco-local", True))
        except Exception as exc:
            items.append({"relative_path": relative_path, "error": f"{type(exc).__name__}: {exc}"})
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
