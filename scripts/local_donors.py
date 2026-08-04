#!/usr/bin/env python3
"""Index every local lab that could serve as a generation base, not just one.

The base-donor pool used to be a single file. `_compat_donor_candidate()`
resolves one compatibility donor, the bundled Cisco samples are all rejected by
the exact-build policy, and curated donor roots are empty unless someone passes
`--donor-root`. So whatever that one donor happened to lack, the skill declared
impossible.

Measured on this machine: 143 local labs carry the running build, several of
them with wireless routers, access points, laptops and IP phones -- while the
chosen donor was a wired campus lab. `1 wireless router 2 laptop qur` was
reported as a donor limitation. It was a donor *selection* limitation.

Indexing them is not free: a full summary is ~770 ms per lab, so 143 labs cost
~110 s, against a 5-7 s generation. The index is therefore cached on disk and
keyed by size and mtime, which makes a warm run cost little more than a `stat`
per file. Version is read with `peek_pkt_header` (~13 ms) before the expensive
summary, so labs on the wrong build never get decoded at all.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from packet_tracer_env import (
    donor_compatibility,
    donor_tier_is_accepted,
    get_donor_policy,
    get_packet_tracer_target_version,
)
from pkt_codec import peek_pkt_header

DEFAULT_INDEX_PATH = Path.home() / ".pkt" / "local-donor-index.json"
DEFAULT_SEARCH_ROOTS = [
    Path.home() / "Downloads",
    Path.home() / "Documents",
    Path.home() / "Desktop",
]
# A ceiling on how much of a lab collection to consider. Ranking gets no better
# past a few dozen candidates, and the first-run indexing cost is linear.
DEFAULT_SCAN_LIMIT = 400

_VERSION_PATTERN = re.compile(rb"<VERSION>([^<]*)</VERSION>")

# `Documents` on this machine holds 414,000 entries and takes 12 s to walk
# recursively -- twice a whole generation run, spent almost entirely inside
# checkouts and dependency trees. Saved labs live at the top of a folder or one
# or two levels down, so the walk is bounded instead of exhaustive.
DEFAULT_MAX_DEPTH = 3
SKIPPED_DIRECTORY_NAMES = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".tox", "site-packages", "dist", "build", ".cache", ".pytest_cache",
    "AppData", ".idea", ".vscode",
    # Generated labs must never become donors. Without this the skill happily
    # picked its own `output/` files as a base -- a lab derived from a lab,
    # carrying every simplification the first pass made.
    "output", "outputs", "scratchpad", "tmp", "temp", ".pkt-cache",
}


def _iter_pkt_files(root: Path, max_depth: int) -> list[Path]:
    """`.pkt` files within `max_depth` levels of `root`, skipping code trees."""
    found: list[Path] = []
    frontier = [(root, 0)]
    while frontier:
        directory, depth = frontier.pop()
        try:
            entries = list(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir():
                    if depth + 1 <= max_depth and entry.name not in SKIPPED_DIRECTORY_NAMES:
                        frontier.append((entry, depth + 1))
                elif entry.suffix.lower() == ".pkt":
                    found.append(entry)
            except OSError:
                continue
    return sorted(found)


@dataclass(frozen=True)
class LocalDonor:
    path: Path
    version: str
    device_counts: dict[str, int] | None = None


def _device_counts_of(path: Path) -> dict[str, int]:
    """Device types a lab contains. Requires a full decode, so cache the result."""
    from collections import Counter

    from pkt_codec import decode_pkt_auto, parse_pkt_xml

    try:
        xml, _container = decode_pkt_auto(path.read_bytes(), verify=False)
        root = parse_pkt_xml(xml)
    except Exception:  # noqa: BLE001 - unreadable labs are simply not donors
        return {}
    counts = Counter(
        (device.findtext("./ENGINE/TYPE", default="") or "").strip()
        for device in root.findall(".//DEVICES/DEVICE")
    )
    return {kind: count for kind, count in counts.items() if kind}


# Packet Tracer's own type names do not match the words a prompt uses, and a
# request for a laptop is served just as well by any of these.
TYPE_EQUIVALENTS: dict[str, tuple[str, ...]] = {
    "WirelessRouter": ("WirelessRouter", "WirelessRouterNewGeneration", "LinksysWRT300N"),
    "Laptop": ("Laptop", "WirelessEndDevice", "LaptopPT"),
    "Tablet": ("Tablet", "TabletPC", "Pda"),
    "LightWeightAccessPoint": ("LightWeightAccessPoint", "AccessPoint", "AccessPointPT"),
    "PC": ("PC", "Pc", "PcPT"),
    "Server": ("Server", "ServerPT"),
    "Switch": ("Switch", "MultiLayerSwitch"),
    "Smartphone": ("Smartphone", "WirelessEndDevice"),
    "MCUComponent": ("MCUComponent", "Thing", "IoE", "SBC", "MCU"),
    "Thing": ("Thing", "MCUComponent", "IoE"),
}


def covers_requested_types(counts: dict[str, int], required: dict[str, int]) -> bool:
    """Whether a lab can supply every device kind a prompt asked for."""
    for kind, needed in required.items():
        if needed <= 0:
            continue
        names = TYPE_EQUIVALENTS.get(kind, (kind,))
        if sum(counts.get(name, 0) for name in names) <= 0:
            return False
    return True


def local_donor_search_roots() -> list[Path]:
    """Where to look for the user's own labs.

    `PKT_LOCAL_DONOR_ROOTS` overrides, using the platform path separator.
    """
    override = (os.getenv("PKT_LOCAL_DONOR_ROOTS") or "").strip()
    if override:
        return [Path(part) for part in override.split(os.pathsep) if part.strip()]

    roots = list(DEFAULT_SEARCH_ROOTS)

    # A donor that ships with the skill. Everything else here depends on the
    # user having Packet Tracer labs on disk -- their own, or the ones Packet
    # Tracer installs -- so a machine with only the skill on it could not
    # generate at all. This one carries a switch with hosts plus the device
    # kinds no ordinary lab contains, and was built and saved through Packet
    # Tracer itself, so it opens like any other.
    shipped = Path(__file__).resolve().parent.parent / "templates" / "pt900" / "donors"
    if shipped.exists():
        roots.append(shipped)
    # Packet Tracer installs several hundred labs under its own `saves/`, and
    # measurement showed it opens every one of them: the version gate is an
    # ordering on major.minor.patch, and a bundled sample is by definition at or
    # below the installed release. They are searched last, so a user's own labs
    # still win, but their presence is what lets a fresh machine generate
    # without downloading a donor first.
    try:
        from packet_tracer_env import get_packet_tracer_saves_root

        bundled = get_packet_tracer_saves_root()
    except Exception:  # noqa: BLE001 - donor discovery must never fail a run
        bundled = None
    if bundled is not None and bundled not in roots:
        roots.append(bundled)
    return roots


def local_donor_indexing_enabled() -> bool:
    return (os.getenv("PKT_LOCAL_DONORS") or "").strip().lower() not in {"0", "off", "false", "no"}


def _version_of(path: Path) -> str:
    """Read `<VERSION>` from the header alone, without decoding the whole lab."""
    try:
        header = peek_pkt_header(path.read_bytes())
    except Exception:  # noqa: BLE001 - an unreadable lab is simply not a donor
        return ""
    match = _VERSION_PATTERN.search(header)
    return match.group(1).decode("utf-8", "replace").strip() if match else ""


def _load_index(index_path: Path) -> dict[str, dict[str, object]]:
    try:
        raw = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    entries = raw.get("entries") if isinstance(raw, dict) else None
    return entries if isinstance(entries, dict) else {}


def _save_index(index_path: Path, entries: dict[str, dict[str, object]]) -> None:
    try:
        index_path.parent.mkdir(parents=True, exist_ok=True)
        index_path.write_text(
            json.dumps({"version": 1, "entries": entries}, indent=1), encoding="utf-8"
        )
    except OSError:
        # The index is an optimisation. Failing to persist it must never fail a
        # generation run.
        pass


def discover_local_donors(
    *,
    roots: list[Path] | None = None,
    index_path: Path | None = None,
    scan_limit: int = DEFAULT_SCAN_LIMIT,
    max_depth: int = DEFAULT_MAX_DEPTH,
    exclude: set[str] | None = None,
    required_types: dict[str, int] | None = None,
    stop_after: int = 0,
) -> list[LocalDonor]:
    """Local labs whose build the running Packet Tracer will accept.

    Results are cached by size and mtime, so only new or edited files pay the
    header read.

    `required_types` additionally filters on what a lab *contains*, which costs
    a full decode the first time a lab is seen (~770 ms) and nothing after that.
    Pass `stop_after` to return as soon as enough matches are found, so the
    common case never pays for the whole collection.
    """
    if not local_donor_indexing_enabled():
        return []

    index_path = index_path or DEFAULT_INDEX_PATH
    entries = _load_index(index_path)
    target = get_packet_tracer_target_version()
    policy = get_donor_policy()
    excluded = {name.lower() for name in (exclude or set())}

    found: list[LocalDonor] = []
    scanned = 0
    dirty = False
    for root in roots or local_donor_search_roots():
        if not root.exists():
            continue
        candidates = _iter_pkt_files(root, max_depth)
        for path in candidates:
            if scanned >= scan_limit:
                break
            scanned += 1
            if path.name.lower() in excluded:
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            key = str(path)
            cached = entries.get(key)
            if (
                isinstance(cached, dict)
                and cached.get("size") == stat.st_size
                and cached.get("mtime_ns") == stat.st_mtime_ns
            ):
                version = str(cached.get("version") or "")
            else:
                version = _version_of(path)
                entries[key] = {
                    "size": stat.st_size,
                    "mtime_ns": stat.st_mtime_ns,
                    "version": version,
                }
                dirty = True
            if not version:
                continue
            if not donor_tier_is_accepted(donor_compatibility(version, target), policy):
                continue

            counts: dict[str, int] | None = None
            if required_types:
                entry = entries.get(key) or {}
                cached_counts = entry.get("device_counts")
                if isinstance(cached_counts, dict):
                    counts = {str(k): int(v) for k, v in cached_counts.items()}
                else:
                    counts = _device_counts_of(path)
                    entry["device_counts"] = counts
                    entries[key] = entry
                    dirty = True
                if not covers_requested_types(counts, required_types):
                    continue

            found.append(LocalDonor(path=path, version=version, device_counts=counts))
            if stop_after and len(found) >= stop_after:
                if dirty:
                    _save_index(index_path, entries)
                return found

    if dirty:
        _save_index(index_path, entries)
    return found


def main() -> int:  # pragma: no cover - operator convenience
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=DEFAULT_SCAN_LIMIT)
    args = parser.parse_args()

    donors = discover_local_donors(scan_limit=args.limit)
    print(f"{len(donors)} local lab(s) usable as a generation base:")
    for donor in donors[:40]:
        print(f"  {donor.version}  {donor.path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
