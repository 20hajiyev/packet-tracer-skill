#!/usr/bin/env python3
"""A local cache of donor labs, so generation stops needing Packet Tracer installed.

The codec is self-contained, but generation still reads device and link
prototypes out of real Packet Tracer saves. That made a local install a hard
requirement for CI, servers, and any machine other than the one where labs are
authored.

The cache is deliberately shaped like a Packet Tracer `saves/` tree, using the
same relative paths. `resolve_sample_path()` and `require_packet_tracer_saves_root()`
are already the single seams every consumer goes through, so a cache that
answers those seams needs no changes anywhere downstream. A separate "where do
samples live" model would be a second source of truth, which is the defect shape
this repo has hit repeatedly.

Nothing is redistributed: the cache is populated from the user's own licensed
install and never leaves the machine.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

MANIFEST_VERSION = 1
MANIFEST_NAME = "manifest.json"
COVERAGE_DIR = "_donors"
DEFAULT_COVERAGE_LIMIT = 3

# Samples the generation and edit paths name directly. Without these a machine
# with no Packet Tracer cannot build links, servers, or wireless clients.
REQUIRED_PROTOTYPE_SAMPLES: tuple[str, ...] = (
    r"01 Networking\FTP\FTP.pkt",
    r"01 Networking\DNS\Multilevel_DNS.pkt",
    r"01 Networking\DHCP\dhcp_reservation.pkt",
)

# Families worth having a donor for beyond what the prototype samples cover.
COVERAGE_FAMILIES: tuple[str, ...] = ("Router", "Switch", "PC", "Server")


@dataclass
class BootstrapReport:
    source_root: str = ""
    cached_paths: list[str] = field(default_factory=list)
    coverage_families: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    bytes_written: int = 0
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and bool(self.cached_paths)

    def summary(self) -> str:
        if self.error:
            return f"donor cache not written: {self.error}"
        families = ", ".join(self.coverage_families) or "none"
        return (
            f"Cached {len(self.cached_paths)} donor sample(s) "
            f"({self.bytes_written / 1024:.0f} KB, families: {families}) in {cache_root()}. "
            "Generation no longer needs Packet Tracer on this machine."
        )


def cache_enabled() -> bool:
    return (os.getenv("PKT_DONOR_CACHE") or "").strip().lower() not in {"off", "0", "false", "none"}


def cache_root() -> Path:
    override = (os.getenv("PKT_DONOR_CACHE") or "").strip()
    if override and override.lower() not in {"off", "0", "false", "none", "on", "1", "true"}:
        return Path(override).expanduser()
    return Path.home() / ".pkt" / "saves"


def manifest_path() -> Path:
    return cache_root() / MANIFEST_NAME


def read_manifest() -> dict | None:
    try:
        data = json.loads(manifest_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def cache_is_usable(target_version: str | None = None) -> bool:
    """True when the manifest is valid and every file it lists still exists."""
    if not cache_enabled():
        return False
    manifest = read_manifest()
    if not manifest or manifest.get("manifest_version") != MANIFEST_VERSION:
        return False
    cached_target = str(manifest.get("target_version") or "")
    if target_version and cached_target:
        # Compare by compatibility tier, not string equality. The detected target
        # legitimately differs between a machine with Packet Tracer installed
        # (`9.0.0`, from the install directory) and one without it (`9.0.0.0810`,
        # from the donor's own VERSION). Exact matching here would discard a
        # perfectly good cache on exactly the machine it exists to serve — the
        # same mistake the donor gate itself used to make.
        from packet_tracer_env import donor_compatibility

        # Deliberately not `donor_tier_is_accepted`: that follows the donor
        # policy, which is `exact` because a generation *base* must be a lab the
        # running install wrote. This check answers a different question — is the
        # cache from the same release line — so it accepts `same_minor` outright.
        if donor_compatibility(cached_target, target_version) not in {"exact", "same_minor"}:
            return False
    entries = manifest.get("cached_paths") or []
    if not entries:
        return False
    root = cache_root()
    return all((root / str(entry)).exists() for entry in entries)


def _copy_into_cache(source: Path, relative_path: str, report: BootstrapReport) -> None:
    destination = cache_root() / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    report.cached_paths.append(relative_path)
    report.bytes_written += destination.stat().st_size


HOST_FAMILIES = {"PC", "Server", "Printer", "Laptop", "Tablet", "Smartphone"}


def _access_score(devices: list, links: list) -> int:
    """How many hosts hang off switches in this lab.

    Donor-prune keeps a switch and renames the hosts attached to it, so the
    useful measure of a donor is its access structure, not its raw device count.
    A 33-device industrial lab whose switches carry no PCs is a worse donor than
    a small campus lab with six hosts on a switch — exactly the mistake an
    earlier version of this selection made.
    """
    from sample_catalog import normalize_device_type

    kind = {str(device.get("name", "")): normalize_device_type(str(device.get("type", ""))) for device in devices}
    host_links = 0
    router_uplinks = 0
    for link in links:
        left, right = str(link.get("from") or ""), str(link.get("to") or "")
        if not left or not right:
            continue
        pair = {kind.get(left), kind.get(right)}
        if "Switch" in pair and pair & HOST_FAMILIES:
            host_links += 1
        elif "Switch" in pair and "Router" in pair:
            router_uplinks += 1
    # Hosts dominate; a router uplink is worth having but only once or twice.
    # Weighting every uplink equally let a four-router lab with a single PC
    # outrank a campus lab with six hosts on a switch.
    return host_links + min(router_uplinks, 2)


def _local_saved_labs(target_version: str | None, limit: int) -> list[Path]:
    """Labs this Packet Tracer wrote, richest access structure first.

    These are the only files usable as a generation base: their `<VERSION>` is
    the running build, so Packet Tracer opens what is built from them.
    """
    from packet_tracer_env import DEFAULT_DONOR_FALLBACKS, _pkt_version
    from pkt_codec import decode_pkt_auto, parse_pkt_xml
    from sample_catalog import normalize_device_type

    scored: list[tuple[int, Path]] = []
    for directory in DEFAULT_DONOR_FALLBACKS:
        if not directory.exists():
            continue
        try:
            candidates = sorted(directory.glob("*.pkt"))[:20]
        except OSError:
            continue
        for candidate in candidates:
            if target_version and _pkt_version(candidate) != target_version:
                continue
            try:
                root = parse_pkt_xml(decode_pkt_auto(candidate.read_bytes())[0])
            except Exception:
                continue
            devices = [
                {
                    "name": device.findtext("./ENGINE/NAME") or "",
                    "type": normalize_device_type(device.findtext("./ENGINE/TYPE") or ""),
                }
                for device in root.findall(".//DEVICES/DEVICE")
            ]
            ref_to_name = {
                device.findtext("./ENGINE/SAVE_REF_ID") or "": device.findtext("./ENGINE/NAME") or ""
                for device in root.findall(".//DEVICES/DEVICE")
            }
            links = []
            for link in root.findall(".//LINKS/LINK"):
                cable = link.find("./CABLE")
                if cable is None:
                    continue
                links.append(
                    {
                        "from": ref_to_name.get(cable.findtext("FROM") or "", ""),
                        "to": ref_to_name.get(cable.findtext("TO") or "", ""),
                    }
                )
            scored.append((_access_score(devices, links), candidate))

    scored.sort(key=lambda item: (-item[0], item[1].name))
    return [path for _, path in scored[:limit]]


def select_coverage_donors(
    catalog: list,
    target_version: str | None,
    limit: int = DEFAULT_COVERAGE_LIMIT,
) -> list[str]:
    """Pick the best-structured version-compatible lab covering each device family.

    The catalogue already records devices, version and capability tags, so this
    reads existing evidence rather than scanning the install again.
    """
    from packet_tracer_env import donor_compatibility, donor_tier_is_accepted
    from sample_catalog import normalize_device_type

    eligible = []
    for sample in catalog:
        version = getattr(sample, "version", "") or ""
        if target_version and not donor_tier_is_accepted(donor_compatibility(version, target_version)):
            continue
        devices = getattr(sample, "devices", [])
        families = {normalize_device_type(str(device.get("type", ""))) for device in devices}
        eligible.append(
            (
                getattr(sample, "relative_path", ""),
                families,
                _access_score(devices, getattr(sample, "links", [])),
            )
        )

    chosen: list[str] = []
    covered: set[str] = set()
    for family in COVERAGE_FAMILIES:
        if family in covered or len(chosen) >= limit:
            continue
        candidates = [item for item in eligible if family in item[1] and item[0] not in chosen]
        if not candidates:
            continue
        # Best access structure first. A donor exists to be pruned *from*, and
        # what gets reused is a switch with hosts on it, so rank by that rather
        # than by device count or file size.
        relative_path, families, _ = max(
            candidates,
            key=lambda item: (item[2], len(item[1] & set(COVERAGE_FAMILIES)), item[0]),
        )
        chosen.append(relative_path)
        covered |= families
    return chosen


def bootstrap(
    saves_root: Path,
    catalog: list | None = None,
    target_version: str | None = None,
    limit: int = DEFAULT_COVERAGE_LIMIT,
) -> BootstrapReport:
    """Populate the cache from a live Packet Tracer install.

    Never raises: a cache that cannot be written must not fail a generation that
    would otherwise succeed.
    """
    report = BootstrapReport(source_root=str(saves_root))
    if not cache_enabled():
        report.error = "disabled by PKT_DONOR_CACHE"
        return report

    try:
        cache_root().mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        report.error = f"cache directory is not writable: {exc}"
        return report

    try:
        for relative_path in REQUIRED_PROTOTYPE_SAMPLES:
            source = saves_root / relative_path
            if source.exists():
                _copy_into_cache(source, relative_path, report)
            else:
                report.skipped.append(relative_path)

        # Coverage donors must be labs the running install actually wrote.
        # Bundled Cisco samples carry other builds and Packet Tracer refuses to
        # open anything generated from them — relabelling the output does not
        # help, because the donor's structures were never migrated.
        for source in _local_saved_labs(target_version, limit):
            destination_relative = str(Path(COVERAGE_DIR) / source.name)
            _copy_into_cache(source, destination_relative, report)
            report.coverage_families.append(source.stem)
        if not report.coverage_families:
            report.skipped.append(
                f"no locally saved lab at build {target_version} was found to cache as a donor"
            )

        manifest = {
            "manifest_version": MANIFEST_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source_root": str(saves_root),
            "target_version": target_version or "",
            "cached_paths": report.cached_paths,
            "skipped": report.skipped,
        }
        manifest_path().write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        report.error = str(exc)
    return report


def missing_requirements_message() -> str:
    """What to tell a user who has neither Packet Tracer nor a cache."""
    required = "\n  ".join(REQUIRED_PROTOTYPE_SAMPLES)
    return (
        "No Packet Tracer install and no donor cache were found. Generation needs real "
        "Packet Tracer saves for device and link prototypes:\n  "
        f"{required}\n"
        f"Run any generate command once on a machine that has Packet Tracer to populate "
        f"{cache_root()}, then copy that folder here. Set PACKET_TRACER_SAVES_ROOT to "
        "point at an existing saves tree instead."
    )


def cache_status(target_version: str | None = None) -> dict[str, object]:
    """Cache state for `--doctor`."""
    manifest = read_manifest()
    return {
        "enabled": cache_enabled(),
        "root": str(cache_root()),
        "usable": cache_is_usable(target_version),
        "cached_file_count": len(manifest.get("cached_paths", [])) if manifest else 0,
        "created_at": manifest.get("created_at", "") if manifest else "",
        "source_root": manifest.get("source_root", "") if manifest else "",
        "target_version": manifest.get("target_version", "") if manifest else "",
    }


def main() -> int:
    print(json.dumps(cache_status(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
