from __future__ import annotations

import os
import re
import platform
from pathlib import Path
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from functools import lru_cache


DEFAULT_INSTALL_CANDIDATES_BY_OS = {
    "Windows": [
        Path(r"C:\Program Files\Cisco Packet Tracer 9.0.0"),
        Path(r"C:\Program Files\Cisco Packet Tracer"),
        Path(r"C:\Program Files (x86)\Cisco Packet Tracer 9.0.0"),
        Path(r"C:\Program Files (x86)\Cisco Packet Tracer"),
    ],
    "Darwin": [
        Path("/Applications/Cisco Packet Tracer.app/Contents/Resources"),
        Path("/Applications/Packet Tracer.app/Contents/Resources"),
        Path.home() / "Applications" / "Cisco Packet Tracer.app" / "Contents" / "Resources",
    ],
    "Linux": [
        Path("/opt/pt"),
        Path("/opt/packettracer"),
        Path("/usr/local/packettracer"),
        Path.home() / "packettracer",
    ],
}
DEFAULT_PACKET_TRACER_TARGET_VERSION = "9.0.0.0810"
DEFAULT_DONOR_FALLBACKS = [
    Path.home() / "Downloads",
    Path.home() / "Documents",
    Path.home() / "Desktop",
]
DEFAULT_SAMPLE_DONOR_FILES = [
    Path("01 Networking") / "FTP" / "FTP.pkt",
    Path("01 Networking") / "HTTPS" / "HTTPS.pkt",
    Path("01 Networking") / "DNS" / "Multilevel_DNS.pkt",
    Path("01 Networking") / "DHCP" / "dhcp_snooping_trusted_untrusted_gigabit_ports.pkt",
]


@dataclass(frozen=True)
class CompatibilityDonorDetails:
    target_version: str
    resolved_path: Path | None
    donor_version: str | None
    donor_source: str | None
    status: str
    blocking_reason: str
    candidate_paths: list[tuple[str, Path]]
    compatibility_tier: str = ""


# --- donor version compatibility -------------------------------------------
#
# Packet Tracer `<VERSION>` strings look like `major.minor.patch.build`, and the
# build field is *not* a schema identifier: it changes with every point release
# and with every re-save. Requiring an exact build match therefore rejects
# essentially the whole donor corpus. Of the 292 sample saves that ship with
# Packet Tracer 9.0.0, none carry `9.0.0.0810` — 48 are 9.0.0.x with other
# builds, and the rest span 5.x through 8.x.
#
# Tiers are ordered from strictest to loosest. A policy names the loosest tier
# that is still acceptable.

COMPATIBILITY_TIERS = ("exact", "same_minor", "same_major", "upgradeable", "incompatible")
DEFAULT_DONOR_POLICY = "same_minor"

# Packet Tracer reliably upgrades saves from this major version onward on open.
MINIMUM_UPGRADEABLE_MAJOR = 6


def _version_fields(version: str | None) -> tuple[int, ...]:
    if not version:
        return ()
    fields: list[int] = []
    for part in str(version).split("."):
        try:
            fields.append(int(part))
        except ValueError:
            break
    return tuple(fields)


def donor_compatibility(donor_version: str | None, target_version: str | None = None) -> str:
    """Classify a donor `<VERSION>` against the target, as a compatibility tier.

    Returns one of `COMPATIBILITY_TIERS`.
    """
    target_version = target_version or get_packet_tracer_target_version()
    if not donor_version:
        return "incompatible"
    if donor_version == target_version:
        return "exact"

    donor_fields = _version_fields(donor_version)
    target_fields = _version_fields(target_version)
    if len(donor_fields) < 2 or len(target_fields) < 2:
        return "incompatible"

    if donor_fields[:2] == target_fields[:2]:
        return "same_minor"
    if donor_fields[0] == target_fields[0]:
        return "same_major"
    if MINIMUM_UPGRADEABLE_MAJOR <= donor_fields[0] < target_fields[0]:
        return "upgradeable"
    return "incompatible"


def get_donor_policy() -> str:
    """The loosest acceptable compatibility tier, from the environment."""
    raw = (os.getenv("PACKET_TRACER_DONOR_POLICY") or "").strip().lower()
    return raw if raw in COMPATIBILITY_TIERS else DEFAULT_DONOR_POLICY


def donor_tier_is_accepted(tier: str, policy: str | None = None) -> bool:
    policy = policy or get_donor_policy()
    if tier not in COMPATIBILITY_TIERS or policy not in COMPATIBILITY_TIERS:
        return False
    if tier == "incompatible":
        return False
    return COMPATIBILITY_TIERS.index(tier) <= COMPATIBILITY_TIERS.index(policy)


def describe_donor_rejection(donor_version: str, target_version: str, tier: str, policy: str) -> str:
    if tier == "incompatible":
        return (
            f"version {donor_version} is not compatible with target {target_version} "
            f"(Packet Tracer does not reliably upgrade saves older than "
            f"{MINIMUM_UPGRADEABLE_MAJOR}.x)"
        )
    return (
        f"version {donor_version} is tier '{tier}' against target {target_version}, "
        f"but the active donor policy is '{policy}'. "
        f"Set PACKET_TRACER_DONOR_POLICY={tier} to accept it."
    )


def _existing_path(raw: str | None) -> Path | None:
    if not raw:
        return None
    path = Path(raw).expanduser()
    return path if path.exists() else None


def _host_os() -> str:
    return platform.system()


def default_install_candidates(host_os: str | None = None) -> list[Path]:
    return DEFAULT_INSTALL_CANDIDATES_BY_OS.get(host_os or _host_os(), [])


def default_executable_candidates(root: Path, host_os: str | None = None) -> list[Path]:
    system = host_os or _host_os()
    if system == "Windows":
        return [root / "bin" / "PacketTracer.exe", root / "PacketTracer.exe"]
    if system == "Darwin":
        return [
            root / "bin" / "PacketTracer",
            root / "Packet Tracer",
            root / "MacOS" / "Packet Tracer",
        ]
    if system == "Linux":
        return [
            root / "bin" / "PacketTracer",
            root / "bin" / "packettracer",
            root / "PacketTracer",
            root / "packettracer",
        ]
    return [root / "bin" / "PacketTracer", root / "PacketTracer"]


def default_saves_candidates(root: Path, host_os: str | None = None) -> list[Path]:
    system = host_os or _host_os()
    candidates = [root / "saves"]
    if system == "Darwin":
        candidates.extend(
            [
                root / "Contents" / "Resources" / "saves",
                root.parent / "Resources" / "saves",
            ]
        )
    elif system == "Linux":
        candidates.extend(
            [
                root / "resources" / "saves",
                root.parent / "saves",
            ]
        )
    return candidates


def detect_packet_tracer_layout(root: Path, host_os: str | None = None) -> str:
    system = host_os or _host_os()
    if system == "Windows":
        if (root / "bin" / "PacketTracer.exe").exists() or (root / "PacketTracer.exe").exists():
            return "windows_install_root"
        normalized_parts = [part.lower() for part in root.parts if part]
        if any(part.startswith("cisco packet tracer") or part == "packet tracer" for part in normalized_parts):
            return "windows_install_root"
    if system == "Darwin":
        if "Contents/Resources" in root.as_posix():
            return "macos_app_bundle_resources"
        if ".app" in root.as_posix():
            return "macos_app_bundle"
    if system == "Linux":
        if (root / "bin" / "packettracer").exists() or (root / "bin" / "PacketTracer").exists():
            return "linux_install_root"
    return "custom"


def recommended_packet_tracer_root(host_os: str | None = None) -> Path | None:
    candidates = default_install_candidates(host_os)
    return candidates[0] if candidates else None


def recommended_packet_tracer_saves_root(host_os: str | None = None) -> Path | None:
    root = recommended_packet_tracer_root(host_os)
    if root is None:
        return None
    candidates = default_saves_candidates(root, host_os)
    return candidates[0] if candidates else None


def get_packet_tracer_root() -> Path | None:
    env_root = _existing_path(os.getenv("PACKET_TRACER_ROOT"))
    if env_root is not None:
        return env_root
    for candidate in default_install_candidates():
        if candidate.exists():
            return candidate
    return None


def get_packet_tracer_saves_root() -> Path | None:
    env_saves = _existing_path(os.getenv("PACKET_TRACER_SAVES_ROOT"))
    if env_saves is not None:
        return env_saves
    root = get_packet_tracer_root()
    if root is None:
        return None
    for candidate in default_saves_candidates(root):
        if candidate.exists():
            return candidate
    return None


def get_packet_tracer_exe() -> Path | None:
    env_exe = _existing_path(os.getenv("PACKET_TRACER_EXE"))
    if env_exe is not None:
        return env_exe
    root = get_packet_tracer_root()
    if root is None:
        return None
    for candidate in default_executable_candidates(root):
        if candidate.exists():
            return candidate
    return None


def require_packet_tracer_saves_root() -> Path:
    saves = get_packet_tracer_saves_root()
    if saves is None:
        raise FileNotFoundError(
            "Packet Tracer sample saves were not found. Set PACKET_TRACER_SAVES_ROOT or PACKET_TRACER_ROOT."
        )
    return saves


def require_packet_tracer_exe() -> Path:
    exe = get_packet_tracer_exe()
    if exe is None:
        raise FileNotFoundError(
            "Packet Tracer executable was not found. Set PACKET_TRACER_EXE or PACKET_TRACER_ROOT."
        )
    return exe


def resolve_sample_path(relative_path: str) -> Path:
    return require_packet_tracer_saves_root() / relative_path


def _version_from_install_root(root: Path) -> str | None:
    """Read a Packet Tracer version out of the install directory name.

    Cisco names the install folder after the release, e.g.
    `Cisco Packet Tracer 9.0.0`. That gives major.minor.patch and nothing more.

    The build field is deliberately omitted rather than padded with `0000`.
    Inventing a build would make bundled samples that happen to carry
    `9.0.0.0000` compare as `exact`, outranking the user's own saves written by
    the actual installed binary. A three-field target can never match `exact`,
    so every donor lands on `same_minor` and is ranked on real criteria instead.
    """
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", root.name)
    if not match:
        return None
    major, minor, patch = match.group(1), match.group(2), match.group(3) or "0"
    return f"{major}.{minor}.{patch}"


def detect_packet_tracer_target_version() -> tuple[str, str]:
    """Resolve the version to target, and say where it came from.

    Order: explicit env override, then the installed Packet Tracer, then the
    resolved compatibility donor's own `<VERSION>`, then the built-in default.
    This is what removes the hard requirement for one specific Packet Tracer
    build: the skill follows whatever release is actually installed.
    """
    override = os.getenv("PACKET_TRACER_TARGET_VERSION")
    if override:
        return override, "env"

    root = get_packet_tracer_root()
    if root is not None:
        detected = _version_from_install_root(root)
        if detected:
            return detected, "install_root"

    env_donor = _existing_path(os.getenv("PACKET_TRACER_COMPAT_DONOR"))
    if env_donor is not None and env_donor.suffix.lower() == ".pkt":
        donor_version = _pkt_version(env_donor)
        if donor_version:
            return donor_version, "compat_donor"

    return DEFAULT_PACKET_TRACER_TARGET_VERSION, "default"


def get_packet_tracer_target_version() -> str:
    return detect_packet_tracer_target_version()[0]


_VERSION_PATTERN = re.compile(rb"<VERSION>([^<]*)</VERSION>")


@lru_cache(maxsize=1024)
def _pkt_version_cached(path_key: str, size: int, mtime_ns: int) -> str | None:
    """Read `<VERSION>` from a `.pkt`, keyed on the file's identity.

    Donor scanning asks the same files for their version many times per run, and
    a full decode of a multi-megabyte lab costs seconds. Reading only the header
    is constant-time; caching removes the repeats. The size and mtime are part
    of the key so an edited file is re-read rather than served stale.
    """
    from pkt_codec import decode_pkt_auto, peek_pkt_header

    raw = Path(path_key).read_bytes()
    try:
        match = _VERSION_PATTERN.search(peek_pkt_header(raw))
        if match:
            return match.group(1).decode("utf-8", "replace")
    except Exception:
        pass

    # The peek only models the modern container. Fall back to a full decode,
    # which also handles pre-Twofish 5.x saves, rather than reporting the file
    # as unreadable.
    try:
        xml, _ = decode_pkt_auto(raw)
        return ET.fromstring(xml).findtext("./VERSION")
    except Exception:
        return None


def _pkt_version(pkt_path: Path) -> str | None:
    try:
        stat = pkt_path.stat()
    except OSError:
        return None
    return _pkt_version_cached(str(pkt_path), stat.st_size, stat.st_mtime_ns)


def _candidate_pkt_files(directory: Path, source: str) -> list[tuple[str, Path]]:
    if not directory.exists() or not directory.is_dir():
        return []
    candidates = sorted(
        (path for path in directory.glob("*.pkt") if path.is_file()),
        key=lambda path: (path.stat().st_mtime, path.name.lower()),
        reverse=True,
    )
    return [(source, candidate) for candidate in candidates]


def _candidate_pkt_files_recursive(directory: Path, source: str, limit: int = 12) -> list[tuple[str, Path]]:
    if not directory.exists() or not directory.is_dir():
        return []
    candidates = sorted(
        (path for path in directory.rglob("*.pkt") if path.is_file()),
        key=lambda path: (path.stat().st_mtime, path.name.lower()),
        reverse=True,
    )
    return [(source, candidate) for candidate in candidates[:limit]]


def list_packet_tracer_compatibility_donor_candidates() -> list[tuple[str, Path]]:
    candidates: list[tuple[str, Path]] = []
    seen: set[str] = set()

    env_donor = os.getenv("PACKET_TRACER_COMPAT_DONOR")
    if env_donor:
        env_path = Path(env_donor).expanduser()
        seen.add(str(env_path).lower())
        candidates.append(("env", env_path))

    for directory in DEFAULT_DONOR_FALLBACKS:
        for source, candidate in _candidate_pkt_files(directory, f"auto:{directory.name.lower()}"):
            key = str(candidate).lower()
            if key in seen:
                continue
            seen.add(key)
            candidates.append((source, candidate))

    saves_root = get_packet_tracer_saves_root()
    if saves_root is not None:
        for relative_path in DEFAULT_SAMPLE_DONOR_FILES:
            candidate = saves_root / relative_path
            key = str(candidate).lower()
            if key in seen:
                continue
            seen.add(key)
            candidates.append(("auto:packet-tracer-saves", candidate))
        for source, candidate in _candidate_pkt_files_recursive(saves_root, "auto:packet-tracer-saves-scan"):
            key = str(candidate).lower()
            if key in seen:
                continue
            seen.add(key)
            candidates.append((source, candidate))

    return candidates


def inspect_packet_tracer_compatibility_donor() -> CompatibilityDonorDetails:
    target_version = get_packet_tracer_target_version()
    candidates = list_packet_tracer_compatibility_donor_candidates()
    env_donor = os.getenv("PACKET_TRACER_COMPAT_DONOR")

    if env_donor:
        env_path = Path(env_donor).expanduser()
        if not env_path.exists():
            return CompatibilityDonorDetails(
                target_version=target_version,
                resolved_path=None,
                donor_version=None,
                donor_source="env",
                status="missing",
                blocking_reason=f"set but missing: {env_path}",
                candidate_paths=candidates,
            )
        if env_path.suffix.lower() != ".pkt":
            return CompatibilityDonorDetails(
                target_version=target_version,
                resolved_path=None,
                donor_version=None,
                donor_source="env",
                status="invalid_extension",
                blocking_reason=f"compatibility donor must be a .pkt file: {env_path}",
                candidate_paths=candidates,
            )
        donor_version = _pkt_version(env_path)
        if donor_version is None:
            return CompatibilityDonorDetails(
                target_version=target_version,
                resolved_path=None,
                donor_version=None,
                donor_source="env",
                status="decode_error",
                blocking_reason=f"could not decode donor version: {env_path}",
                candidate_paths=candidates,
            )
        policy = get_donor_policy()
        tier = donor_compatibility(donor_version, target_version)
        if not donor_tier_is_accepted(tier, policy):
            return CompatibilityDonorDetails(
                target_version=target_version,
                resolved_path=None,
                donor_version=donor_version,
                donor_source="env",
                status="version_mismatch",
                blocking_reason=(
                    f"{env_path}: "
                    + describe_donor_rejection(donor_version, target_version, tier, policy)
                ),
                candidate_paths=candidates,
                compatibility_tier=tier,
            )
        return CompatibilityDonorDetails(
            target_version=target_version,
            resolved_path=env_path,
            donor_version=donor_version,
            donor_source="env",
            status="ok",
            blocking_reason="",
            candidate_paths=candidates,
            compatibility_tier=tier,
        )

    policy = get_donor_policy()
    decode_failures = 0
    wrong_version_count = 0
    # Prefer the strictest tier available rather than the first candidate that
    # merely passes policy, so an exact-build donor always beats a same_minor one.
    best: tuple[int, str, Path, str] | None = None
    for source, candidate in candidates:
        if not candidate.exists() or candidate.suffix.lower() != ".pkt":
            continue
        donor_version = _pkt_version(candidate)
        if donor_version is None:
            decode_failures += 1
            continue
        tier = donor_compatibility(donor_version, target_version)
        if not donor_tier_is_accepted(tier, policy):
            wrong_version_count += 1
            continue
        rank = COMPATIBILITY_TIERS.index(tier)
        if best is None or rank < best[0]:
            best = (rank, donor_version, candidate, source)
        if rank == 0:
            break

    if best is not None:
        _, donor_version, candidate, source = best
        return CompatibilityDonorDetails(
            target_version=target_version,
            resolved_path=candidate,
            donor_version=donor_version,
            donor_source=source,
            status="ok",
            blocking_reason="",
            candidate_paths=candidates,
            compatibility_tier=COMPATIBILITY_TIERS[best[0]],
        )

    if candidates:
        if decode_failures == len(candidates):
            reason = (
                "donor candidates were found, but none could be decoded. "
                "They may use an unsupported Packet Tracer container variant."
            )
        elif wrong_version_count > 0:
            reason = (
                f"no donor compatible with {target_version} under the '{policy}' policy was found "
                f"among {wrong_version_count} discovered local candidates. "
                "Set PACKET_TRACER_DONOR_POLICY to a looser tier "
                f"({', '.join(COMPATIBILITY_TIERS[:-1])}) to widen the search."
            )
        else:
            reason = f"no compatible Packet Tracer {target_version} donor was found"
    else:
        reason = (
            "no donor candidates were discovered. Set PACKET_TRACER_COMPAT_DONOR "
            "or place a working 9.0 donor lab in Downloads, Documents, Desktop, or Packet Tracer saves."
        )

    return CompatibilityDonorDetails(
        target_version=target_version,
        resolved_path=None,
        donor_version=None,
        donor_source=None,
        status="missing",
        blocking_reason=reason,
        candidate_paths=candidates,
    )


def get_packet_tracer_compatibility_donor() -> Path | None:
    details = inspect_packet_tracer_compatibility_donor()
    return details.resolved_path if details.status == "ok" else None


def require_packet_tracer_compatibility_donor() -> Path:
    details = inspect_packet_tracer_compatibility_donor()
    if details.status != "ok" or details.resolved_path is None:
        raise FileNotFoundError(
            "Packet Tracer 9.0 compatibility donor was not found. "
            f"{details.blocking_reason}"
        )
    return details.resolved_path
