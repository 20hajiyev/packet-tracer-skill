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

# Measured against a running Packet Tracer 9.0.0.0810, one file at a time:
#
#   6.2.0.0000  opens        8.0.0.0000  opens (original, re-encoded, relabelled)
#   9.0.0.0000  opens        9.0.0.0172  opens
#   9.0.0.4178  opens        9.0.0.9999  opens
#   9.1.0.0000  REFUSED      99.9.9.9999 REFUSED
#
# So the gate is an ordering on the first three fields, and the build field is
# ignored entirely. Anything at or below the installed release opens; anything
# above it does not.
#
# An earlier reading of the same symptom concluded that the build had to match
# exactly and that none of the bundled Cisco samples could serve as a donor.
# That was inferred from generated files failing to open -- which they did, for
# unrelated reasons -- and never tested against an untouched sample. The control
# that settles it: the *original* 8.0.0.0000 sample opens, and a file whose
# version was relabelled to a nonexistent build is refused, so the bridge does
# report refusals rather than silently succeeding.
#
# The consequence would be large -- Packet Tracer ships hundreds of labs under
# its own `saves/`, all at or below the installed release, so a fresh install
# would need no downloaded donor at all. It is not switched on yet, because two
# questions remain open:
#
#   * every measurement above opened an *untouched* or merely relabelled lab.
#     Whether a lab *generated* from an older donor opens is untested, and an
#     earlier session recorded that one was refused;
#   * loosening the default here changes which donor gets picked, and at scale
#     that produced switches carrying two cables on one interface.
#
# So the tier model is corrected to match what was measured, while the default
# stays where evidence supports it. Set PACKET_TRACER_DONOR_POLICY=upgradeable
# to opt in.
DEFAULT_DONOR_POLICY = "exact"

# Packet Tracer reliably upgrades saves from this major version onward on open.
MINIMUM_UPGRADEABLE_MAJOR = 6


def _release_fields(version: str | None) -> tuple[int, int, int] | None:
    """The major.minor.patch a version names, padded, or None if unreadable."""
    fields = _version_fields(version)
    if not fields:
        return None
    padded = (*fields, 0, 0, 0)[:3]
    return (padded[0], padded[1], padded[2])


def donor_opens_in_target(donor_version: str | None, target_version: str | None = None) -> bool:
    """Whether Packet Tracer will open a lab carrying `donor_version`.

    The rule is measured, not assumed: the donor's major.minor.patch must not
    exceed the installed release. The fourth field -- the build -- is ignored,
    which is why a 9.0.0.9999 lab opens on a 9.0.0.0810 install.
    """
    target_version = target_version or get_packet_tracer_target_version()
    donor = _release_fields(donor_version)
    target = _release_fields(target_version)
    if donor is None or target is None:
        return False
    return donor <= target


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

    # Similarity is not the gate; the ordering is. A 9.1.0 donor resembles a
    # 9.0.0 target more closely than an 8.0.0 one does, yet Packet Tracer opens
    # the 8.0.0 lab and refuses the 9.1.0 lab. Rank only what actually opens.
    if not donor_opens_in_target(donor_version, target_version):
        return "incompatible"

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


def build_is_known(target_version: str | None = None) -> bool:
    """Whether the running Packet Tracer build is known, not just its release.

    An install directory yields `9.0.0` — a release. Only a lab the install
    saved carries the build (`9.0.0.0810`), and Packet Tracer refuses to open
    anything generated from a donor with a different build.
    """
    # `None` means "detect it"; an empty string means "known to be unknown".
    resolved = get_packet_tracer_target_version() if target_version is None else target_version
    return len(_version_fields(resolved)) >= 4


def save_a_lab_hint() -> str:
    return (
        "Open Packet Tracer, then File > Save As and save any lab (an empty one is fine) "
        "into Documents, Downloads or Desktop. That file carries your exact Packet Tracer "
        "build, which is what generated labs must match."
    )


def describe_donor_rejection(donor_version: str, target_version: str, tier: str, policy: str) -> str:
    if tier == "incompatible":
        return (
            f"version {donor_version} is not compatible with target {target_version} "
            f"(Packet Tracer does not reliably upgrade saves older than "
            f"{MINIMUM_UPGRADEABLE_MAJOR}.x)"
        )
    if policy == "exact":
        # Do not offer a looser policy here. Loosening was measured to produce
        # files Packet Tracer refuses to open, so suggesting it would walk the
        # user into a broken state that looks like progress.
        return (
            f"version {donor_version} does not match your Packet Tracer build {target_version}. "
            "A generated lab must be built from a donor your own Packet Tracer saved. "
            + save_a_lab_hint()
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
    """Resolve a saves tree: explicit override, live install, then the local cache.

    The cache is shaped like a real `saves/` tree, so it can answer this seam
    directly and every consumer of `resolve_sample_path()` keeps working
    unchanged on a machine with no Packet Tracer installed.
    """
    env_saves = _existing_path(os.getenv("PACKET_TRACER_SAVES_ROOT"))
    if env_saves is not None:
        return env_saves

    root = get_packet_tracer_root()
    if root is not None:
        for candidate in default_saves_candidates(root):
            if candidate.exists():
                _refresh_donor_cache(candidate)
                return candidate

    from donor_cache import cache_is_usable, cache_root

    if cache_is_usable(get_packet_tracer_target_version()):
        return cache_root()
    return None


_DONOR_CACHE_REFRESHED = False


def _refresh_donor_cache(saves_root: Path) -> None:
    """Populate the cache once per process while a live install is available.

    Failure here is never fatal: the cache improves availability on *other*
    machines and must not break the machine that already works.
    """
    global _DONOR_CACHE_REFRESHED
    if _DONOR_CACHE_REFRESHED:
        return
    _DONOR_CACHE_REFRESHED = True
    try:
        from donor_cache import bootstrap, cache_enabled, cache_is_usable

        target_version = get_packet_tracer_target_version()
        if not cache_enabled() or cache_is_usable(target_version):
            return
        report = bootstrap(saves_root, target_version=target_version)
        if report.ok:
            print(report.summary())
    except Exception:
        return


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
        from donor_cache import missing_requirements_message

        raise FileNotFoundError(missing_requirements_message())
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


def _build_from_executable(release_version: str = "") -> str | None:
    """Read the running build straight out of the Packet Tracer binary.

    This is the authoritative source and it needs nothing from the user. The
    binary's `FileVersion` resource carries the same four-field string Packet
    Tracer stamps into every lab it saves — measured on 9.0.0: the executable
    reports `9.0.0.0810`, exactly what its saves contain.

    Reading it here removes the one-time bootstrap the skill used to require.
    Before this, the build could only be learned from a lab the install had
    already written, so a user who had never saved anything got a three-field
    release (`9.0.0`) that no donor can match under the `exact` policy -- not
    even a genuine lab written by that very install.

    Windows only for now: the version resource is a PE feature, and no
    equivalent has been measured on the Linux and macOS builds. Returns None
    there so the local-save path still runs.
    """
    if platform.system() != "Windows":
        return None
    exe = get_packet_tracer_exe()
    if exe is None:
        return None

    try:
        import ctypes
        from ctypes import wintypes

        version_dll = ctypes.WinDLL("version")
        path = str(exe)
        size = version_dll.GetFileVersionInfoSizeW(path, None)
        if not size:
            return None
        buffer = ctypes.create_string_buffer(size)
        if not version_dll.GetFileVersionInfoW(path, 0, size, buffer):
            return None

        value = ctypes.c_void_p()
        length = wintypes.UINT()
        # The language/codepage of the string table is not fixed, so ask the
        # file which translations it actually carries instead of guessing.
        if not version_dll.VerQueryValueW(
            buffer, r"\VarFileInfo\Translation", ctypes.byref(value), ctypes.byref(length)
        ) or not length.value:
            return None
        language, codepage = ctypes.cast(
            value, ctypes.POINTER(wintypes.WORD * 2)
        ).contents[:]

        if not version_dll.VerQueryValueW(
            buffer,
            rf"\StringFileInfo\{language:04x}{codepage:04x}\FileVersion",
            ctypes.byref(value),
            ctypes.byref(length),
        ) or not length.value:
            return None
        detected = ctypes.wstring_at(value.value, length.value).strip().rstrip("\x00").strip()
    except (OSError, AttributeError, ValueError):
        return None

    # Only a full four-field build is useful; anything shorter tells us no more
    # than the install directory name already did.
    fields = _version_fields(detected)
    if len(fields) < 4:
        return None
    if release_version:
        release_fields = _version_fields(release_version)[:2]
        if len(release_fields) == 2 and fields[:2] != release_fields:
            # The binary disagrees with the directory it sits in; trust neither.
            return None
    return detected


def _build_from_local_saves(release_version: str) -> str | None:
    """Find the running build by reading a lab this Packet Tracer saved.

    Only files the local install wrote carry its build number. Bundled Cisco
    samples do not: they ship as `9.0.0.0000` and friends, which is precisely
    the value Packet Tracer then refuses to open.
    """
    release_fields = _version_fields(release_version)[:2]
    if len(release_fields) < 2:
        return None

    best: tuple[tuple[int, ...], str] | None = None
    for directory in DEFAULT_DONOR_FALLBACKS:
        if not directory.exists():
            continue
        try:
            candidates = sorted(directory.glob("*.pkt"))[:12]
        except OSError:
            continue
        for candidate in candidates:
            version = _pkt_version(candidate)
            fields = _version_fields(version)
            if len(fields) < 4 or fields[:2] != release_fields:
                continue
            if best is None or fields > best[0]:
                best = (fields, str(version))
    return best[1] if best else None


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
            # The directory name gives major.minor.patch but not the build, and
            # Packet Tracer refuses to open a file whose <VERSION> build differs
            # from its own: "This file requires 9.0.0.0000. Your current version
            # is 9.0.0.0810."
            #
            # The binary itself knows its build, so ask it first: that works on a
            # machine where nothing has ever been saved. Labs this install wrote
            # carry the same string and cover the platforms where no version
            # resource is available.
            build = _build_from_executable(detected)
            if build:
                return build, "executable"
            build = _build_from_local_saves(detected)
            if build:
                return build, "local_save"
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
            )
            if policy == "exact":
                # Never offer a looser policy under `exact`. Loosening was
                # measured to produce files Packet Tracer refuses to open, so it
                # walks the user into a broken state that looks like progress.
                # The bundled Cisco samples are exactly this trap: there are
                # dozens of them, all carrying a build the local install rejects.
                reason += (
                    "Bundled Cisco samples do not qualify -- they ship with a different "
                    "build, and a lab generated from one is refused on open. " + save_a_lab_hint()
                )
            else:
                reason += (
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
