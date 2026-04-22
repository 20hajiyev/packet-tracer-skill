from __future__ import annotations

import os
import platform
from pathlib import Path
import xml.etree.ElementTree as ET
from dataclasses import dataclass


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


def get_packet_tracer_target_version() -> str:
    return os.getenv("PACKET_TRACER_TARGET_VERSION", DEFAULT_PACKET_TRACER_TARGET_VERSION)


def _pkt_version(pkt_path: Path) -> str | None:
    try:
        from pkt_codec import decode_pkt_modern

        root = ET.fromstring(decode_pkt_modern(pkt_path.read_bytes()))
    except Exception:
        return None
    return root.findtext("./VERSION")


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
        if donor_version != target_version:
            return CompatibilityDonorDetails(
                target_version=target_version,
                resolved_path=None,
                donor_version=donor_version,
                donor_source="env",
                status="version_mismatch",
                blocking_reason=f"{env_path} is version {donor_version}; expected {target_version}",
                candidate_paths=candidates,
            )
        return CompatibilityDonorDetails(
            target_version=target_version,
            resolved_path=env_path,
            donor_version=donor_version,
            donor_source="env",
            status="ok",
            blocking_reason="",
            candidate_paths=candidates,
        )

    decode_failures = 0
    wrong_version_count = 0
    for source, candidate in candidates:
        if not candidate.exists() or candidate.suffix.lower() != ".pkt":
            continue
        donor_version = _pkt_version(candidate)
        if donor_version is None:
            decode_failures += 1
            continue
        if donor_version != target_version:
            wrong_version_count += 1
            continue
        return CompatibilityDonorDetails(
            target_version=target_version,
            resolved_path=candidate,
            donor_version=donor_version,
            donor_source=source,
            status="ok",
            blocking_reason="",
            candidate_paths=candidates,
        )

    if candidates:
        if decode_failures == len(candidates):
            reason = (
                "donor candidates were found, but none could be decoded. "
                "Check the local Twofish bridge and Python 3.14 runtime."
            )
        elif wrong_version_count > 0:
            reason = f"no Packet Tracer {target_version} donor was found among the discovered local candidates"
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
