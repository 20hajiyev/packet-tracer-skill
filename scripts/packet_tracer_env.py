from __future__ import annotations

import os
from pathlib import Path
import xml.etree.ElementTree as ET


DEFAULT_INSTALL_CANDIDATES = [
    Path(r"C:\Program Files\Cisco Packet Tracer 9.0.0"),
    Path(r"C:\Program Files\Cisco Packet Tracer"),
    Path(r"C:\Program Files (x86)\Cisco Packet Tracer 9.0.0"),
    Path(r"C:\Program Files (x86)\Cisco Packet Tracer"),
]
DEFAULT_PACKET_TRACER_TARGET_VERSION = "9.0.0.0810"


def _existing_path(raw: str | None) -> Path | None:
    if not raw:
        return None
    path = Path(raw).expanduser()
    return path if path.exists() else None


def get_packet_tracer_root() -> Path | None:
    env_root = _existing_path(os.getenv("PACKET_TRACER_ROOT"))
    if env_root is not None:
        return env_root
    for candidate in DEFAULT_INSTALL_CANDIDATES:
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
    saves = root / "saves"
    return saves if saves.exists() else None


def get_packet_tracer_exe() -> Path | None:
    env_exe = _existing_path(os.getenv("PACKET_TRACER_EXE"))
    if env_exe is not None:
        return env_exe
    root = get_packet_tracer_root()
    if root is None:
        return None
    for candidate in [root / "bin" / "PacketTracer.exe", root / "PacketTracer.exe"]:
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


def get_packet_tracer_compatibility_donor() -> Path | None:
    env_donor = _existing_path(os.getenv("PACKET_TRACER_COMPAT_DONOR"))
    target_version = get_packet_tracer_target_version()
    if env_donor is not None and env_donor.suffix.lower() == ".pkt":
        if _pkt_version(env_donor) == target_version:
            return env_donor
    return None


def require_packet_tracer_compatibility_donor() -> Path:
    donor = get_packet_tracer_compatibility_donor()
    if donor is None:
        raise FileNotFoundError(
            "Packet Tracer 9.0 compatibility donor was not found. Set PACKET_TRACER_COMPAT_DONOR to a local 9.0 donor lab."
        )
    return donor
