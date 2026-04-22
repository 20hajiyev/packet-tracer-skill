from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import packet_tracer_env  # noqa: E402


def test_default_install_candidates_cover_supported_oses() -> None:
    assert packet_tracer_env.default_install_candidates("Windows")
    assert packet_tracer_env.default_install_candidates("Darwin")
    assert packet_tracer_env.default_install_candidates("Linux")


def test_default_executable_candidates_are_platform_specific() -> None:
    root = Path("/tmp/packet-tracer")
    windows = packet_tracer_env.default_executable_candidates(root, "Windows")
    macos = packet_tracer_env.default_executable_candidates(root, "Darwin")
    linux = packet_tracer_env.default_executable_candidates(root, "Linux")

    assert any(str(path).endswith(".exe") for path in windows)
    assert any("Packet Tracer" in str(path) or "PacketTracer" in str(path) for path in macos)
    assert any(str(path).endswith("packettracer") or str(path).endswith("PacketTracer") for path in linux)


def test_default_saves_candidates_are_platform_specific() -> None:
    root = Path("/tmp/packet-tracer")
    windows = packet_tracer_env.default_saves_candidates(root, "Windows")
    macos = packet_tracer_env.default_saves_candidates(root, "Darwin")
    linux = packet_tracer_env.default_saves_candidates(root, "Linux")

    assert windows == [root / "saves"]
    assert any(path.parts[-3:] == ("Contents", "Resources", "saves") for path in macos)
    assert any(path.parts[-2:] == ("resources", "saves") for path in linux)


def test_recommended_packet_tracer_saves_root_matches_first_candidate() -> None:
    windows = packet_tracer_env.recommended_packet_tracer_saves_root("Windows")
    macos = packet_tracer_env.recommended_packet_tracer_saves_root("Darwin")
    linux = packet_tracer_env.recommended_packet_tracer_saves_root("Linux")

    assert windows is not None and windows.parts[-1] == "saves"
    assert macos is not None and macos.parts[-1] == "saves"
    assert linux is not None and linux.parts[-1] == "saves"


def test_detect_packet_tracer_layout_variants(tmp_path: Path) -> None:
    windows_root = tmp_path / "win"
    (windows_root / "bin").mkdir(parents=True)
    (windows_root / "bin" / "PacketTracer.exe").write_text("", encoding="utf-8")
    assert packet_tracer_env.detect_packet_tracer_layout(windows_root, "Windows") == "windows_install_root"

    macos_root = Path("/Applications/Cisco Packet Tracer.app/Contents/Resources")
    assert packet_tracer_env.detect_packet_tracer_layout(macos_root, "Darwin") == "macos_app_bundle_resources"

    linux_root = tmp_path / "linux"
    (linux_root / "bin").mkdir(parents=True)
    (linux_root / "bin" / "packettracer").write_text("", encoding="utf-8")
    assert packet_tracer_env.detect_packet_tracer_layout(linux_root, "Linux") == "linux_install_root"


def test_detect_packet_tracer_layout_recognizes_canonical_windows_root_without_files() -> None:
    canonical_root = Path(r"C:\Program Files\Cisco Packet Tracer 9.0.0")
    assert packet_tracer_env.detect_packet_tracer_layout(canonical_root, "Windows") == "windows_install_root"


def test_get_packet_tracer_root_uses_os_candidates(monkeypatch, tmp_path: Path) -> None:
    linux_root = tmp_path / "packettracer"
    linux_root.mkdir()
    monkeypatch.delenv("PACKET_TRACER_ROOT", raising=False)
    monkeypatch.setattr(packet_tracer_env, "_host_os", lambda: "Linux")
    monkeypatch.setattr(packet_tracer_env, "default_install_candidates", lambda host_os=None: [linux_root])

    resolved = packet_tracer_env.get_packet_tracer_root()

    assert resolved == linux_root


def test_get_packet_tracer_exe_uses_platform_candidate_names(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "pt"
    bin_dir = root / "bin"
    bin_dir.mkdir(parents=True)
    exe = bin_dir / "packettracer"
    exe.write_text("", encoding="utf-8")
    monkeypatch.delenv("PACKET_TRACER_EXE", raising=False)
    monkeypatch.setattr(packet_tracer_env, "get_packet_tracer_root", lambda: root)
    monkeypatch.setattr(packet_tracer_env, "_host_os", lambda: "Linux")

    resolved = packet_tracer_env.get_packet_tracer_exe()

    assert resolved == exe


def test_get_packet_tracer_saves_root_uses_platform_candidates(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "pt"
    saves = root / "resources" / "saves"
    saves.mkdir(parents=True)
    monkeypatch.delenv("PACKET_TRACER_SAVES_ROOT", raising=False)
    monkeypatch.setattr(packet_tracer_env, "get_packet_tracer_root", lambda: root)
    monkeypatch.setattr(packet_tracer_env, "_host_os", lambda: "Linux")

    resolved = packet_tracer_env.get_packet_tracer_saves_root()

    assert resolved == saves


def test_list_packet_tracer_compatibility_donor_candidates_scans_saves_root(monkeypatch, tmp_path: Path) -> None:
    saves = tmp_path / "saves"
    nested = saves / "01 Networking" / "FTP"
    nested.mkdir(parents=True)
    donor = nested / "FTP.pkt"
    donor.write_bytes(b"pkt")
    monkeypatch.delenv("PACKET_TRACER_COMPAT_DONOR", raising=False)
    monkeypatch.setattr(packet_tracer_env, "get_packet_tracer_saves_root", lambda: saves)
    monkeypatch.setattr(packet_tracer_env, "_candidate_pkt_files", lambda directory, source: [])

    candidates = packet_tracer_env.list_packet_tracer_compatibility_donor_candidates()

    assert any(path == donor and source.startswith("auto:packet-tracer-saves") for source, path in candidates)
