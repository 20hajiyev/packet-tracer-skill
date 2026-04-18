from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from twofish_runtime import (  # noqa: E402
    bridge_extensions,
    candidate_bridge_paths,
    expected_bridge_patterns,
    normalized_host_os,
)


def test_normalized_host_os_maps_known_platforms() -> None:
    assert normalized_host_os("win32") == "windows"
    assert normalized_host_os("darwin") == "macos"
    assert normalized_host_os("linux") == "linux"


def test_expected_bridge_patterns_are_platform_specific() -> None:
    assert any(pattern.endswith(".pyd") for pattern in expected_bridge_patterns("win32"))
    assert any(pattern.endswith(".dylib") for pattern in expected_bridge_patterns("darwin"))
    assert all(pattern.endswith(".so") for pattern in expected_bridge_patterns("linux"))


def test_bridge_extensions_are_platform_specific() -> None:
    assert ".pyd" in bridge_extensions("win32")
    assert ".dylib" in bridge_extensions("darwin")
    assert bridge_extensions("linux") == [".so"]


def test_candidate_bridge_paths_prefers_env_and_search_roots(tmp_path: Path, monkeypatch) -> None:
    vendor_dir = tmp_path / "vendor"
    vendor_dir.mkdir()
    env_bridge = tmp_path / "_twofish.cp314-win_amd64.pyd"
    env_bridge.write_bytes(b"env")
    search_root = tmp_path / "search"
    search_root.mkdir()
    search_bridge = search_root / "_twofish.cp314-linux_x86_64.so"
    search_bridge.write_bytes(b"search")
    sibling_bridge = vendor_dir / "_twofish.cp314-macos_universal2.dylib"
    sibling_bridge.write_bytes(b"sibling")

    monkeypatch.setenv("PKT_TWOFISH_SEARCH_ROOTS", str(search_root))
    candidates = candidate_bridge_paths(vendor_dir, env_path=str(env_bridge), platform_name="linux")

    assert candidates[0][0] == "env"
    assert candidates[0][1] == env_bridge
    assert any(source.startswith("search-root:") and path == search_bridge for source, path in candidates)
    assert all(path.exists() for _, path in candidates)

    monkeypatch.delenv("PKT_TWOFISH_SEARCH_ROOTS", raising=False)
