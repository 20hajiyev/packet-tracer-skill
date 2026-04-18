from __future__ import annotations

import os
import sys
from pathlib import Path


SUPPORTED_PYTHON = (3, 14)


def normalized_host_os(platform_name: str | None = None) -> str:
    value = (platform_name or sys.platform).lower()
    if value.startswith("win"):
        return "windows"
    if value == "darwin":
        return "macos"
    if value.startswith("linux"):
        return "linux"
    return value or "unknown"


def bridge_extensions(platform_name: str | None = None) -> list[str]:
    host = normalized_host_os(platform_name)
    if host == "windows":
        return [".pyd", ".dll"]
    if host == "macos":
        return [".dylib", ".so"]
    if host == "linux":
        return [".so"]
    return [".pyd", ".dll", ".dylib", ".so"]


def expected_bridge_patterns(
    platform_name: str | None = None,
    python_version: tuple[int, int] | None = None,
) -> list[str]:
    major, minor = python_version or SUPPORTED_PYTHON
    abi = f"cp{major}{minor}"
    host = normalized_host_os(platform_name)
    patterns: list[str] = []
    for extension in bridge_extensions(platform_name):
        if host == "windows":
            patterns.append(f"_twofish.{abi}-win_*{extension}")
        elif host == "macos":
            patterns.append(f"_twofish.{abi}-macos*{extension}")
        elif host == "linux":
            patterns.append(f"_twofish.{abi}-linux*{extension}")
        else:
            patterns.append(f"_twofish.{abi}-*{extension}")
    return patterns


def _split_search_roots(raw: str | None) -> list[Path]:
    if not raw:
        return []
    paths: list[Path] = []
    for item in raw.split(os.pathsep):
        candidate = Path(item).expanduser()
        if candidate.exists() and candidate.is_dir():
            paths.append(candidate)
    return paths


def candidate_bridge_paths(
    vendor_dir: Path,
    env_path: str | None = None,
    extra_roots: list[Path] | None = None,
    platform_name: str | None = None,
) -> list[tuple[str, Path]]:
    candidates: list[tuple[str, Path]] = []
    seen: set[str] = set()

    def remember(source: str, path: Path) -> None:
        key = str(path.resolve() if path.exists() else path).lower()
        if key in seen:
            return
        seen.add(key)
        candidates.append((source, path))

    if env_path:
        remember("env", Path(env_path).expanduser())

    roots = [vendor_dir]
    roots.extend(extra_roots or [])
    roots.extend(_split_search_roots(os.getenv("PKT_TWOFISH_SEARCH_ROOTS")))

    for root in roots:
        for pattern in expected_bridge_patterns(platform_name):
            for candidate in sorted(root.glob(pattern)):
                remember("sibling" if root == vendor_dir else f"search-root:{root}", candidate)
        for extension in bridge_extensions(platform_name):
            for candidate in sorted(root.glob(f"_twofish*{extension}")):
                remember("sibling" if root == vendor_dir else f"search-root:{root}", candidate)

    return candidates


def recommended_search_roots(vendor_dir: Path) -> list[str]:
    roots = [str(vendor_dir)]
    roots.extend(str(path) for path in _split_search_roots(os.getenv("PKT_TWOFISH_SEARCH_ROOTS")))
    return roots
