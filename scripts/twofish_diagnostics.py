#!/usr/bin/env python3
"""Runtime diagnostics for the local Twofish bridge."""

from __future__ import annotations

import json
import hashlib
import os
import sys
from ctypes import CDLL
from pathlib import Path


SUPPORTED_PYTHON = (3, 14)


def _vendor_dir() -> Path:
    return Path(__file__).resolve().parent / "vendor"


def _candidate_paths() -> list[tuple[str, Path]]:
    vendor_dir = _vendor_dir()
    env_path = os.getenv("PKT_TWOFISH_LIBRARY")
    candidates: list[tuple[str, Path]] = []
    if env_path:
        candidates.append(("env", Path(env_path).expanduser()))
    for pattern in ("_twofish*.pyd", "_twofish*.so", "_twofish*.dll"):
        for candidate in sorted(vendor_dir.glob(pattern)):
            candidates.append(("sibling", candidate))
    return candidates


def main() -> int:
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    python_supported = sys.version_info[:2] == SUPPORTED_PYTHON
    result = {
        "python_version": python_version,
        "python_support_status": "ok" if python_supported else "unsupported",
        "python_support_message": (
            "supported"
            if python_supported
            else f"requires Python {SUPPORTED_PYTHON[0]}.{SUPPORTED_PYTHON[1]}.x"
        ),
        "resolved_twofish_path": "",
        "twofish_source": "",
        "twofish_load_status": "missing",
        "twofish_message": "no local Twofish bridge was found",
        "twofish_sha256": "",
    }

    for source, candidate in _candidate_paths():
        if not candidate.exists():
            continue
        result["resolved_twofish_path"] = str(candidate)
        result["twofish_source"] = source
        result["twofish_sha256"] = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if not python_supported:
            result["twofish_load_status"] = "python_unsupported"
            result["twofish_message"] = (
                f"found {candidate}, but this bridge is only supported with Python "
                f"{SUPPORTED_PYTHON[0]}.{SUPPORTED_PYTHON[1]}.x"
            )
            print(json.dumps(result))
            return 0
        try:
            library = CDLL(str(candidate))
            getattr(library, "exp_Twofish_encrypt")
            getattr(library, "exp_Twofish_decrypt")
            result["twofish_load_status"] = "ok"
            result["twofish_message"] = f"loaded {candidate}"
            print(json.dumps(result))
            return 0
        except Exception as exc:  # pragma: no cover - runtime diagnostics
            result["twofish_load_status"] = "load_error"
            result["twofish_message"] = f"{candidate}: {exc}"
            print(json.dumps(result))
            return 0

    env_path = os.getenv("PKT_TWOFISH_LIBRARY")
    if env_path:
        result["resolved_twofish_path"] = str(Path(env_path).expanduser())
        result["twofish_source"] = "env"
        result["twofish_load_status"] = "missing"
        result["twofish_message"] = f"set but missing: {env_path}"

    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
