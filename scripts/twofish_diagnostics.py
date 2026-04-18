#!/usr/bin/env python3
"""Runtime diagnostics for the local Twofish bridge."""

from __future__ import annotations

import json
import hashlib
import os
import sys
from ctypes import CDLL
from pathlib import Path

from twofish_runtime import (
    SUPPORTED_PYTHON,
    candidate_bridge_paths,
    expected_bridge_patterns,
    normalized_host_os,
    recommended_search_roots,
)


def _vendor_dir() -> Path:
    return Path(__file__).resolve().parent / "vendor"


def collect_twofish_diagnostics() -> dict[str, str]:
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    python_supported = sys.version_info[:2] == SUPPORTED_PYTHON
    result = {
        "host_os": normalized_host_os(),
        "python_version": python_version,
        "python_support_status": "ok" if python_supported else "unsupported",
        "python_support_message": (
            "supported"
            if python_supported
            else f"requires Python {SUPPORTED_PYTHON[0]}.{SUPPORTED_PYTHON[1]}.x"
        ),
        "expected_twofish_patterns": expected_bridge_patterns(),
        "twofish_search_roots": recommended_search_roots(_vendor_dir()),
        "resolved_twofish_path": "",
        "twofish_source": "",
        "twofish_load_status": "missing",
        "twofish_message": "no local Twofish bridge was found",
        "twofish_sha256": "",
    }

    for source, candidate in candidate_bridge_paths(_vendor_dir(), env_path=os.getenv("PKT_TWOFISH_LIBRARY")):
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
            return result
        try:
            library = CDLL(str(candidate))
            getattr(library, "exp_Twofish_encrypt")
            getattr(library, "exp_Twofish_decrypt")
            result["twofish_load_status"] = "ok"
            result["twofish_message"] = f"loaded {candidate}"
            return result
        except Exception as exc:  # pragma: no cover - runtime diagnostics
            result["twofish_load_status"] = "load_error"
            result["twofish_message"] = f"{candidate}: {exc}"
            return result

    env_path = os.getenv("PKT_TWOFISH_LIBRARY")
    if env_path:
        result["resolved_twofish_path"] = str(Path(env_path).expanduser())
        result["twofish_source"] = "env"
        result["twofish_load_status"] = "missing"
        result["twofish_message"] = f"set but missing: {env_path}"

    return result


def main() -> int:
    print(json.dumps(collect_twofish_diagnostics()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
