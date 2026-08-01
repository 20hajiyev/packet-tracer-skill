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


MINIMUM_PYTHON = (3, 10)


def _pure_python_status() -> tuple[bool, str]:
    """Verify the vendored pure-Python engine against the official vectors."""
    try:
        sys.path.insert(0, str(_vendor_dir()))
        from twofish_pure import self_test

        self_test()
        return True, "vendored pure-Python Twofish (official test vectors pass)"
    except Exception as exc:  # pragma: no cover - runtime diagnostics
        return False, f"vendored pure-Python Twofish failed: {exc}"


def collect_twofish_diagnostics() -> dict[str, str]:
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    python_supported = sys.version_info[:2] >= MINIMUM_PYTHON
    compiled_abi_match = sys.version_info[:2] == SUPPORTED_PYTHON
    result = {
        "host_os": normalized_host_os(),
        "python_version": python_version,
        "python_support_status": "ok" if python_supported else "unsupported",
        "python_support_message": (
            "supported"
            if python_supported
            else f"requires Python {MINIMUM_PYTHON[0]}.{MINIMUM_PYTHON[1]} or newer"
        ),
        "expected_twofish_patterns": expected_bridge_patterns(),
        "twofish_search_roots": recommended_search_roots(_vendor_dir()),
        "resolved_twofish_path": "",
        "twofish_source": "",
        "twofish_backend": "",
        "twofish_load_status": "missing",
        "twofish_message": "no Twofish engine could be resolved",
        "twofish_sha256": "",
    }

    # The compiled bridge is an optional accelerator: preferred when it loads,
    # but never required, because the vendored pure-Python engine always works.
    if compiled_abi_match:
        for source, candidate in candidate_bridge_paths(
            _vendor_dir(), env_path=os.getenv("PKT_TWOFISH_LIBRARY")
        ):
            if not candidate.exists():
                continue
            try:
                library = CDLL(str(candidate))
                getattr(library, "exp_Twofish_encrypt")
                getattr(library, "exp_Twofish_decrypt")
            except Exception:  # pragma: no cover - runtime diagnostics
                continue
            result["resolved_twofish_path"] = str(candidate)
            result["twofish_source"] = source
            result["twofish_sha256"] = hashlib.sha256(candidate.read_bytes()).hexdigest()
            result["twofish_backend"] = "compiled"
            result["twofish_load_status"] = "ok"
            result["twofish_message"] = f"loaded compiled accelerator {candidate}"
            return result

    pure_ok, pure_message = _pure_python_status()
    if pure_ok and python_supported:
        result["twofish_backend"] = "pure_python"
        result["twofish_source"] = "vendored"
        result["resolved_twofish_path"] = str(_vendor_dir() / "twofish_pure.py")
        result["twofish_load_status"] = "ok"
        result["twofish_message"] = pure_message
        return result

    result["twofish_message"] = pure_message
    return result


def main() -> int:
    print(json.dumps(collect_twofish_diagnostics()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
