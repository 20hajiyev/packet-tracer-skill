"""
Vendored Twofish ctypes wrapper for the pkt skill.

This wrapper loads a local Twofish bridge from either:

- `PKT_TWOFISH_LIBRARY`
- a sibling binary named like `_twofish*.pyd` / `.so` / `.dll`

See `scripts/vendor/README.md` for setup guidance.
"""

from __future__ import annotations

import os
import sys
from ctypes import POINTER, CDLL, Structure, c_char_p, c_int, c_uint32, create_string_buffer, pointer
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from twofish_runtime import candidate_bridge_paths, expected_bridge_patterns  # noqa: E402


def _load_library() -> CDLL:
    here = Path(__file__).resolve().parent
    env_path = os.getenv("PKT_TWOFISH_LIBRARY")
    candidates = [path for _, path in candidate_bridge_paths(here, env_path=env_path) if path.exists()]
    if not candidates:
        patterns = ", ".join(expected_bridge_patterns())
        raise ImportError(
            "Twofish bridge not found. Set PKT_TWOFISH_LIBRARY or place a local _twofish binary "
            "next to scripts/vendor/twofish.py. "
            f"Expected patterns for this host: {patterns}. See scripts/vendor/README.md."
        )
    return CDLL(str(candidates[0]))


_twofish = _load_library()


class _TwofishKey(Structure):
    _fields_ = [("s", (c_uint32 * 4) * 256), ("K", c_uint32 * 40)]


_twofish.exp_Twofish_initialise.argtypes = []
_twofish.exp_Twofish_initialise.restype = None
_twofish.exp_Twofish_prepare_key.argtypes = [c_char_p, c_int, POINTER(_TwofishKey)]
_twofish.exp_Twofish_prepare_key.restype = None
_twofish.exp_Twofish_encrypt.argtypes = [POINTER(_TwofishKey), c_char_p, c_char_p]
_twofish.exp_Twofish_encrypt.restype = None
_twofish.exp_Twofish_decrypt.argtypes = [POINTER(_TwofishKey), c_char_p, c_char_p]
_twofish.exp_Twofish_decrypt.restype = None
_twofish.exp_Twofish_initialise()


class Twofish:
    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes):
            raise TypeError("Twofish key must be bytes")
        if not 0 < len(key) <= 32:
            raise ValueError("invalid Twofish key length")
        self._key = _TwofishKey()
        _twofish.exp_Twofish_prepare_key(key, len(key), pointer(self._key))

    def encrypt(self, block: bytes) -> bytes:
        if not isinstance(block, bytes):
            raise TypeError("block must be bytes")
        if len(block) != 16:
            raise ValueError("Twofish encrypt expects a 16-byte block")
        outbuf = create_string_buffer(16)
        _twofish.exp_Twofish_encrypt(pointer(self._key), block, outbuf)
        return outbuf.raw

    def decrypt(self, block: bytes) -> bytes:
        if not isinstance(block, bytes):
            raise TypeError("block must be bytes")
        if len(block) != 16:
            raise ValueError("Twofish decrypt expects a 16-byte block")
        outbuf = create_string_buffer(16)
        _twofish.exp_Twofish_decrypt(pointer(self._key), block, outbuf)
        return outbuf.raw
