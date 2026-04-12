from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from pkt_codec import decode_pkt_modern, encode_pkt_modern, qcompress  # noqa: E402


def test_qcompress_big_endian_prefix() -> None:
    blob = qcompress(b"abc")
    assert blob[:4] == b"\x00\x00\x00\x03"


def test_modern_codec_roundtrip() -> None:
    xml_bytes = (
        b'<?xml version="1.0" encoding="utf-8"?><PACKETTRACER5><VERSION>9.0.0.0810</VERSION></PACKETTRACER5>'
    )
    try:
        pkt = encode_pkt_modern(xml_bytes)
        decoded = decode_pkt_modern(pkt)
    except ImportError:
        return
    assert decoded == xml_bytes
