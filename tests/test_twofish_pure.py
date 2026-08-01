"""Correctness tests for the vendored pure-Python Twofish engine.

These are unconditional: the pure engine is the repo-local baseline and must
work with no compiled bridge and no environment variables. If these fail, the
whole `.pkt` decode/edit/generate path is unusable on a clean checkout.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts" / "vendor"))

from twofish_pure import TEST_VECTORS, Twofish, self_test  # noqa: E402


def test_official_vectors_pass() -> None:
    self_test()


@pytest.mark.parametrize("key_hex,plain_hex,cipher_hex", TEST_VECTORS)
def test_each_official_vector(key_hex: str, plain_hex: str, cipher_hex: str) -> None:
    engine = Twofish(bytes.fromhex(key_hex))
    assert engine.encrypt(bytes.fromhex(plain_hex)) == bytes.fromhex(cipher_hex)
    assert engine.decrypt(bytes.fromhex(cipher_hex)) == bytes.fromhex(plain_hex)


@pytest.mark.parametrize("key_length", [16, 24, 32])
def test_roundtrip_is_stable(key_length: int) -> None:
    key = bytes(range(key_length))
    engine = Twofish(key)
    for seed in range(16):
        block = bytes((seed * 17 + index) & 0xFF for index in range(16))
        assert engine.decrypt(engine.encrypt(block)) == block


def test_packet_tracer_key_is_accepted() -> None:
    """The `.pkt` format uses a fixed 128-bit key of repeated 0x89 bytes."""
    engine = Twofish(bytes([0x89]) * 16)
    block = bytes([0x10]) * 16
    assert engine.decrypt(engine.encrypt(block)) == block


def test_short_keys_are_padded_not_rejected() -> None:
    assert Twofish(b"\x01" * 8).encrypt(b"\x00" * 16) == Twofish(
        b"\x01" * 8 + b"\x00" * 8
    ).encrypt(b"\x00" * 16)


@pytest.mark.parametrize("bad_key", [b"", b"\x00" * 33, "not-bytes"])
def test_invalid_keys_are_rejected(bad_key: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        Twofish(bad_key)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_block", [b"", b"\x00" * 15, b"\x00" * 17])
def test_invalid_block_sizes_are_rejected(bad_block: bytes) -> None:
    engine = Twofish(bytes([0x89]) * 16)
    with pytest.raises(ValueError):
        engine.encrypt(bad_block)
    with pytest.raises(ValueError):
        engine.decrypt(bad_block)


def test_codec_resolves_an_engine_without_any_environment(monkeypatch) -> None:
    """`pkt_codec` must produce a working engine with no bridge configured."""
    monkeypatch.delenv("PKT_TWOFISH_LIBRARY", raising=False)
    monkeypatch.delenv("PKT_TWOFISH_SEARCH_ROOTS", raising=False)

    import pkt_codec

    monkeypatch.setattr(pkt_codec, "_TWOFISH_CLS", None)
    monkeypatch.setattr(pkt_codec, "_TWOFISH_BACKEND", "")

    engine_cls = pkt_codec._twofish_cls()
    assert pkt_codec.twofish_backend() in {"compiled", "pure_python"}

    block = bytes([0x10]) * 16
    engine = engine_cls(bytes([0x89]) * 16)
    assert engine.decrypt(engine.encrypt(block)) == block


def test_codec_roundtrips_xml_without_any_environment(monkeypatch) -> None:
    monkeypatch.delenv("PKT_TWOFISH_LIBRARY", raising=False)
    monkeypatch.delenv("PKT_TWOFISH_SEARCH_ROOTS", raising=False)

    import pkt_codec

    monkeypatch.setattr(pkt_codec, "_TWOFISH_CLS", None)
    monkeypatch.setattr(pkt_codec, "_TWOFISH_BACKEND", "")

    xml = b"<?xml version='1.0'?><PACKETTRACER5><VERSION>9.0.0.0810</VERSION></PACKETTRACER5>"
    assert pkt_codec.decode_pkt_modern(pkt_codec.encode_pkt_modern(xml)) == xml


def test_pure_and_compiled_agree_when_both_are_available() -> None:
    """When a compiled bridge is present, both engines must be bit-identical."""
    try:
        from vendor.twofish import Twofish as CompiledTwofish
    except Exception:
        pytest.skip("no compiled Twofish accelerator on this host")

    for key_length in (16, 24, 32):
        key = bytes((index * 7 + 3) & 0xFF for index in range(key_length))
        block = bytes((index * 13 + 5) & 0xFF for index in range(16))
        compiled = CompiledTwofish(key)
        pure = Twofish(key)
        assert compiled.encrypt(block) == pure.encrypt(block)
        assert compiled.decrypt(block) == pure.decrypt(block)
