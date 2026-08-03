"""Tests for the pre-Twofish `.pkt` container.

18 of the 292 samples bundled with Packet Tracer 9.0 are Packet Tracer 5.x
saves written before Twofish was introduced. They failed EAX tag verification
and were reported as undecodable, which quietly removed the QoS, SNMP, NAT,
TFTP, IPsec, AAA, CBAC, ZFW and VoIP labs from everything that reads samples.

The format is qCompress output XORed byte-wise with `(length - index)`.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from pkt_codec import (  # noqa: E402
    decode_pkt_auto,
    decode_pkt_legacy,
    decode_pkt_modern,
    detect_pkt_format,
    encode_pkt_legacy,
    encode_pkt_modern,
    legacy_xor,
)


def _lab_xml(version: str = "5.2.0.0068") -> bytes:
    root = ET.Element("PACKETTRACER5")
    ET.SubElement(root, "VERSION").text = version
    devices = ET.SubElement(root, "DEVICES")
    for index in range(3):
        device = ET.SubElement(devices, "DEVICE")
        engine = ET.SubElement(device, "ENGINE")
        ET.SubElement(engine, "NAME").text = f"D{index}"
    ET.SubElement(root, "LINKS")
    return ET.tostring(root, encoding="utf-8")


def test_legacy_xor_is_its_own_inverse() -> None:
    data = bytes(range(256)) * 3

    assert legacy_xor(legacy_xor(data)) == data


def test_legacy_roundtrip() -> None:
    xml = _lab_xml()

    assert decode_pkt_legacy(encode_pkt_legacy(xml)) == xml


def test_modern_roundtrip_is_unaffected() -> None:
    xml = _lab_xml("9.0.0.0810")

    assert decode_pkt_modern(encode_pkt_modern(xml)) == xml


@pytest.mark.parametrize(
    "encoder,expected",
    [(encode_pkt_legacy, "legacy"), (encode_pkt_modern, "modern")],
)
def test_format_detection(encoder, expected: str) -> None:
    assert detect_pkt_format(encoder(_lab_xml())) == expected


def test_detection_reports_unknown_for_junk() -> None:
    assert detect_pkt_format(b"this is not a packet tracer save at all") == "unknown"


@pytest.mark.parametrize(
    "encoder,expected",
    [(encode_pkt_legacy, "legacy"), (encode_pkt_modern, "modern")],
)
def test_auto_decode_reports_which_container_matched(encoder, expected: str) -> None:
    xml = _lab_xml()

    decoded, container = decode_pkt_auto(encoder(xml))

    assert decoded == xml
    assert container == expected


def test_auto_decode_raises_with_both_reasons() -> None:
    with pytest.raises(ValueError) as excinfo:
        decode_pkt_auto(b"junk" * 32)

    message = str(excinfo.value)
    assert "modern decode failed" in message
    assert "legacy container did not match" in message


def test_modern_decode_still_rejects_a_legacy_file() -> None:
    """The two containers must stay distinguishable, not silently interchangeable."""
    with pytest.raises(Exception):
        decode_pkt_modern(encode_pkt_legacy(_lab_xml()))


def test_bulk_stage_transforms_match_the_byte_at_a_time_definition() -> None:
    """The stage masks are 256-periodic, which is what makes bulk XOR valid.

    Stage 2 masks byte `i` with `(length - i) & 0xFF`; stage 1 uses
    `(length - i * length) & 0xFF`, and stepping `i` by 256 adds `256 * length`,
    zero modulo 256. Getting that wrong would corrupt every file silently, so
    the optimised versions are pinned against the original definitions.
    """
    import random

    from pkt_codec import stage1_deobfuscate, stage1_obfuscate, stage2_xor

    def reference_stage2(data: bytes) -> bytes:
        length = len(data)
        return bytes(byte ^ ((length - index) & 0xFF) for index, byte in enumerate(data))

    def reference_stage1_obfuscate(clear: bytes) -> bytes:
        length = len(clear)
        out = bytearray(length)
        for index, byte in enumerate(clear):
            out[length - 1 - index] = byte ^ ((length - index * length) & 0xFF)
        return bytes(out)

    random.seed(11)
    for size in (0, 1, 15, 16, 17, 255, 256, 257, 4096, 10007):
        payload = bytes(random.getrandbits(8) for _ in range(size))
        assert stage2_xor(payload) == reference_stage2(payload)
        assert stage1_obfuscate(payload) == reference_stage1_obfuscate(payload)
        assert stage1_deobfuscate(stage1_obfuscate(payload)) == payload


def test_skipping_verification_returns_identical_bytes() -> None:
    """EAX runs the cipher twice -- once for CTR, once for the tag.

    Inspection paths parse the result as XML immediately, so corruption surfaces
    there anyway and the authentication pass is pure cost.
    """
    from pkt_codec import decode_pkt_auto, encode_pkt_modern

    payload = b"<PACKETTRACER5><VERSION>9.0.0.0810</VERSION><DEVICES/></PACKETTRACER5>"
    blob = encode_pkt_modern(payload)

    verified, _ = decode_pkt_auto(blob)
    unverified, _ = decode_pkt_auto(blob, verify=False)

    assert verified == unverified == payload


def test_a_corrupt_tag_is_still_rejected_when_verifying() -> None:
    import pytest

    from pkt_codec import decode_pkt_modern, encode_pkt_modern, stage1_deobfuscate, stage1_obfuscate

    blob = encode_pkt_modern(b"<PACKETTRACER5><VERSION>9.0.0.0810</VERSION></PACKETTRACER5>")
    stage1 = bytearray(stage1_deobfuscate(blob))
    stage1[-1] ^= 0xFF  # damage the tag
    damaged = stage1_obfuscate(bytes(stage1))

    with pytest.raises(ValueError, match="tag verification failed"):
        decode_pkt_modern(damaged)
