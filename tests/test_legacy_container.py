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
