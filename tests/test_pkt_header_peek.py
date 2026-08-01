"""Tests for the fast header probe used during donor scanning.

Reading `<VERSION>` used to cost a full authenticated decode of every candidate,
which measured at ~3 s per multi-megabyte lab and dominated generation time.
The probe must stay both fast and exactly as accurate as the full decode.
"""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from packet_tracer_env import _pkt_version  # noqa: E402
from pkt_codec import decode_pkt_modern, encode_pkt_modern, peek_pkt_header  # noqa: E402

VERSION_PATTERN = re.compile(rb"<VERSION>([^<]*)</VERSION>")


def _lab_bytes(version: str = "9.0.0.0810", device_count: int = 2) -> bytes:
    root = ET.Element("PACKETTRACER5")
    ET.SubElement(root, "VERSION").text = version
    devices = ET.SubElement(root, "DEVICES")
    for index in range(device_count):
        device = ET.SubElement(devices, "DEVICE")
        engine = ET.SubElement(device, "ENGINE")
        ET.SubElement(engine, "NAME").text = f"D{index}"
        # Padding so the file is comfortably larger than one cipher block.
        ET.SubElement(engine, "NOTE").text = "x" * 512
    ET.SubElement(root, "LINKS")
    return encode_pkt_modern(ET.tostring(root, encoding="utf-8"))


@pytest.mark.parametrize("version", ["9.0.0.0810", "9.0.0.0000", "6.1.0.0026", "8.2.1.4208"])
def test_peek_matches_the_full_decode(version: str) -> None:
    blob = _lab_bytes(version)

    peeked = VERSION_PATTERN.search(peek_pkt_header(blob))
    full = VERSION_PATTERN.search(decode_pkt_modern(blob))

    assert peeked is not None and full is not None
    assert peeked.group(1) == full.group(1) == version.encode()


def test_peek_works_on_a_large_lab() -> None:
    """The probe must not depend on reading the whole file."""
    blob = _lab_bytes(device_count=400)

    match = VERSION_PATTERN.search(peek_pkt_header(blob))

    assert match is not None
    assert match.group(1) == b"9.0.0.0810"


def test_peek_rejects_a_blob_that_is_too_short() -> None:
    with pytest.raises(ValueError):
        peek_pkt_header(b"\x00" * 8)


def test_peek_raises_on_corrupt_payload() -> None:
    blob = bytearray(_lab_bytes(device_count=60))
    # Corrupt the tail, which stage 1 maps to the front of the plaintext.
    for index in range(1, min(200, len(blob))):
        blob[-index] ^= 0xFF

    with pytest.raises(ValueError):
        peek_pkt_header(bytes(blob))


def test_pkt_version_reads_the_version(tmp_path: Path) -> None:
    path = tmp_path / "lab.pkt"
    path.write_bytes(_lab_bytes("9.0.0.0810"))

    assert _pkt_version(path) == "9.0.0.0810"


def test_pkt_version_cache_is_invalidated_when_the_file_changes(tmp_path: Path) -> None:
    """The cache key includes size and mtime, so an edited file is re-read."""
    path = tmp_path / "lab.pkt"
    path.write_bytes(_lab_bytes("9.0.0.0810"))
    assert _pkt_version(path) == "9.0.0.0810"

    path.write_bytes(_lab_bytes("8.2.1.4208", device_count=3))

    assert _pkt_version(path) == "8.2.1.4208"


def test_pkt_version_returns_none_for_a_missing_file(tmp_path: Path) -> None:
    assert _pkt_version(tmp_path / "absent.pkt") is None


def test_pkt_version_returns_none_for_a_non_pkt_file(tmp_path: Path) -> None:
    path = tmp_path / "not-a-lab.pkt"
    path.write_bytes(b"plain text, definitely not a packet tracer save")

    assert _pkt_version(path) is None
