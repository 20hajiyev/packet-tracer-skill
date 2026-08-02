"""Tests for the two-tier verification of generated `.pkt` files.

Tier 1 must catch the ways a pruned donor stops being a valid Packet Tracer
file. Tier 2 is exercised manually against a real Packet Tracer install; only
its contract is pinned here.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from pkt_codec import encode_pkt_modern  # noqa: E402
from pkt_verify import OpenReport, open_check, structural_check  # noqa: E402


def _lab_xml(
    *,
    version: str = "9.0.0.0810",
    device_names: tuple[str, ...] = ("R1", "SW1"),
    dangling_link: bool = False,
    root_tag: str = "PACKETTRACER5",
) -> bytes:
    root = ET.Element(root_tag)
    ET.SubElement(root, "VERSION").text = version
    devices = ET.SubElement(root, "DEVICES")
    for index, name in enumerate(device_names):
        device = ET.SubElement(devices, "DEVICE")
        engine = ET.SubElement(device, "ENGINE")
        ET.SubElement(engine, "NAME").text = name
        ET.SubElement(engine, "TYPE").text = "Router" if name.startswith("R") else "Switch"
        ET.SubElement(engine, "SAVE_REF_ID").text = f"ref-{index}"
    links = ET.SubElement(root, "LINKS")
    if len(device_names) >= 2:
        link = ET.SubElement(links, "LINK")
        cable = ET.SubElement(link, "CABLE")
        ET.SubElement(cable, "FROM").text = "ref-0"
        ET.SubElement(cable, "TO").text = "ref-99" if dangling_link else "ref-1"
    return ET.tostring(root, encoding="utf-8")


def _write_lab(tmp_path: Path, name: str = "lab.pkt", **kwargs: object) -> Path:
    path = tmp_path / name
    path.write_bytes(encode_pkt_modern(_lab_xml(**kwargs)))  # type: ignore[arg-type]
    return path


def test_valid_lab_passes(tmp_path: Path) -> None:
    report = structural_check(_write_lab(tmp_path))

    assert report.passed
    assert report.failures == []
    assert report.version == "9.0.0.0810"
    assert report.device_count == 2
    assert report.link_count == 1


def test_missing_file_fails(tmp_path: Path) -> None:
    report = structural_check(tmp_path / "absent.pkt")

    assert not report.passed
    assert any("does not exist" in failure for failure in report.failures)


def test_empty_file_fails(tmp_path: Path) -> None:
    path = tmp_path / "empty.pkt"
    path.write_bytes(b"")

    report = structural_check(path)

    assert not report.passed
    assert any("empty" in failure for failure in report.failures)


def test_truncated_bytes_fail_to_decode(tmp_path: Path) -> None:
    path = _write_lab(tmp_path)
    path.write_bytes(path.read_bytes()[:-40])

    report = structural_check(path)

    assert not report.passed
    assert any("decode failed" in failure for failure in report.failures)


def test_dangling_link_endpoint_is_caught(tmp_path: Path) -> None:
    """A pruned donor that keeps a link to a deleted device will not open."""
    report = structural_check(_write_lab(tmp_path, dangling_link=True))

    assert not report.passed
    assert any("references unknown device" in failure for failure in report.failures)


def test_duplicate_device_names_are_caught(tmp_path: Path) -> None:
    report = structural_check(_write_lab(tmp_path, device_names=("SW1", "SW1")))

    assert not report.passed
    assert any("duplicate device names" in failure for failure in report.failures)


def test_incompatible_version_is_caught(tmp_path: Path) -> None:
    report = structural_check(_write_lab(tmp_path, version="5.3.0.0011"))

    assert not report.passed
    assert report.compatibility_tier == "incompatible"


def test_wrong_root_element_is_caught(tmp_path: Path) -> None:
    report = structural_check(_write_lab(tmp_path, root_tag="NOTPACKETTRACER"))

    assert not report.passed
    assert any("unexpected root element" in failure for failure in report.failures)


def test_no_devices_is_caught(tmp_path: Path) -> None:
    report = structural_check(_write_lab(tmp_path, device_names=()))

    assert not report.passed
    assert any("no devices" in failure for failure in report.failures)


def test_device_count_mismatch_is_a_warning_not_a_failure(tmp_path: Path) -> None:
    """Parked donor spares inflate the count without making the file invalid."""
    report = structural_check(_write_lab(tmp_path), expected_devices=5)

    assert report.passed
    assert report.failures == []
    assert any("parked rather than deleted" in warning for warning in report.warnings)


def test_open_check_reports_missing_packet_tracer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import pkt_verify

    monkeypatch.setattr(pkt_verify, "get_packet_tracer_exe", lambda: None)

    report = open_check(_write_lab(tmp_path))

    assert report.status == "packet_tracer_missing"
    assert not report.opened
    assert "PACKET_TRACER_ROOT" in report.detail


def test_open_report_json_is_explicit_about_proof() -> None:
    payload = OpenReport(status="timeout", pkt_path="x.pkt", elapsed_seconds=12.34).to_json()

    assert payload["tier"] == "open"
    assert payload["opened"] is False
    assert payload["elapsed_seconds"] == 12.3


def test_new_links_carry_no_invented_memory_addresses(tmp_path: Path) -> None:
    """Link MEM_ADDRs are runtime pointers; inventing them breaks the file.

    A created host link with those fields omitted opens in Packet Tracer; the
    same link with values written in does not.
    """
    import xml.etree.ElementTree as ET

    from pkt_editor import _ensure_link

    root = ET.fromstring(
        "<PACKETTRACER5><VERSION>9.0.0.0810</VERSION><DEVICES>"
        "<DEVICE><ENGINE><NAME>SW1</NAME><TYPE>Switch</TYPE>"
        "<SAVE_REF_ID>ref-a</SAVE_REF_ID></ENGINE>"
        "<WORKSPACE><LOGICAL><MEM_ADDR>111</MEM_ADDR></LOGICAL></WORKSPACE></DEVICE>"
        "<DEVICE><ENGINE><NAME>PC1</NAME><TYPE>Pc</TYPE>"
        "<SAVE_REF_ID>ref-b</SAVE_REF_ID></ENGINE>"
        "<WORKSPACE><LOGICAL><MEM_ADDR>222</MEM_ADDR></LOGICAL></WORKSPACE></DEVICE>"
        "</DEVICES><LINKS/></PACKETTRACER5>"
    )

    _ensure_link(root, "SW1", "FastEthernet0/1", "PC1", "FastEthernet0", "straight-through")

    cables = root.findall(".//LINKS/LINK/CABLE")
    assert cables, "a link should have been created"
    for tag in ("FROM_DEVICE_MEM_ADDR", "TO_DEVICE_MEM_ADDR", "FROM_PORT_MEM_ADDR", "TO_PORT_MEM_ADDR"):
        assert cables[0].find(tag) is None, f"{tag} must not be invented on a new link"
