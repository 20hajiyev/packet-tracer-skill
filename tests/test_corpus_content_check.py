"""The corpus must prove a lab does what was asked, not merely that it opens.

Two cases passed for a week on the weaker standard: they requested router DHCP
and server DNS/HTTP, produced neither, and were counted as verified because
Packet Tracer opened the donor-shaped file anyway.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import corpus_runner  # noqa: E402
from pkt_codec import encode_pkt_modern  # noqa: E402


def _lab(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "lab.pkt"
    xml = f"<PACKETTRACER5><VERSION>9.0.0.0810</VERSION>{body}</PACKETTRACER5>".encode()
    path.write_bytes(encode_pkt_modern(xml))
    return path


def test_missing_marker_is_reported(tmp_path: Path) -> None:
    path = _lab(tmp_path, "<DEVICES/>")

    assert corpus_runner._missing_content(path, ("ip dhcp pool",)) == ["ip dhcp pool"]


def test_present_marker_passes(tmp_path: Path) -> None:
    path = _lab(tmp_path, "<CONFIG>ip dhcp pool LAN</CONFIG>")

    assert corpus_runner._missing_content(path, ("ip dhcp pool",)) == []


def test_marker_matching_ignores_case(tmp_path: Path) -> None:
    path = _lab(tmp_path, "<DNS><ENABLED>1</ENABLED></DNS>")

    assert corpus_runner._missing_content(path, ("<dns>",)) == []


def test_undecodable_file_reports_rather_than_raising(tmp_path: Path) -> None:
    path = tmp_path / "broken.pkt"
    path.write_bytes(b"not a packet tracer file")

    missing = corpus_runner._missing_content(path, ("ip dhcp pool",))

    assert len(missing) == 1
    assert "could not decode" in missing[0]


def test_capability_gaps_declare_what_they_are_missing() -> None:
    """A gap case without a content marker cannot be told from a success."""
    for case in corpus_runner.CORPUS:
        if case.name in {"router_dhcp", "server_services"}:
            assert case.expects == "capability_gap"
            assert case.requires_content, f"{case.name} must state what it lacks"


def test_vlan_cases_assert_the_vlans_they_request() -> None:
    """VLAN configuration is real, unlike DHCP -- pin it so it stays real."""
    by_name = {case.name: case for case in corpus_runner.CORPUS}

    assert by_name["campus_star_vlan"].requires_content == ("vlan 10", "vlan 20", "vlan 30")
    assert by_name["vlan_uneven"].requires_content == ("vlan 10", "vlan 20")
