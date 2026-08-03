"""The edit surface is advertised but was never verified end to end.

Three realistic requests were run against a real lab and opened in Packet
Tracer. All three produced files that opened -- and two of the three had not
been applied at all. The file opened because it was an unchanged copy, which is
the same trap the corpus fell into: "it opened" read as "it worked".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from intent_parser import parse_intent  # noqa: E402


def _renames(prompt: str) -> list[tuple[str, str]]:
    plan = parse_intent(prompt)
    return [
        (str(op["device"]), str(op["new_name"]))
        for op in plan.edit_operations
        if op["op"] == "rename_device"
    ]


def test_the_english_command_form_still_works() -> None:
    assert _renames("rename PC1 to PC-Ofis") == [("PC1", "PC-Ofis")]


@pytest.mark.parametrize(
    "prompt",
    [
        "PC1 adini PC-Ofis et",
        "PC1 adını PC-Ofis dəyiş",
        "PC1 adini PC-Ofis ele",
    ],
)
def test_natural_rename_phrasings_are_understood(prompt: str) -> None:
    """Only `rename X to Y` was understood, so `--edit` fell back to generating
    and wrote an unchanged copy while reporting success."""
    assert _renames(prompt) == [("PC1", "PC-Ofis")]


def test_the_possessive_phrasing_is_understood() -> None:
    assert _renames("SW1 in adi CORE olsun") == [("SW1", "CORE")]


def test_diacritics_do_not_defeat_the_patterns() -> None:
    """`dəyiş` has to read as `deyis`, but device names keep their case, so the
    patterns run on a transliterated-but-not-lowercased prompt."""
    assert _renames("SW1 adını Core-SW elə") == [("SW1", "Core-SW")]


def test_a_topology_request_is_not_read_as_a_rename() -> None:
    assert _renames("1 router 1 switch 3 pc qur") == []
    assert _renames("3 switch qur") == []


def test_an_unintelligible_edit_refuses_instead_of_copying(tmp_path: Path) -> None:
    """Writing the original back and calling it an edit is the worst outcome:
    the file opens, so nothing anywhere reports a problem."""
    import generate_pkt
    from generate_pkt import PlanningError, edit_from_prompt
    from pkt_codec import encode_pkt_modern

    source = tmp_path / "lab.pkt"
    source.write_bytes(
        encode_pkt_modern(
            b"<PACKETTRACER5><VERSION>9.0.0.0810</VERSION><DEVICES>"
            b"<DEVICE><ENGINE><NAME>PC1</NAME><TYPE>Pc</TYPE>"
            b"<SAVE_REF_ID>r0</SAVE_REF_ID></ENGINE></DEVICE>"
            b"</DEVICES><LINKS/></PACKETTRACER5>"
        )
    )
    output = tmp_path / "out.pkt"

    with pytest.raises(PlanningError, match="No edit was understood"):
        edit_from_prompt(source, "bir seyler et", output)

    assert not output.exists()
    assert generate_pkt  # module import is part of the contract under test


def _lab_with_ports(tmp_path: Path) -> Path:
    """A lab whose devices use different port-naming shapes, as real ones do."""
    from pkt_codec import encode_pkt_modern

    path = tmp_path / "ports.pkt"
    path.write_bytes(
        encode_pkt_modern(
            b"<PACKETTRACER5><VERSION>9.0.0.0810</VERSION><DEVICES>"
            b"<DEVICE><ENGINE><NAME>R1</NAME><TYPE>Router</TYPE><SAVE_REF_ID>r0</SAVE_REF_ID>"
            # An ISR numbers interfaces `GigabitEthernet0/0/x` and carries
            # several; `port_exists` indexes on the trailing number, so a
            # realistic count is needed for it to accept `0/0/2`.
            + b"<PORT><TYPE>eCopperGigabitEthernet</TYPE></PORT>" * 6
            + b"</ENGINE></DEVICE>"
            b"<DEVICE><ENGINE><NAME>SW1</NAME><TYPE>Switch</TYPE><SAVE_REF_ID>r1</SAVE_REF_ID>"
            + b"<PORT><TYPE>eCopperFastEthernet</TYPE></PORT>" * 8
            + b"<PORT><TYPE>eCopperGigabitEthernet</TYPE></PORT>" * 2
            + b"</ENGINE></DEVICE>"
            b"<DEVICE><ENGINE><NAME>PC1</NAME><TYPE>Pc</TYPE><SAVE_REF_ID>r2</SAVE_REF_ID>"
            b"<PORT><TYPE>eCopperFastEthernet</TYPE></PORT></ENGINE></DEVICE>"
            b"</DEVICES><LINKS><LINK><CABLE><FROM>r0</FROM><TO>r1</TO>"
            b"<PORT>GigabitEthernet0/0/1</PORT><PORT>GigabitEthernet0/1</PORT>"
            b"</CABLE></LINK></LINKS></PACKETTRACER5>"
        )
    )
    return path


def test_link_ports_take_their_shape_from_the_file(tmp_path: Path) -> None:
    """Port names vary by model and cannot be guessed.

    Three rounds of guessing produced `FastEthernet0` for a switch,
    `FastEthernet0/1` for a PC, and `GigabitEthernet0/1` for an ISR router that
    numbers its interfaces `GigabitEthernet0/0/x`. Packet Tracer rejects a lab
    referencing an interface that does not exist, so the shape is taken from
    ports the device is already using.
    """
    from generate_pkt import _resolve_edit_link_ports

    plan = parse_intent("R1 ve SW1 arasinda link qur")
    plan.goal = "edit"
    _resolve_edit_link_ports(_lab_with_ports(tmp_path), plan)

    links = [op for op in plan.edit_operations if op["op"] == "set_link"]
    assert links, "the link operation should survive resolution"
    assert links[0]["a"]["port"] == "GigabitEthernet0/0/2"


def test_a_host_gets_its_single_interface(tmp_path: Path) -> None:
    from generate_pkt import _resolve_edit_link_ports

    plan = parse_intent("PC1 ve SW1 arasinda link qur")
    plan.goal = "edit"
    _resolve_edit_link_ports(_lab_with_ports(tmp_path), plan)

    links = [op for op in plan.edit_operations if op["op"] == "set_link"]
    assert links[0]["a"]["port"] == "FastEthernet0"


def test_an_unresolvable_link_is_dropped_rather_than_written_broken(tmp_path: Path) -> None:
    from generate_pkt import _resolve_edit_link_ports

    plan = parse_intent("Ghost1 ve SW1 arasinda link qur")
    plan.goal = "edit"
    _resolve_edit_link_ports(_lab_with_ports(tmp_path), plan)

    assert not [op for op in plan.edit_operations if op["op"] == "set_link"]
    assert any("free port" in gap for gap in plan.blocking_gaps)


def test_natural_edit_phrasings_reach_the_editor() -> None:
    """`pkt_editor` implemented all of these; only the parsing was missing."""
    def ops(prompt: str) -> list[str]:
        plan = parse_intent(prompt)
        return [str(op["op"]) for op in plan.edit_operations + plan.switch_ops]

    assert "set_vlan" in ops("SW1 de vlan 20 yarat")
    assert "set_link" in ops("PC1 ile SW1 i birlesdir")
    assert "prune_device" in ops("PC3 u sil")
    assert "remove_link" in ops("R1 ve SW1 arasindaki linki sil")


def test_a_generation_request_produces_no_edit_operations() -> None:
    for prompt in ("1 router 1 switch 3 pc qur", "3 dene switch ve 6 komputer qur"):
        plan = parse_intent(prompt)
        assert not plan.edit_operations
