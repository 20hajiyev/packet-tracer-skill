"""Large labs have to be readable, not just correct.

Hosts were dealt into one global six-wide grid regardless of which switch they
belonged to. A 500-host lab came out ten thousand units tall, with hosts
hundreds of units away from the switch they plug into -- structurally valid and
impossible to follow.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_pkt import _lay_out_switch_blocks, build_prompt_blueprint  # noqa: E402
from intent_parser import parse_intent  # noqa: E402


def _placed(prompt: str) -> list[dict[str, object]]:
    blueprint, _ = build_prompt_blueprint(parse_intent(prompt))
    return [device for device in blueprint["devices"] if "x" in device and "y" in device]


@pytest.mark.requires_donors
def test_a_large_lab_stays_roughly_square() -> None:
    """Ten thousand units of vertical scroll is not a diagram anyone can read."""
    devices = _placed("200 komputer 10 switch 1 router qur")
    heights = [int(device["y"]) for device in devices]
    widths = [int(device["x"]) for device in devices]

    span_y = max(heights) - min(heights)
    span_x = max(widths) - min(widths)

    assert span_y < 4000, f"layout is {span_y} units tall"
    assert span_y < span_x * 3, "the canvas should not be a narrow column"
    # The column check alone let the opposite through. Eighteen switch blocks
    # laid end to end measured 15,640 units wide against 4,020 tall and passed
    # this test, because nothing here constrained width: a strip you scroll
    # sideways through and never see at once. A diagram is readable when both
    # spans are of the same order.
    assert span_x < 4000, f"layout is {span_x} units wide"
    assert span_x < span_y * 3, "the canvas should not be a wide strip"


def test_hosts_sit_under_the_switch_they_belong_to() -> None:
    switches = [{"name": "SW1", "type": "Switch"}, {"name": "SW2", "type": "Switch"}]
    hosts = [{"name": f"PC{index}", "type": "PC"} for index in range(1, 11)]

    _lay_out_switch_blocks(switches, hosts)

    # SW2 is the only access switch here, so every host belongs to its block.
    access = switches[1]
    for host in hosts:
        assert host["y"] > access["y"], "hosts belong below their switch"
        assert abs(int(host["x"]) - int(access["x"])) < 600, "hosts drifted away from their switch"


def test_blocks_wrap_instead_of_running_off_to_the_right() -> None:
    switches = [{"name": "CORE", "type": "Switch"}] + [
        {"name": f"SW{index}", "type": "Switch"} for index in range(1, 13)
    ]
    hosts = [{"name": f"PC{index}", "type": "PC"} for index in range(1, 25)]

    _lay_out_switch_blocks(switches, hosts)

    access_rows = {int(switch["y"]) for switch in switches[1:]}
    assert len(access_rows) > 1, "twelve access switches should wrap onto more than one row"


def test_a_lone_switch_still_gets_its_hosts() -> None:
    switches = [{"name": "SW1", "type": "Switch"}]
    hosts = [{"name": f"PC{index}", "type": "PC"} for index in range(1, 6)]

    _lay_out_switch_blocks(switches, hosts)

    assert all("x" in host and "y" in host for host in hosts)
    assert all(int(host["y"]) > int(switches[0]["y"]) for host in hosts)


def test_hosts_with_no_switch_are_still_placed() -> None:
    hosts = [{"name": f"PC{index}", "type": "PC"} for index in range(1, 4)]

    _lay_out_switch_blocks([], hosts)

    assert all("x" in host and "y" in host for host in hosts)


def _bare_lab(devices: list[tuple[str, int]], cables: list[tuple[str, str]]) -> "ET.Element":
    import xml.etree.ElementTree as ET

    root = ET.fromstring("<PACKETTRACER5><NETWORK><DEVICES/><LINKS/></NETWORK></PACKETTRACER5>")
    for name, x in devices:
        device = ET.fromstring(
            "<DEVICE><ENGINE><NAME/><TYPE>Pc</TYPE><SAVE_REF_ID/></ENGINE>"
            "<WORKSPACE><LOGICAL><X/><Y>100</Y></LOGICAL></WORKSPACE></DEVICE>"
        )
        device.find("./ENGINE/NAME").text = name
        device.find("./ENGINE/SAVE_REF_ID").text = f"ref-{name}"
        device.find("./WORKSPACE/LOGICAL/X").text = str(x)
        root.find(".//DEVICES").append(device)
    for left, right in cables:
        cable = ET.SubElement(ET.SubElement(root.find(".//LINKS"), "LINK"), "CABLE")
        ET.SubElement(cable, "FROM").text = f"ref-{left}"
        ET.SubElement(cable, "PORT").text = "FastEthernet0"
        ET.SubElement(cable, "TO").text = f"ref-{right}"
        ET.SubElement(cable, "PORT").text = "FastEthernet0"
    return root


def test_a_cabled_device_is_never_parked_however_far_right_it_sits() -> None:
    """Four passes each tested x against the threshold and nothing else.

    A lab whose blocks had been laid end to end ran past 9,000 halfway through,
    and from there the layout stopped tidying, the compaction stopped pulling
    in, the overlap pass stopped separating and the annotation stopped drawing
    frames. One rule, written four times, wrong in every copy.
    """
    from generate_pkt import _parked_names

    root = _bare_lab([("PC1", 15510), ("PC2", 200), ("UNUSED-PC1", 15800)], [("PC1", "PC2")])
    assert _parked_names(root) == {"UNUSED-PC1"}


def test_an_uncabled_device_inside_the_canvas_is_not_parked_either() -> None:
    from generate_pkt import _parked_names

    root = _bare_lab([("PC1", 400), ("PC2", 500)], [])
    assert _parked_names(root) == set()
