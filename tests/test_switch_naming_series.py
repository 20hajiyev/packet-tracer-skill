"""A switch promoted to a multilayer model is still one of the switches asked for.

`3 switch 1 router ve 4 komputer qur` is promoted to two switches plus one
multilayer switch so it fits the donor pool. The promoted one was named by its
type -- `MultiLayerSwitch1` -- because `_default_name_for_type` had no entry for
that type and fell through to `f"{device_type}{index}"`.

So a prompt asking for three switches shipped `SW1`, `SW2` and
`MultiLayerSwitch1`. The device was there and correctly cabled; four corpus labs
looked one device short for this reason alone, and the shortfall check reported
`SW3` missing while it stood there under another name.

Numbering is offset by the plain switches counted once. Adding the requirement
and the running count together produced `SW5` for the third switch of three,
because whether the plain switches are seeded before or after the multilayer one
depends on requirement ordering.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_pkt import _default_name_for_type, _seed_devices_from_plan  # noqa: E402
from intent_parser import IntentPlan, parse_intent  # noqa: E402


def _switch_names(plan: IntentPlan) -> list[str]:
    devices = _seed_devices_from_plan(plan)
    return [
        str(device.get("name"))
        for device in devices
        if str(device.get("type", "")).endswith("Switch")
    ]


def test_a_multilayer_switch_is_named_in_the_switch_series() -> None:
    assert _default_name_for_type("MultiLayerSwitch", 3) == "SW3"


def test_a_promoted_switch_continues_the_numbering() -> None:
    plan = parse_intent("3 switch 1 router ve 4 komputer qur")
    plan.device_requirements = {"Router": 1, "Switch": 2, "MultiLayerSwitch": 1, "PC": 4}
    assert _switch_names(plan) == ["SW1", "SW2", "SW3"]


def test_the_offset_counts_the_plain_switches_once() -> None:
    """Summing the requirement and the running count gave `SW5` for three switches."""
    plan = parse_intent("4 switch 1 router 8 komputer qur")
    plan.device_requirements = {"Router": 1, "Switch": 3, "MultiLayerSwitch": 1, "PC": 8}
    names = _switch_names(plan)
    assert names == ["SW1", "SW2", "SW3", "SW4"]
    assert len(set(names)) == len(names)


def test_ordering_of_the_requirements_does_not_change_the_names() -> None:
    ordered = parse_intent("3 switch 1 router ve 4 komputer qur")
    ordered.device_requirements = {"Switch": 2, "MultiLayerSwitch": 1, "PC": 4, "Router": 1}
    reversed_order = parse_intent("3 switch 1 router ve 4 komputer qur")
    reversed_order.device_requirements = {"MultiLayerSwitch": 1, "Switch": 2, "PC": 4, "Router": 1}
    assert sorted(_switch_names(ordered)) == sorted(_switch_names(reversed_order)) == ["SW1", "SW2", "SW3"]


def test_a_plain_switch_lab_is_unchanged() -> None:
    plan = parse_intent("1 router 1 switch ve 3 komputer qur")
    assert _switch_names(plan) == ["SW1"]
