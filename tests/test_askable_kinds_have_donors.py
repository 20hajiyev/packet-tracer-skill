"""Asking for a device kind no lab contains can only end as an undelivered device.

`CCTVCamera` was a key the planner produced and no donor could satisfy: across
the 642 catalogued samples there is not one camera-like device type, against
439 IoT things. Packet Tracer models a camera as an IoT thing, so a camera word
belongs on that key. The palette is not the vocabulary -- `SMARTPHONE-PT` saves
as `Pda`, `Fiber Patch Panel` saves as `Patch Panel` -- and this test holds the
vocabulary to what a saved lab actually writes.

The gap ran the other way too: `MCU` survives as its own type in 45 devices
across 37 samples and there was no word for it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from intent_parser import NATURAL_DEVICE_ALIASES, parse_intent  # noqa: E402
from sample_catalog import normalize_device_type  # noqa: E402

CATALOG = ROOT / "references" / "packettracer-sample-catalog.json"

# Kinds the generator builds rather than copies out of a donor, so a catalogue
# with none of them is not evidence of a gap.
SYNTHESISED = {"Patch Panel", "Wall Mount"}


def _kinds_in_real_labs() -> set[str]:
    entries = json.loads(CATALOG.read_text(encoding="utf-8"))
    found: set[str] = set()
    for sample in entries:
        for device in sample.get("devices") or []:
            kind = device.get("type") if isinstance(device, dict) else device
            if kind:
                found.add(normalize_device_type(kind))
    return found


# This direction is a property of the donor corpus, not of the repository. The
# committed catalogue is whatever the machine that last rebuilt it could see,
# and CI's copy carries no Printer, Bridge or Repeater although Packet Tracer's
# own samples are full of them -- so asserting it there measures the checkout,
# not the skill. It runs where a real corpus exists. Shipping it unguarded
# turned CI red on the first push: measured with one catalogue, asserted
# against another.
@pytest.mark.requires_donors
@pytest.mark.skipif(not CATALOG.exists(), reason="sample catalogue not built")
def test_every_askable_kind_exists_in_some_real_lab() -> None:
    available = _kinds_in_real_labs()
    askable = set(NATURAL_DEVICE_ALIASES) - SYNTHESISED
    orphans = sorted(askable - available)
    assert not orphans, f"askable with no donor behind them: {orphans}"


@pytest.mark.skipif(not CATALOG.exists(), reason="sample catalogue not built")
def test_every_kind_a_real_lab_carries_can_be_asked_for() -> None:
    askable = set(NATURAL_DEVICE_ALIASES)
    unreachable = sorted(_kinds_in_real_labs() - askable)
    assert not unreachable, f"present in donors but nothing asks for them: {unreachable}"


def test_a_camera_is_an_iot_thing() -> None:
    for word in ("kamera", "camera", "cctv", "webcam"):
        counts = parse_intent(f"1 switch ve 3 {word} qur").device_counts
        assert counts.get("IoT") == 3, f"{word} -> {counts}"


def test_a_microcontroller_can_be_asked_for() -> None:
    for word in ("mcu", "microcontroller", "mikrokontroller"):
        counts = parse_intent(f"1 switch ve 2 {word} qur").device_counts
        assert counts.get("MCU") == 2, f"{word} -> {counts}"
