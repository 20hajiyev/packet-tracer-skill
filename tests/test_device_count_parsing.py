"""Device counts must attach to the device word they belong to.

Two phrasings are supported: `3 switch` and `switch 3`. Pooling both through
`max` let the trailing form swallow the next device's number, so
"4 switch 1 router 8 komputer" produced eight routers. The corpus runner found
this; no unit test had ever asserted a multi-device count.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from intent_parser import parse_intent  # noqa: E402


@pytest.mark.parametrize(
    "prompt,expected",
    [
        ("1 router 1 switch ve 3 komputer qur", {"Router": 1, "Switch": 1, "PC": 3}),
        ("1 switch ve 5 komputer qur", {"Switch": 1, "PC": 5}),
        # The regressions: a count for one device landing on the previous one.
        ("4 switch 1 router 8 komputer qur", {"Router": 1, "Switch": 4, "PC": 8}),
        ("1 router 1 switch 2 komputer 1 server qur", {"Router": 1, "Switch": 1, "PC": 2, "Server": 1}),
        ("2 switch 1 router 7 komputer vlanlarda 10,20", {"Router": 1, "Switch": 2, "PC": 7}),
        (
            "3 dene switch ve 6 komputer ve 1 router vlanlarda 10,20,30",
            {"Router": 1, "Switch": 3, "PC": 6},
        ),
    ],
)
def test_counts_attach_to_the_right_device(prompt: str, expected: dict[str, int]) -> None:
    counts = parse_intent(prompt).device_requirements

    for device_type, count in expected.items():
        assert counts.get(device_type) == count, f"{device_type} in {counts}"


def test_trailing_form_still_works_when_nothing_follows() -> None:
    counts = parse_intent("switch 3 ve router 1 qur").device_requirements

    assert counts.get("Switch") == 3
    assert counts.get("Router") == 1


@pytest.mark.parametrize(
    "prompt",
    ["router 1 ve switch 4 qur", "switch 4 ve router 1 qur"],
)
def test_separated_trailing_form_does_not_consume_the_next_count(prompt: str) -> None:
    counts = parse_intent(prompt).device_requirements

    assert counts.get("Router") == 1
    assert counts.get("Switch") == 4


def test_unseparated_trailing_form_is_ambiguous_and_reads_leading_first() -> None:
    """`router 1 switch 4` can be read either way; the leading form wins.

    Pinned so the choice is deliberate rather than accidental. Adding a
    separator (`router 1 ve switch 4`) resolves it unambiguously.
    """
    counts = parse_intent("router 1 switch 4 qur").device_requirements

    assert counts.get("Switch") == 1


@pytest.mark.parametrize(
    "prompt",
    ["sebeke haqqinda melumat ver", "packet tracer nedir", "salam"],
)
def test_a_prompt_with_no_topology_signal_is_refused(prompt: str) -> None:
    """Inventing a lab is worse than refusing: the user never sees the misread."""
    plan = parse_intent(prompt)

    assert any("does not describe a topology" in gap for gap in plan.blocking_gaps)


@pytest.mark.parametrize(
    "prompt",
    [
        "campus sebekesi qur",
        "1 router 1 switch ve 3 komputer qur",
        "wireless ap qur",
        "6 sobeli kampus sebekesi qur",
    ],
)
def test_real_requests_are_not_caught_by_the_no_signal_check(prompt: str) -> None:
    plan = parse_intent(prompt)

    assert not any("does not describe a topology" in gap for gap in plan.blocking_gaps)


def test_english_plurals_are_counted_for_every_device_type() -> None:
    """Plurals were listed by hand, so the table disagreed with itself.

    `PC` carried `computers` and `pcs`; `Switch` and `Router` had no English
    plural at all. The switches vanished silently and the user got a topology
    without them -- the worst kind of parse failure, because it looks like it
    worked.
    """
    counts = parse_intent("2 switches 1 router 4 computers").device_counts

    assert counts == {"Router": 1, "Switch": 2, "PC": 4}


def test_spelled_out_counts_are_understood() -> None:
    """Every downstream extractor matches digits, so words parsed as nothing."""
    assert parse_intent("bir router iki switch uc komputer qur").device_counts == {
        "Router": 1,
        "Switch": 2,
        "PC": 3,
    }
    assert parse_intent("three routers two switches ten computers").device_counts == {
        "Router": 3,
        "Switch": 2,
        "PC": 10,
    }


def test_prepositional_on_is_never_read_as_a_count() -> None:
    """`on` is ten in Azerbaijani and a preposition in English.

    It sits directly in front of the words that identify a device, so no
    lookahead separates the readings. Treating it as a count silently ordered
    ten routers; it is excluded from the number-word table for that reason.
    """
    assert parse_intent("1 router 1 switch 3 komputer qur dhcp on router").device_counts == {
        "Router": 1,
        "Switch": 1,
        "PC": 3,
    }
    assert parse_intent("enable telnet on switch 2 switch 1 router 4 pc").device_counts == {
        "Router": 1,
        "Switch": 2,
        "PC": 4,
    }


def test_komutator_is_a_switch() -> None:
    assert parse_intent("5 kompyuter 1 komutator qur").device_counts == {"Switch": 1, "PC": 5}


def test_a_device_named_without_a_number_means_one() -> None:
    """`router switch pc qur` was refused as "does not describe a topology".

    The message was contradicted by the prompt itself, which names three
    devices. Only the count was missing.
    """
    assert parse_intent("router switch pc qur").device_counts == {
        "Router": 1,
        "Switch": 1,
        "PC": 1,
    }


def test_counted_and_bare_devices_mix_correctly() -> None:
    """The fallback is per device type, so it must not flatten counted ones."""
    assert parse_intent("2 switch ve router qur").device_counts == {"Router": 1, "Switch": 2}


def test_a_longer_device_name_is_not_also_counted_as_the_shorter_one() -> None:
    """`wireless router` contains `router`, and the bare scan credited both."""
    assert parse_intent("1 wireless router 2 laptop qur").device_counts == {
        "WirelessRouter": 1,
        "Laptop": 2,
    }


def test_a_prompt_with_no_devices_still_refuses() -> None:
    assert parse_intent("sebeke haqqinda melumat ver").device_counts == {}


def test_hosts_with_nothing_to_connect_to_get_a_switch() -> None:
    """Ten PCs and no switch became ten standalone targets, and generation
    refused when the donor ran out of spare PCs -- reported as a donor limit
    though the real problem was a topology with nothing to plug into."""
    plan = parse_intent("bir sebeke lazimdir 10 kompyuter ucun")

    assert plan.device_requirements == {"PC": 10, "Switch": 1}
    assert any("nothing for them to connect to" in note for note in plan.assumptions_used)


def test_no_switch_is_invented_when_one_was_asked_for() -> None:
    plan = parse_intent("1 switch ve 5 komputer qur")

    assert plan.device_requirements == {"Switch": 1, "PC": 5}
    assert not any("nothing for them to connect to" in note for note in plan.assumptions_used)


def test_a_wireless_router_counts_as_something_to_connect_to() -> None:
    plan = parse_intent("1 wireless router 2 laptop qur")

    assert "Switch" not in plan.device_requirements
