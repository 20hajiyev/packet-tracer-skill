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

from intent_parser import NATURAL_DEVICE_ALIASES, parse_intent  # noqa: E402


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


def test_a_model_number_is_not_a_device_count() -> None:
    """`2911 router qur` asked for two thousand nine hundred and eleven routers.

    Cisco model designations sit exactly where a count goes, and the planner
    spent minutes on the request before failing.
    """
    assert parse_intent("2911 router qur").device_counts == {"Router": 1}
    assert parse_intent("2911 router ve 2960 switch ile 3 pc qur").device_counts == {
        "Router": 1,
        "Switch": 1,
        "PC": 3,
    }


def test_real_counts_are_still_read() -> None:
    """The guard must not swallow ordinary numbers."""
    assert parse_intent("100 komputer 1 switch qur").device_counts == {"Switch": 1, "PC": 100}
    assert parse_intent("2 switch 1 router 4 komputer qur").device_counts == {
        "Router": 1,
        "Switch": 2,
        "PC": 4,
    }


def test_requested_models_are_recorded() -> None:
    assert parse_intent("2911 router qur").requested_models == ["2911"]
    assert parse_intent("2960-24TT switch qur").requested_models == ["2960-24TT"]
    assert parse_intent("1 ISR4331 router qur").requested_models == ["ISR4331"]
    assert parse_intent("1 router 1 switch 3 pc qur").requested_models == []


def test_an_unavailable_model_is_reported_not_silently_swapped() -> None:
    """Device models come from whichever donor supplied the prototype.

    The local donors carry PT8200 and ISR4331, so asking for a 2911 -- the model
    most CCNA material uses -- quietly produced something else.
    """
    from generate_pkt import _note_model_substitutions

    plan = parse_intent("1 router 2911 1 switch 3 pc qur")
    _note_model_substitutions(
        plan,
        [{"name": "R1", "type": "Router", "model": "PT8200"}],
    )

    assert any("2911" in note and "not available" in note for note in plan.assumptions_used)


def test_a_satisfied_model_produces_no_note() -> None:
    from generate_pkt import _note_model_substitutions

    plan = parse_intent("1 ISR4331 router qur")
    _note_model_substitutions(plan, [{"name": "R1", "type": "Router", "model": "ISR4331"}])

    assert not any("not available" in note for note in plan.assumptions_used)


def test_a_large_but_ordinary_count_is_not_capped() -> None:
    """The model guard used a ceiling of 200, which silently turned
    "500 komputer" into a single PC: the number was rejected as a count and the
    bare-name fallback then supplied 1. Enterprise labs really do have hundreds
    of hosts."""
    assert parse_intent("500 komputer 20 switch 4 router qur").device_counts == {
        "Router": 4,
        "Switch": 20,
        "PC": 500,
    }
    assert parse_intent("1000 pc 40 switch qur").device_counts == {"Switch": 40, "PC": 1000}
    # And a model designation is still not a count.
    assert parse_intent("2911 router qur").device_counts == {"Router": 1}


def test_a_group_noun_other_than_department_repeats_its_devices() -> None:
    """The count pattern and the per-group pattern carried separate word lists,
    so a noun in one and not the other half worked in silence. `3 mertebe, her
    mertebede 6 komputer` gave six PCs on one switch -- neither list had heard
    of a floor -- while the same prompt with `sobe` gave eighteen on three."""
    for prompt in (
        "3 mertebe, her mertebede 6 komputer qur",
        "3 mərtəbə, hər mərtəbədə 6 komputer qur",
        "3 sobe, her sobede 6 komputer qur",
    ):
        assert parse_intent(prompt).device_requirements == {"PC": 18, "Switch": 3}, prompt

    assert parse_intent("4 ofis, her ofisde 5 komputer 1 printer qur").device_requirements == {
        "PC": 20,
        "Printer": 4,
        "Switch": 4,
    }


def test_english_per_group_counts_parse_in_both_orders() -> None:
    """`6 computers each` names the count after the device, which the forward
    pattern could not read; the plural `computers` also broke the word boundary
    the forward pattern relied on."""
    assert parse_intent("3 department, 6 computers each qur").device_requirements == {
        "PC": 18,
        "Switch": 3,
    }
    assert parse_intent("3 floors, each floor 4 computers qur").device_requirements == {
        "PC": 12,
        "Switch": 3,
    }


def test_a_bare_plural_still_names_a_device() -> None:
    """`switchler ve routerler qur` parsed as an empty plan. The no-number
    fallback masks longer aliases that contain a shorter one, to stop `wireless
    router` crediting a plain router -- but it also masked a type's own longer
    aliases, deleting the only word the scan had."""
    assert parse_intent("switchler ve routerler qur").device_requirements == {
        "Router": 1,
        "Switch": 1,
    }
    assert parse_intent("serverler ve komputerler qur").device_requirements["Server"] == 1

    # The guard the masking exists for still holds: no plain Router is credited.
    assert parse_intent("1 wireless router 2 laptop qur").device_requirements == {
        "WirelessRouter": 1,
        "Laptop": 2,
    }


def test_a_donor_device_type_normalises_to_a_kind_a_prompt_can_name() -> None:
    """The contract that `Cable Modem` broke: whatever a donor's XML calls a
    device, the kind it normalises to has to be one a prompt can ask for.

    Asserting instead that every alias key normalises to itself would prove
    nothing -- `normalize_device_type` passes unknown names straight through, so
    the broken `Cable Modem` key satisfied that too. The donor's own spelling is
    what has to line up.
    """
    from sample_catalog import normalize_device_type

    donor_spellings = {
        "CableModem": "CableModem",
        "DslModem": "DslModem",
        "CentralOfficeServer": "CentralOfficeServer",
        "NetworkController": "NetworkController",
        "PLC": "PLC",
        "Pc": "PC",
        "MCUComponent": "IoT",
        "Pda": "Tablet",
        "AccessPoint": "LightWeightAccessPoint",
    }
    for donor_type, expected_kind in donor_spellings.items():
        kind = normalize_device_type(donor_type)
        assert kind == expected_kind, f"{donor_type!r} normalised to {kind!r}"
        assert kind in NATURAL_DEVICE_ALIASES, (
            f"a donor carries {donor_type!r}, which normalises to {kind!r}, and no prompt can name it"
        )


def test_the_donor_kinds_that_had_no_alias_can_now_be_asked_for() -> None:
    """Each of these is present in the local donor pool and had no alias, so a
    prompt naming one produced a plan without it."""
    for prompt, kind in (
        ("1 cable modem qur", "CableModem"),
        ("1 dsl modem qur", "DslModem"),
        ("1 central office server qur", "CentralOfficeServer"),
        ("1 network controller qur", "NetworkController"),
        ("2 plc qur", "PLC"),
        ("1 cyber observer qur", "CyberObserver"),
        ("1 data historian qur", "DataHistorian"),
    ):
        assert kind in parse_intent(prompt).device_requirements, prompt

    # `meraki` alone is the security appliance; only `meraki server` is the
    # server. The counted scan credited both until it masked longer aliases the
    # way the no-number scan already did.
    assert parse_intent("1 meraki server qur").device_requirements == {"MerakiServer": 1}
    assert parse_intent("1 meraki qur").device_requirements == {"SecurityAppliance": 1}
