"""`her ofisde N komputer` means N in each office, whichever way you count them.

Two spellings of the same request produced different labs. `2 ofis, her ofisde
1 switch ve 4 komputer` built two offices with four PCs each. `iki ofis, her
ofisde 1 switch ve 4 komputer` built one office with four, because the group
extractor matches `\\d+` and `iki` was never turned into a digit: the
spelled-number rewrite only fires when a *device* word follows, and `ofis` is a
group noun.

The same request also lost its PCs when it named a router first. The per-group
segment ended at the word `router`, so `her ofisde 1 router 1 switch 4
komputer` left a segment of `1 ` and the four PCs were counted once for the
whole lab rather than once per office. A router is a device in that sentence,
not a capability.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from intent_parser import parse_intent  # noqa: E402


def _counts(prompt: str) -> dict[str, int]:
    return dict(parse_intent(prompt).device_requirements)


def test_a_spelled_group_count_matches_the_digit_spelling() -> None:
    digits = _counts("2 ofis, her ofisde 1 switch ve 4 komputer")
    words = _counts("iki ofis, her ofisde 1 switch ve 4 komputer")
    assert digits == words
    assert words["PC"] == 8
    assert words["Switch"] == 2


def test_spelled_group_counts_work_past_two() -> None:
    counts = _counts("uc filial, her filialda 1 switch ve 3 komputer")
    assert counts["Switch"] == 3
    assert counts["PC"] == 9


def test_a_router_in_the_per_group_list_does_not_truncate_it() -> None:
    counts = _counts("iki ofis arasinda serial WAN, her ofisde 1 router 1 switch 4 komputer")
    assert counts["Switch"] == 2
    assert counts["PC"] == 8


def test_the_segment_still_ends_at_a_capability_word() -> None:
    """`dhcp ile` describes the lab, not one office, so it must end the segment."""
    counts = _counts("her ofisde 4 komputer, dhcp ile, 2 ofis")
    assert counts["PC"] == 8


def test_a_preposition_is_still_not_a_count() -> None:
    """The reason the spelled-number rewrite is narrow in the first place."""
    counts = _counts("dhcp on router")
    assert counts.get("Router", 0) == 1


def test_plain_totals_are_unchanged() -> None:
    counts = _counts("2 router 2 switch 8 komputer")
    assert counts == {"Router": 2, "Switch": 2, "PC": 8}
