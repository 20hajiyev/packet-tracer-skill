"""Tests for the donor version compatibility ladder.

Background: Packet Tracer `<VERSION>` strings carry a build field that changes
on every point release and re-save. Requiring an exact build match rejected the
entire bundled Cisco corpus — all 292 sample saves shipped with Packet Tracer
9.0.0 fail an exact match against `9.0.0.0810`. These tests pin the tier
classification so that regression cannot return.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from packet_tracer_env import (  # noqa: E402
    COMPATIBILITY_TIERS,
    DEFAULT_DONOR_POLICY,
    donor_compatibility,
    donor_tier_is_accepted,
    get_donor_policy,
)

TARGET = "9.0.0.0810"


@pytest.mark.parametrize(
    "donor_version,expected_tier",
    [
        ("9.0.0.0810", "exact"),
        # Real build strings observed in the Packet Tracer 9.0.0 sample corpus.
        ("9.0.0.0000", "same_minor"),
        ("9.0.0.4178", "same_minor"),
        ("9.0.0.0112", "same_minor"),
        ("9.0.0.0172", "same_minor"),
        ("9.1.0.0000", "same_major"),
        ("8.2.1.4208", "upgradeable"),
        ("7.1.0.0000", "upgradeable"),
        ("6.0.0.0002", "upgradeable"),
        ("5.3.0.0011", "incompatible"),
        ("5.2.0.0068", "incompatible"),
        ("", "incompatible"),
        (None, "incompatible"),
        ("not-a-version", "incompatible"),
    ],
)
def test_tier_classification(donor_version: str | None, expected_tier: str) -> None:
    assert donor_compatibility(donor_version, TARGET) == expected_tier


def test_default_policy_requires_the_running_build() -> None:
    """Measured, not assumed: a generation base must carry the running build.

    `same_minor` was the default until a real open test contradicted it. Packet
    Tracer rejects a file built from a `9.0.0.0000` sample with "This file
    requires Cisco Packet Tracer version 9.0.0.0000. Your current version is
    9.0.0.0810", and relabelling the output does not help — the donor's
    structures are never migrated. None of the 292 bundled samples carries the
    running build; the user's own saves do.
    """
    assert DEFAULT_DONOR_POLICY == "exact"
    assert donor_tier_is_accepted(donor_compatibility("9.0.0.0810", TARGET), DEFAULT_DONOR_POLICY)
    for donor_version in ("9.0.0.0000", "9.0.0.4178"):
        tier = donor_compatibility(donor_version, TARGET)
        assert tier == "same_minor"
        assert not donor_tier_is_accepted(tier, DEFAULT_DONOR_POLICY)


def test_looser_policies_remain_available_for_inspection() -> None:
    """The ladder still classifies; only the default for *generation* is strict."""
    for donor_version in ("9.0.0.0000", "9.0.0.4178"):
        assert donor_tier_is_accepted(donor_compatibility(donor_version, TARGET), "same_minor")


def test_default_policy_still_rejects_legacy_and_cross_minor_donors() -> None:
    for donor_version in ("5.3.0.0011", "7.1.0.0000", "8.2.1.4208", "9.1.0.0000"):
        tier = donor_compatibility(donor_version, TARGET)
        assert not donor_tier_is_accepted(tier, DEFAULT_DONOR_POLICY)


def test_upgradeable_policy_widens_the_pool_without_admitting_five_x() -> None:
    assert donor_tier_is_accepted(donor_compatibility("7.1.0.0000", TARGET), "upgradeable")
    assert donor_tier_is_accepted(donor_compatibility("6.0.0.0002", TARGET), "upgradeable")
    assert not donor_tier_is_accepted(donor_compatibility("5.3.0.0011", TARGET), "upgradeable")


def test_exact_policy_restores_the_old_strict_behaviour() -> None:
    assert donor_tier_is_accepted(donor_compatibility(TARGET, TARGET), "exact")
    assert not donor_tier_is_accepted(donor_compatibility("9.0.0.0000", TARGET), "exact")


def test_incompatible_is_never_accepted_at_any_policy() -> None:
    for policy in COMPATIBILITY_TIERS:
        assert not donor_tier_is_accepted("incompatible", policy)


def test_policy_comes_from_the_environment(monkeypatch) -> None:
    monkeypatch.setenv("PACKET_TRACER_DONOR_POLICY", "upgradeable")
    assert get_donor_policy() == "upgradeable"

    monkeypatch.setenv("PACKET_TRACER_DONOR_POLICY", "  EXACT  ")
    assert get_donor_policy() == "exact"


def test_unknown_policy_falls_back_to_the_default(monkeypatch) -> None:
    monkeypatch.setenv("PACKET_TRACER_DONOR_POLICY", "anything-goes")
    assert get_donor_policy() == DEFAULT_DONOR_POLICY

    monkeypatch.delenv("PACKET_TRACER_DONOR_POLICY", raising=False)
    assert get_donor_policy() == DEFAULT_DONOR_POLICY


def test_tiers_are_ordered_strictest_first() -> None:
    assert COMPATIBILITY_TIERS[0] == "exact"
    assert COMPATIBILITY_TIERS[-1] == "incompatible"
    # A stricter tier must be accepted by every looser policy.
    for policy_index, policy in enumerate(COMPATIBILITY_TIERS[:-1]):
        for tier in COMPATIBILITY_TIERS[: policy_index + 1]:
            assert donor_tier_is_accepted(tier, policy)
