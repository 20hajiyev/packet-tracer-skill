"""Regression tests for the donor-prune grouping and wiring contract.

These pin three defects that together rejected every donor for every prompt.
Each one had the same shape: two independent models of the same concept that
disagreed, or a planner assumption promoted into a hard requirement.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_pkt import (  # noqa: E402
    DEFAULTED_LINK_WIRING_ASSUMPTIONS,
    _fallback_group_member_type,
    _link_wiring_was_defaulted,
    _target_groups_from_blueprint,
)
from intent_parser import IntentPlan  # noqa: E402


def _plan(**overrides: object) -> IntentPlan:
    plan = IntentPlan(goal="generate", prompt="test")
    for key, value in overrides.items():
        setattr(plan, key, value)
    return plan


def _blueprint() -> dict[str, object]:
    return {
        "devices": [
            {"name": "R1", "type": "Router"},
            {"name": "SW1", "type": "Switch"},
            {"name": "PC1", "type": "PC"},
            {"name": "PC2", "type": "PC"},
            {"name": "PC3", "type": "PC"},
        ],
        "links": [
            {"a": {"dev": "SW1", "port": "GigabitEthernet0/1"}, "b": {"dev": "R1", "port": "GigabitEthernet0/0"}},
            {"a": {"dev": "PC1", "port": "FastEthernet0"}, "b": {"dev": "SW1", "port": "FastEthernet0/1"}},
            {"a": {"dev": "PC2", "port": "FastEthernet0"}, "b": {"dev": "SW1", "port": "FastEthernet0/2"}},
            {"a": {"dev": "PC3", "port": "FastEthernet0"}, "b": {"dev": "SW1", "port": "FastEthernet0/3"}},
        ],
    }


def test_router_is_not_a_target_group_member() -> None:
    """Routers are matched separately against the donor router.

    Counting a router as a switch-group member too made every target group
    demand a router that no donor group can supply, because
    `_collect_donor_groups` excludes routers by design. Every candidate donor
    was then rejected with
    `donor group Switch0 has only 0 Router device(s); requested 1 for SW1`.
    """
    groups = _target_groups_from_blueprint(_plan(), _blueprint())

    assert len(groups) == 1
    members = groups[0]["members"]
    member_types = {str(member["type"]) for member in members}

    assert "Router" not in member_types
    assert member_types == {"PC"}
    assert len(members) == 3


def test_target_and_donor_grouping_use_the_same_membership_predicate() -> None:
    """The two grouping models must not drift apart again."""
    groups = _target_groups_from_blueprint(_plan(), _blueprint())
    for member in groups[0]["members"]:
        assert _fallback_group_member_type(str(member["type"]))

    assert _fallback_group_member_type("PC")
    assert _fallback_group_member_type("Server")
    assert not _fallback_group_member_type("Router")
    assert not _fallback_group_member_type("Switch")


def test_hosts_without_an_explicit_switch_link_still_get_grouped() -> None:
    blueprint = _blueprint()
    blueprint["links"] = [blueprint["links"][0]]  # only the router uplink

    groups = _target_groups_from_blueprint(_plan(), blueprint)

    assert len(groups[0]["members"]) == 3
    assert {str(member["type"]) for member in groups[0]["members"]} == {"PC"}


def test_defaulted_wiring_is_detected() -> None:
    """A defaulted port is a preference, not a requirement."""
    for assumption in DEFAULTED_LINK_WIRING_ASSUMPTIONS:
        assert _link_wiring_was_defaulted(_plan(assumptions_used=[assumption]))


def test_explicit_wiring_is_not_treated_as_defaulted() -> None:
    assert not _link_wiring_was_defaulted(_plan(assumptions_used=[]))
    assert not _link_wiring_was_defaulted(
        _plan(assumptions_used=["Generated default VLAN IDs in 10-step increments for each department."])
    )


def test_department_groups_path_also_excludes_routers() -> None:
    plan = _plan(department_groups=[{"name": "Finance", "devices": {"PC": 2}}])
    blueprint = {
        "devices": [
            {"name": "R1", "type": "Router", "group": "Finance"},
            {"name": "SW1", "type": "Switch", "group": "Finance"},
            {"name": "PC1", "type": "PC", "group": "Finance"},
            {"name": "PC2", "type": "PC", "group": "Finance"},
        ],
        "links": [],
    }

    groups = _target_groups_from_blueprint(plan, blueprint)

    assert len(groups) == 1
    assert {str(member["type"]) for member in groups[0]["members"]} == {"PC"}


def test_default_spare_strategy_is_prune(monkeypatch: object) -> None:
    """Leftover donor devices are deleted, not hidden offscreen.

    Parking renamed them `UNUSED-*` and moved them to x=9000, so a five-device
    request produced a twenty-device, 282 KB file. Pruning was verified against a
    real Packet Tracer open (6 devices, 73 KB, opened in 17s) before becoming the
    default; `park` stays available as an escape hatch.
    """
    from generate_pkt import DEFAULT_SPARE_STRATEGY, SPARE_STRATEGIES, _spare_strategy

    assert DEFAULT_SPARE_STRATEGY == "prune"
    assert set(SPARE_STRATEGIES) == {"park", "prune"}
    assert _spare_strategy() == "prune"


def test_spare_strategy_can_be_overridden(monkeypatch) -> None:
    from generate_pkt import DEFAULT_SPARE_STRATEGY, _spare_strategy

    monkeypatch.setenv("PACKET_TRACER_SPARE_STRATEGY", "park")
    assert _spare_strategy() == "park"

    monkeypatch.setenv("PACKET_TRACER_SPARE_STRATEGY", "  PRUNE  ")
    assert _spare_strategy() == "prune"

    monkeypatch.setenv("PACKET_TRACER_SPARE_STRATEGY", "nonsense")
    assert _spare_strategy() == DEFAULT_SPARE_STRATEGY
