from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from packet_tracer_env import get_packet_tracer_compatibility_donor  # noqa: E402
from generate_pkt import PlanningError, _build_donor_prune_plan, build_prompt_blueprint, prepare_generation_plan  # noqa: E402
from intent_parser import parse_intent  # noqa: E402


def test_prepare_generation_plan_keeps_blocking_gap_for_missing_vlan_assignment() -> None:
    plan = prepare_generation_plan(
        parse_intent(
            "3 dene switch ve 6 komputer ve 1 router "
            "vlanlarda 10,20,30 "
            "switchlerin oz aralarinda ve routerle aralarinda gig portuna qosulsun "
            "komputerler ise fa portlarla qosulsun"
        )
    )
    assert "core_switch" == plan.topology_requirements["uplink_topology"]
    assert plan.blocking_gaps


def test_build_prompt_blueprint_synthesizes_core_switch_topology() -> None:
    if get_packet_tracer_compatibility_donor() is None:
        return
    blueprint, plan = build_prompt_blueprint(
        parse_intent(
            "3 dene switch ve 6 komputer ve 1 router "
            "vlanlarda 10,20,30 "
            "vlan 10 da 2 komputer vlan 20 de 2 komputer vlan 30 da 2 komputer "
            "switchlerin oz aralarinda ve routerle aralarinda gig portuna qosulsun "
            "komputerler ise fa portlarla qosulsun"
        )
    )
    devices = blueprint["devices"]
    switches = [device for device in devices if device["type"] == "Switch"]
    routers = [device for device in devices if device["type"] == "Router"]
    assert len(switches) == 3
    assert len(routers) == 1
    if get_packet_tracer_compatibility_donor() is not None:
        assert switches[0]["model"] == "2960-24TT"
    else:
        assert switches[0]["model"] == "3650-24PS"
    assert all(link["a"]["port"].startswith("GigabitEthernet") or link["b"]["port"].startswith("GigabitEthernet") for link in blueprint["links"][:3])
    host_links = [link for link in blueprint["links"] if link["a"]["dev"].startswith("PC")]
    assert host_links
    assert all(link["a"]["port"] == "FastEthernet0" for link in host_links)
    assert any(op["op"] == "set_trunk_port" for op in plan.switch_ops)
    assert any(op["op"] == "set_subinterface" for op in plan.router_ops)
    assert any(op["op"] == "set_access_port" for op in plan.switch_ops)


def test_build_prompt_blueprint_raises_on_incomplete_plan() -> None:
    try:
        build_prompt_blueprint(parse_intent("2 switch 4 komputer vlanlarda 10 20"))
    except PlanningError as exc:
        assert exc.plan.blocking_gaps
    else:
        raise AssertionError("Expected PlanningError for incomplete VLAN assignment")


def test_build_prompt_blueprint_department_prompt_uses_chain_archetype() -> None:
    if get_packet_tracer_compatibility_donor() is None:
        return
    blueprint, plan = build_prompt_blueprint(
        parse_intent(
            "6 şöbəli şəbəkə qur, hər şöbədə 1 switch, 1 AP, 1 printer, 2 PC, 2 tablet olsun, "
            "router-on-a-stick olsun, DHCP routerdən verilsin, management VLAN və telnet olsun"
        )
    )
    assert blueprint["topology_archetype"] == "chain"
    topology_plan = blueprint["topology_plan"]
    assert topology_plan["topology_archetype"] == "chain"
    assert len([device for device in blueprint["devices"] if device["type"] == "Switch"]) == 6
    assert len([device for device in blueprint["devices"] if device["type"] == "LightWeightAccessPoint"]) == 6
    tablet_links = [link for link in blueprint["links"] if "TAB" in str(link["a"]["dev"]) or "TAB" in str(link["b"]["dev"])]
    assert not tablet_links
    assert any("wireless clients" in assumption.lower() for assumption in plan.assumptions_used)
    assert any(op["op"] == "set_trunk_port" for op in plan.switch_ops)
    assert any(op["op"] == "set_subinterface" for op in plan.router_ops)


def test_build_donor_prune_plan_for_department_prompt() -> None:
    if get_packet_tracer_compatibility_donor() is None:
        return
    blueprint, plan = build_prompt_blueprint(
        parse_intent(
            "6 şöbəli şəbəkə qur, hər şöbədə 1 switch, 1 AP, 1 printer, 2 PC, 2 tablet olsun, "
            "router-on-a-stick olsun, DHCP routerdən verilsin, management VLAN və telnet olsun"
        )
    )
    adapted, donor_plan = _build_donor_prune_plan(plan, blueprint)
    assert donor_plan.compat_donor
    assert donor_plan.layout_strategy == "donor_preserve_park_unused"
    assert donor_plan.pruned_devices
    assert any(op["op"] == "rename_device" for op in adapted.edit_operations)
    assert any(op["op"] == "reflow_layout" for op in adapted.edit_operations)
    assert not any(op["op"] == "prune_device" for op in adapted.edit_operations)
