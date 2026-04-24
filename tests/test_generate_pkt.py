from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import generate_pkt as generate_pkt_module  # noqa: E402
from packet_tracer_env import get_packet_tracer_compatibility_donor  # noqa: E402
from generate_pkt import (  # noqa: E402
    DonorArchetypePlan,
    PlanningError,
    _augment_coverage_gap_actions,
    _apply_safe_open_preview,
    _apply_safe_open_profile,
    _build_donor_prune_plan,
    _build_donor_prune_plan_for_donor,
    _best_rejected_donor_summary,
    _candidate_acceptance_penalty,
    _candidate_to_dict,
    _donor_graph_fit_summary,
    _filter_candidates_for_blueprint,
    _evaluate_donor_prune_candidates,
    _collect_donor_groups,
    _preferred_donor_archetypes_for_plan,
    _scenario_acceptance_summary,
    _scenario_matrix_table,
    _scenario_matrix_row,
    _scenario_generate_decision,
    _selected_donor_summary,
    _summarize_candidate_pool,
    compare_scenarios,
    parity_report,
    build_prompt_blueprint,
    edit_from_prompt,
    inventory_pkt,
    prepare_generation_plan,
)
from intent_parser import parse_intent  # noqa: E402
from sample_catalog import SampleCandidate, SampleDescriptor  # noqa: E402


def _make_device(name: str, device_type: str, model: str = "") -> ET.Element:
    device = ET.Element("DEVICE")
    engine = ET.SubElement(device, "ENGINE")
    dtype = ET.SubElement(engine, "TYPE")
    dtype.text = device_type
    if model:
        dtype.set("model", model)
    ET.SubElement(engine, "NAME").text = name
    return device


def _make_link(from_index: int, to_index: int, from_port: str, to_port: str, media: str = "eStraightThrough") -> ET.Element:
    link = ET.Element("LINK")
    cable = ET.SubElement(link, "CABLE")
    ET.SubElement(cable, "FROM").text = str(from_index)
    ET.SubElement(cable, "TO").text = str(to_index)
    ET.SubElement(cable, "PORT").text = from_port
    ET.SubElement(cable, "PORT").text = to_port
    ET.SubElement(cable, "TYPE").text = media
    return link


def _make_safe_open_root() -> ET.Element:
    donor_root = ET.Element("PACKETTRACER5")
    devices = ET.SubElement(donor_root, "DEVICES")

    switch = _make_device("SW1", "Switch", "2960-24TT")
    switch_engine = switch.find("./ENGINE")
    assert switch_engine is not None
    ET.SubElement(switch_engine, "SAVE_REF_ID").text = "save-ref-id:sw1"
    switch_workspace = ET.SubElement(switch, "WORKSPACE")
    switch_logical = ET.SubElement(switch_workspace, "LOGICAL")
    ET.SubElement(switch_logical, "X").text = "100"
    ET.SubElement(switch_logical, "Y").text = "100"
    ET.SubElement(switch_logical, "MEM_ADDR").text = "mem-sw1"
    ET.SubElement(switch_workspace, "PHYSICAL").text = "Intercity,Home City,Corporate Office,Main Wiring Closet,Rack,SW1"
    devices.append(switch)

    router = _make_device("R1", "Router", "ISR4331")
    router_engine = router.find("./ENGINE")
    assert router_engine is not None
    ET.SubElement(router_engine, "SAVE_REF_ID").text = "save-ref-id:r1"
    router_workspace = ET.SubElement(router, "WORKSPACE")
    router_logical = ET.SubElement(router_workspace, "LOGICAL")
    ET.SubElement(router_logical, "X").text = "200"
    ET.SubElement(router_logical, "Y").text = "100"
    ET.SubElement(router_logical, "MEM_ADDR").text = "mem-r1"
    ET.SubElement(router_workspace, "PHYSICAL").text = "Intercity,Home City,Corporate Office,Main Wiring Closet,Rack,R1"
    devices.append(router)

    links = ET.SubElement(donor_root, "LINKS")
    cable = ET.SubElement(ET.SubElement(links, "LINK"), "CABLE")
    ET.SubElement(cable, "FROM").text = "save-ref-id:sw1"
    ET.SubElement(cable, "TO").text = "save-ref-id:r1"
    ET.SubElement(cable, "PORT").text = "GigabitEthernet0/1"
    ET.SubElement(cable, "PORT").text = "GigabitEthernet0/0/0"
    ET.SubElement(cable, "TYPE").text = "eStraightThrough"
    ET.SubElement(cable, "FROM_DEVICE_MEM_ADDR").text = "mem-sw1"
    ET.SubElement(cable, "TO_DEVICE_MEM_ADDR").text = "mem-r1"
    ET.SubElement(cable, "FROM_PORT_MEM_ADDR").text = "port-sw1-gi1"
    ET.SubElement(cable, "TO_PORT_MEM_ADDR").text = "port-r1-gi0"
    ET.SubElement(cable, "FUNCTIONAL").text = "true"
    ET.SubElement(cable, "GEO_VIEW_COLOR").text = "#6ba72e"
    ET.SubElement(cable, "IS_MANAGED_IN_RACK_VIEW").text = "false"
    return donor_root


def _make_safe_open_plan():
    plan = parse_intent("set SW1 vlan 10 name Finance")
    plan.edit_operations = [
        {"op": "rename_device", "device": "SW1", "new_name": "DIST-SW1"},
        {"op": "reflow_layout", "device": "DIST-SW1", "x": 220, "y": 280},
        {"op": "remove_link", "a": {"dev": "DIST-SW1"}, "b": {"dev": "R1"}},
        {
            "op": "set_link",
            "a": {"dev": "DIST-SW1", "port": "GigabitEthernet0/1"},
            "b": {"dev": "R1", "port": "GigabitEthernet0/0/0"},
            "media": "straight-through",
        },
    ]
    plan.switch_ops = [{"op": "set_vlan", "device": "DIST-SW1", "vlan": 10, "name": "Finance"}]
    plan.router_ops = [
        {
            "op": "set_subinterface",
            "device": "R1",
            "subinterface": "GigabitEthernet0/0/0.10",
            "vlan": 10,
            "ip": "192.168.10.1",
            "prefix": 24,
        }
    ]
    return plan


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


def test_edit_from_prompt_forces_edit_mode_and_pkt_path(tmp_path: Path) -> None:
    source = tmp_path / "source.pkt"
    source.write_bytes(b"pkt")
    output = tmp_path / "edited.pkt"
    xml_out = tmp_path / "edited.xml"
    captured: dict[str, object] = {}
    original_edit = generate_pkt_module.edit_pkt_file
    try:
        def fake_edit(pkt_path, plan, output_path, xml_out_path=None):
            captured["pkt_path"] = str(pkt_path)
            captured["goal"] = plan.goal
            captured["plan_pkt_path"] = plan.pkt_path
            captured["output"] = str(output_path)
            captured["xml_out"] = str(xml_out_path) if xml_out_path is not None else None
            Path(output_path).write_bytes(b"ok")
            if xml_out_path is not None:
                Path(xml_out_path).write_text("<xml />", encoding="utf-8")
            return Path(output_path)

        generate_pkt_module.edit_pkt_file = fake_edit
        edit_from_prompt(source, "set AP1 ssid FIN_WIFI security wpa2-psk passphrase fin12345 channel 6", output, xml_out)
    finally:
        generate_pkt_module.edit_pkt_file = original_edit

    assert captured["pkt_path"] == str(source)
    assert captured["goal"] == "edit"
    assert captured["plan_pkt_path"] == str(source)
    assert captured["output"] == str(output)
    assert captured["xml_out"] == str(xml_out)
    assert output.exists()
    assert xml_out.exists()


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
    assert switches[0]["model"] == "2960-24TT"
    assert all(
        link["a"]["port"].startswith("GigabitEthernet") or link["b"]["port"].startswith("GigabitEthernet")
        for link in blueprint["links"][:3]
    )
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
        assert exc.plan.blueprint_plan
    else:
        raise AssertionError("Expected PlanningError for incomplete VLAN assignment")


def test_generate_from_prompt_writes_blueprint_on_refusal(tmp_path: Path, monkeypatch) -> None:
    plan = parse_intent("campus sebekesi qur")
    plan.blueprint_plan = {"requested_devices": [{"name": "R1", "type": "Router"}]}

    def fake_build_prompt_blueprint(raw_plan, donor_roots=None):
        raise PlanningError("blocked", plan)

    monkeypatch.setattr(generate_pkt_module, "build_prompt_blueprint", fake_build_prompt_blueprint)

    output = tmp_path / "refused.pkt"
    blueprint_out = tmp_path / "refused_blueprint.json"

    try:
        generate_pkt_module.generate_from_prompt(
            "campus sebekesi qur",
            output,
            blueprint_out_path=blueprint_out,
        )
    except PlanningError as exc:
        assert exc.plan.blueprint_plan == plan.blueprint_plan
    else:
        raise AssertionError("Expected PlanningError")

    assert not output.exists()
    assert blueprint_out.exists()
    assert json.loads(blueprint_out.read_text(encoding="utf-8")) == plan.blueprint_plan


def test_generate_from_prompt_blocks_acceptance_gated_scenario_before_donor_apply(tmp_path: Path, monkeypatch) -> None:
    raw_plan = parse_intent("home iot sebekesi qur register qapi cihazlarini gatewaye qos")
    raw_plan.blueprint_plan = {"requested_devices": [{"name": "Home Gateway0", "type": "HomeGateway"}]}
    blueprint = {
        "topology_archetype": "home_router_edge",
        "preferred_donor_archetypes": ["IoT/home gateway"],
        "devices": [{"name": "Home Gateway0", "type": "HomeGateway"}],
        "links": [],
    }
    coverage_gap = {
        "unsupported_capabilities": [],
        "requires_manual_acceptance": ["iot_registration", "iot_control"],
        "scenario_generate_readiness": {
            "family": "home_iot",
            "status": "acceptance_gated",
            "critical_capabilities": ["iot_registration", "iot_control"],
            "missing_critical_capabilities": [],
            "reasons": ["critical capabilities remain acceptance-gated: iot_registration, iot_control"],
        },
        "recommended_next_actions": [],
    }

    monkeypatch.setattr(generate_pkt_module, "parse_intent", lambda prompt: raw_plan)
    monkeypatch.setattr(generate_pkt_module, "_resolve_remote_sources", lambda *args, **kwargs: ([], [], []))
    monkeypatch.setattr(generate_pkt_module, "build_prompt_blueprint", lambda raw_plan_arg, donor_roots=None: (blueprint, raw_plan))
    monkeypatch.setattr(generate_pkt_module, "_rank_generation_donors", lambda *args, **kwargs: ([], [], []))
    monkeypatch.setattr(
        generate_pkt_module,
        "_build_support_reports",
        lambda *args, **kwargs: ([], coverage_gap, raw_plan.blueprint_plan),
    )
    monkeypatch.setattr(
        generate_pkt_module,
        "inspect_packet_tracer_compatibility_donor",
        lambda: SimpleNamespace(blocking_reason=None),
    )

    output = tmp_path / "blocked_home_iot.pkt"
    blueprint_out = tmp_path / "blocked_home_iot_blueprint.json"

    try:
        generate_pkt_module.generate_from_prompt(
            "home iot sebekesi qur register qapi cihazlarini gatewaye qos",
            output,
            blueprint_out_path=blueprint_out,
        )
    except PlanningError as exc:
        assert any("acceptance-gated" in gap for gap in exc.plan.blocking_gaps)
    else:
        raise AssertionError("Expected PlanningError")

    assert not output.exists()
    assert blueprint_out.exists()


def test_generate_from_prompt_writes_pkt_on_safe_open_selection(tmp_path: Path, monkeypatch) -> None:
    raw_plan = parse_intent("set SW1 vlan 10 name Finance")
    blueprint = {
        "topology_archetype": "general",
        "topology_plan": {
            "topology_archetype": "general",
            "devices": [],
            "links": [],
            "layout": {},
            "port_map": {},
        },
        "config_plan": {
            "switch_ops": [],
            "router_ops": [],
            "server_ops": [],
            "wireless_ops": [],
            "end_device_ops": [],
            "management_ops": [],
            "assumptions_used": [],
        },
    }
    donor_path = tmp_path / "donor.pkt"
    donor_path.write_bytes(b"donor")
    donor_root = _make_safe_open_root()
    safe_plan = parse_intent("set SW1 vlan 10 name Finance")
    safe_plan.blocked_mutations = []
    safe_plan.unsafe_mutations_requested = []
    safe_plan.acceptance_stage_plan = []
    safe_plan.compatibility_profile = {"mode": "safe_open_strict_9_0"}

    monkeypatch.setattr(generate_pkt_module, "parse_intent", lambda prompt: raw_plan)
    monkeypatch.setattr(generate_pkt_module, "_resolve_remote_sources", lambda *args, **kwargs: ([], [], []))
    monkeypatch.setattr(generate_pkt_module, "build_prompt_blueprint", lambda raw_plan, donor_roots=None: (blueprint, raw_plan))
    monkeypatch.setattr(generate_pkt_module, "_rank_generation_donors", lambda *args, **kwargs: ([], [], []))
    monkeypatch.setattr(
        generate_pkt_module,
        "_build_support_reports",
        lambda *args, **kwargs: ([], {"unsupported_capabilities": [], "recommended_next_actions": []}, {"requested_devices": []}),
    )
    monkeypatch.setattr(
        generate_pkt_module,
        "inspect_packet_tracer_compatibility_donor",
        lambda: SimpleNamespace(blocking_reason=None),
    )
    monkeypatch.setattr(
        generate_pkt_module,
        "_build_donor_prune_plan",
        lambda prepared_plan, generated_blueprint, donor_roots=None: (
            raw_plan,
            DonorArchetypePlan(
                compat_donor=str(donor_path),
                donor_capacity={"devices": 2},
                kept_devices=["SW1", "R1"],
                pruned_devices=[],
                renamed_devices=[],
                mutation_groups=[],
                layout_strategy="preserve",
            ),
        ),
    )
    monkeypatch.setattr(
        generate_pkt_module,
        "_evaluate_donor_prune_candidates",
        lambda prepared_plan, generated_blueprint, donor_candidates: (
            (
                raw_plan,
                DonorArchetypePlan(
                    compat_donor=str(donor_path),
                    donor_capacity={"devices": 2},
                    kept_devices=["SW1", "R1"],
                    pruned_devices=[],
                    renamed_devices=[],
                    mutation_groups=[],
                    layout_strategy="preserve",
                    selection_reasons=["capability:vlan", "origin:cisco-local"],
                ),
                donor_root,
                SampleCandidate(
                    sample=SampleDescriptor(
                        path=str(donor_path),
                        relative_path="donor.pkt",
                        version="9.0.0.0810",
                        device_count=2,
                        link_count=1,
                        devices=[],
                        links=[],
                        capability_tags=["vlan"],
                        topology_tags=["general"],
                        preferred_roles=[],
                        origin="cisco-local",
                        apply_safety_level="acceptance-verified",
                    ),
                    capability_score=12,
                    topology_score=6,
                    total_score=18,
                    reasons=["capability:vlan"],
                ),
            ),
            [
                {
                    "relative_path": "donor.pkt",
                    "origin": "cisco-local",
                    "status": "selected",
                    "reasons": ["capability:vlan", "origin:cisco-local"],
                    "sample_archetypes": ["campus/core"],
                    "archetype_match_reasons": ["archetype:campus/core"],
                    "donor_graph_fit": {"layout_reuse_score": 21},
                    "donor_graph_summary": {
                        "required_pair_count": 1,
                        "reusable_pair_count": 1,
                        "missing_pair_count": 0,
                        "conflict_count": 0,
                        "reusable_pair_coverage": 100,
                        "layout_reuse_status": "strong",
                    },
                    "adjusted_total_score": 18,
                }
            ],
        ),
    )
    monkeypatch.setattr(generate_pkt_module, "decode_pkt_to_root", lambda path: donor_root)
    monkeypatch.setattr(generate_pkt_module, "_apply_safe_open_profile", lambda donor_root_arg, adapted_plan: (safe_plan, safe_plan))
    monkeypatch.setattr(generate_pkt_module, "apply_plan_operations", lambda donor_root_arg, safe_plan_arg: donor_root)
    monkeypatch.setattr(generate_pkt_module, "_sanitize_runtime_sections", lambda root: None)
    monkeypatch.setattr(generate_pkt_module, "_unexpected_workspace_issues", lambda donor_root_arg, root: [])
    monkeypatch.setattr(generate_pkt_module, "validate_donor_coherence", lambda donor_root_arg, root: None)
    monkeypatch.setattr(generate_pkt_module, "encode_pkt_modern", lambda xml_bytes: b"pkt")
    monkeypatch.setattr(generate_pkt_module, "_compat_donor_details", lambda: (donor_path, "9.0.0.0810"))

    output = tmp_path / "generated.pkt"
    xml_out = tmp_path / "generated.xml"
    blueprint_out = tmp_path / "generated_blueprint.json"

    generate_pkt_module.generate_from_prompt(
        "set SW1 vlan 10 name Finance",
        output,
        xml_out_path=xml_out,
        blueprint_out_path=blueprint_out,
    )

    assert output.exists()
    assert output.read_bytes() == b"pkt"
    assert xml_out.exists()
    assert blueprint_out.exists()


def test_inventory_pkt_can_write_json_artifact(tmp_path: Path, monkeypatch) -> None:
    pkt_path = tmp_path / "lab.pkt"
    out_path = tmp_path / "lab.inventory.json"
    pkt_path.write_bytes(b"pkt")
    donor_root = _make_safe_open_root()

    monkeypatch.setattr(generate_pkt_module, "decode_pkt_modern", lambda payload: ET.tostring(donor_root, encoding="utf-8"))
    monkeypatch.setattr(
        generate_pkt_module,
        "inspect_workspace_integrity",
        lambda root: SimpleNamespace(
            workspace_mode="logical",
            logical_status="ok",
            physical_status="ok",
            blocking_issues=[],
        ),
    )
    monkeypatch.setattr(
        generate_pkt_module,
        "inspect_packet_tracer_compatibility_donor",
        lambda: SimpleNamespace(
            resolved_path=None,
            donor_version=None,
            donor_source=None,
            target_version="9.0.0.0810",
            blocking_reason=None,
            candidate_paths=[],
        ),
    )
    monkeypatch.setattr(generate_pkt_module, "_link_schema_summary", lambda root: {"link_schema_mode": "unit-test"})

    inventory_pkt(pkt_path, inventory_out=out_path)

    assert out_path.exists()
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["workspace_validation"]["logical_status"] == "ok"
    assert payload["link_schema_mode"] == "unit-test"


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
    try:
        adapted, donor_plan = _build_donor_prune_plan(plan, blueprint)
    except PlanningError as exc:
        assert exc.plan.blocking_gaps
        assert any("donor" in gap.lower() or "compatibility" in gap.lower() for gap in exc.plan.blocking_gaps)
    else:
        assert donor_plan.compat_donor
        assert donor_plan.layout_strategy == "donor_park_clean"
        assert donor_plan.pruned_devices
        assert any(op["op"] == "rename_device" for op in adapted.edit_operations)
        assert any(op["op"] == "reflow_layout" for op in adapted.edit_operations)
        assert not any(op["op"] == "prune_device" for op in adapted.edit_operations)


def test_build_donor_prune_plan_blocks_new_link_pairs_in_open_first_mode() -> None:
    compat_donor = get_packet_tracer_compatibility_donor()
    if compat_donor is None:
        return
    blueprint, plan = build_prompt_blueprint(
        parse_intent(
            "6 şöbəli şəbəkə qur, hər şöbədə 1 switch, 1 AP, 1 printer, 2 PC, 2 tablet olsun, "
            "router-on-a-stick olsun, DHCP routerdən verilsin, management VLAN və telnet olsun"
        )
    )
    try:
        _build_donor_prune_plan_for_donor(plan, blueprint, Path(compat_donor))
    except PlanningError as exc:
        assert any(
            "cannot create new donor link pair" in gap
            or "requires donor link reuse" in gap
            or "supports only" in gap
            for gap in exc.plan.blocking_gaps
        )
    else:
        raise AssertionError("Expected open-first donor graph reuse to block unsupported link mutations")


def test_collect_donor_groups_falls_back_to_link_topology() -> None:
    root = ET.Element("PACKETTRACER5")
    devices = ET.SubElement(root, "DEVICES")
    for name, device_type, model in [
        ("Mertebe 3", "Switch", "2960-24TT"),
        ("Mertebe 1", "Switch", "2960-24TT"),
        ("Mertebe 2", "Switch", "2960-24TT"),
        ("DIA-RS", "Router", "PT8200"),
        ("DNS DHCP 192.168.20.2", "Server", "Server-PT"),
        ("web 192.168.20.3", "Server", "Server-PT"),
        ("SQL 192.168.20.4", "Server", "Server-PT"),
        ("Muhasib-1", "PC", "PC-PT"),
        ("Muhasib-2", "PC", "PC-PT"),
        ("II-dek-01", "PC", "PC-PT"),
        ("II-dek-02", "PC", "PC-PT"),
    ]:
        devices.append(_make_device(name, device_type, model))
    links = ET.SubElement(root, "LINKS")
    for args in [
        (0, 3, "GigabitEthernet0/1", "GigabitEthernet0/0/1"),
        (0, 4, "FastEthernet0/6", "FastEthernet0"),
        (0, 5, "FastEthernet0/5", "FastEthernet0"),
        (0, 6, "FastEthernet0/4", "FastEthernet0"),
        (1, 7, "FastEthernet0/1", "FastEthernet0"),
        (1, 8, "FastEthernet0/2", "FastEthernet0"),
        (2, 9, "FastEthernet0/1", "FastEthernet0"),
        (2, 10, "FastEthernet0/2", "FastEthernet0"),
    ]:
        links.append(_make_link(*args))

    groups = _collect_donor_groups(root)

    assert [group["group_name"] for group in groups] == ["Mertebe 1", "Mertebe 2", "Mertebe 3"]
    mertebe3 = next(group for group in groups if group["group_name"] == "Mertebe 3")
    assert mertebe3["members_by_type"]["Server"]
    assert len(mertebe3["members_by_type"]["Server"]) == 3


def test_safe_open_profile_blocks_department_link_mutations_until_cumulative_acceptance() -> None:
    donor_root = _make_safe_open_root()
    plan = _make_safe_open_plan()
    original_apply = generate_pkt_module.apply_plan_operations
    try:
        generate_pkt_module.apply_plan_operations = lambda donor_root_arg, stage_plan: donor_root_arg
        safe_plan, profiled_plan = _apply_safe_open_profile(donor_root, plan)
    finally:
        generate_pkt_module.apply_plan_operations = original_apply

    assert profiled_plan.compatibility_profile["mode"] == "safe_open_strict_9_0"
    assert "link_rewrite" in profiled_plan.blocked_mutations
    assert "port_reassignment" in profiled_plan.blocked_mutations
    assert profiled_plan.acceptance_stage_plan
    assert any(stage["stage_name"] == "link_remove_only" for stage in profiled_plan.acceptance_stage_plan)
    assert any(stage["stage_name"] == "link_add_only" for stage in profiled_plan.acceptance_stage_plan)
    assert all(op["op"] in {"rename_device", "reflow_layout"} for op in safe_plan.edit_operations)


def test_safe_open_profile_allows_rename_layout_and_config_only() -> None:
    donor_root = ET.Element("PACKETTRACER5")
    devices = ET.SubElement(donor_root, "DEVICES")
    device = _make_device("SW1", "Switch", "2960-24TT")
    engine = device.find("./ENGINE")
    assert engine is not None
    ET.SubElement(engine, "SAVE_REF_ID").text = "save-ref-id:1"
    workspace = ET.SubElement(device, "WORKSPACE")
    logical = ET.SubElement(workspace, "LOGICAL")
    ET.SubElement(logical, "X").text = "10"
    ET.SubElement(logical, "Y").text = "10"
    ET.SubElement(logical, "MEM_ADDR").text = "mem-1"
    ET.SubElement(workspace, "PHYSICAL").text = "Intercity,Home City,Corporate Office,Main Wiring Closet,Rack,SW1"
    devices.append(device)
    ET.SubElement(donor_root, "LINKS")

    plan = parse_intent("set SW1 vlan 10 name Finance")
    plan.edit_operations = [
        {"op": "rename_device", "device": "SW1", "new_name": "DIST-SW1"},
        {"op": "reflow_layout", "device": "DIST-SW1", "x": 200, "y": 320},
    ]
    plan.switch_ops = [{"op": "set_vlan", "device": "DIST-SW1", "vlan": 10, "name": "Finance"}]

    safe_plan, profiled_plan = _apply_safe_open_profile(donor_root, plan)

    assert not profiled_plan.blocked_mutations
    assert safe_plan.edit_operations == plan.edit_operations
    assert safe_plan.switch_ops == plan.switch_ops


def test_safe_open_profile_still_blocks_wireless_and_end_device_mutations() -> None:
    donor_root = ET.Element("PACKETTRACER5")
    devices = ET.SubElement(donor_root, "DEVICES")
    device = _make_device("AP1", "Access Point", "AccessPoint-PT")
    engine = device.find("./ENGINE")
    assert engine is not None
    ET.SubElement(engine, "SAVE_REF_ID").text = "save-ref-id:2"
    workspace = ET.SubElement(device, "WORKSPACE")
    logical = ET.SubElement(workspace, "LOGICAL")
    ET.SubElement(logical, "X").text = "10"
    ET.SubElement(logical, "Y").text = "10"
    ET.SubElement(logical, "MEM_ADDR").text = "mem-2"
    ET.SubElement(workspace, "PHYSICAL").text = "Intercity,Home City,Corporate Office,Main Wiring Closet,Rack,AP1"
    devices.append(device)
    ET.SubElement(donor_root, "LINKS")

    plan = parse_intent("set AP1 ssid TEST security wpa2-psk passphrase test12345")
    plan.wireless_ops = [{"op": "set_ssid", "device": "AP1", "ssid": "TEST"}]
    plan.end_device_ops = [{"op": "set_end_device_ip_mode", "device": "Tablet0", "mode": "dhcp"}]

    safe_plan, profiled_plan = _apply_safe_open_profile(donor_root, plan)

    assert "wireless_mutation" in profiled_plan.blocked_mutations
    assert "end_device_mutation" in profiled_plan.blocked_mutations
    assert not safe_plan.wireless_ops
    assert not safe_plan.end_device_ops


def test_safe_open_preview_reports_wireless_and_end_device_mutations() -> None:
    plan = parse_intent(
        "set AP1 ssid TEST security wpa2-psk passphrase test12345 "
        "associate Tablet0 to AP1 ssid TEST dhcp "
        "set Tablet0 dns 192.168.10.20"
    )
    preview = _apply_safe_open_preview(plan)
    assert "wireless_mutation" in preview.blocked_mutations
    assert "wireless_client_association" in preview.blocked_mutations
    assert "end_device_mutation" in preview.blocked_mutations
    assert any("wireless_mutation" in gap for gap in preview.blocking_gaps)


def test_cumulative_link_stages_include_expected_dependencies() -> None:
    donor_root = _make_safe_open_root()
    plan = _make_safe_open_plan()
    original_apply = generate_pkt_module.apply_plan_operations
    try:
        generate_pkt_module.apply_plan_operations = lambda donor_root_arg, stage_plan: donor_root_arg
        _, profiled_plan = _apply_safe_open_profile(donor_root, plan)
    finally:
        generate_pkt_module.apply_plan_operations = original_apply
    remove_stage = next(stage for stage in profiled_plan.acceptance_stage_plan if stage["stage_name"] == "link_remove_only")
    add_stage = next(stage for stage in profiled_plan.acceptance_stage_plan if stage["stage_name"] == "link_add_only")

    assert "rename_device" in remove_stage["applied_operations"]
    assert "reflow_layout" in remove_stage["applied_operations"]
    assert "set_vlan" in remove_stage["applied_operations"]
    assert "set_subinterface" in remove_stage["applied_operations"]
    assert "remove_link" in remove_stage["applied_operations"]
    assert "set_link" not in remove_stage["applied_operations"]

    assert "rename_device" in add_stage["applied_operations"]
    assert "reflow_layout" in add_stage["applied_operations"]
    assert "set_vlan" in add_stage["applied_operations"]
    assert "set_subinterface" in add_stage["applied_operations"]
    assert "remove_link" in add_stage["applied_operations"]
    assert "set_link" in add_stage["applied_operations"]


def test_evaluate_donor_prune_candidates_reports_rejection_reasons() -> None:
    plan = parse_intent("set SW1 vlan 10 name Finance")
    blueprint = {"devices": [], "links": []}
    bad_sample = SampleDescriptor(
        path="bad.pkt",
        relative_path="bad.pkt",
        version="9.0.0.0810",
        device_count=2,
        link_count=0,
        devices=[],
        links=[],
        capability_tags=["vlan"],
        topology_tags=["general"],
        preferred_roles=[],
        apply_safety_level="acceptance-verified",
    )
    good_sample = SampleDescriptor(
        path="good.pkt",
        relative_path="good.pkt",
        version="9.0.0.0810",
        device_count=2,
        link_count=0,
        devices=[],
        links=[],
        capability_tags=["vlan"],
        topology_tags=["general"],
        preferred_roles=[],
        apply_safety_level="acceptance-verified",
    )
    candidates = [
        SampleCandidate(sample=bad_sample, capability_score=5, topology_score=5, total_score=10, reasons=["bad fit"]),
        SampleCandidate(sample=good_sample, capability_score=8, topology_score=7, total_score=15, reasons=["good fit"]),
    ]
    original_build = generate_pkt_module._build_donor_prune_plan_for_donor
    original_decode = generate_pkt_module.decode_pkt_to_root
    original_apply = generate_pkt_module.apply_plan_operations
    original_validate = generate_pkt_module.validate_donor_coherence
    original_unexpected = generate_pkt_module._unexpected_workspace_issues
    original_sanitize = generate_pkt_module._sanitize_runtime_sections
    try:
        def fake_build(plan_arg, blueprint_arg, donor_path):
            if Path(donor_path).name == "bad.pkt":
                rejected_plan = parse_intent("set SW1 vlan 10 name Finance")
                rejected_plan.blocking_gaps.append("Open-first mode cannot create new donor link pair SW1 <-> R1.")
                raise PlanningError("blocked", rejected_plan)
            adapted_plan = parse_intent("set SW1 vlan 10 name Finance")
            archetype_plan = DonorArchetypePlan(
                compat_donor=str(donor_path),
                donor_capacity={"Switch": 1},
                kept_devices=["SW1"],
                pruned_devices=[],
                renamed_devices=[],
                mutation_groups=[],
                layout_strategy="donor_park_clean",
            )
            return adapted_plan, archetype_plan

        generate_pkt_module._build_donor_prune_plan_for_donor = fake_build
        generate_pkt_module.decode_pkt_to_root = lambda donor_path: ET.Element("PACKETTRACER5")
        generate_pkt_module.apply_plan_operations = lambda donor_root, adapted_plan: donor_root
        generate_pkt_module.validate_donor_coherence = lambda donor_root, candidate_root: None
        generate_pkt_module._unexpected_workspace_issues = lambda donor_root, candidate_root: []
        generate_pkt_module._sanitize_runtime_sections = lambda root: None

        evaluation, diagnostics = _evaluate_donor_prune_candidates(plan, blueprint, candidates)
    finally:
        generate_pkt_module._build_donor_prune_plan_for_donor = original_build
        generate_pkt_module.decode_pkt_to_root = original_decode
        generate_pkt_module.apply_plan_operations = original_apply
        generate_pkt_module.validate_donor_coherence = original_validate
        generate_pkt_module._unexpected_workspace_issues = original_unexpected
        generate_pkt_module._sanitize_runtime_sections = original_sanitize

    assert evaluation is not None
    assert evaluation[1].compat_donor_relative_path == "good.pkt"
    rejected = next(item for item in diagnostics if item["relative_path"] == "bad.pkt")
    assert rejected["status"] == "rejected"
    assert any("cannot create new donor link pair" in reason for reason in rejected["rejection_reasons"])
    selected = next(item for item in diagnostics if item["relative_path"] == "good.pkt")
    assert selected["status"] == "selected"


def test_candidate_acceptance_penalty_reflects_graph_gaps() -> None:
    sample = SampleDescriptor(
        path="sample.pkt",
        relative_path="sample.pkt",
        version="9.0.0.0810",
        device_count=2,
        link_count=1,
        devices=[],
        links=[
            {
                "from": "R1",
                "to": "SW1",
                "media": "eStraightThrough",
                "ports": ["GigabitEthernet0/0/1", "GigabitEthernet0/1"],
            }
        ],
        capability_tags=["vlan"],
        topology_tags=["general"],
        preferred_roles=[],
        apply_safety_level="config-mutation-supported",
    )
    candidate = SampleCandidate(sample=sample, capability_score=10, topology_score=5, total_score=15, reasons=[])
    blueprint = {
        "links": [
            {
                "a": {"dev": "R1", "port": "GigabitEthernet0/0/0"},
                "b": {"dev": "SW1", "port": "GigabitEthernet0/1"},
                "media": "crossover",
            },
            {
                "a": {"dev": "R1", "port": "GigabitEthernet0/0/1"},
                "b": {"dev": "SW2", "port": "GigabitEthernet0/1"},
                "media": "straight-through",
            },
        ]
    }
    penalty, reasons = _candidate_acceptance_penalty(candidate, blueprint)
    assert penalty > 0
    assert any(reason.startswith("missing_link_pairs:") for reason in reasons)
    assert any(reason.startswith("port_media_conflicts:") for reason in reasons)
    assert any(reason.startswith("apply_safety:") for reason in reasons)


def test_candidate_acceptance_penalty_tracks_wireless_and_end_device_capability_gaps() -> None:
    sample = SampleDescriptor(
        path="sample.pkt",
        relative_path="sample.pkt",
        version="9.0.0.0810",
        device_count=2,
        link_count=1,
        devices=[{"name": "WR1", "type": "WirelessRouter", "model": "HomeRouter-PT-AC"}],
        links=[],
        capability_tags=["wireless_ap"],
        topology_tags=["wireless_edge"],
        preferred_roles=[],
        apply_safety_level="acceptance-verified",
    )
    candidate = SampleCandidate(sample=sample, capability_score=10, topology_score=5, total_score=15, reasons=[])
    blueprint = {
        "capabilities": ["wireless_mutation", "wireless_client_association", "end_device_mutation"],
        "links": [],
    }
    penalty, reasons = _candidate_acceptance_penalty(candidate, blueprint)
    assert penalty > 0
    assert "capability_gap:wireless_mutation" in reasons
    assert "capability_gap:wireless_client_association" in reasons
    assert "capability_gap:end_device_mutation" in reasons


def test_candidate_acceptance_penalty_tracks_archetype_gap() -> None:
    sample = SampleDescriptor(
        path="sample.pkt",
        relative_path="sample.pkt",
        version="9.0.0.0810",
        device_count=2,
        link_count=1,
        devices=[
            {"name": "R1", "type": "Router", "model": "ISR4331"},
            {"name": "SW1", "type": "Switch", "model": "2960-24TT"},
        ],
        links=[],
        capability_tags=["vlan"],
        topology_tags=["core_access"],
        preferred_roles=[],
        apply_safety_level="acceptance-verified",
    )
    candidate = SampleCandidate(sample=sample, capability_score=10, topology_score=5, total_score=15, reasons=[])
    blueprint = {
        "preferred_donor_archetypes": ["wireless-heavy"],
        "links": [],
        "capabilities": [],
    }
    penalty, reasons = _candidate_acceptance_penalty(candidate, blueprint)
    assert penalty > 0
    assert any(reason.startswith("archetype_gap:") for reason in reasons)


def test_candidate_to_dict_includes_archetype_and_layout_diagnostics() -> None:
    sample = SampleDescriptor(
        path="sample.pkt",
        relative_path="sample.pkt",
        version="9.0.0.0810",
        device_count=3,
        link_count=1,
        devices=[
            {"name": "R1", "type": "Router", "model": "ISR4331"},
            {"name": "SW1", "type": "Switch", "model": "2960-24TT"},
            {"name": "AP1", "type": "LightWeightAccessPoint", "model": "AP-PT"},
        ],
        links=[
            {
                "from": "R1",
                "to": "SW1",
                "media": "eStraightThrough",
                "ports": ["GigabitEthernet0/0/0", "GigabitEthernet0/1"],
            }
        ],
        capability_tags=["vlan", "wireless_ap"],
        topology_tags=["wireless_edge", "core_access"],
        preferred_roles=[],
        wireless_mode_tags=["ap_bridge"],
        apply_safety_level="acceptance-verified",
    )
    candidate = SampleCandidate(sample=sample, capability_score=20, topology_score=10, total_score=30, reasons=["fit"])
    payload = _candidate_to_dict(
        candidate,
        {
            "preferred_donor_archetypes": ["wireless-heavy", "campus/core"],
            "topology_archetype": "core_access",
            "devices": [{"name": "R1"}, {"name": "SW1"}],
            "links": [],
        },
    )
    assert payload["preferred_donor_archetypes"] == ["wireless-heavy", "campus/core"]
    assert payload["sample_archetypes"]
    assert payload["archetype_match_score"] > 0
    assert "layout_reuse_score" in payload["donor_graph_fit"]
    assert payload["donor_graph_summary"]["layout_reuse_status"] == "not_applicable"
    assert payload["donor_graph_summary"]["reusable_pair_coverage"] == 100


def test_donor_graph_fit_summary_marks_weak_reuse() -> None:
    sample = SampleDescriptor(
        path="weak-layout.pkt",
        relative_path="weak-layout.pkt",
        version="9.0.0.0810",
        device_count=2,
        link_count=1,
        devices=[
            {"name": "R1", "type": "Router", "model": "ISR4331"},
            {"name": "SW1", "type": "Switch", "model": "2960-24TT"},
        ],
        links=[
            {
                "from": "R1",
                "to": "SW1",
                "media": "eStraightThrough",
                "ports": ["GigabitEthernet0/0/0", "GigabitEthernet0/1"],
            }
        ],
        capability_tags=["vlan"],
        topology_tags=["general"],
        preferred_roles=[],
        apply_safety_level="acceptance-verified",
    )
    candidate = SampleCandidate(sample=sample, capability_score=20, topology_score=10, total_score=30, reasons=["fit"])
    payload = _candidate_to_dict(
        candidate,
        {
            "preferred_donor_archetypes": ["wireless-heavy"],
            "topology_archetype": "wireless_branch",
            "devices": [{"name": "R1"}, {"name": "SW1"}, {"name": "AP1"}, {"name": "TAB1"}],
            "links": [
                {"a": {"dev": "R1", "port": "GigabitEthernet0/0/0"}, "b": {"dev": "SW1", "port": "GigabitEthernet0/1"}, "media": "straight-through"},
                {"a": {"dev": "SW1", "port": "GigabitEthernet0/2"}, "b": {"dev": "AP1", "port": "GigabitEthernet0"}, "media": "straight-through"},
                {"a": {"dev": "AP1", "port": "Wireless0"}, "b": {"dev": "TAB1", "port": "Wireless0"}, "media": "wireless"},
            ],
        },
    )
    assert payload["donor_graph_summary"]["required_pair_count"] == 3
    assert payload["donor_graph_summary"]["reusable_pair_count"] == 1
    assert payload["donor_graph_summary"]["reusable_pair_coverage"] == 33
    assert payload["donor_graph_summary"]["layout_reuse_status"] == "weak"


def test_preferred_donor_archetypes_for_plan_covers_campus_service_and_wireless() -> None:
    plan = parse_intent("campus sebekesi qur dns dhcp wifi")
    plan.device_requirements = {"Router": 1, "Switch": 3, "Server": 2, "LightWeightAccessPoint": 2}
    plan.capabilities = ["dns", "dhcp", "wireless_ap", "wireless_client_association", "vlan"]
    plan.wireless_mode = "ap_bridge"
    plan.service_requirements = {"services": ["dns", "dhcp", "http"]}
    preferred = _preferred_donor_archetypes_for_plan(plan, ["chain", "server_services", "wireless_edge"])
    assert "campus/core" in preferred
    assert "service-heavy" in preferred
    assert "wireless-heavy" in preferred


def test_filter_candidates_for_blueprint_filters_zero_viability_donor() -> None:
    filtered_sample = SampleDescriptor(
        path="filtered.pkt",
        relative_path="filtered.pkt",
        version="9.0.0.0810",
        device_count=2,
        link_count=1,
        devices=[],
        links=[],
        capability_tags=["vlan"],
        topology_tags=["general"],
        preferred_roles=[],
        apply_safety_level="config-mutation-supported",
    )
    viable_sample = SampleDescriptor(
        path="viable.pkt",
        relative_path="viable.pkt",
        version="9.0.0.0810",
        device_count=2,
        link_count=1,
        devices=[],
        links=[
            {
                "from": "R1",
                "to": "SW1",
                "media": "eStraightThrough",
                "ports": ["GigabitEthernet0/0/0", "GigabitEthernet0/1"],
            }
        ],
        capability_tags=["vlan"],
        topology_tags=["general"],
        preferred_roles=[],
        apply_safety_level="acceptance-verified",
    )
    candidates = [
        SampleCandidate(sample=filtered_sample, capability_score=10, topology_score=5, total_score=15, reasons=["filtered"]),
        SampleCandidate(sample=viable_sample, capability_score=20, topology_score=10, total_score=30, reasons=["viable"]),
    ]
    blueprint = {
        "links": [
            {
                "a": {"dev": "R1", "port": "GigabitEthernet0/0/0"},
                "b": {"dev": "SW1", "port": "GigabitEthernet0/1"},
                "media": "straight-through",
            }
        ]
    }
    viable, diagnostics = _filter_candidates_for_blueprint(candidates, blueprint)
    assert [candidate.sample.relative_path for candidate in viable] == ["viable.pkt"]
    assert diagnostics
    assert diagnostics[0]["status"] == "filtered"
    assert any("no reusable link pairs" in reason for reason in diagnostics[0]["rejection_reasons"])


def test_filter_candidates_for_blueprint_filters_wireless_association_gap() -> None:
    weak_sample = SampleDescriptor(
        path="weak.pkt",
        relative_path="weak.pkt",
        version="9.0.0.0810",
        device_count=2,
        link_count=0,
        devices=[{"name": "WR1", "type": "WirelessRouter", "model": "HomeRouter-PT-AC"}],
        links=[],
        capability_tags=["wireless_ap"],
        topology_tags=["wireless_edge"],
        preferred_roles=[],
        apply_safety_level="acceptance-verified",
    )
    strong_sample = SampleDescriptor(
        path="strong.pkt",
        relative_path="strong.pkt",
        version="9.0.0.0810",
        device_count=3,
        link_count=0,
        devices=[
            {"name": "AP1", "type": "LightWeightAccessPoint", "model": "AccessPoint-PT"},
            {"name": "TAB1", "type": "Tablet", "model": "TabletPC-PT"},
        ],
        links=[],
        capability_tags=["wireless_ap"],
        topology_tags=["wireless_edge"],
        preferred_roles=[],
        wireless_mode_tags=["ap_bridge"],
        apply_safety_level="acceptance-verified",
    )
    candidates = [
        SampleCandidate(sample=weak_sample, capability_score=12, topology_score=4, total_score=16, reasons=[]),
        SampleCandidate(sample=strong_sample, capability_score=12, topology_score=4, total_score=16, reasons=[]),
    ]
    blueprint = {"capabilities": ["wireless_client_association"], "links": []}
    viable, diagnostics = _filter_candidates_for_blueprint(candidates, blueprint)
    assert [candidate.sample.relative_path for candidate in viable] == ["strong.pkt"]
    assert any(
        "sample lacks donor-backed support for requested wireless client association" in reason
        for item in diagnostics
        for reason in item["rejection_reasons"]
    )


def test_filter_candidates_for_blueprint_filters_wireless_mutation_gap() -> None:
    weak_sample = SampleDescriptor(
        path="weak_wireless_mutation.pkt",
        relative_path="weak_wireless_mutation.pkt",
        version="9.0.0.0810",
        device_count=1,
        link_count=0,
        devices=[{"name": "AP1", "type": "LightWeightAccessPoint", "model": "AccessPoint-PT"}],
        links=[],
        capability_tags=["wireless_ap"],
        topology_tags=["wireless_edge"],
        preferred_roles=[],
        apply_safety_level="acceptance-verified",
    )
    strong_sample = SampleDescriptor(
        path="strong_wireless_mutation.pkt",
        relative_path="strong_wireless_mutation.pkt",
        version="9.0.0.0810",
        device_count=2,
        link_count=0,
        devices=[{"name": "AP1", "type": "LightWeightAccessPoint", "model": "AccessPoint-PT"}],
        links=[],
        capability_tags=["wireless_ap"],
        topology_tags=["wireless_edge"],
        preferred_roles=[],
        wireless_mode_tags=["ap_bridge"],
        apply_safety_level="acceptance-verified",
    )
    candidates = [
        SampleCandidate(sample=weak_sample, capability_score=12, topology_score=4, total_score=16, reasons=[]),
        SampleCandidate(sample=strong_sample, capability_score=12, topology_score=4, total_score=16, reasons=[]),
    ]
    blueprint = {"capabilities": ["wireless_mutation"], "links": []}
    viable, diagnostics = _filter_candidates_for_blueprint(candidates, blueprint)
    assert [candidate.sample.relative_path for candidate in viable] == ["strong_wireless_mutation.pkt"]
    assert any(
        "sample lacks donor-backed support for requested wireless mutation" in reason
        for item in diagnostics
        for reason in item["rejection_reasons"]
    )


def test_filter_candidates_for_blueprint_filters_end_device_mutation_gap() -> None:
    weak_sample = SampleDescriptor(
        path="weak_end_devices.pkt",
        relative_path="weak_end_devices.pkt",
        version="9.0.0.0810",
        device_count=1,
        link_count=0,
        devices=[{"name": "R1", "type": "Router", "model": "ISR4331"}],
        links=[],
        capability_tags=["dns"],
        topology_tags=["general"],
        preferred_roles=[],
        apply_safety_level="acceptance-verified",
    )
    strong_sample = SampleDescriptor(
        path="strong_end_devices.pkt",
        relative_path="strong_end_devices.pkt",
        version="8.2.1.4208",
        device_count=2,
        link_count=0,
        devices=[
            {"name": "PC1", "type": "PC", "model": "PC-PT"},
            {"name": "TAB1", "type": "Tablet", "model": "TabletPC-PT"},
        ],
        links=[],
        capability_tags=["host_server"],
        topology_tags=["department_lan"],
        preferred_roles=[],
        apply_safety_level="safe-open-generate-supported",
    )
    candidates = [
        SampleCandidate(sample=weak_sample, capability_score=12, topology_score=4, total_score=16, reasons=[]),
        SampleCandidate(sample=strong_sample, capability_score=12, topology_score=4, total_score=16, reasons=[]),
    ]
    blueprint = {"capabilities": ["end_device_mutation"], "links": []}
    viable, diagnostics = _filter_candidates_for_blueprint(candidates, blueprint)
    assert [candidate.sample.relative_path for candidate in viable] == ["strong_end_devices.pkt"]
    assert any(
        "sample lacks donor-backed support for requested end-device mutation" in reason
        for item in diagnostics
        for reason in item["rejection_reasons"]
    )


def test_filter_candidates_for_blueprint_filters_archetype_mismatch_with_weak_layout_reuse() -> None:
    weak_sample = SampleDescriptor(
        path="weak-archetype.pkt",
        relative_path="weak-archetype.pkt",
        version="9.0.0.0810",
        device_count=2,
        link_count=1,
        devices=[
            {"name": "R1", "type": "Router", "model": "ISR4331"},
            {"name": "SW1", "type": "Switch", "model": "2960-24TT"},
        ],
        links=[
            {
                "from": "R1",
                "to": "SW1",
                "media": "eStraightThrough",
                "ports": ["GigabitEthernet0/0/0", "GigabitEthernet0/1"],
            }
        ],
        capability_tags=["vlan"],
        topology_tags=["general"],
        preferred_roles=[],
        apply_safety_level="acceptance-verified",
    )
    strong_sample = SampleDescriptor(
        path="strong-archetype.pkt",
        relative_path="strong-archetype.pkt",
        version="9.0.0.0810",
        device_count=4,
        link_count=3,
        devices=[
            {"name": "R1", "type": "Router", "model": "ISR4331"},
            {"name": "SW1", "type": "Switch", "model": "2960-24TT"},
            {"name": "AP1", "type": "LightWeightAccessPoint", "model": "AccessPoint-PT"},
            {"name": "TAB1", "type": "Tablet", "model": "TabletPC-PT"},
        ],
        links=[
            {"from": "R1", "to": "SW1", "media": "eStraightThrough", "ports": ["GigabitEthernet0/0/0", "GigabitEthernet0/1"]},
            {"from": "SW1", "to": "AP1", "media": "eStraightThrough", "ports": ["GigabitEthernet0/2", "GigabitEthernet0"]},
            {"from": "AP1", "to": "TAB1", "media": "wireless", "ports": ["Wireless0", "Wireless0"]},
        ],
        capability_tags=["wireless_ap", "wireless_client_association"],
        topology_tags=["wireless_edge"],
        preferred_roles=[],
        wireless_mode_tags=["ap_bridge"],
        apply_safety_level="acceptance-verified",
    )
    candidates = [
        SampleCandidate(sample=weak_sample, capability_score=20, topology_score=10, total_score=30, reasons=["weak-fit"]),
        SampleCandidate(sample=strong_sample, capability_score=20, topology_score=10, total_score=30, reasons=["strong-fit"]),
    ]
    blueprint = {
        "preferred_donor_archetypes": ["wireless-heavy"],
        "capabilities": ["wireless_client_association"],
        "links": [
            {"a": {"dev": "R1", "port": "GigabitEthernet0/0/0"}, "b": {"dev": "SW1", "port": "GigabitEthernet0/1"}, "media": "straight-through"},
            {"a": {"dev": "SW1", "port": "GigabitEthernet0/2"}, "b": {"dev": "AP1", "port": "GigabitEthernet0"}, "media": "straight-through"},
            {"a": {"dev": "AP1", "port": "Wireless0"}, "b": {"dev": "TAB1", "port": "Wireless0"}, "media": "wireless"},
        ],
    }
    viable, diagnostics = _filter_candidates_for_blueprint(candidates, blueprint)
    assert [candidate.sample.relative_path for candidate in viable] == ["strong-archetype.pkt"]
    assert any(
        "sample archetype does not align with the requested donor shape" in reason
        for item in diagnostics
        for reason in item["rejection_reasons"]
    )
    assert diagnostics[0]["donor_graph_summary"]["layout_reuse_status"] == "weak"


def test_summarize_candidate_pool_reports_counts_and_top_reasons() -> None:
    summary = _summarize_candidate_pool(
        [
            {"status": "filtered", "adjusted_total_score": 4, "donor_graph_fit": {"layout_reuse_score": 0}, "rejection_reasons": ["reason-a", "reason-b"]},
            {"status": "rejected", "adjusted_total_score": 12, "donor_graph_fit": {"layout_reuse_score": 8}, "rejection_reasons": ["reason-c"]},
            {"status": "selected", "adjusted_total_score": 20, "donor_graph_fit": {"layout_reuse_score": 21}, "rejection_reasons": []},
        ],
        ["campus/core", "service-heavy"],
    )
    assert summary["preferred_donor_archetypes"] == ["campus/core", "service-heavy"]
    assert summary["candidate_counts"] == {"selected": 1, "rejected": 1, "filtered": 1}
    assert summary["best_adjusted_total_score"] == 20
    assert summary["best_layout_reuse_score"] == 21
    assert summary["top_rejection_reasons"] == ["reason-a", "reason-b", "reason-c"]
    assert summary["best_rejected_donor_class"] == "campus/core"
    assert summary["primary_rejection_code"] is None
    assert summary["primary_rejection_layer"] is None


def test_selected_donor_summary_reports_why_selected() -> None:
    donor_plan = DonorArchetypePlan(
        compat_donor="donor.pkt",
        donor_capacity={"devices": 4},
        kept_devices=["R1", "SW1"],
        pruned_devices=[],
        renamed_devices=[],
        mutation_groups=[],
        layout_strategy="preserve",
        selection_reasons=["capability:vlan", "origin:cisco-local"],
    )
    summary = _selected_donor_summary(
        [
            {
                "relative_path": "donor.pkt",
                "origin": "cisco-local",
                "promotion_status": "validated_primary",
                "promotion_evidence": ["validation:validated", "apply_safety:acceptance-verified"],
                "validated_edit_capabilities": ["vlan", "management_vlan", "telnet"],
                "acceptance_notes": ["workspace logical=ok physical=ok"],
                "status": "selected",
                "reasons": ["capability:vlan"],
                "sample_archetypes": ["campus/core"],
                "archetype_match_reasons": ["archetype:campus/core"],
                "donor_graph_summary": {
                    "reusable_pair_coverage": 100,
                    "layout_reuse_status": "strong",
                },
                "adjusted_total_score": 18,
            }
        ],
        donor_plan,
    )
    assert summary is not None
    assert summary["relative_path"] == "donor.pkt"
    assert summary["selection_reasons"] == ["capability:vlan", "origin:cisco-local"]
    assert summary["promotion_status"] == "validated_primary"
    assert summary["validated_edit_capabilities"] == ["vlan", "management_vlan", "telnet"]
    assert any("layout reuse 100% (strong)" == item for item in summary["why_selected"])
    assert any("archetype match via archetype:campus/core" == item for item in summary["why_selected"])
    assert any("promotion evidence: validation:validated, apply_safety:acceptance-verified" == item for item in summary["why_selected"])


def test_scenario_generate_decision_blocks_acceptance_gated_and_unsupported() -> None:
    acceptance_gated = _scenario_generate_decision(
        {
            "scenario_generate_readiness": {
                "family": "home_iot",
                "status": "acceptance_gated",
            }
        }
    )
    unsupported = _scenario_generate_decision(
        {
            "scenario_generate_readiness": {
                "family": "campus",
                "status": "unsupported",
            }
        }
    )

    assert acceptance_gated["allow_generate"] is False
    assert acceptance_gated["status"] == "blocked_by_acceptance"
    assert any("acceptance-gated" in item for item in acceptance_gated["blocking_reasons"])
    assert unsupported["allow_generate"] is False
    assert unsupported["status"] == "blocked_by_capability"
    assert any("not generate-ready" in item for item in unsupported["blocking_reasons"])


def test_scenario_generate_decision_requires_selected_donor_before_allowing_ready_generate() -> None:
    ready = _scenario_generate_decision(
        {
            "scenario_generate_readiness": {
                "family": "campus",
                "status": "ready",
            }
        }
    )
    donor_limited = _scenario_generate_decision(
        {
            "scenario_generate_readiness": {
                "family": "service_heavy",
                "status": "donor_limited",
            }
        },
        donor_selection_summary={"candidate_counts": {"selected": 1}},
        selected_donor_summary={
            "sample_archetypes": ["service-heavy", "wireless-heavy"],
            "donor_graph_summary": {
                "layout_reuse_status": "strong",
                "reusable_pair_coverage": 100,
            }
        },
    )

    assert ready["allow_generate"] is False
    assert ready["status"] == "ready_without_selected_donor"
    assert ready["what_failed"] == "donor selection"
    assert ready["blocking_layer"] == "donor"
    assert ready["decision_confidence"] == 0.55
    assert donor_limited["allow_generate"] is True
    assert donor_limited["status"] == "ready_with_selected_donor"
    assert donor_limited["selected_donor_aligned"] is True
    assert donor_limited["blocking_layer"] is None
    assert any("selected donor archetype aligns" in item for item in donor_limited["notes"])
    assert any("100% reusable link-pair coverage" in item for item in donor_limited["notes"])


def test_scenario_generate_decision_reports_selected_donor_mismatch() -> None:
    decision = _scenario_generate_decision(
        {
            "scenario_generate_readiness": {
                "family": "home_iot",
                "status": "ready",
            }
        },
        selected_donor_summary={
            "sample_archetypes": ["campus/core", "service-heavy"],
            "donor_graph_summary": {
                "layout_reuse_status": "strong",
                "reusable_pair_coverage": 80,
            },
        },
    )

    assert decision["allow_generate"] is True
    assert decision["status"] == "ready_with_selected_donor"
    assert decision["selected_donor_aligned"] is False
    assert any("do not match expected IoT/home gateway" in item for item in decision["notes"])


def test_scenario_acceptance_summary_reports_blocked_candidate_pool() -> None:
    summary = _scenario_acceptance_summary(
        {
            "recommended_next_actions": ["Choose a donor closer to the requested archetype."],
            "scenario_generate_readiness": {
                "family": "campus",
                "status": "unsupported",
                "critical_capabilities": ["router_on_a_stick", "trunk"],
                "missing_critical_capabilities": ["router_on_a_stick"],
            },
        },
        donor_selection_summary={
            "candidate_counts": {"selected": 0, "rejected": 2, "filtered": 1},
            "top_rejection_reasons": ["archetype_gap:wireless-heavy", "missing_link_pairs:4"],
        },
    )

    assert summary["family"] == "campus"
    assert summary["generate_state"] == "blocked"
    assert summary["donor_state"] == "candidate_pool_blocked"
    assert summary["decision_state"] == "blocked_by_capability"
    assert summary["candidate_counts"] == {"selected": 0, "rejected": 2, "filtered": 1}
    assert summary["top_rejection_reasons"] == ["archetype_gap:wireless-heavy", "missing_link_pairs:4"]
    assert summary["critical_capabilities"] == ["router_on_a_stick", "trunk"]
    assert summary["missing_critical_capabilities"] == ["router_on_a_stick"]
    assert len(summary["critical_capability_parity"]) == 0
    assert len(summary["critical_parity_mismatches"]) == 0
    assert summary["next_best_action"] == "Choose a donor closer to the requested archetype."
    assert summary["selection_failure_type"] == "viable_donor_found_but_archetype_misaligned"
    assert summary["best_rejected_donor_class"] == "campus/core"
    assert summary["primary_rejection_layer"] == "donor"
    assert summary["primary_rejection_code"] == "archetype_misaligned"
    assert "Best rejected donor class campus/core was closest" in summary["best_rejected_donor_summary"]
    assert summary["decision_confidence"] == 0.9
    assert summary["key_reasons"]


def test_scenario_acceptance_summary_reports_selected_aligned_donor() -> None:
    summary = _scenario_acceptance_summary(
        {
            "recommended_next_actions": ["No action required."],
            "scenario_generate_readiness": {
                "family": "service_heavy",
                "status": "donor_limited",
                "critical_capabilities": ["server_dns", "server_ftp"],
                "missing_critical_capabilities": [],
            },
        },
        donor_selection_summary={"candidate_counts": {"selected": 1, "rejected": 0, "filtered": 0}},
        selected_donor_summary={
            "sample_archetypes": ["service-heavy"],
            "donor_graph_summary": {
                "layout_reuse_status": "strong",
                "reusable_pair_coverage": 100,
            },
        },
    )

    assert summary["generate_state"] == "allowed"
    assert summary["donor_state"] == "selected"
    assert summary["selected_donor_aligned"] is True
    assert summary["selection_failure_type"] is None
    assert summary["best_rejected_donor_class"] is None
    assert summary["primary_rejection_layer"] is None
    assert summary["primary_rejection_code"] is None
    assert summary["best_rejected_donor_summary"] is None
    assert summary["decision_state"] == "ready_with_selected_donor"
    assert summary["candidate_counts"] == {"selected": 1, "rejected": 0, "filtered": 0}
    assert summary["critical_capabilities"] == ["server_dns", "server_ftp"]
    assert summary["missing_critical_capabilities"] == []
    assert summary["key_reasons"]


def test_scenario_matrix_row_reports_blocked_summary() -> None:
    row = _scenario_matrix_row(
        {
            "family": "campus",
            "readiness_status": "unsupported",
            "generate_state": "blocked",
            "donor_state": "candidate_pool_blocked",
            "selected_donor_aligned": None,
            "candidate_counts": {"selected": 0, "rejected": 2, "filtered": 1},
            "critical_capabilities": ["router_on_a_stick", "trunk"],
            "missing_critical_capabilities": ["router_on_a_stick"],
            "top_rejection_reasons": ["missing_link_pairs:4"],
            "next_best_action": "Choose a donor closer to the requested archetype.",
            "decision_confidence": 0.9,
            "blocking_layer": "capability",
            "best_available_donor_class": "campus/core",
            "best_rejected_donor_class": "campus/core",
            "primary_rejection_layer": "donor",
            "primary_rejection_code": "layout_reuse_too_weak",
            "remediation_steps": ["Choose a donor closer to the requested archetype."],
        }
    )

    assert row["family"] == "campus"
    assert row["generate_state"] == "blocked"
    assert row["acceptance_rank"] == 1
    assert row["acceptance_label"] == "blocked_by_donor_selection"
    assert row["comparison_score"] == 87
    assert "campus: blocked_by_donor_selection" in row["comparison_summary"]
    assert row["selection_failure_type"] == "viable_donor_found_but_acceptance_weak"
    assert row["critical_capability_count"] == 2
    assert row["missing_critical_capability_count"] == 1
    assert row["parity_mismatch_count"] == 0
    assert row["top_rejection_reason"] == "missing_link_pairs:4"
    assert row["decision_confidence"] == 0.9
    assert row["blocking_layer"] == "capability"
    assert row["best_available_donor_class"] == "campus/core"
    assert row["primary_rejection_code"] == "layout_reuse_too_weak"
    assert row["remediation_hint"] == "Choose a donor closer to the requested archetype."


def test_scenario_matrix_row_reports_selected_donor() -> None:
    row = _scenario_matrix_row(
        {
            "family": "service_heavy",
            "readiness_status": "donor_limited",
            "generate_state": "allowed",
            "donor_state": "selected",
            "selected_donor_aligned": True,
            "candidate_counts": {"selected": 1, "rejected": 0, "filtered": 0},
            "critical_capabilities": ["server_dns", "server_ftp"],
            "missing_critical_capabilities": [],
            "top_rejection_reasons": [],
            "next_best_action": "No action required.",
        },
        selected_donor_summary={"relative_path": "service_donor.pkt"},
    )

    assert row["family"] == "service_heavy"
    assert row["donor_state"] == "selected"
    assert row["acceptance_rank"] == 3
    assert row["acceptance_label"] == "ready_with_selected_donor"
    assert row["comparison_score"] == 300
    assert "service_heavy: ready_with_selected_donor" in row["comparison_summary"]
    assert row["selected_donor"] == "service_donor.pkt"
    assert row["selected_donor_aligned"] is True
    assert row["selection_failure_type"] is None
    assert row["primary_rejection_code"] is None
    assert row["parity_mismatch_count"] == 0


def test_scenario_acceptance_summary_reports_runtime_subtree_missing_code() -> None:
    summary = _scenario_acceptance_summary(
        {
            "recommended_next_actions": ["Import a donor with the required runtime subtree first."],
            "scenario_generate_readiness": {
                "family": "campus",
                "status": "donor_limited",
                "critical_capabilities": ["management_vlan"],
                "missing_critical_capabilities": [],
            },
        },
        donor_selection_summary={
            "candidate_counts": {"selected": 0, "rejected": 1, "filtered": 0},
            "preferred_donor_archetypes": ["campus/core"],
            "top_rejection_reasons": ["runtime subtree is missing for donor reuse"],
            "primary_rejection_code": "runtime_subtree_missing",
            "primary_rejection_layer": "donor",
            "best_rejected_donor_class": "campus/core",
        },
    )

    assert summary["selection_failure_type"] == "viable_donor_found_but_runtime_subtree_missing"
    assert summary["primary_rejection_code"] == "runtime_subtree_missing"
    assert summary["primary_rejection_layer"] == "donor"
    assert summary["best_rejected_donor_class"] == "campus/core"
    assert "runtime subtree is missing" in summary["best_rejected_donor_summary"]


def test_scenario_acceptance_summary_reports_campus_layout_reuse_blocker() -> None:
    summary = _scenario_acceptance_summary(
        {
            "recommended_next_actions": ["Import a campus/core donor with a reusable router-switch-management skeleton."],
            "scenario_generate_readiness": {
                "family": "campus",
                "status": "donor_limited",
                "critical_capabilities": ["management_vlan", "telnet", "acl"],
                "missing_critical_capabilities": [],
            },
        },
        donor_selection_summary={
            "candidate_counts": {"selected": 0, "rejected": 2, "filtered": 1},
            "preferred_donor_archetypes": ["campus/core"],
            "top_rejection_reasons": ["missing_link_pairs:6", "sample reuses too little of the requested link skeleton"],
            "primary_rejection_code": "layout_reuse_too_weak",
            "primary_rejection_layer": "donor",
            "best_rejected_donor_class": "campus/core",
        },
    )

    assert summary["family"] == "campus"
    assert summary["decision_state"] == "blocked_by_donor_selection"
    assert summary["selection_failure_type"] == "viable_donor_found_but_acceptance_weak"
    assert summary["best_rejected_donor_class"] == "campus/core"
    assert summary["primary_rejection_layer"] == "donor"
    assert summary["primary_rejection_code"] == "layout_reuse_too_weak"


def test_selected_donor_summary_reports_registry_backed_evidence_source() -> None:
    summary = _selected_donor_summary(
        [
            {
                "status": "selected",
                "relative_path": "service_heavy_cli_edit_v1.pkt",
                "origin": "external-curated",
                "promotion_status": "acceptance_verified_curated",
                "evidence_source": "registry+inferred",
                "promotion_evidence": [
                    "promotion:acceptance_verified_curated",
                    "acceptance_fixture:service_heavy_complex",
                    "evidence_source:registry+inferred",
                ],
                "validated_edit_capabilities": ["server_dns", "server_dhcp", "server_ftp"],
                "acceptance_notes": ["Known working service-heavy example."],
                "acceptance_fixtures": ["service_heavy_complex"],
                "provenance": "known-working-example:service_heavy_cli_edit_v1",
                "workspace_validation": "inventory_roundtrip_verified",
                "sample_archetypes": ["service-heavy"],
                "archetype_match_reasons": ["archetype:service-heavy"],
                "adjusted_total_score": 42,
                "donor_graph_summary": {
                    "reusable_pair_coverage": 100,
                    "layout_reuse_status": "strong",
                },
                "reasons": ["capability:server_dns", "capability:server_ftp"],
            }
        ]
    )

    assert summary is not None
    assert summary["evidence_source"] == "registry+inferred"
    assert summary["workspace_validation"] == "inventory_roundtrip_verified"
    assert any("evidence source: registry+inferred" == item for item in summary["promotion_reasoning"])
    assert any("workspace validation: inventory_roundtrip_verified" == item for item in summary["promotion_reasoning"])
    assert any("evidence source: registry+inferred" == item for item in summary["why_selected"])


def test_scenario_generate_decision_handles_wan_security_edge() -> None:
    decision = _scenario_generate_decision(
        {
            "scenario_generate_readiness": {
                "family": "wan_security_edge",
                "status": "donor_limited",
                "critical_capabilities": ["vpn", "ipsec", "gre"],
                "missing_critical_capabilities": [],
            }
        },
        donor_selection_summary={"candidate_counts": {"selected": 0, "rejected": 1, "filtered": 1}},
        selected_donor_summary=None,
    )
    assert decision["family"] == "wan_security_edge"
    assert decision["allow_generate"] is False
    assert decision["status"] == "blocked_by_donor_selection"
    assert any("WAN/security edge" in item for item in decision["blocking_reasons"])


def test_scenario_generate_decision_reports_runtime_blocker() -> None:
    decision = _scenario_generate_decision(
        {
            "scenario_generate_readiness": {
                "family": "campus",
                "status": "ready",
            },
            "recommended_next_actions": ["Set PACKET_TRACER_COMPAT_DONOR first."],
        },
        runtime_blocked=True,
        runtime_blocking_reason="missing_or_incompatible_donor",
    )
    assert decision["allow_generate"] is False
    assert decision["runtime_blocked"] is True
    assert decision["status"] == "blocked_by_runtime"
    assert decision["what_failed"] == "runtime readiness"
    assert decision["why_failed"] == "missing_or_incompatible_donor"
    assert decision["blocking_layer"] == "runtime"


def test_scenario_acceptance_matrix_examples_cover_campus_service_heavy_and_home_iot() -> None:
    cases = [
        {
            "coverage_gap": {
                "recommended_next_actions": ["Choose a donor closer to the requested archetype."],
                "scenario_generate_readiness": {
                    "family": "campus",
                    "status": "unsupported",
                    "critical_capabilities": ["router_on_a_stick", "trunk"],
                    "missing_critical_capabilities": ["router_on_a_stick"],
                },
            },
            "donor_selection_summary": {
                "candidate_counts": {"selected": 0, "rejected": 2, "filtered": 1},
                "top_rejection_reasons": ["missing_link_pairs:4"],
            },
            "selected_donor_summary": None,
            "expected": {
                "family": "campus",
                "generate_state": "blocked",
                "donor_state": "candidate_pool_blocked",
                "critical_capability_count": 2,
                "missing_critical_capability_count": 1,
            },
        },
        {
            "coverage_gap": {
                "recommended_next_actions": ["No action required."],
                "scenario_generate_readiness": {
                    "family": "service_heavy",
                    "status": "donor_limited",
                    "critical_capabilities": ["server_dns", "server_ftp"],
                    "missing_critical_capabilities": [],
                },
            },
            "donor_selection_summary": {
                "candidate_counts": {"selected": 1, "rejected": 0, "filtered": 0},
                "top_rejection_reasons": [],
            },
            "selected_donor_summary": {
                "relative_path": "service_donor.pkt",
                "sample_archetypes": ["service-heavy"],
                "donor_graph_summary": {
                    "layout_reuse_status": "strong",
                    "reusable_pair_coverage": 100,
                },
            },
            "expected": {
                "family": "service_heavy",
                "generate_state": "allowed",
                "donor_state": "selected",
                "critical_capability_count": 2,
                "missing_critical_capability_count": 0,
            },
        },
        {
            "coverage_gap": {
                "recommended_next_actions": ["Use edit/inventory flow before prompt generate."],
                "scenario_generate_readiness": {
                    "family": "home_iot",
                    "status": "acceptance_gated",
                    "critical_capabilities": ["iot_registration", "iot_control"],
                    "missing_critical_capabilities": [],
                },
            },
            "donor_selection_summary": {
                "candidate_counts": {"selected": 0, "rejected": 1, "filtered": 0},
                "top_rejection_reasons": ["acceptance_gated:iot_registration"],
            },
            "selected_donor_summary": None,
            "expected": {
                "family": "home_iot",
                "generate_state": "blocked",
                "donor_state": "candidate_pool_blocked",
                "critical_capability_count": 2,
                "missing_critical_capability_count": 0,
            },
        },
    ]

    for case in cases:
        summary = _scenario_acceptance_summary(
            case["coverage_gap"],
            donor_selection_summary=case["donor_selection_summary"],
            selected_donor_summary=case["selected_donor_summary"],
        )
        row = _scenario_matrix_row(
            summary,
            selected_donor_summary=case["selected_donor_summary"],
        )
        assert row["family"] == case["expected"]["family"]
        assert row["generate_state"] == case["expected"]["generate_state"]
        assert row["donor_state"] == case["expected"]["donor_state"]
        assert row["critical_capability_count"] == case["expected"]["critical_capability_count"]
        assert row["missing_critical_capability_count"] == case["expected"]["missing_critical_capability_count"]
        assert "acceptance_rank" in row
        assert "acceptance_label" in row
        assert "comparison_score" in row
        assert "comparison_summary" in row


def test_scenario_matrix_table_sorts_by_comparison_score_then_missing_capabilities() -> None:
    rows = [
        {
            "family": "campus",
            "comparison_score": 87,
            "missing_critical_capability_count": 1,
        },
        {
            "family": "service_heavy",
            "comparison_score": 300,
            "missing_critical_capability_count": 0,
        },
        {
            "family": "home_iot",
            "comparison_score": 98,
            "missing_critical_capability_count": 0,
        },
    ]

    table = _scenario_matrix_table(rows)

    assert [row["family"] for row in table] == ["service_heavy", "home_iot", "campus"]


def test_compare_scenarios_builds_sorted_matrix_and_writes_output(tmp_path: Path, monkeypatch) -> None:
    payloads = {
        "campus prompt": {
            "scenario_matrix_row": {
                "family": "campus",
                "comparison_score": 87,
                "missing_critical_capability_count": 1,
                "fixture_name": "campus_core_complex",
                "matrix_version": "2.1",
                "parity_supported_count": 2,
                "parity_generate_ready_count": 1,
                "parity_acceptance_verified_count": 0,
                "parity_mismatch_count": 1,
            },
            "scenario_acceptance_summary": {"family": "campus"},
            "scenario_generate_decision": {"family": "campus"},
            "selected_donor_summary": None,
            "donor_selection_summary": {"candidate_counts": {"selected": 0, "rejected": 1, "filtered": 1}},
            "capability_parity": [{"capability": "router_on_a_stick", "generate_mismatch_reason": "supported_but_donor_limited"}],
        },
        "service prompt": {
            "scenario_matrix_row": {
                "family": "service_heavy",
                "comparison_score": 300,
                "missing_critical_capability_count": 0,
                "fixture_name": "service_heavy_complex",
                "matrix_version": "2.1",
                "parity_supported_count": 3,
                "parity_generate_ready_count": 3,
                "parity_acceptance_verified_count": 2,
                "parity_mismatch_count": 0,
            },
            "scenario_acceptance_summary": {"family": "service_heavy"},
            "scenario_generate_decision": {"family": "service_heavy"},
            "selected_donor_summary": {"relative_path": "service_donor.pkt"},
            "donor_selection_summary": {"candidate_counts": {"selected": 1, "rejected": 0, "filtered": 0}},
            "capability_parity": [{"capability": "server_dns", "generate_mismatch_reason": None}],
        },
    }

    monkeypatch.setattr(
        generate_pkt_module,
        "_explain_plan_payload",
        lambda prompt, *args, **kwargs: payloads[prompt],
    )

    matrix_out = tmp_path / "matrix.json"
    compare_scenarios(["campus prompt", "service prompt"], matrix_out=matrix_out)

    assert matrix_out.exists()
    payload = json.loads(matrix_out.read_text(encoding="utf-8"))
    assert payload["matrix_version"] == "2.1"
    assert payload["fixture_registry_version"] == "1.0"
    assert payload["scenario_count"] == 2
    assert [row["family"] for row in payload["matrix"]] == ["service_heavy", "campus"]
    assert payload["scenarios"][0]["fixture_name"] == "campus_core_complex"
    assert payload["scenarios"][0]["fixture_expectation_status"] == "gapped"


def test_parity_report_writes_prompt_scoped_parity_payload(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        generate_pkt_module,
        "_explain_plan_payload",
        lambda prompt, *args, **kwargs: {
            "coverage_gaps": {
                "scenario_family": "service_heavy",
                "scenario_generate_readiness": {
                    "critical_capabilities": ["server_dns", "server_email"],
                },
            },
            "capability_parity": [
                {
                    "capability": "server_dns",
                    "inventory_supported": True,
                    "edit_supported": True,
                    "generate_supported": True,
                    "acceptance_verified": True,
                    "best_maturity_level": "acceptance-verified",
                    "generate_mismatch_reason": None,
                },
                {
                    "capability": "server_email",
                    "inventory_supported": True,
                    "edit_supported": True,
                    "generate_supported": True,
                    "acceptance_verified": False,
                    "best_maturity_level": "safe-open-generate-supported",
                    "generate_mismatch_reason": "supported_but_donor_limited",
                },
            ],
        },
    )
    out_path = tmp_path / "parity.json"
    parity_report("service-heavy", acceptance_json_out=out_path)
    payload = json.loads(capsys.readouterr().out)
    assert payload["scenario_family"] == "service_heavy"
    assert payload["parity_supported_count"] == 2
    assert payload["parity_generate_ready_count"] == 2
    assert payload["parity_acceptance_verified_count"] == 1
    assert payload["parity_mismatch_count"] == 1
    assert len(payload["critical_capability_parity"]) == 2
    assert len(payload["critical_parity_mismatches"]) == 1
    assert out_path.exists()


def test_augment_coverage_gap_actions_adds_runtime_and_link_guidance() -> None:
    coverage_gap = {
        "unsupported_capabilities": ["router_on_a_stick"],
        "recommended_next_actions": ["Run explain-plan first."],
        "scenario_generate_readiness": {"family": "campus", "status": "donor_limited"},
    }
    diagnostics = [
        {
            "relative_path": "donor1.pkt",
            "rejection_reasons": [
                "Open-first mode cannot create new donor link pair SW1 <-> R1.",
                "Open-first mode requires donor link reuse for SW1 <-> R1; donor ports/media are ['Gi0/1', 'Gi0/0'] / eStraightThrough, requested ['Gi0/2', 'Gi0/0'] / crossover.",
            ],
        }
    ]
    updated = _augment_coverage_gap_actions(
        coverage_gap,
        donor_diagnostics=diagnostics,
        donor_selection_summary={
            "preferred_donor_archetypes": ["campus/core", "service-heavy"],
            "candidate_counts": {"selected": 0, "rejected": 1, "filtered": 1},
            "best_layout_reuse_score": 0,
            "top_rejection_reasons": ["archetype_gap:wireless-heavy", "missing_link_pairs:3"],
        },
        donor_blocking_reason="Packet Tracer modern codec requires a local Twofish bridge.",
    )
    assert any("PKT_TWOFISH_LIBRARY" in action for action in updated["recommended_next_actions"])
    assert any("link skeleton" in action for action in updated["recommended_next_actions"])
    assert any("ports/media" in action for action in updated["recommended_next_actions"])
    assert any("--blueprint-out" in action for action in updated["recommended_next_actions"])
    assert any("campus/core, service-heavy" in action for action in updated["recommended_next_actions"])
    assert any("Simplify the topology" in action for action in updated["recommended_next_actions"])


def test_preferred_donor_archetypes_keep_campus_primary_for_shorthand_prompt() -> None:
    plan = parse_intent("campus with VLAN DHCP ACL")

    preferred = _preferred_donor_archetypes_for_plan(plan, [])

    assert preferred[0] == "campus/core"
    assert "service-heavy" not in preferred


def test_explain_plan_classifies_campus_shorthand_prompt_as_campus() -> None:
    payload = generate_pkt_module._explain_plan_payload("campus with VLAN DHCP ACL")

    assert payload["coverage_gaps"]["scenario_family"] == "campus"
    assert payload["coverage_gaps"]["scenario_generate_readiness"]["family"] == "campus"
    assert payload["scenario_generate_decision"]["family"] == "campus"
    assert payload["scenario_matrix_row"]["family"] == "campus"
    assert payload["scenario_matrix_row"]["fixture_name"] == "campus_core_complex"
    assert payload["fixture_expectation_status"] == "matched"
    assert payload["preferred_donor_archetypes"][0] == "campus/core"
    assert payload["preferred_donor_archetypes"].count("campus/core") == 1


def test_explain_plan_keeps_home_iot_public_family_even_with_small_office_style() -> None:
    payload = generate_pkt_module._explain_plan_payload("home with IoT registration and wireless gateway")

    assert payload["intent_plan"]["network_style"] == "small_office"
    assert payload["coverage_gaps"]["scenario_family"] == "home_iot"
    assert payload["coverage_gaps"]["scenario_generate_readiness"]["family"] == "home_iot"
    assert payload["scenario_generate_decision"]["family"] == "home_iot"


def test_preferred_donor_archetypes_keep_home_gateway_wireless_prompt_in_home_iot_family() -> None:
    plan = parse_intent("associate Laptop0 to Home Gateway0 ssid HOME dhcp")

    preferred = _preferred_donor_archetypes_for_plan(plan, [])

    assert preferred[0] == "IoT/home gateway"
    assert "wireless-heavy" in preferred
    assert "service-heavy" not in preferred


def test_preferred_donor_archetypes_keep_wan_security_primary_for_tunnel_prompt() -> None:
    plan = parse_intent("wan security edge qur gre tunnel ve ipsec vpn ppp olsun 1 multilayer switch 1 asa 1 cloud")

    preferred = _preferred_donor_archetypes_for_plan(plan, [])

    assert preferred[0] == "WAN/security edge"
    assert "service-heavy" not in preferred[:1]
    assert "campus/core" not in preferred[:1]


def test_best_rejected_donor_summary_uses_wan_security_remediation() -> None:
    summary = _best_rejected_donor_summary(
        "WAN/security edge",
        "layout_reuse_too_weak",
        ["missing_link_pairs:ASA1 <-> Cloud0"],
    )

    assert summary is not None
    assert "Best rejected donor class WAN/security edge was closest" in summary
    assert "ASA/cloud/serial or tunnel skeleton" in summary
    assert "missing_link_pairs:ASA1 <-> Cloud0" in summary


def test_explain_plan_keeps_home_gateway_wireless_association_in_home_iot_family() -> None:
    payload = generate_pkt_module._explain_plan_payload("associate Laptop0 to Home Gateway0 ssid HOME dhcp")

    assert payload["intent_plan"]["network_style"] == "small_office"
    assert payload["coverage_gaps"]["scenario_family"] == "home_iot"
    assert payload["coverage_gaps"]["scenario_generate_readiness"]["family"] == "home_iot"
    assert payload["preferred_donor_archetypes"][0] == "IoT/home gateway"


def test_fixture_corpus_uses_utf8_prompts_and_campus_alias() -> None:
    payload = json.loads((ROOT / "references" / "scenario-fixture-corpus.json").read_text(encoding="utf-8"))
    fixtures = {item["name"]: item for item in payload["fixtures"]}

    assert fixtures["campus_core_complex"]["canonical_prompt"].startswith("6 şöbəli kampus")
    assert fixtures["service_heavy_complex"]["canonical_prompt"].startswith("server yönümlü lab")
    assert fixtures["campus_core_complex"]["prompt_aliases"] == ["campus with VLAN DHCP ACL"]
    assert any("closer to the requested scenario" in action for action in updated["recommended_next_actions"])
    assert any("campus/core donor" in action for action in updated["recommended_next_actions"])


def test_fixture_corpus_uses_utf8_prompts_and_campus_alias_override() -> None:
    payload = json.loads((ROOT / "references" / "scenario-fixture-corpus.json").read_text(encoding="utf-8"))
    fixtures = {item["name"]: item for item in payload["fixtures"]}

    assert fixtures["campus_core_complex"]["canonical_prompt"].startswith("6 şöbəli kampus")
    assert fixtures["service_heavy_complex"]["canonical_prompt"].startswith("server yönümlü lab")
    assert fixtures["campus_core_complex"]["prompt_aliases"] == ["campus with VLAN DHCP ACL"]


def test_fixture_corpus_uses_utf8_prompts_and_campus_alias() -> None:
    payload = json.loads((ROOT / "references" / "scenario-fixture-corpus.json").read_text(encoding="utf-8"))
    fixtures = {item["name"]: item for item in payload["fixtures"]}

    assert fixtures["campus_core_complex"]["canonical_prompt"].startswith("6 şöbəli kampus")
    assert fixtures["service_heavy_complex"]["canonical_prompt"].startswith("server yönümlü lab")
    assert fixtures["campus_core_complex"]["prompt_aliases"] == ["campus with VLAN DHCP ACL"]


def test_augment_coverage_gap_actions_adds_service_heavy_and_home_iot_guidance() -> None:
    service_updated = _augment_coverage_gap_actions(
        {
            "unsupported_capabilities": [],
            "recommended_next_actions": [],
            "scenario_generate_readiness": {"family": "service_heavy", "status": "acceptance_gated"},
        }
    )
    home_iot_updated = _augment_coverage_gap_actions(
        {
            "unsupported_capabilities": [],
            "recommended_next_actions": [],
            "scenario_generate_readiness": {"family": "home_iot", "status": "unsupported"},
        }
    )

    assert any("required server service family" in action for action in service_updated["recommended_next_actions"])
    assert any("Home Gateway plus existing IoT registration/control structure" in action for action in home_iot_updated["recommended_next_actions"])
