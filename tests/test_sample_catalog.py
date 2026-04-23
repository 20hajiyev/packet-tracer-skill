from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import sample_catalog as sample_catalog_module  # noqa: E402
from sample_catalog import SampleDescriptor, load_catalog, load_curated_donor_catalog, load_curated_donor_registry  # noqa: E402
from sample_selector import rank_curated_donor_samples, rank_reference_samples, rank_samples, select_best_sample  # noqa: E402


def test_catalog_has_capability_tags() -> None:
    catalog = load_catalog()
    assert catalog
    assert any("dhcp_pool" in item.capability_tags for item in catalog)
    assert any("ospf" in item.capability_tags for item in catalog)
    assert any("wireless_ap" in item.capability_tags for item in catalog)
    assert any("telnet" in item.capability_tags for item in catalog)


def test_selector_finds_vlan_capable_sample() -> None:
    catalog = load_catalog()
    sample = select_best_sample(catalog, ["vlan"], {"Switch": 1, "Router": 1}, topology_tags=["router_on_a_stick"])
    assert sample.relative_path
    assert sample.device_count >= 2


def test_selector_keeps_external_reference_out_of_prototype_choice() -> None:
    cisco = SampleDescriptor(
        path="cisco.pkt",
        relative_path="cisco.pkt",
        version="9.0.0",
        device_count=2,
        link_count=1,
        devices=[{"name": "R1", "type": "Router", "model": "2901"}, {"name": "SW1", "type": "Switch", "model": "2960-24TT"}],
        links=[],
        capability_tags=["vlan"],
        topology_tags=["router_on_a_stick"],
        preferred_roles=["preferred_vlan"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
    )
    external = SampleDescriptor(
        path="ext.pkt",
        relative_path="ext.pkt",
        version="9.0.0",
        device_count=4,
        link_count=3,
        devices=[{"name": "R1", "type": "Router", "model": "2901"}, {"name": "SW1", "type": "Switch", "model": "2960-24TT"}],
        links=[],
        capability_tags=["vlan", "acl"],
        topology_tags=["department_lan", "router_on_a_stick"],
        preferred_roles=["preferred_vlan"],
        trust_level="reference-only",
        origin="external-reference",
        role="reference",
        prototype_eligible=False,
    )
    ranked = rank_samples([external, cisco], ["vlan"], {"Switch": 1, "Router": 1}, topology_tags=["router_on_a_stick"], prototype_only=True)
    assert ranked
    assert ranked[0].sample.origin == "cisco-local"


def test_normalize_device_type_covers_home_gateway_and_iot_runtime_types() -> None:
    assert sample_catalog_module.normalize_device_type("WirelessRouterNewGeneration") == "WirelessRouter"
    assert sample_catalog_module.normalize_device_type("HomeGateway") == "WirelessRouter"
    assert sample_catalog_module.normalize_device_type("WirelessLanController") == "LightWeightAccessPoint"
    assert sample_catalog_module.normalize_device_type("MCUComponent") == "IoT"
    assert sample_catalog_module.normalize_device_type("MultiLayerSwitch") == "MultiLayerSwitch"


def test_infer_device_families_covers_home_gateway_wlc_and_iot_components() -> None:
    families = sample_catalog_module.infer_device_families(
        {
            "devices": [
                {"type": "HomeGateway"},
                {"type": "WirelessLanController"},
                {"type": "MCUComponent"},
            ]
        }
    )
    assert "home/wireless routers" in families
    assert "access points" in families
    assert "iot devices" in families


def test_infer_home_iot_shape_roles_runtime_and_edit_capabilities() -> None:
    item = {
        "devices": [
            {"type": "HomeGateway"},
            {"type": "MCUComponent"},
            {"type": "Server"},
        ],
        "device_families": ["home/wireless routers", "iot devices", "servers"],
        "capability_tags": ["host_server", "iot"],
        "wireless_mode_tags": ["home_router_edge"],
        "apply_safety_level": "acceptance-verified",
    }
    assert {"gateway", "thing", "server"} <= set(sample_catalog_module.infer_iot_roles(item))
    assert "iot_runtime" in sample_catalog_module.infer_runtime_features(item)
    validated = set(sample_catalog_module.infer_validated_edit_capabilities(item))
    assert {"iot", "iot_registration", "iot_control", "wireless_mutation"} <= validated


def test_reference_ranking_prefers_matching_external_patterns() -> None:
    external_vlan = SampleDescriptor(
        path="ext1.pkt",
        relative_path="ext1.pkt",
        version="9.0.0",
        device_count=6,
        link_count=5,
        devices=[{"name": "R1", "type": "Router", "model": "2901"}, {"name": "SW1", "type": "Switch", "model": "2960-24TT"}],
        links=[],
        capability_tags=["vlan", "wireless_ap"],
        topology_tags=["department_lan", "router_on_a_stick"],
        preferred_roles=["preferred_vlan"],
        trust_level="reference-only",
        origin="external-reference",
        role="reference",
        prototype_eligible=False,
    )
    external_small = SampleDescriptor(
        path="ext2.pkt",
        relative_path="ext2.pkt",
        version="9.0.0",
        device_count=2,
        link_count=1,
        devices=[{"name": "SW1", "type": "Switch", "model": "2960-24TT"}],
        links=[],
        capability_tags=["switching"],
        topology_tags=["small_office"],
        preferred_roles=["preferred_general"],
        trust_level="reference-only",
        origin="external-reference",
        role="reference",
        prototype_eligible=False,
    )
    ranked = rank_reference_samples(
        [external_small, external_vlan],
        ["vlan", "wireless_ap"],
        {"Switch": 1, "Router": 1},
        topology_tags=["department_lan", "router_on_a_stick"],
    )
    assert ranked
    assert ranked[0].sample.relative_path == "ext1.pkt"


def test_load_curated_donor_catalog_promotes_validated_external_samples(tmp_path, monkeypatch) -> None:
    donor_root = tmp_path / "donors"
    donor_root.mkdir()
    (donor_root / "LICENSE").write_text("MIT License", encoding="utf-8")
    pkt_path = donor_root / "campus_lab.pkt"
    pkt_path.write_bytes(b"fake")

    def fake_summary(path, relative_path, origin, prototype_eligible):
        assert path == pkt_path
        return {
            "path": str(path),
            "relative_path": relative_path,
            "version": "9.0.0.0810",
            "device_count": 4,
            "link_count": 3,
            "devices": [
                {"name": "R1", "type": "Router", "model": "ISR4331"},
                {"name": "SW1", "type": "Switch", "model": "2960-24TT"},
                {"name": "AP1", "type": "LightWeightAccessPoint", "model": "AccessPoint-PT"},
                {"name": "PC1", "type": "PC", "model": "PC-PT"},
            ],
            "links": [{"type": "copper"}],
            "origin": origin,
            "trust_level": "reference-only",
            "role": "reference",
            "prototype_eligible": prototype_eligible,
            "workspace_validation": {
                "workspace_mode": "mixed_physical",
                "logical_status": "ok",
                "physical_status": "ok",
                "blocking_issue_count": 0,
                "blocking_issues": [],
            },
        }

    sample_catalog_module._load_curated_donor_catalog_cached.cache_clear()
    monkeypatch.setattr(sample_catalog_module, "_summarize_pkt", fake_summary)
    catalog = load_curated_donor_catalog([donor_root])
    assert len(catalog) == 1
    sample = catalog[0]
    assert sample.origin == "external-curated"
    assert sample.donor_eligible is True
    assert sample.prototype_eligible is True
    assert sample.promotion_status == "validated_curated"
    assert sample.license_or_permission == "MIT"
    assert "ap_bridge" in sample.wireless_mode_tags
    assert "promotion:validated_curated" in sample.promotion_evidence
    assert "workspace_validated" in sample.promotion_evidence
    assert "wireless_mutation" in sample.validated_edit_capabilities
    assert "campus/core" in sample.archetype_tags


def test_load_curated_donor_catalog_merges_explicit_registry_metadata(tmp_path, monkeypatch) -> None:
    donor_root = tmp_path / "donors"
    donor_root.mkdir()
    pkt_path = donor_root / "wan_lab.pkt"
    pkt_path.write_bytes(b"fake")
    registry_path = tmp_path / "curated-donor-registry.json"
    registry_path.write_text(
        json.dumps(
            {
                "registry_version": "1.0",
                "donors": [
                    {
                        "relative_path": "wan_lab.pkt",
                        "promotion_status": "acceptance_verified_curated",
                        "acceptance_fixtures": ["wan_security_complex"],
                        "validated_edit_capabilities": ["vpn", "acl", "nat"],
                        "archetype_tags": ["WAN/security edge"],
                        "acceptance_notes": ["fixture-backed donor"],
                        "provenance": "manual-registry",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    def fake_summary(path, relative_path, origin, prototype_eligible):
        assert path == pkt_path
        return {
            "path": str(path),
            "relative_path": relative_path,
            "version": "9.0.0.0810",
            "device_count": 3,
            "link_count": 2,
                "devices": [
                    {"name": "ASA1", "type": "ASA", "model": "ASA-5505"},
                    {"name": "Cloud0", "type": "Cloud", "model": "Cloud-PT"},
                    {"name": "R1", "type": "Router", "model": "ISR4331"},
                ],
            "links": [{"type": "serial"}],
            "origin": origin,
            "trust_level": "reference-only",
            "role": "reference",
            "prototype_eligible": prototype_eligible,
            "workspace_validation": {
                "workspace_mode": "mixed_physical",
                "logical_status": "ok",
                "physical_status": "ok",
                "blocking_issue_count": 0,
                "blocking_issues": [],
            },
        }

    sample_catalog_module._load_curated_donor_catalog_cached.cache_clear()
    sample_catalog_module._load_curated_donor_registry_cached.cache_clear()
    monkeypatch.setattr(sample_catalog_module, "_summarize_pkt", fake_summary)
    monkeypatch.setattr(sample_catalog_module, "DEFAULT_CURATED_DONOR_REGISTRY", registry_path)
    catalog = load_curated_donor_catalog([donor_root])
    assert len(catalog) == 1
    sample = catalog[0]
    assert sample.promotion_status == "acceptance_verified_curated"
    assert sample.acceptance_fixtures == ["wan_security_complex"]
    assert sample.provenance == "manual-registry"
    assert "acceptance_fixture:wan_security_complex" in sample.promotion_evidence
    assert "provenance:manual-registry" in sample.promotion_evidence
    assert sample.evidence_source == "registry+inferred"
    assert sample.workspace_validation_status == ""


def test_default_curated_donor_registry_is_seeded_from_known_examples() -> None:
    registry = load_curated_donor_registry()
    assert {"complex_campus_master_edit_v4.pkt", "home_iot_cli_edit_v1.pkt", "service_heavy_cli_edit_v1.pkt"} <= set(registry)
    assert registry["complex_campus_master_edit_v4.pkt"]["promotion_status"] == "acceptance_verified_curated"
    assert any(
        "Local inventory smoke revalidated" in note
        for note in registry["complex_campus_master_edit_v4.pkt"]["acceptance_notes"]
    )
    assert any(
        "docs/campus-donor-proof.md" in note
        for note in registry["complex_campus_master_edit_v4.pkt"]["acceptance_notes"]
    )
    assert registry["home_iot_cli_edit_v1.pkt"]["workspace_validation"] == "inventory_roundtrip_verified"
    assert registry["service_heavy_cli_edit_v1.pkt"]["provenance"] == "known-working-example:service_heavy_cli_edit_v1"


def test_load_curated_donor_catalog_promotes_legacy_memaddr_only_samples(tmp_path, monkeypatch) -> None:
    donor_root = tmp_path / "donors"
    donor_root.mkdir()
    pkt_path = donor_root / "legacy_lab.pkt"
    pkt_path.write_bytes(b"fake")

    def fake_summary(path, relative_path, origin, prototype_eligible):
        assert path == pkt_path
        return {
            "path": str(path),
            "relative_path": relative_path,
            "version": "9.0.0.0810",
            "device_count": 4,
            "link_count": 3,
            "devices": [
                {"name": "R1", "type": "Router", "model": "ISR4331"},
                {"name": "SW1", "type": "Switch", "model": "2960-24TT"},
            ],
            "links": [{"type": "copper"}],
            "origin": origin,
            "trust_level": "reference-only",
            "role": "reference",
            "prototype_eligible": prototype_eligible,
            "workspace_validation": {
                "workspace_mode": "legacy_uuid_physical",
                "logical_status": "invalid",
                "physical_status": "ok",
                "blocking_issue_count": 12,
                "blocking_issues": [
                    "Link device MEM_ADDR references do not match device workspace records",
                    "Link device MEM_ADDR references do not match device workspace records",
                ],
            },
        }

    sample_catalog_module._load_curated_donor_catalog_cached.cache_clear()
    monkeypatch.setattr(sample_catalog_module, "_summarize_pkt", fake_summary)
    catalog = load_curated_donor_catalog([donor_root])
    assert len(catalog) == 1
    sample = catalog[0]
    assert sample.origin == "external-curated"
    assert sample.donor_eligible is True
    assert sample.prototype_eligible is True
    assert sample.promotion_status == "validated_curated"
    assert sample.validation_status == "validated"


def test_load_curated_donor_catalog_demotes_workspace_invalid_samples(tmp_path, monkeypatch) -> None:
    donor_root = tmp_path / "donors"
    donor_root.mkdir()
    pkt_path = donor_root / "broken_lab.pkt"
    pkt_path.write_bytes(b"fake")

    def fake_summary(path, relative_path, origin, prototype_eligible):
        assert path == pkt_path
        return {
            "path": str(path),
            "relative_path": relative_path,
            "version": "9.0.0.0810",
            "device_count": 4,
            "link_count": 3,
            "devices": [
                {"name": "R1", "type": "Router", "model": "ISR4331"},
                {"name": "SW1", "type": "Switch", "model": "2960-24TT"},
            ],
            "links": [{"type": "copper"}],
            "origin": origin,
            "trust_level": "reference-only",
            "role": "reference",
            "prototype_eligible": prototype_eligible,
            "workspace_validation": {
                "workspace_mode": "legacy_uuid_physical",
                "logical_status": "invalid",
                "physical_status": "ok",
                "blocking_issue_count": 1,
                "blocking_issues": ["No devices remain in generated Packet Tracer XML"],
            },
        }

    sample_catalog_module._load_curated_donor_catalog_cached.cache_clear()
    monkeypatch.setattr(sample_catalog_module, "_summarize_pkt", fake_summary)
    catalog = load_curated_donor_catalog([donor_root])
    assert len(catalog) == 1
    sample = catalog[0]
    assert sample.origin == "external-curated"
    assert sample.donor_eligible is False
    assert sample.prototype_eligible is False
    assert sample.promotion_status == "reference_only"
    assert sample.validation_status == "blocked"


def test_curated_donor_ranking_keeps_cisco_priority_for_prototypes() -> None:
    cisco = SampleDescriptor(
        path="cisco.pkt",
        relative_path="cisco.pkt",
        version="9.0.0.0810",
        device_count=4,
        link_count=3,
        devices=[{"name": "R1", "type": "Router", "model": "ISR4331"}, {"name": "SW1", "type": "Switch", "model": "2960-24TT"}],
        links=[],
        capability_tags=["vlan", "wireless_ap"],
        topology_tags=["department_lan", "router_on_a_stick"],
        preferred_roles=["preferred_vlan"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
    )
    curated = SampleDescriptor(
        path="curated.pkt",
        relative_path="curated.pkt",
        version="9.0.0.0810",
        device_count=5,
        link_count=4,
        devices=[{"name": "R1", "type": "Router", "model": "ISR4331"}, {"name": "SW1", "type": "Switch", "model": "2960-24TT"}],
        links=[],
        capability_tags=["vlan", "wireless_ap"],
        topology_tags=["department_lan", "router_on_a_stick"],
        preferred_roles=["preferred_vlan"],
        trust_level="curated",
        origin="external-curated",
        role="secondary",
        prototype_eligible=True,
        promotion_status="validated_curated",
        validation_status="validated",
        donor_eligible=True,
        promotion_evidence=["validation:validated", "promotion:validated_curated", "edit_capabilities:4"],
        validated_edit_capabilities=["vlan", "wireless_mutation", "management_vlan", "telnet"],
        archetype_tags=["campus/core"],
    )
    overall = rank_samples([curated, cisco], ["vlan", "wireless_ap"], {"Switch": 1, "Router": 1}, topology_tags=["department_lan"], prototype_only=True)
    assert overall
    assert overall[0].sample.origin == "cisco-local"
    curated_only = rank_curated_donor_samples([curated], ["vlan", "wireless_ap"], {"Switch": 1, "Router": 1}, topology_tags=["department_lan"])
    assert curated_only
    assert curated_only[0].sample.origin == "external-curated"


def test_ranking_prefers_curated_donor_with_stronger_promotion_evidence() -> None:
    curated_strong = SampleDescriptor(
        path="curated_strong.pkt",
        relative_path="curated_strong.pkt",
        version="9.0.0.0810",
        device_count=5,
        link_count=4,
        devices=[{"name": "R1", "type": "Router", "model": "ISR4331"}, {"name": "SW1", "type": "Switch", "model": "2960-24TT"}],
        links=[],
        capability_tags=["vlan", "server_dns"],
        topology_tags=["department_lan", "router_on_a_stick"],
        preferred_roles=["preferred_vlan", "preferred_server"],
        trust_level="curated",
        origin="external-curated",
        role="secondary",
        prototype_eligible=True,
        donor_eligible=True,
        promotion_status="validated_curated",
        validation_status="validated",
        apply_safety_level="safe-open-generate-supported",
        promotion_evidence=["validation:validated", "promotion:validated_curated", "workspace_validated", "edit_capabilities:5"],
        validated_edit_capabilities=["vlan", "server_dns", "management_vlan", "telnet", "end_device_mutation"],
    )
    curated_weak = SampleDescriptor(
        path="curated_weak.pkt",
        relative_path="curated_weak.pkt",
        version="9.0.0.0810",
        device_count=5,
        link_count=4,
        devices=[{"name": "R1", "type": "Router", "model": "ISR4331"}, {"name": "SW1", "type": "Switch", "model": "2960-24TT"}],
        links=[],
        capability_tags=["vlan", "server_dns"],
        topology_tags=["department_lan", "router_on_a_stick"],
        preferred_roles=["preferred_vlan", "preferred_server"],
        trust_level="curated",
        origin="external-curated",
        role="secondary",
        prototype_eligible=True,
        donor_eligible=True,
        promotion_status="validated_curated",
        validation_status="validated",
        apply_safety_level="safe-open-generate-supported",
    )
    ranked = rank_curated_donor_samples(
        [curated_weak, curated_strong],
        ["vlan", "server_dns"],
        {"Switch": 1, "Router": 1},
        topology_tags=["department_lan"],
        requested_services=["dns"],
    )
    assert ranked
    assert ranked[0].sample.relative_path == "curated_strong.pkt"


def test_ranking_prefers_acceptance_verified_curated_over_validated_curated() -> None:
    curated_verified = SampleDescriptor(
        path="curated_verified.pkt",
        relative_path="curated_verified.pkt",
        version="9.0.0.0810",
        device_count=5,
        link_count=4,
        devices=[{"name": "ASA1", "type": "ASA", "model": "ASA-5505"}, {"name": "Cloud0", "type": "Cloud", "model": "Cloud-PT"}],
        links=[],
        capability_tags=["vpn", "acl", "nat"],
        topology_tags=["general"],
        preferred_roles=["preferred_security", "preferred_wan"],
        trust_level="curated",
        origin="external-curated",
        role="secondary",
        prototype_eligible=True,
        donor_eligible=True,
        promotion_status="acceptance_verified_curated",
        validation_status="validated",
        apply_safety_level="safe-open-generate-supported",
        promotion_evidence=[
            "validation:validated",
            "promotion:acceptance_verified_curated",
            "workspace_validated",
            "edit_capabilities:4",
            "acceptance_fixture:wan_security_edge",
        ],
        validated_edit_capabilities=["vpn", "acl", "nat", "ppp"],
        archetype_tags=["WAN/security edge"],
    )
    curated_validated = SampleDescriptor(
        path="curated_validated.pkt",
        relative_path="curated_validated.pkt",
        version="9.0.0.0810",
        device_count=5,
        link_count=4,
        devices=[{"name": "ASA1", "type": "ASA", "model": "ASA-5505"}, {"name": "Cloud0", "type": "Cloud", "model": "Cloud-PT"}],
        links=[],
        capability_tags=["vpn", "acl", "nat"],
        topology_tags=["general"],
        preferred_roles=["preferred_security", "preferred_wan"],
        trust_level="curated",
        origin="external-curated",
        role="secondary",
        prototype_eligible=True,
        donor_eligible=True,
        promotion_status="validated_curated",
        validation_status="validated",
        apply_safety_level="safe-open-generate-supported",
        promotion_evidence=["validation:validated", "promotion:validated_curated", "workspace_validated", "edit_capabilities:4"],
        validated_edit_capabilities=["vpn", "acl", "nat", "ppp"],
        archetype_tags=["WAN/security edge"],
    )
    ranked = rank_curated_donor_samples(
        [curated_validated, curated_verified],
        ["vpn", "acl", "nat"],
        {"ASA": 1, "Cloud": 1},
        topology_tags=["general"],
    )
    assert ranked
    assert ranked[0].sample.relative_path == "curated_verified.pkt"


def test_ranking_prefers_matching_wireless_mode_and_service_support() -> None:
    ap_branch = SampleDescriptor(
        path="ap_branch.pkt",
        relative_path="ap_branch.pkt",
        version="9.0.0.0810",
        device_count=5,
        link_count=4,
        devices=[
            {"name": "R1", "type": "Router", "model": "ISR4331"},
            {"name": "SW1", "type": "Switch", "model": "2960-24TT"},
            {"name": "AP1", "type": "LightWeightAccessPoint", "model": "AccessPoint-PT"},
        ],
        links=[],
        capability_tags=["wireless_ap", "server_dns"],
        topology_tags=["wireless_edge", "department_lan"],
        preferred_roles=["preferred_wireless", "preferred_server"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
        wireless_mode_tags=["ap_bridge"],
        service_support=["dns"],
        apply_safety_level="acceptance-verified",
    )
    home_router = SampleDescriptor(
        path="home_router.pkt",
        relative_path="home_router.pkt",
        version="9.0.0.0810",
        device_count=5,
        link_count=4,
        devices=[
            {"name": "WR1", "type": "WirelessRouter", "model": "HomeRouter-PT-AC"},
            {"name": "PC1", "type": "PC", "model": "PC-PT"},
        ],
        links=[],
        capability_tags=["wireless_ap", "dhcp_pool"],
        topology_tags=["small_office", "wireless_edge"],
        preferred_roles=["preferred_wireless"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
        wireless_mode_tags=["home_router_edge"],
        service_support=["dhcp"],
        apply_safety_level="safe-open-generate-supported",
    )
    ranked = rank_samples(
        [home_router, ap_branch],
        ["wireless_ap", "server_dns"],
        {"Switch": 1, "Router": 1},
        topology_tags=["wireless_edge"],
        prototype_only=True,
        wireless_mode="ap_bridge",
        requested_services=["dns"],
    )
    assert ranked
    assert ranked[0].sample.relative_path == "ap_branch.pkt"


def test_ranking_uses_derived_wireless_client_association_capability() -> None:
    ap_branch = SampleDescriptor(
        path="ap_branch.pkt",
        relative_path="ap_branch.pkt",
        version="9.0.0.0810",
        device_count=4,
        link_count=2,
        devices=[
            {"name": "AP1", "type": "LightWeightAccessPoint", "model": "AccessPoint-PT"},
            {"name": "TAB1", "type": "Tablet", "model": "TabletPC-PT"},
        ],
        links=[],
        capability_tags=["wireless_ap"],
        topology_tags=["wireless_edge"],
        preferred_roles=["preferred_wireless"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
        wireless_mode_tags=["ap_bridge"],
        apply_safety_level="acceptance-verified",
    )
    weak_branch = SampleDescriptor(
        path="weak_branch.pkt",
        relative_path="weak_branch.pkt",
        version="9.0.0.0810",
        device_count=3,
        link_count=1,
        devices=[
            {"name": "WR1", "type": "WirelessRouter", "model": "HomeRouter-PT-AC"},
        ],
        links=[],
        capability_tags=["wireless_ap"],
        topology_tags=["wireless_edge"],
        preferred_roles=["preferred_wireless"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
        apply_safety_level="acceptance-verified",
    )
    ranked = rank_samples(
        [weak_branch, ap_branch],
        ["wireless_client_association"],
        {"Tablet": 1},
        topology_tags=["wireless_edge"],
        prototype_only=True,
        wireless_mode="ap_bridge",
    )
    assert ranked
    assert ranked[0].sample.relative_path == "ap_branch.pkt"


def test_ranking_uses_derived_wireless_mutation_capability() -> None:
    strong_ap = SampleDescriptor(
        path="strong_ap.pkt",
        relative_path="strong_ap.pkt",
        version="9.0.0.0810",
        device_count=2,
        link_count=0,
        devices=[{"name": "AP1", "type": "LightWeightAccessPoint", "model": "AccessPoint-PT"}],
        links=[],
        capability_tags=["wireless_ap"],
        topology_tags=["wireless_edge"],
        preferred_roles=["preferred_wireless"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
        wireless_mode_tags=["ap_bridge"],
        apply_safety_level="acceptance-verified",
    )
    weak_ap = SampleDescriptor(
        path="weak_ap.pkt",
        relative_path="weak_ap.pkt",
        version="9.0.0.0810",
        device_count=1,
        link_count=0,
        devices=[{"name": "AP1", "type": "LightWeightAccessPoint", "model": "AccessPoint-PT"}],
        links=[],
        capability_tags=["wireless_ap"],
        topology_tags=["wireless_edge"],
        preferred_roles=["preferred_wireless"],
        trust_level="trusted",
        origin="cisco-local",
        role="primary",
        prototype_eligible=True,
        donor_eligible=True,
        apply_safety_level="acceptance-verified",
    )
    ranked = rank_samples(
        [weak_ap, strong_ap],
        ["wireless_mutation"],
        {"LightWeightAccessPoint": 1},
        topology_tags=["wireless_edge"],
        prototype_only=True,
        wireless_mode="ap_bridge",
    )
    assert ranked
    assert ranked[0].sample.relative_path == "strong_ap.pkt"
