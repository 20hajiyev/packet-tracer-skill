from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from sample_catalog import SampleDescriptor, load_catalog  # noqa: E402
from sample_selector import rank_reference_samples, rank_samples, select_best_sample  # noqa: E402


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
