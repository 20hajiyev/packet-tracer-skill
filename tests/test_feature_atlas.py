from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from feature_atlas import build_feature_gap_report  # noqa: E402


def test_feature_atlas_truth_source_covers_packet_tracer_gap_families() -> None:
    atlas = json.loads((ROOT / "references" / "packettracer-feature-atlas.json").read_text(encoding="utf-8"))
    groups = {group["id"]: group for group in atlas["feature_groups"]}

    assert atlas["target_packet_tracer_version"] == "9.0.0.0810"
    assert {
        "ipv6_routing",
        "l2_security_monitoring",
        "wan_security_edge",
        "security_edge_deepening",
        "wireless_advanced",
        "automation_controller",
        "voice_collaboration",
        "industrial_iot",
        "physical_media_device_gaps",
    } <= set(groups)
    assert any(feature["capability"] == "dhcpv6_stateful" for feature in groups["ipv6_routing"]["features"])
    assert any(feature["capability"] == "netflow" for feature in groups["l2_security_monitoring"]["features"])
    assert any(feature["capability"] == "gre" for feature in groups["wan_security_edge"]["features"])
    assert any(feature["capability"] == "mqtt" for feature in groups["industrial_iot"]["features"])


def test_feature_gap_report_compares_parser_catalog_coverage_and_samples() -> None:
    report = build_feature_gap_report()
    group_by_id = {group["id"]: group for group in report["groups"]}
    status_by_capability = {
        feature["capability"]: feature
        for group in report["groups"]
        for feature in group["features"]
    }

    assert report["packet_tracer_sample_count"] >= 290
    assert report["total_feature_count"] >= 50
    assert report["mapped_feature_count"] > report["unmapped_feature_count"]
    assert group_by_id["ipv6_routing"]["scenario_family"] == "ipv6_routing"
    assert status_by_capability["dhcpv6_stateful"]["status"] == "edit_proven"
    assert status_by_capability["dhcp_snooping"]["status"] == "edit_proven"
    assert status_by_capability["span"]["status"] == "edit_proven"
    assert status_by_capability["snmp"]["evidence"]["parser_pattern"] is True
    assert status_by_capability["snmp"]["evidence"]["editor_roundtrip_test"] is True
    assert status_by_capability["mqtt"]["evidence"]["sample_count"] >= 1
    assert status_by_capability["voip"]["status"] == "report_supported"
    assert status_by_capability["port_security"]["status"] == "edit_proven"
    assert status_by_capability["qos"]["status"] == "report_supported"
    assert status_by_capability["qos"]["evidence"]["sample_path_count"] >= 1
    assert status_by_capability["qos"]["evidence"]["decode_verified_sample_count"] == 0
    assert status_by_capability["dot1x"]["status"] == "report_supported"
    assert status_by_capability["wep"]["status"] == "edit_proven"
    assert status_by_capability["wpa_enterprise"]["status"] == "edit_proven"
    assert status_by_capability["wlc"]["status"] == "report_supported"
    assert status_by_capability["bluetooth"]["status"] == "report_supported"
    assert status_by_capability["gre"]["status"] == "edit_proven"
    assert status_by_capability["ppp"]["status"] == "edit_proven"
    assert status_by_capability["ipsec"]["status"] == "edit_proven"
    assert status_by_capability["vpn"]["status"] == "edit_proven"
    assert status_by_capability["security_edge"]["status"] == "report_supported"


def test_feature_gap_report_keeps_atlas_features_below_generate_ready() -> None:
    report = build_feature_gap_report()
    for group in report["groups"]:
        for feature in group["features"]:
            assert feature["status"] != "generate_ready", feature
            assert feature["support_ceiling"] in {"inventory_known", "report_supported", "edit_proven"}
