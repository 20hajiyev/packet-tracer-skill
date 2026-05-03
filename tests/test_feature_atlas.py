from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from feature_atlas import build_feature_gap_report  # noqa: E402


def test_feature_atlas_truth_source_covers_packet_tracer_gap_families() -> None:
    atlas = json.loads((ROOT / "references" / "packettracer-feature-atlas.json").read_text(encoding="utf-8"))
    groups = {group["id"]: group for group in atlas["feature_groups"]}

    assert atlas["target_packet_tracer_version"] == "9.0.0.0810"
    assert {
        "ipv6_routing",
        "ipv4_routing_management",
        "l2_resiliency_routing",
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
    assert any(feature["capability"] == "ospfv2" for feature in groups["ipv4_routing_management"]["features"])
    assert any(feature["capability"] == "pat" for feature in groups["ipv4_routing_management"]["features"])
    assert any(feature["capability"] == "bgp" for feature in groups["l2_resiliency_routing"]["features"])
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
    assert status_by_capability["dhcpv6_stateful"]["evidence"]["donor_backed_proof_ready"] is False
    for capability in ["ospfv3", "eigrp_ipv6", "ripng", "hsrp"]:
        assert status_by_capability[capability]["status"] == "donor_backed_ready"
        assert status_by_capability[capability]["evidence"]["donor_backed_proof"] is True
        assert status_by_capability[capability]["evidence"]["donor_backed_proof_ready"] is True
    for capability in ["bgp", "stp", "rstp", "etherchannel", "lacp", "pagp", "vtp", "dtp"]:
        assert status_by_capability[capability]["status"] == "edit_proven"
        assert status_by_capability[capability]["evidence"]["parser_pattern"] is True
        assert status_by_capability[capability]["evidence"]["catalog_keyword"] is True
        assert status_by_capability[capability]["evidence"]["coverage_provider"] is True
        assert status_by_capability[capability]["evidence"]["editor_roundtrip_test"] is True
    for capability in ["ospfv2", "eigrp_ipv4", "ripv2", "static_route", "default_route", "dhcp_relay", "nat_static", "nat_dynamic", "pat", "ssh_ios", "ntp_ios", "syslog_ios"]:
        assert status_by_capability[capability]["status"] == "edit_proven"
        assert status_by_capability[capability]["evidence"]["parser_pattern"] is True
        assert status_by_capability[capability]["evidence"]["catalog_keyword"] is True
        assert status_by_capability[capability]["evidence"]["coverage_provider"] is True
        assert status_by_capability[capability]["evidence"]["editor_roundtrip_test"] is True
        assert status_by_capability[capability]["evidence"]["donor_backed_proof_ready"] is False
    assert status_by_capability["dhcp_snooping"]["status"] == "edit_proven"
    assert status_by_capability["span"]["status"] == "edit_proven"
    assert status_by_capability["snmp"]["evidence"]["parser_pattern"] is True
    assert status_by_capability["snmp"]["evidence"]["editor_roundtrip_test"] is True
    assert status_by_capability["mqtt"]["evidence"]["sample_count"] >= 1
    assert status_by_capability["linksys_voice"]["status"] == "report_supported"
    assert status_by_capability["network_controller"]["status"] == "report_supported"
    assert status_by_capability["blockly_programming"]["status"] == "report_supported"
    assert status_by_capability["vm_iox"]["status"] == "report_supported"
    assert status_by_capability["port_security"]["status"] == "edit_proven"
    assert status_by_capability["qos"]["status"] == "edit_proven"
    assert status_by_capability["qos"]["evidence"]["donor_backed_proof"] is True
    assert status_by_capability["qos"]["evidence"]["donor_backed_proof_ready"] is False
    assert status_by_capability["qos"]["evidence"]["sample_path_count"] >= 1
    assert status_by_capability["qos"]["evidence"]["decode_verified_sample_count"] == 0
    assert status_by_capability["dot1x"]["status"] == "donor_backed_ready"
    assert status_by_capability["dot1x"]["evidence"]["donor_backed_proof_ready"] is True
    assert status_by_capability["wep"]["status"] == "edit_proven"
    assert status_by_capability["wpa_enterprise"]["status"] == "edit_proven"
    assert status_by_capability["wlc"]["status"] == "report_supported"
    assert status_by_capability["bluetooth"]["status"] == "report_supported"
    assert status_by_capability["gre"]["status"] == "edit_proven"
    assert status_by_capability["ppp"]["status"] == "edit_proven"
    assert status_by_capability["ipsec"]["status"] == "edit_proven"
    assert status_by_capability["vpn"]["status"] == "edit_proven"
    assert status_by_capability["security_edge"]["status"] == "report_supported"
    assert status_by_capability["cbac"]["status"] == "edit_proven"
    assert status_by_capability["cbac"]["evidence"]["donor_backed_proof"] is True
    assert status_by_capability["cbac"]["evidence"]["donor_backed_proof_ready"] is False
    assert status_by_capability["zfw"]["status"] == "donor_backed_ready"
    assert status_by_capability["zfw"]["evidence"]["donor_backed_proof_ready"] is True
    assert status_by_capability["asa_service_policy"]["status"] == "report_supported"
    assert status_by_capability["clientless_vpn"]["status"] == "report_supported"
    assert status_by_capability["voip"]["status"] == "donor_backed_ready"
    assert status_by_capability["ip_phone"]["status"] == "donor_backed_ready"
    assert status_by_capability["call_manager"]["status"] == "donor_backed_ready"
    assert status_by_capability["python_programming"]["status"] == "donor_backed_ready"
    assert status_by_capability["javascript_programming"]["status"] == "donor_backed_ready"
    assert status_by_capability["tcp_udp_app"]["status"] == "donor_backed_ready"
    assert status_by_capability["real_http"]["status"] == "donor_backed_ready"
    assert status_by_capability["real_http"]["evidence"]["donor_backed_proof"] is True
    assert status_by_capability["real_http"]["evidence"]["donor_backed_proof_ready"] is True
    assert status_by_capability["real_websocket"]["status"] == "donor_backed_ready"
    assert status_by_capability["real_websocket"]["evidence"]["donor_backed_proof"] is True
    assert status_by_capability["real_websocket"]["evidence"]["donor_backed_proof_ready"] is True
    assert status_by_capability["mqtt"]["status"] == "report_supported"


def test_feature_gap_report_keeps_atlas_features_below_generate_ready() -> None:
    report = build_feature_gap_report()
    for group in report["groups"]:
        for feature in group["features"]:
            assert feature["status"] != "generate_ready", feature
            assert feature["support_ceiling"] in {"inventory_known", "report_supported", "edit_proven", "donor_backed_ready"}


def test_feature_gap_report_requires_roundtrip_and_decode_for_donor_backed_ready() -> None:
    with patch("feature_atlas._editor_test_mentions", return_value=False):
        report = build_feature_gap_report()

    status_by_capability = {
        feature["capability"]: feature
        for group in report["groups"]
        for feature in group["features"]
    }

    assert status_by_capability["real_http"]["evidence"]["donor_backed_proof"] is True
    assert status_by_capability["real_http"]["evidence"]["donor_backed_proof_ready"] is False
    assert status_by_capability["real_http"]["status"] == "report_supported"
    assert status_by_capability["real_websocket"]["evidence"]["donor_backed_proof"] is True
    assert status_by_capability["real_websocket"]["evidence"]["donor_backed_proof_ready"] is False
    assert status_by_capability["real_websocket"]["status"] == "report_supported"
