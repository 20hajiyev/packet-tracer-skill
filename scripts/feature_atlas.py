from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from coverage_matrix import CAPABILITY_PROVIDER_FAMILIES
from intent_parser import CAPABILITY_PATTERNS
from sample_catalog import CAPABILITY_KEYWORDS


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FEATURE_ATLAS = ROOT / "references" / "packettracer-feature-atlas.json"
DEFAULT_SAMPLE_CATALOG = ROOT / "references" / "packettracer-sample-catalog.json"
EDITOR_TEST_PATH = ROOT / "tests" / "test_pkt_editor.py"
EDITOR_TEST_ALIASES = {
    "ipv6_slaac": ["set_ipv6_slaac", "slaac on"],
    "dhcpv6_stateful": ["set_dhcpv6_pool", "dhcpv6 pool"],
    "ospfv3": ["set_ospfv3_interface", "ospfv3"],
    "eigrp_ipv6": ["set_eigrp_ipv6_interface", "eigrp ipv6"],
    "ripng": ["set_ripng_interface", "ripng"],
    "hsrp": ["set_hsrp_ipv6", "hsrp"],
    "dhcp_snooping": ["set_dhcp_snooping", "dhcp snooping"],
    "dai": ["set_dai", "dynamic arp inspection"],
    "lldp": ["set_lldp", "lldp enable"],
    "rep": ["set_rep", "rep segment"],
    "snmp": ["set_snmp_community", "snmp community"],
    "netflow": ["set_netflow", "netflow destination"],
    "span": ["set_span", "monitor session"],
    "port_security": ["set_port_security", "port-security"],
    "wep": ["security wep", "WEP_KEY"],
    "wpa_enterprise": ["wpa-enterprise", "wpa2-enterprise", "802.1x", "radius_server"],
    "gre": ["set_gre_tunnel", "gre tunnel", "tunnel mode gre ip"],
    "ppp": ["set_ppp_interface", "encapsulation ppp"],
    "ipsec": ["set_ipsec_transform_set", "crypto ipsec transform-set", "set_crypto_map"],
    "vpn": ["set_crypto_map", "crypto map"],
    "real_http": ["set_script_file_content", "realhttp", "real http"],
    "real_websocket": ["set_script_file_content", "realws", "websocket"],
    "python_programming": ["set_script_file_content", "main.py", "python"],
    "javascript_programming": ["set_script_file_content", "main.js", "javascript"],
}

STATUS_ORDER = [
    "not_mapped",
    "inventory_known",
    "report_supported",
    "edit_proven",
    "donor_backed_ready",
    "generate_ready",
]
STATUS_RANK = {status: index for index, status in enumerate(STATUS_ORDER)}


def load_feature_atlas(path: Path = DEFAULT_FEATURE_ATLAS) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_sample_catalog(path: Path = DEFAULT_SAMPLE_CATALOG) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("samples", "items"):
            items = payload.get(key)
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
    return []


def _status_at_most(status: str, ceiling: str) -> str:
    if STATUS_RANK[status] <= STATUS_RANK[ceiling]:
        return status
    return ceiling


def _sample_matches(feature: dict[str, Any], sample: dict[str, Any]) -> bool:
    rel = str(sample.get("relative_path") or "").replace("\\", "/").lower()
    tags = {str(tag).lower() for tag in sample.get("capability_tags", [])}
    capability = str(feature.get("capability") or feature.get("id") or "").lower()
    if capability in tags:
        return True
    for keyword in feature.get("sample_path_keywords", []):
        if str(keyword).lower() in rel:
            return True
    return False


def _sample_hits(feature: dict[str, Any], samples: list[dict[str, Any]]) -> list[str]:
    hits: list[str] = []
    for sample in samples:
        if _sample_matches(feature, sample):
            rel = str(sample.get("relative_path") or "")
            if rel:
                hits.append(rel)
    return sorted(dict.fromkeys(hits))


def _decoded_sample_hits(feature: dict[str, Any], samples: list[dict[str, Any]]) -> list[str]:
    hits: list[str] = []
    for sample in samples:
        if not _sample_matches(feature, sample):
            continue
        if not str(sample.get("version") or "").strip():
            continue
        rel = str(sample.get("relative_path") or "")
        if rel:
            hits.append(rel)
    return sorted(dict.fromkeys(hits))


def _editor_test_mentions(capability: str) -> bool:
    if not EDITOR_TEST_PATH.exists():
        return False
    text = EDITOR_TEST_PATH.read_text(encoding="utf-8").lower()
    needles = [capability.lower(), *[alias.lower() for alias in EDITOR_TEST_ALIASES.get(capability, [])]]
    return any(needle in text for needle in needles)


def _feature_status(feature: dict[str, Any], evidence: dict[str, Any]) -> str:
    capability = str(feature.get("capability") or feature.get("id") or "")
    ceiling = str(feature.get("support_ceiling") or "report_supported")
    if evidence["editor_roundtrip_test"]:
        raw_status = "edit_proven"
    elif evidence["parser_pattern"] and (evidence["sample_count"] or evidence["catalog_keyword"] or evidence["coverage_provider"]):
        raw_status = "report_supported"
    elif evidence["sample_count"] or evidence["catalog_keyword"] or evidence["coverage_provider"]:
        raw_status = "inventory_known"
    else:
        raw_status = "not_mapped"
    if capability in {"vlan", "trunk", "access_port", "router_on_a_stick", "management_vlan", "telnet", "acl", "dhcp_pool"}:
        raw_status = "generate_ready"
    return _status_at_most(raw_status, ceiling)


def _next_safe_action(status: str, feature: dict[str, Any]) -> str:
    label = str(feature.get("label") or feature.get("id"))
    if status == "not_mapped":
        return f"Add parser/catalog recognition for {label}, then keep it report-only until donor evidence exists."
    if status == "inventory_known":
        return f"Add prompt parsing and scenario-family report coverage for {label}."
    if status == "report_supported":
        return f"Keep {label} report-only; add donor-backed proof before edit/generate readiness."
    if status == "edit_proven":
        return f"Promote {label} only after selected-donor and acceptance fixture coverage exists."
    if status == "donor_backed_ready":
        return f"Add constrained acceptance fixtures before claiming broad generate for {label}."
    return f"Keep regression coverage for {label}."


def build_feature_gap_report(
    atlas_path: Path = DEFAULT_FEATURE_ATLAS,
    sample_catalog_path: Path = DEFAULT_SAMPLE_CATALOG,
) -> dict[str, Any]:
    atlas = load_feature_atlas(atlas_path)
    samples = load_sample_catalog(sample_catalog_path)
    groups: list[dict[str, Any]] = []
    status_counts = {status: 0 for status in STATUS_ORDER}
    total_features = 0
    mapped_features = 0
    sample_feature_count = 0

    for group in atlas.get("feature_groups", []):
        group_features: list[dict[str, Any]] = []
        group_status_counts = {status: 0 for status in STATUS_ORDER}
        for feature in group.get("features", []):
            total_features += 1
            capability = str(feature.get("capability") or feature.get("id") or "")
            hits = _sample_hits(feature, samples)
            decoded_hits = _decoded_sample_hits(feature, samples)
            evidence = {
                "parser_pattern": capability in CAPABILITY_PATTERNS,
                "catalog_keyword": capability in CAPABILITY_KEYWORDS,
                "coverage_provider": capability in CAPABILITY_PROVIDER_FAMILIES,
                "editor_roundtrip_test": _editor_test_mentions(capability),
                "sample_count": len(hits),
                "sample_examples": hits[:5],
                "sample_path_count": len(hits),
                "decode_verified_sample_count": len(decoded_hits),
                "decode_verified_examples": decoded_hits[:5],
            }
            status = _feature_status(feature, evidence)
            if status != "not_mapped":
                mapped_features += 1
            if hits:
                sample_feature_count += 1
            status_counts[status] += 1
            group_status_counts[status] += 1
            group_features.append(
                {
                    "id": feature.get("id"),
                    "capability": capability,
                    "label": feature.get("label"),
                    "status": status,
                    "support_ceiling": feature.get("support_ceiling", "report_supported"),
                    "evidence": evidence,
                    "next_safe_action": _next_safe_action(status, feature),
                }
            )
        groups.append(
            {
                "id": group.get("id"),
                "label": group.get("label"),
                "scenario_family": group.get("scenario_family"),
                "wave": group.get("wave"),
                "status_counts": group_status_counts,
                "features": group_features,
            }
        )

    missing_groups = sorted(
        (
            {
                "id": group["id"],
                "label": group["label"],
                "not_generate_ready_count": sum(
                    count for status, count in group["status_counts"].items() if status != "generate_ready"
                ),
            }
            for group in groups
        ),
        key=lambda item: (-int(item["not_generate_ready_count"]), str(item["id"])),
    )

    return {
        "atlas_version": atlas.get("atlas_version", "unknown"),
        "target_packet_tracer_version": atlas.get("target_packet_tracer_version", "unknown"),
        "support_policy": atlas.get("support_policy", ""),
        "status_contract": STATUS_ORDER,
        "packet_tracer_sample_count": len(samples),
        "total_feature_count": total_features,
        "mapped_feature_count": mapped_features,
        "unmapped_feature_count": total_features - mapped_features,
        "sample_backed_feature_count": sample_feature_count,
        "status_counts": status_counts,
        "top_missing_feature_families": missing_groups[:8],
        "groups": groups,
    }
