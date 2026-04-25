#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

from coverage_matrix import (
    BlueprintPlan,
    CoverageGapReport,
    _expanded_sample_capabilities,
    asdict_list as coverage_asdict_list,
    build_blueprint_plan,
    build_capability_matrix,
    build_coverage_gap_report,
    build_donor_graph_fit,
    build_inventory_capability_report,
    select_capability_matrix_hits,
)
from feature_atlas import build_feature_gap_report
from intent_parser import IntentPlan, parse_intent
from packet_tracer_env import (
    get_packet_tracer_compatibility_donor,
    inspect_packet_tracer_compatibility_donor,
    require_packet_tracer_exe,
)
from pkt_builder import build_packet_tracer_xml
from pkt_codec import decode_pkt_file, decode_pkt_modern, encode_pkt_modern
from pkt_editor import apply_plan_operations, decode_pkt_to_root, edit_pkt_file, inventory_devices, inventory_links, inventory_root
from pkt_transformer import transform_from_blueprint
from remote_search import asdict_list as remote_asdict_list, auto_import_remote_candidates, search_remote_candidates
from sample_catalog import ReferencePattern, SampleCandidate, SampleDescriptor, load_catalog, load_curated_donor_catalog, load_reference_catalog, summarize_pkt_descriptor
from sample_selector import rank_curated_donor_samples, rank_reference_samples, rank_samples, select_best_sample
from workspace_repair import inspect_donor_coherence, inspect_workspace_integrity, validate_donor_coherence, validate_workspace_integrity

FIXTURE_CORPUS_PATH = Path(__file__).resolve().parents[1] / "references" / "scenario-fixture-corpus.json"
RUNTIME_CLEANUP_MODE = "donor_preserve_runtime"
SAFE_OPEN_COMPATIBILITY_MODE = "safe_open_strict_9_0"
PRESERVED_VISUAL_SECTIONS = [
    "FILTERS",
    "CLUSTERS",
    "GEOVIEW_GRAPHICSITEMS",
    "RECTANGLES",
    "ELLIPSES",
    "POLYGONS",
    "PHYSICALWORKSPACE/NOTES",
    "ANSWER_TREE_SELECTED",
    "PHYSICALALIGN",
    "HIDEPHYSICAL",
    "CABLE_POPUP_IN_PHYSICAL",
]
CLEANED_SCENARIO_SECTIONS: list[str] = []
PRESERVED_SCENARIO_SECTIONS = [
    "SCENARIOSET",
    "COMMAND_LOGS",
    "CEPS",
]
NEUTRALIZED_VISUAL_SECTIONS = [
    "RECTANGLES",
    "ELLIPSES",
    "POLYGONS",
    "PHYSICALWORKSPACE/NOTES",
]
OFFSCREEN_X = 50000
OFFSCREEN_Y = 50000

DEVICE_FAMILY_MAP = {
    "Router": "routers",
    "Switch": "switches",
    "MultiLayerSwitch": "multilayer switches",
    "Server": "servers",
    "PC": "end devices",
    "Laptop": "end devices",
    "Tablet": "end devices",
    "Smartphone": "end devices",
    "Printer": "end devices",
    "LightWeightAccessPoint": "access points",
    "WirelessRouter": "home/wireless routers",
    "WirelessRouterNewGeneration": "home/wireless routers",
    "HomeGateway": "home/wireless routers",
    "WirelessLanController": "access points",
    "Power Distribution Device": "pt-specific edge/utility devices",
    "Cloud": "wan/cloud/dsl/cable devices",
    "Cable Modem": "wan/cloud/dsl/cable devices",
    "Dsl Modem": "wan/cloud/dsl/cable devices",
    "Security Appliance": "security devices",
    "ASA": "security devices",
    "IoT": "iot devices",
    "Board": "iot devices",
    "Sensor": "iot devices",
    "Actuator": "iot devices",
    "MCUComponent": "iot devices",
}


if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


class PlanningError(RuntimeError):
    def __init__(self, message: str, plan: IntentPlan) -> None:
        super().__init__(message)
        self.plan = plan

    def to_dict(self) -> dict[str, object]:
        return {
            "error": str(self),
            "blocking_gaps": self.plan.blocking_gaps,
            "parse_warnings": self.plan.parse_warnings,
            "device_requirements": self.plan.device_requirements,
            "vlan_ids": self.plan.vlan_ids,
            "topology_requirements": self.plan.topology_requirements,
            "compatibility_profile": self.plan.compatibility_profile,
            "unsafe_mutations_requested": self.plan.unsafe_mutations_requested,
            "blocked_mutations": self.plan.blocked_mutations,
            "acceptance_stage_plan": self.plan.acceptance_stage_plan,
            "capability_matrix_hits": self.plan.capability_matrix_hits,
            "unsupported_capabilities": self.plan.unsupported_capabilities,
            "coverage_gap_report": self.plan.coverage_gap_report,
            "blueprint_plan": self.plan.blueprint_plan,
            "remote_search_results": self.plan.remote_search_results,
        }


STRICT_COMPATIBILITY_GAP = (
    "Strict 9.0 generation requires a compatible Packet Tracer 9.0 donor lab. "
    "Set PACKET_TRACER_COMPAT_DONOR explicitly, let the repo auto-detect one, or provide --donor-root with validated local donor labs."
)


def _compat_donor_details() -> tuple[Path | None, str | None]:
    details = inspect_packet_tracer_compatibility_donor()
    return details.resolved_path, details.donor_version


def _existing_ranked_candidates(ranked: list[SampleCandidate]) -> list[SampleCandidate]:
    return [candidate for candidate in ranked if Path(candidate.sample.path).exists()]


def _compat_donor_candidate() -> SampleCandidate | None:
    compat_donor, compat_donor_version = _compat_donor_details()
    if compat_donor is None or not compat_donor.exists():
        return None
    sample = summarize_pkt_descriptor(
        compat_donor,
        relative_path=compat_donor.name,
        origin="compat-donor",
        prototype_eligible=True,
        trust_level="trusted",
        role="compatibility",
        license_or_permission="local-user",
        promotion_status="validated_compat",
        validation_status="validated",
        donor_eligible=True,
    )
    if compat_donor_version:
        sample.version = compat_donor_version
        sample.packet_tracer_version = compat_donor_version
    return SampleCandidate(
        sample=sample,
        capability_score=100,
        topology_score=0,
        total_score=100,
        reasons=["compatibility-donor"],
    )


def _rank_generation_donors(
    plan: IntentPlan,
    topology_tags: list[str],
    donor_roots: list[Path] | None = None,
) -> tuple[list[SampleCandidate], list[SampleCandidate], list[SampleCandidate]]:
    requested_services = [str(service) for service in plan.service_requirements.get("services", []) if service]
    preferred_archetypes = _preferred_donor_archetypes_for_plan(plan, topology_tags)
    required_fixtures = _required_acceptance_fixtures_for_plan(
        "wan_security_edge"
        if "WAN/security edge" in preferred_archetypes
        else "home_iot"
        if "IoT/home gateway" in preferred_archetypes
        else "service_heavy"
        if "service-heavy" in preferred_archetypes and "campus/core" not in preferred_archetypes
        else "campus"
        if "campus/core" in preferred_archetypes
        else None
    )
    required_runtime_features = _required_runtime_features_for_plan(plan)
    cisco_ranked = _existing_ranked_candidates(
        rank_samples(
            load_catalog(),
            plan.capabilities,
            plan.device_requirements,
            topology_tags=topology_tags,
            prototype_only=True,
            wireless_mode=plan.wireless_mode,
            requested_services=requested_services,
            required_acceptance_fixtures=required_fixtures,
            required_runtime_features=required_runtime_features,
        )
    )
    curated_ranked = _existing_ranked_candidates(
        rank_curated_donor_samples(
            load_curated_donor_catalog(donor_roots),
            plan.capabilities,
            plan.device_requirements,
            topology_tags=topology_tags,
            wireless_mode=plan.wireless_mode,
            requested_services=requested_services,
            required_acceptance_fixtures=required_fixtures,
            required_runtime_features=required_runtime_features,
        )
    )
    ordered: list[SampleCandidate] = []
    seen_paths: set[str] = set()
    for bucket in [[candidate] if (candidate := _compat_donor_candidate()) is not None else [], cisco_ranked, curated_ranked]:
        for donor_candidate in bucket:
            key = str(Path(donor_candidate.sample.path).resolve()).lower()
            if key in seen_paths:
                continue
            seen_paths.add(key)
            ordered.append(donor_candidate)
    return cisco_ranked, curated_ranked, ordered


def _default_import_cache_root() -> Path:
    return Path(__file__).resolve().parents[1] / "output" / "remote-import-cache"


def _resolve_remote_sources(
    plan: IntentPlan,
    reference_roots: list[Path] | None,
    donor_roots: list[Path] | None,
    *,
    search_remote: bool = False,
    remote_provider: str = "github",
    import_cache_root: Path | None = None,
    max_remote_results: int = 10,
) -> tuple[list[Path], list[Path], list[dict[str, object]]]:
    resolved_reference_roots = list(reference_roots or [])
    resolved_donor_roots = list(donor_roots or [])
    if not search_remote:
        return resolved_reference_roots, resolved_donor_roots, []
    remote_candidates = search_remote_candidates(plan, provider=remote_provider, max_results=max_remote_results)
    cache_root = import_cache_root or _default_import_cache_root()
    imported_candidates = auto_import_remote_candidates(remote_candidates, cache_root, max_results=max_remote_results)
    for candidate in imported_candidates:
        if candidate.path:
            imported_root = Path(candidate.path)
            if imported_root not in resolved_reference_roots:
                resolved_reference_roots.append(imported_root)
            if imported_root not in resolved_donor_roots:
                resolved_donor_roots.append(imported_root)
    return resolved_reference_roots, resolved_donor_roots, remote_asdict_list(imported_candidates)


def _candidate_to_dict(candidate: SampleCandidate, blueprint: dict[str, object] | None = None) -> dict[str, object]:
    donor_graph_fit = build_donor_graph_fit(candidate.sample, blueprint)
    donor_graph_summary = _donor_graph_fit_summary(donor_graph_fit, blueprint)
    acceptance_penalty, acceptance_risk_reasons = _candidate_acceptance_penalty(candidate, blueprint)
    preferred_archetypes = [str(item) for item in list((blueprint or {}).get("preferred_donor_archetypes", [])) if item]
    archetype_match_score, archetype_reasons, sample_archetypes = _candidate_archetype_alignment(
        candidate.sample,
        preferred_archetypes,
    )
    return {
        "relative_path": candidate.sample.relative_path,
        "origin": candidate.sample.origin,
        "license_or_permission": candidate.sample.license_or_permission,
        "promotion_status": candidate.sample.promotion_status,
        "evidence_source": candidate.sample.evidence_source,
        "promotion_evidence": candidate.sample.promotion_evidence,
        "validation_status": candidate.sample.validation_status,
        "validated_edit_capabilities": candidate.sample.validated_edit_capabilities,
        "acceptance_notes": candidate.sample.acceptance_notes,
        "acceptance_fixtures": candidate.sample.acceptance_fixtures,
        "provenance": candidate.sample.provenance,
        "workspace_validation": candidate.sample.workspace_validation_status,
        "wireless_mode_tags": candidate.sample.wireless_mode_tags,
        "archetype_tags": candidate.sample.archetype_tags,
        "device_families": candidate.sample.device_families,
        "service_support": candidate.sample.service_support,
        "runtime_features": candidate.sample.runtime_features,
        "apply_safety_level": candidate.sample.apply_safety_level,
        "total_score": candidate.total_score,
        "capability_score": candidate.capability_score,
        "topology_score": candidate.topology_score,
        "reasons": candidate.reasons[:8],
        "donor_graph_fit": asdict(donor_graph_fit),
        "donor_graph_summary": donor_graph_summary,
        "preferred_donor_archetypes": preferred_archetypes,
        "sample_archetypes": sample_archetypes,
        "archetype_match_score": archetype_match_score,
        "archetype_match_reasons": archetype_reasons,
        "acceptance_penalty": acceptance_penalty,
        "acceptance_risk_reasons": acceptance_risk_reasons,
        "adjusted_total_score": candidate.total_score - acceptance_penalty,
    }


def _sample_device_families(sample: SampleDescriptor) -> list[str]:
    if sample.device_families:
        return sample.device_families
    families = {
        DEVICE_FAMILY_MAP.get(str(device.get("type", "")), "pt-specific edge/utility devices")
        for device in sample.devices
        if device.get("type")
    }
    return sorted(families)


def _preferred_donor_archetypes_for_plan(plan: IntentPlan, topology_tags: list[str] | None = None) -> list[str]:
    preferred: list[str] = []
    requested_services = {str(service) for service in plan.service_requirements.get("services", []) if service}
    device_families = {
        DEVICE_FAMILY_MAP.get(device_type, "pt-specific edge/utility devices")
        for device_type, count in plan.device_requirements.items()
        if count
    }
    capabilities = set(plan.capabilities)
    tags = set(topology_tags or [])
    prompt_lower = str(plan.prompt or "").lower()
    explicit_home_gateway_prompt = any(
        token in prompt_lower
        for token in ["home gateway", "homegateway", "smart home", "iot "]
    )
    family_hints: list[str] = []
    campus_signal = (
        plan.network_style == "campus"
        or "campus" in prompt_lower
        or "kampus" in prompt_lower
        or bool(plan.department_groups)
        or bool(tags & {"chain", "core_access", "router_on_a_stick", "acl_policy"})
        or bool(
            device_families & {"routers", "switches", "multilayer switches"}
            and capabilities & {"vlan", "router_on_a_stick", "management_vlan", "telnet", "acl", "trunk", "access_port"}
        )
    )
    home_iot_signal = (
        plan.network_style in {"home_iot", "smart_home"}
        or explicit_home_gateway_prompt
        or plan.wireless_mode == "home_router_edge"
        or bool(capabilities & {"iot", "iot_registration", "iot_control"})
        or bool("iot devices" in device_families)
    )
    wan_signal = (
        plan.network_style == "wan_security"
        or bool(device_families & {"wan/cloud/dsl/cable devices", "security devices"})
        or bool(capabilities & {"vpn", "ipsec", "gre", "ppp", "multilayer_switching", "security_edge"})
    )
    ipv6_routing_signal = plan.network_style == "ipv6_routing" or bool(capabilities & {"ipv6_slaac", "dhcpv6_stateful", "dhcpv6_stateless", "ipv6_prefix_delegation", "ipv6_dns_aaaa", "ipv6_tunneling", "isatap", "ospfv3", "eigrp_ipv6", "ripng", "hsrp"})
    l2_security_monitoring_signal = plan.network_style == "l2_security_monitoring" or bool(capabilities & {"dhcp_snooping", "dai", "dot1x", "lldp", "rep", "snmp", "netflow", "span", "qos", "port_security"})
    wireless_advanced_signal = plan.network_style == "wireless_advanced" or bool(capabilities & {"wlc", "wpa_enterprise", "wep", "guest_wifi", "beamforming", "meraki", "cellular_5g", "bluetooth"})
    automation_controller_signal = plan.network_style == "automation_controller" or bool(capabilities & {"network_controller", "python_programming", "javascript_programming", "blockly_programming", "tcp_udp_app", "vm_iox"})
    voice_collaboration_signal = plan.network_style == "voice_collaboration" or bool(capabilities & {"voip", "ip_phone", "call_manager", "linksys_voice"})
    industrial_iot_signal = plan.network_style == "industrial_iot" or bool(capabilities & {"mqtt", "real_http", "real_websocket", "visual_scripting", "ptp", "profinet", "l2nat", "cyberobserver", "industrial_firewall"})
    wireless_signal = plan.wireless_mode or capabilities & {
        "wireless_ap",
        "wireless_client",
        "wireless_mutation",
        "wireless_client_association",
    }
    service_signal = (
        requested_services & {"dns", "dhcp", "http", "https", "ftp", "tftp", "email", "syslog", "aaa", "ntp"}
        or capabilities & {"server_dns", "server_dhcp", "server_http", "server_https", "server_ftp", "server_tftp", "server_email", "server_syslog", "server_aaa"}
        or "servers" in device_families
    )

    if industrial_iot_signal:
        family_hints.append("industrial IoT")
    elif automation_controller_signal:
        family_hints.append("automation/controller")
    elif voice_collaboration_signal:
        family_hints.append("voice/collaboration")
    elif wireless_advanced_signal:
        family_hints.append("advanced wireless")
    elif l2_security_monitoring_signal:
        family_hints.append("L2 security/monitoring")
    elif ipv6_routing_signal:
        family_hints.append("IPv6/routing")
    elif wan_signal:
        family_hints.append("WAN/security edge")
        if campus_signal and not bool(capabilities & {"vpn", "ipsec", "gre", "ppp", "security_edge"}):
            family_hints.append("campus/core")
    elif campus_signal:
        family_hints.append("campus/core")
        if wireless_signal:
            family_hints.append("wireless-heavy")
        if service_signal and requested_services & {"email", "syslog", "aaa", "http", "https", "ftp", "tftp"}:
            family_hints.append("service-heavy")
    elif home_iot_signal:
        family_hints.append("IoT/home gateway")
        if wireless_signal:
            family_hints.append("wireless-heavy")
    elif service_signal:
        family_hints.append("service-heavy")
    elif wireless_signal:
        family_hints.append("wireless-heavy")

    if not family_hints:
        if service_signal:
            family_hints.append("service-heavy")
        if wireless_signal:
            family_hints.append("wireless-heavy")
        if home_iot_signal:
            family_hints.append("IoT/home gateway")
        if wan_signal:
            family_hints.append("WAN/security edge")

    for item in family_hints:
        if item not in preferred:
            preferred.append(item)
    return preferred


def _required_runtime_features_for_plan(plan: IntentPlan) -> list[str]:
    features = {"workspace_validated"}
    capabilities = set(plan.capabilities)
    if capabilities & {"server_http", "server_https", "server_ftp", "server_tftp", "server_email", "server_syslog", "server_aaa", "server_dns", "server_dhcp", "ntp"}:
        features.add("server_runtime")
    if capabilities & {"wireless_ap", "wireless_mutation", "wireless_client_association"}:
        features.add("wireless_runtime")
    if capabilities & {"iot", "iot_registration", "iot_control"}:
        features.add("iot_runtime")
    if capabilities & {"vpn", "ipsec", "gre"}:
        features.add("tunnel_runtime")
    if capabilities & {"ppp"}:
        features.add("wan_runtime")
    if capabilities & {"security_edge", "acl", "nat"}:
        features.add("security_runtime")
    if capabilities & {"multilayer_switching"}:
        features.add("multilayer_runtime")
    if capabilities & {"ipv6_slaac", "dhcpv6_stateful", "dhcpv6_stateless", "ospfv3", "eigrp_ipv6", "ripng", "hsrp"}:
        features.add("ipv6_runtime")
    return sorted(features)


def _sample_archetypes(sample: SampleDescriptor) -> list[str]:
    families = set(_sample_device_families(sample))
    capabilities = set(_expanded_sample_capabilities(sample, list(families)))
    topology_tags = set(sample.topology_tags)
    archetypes: list[str] = []
    if topology_tags & {"chain", "core_access", "department_lan", "router_on_a_stick"} or (
        families & {"routers", "switches", "multilayer switches"}
        and capabilities & {"vlan", "router_on_a_stick", "management_vlan", "telnet"}
    ):
        archetypes.append("campus/core")
    if sample.service_support or "servers" in families or "server_services" in topology_tags:
        archetypes.append("service-heavy")
    if sample.wireless_mode_tags or families & {"access points", "home/wireless routers"}:
        archetypes.append("wireless-heavy")
    if sample.iot_roles or "iot devices" in families or "HomeGateway" in sample.model_families:
        archetypes.append("IoT/home gateway")
    if families & {"wan/cloud/dsl/cable devices", "security devices"} or capabilities & {"vpn", "nat", "pat", "acl"}:
        archetypes.append("WAN/security edge")
    return archetypes


def _candidate_archetype_alignment(
    sample: SampleDescriptor,
    preferred_archetypes: list[str],
) -> tuple[int, list[str], list[str]]:
    sample_archetypes = _sample_archetypes(sample)
    matches = [item for item in preferred_archetypes if item in sample_archetypes]
    score = len(matches) * 9
    reasons = [f"archetype:{item}" for item in matches]
    return score, reasons, sample_archetypes


def _build_support_reports(
    plan: IntentPlan,
    *,
    blueprint: dict[str, object] | None = None,
    cisco_ranked: list[SampleCandidate] | None = None,
    curated_ranked: list[SampleCandidate] | None = None,
    reference_catalog: list[SampleDescriptor] | None = None,
    selected_donor: str | None = None,
) -> tuple[list[dict[str, object]], dict[str, object], dict[str, object]]:
    samples: list[SampleDescriptor] = []
    for bucket in [cisco_ranked or [], curated_ranked or []]:
        for candidate in bucket:
            samples.append(candidate.sample)
    for sample in reference_catalog or []:
        samples.append(sample)
    matrix_entries = coverage_asdict_list(select_capability_matrix_hits(plan, samples))
    coverage_gap = asdict(build_coverage_gap_report(plan, samples, selected_donor=selected_donor))
    blueprint_plan = asdict(build_blueprint_plan(plan, blueprint))
    return matrix_entries, coverage_gap, blueprint_plan


def _candidate_acceptance_penalty(candidate: SampleCandidate, blueprint: dict[str, object] | None) -> tuple[int, list[str]]:
    if blueprint is None:
        return 0, []
    fit = build_donor_graph_fit(candidate.sample, blueprint)
    penalty = 0
    reasons: list[str] = []
    requested_capabilities = {str(item) for item in list(blueprint.get("capabilities", []))}
    supported_capabilities = set(_expanded_sample_capabilities(candidate.sample, _sample_device_families(candidate.sample)))
    preferred_archetypes = [str(item) for item in list(blueprint.get("preferred_donor_archetypes", [])) if item]
    archetype_score, _, sample_archetypes = _candidate_archetype_alignment(candidate.sample, preferred_archetypes)
    if fit.missing_pairs:
        penalty += len(fit.missing_pairs) * 20
        reasons.append(f"missing_link_pairs:{len(fit.missing_pairs)}")
    if fit.port_media_conflicts:
        penalty += len(fit.port_media_conflicts) * 12
        reasons.append(f"port_media_conflicts:{len(fit.port_media_conflicts)}")
    for capability, penalty_value in {
        "wireless_mutation": 18,
        "wireless_client_association": 22,
        "end_device_mutation": 12,
        "iot_registration": 26,
        "iot_control": 24,
        "vpn": 22,
        "ipsec": 22,
        "gre": 20,
        "ppp": 18,
        "security_edge": 20,
        "multilayer_switching": 16,
        "ipv6_slaac": 18,
        "dhcpv6_stateful": 18,
        "ospfv3": 18,
        "eigrp_ipv6": 18,
        "ripng": 16,
        "hsrp": 16,
    }.items():
        if capability in requested_capabilities and capability not in supported_capabilities:
            penalty += penalty_value
            reasons.append(f"capability_gap:{capability}")
    if candidate.sample.apply_safety_level not in {"safe-open-generate-supported", "acceptance-verified"}:
        penalty += 15
        reasons.append(f"apply_safety:{candidate.sample.apply_safety_level}")
    if preferred_archetypes and not archetype_score:
        penalty += 8
        reasons.append(f"archetype_gap:{','.join(sample_archetypes) if sample_archetypes else 'none'}")
    return penalty, reasons


def _donor_graph_fit_summary(fit, blueprint: dict[str, object] | None = None) -> dict[str, object]:
    required_pair_count = len(list((blueprint or {}).get("links", [])))
    effective_required_pairs = len(fit.matched_pairs) + len(fit.missing_pairs)
    if effective_required_pairs:
        required_pair_count = effective_required_pairs
    reusable_pair_count = len(fit.matched_pairs)
    missing_pair_count = len(fit.missing_pairs)
    conflict_count = len(fit.port_media_conflicts)
    if required_pair_count <= 0:
        reusable_pair_coverage = 100
    else:
        reusable_pair_coverage = int(round((reusable_pair_count / required_pair_count) * 100))
    if required_pair_count <= 0:
        layout_reuse_status = "not_applicable"
    elif missing_pair_count == 0 and conflict_count == 0:
        layout_reuse_status = "strong"
    elif reusable_pair_count > 0 and reusable_pair_coverage >= 50 and conflict_count <= reusable_pair_count:
        layout_reuse_status = "partial"
    else:
        layout_reuse_status = "weak"
    return {
        "required_pair_count": required_pair_count,
        "reusable_pair_count": reusable_pair_count,
        "missing_pair_count": missing_pair_count,
        "conflict_count": conflict_count,
        "reusable_pair_coverage": reusable_pair_coverage,
        "layout_reuse_status": layout_reuse_status,
    }


def _summarize_candidate_pool(
    diagnostics: list[dict[str, object]],
    preferred_archetypes: list[str] | None = None,
) -> dict[str, object]:
    counts = {"selected": 0, "rejected": 0, "filtered": 0}
    top_rejection_reasons: list[str] = []
    best_adjusted_score: int | None = None
    best_layout_reuse_score: int | None = None
    for item in diagnostics:
        status = str(item.get("status", "")).strip()
        if status in counts:
            counts[status] += 1
        adjusted_total_score = item.get("adjusted_total_score")
        if isinstance(adjusted_total_score, int):
            best_adjusted_score = adjusted_total_score if best_adjusted_score is None else max(best_adjusted_score, adjusted_total_score)
        donor_graph_fit = item.get("donor_graph_fit", {})
        layout_reuse_score = donor_graph_fit.get("layout_reuse_score")
        if isinstance(layout_reuse_score, int):
            best_layout_reuse_score = layout_reuse_score if best_layout_reuse_score is None else max(best_layout_reuse_score, layout_reuse_score)
        for reason in item.get("rejection_reasons", []):
            normalized = str(reason).strip()
            if normalized and normalized not in top_rejection_reasons:
                top_rejection_reasons.append(normalized)
            if len(top_rejection_reasons) >= 5:
                break
        if len(top_rejection_reasons) >= 5:
            continue
    primary_rejection_code = _primary_rejection_code(top_rejection_reasons)
    primary_rejection_layer = _primary_rejection_layer(primary_rejection_code)
    best_rejected_donor_class = (
        next((str(item) for item in list(preferred_archetypes or []) if str(item).strip()), None)
        if any(counts[key] > 0 for key in ("rejected", "filtered"))
        else None
    )
    return {
        "preferred_donor_archetypes": list(preferred_archetypes or []),
        "candidate_counts": counts,
        "best_adjusted_total_score": best_adjusted_score,
        "best_layout_reuse_score": best_layout_reuse_score,
        "top_rejection_reasons": top_rejection_reasons,
        "best_rejected_donor_class": best_rejected_donor_class,
        "primary_rejection_code": primary_rejection_code,
        "primary_rejection_layer": primary_rejection_layer,
    }


def _primary_rejection_code(rejection_reasons: list[str]) -> str | None:
    normalized = [str(item).strip().lower() for item in rejection_reasons if str(item).strip()]
    if any("runtime subtree" in reason for reason in normalized):
        return "runtime_subtree_missing"
    if any("archetype_gap:" in reason or "archetype does not align" in reason for reason in normalized):
        return "archetype_misaligned"
    if any(
        marker in reason
        for reason in normalized
        for marker in (
            "missing_link_pairs:",
            "no reusable link pairs",
            "reuses too little of the requested link skeleton",
            "cannot create new donor link pair",
            "requires donor link reuse",
            "port mismatch",
            "media mismatch",
            "ports/media",
        )
    ):
        return "layout_reuse_too_weak"
    if any(
        marker in reason
        for reason in normalized
        for marker in (
            "acceptance penalty",
            "acceptance_gated",
            "acceptance-gated",
            "acceptance fixture",
            "acceptance evidence",
            "acceptance risk",
        )
    ):
        return "acceptance_evidence_too_weak"
    return None


def _primary_rejection_layer(primary_rejection_code: str | None) -> str | None:
    if primary_rejection_code == "acceptance_evidence_too_weak":
        return "acceptance"
    if primary_rejection_code in {
        "layout_reuse_too_weak",
        "archetype_misaligned",
        "runtime_subtree_missing",
    }:
        return "donor"
    return None


def _best_rejected_donor_summary(
    best_rejected_donor_class: str | None,
    primary_rejection_code: str | None,
    top_rejection_reasons: list[str],
) -> str | None:
    if not best_rejected_donor_class and not primary_rejection_code:
        return None
    reason_sentence_map = {
        "layout_reuse_too_weak": "its reusable link skeleton is still too weak for the requested topology",
        "acceptance_evidence_too_weak": "its acceptance evidence is still too weak for prompt-level generate",
        "archetype_misaligned": "its donor shape does not align with the requested scenario archetype",
        "runtime_subtree_missing": "the required runtime subtree is missing from the donor path",
    }
    next_shape_map = {
        "layout_reuse_too_weak": "choose a donor with the same family but a stronger reusable router-switch-service skeleton",
        "acceptance_evidence_too_weak": "choose a donor with explicit acceptance-backed coverage for the same scenario family",
        "archetype_misaligned": "choose a donor whose archetype already matches the requested family",
        "runtime_subtree_missing": "choose a donor that already contains the required runtime subtree and open-state structure",
    }
    donor_class = best_rejected_donor_class or "the closest donor class"
    reason = reason_sentence_map.get(primary_rejection_code or "", "it still did not satisfy strict donor selection")
    next_shape = next_shape_map.get(primary_rejection_code or "", "choose a closer donor before prompt generate")
    if donor_class == "WAN/security edge":
        wan_next_shape_map = {
            "layout_reuse_too_weak": "choose a WAN/security donor with reusable ASA/cloud/serial or tunnel skeleton",
            "acceptance_evidence_too_weak": "choose a WAN/security donor with explicit VPN/IPSec/GRE/PPP acceptance evidence",
            "archetype_misaligned": "choose a donor already tagged as WAN/security edge",
            "runtime_subtree_missing": "choose a donor that already contains the WAN/security runtime subtree",
        }
        next_shape = wan_next_shape_map.get(primary_rejection_code or "", "choose a closer WAN/security donor before prompt generate")
    summary = f"Best rejected donor class {donor_class} was closest, but {reason}; {next_shape}."
    if top_rejection_reasons:
        summary = f"{summary} Top rejection signal: {top_rejection_reasons[0]}."
    return summary


def _load_fixture_corpus() -> dict[str, object]:
    if not FIXTURE_CORPUS_PATH.exists():
        return {"fixture_registry_version": "missing", "fixtures": []}
    try:
        return json.loads(FIXTURE_CORPUS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"fixture_registry_version": "invalid", "fixtures": []}


def _fixture_by_family() -> dict[str, dict[str, object]]:
    payload = _load_fixture_corpus()
    mapping: dict[str, dict[str, object]] = {}
    for fixture in list(payload.get("fixtures", []) or []):
        family = str((fixture or {}).get("scenario_family") or "").strip()
        if family:
            mapping[family] = dict(fixture)
    return mapping


def _scenario_fixture_name(family: str | None) -> str | None:
    if not family:
        return None
    fixture = _fixture_by_family().get(str(family).strip())
    return str(fixture.get("name")).strip() if fixture else None


def _required_acceptance_fixtures_for_plan(family: str | None) -> list[str]:
    fixture = _scenario_fixture_name(family)
    return [fixture] if fixture else []


def _fixture_expectation_for_family(family: str | None) -> dict[str, object] | None:
    if not family:
        return None
    return _fixture_by_family().get(str(family).strip())


def _fixture_expectation_status(payload: dict[str, object]) -> tuple[str, list[str]]:
    row = dict(payload.get("scenario_matrix_row") or {})
    summary = dict(payload.get("scenario_acceptance_summary") or {})
    fixture = _fixture_expectation_for_family(row.get("family"))
    if not fixture:
        return "not_applicable", []
    gaps: list[str] = []
    expected_family = str(fixture.get("scenario_family") or "").strip()
    if expected_family and str(row.get("family") or "").strip() != expected_family:
        gaps.append(f"family mismatch: expected {expected_family}")
    expected_criticals = {str(item) for item in list(fixture.get("critical_capabilities", [])) if str(item).strip()}
    actual_criticals = {str(item) for item in list(summary.get("critical_capabilities", [])) if str(item).strip()}
    if expected_criticals and not actual_criticals:
        gaps.append("missing critical capability set")
    elif expected_criticals and not (actual_criticals & expected_criticals):
        gaps.append("critical capability set does not overlap fixture")
    if not summary:
        gaps.append("missing acceptance summary")
    if not row:
        gaps.append("missing matrix row")
    return ("matched" if not gaps else "gapped"), gaps


def _capability_parity_entries(coverage_gap: dict[str, object]) -> list[dict[str, object]]:
    return [dict(item) for item in list(coverage_gap.get("capability_parity", []) or [])]


def _critical_capability_parity(coverage_gap: dict[str, object]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    readiness = dict(coverage_gap.get("scenario_generate_readiness") or {})
    critical = {str(item) for item in list(readiness.get("critical_capabilities", [])) if str(item).strip()}
    parity_entries = _capability_parity_entries(coverage_gap)
    if not critical:
        return [], []
    critical_entries = [entry for entry in parity_entries if str(entry.get("capability")) in critical]
    mismatches = [entry for entry in critical_entries if entry.get("generate_mismatch_reason")]
    return critical_entries, mismatches


def _parity_counts(parity_entries: list[dict[str, object]]) -> dict[str, int]:
    return {
        "parity_supported_count": sum(1 for entry in parity_entries if bool(entry.get("inventory_supported"))),
        "parity_generate_ready_count": sum(1 for entry in parity_entries if bool(entry.get("generate_supported"))),
        "parity_acceptance_verified_count": sum(1 for entry in parity_entries if bool(entry.get("acceptance_verified"))),
        "parity_mismatch_count": sum(1 for entry in parity_entries if entry.get("generate_mismatch_reason")),
    }


def _selected_donor_summary(
    diagnostics: list[dict[str, object]],
    donor_archetype: DonorArchetypePlan | None = None,
) -> dict[str, object] | None:
    selected = next((item for item in diagnostics if item.get("status") == "selected"), None)
    if selected is None:
        return None
    donor_graph_summary = dict(selected.get("donor_graph_summary") or {})
    summary = {
        "relative_path": selected.get("relative_path"),
        "origin": selected.get("origin"),
        "promotion_status": selected.get("promotion_status"),
        "evidence_source": selected.get("evidence_source"),
        "promotion_evidence": list(selected.get("promotion_evidence", []))[:8],
        "validated_edit_capabilities": list(selected.get("validated_edit_capabilities", []))[:12],
        "acceptance_notes": list(selected.get("acceptance_notes", []))[:6],
        "acceptance_fixtures": list(selected.get("acceptance_fixtures", []))[:6],
        "provenance": selected.get("provenance"),
        "workspace_validation": selected.get("workspace_validation"),
        "selection_reasons": list(donor_archetype.selection_reasons if donor_archetype is not None else selected.get("reasons", []))[:8],
        "sample_archetypes": list(selected.get("sample_archetypes", []) or selected.get("archetype_tags", [])),
        "archetype_match_reasons": list(selected.get("archetype_match_reasons", [])),
        "adjusted_total_score": selected.get("adjusted_total_score", selected.get("total_score")),
        "donor_graph_summary": donor_graph_summary,
        "validated_capability_overlap": sorted(
            {
                str(reason).split(":", 1)[1]
                for reason in list(selected.get("reasons", []))
                if str(reason).startswith("capability:")
            }
            & set(str(item) for item in list(selected.get("validated_edit_capabilities", [])) if str(item).strip())
        ),
    }
    summary["donor_evidence_score"] = (
        len(summary["promotion_evidence"]) * 2
        + len(summary["validated_edit_capabilities"])
        + len(summary["acceptance_fixtures"]) * 3
    )
    summary["promotion_reasoning"] = [
        item
        for item in [
            f"promotion status: {summary['promotion_status']}" if summary.get("promotion_status") else None,
            f"evidence source: {summary['evidence_source']}" if summary.get("evidence_source") else None,
            f"workspace validation: {summary['workspace_validation']}" if summary.get("workspace_validation") else None,
            f"fixtures: {', '.join(summary['acceptance_fixtures'][:3])}" if summary["acceptance_fixtures"] else None,
        ]
        if item
    ]
    reusable_pair_coverage = donor_graph_summary.get("reusable_pair_coverage")
    layout_reuse_status = donor_graph_summary.get("layout_reuse_status")
    summary["why_selected"] = [
        item
        for item in [
            f"layout reuse {reusable_pair_coverage}% ({layout_reuse_status})" if reusable_pair_coverage is not None and layout_reuse_status else None,
            f"archetype match via {', '.join(summary['archetype_match_reasons'])}" if summary["archetype_match_reasons"] else None,
            f"promotion evidence: {', '.join(summary['promotion_evidence'][:3])}" if summary["promotion_evidence"] else None,
            f"evidence source: {summary['evidence_source']}" if summary.get("evidence_source") else None,
            f"validated edit capabilities: {', '.join(summary['validated_edit_capabilities'][:4])}" if summary["validated_edit_capabilities"] else None,
            f"selection reasons: {', '.join(summary['selection_reasons'][:4])}" if summary["selection_reasons"] else None,
        ]
        if item
    ]
    return summary


def _filter_candidates_for_blueprint(
    candidates: list[SampleCandidate],
    blueprint: dict[str, object] | None,
) -> tuple[list[SampleCandidate], list[dict[str, object]]]:
    if blueprint is None:
        return candidates, []
    required_link_count = len(list(blueprint.get("links", [])))
    required_capabilities = {str(item) for item in list(blueprint.get("capabilities", []))}
    viable: list[SampleCandidate] = []
    filtered_diagnostics: list[dict[str, object]] = []
    for candidate in candidates:
        fit = build_donor_graph_fit(candidate.sample, blueprint)
        fit_summary = _donor_graph_fit_summary(fit, blueprint)
        acceptance_penalty, penalty_reasons = _candidate_acceptance_penalty(candidate, blueprint)
        adjusted_total_score = candidate.total_score - acceptance_penalty
        preferred_archetypes = [str(item) for item in list(blueprint.get("preferred_donor_archetypes", [])) if item]
        archetype_match_score, archetype_reasons, sample_archetypes = _candidate_archetype_alignment(
            candidate.sample,
            preferred_archetypes,
        )
        supported_capabilities = set(_expanded_sample_capabilities(candidate.sample, _sample_device_families(candidate.sample)))
        filter_reasons: list[str] = []
        if required_link_count and len(fit.missing_pairs) >= required_link_count and not fit.matched_pairs:
            filter_reasons.append("donor graph has no reusable link pairs for the requested topology")
        if fit_summary["required_pair_count"] >= 3 and fit_summary["reusable_pair_coverage"] < 40 and fit.layout_reuse_score <= 0:
            filter_reasons.append("sample reuses too little of the requested link skeleton")
        if preferred_archetypes and not archetype_match_score and fit_summary["layout_reuse_status"] == "weak":
            filter_reasons.append("sample archetype does not align with the requested donor shape")
        if "wireless_client_association" in required_capabilities and "wireless_client_association" not in supported_capabilities:
            filter_reasons.append("sample lacks donor-backed support for requested wireless client association")
        if "wireless_mutation" in required_capabilities and "wireless_mutation" not in supported_capabilities:
            filter_reasons.append("sample lacks donor-backed support for requested wireless mutation")
        if "end_device_mutation" in required_capabilities and "end_device_mutation" not in supported_capabilities:
            filter_reasons.append("sample lacks donor-backed support for requested end-device mutation")
        if "iot_registration" in required_capabilities and "iot_registration" not in supported_capabilities:
            filter_reasons.append("sample lacks donor-backed support for requested IoT registration")
        if "iot_control" in required_capabilities and "iot_control" not in supported_capabilities:
            filter_reasons.append("sample lacks donor-backed support for requested IoT control")
        if adjusted_total_score <= 0:
            filter_reasons.append("acceptance penalty reduced the donor score below zero")
        if filter_reasons:
            filtered_diagnostics.append(
                {
                    "relative_path": candidate.sample.relative_path,
                    "origin": candidate.sample.origin,
                    "total_score": candidate.total_score,
                    "adjusted_total_score": adjusted_total_score,
                    "reasons": candidate.reasons[:8],
                    "donor_graph_fit": asdict(fit),
                    "donor_graph_summary": fit_summary,
                    "preferred_donor_archetypes": preferred_archetypes,
                    "sample_archetypes": sample_archetypes,
                    "archetype_match_score": archetype_match_score,
                    "archetype_match_reasons": archetype_reasons,
                    "status": "filtered",
                    "rejection_reasons": [*filter_reasons, *penalty_reasons],
                }
            )
            continue
        viable.append(candidate)
    return viable, filtered_diagnostics


def _rerank_candidates_for_blueprint(candidates: list[SampleCandidate], blueprint: dict[str, object]) -> list[SampleCandidate]:
    def _sort_key(candidate: SampleCandidate) -> tuple[int, int, int, int, int, int]:
        fit = build_donor_graph_fit(candidate.sample, blueprint)
        acceptance_penalty, _ = _candidate_acceptance_penalty(candidate, blueprint)
        adjusted_score = candidate.total_score - acceptance_penalty
        preferred_archetypes = [str(item) for item in list(blueprint.get("preferred_donor_archetypes", [])) if item]
        archetype_match_score, _, _ = _candidate_archetype_alignment(candidate.sample, preferred_archetypes)
        return (
            fit.layout_reuse_score,
            archetype_match_score,
            fit.fit_score - acceptance_penalty,
            -len(fit.port_media_conflicts),
            -len(fit.missing_pairs),
            adjusted_score,
        )

    return sorted(
        candidates,
        key=_sort_key,
        reverse=True,
    )


def _summarize_rejection_issues(issues: list[str]) -> list[str]:
    summarized: list[str] = []
    seen: set[str] = set()
    for issue in issues:
        normalized = str(issue).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        summarized.append(normalized)
        if len(summarized) >= 5:
            break
    return summarized


def _evaluate_donor_prune_candidates(
    plan: IntentPlan,
    blueprint: dict[str, object],
    donor_candidates: list[SampleCandidate],
) -> tuple[
    tuple[IntentPlan, DonorArchetypePlan, ET.Element, SampleCandidate] | None,
    list[dict[str, object]],
    ]:
    diagnostics: list[dict[str, object]] = []
    latest_plan: IntentPlan | None = None
    viable_candidates, filtered_diagnostics = _filter_candidates_for_blueprint(donor_candidates, blueprint)
    diagnostics.extend(filtered_diagnostics)
    for donor_candidate in viable_candidates:
        donor_path = Path(donor_candidate.sample.path)
        donor_graph_fit = build_donor_graph_fit(donor_candidate.sample, blueprint)
        diagnostic: dict[str, object] = {
            "relative_path": donor_candidate.sample.relative_path,
            "origin": donor_candidate.sample.origin,
            "total_score": donor_candidate.total_score,
            "reasons": donor_candidate.reasons[:8],
            "donor_graph_fit": asdict(donor_graph_fit),
            "donor_graph_summary": _donor_graph_fit_summary(donor_graph_fit, blueprint),
        }
        try:
            adapted_plan, archetype_plan = _build_donor_prune_plan_for_donor(plan, blueprint, donor_path)
            donor_root = decode_pkt_to_root(donor_path)
            candidate_root = apply_plan_operations(donor_root, adapted_plan)
            _sanitize_runtime_sections(candidate_root)
            unexpected_workspace_issues = _unexpected_workspace_issues(donor_root, candidate_root)
            if unexpected_workspace_issues:
                raise ValueError("; ".join(unexpected_workspace_issues))
            validate_donor_coherence(donor_root, candidate_root)
            archetype_plan.compat_donor_origin = donor_candidate.sample.origin
            archetype_plan.compat_donor_relative_path = donor_candidate.sample.relative_path
            archetype_plan.selection_reasons = donor_candidate.reasons[:8]
            diagnostic["status"] = "selected"
            diagnostic["rejection_reasons"] = []
            diagnostics.append(diagnostic)
            return (adapted_plan, archetype_plan, donor_root, donor_candidate), diagnostics
        except PlanningError as exc:
            latest_plan = exc.plan
            diagnostic["status"] = "rejected"
            diagnostic["rejection_reasons"] = _summarize_rejection_issues(exc.plan.blocking_gaps)
        except Exception as exc:
            diagnostic["status"] = "rejected"
            diagnostic["rejection_reasons"] = _summarize_rejection_issues([str(exc)])
        diagnostics.append(diagnostic)
    if latest_plan is not None:
        plan.blocking_gaps = list(dict.fromkeys([*plan.blocking_gaps, *latest_plan.blocking_gaps]))
    return None, diagnostics


def _apply_prompt_compatibility_requirements(plan: IntentPlan, donor_roots: list[Path] | None = None) -> IntentPlan:
    prepared = prepare_generation_plan(plan)
    if prepared.goal != "edit":
        topology_tags = _topology_tags_for_plan(prepared, _choose_topology_archetype(prepared))
        _, _, donor_candidates = _rank_generation_donors(prepared, topology_tags, donor_roots)
        if not donor_candidates and STRICT_COMPATIBILITY_GAP not in prepared.blocking_gaps:
            prepared.blocking_gaps.append(STRICT_COMPATIBILITY_GAP)
    return prepared


def _link_schema_summary(root: ET.Element) -> dict[str, object]:
    cable = root.find(".//LINKS/LINK/CABLE")
    if cable is None:
        return {"link_schema_mode": "none", "link_schema_missing_fields": []}
    from_ref = cable.findtext("FROM", default="")
    mode = "save_ref_id" if from_ref.startswith("save-ref-id:") else ("numeric_index" if from_ref.isdigit() else "unknown")
    required = ["FUNCTIONAL", "GEO_VIEW_COLOR", "IS_MANAGED_IN_RACK_VIEW"]
    missing = [tag for tag in required if cable.find(tag) is None]
    if mode == "save_ref_id":
        mode = "save_ref_id_complete" if not missing else "save_ref_id_missing_fields"
    return {"link_schema_mode": mode, "link_schema_missing_fields": missing}


@dataclass
class TopologyPlan:
    topology_archetype: str
    devices: list[dict[str, object]]
    links: list[dict[str, object]]
    layout: dict[str, dict[str, int]]
    port_map: dict[str, list[str]]


@dataclass
class ConfigPlan:
    switch_ops: list[dict[str, object]]
    router_ops: list[dict[str, object]]
    server_ops: list[dict[str, object]]
    wireless_ops: list[dict[str, object]]
    end_device_ops: list[dict[str, object]]
    management_ops: list[dict[str, object]]
    assumptions_used: list[str]


@dataclass
class DonorArchetypePlan:
    compat_donor: str
    donor_capacity: dict[str, object]
    kept_devices: list[str]
    pruned_devices: list[str]
    renamed_devices: list[dict[str, str]]
    mutation_groups: list[dict[str, object]]
    layout_strategy: str
    compat_donor_origin: str | None = None
    compat_donor_relative_path: str | None = None
    selection_reasons: list[str] = field(default_factory=list)


@dataclass
class CompatibilityProfile:
    mode: str
    allowed_operations: list[str]
    blocked_operations: list[str]
    requires_acceptance: bool


@dataclass
class MutationStageResult:
    stage_name: str
    applied_operations: list[str]
    changed_devices: list[str]
    changed_links: list[str]
    blocked_mutations: list[str]
    suspect_sections: list[str]


@dataclass
class SubtreeDiffReport:
    device_name: str
    changed_paths: list[str]
    runtime_suspects: list[str]


SAFE_OPEN_ALLOWED_MUTATIONS = [
    "device_rename",
    "layout_reposition",
    "config_mutation",
    "service_mutation",
]
SAFE_OPEN_BLOCKED_MUTATIONS = [
    "link_rewrite",
    "port_reassignment",
    "device_prune",
    "donor_group_reduction",
    "wireless_mutation",
    "wireless_client_association",
    "end_device_mutation",
    "workspace_physical_mutation",
]
MUTATION_STAGE_ORDER = [
    "baseline",
    "rename_only",
    "layout_only",
    "config_only",
    "service_only",
    "link_remove_only",
    "link_add_only",
    "wireless_only",
]
STAGE_SUSPECT_SECTION_HINTS = {
    "baseline": [],
    "rename_only": ["ENGINE/NAME", "ENGINE/SYS_NAME", "ENGINE/RUNNINGCONFIG", "PHYSICALWORKSPACE"],
    "layout_only": ["WORKSPACE/LOGICAL", "COORD_SETTINGS"],
    "config_only": ["ENGINE/RUNNINGCONFIG", "ENGINE/STARTUPCONFIG", "FILE_CONTENT/CONFIG"],
    "service_only": ["ENGINE/DNS_SERVER", "ENGINE/DHCP_SERVER", "ENGINE/HTTP_SERVER", "ENGINE/FTP_SERVER", "ENGINE/NTP_SERVER"],
    "link_remove_only": ["LINK/CABLE", "ENGINE/MODULE", "ENGINE/SLOT", "ENGINE/PORT", "CUSTOM_INTERFACE"],
    "link_add_only": ["LINK/CABLE", "ENGINE/MODULE", "ENGINE/SLOT", "ENGINE/PORT", "CUSTOM_INTERFACE"],
    "wireless_only": ["WIRELESS_SERVER", "WIRELESS_CLIENT", "USER_APPS", "CUSTOM_INTERFACE"],
}


def _estimate_plan(topology_plan: TopologyPlan, config_plan: ConfigPlan) -> dict[str, object]:
    device_count = len(topology_plan.devices)
    link_count = len(topology_plan.links)
    op_count = sum(
        len(bucket)
        for bucket in [
            config_plan.switch_ops,
            config_plan.router_ops,
            config_plan.server_ops,
            config_plan.wireless_ops,
            config_plan.end_device_ops,
            config_plan.management_ops,
        ]
    )
    complexity = "small"
    if device_count >= 20 or link_count >= 18 or op_count >= 20:
        complexity = "medium"
    if device_count >= 40 or link_count >= 40 or op_count >= 40:
        complexity = "large"
    return {
        "device_count": device_count,
        "link_count": link_count,
        "config_operation_count": op_count,
        "complexity": complexity,
    }


def _preflight_validation(plan: IntentPlan, topology_plan: TopologyPlan, config_plan: ConfigPlan) -> dict[str, object]:
    issues = list(plan.blocking_gaps)
    warnings = list(plan.parse_warnings)
    if topology_plan.topology_archetype == "chain" and len([device for device in topology_plan.devices if _device_kind(device) == "Switch"]) < 2:
        warnings.append("Chain archetype selected with fewer than two switches.")
    if "router_on_a_stick" in plan.capabilities and not any(op.get("op") == "set_subinterface" for op in config_plan.router_ops):
        issues.append("Router-on-a-stick was requested but no router subinterfaces were planned.")
    if "wireless_ap" in plan.capabilities and not any(op.get("op") == "set_ssid" for op in config_plan.wireless_ops):
        warnings.append("Wireless access points are present but no SSID mutation was planned.")
    if plan.device_requirements.get("Printer", 0) and not any(device.get("type") == "Printer" for device in topology_plan.devices):
        issues.append("Prompt requested printers but topology plan did not allocate printer devices.")
    status = "blocked" if issues else ("warning" if warnings else "ok")
    return {
        "status": status,
        "issues": issues,
        "warnings": warnings,
    }


def _autofix_summary(plan: IntentPlan, validation: dict[str, object]) -> dict[str, object]:
    applied = list(plan.assumptions_used)
    pending = list(validation.get("issues", []))
    return {
        "applied": applied,
        "pending_manual_input": pending,
    }


def _default_name_for_type(device_type: str, index: int) -> str:
    return {
        "Router": f"R{index}",
        "Switch": f"SW{index}",
        "PC": f"PC{index}",
        "Server": f"Server{index}",
        "LightWeightAccessPoint": f"AP{index}",
        "WirelessRouter": f"WRT{index}",
        "Tablet": f"Tablet{index}",
        "Laptop": f"Laptop{index}",
        "Printer": f"Printer{index}",
        "Smartphone": f"Phone{index}",
    }.get(device_type, f"{device_type}{index}")


def _device_kind(device: dict[str, object]) -> str:
    return str(device.get("type", ""))


def _is_host_device(device: dict[str, object]) -> bool:
    return _device_kind(device) in {"PC", "Server", "Printer", "Laptop"}


def _is_wireless_client_device(device: dict[str, object]) -> bool:
    return _device_kind(device) in {"Tablet", "Smartphone"}


def _router_port(device: dict[str, object], index: int = 1) -> str:
    model = str(device.get("model") or "")
    if model.startswith("2901"):
        return f"GigabitEthernet0/{index - 1}"
    if model.startswith("ISR"):
        return f"GigabitEthernet0/0/{index - 1}"
    return f"FastEthernet0/{index - 1}"


def _switch_uplink_port(device: dict[str, object], index: int) -> str:
    model = str(device.get("model") or "")
    if model.startswith("3650"):
        return f"GigabitEthernet1/0/{index}"
    return f"GigabitEthernet0/{index}"


def _switch_access_port(index: int) -> str:
    return f"FastEthernet0/{index}"


def _host_port(device: dict[str, object]) -> str:
    kind = _device_kind(device)
    if kind in {"Tablet", "Smartphone"}:
        return "Wireless0"
    return "FastEthernet0"


def _department_device_name(group_name: str, device_type: str, index: int) -> str:
    suffix = {
        "Switch": "SW",
        "LightWeightAccessPoint": "AP",
        "Printer": "PRN",
        "PC": "PC",
        "Tablet": "TAB",
        "Laptop": "LAP",
        "Server": "SRV",
        "Smartphone": "PH",
    }.get(device_type, device_type.upper())
    return f"{group_name}-{suffix}{index}"


def _choose_switch_model(index: int, total_switches: int, uplink_intent: str | None) -> str:
    if get_packet_tracer_compatibility_donor() is not None:
        return "2960-24TT"
    if total_switches > 1 and index == 1:
        return "3650-24PS"
    if uplink_intent == "gigabit" and total_switches == 1:
        return "2960-24TT"
    return "2960-24TT"


def _choose_router_model(plan: IntentPlan) -> str:
    if get_packet_tracer_compatibility_donor() is not None:
        return "ISR4331"
    if plan.vlan_ids or plan.uplink_intent == "gigabit" or plan.device_requirements.get("Switch", 0):
        return "2901"
    return "1841"


def _append_unique_op(bucket: list[dict[str, object]], operation: dict[str, object]) -> None:
    if operation not in bucket:
        bucket.append(operation)


def _copy_plan(plan: IntentPlan) -> IntentPlan:
    return copy.deepcopy(plan)


def _empty_plan_like(plan: IntentPlan) -> IntentPlan:
    staged = _copy_plan(plan)
    staged.edit_operations = []
    staged.switch_ops = []
    staged.router_ops = []
    staged.server_ops = []
    staged.wireless_ops = []
    staged.end_device_ops = []
    staged.management_ops = []
    staged.verification_ops = []
    return staged


def _operation_category(bucket_name: str, operation: dict[str, object]) -> str:
    op_name = str(operation.get("op") or "")
    if bucket_name == "edit_operations":
        if op_name == "rename_device":
            return "device_rename"
        if op_name == "reflow_layout":
            return "layout_reposition"
        if op_name == "prune_device":
            return "device_prune"
        if op_name == "set_link":
            return "link_rewrite"
        if op_name == "remove_link":
            return "port_reassignment"
        return "workspace_physical_mutation"
    if bucket_name in {"switch_ops", "router_ops", "management_ops"}:
        return "config_mutation"
    if bucket_name == "server_ops":
        return "service_mutation"
    if bucket_name == "wireless_ops":
        if op_name == "associate_wireless_client":
            return "wireless_client_association"
        return "wireless_mutation"
    if bucket_name == "end_device_ops":
        return "end_device_mutation"
    if bucket_name == "verification_ops":
        return "verification_only"
    return "workspace_physical_mutation"


def _bucket_operations(plan: IntentPlan) -> list[tuple[str, dict[str, object]]]:
    ordered: list[tuple[str, dict[str, object]]] = []
    for bucket_name in [
        "edit_operations",
        "switch_ops",
        "router_ops",
        "server_ops",
        "wireless_ops",
        "end_device_ops",
        "management_ops",
        "verification_ops",
    ]:
        for operation in getattr(plan, bucket_name):
            ordered.append((bucket_name, operation))
    return ordered


def _operation_device_names(operation: dict[str, object]) -> list[str]:
    names: list[str] = []
    if isinstance(operation.get("device"), str):
        names.append(str(operation["device"]))
    for endpoint in ("a", "b"):
        endpoint_value = operation.get(endpoint)
        if isinstance(endpoint_value, dict) and endpoint_value.get("dev"):
            names.append(str(endpoint_value["dev"]))
    if isinstance(operation.get("new_name"), str):
        names.append(str(operation["new_name"]))
    return sorted(dict.fromkeys(names), key=str.lower)


def _operation_link_labels(operation: dict[str, object]) -> list[str]:
    op_name = str(operation.get("op") or "")
    if op_name not in {"set_link", "remove_link"}:
        return []
    left = operation.get("a") or {}
    right = operation.get("b") or {}
    left_label = str(left.get("dev", ""))
    right_label = str(right.get("dev", ""))
    if op_name == "set_link":
        left_port = str(left.get("port", ""))
        right_port = str(right.get("port", ""))
        return [f"{left_label}:{left_port} <-> {right_label}:{right_port}"]
    return [f"{left_label} <-> {right_label}"]


def _device_by_save_ref(root: ET.Element) -> dict[str, ET.Element]:
    devices: dict[str, ET.Element] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        save_ref = device.findtext("./ENGINE/SAVE_REF_ID", default="").strip()
        if save_ref:
            devices[save_ref] = device
    return devices


def _save_ref_by_name(root: ET.Element) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME", default="").strip()
        save_ref = device.findtext("./ENGINE/SAVE_REF_ID", default="").strip()
        if name and save_ref:
            mapping[name] = save_ref
    return mapping


def _collect_subtree_values(node: ET.Element, path: str | None = None, sink: dict[str, str] | None = None) -> dict[str, str]:
    target = sink if sink is not None else {}
    current_path = path or node.tag
    text = (node.text or "").strip()
    if text:
        target[f"{current_path}#text"] = text
    for key, value in sorted(node.attrib.items()):
        target[f"{current_path}@{key}"] = value
    child_counts: dict[str, int] = {}
    for child in list(node):
        index = child_counts.get(child.tag, 0)
        child_counts[child.tag] = index + 1
        _collect_subtree_values(child, f"{current_path}/{child.tag}[{index}]", target)
    return target


def _subtree_diff_report(device_name: str, donor_device: ET.Element, generated_device: ET.Element) -> SubtreeDiffReport:
    donor_values = _collect_subtree_values(donor_device)
    generated_values = _collect_subtree_values(generated_device)
    changed_paths = sorted(
        {
            key
            for key in set(donor_values) | set(generated_values)
            if donor_values.get(key) != generated_values.get(key)
        }
    )
    suspect_prefixes = [
        "DEVICE/ENGINE/MODULE",
        "DEVICE/ENGINE/SLOT",
        "DEVICE/ENGINE/PORT",
        "DEVICE/ENGINE/USER_APPS",
        "DEVICE/ENGINE/CUSTOM_INTERFACE",
        "DEVICE/WORKSPACE/LOGICAL",
        "DEVICE/ENGINE/WIRELESS_SERVER",
        "DEVICE/ENGINE/WIRELESS_CLIENT",
        "DEVICE/ENGINE/COORD_SETTINGS",
    ]
    runtime_suspects = [prefix for prefix in suspect_prefixes if any(path.startswith(prefix) for path in changed_paths)]
    return SubtreeDiffReport(
        device_name=device_name,
        changed_paths=changed_paths[:40],
        runtime_suspects=runtime_suspects,
    )


def _stage_plan(plan: IntentPlan, stage_name: str) -> IntentPlan:
    staged = _empty_plan_like(plan)
    if stage_name == "baseline":
        return staged
    if stage_name == "rename_only":
        staged.edit_operations = [op for op in plan.edit_operations if op.get("op") == "rename_device"]
        return staged
    if stage_name == "layout_only":
        staged.edit_operations = [
            op for op in plan.edit_operations if op.get("op") in {"rename_device", "reflow_layout"}
        ]
        return staged
    if stage_name == "config_only":
        staged.edit_operations = [
            op for op in plan.edit_operations if op.get("op") in {"rename_device", "reflow_layout"}
        ]
        staged.switch_ops = copy.deepcopy(plan.switch_ops)
        staged.router_ops = copy.deepcopy(plan.router_ops)
        staged.management_ops = copy.deepcopy(plan.management_ops)
        return staged
    if stage_name == "service_only":
        staged.edit_operations = [
            op for op in plan.edit_operations if op.get("op") in {"rename_device", "reflow_layout"}
        ]
        staged.switch_ops = copy.deepcopy(plan.switch_ops)
        staged.router_ops = copy.deepcopy(plan.router_ops)
        staged.management_ops = copy.deepcopy(plan.management_ops)
        staged.server_ops = copy.deepcopy(plan.server_ops)
        return staged
    if stage_name == "link_remove_only":
        staged.edit_operations = [
            op
            for op in plan.edit_operations
            if op.get("op") in {"rename_device", "reflow_layout", "remove_link"}
        ]
        staged.switch_ops = copy.deepcopy(plan.switch_ops)
        staged.router_ops = copy.deepcopy(plan.router_ops)
        staged.management_ops = copy.deepcopy(plan.management_ops)
        staged.server_ops = copy.deepcopy(plan.server_ops)
        return staged
    if stage_name == "link_add_only":
        staged.edit_operations = [
            op
            for op in plan.edit_operations
            if op.get("op") in {"rename_device", "reflow_layout", "remove_link", "set_link"}
        ]
        staged.switch_ops = copy.deepcopy(plan.switch_ops)
        staged.router_ops = copy.deepcopy(plan.router_ops)
        staged.management_ops = copy.deepcopy(plan.management_ops)
        staged.server_ops = copy.deepcopy(plan.server_ops)
        return staged
    if stage_name == "wireless_only":
        staged.edit_operations = copy.deepcopy(plan.edit_operations)
        staged.switch_ops = copy.deepcopy(plan.switch_ops)
        staged.router_ops = copy.deepcopy(plan.router_ops)
        staged.management_ops = copy.deepcopy(plan.management_ops)
        staged.server_ops = copy.deepcopy(plan.server_ops)
        staged.wireless_ops = copy.deepcopy(plan.wireless_ops)
        staged.end_device_ops = copy.deepcopy(plan.end_device_ops)
        return staged
    return staged


def _plan_has_mutations(plan: IntentPlan) -> bool:
    return any(
        getattr(plan, bucket_name)
        for bucket_name in [
            "edit_operations",
            "switch_ops",
            "router_ops",
            "server_ops",
            "wireless_ops",
            "end_device_ops",
            "management_ops",
        ]
    )


def _compatibility_profile() -> CompatibilityProfile:
    return CompatibilityProfile(
        mode=SAFE_OPEN_COMPATIBILITY_MODE,
        allowed_operations=SAFE_OPEN_ALLOWED_MUTATIONS,
        blocked_operations=SAFE_OPEN_BLOCKED_MUTATIONS,
        requires_acceptance=True,
    )


def _safe_open_plan(plan: IntentPlan) -> tuple[IntentPlan, list[str]]:
    safe_plan = _empty_plan_like(plan)
    blocked: list[str] = []
    for bucket_name, operation in _bucket_operations(plan):
        category = _operation_category(bucket_name, operation)
        if category in SAFE_OPEN_ALLOWED_MUTATIONS:
            getattr(safe_plan, bucket_name).append(copy.deepcopy(operation))
        elif category == "verification_only":
            continue
        elif category in SAFE_OPEN_BLOCKED_MUTATIONS:
            blocked.append(category)
        else:
            blocked.append("workspace_physical_mutation")
    return safe_plan, sorted(dict.fromkeys(blocked))


def _stage_result(
    stage_name: str,
    donor_root: ET.Element,
    stage_plan: IntentPlan,
    blocked_mutations: list[str],
) -> MutationStageResult:
    if stage_name == "baseline":
        return MutationStageResult(
            stage_name=stage_name,
            applied_operations=[],
            changed_devices=[],
            changed_links=[],
            blocked_mutations=[],
            suspect_sections=[],
        )
    generated_root = apply_plan_operations(donor_root, stage_plan)
    donor_name_to_ref = _save_ref_by_name(donor_root)
    generated_name_to_ref = _save_ref_by_name(generated_root)
    donor_devices = _device_by_save_ref(donor_root)
    generated_devices = _device_by_save_ref(generated_root)
    changed_device_names: list[str] = []
    changed_links: list[str] = []
    touched_refs: set[str] = set()
    applied_operations: list[str] = []
    for bucket_name, operation in _bucket_operations(stage_plan):
        applied_operations.append(str(operation.get("op") or bucket_name))
        changed_device_names.extend(_operation_device_names(operation))
        changed_links.extend(_operation_link_labels(operation))
        for name in _operation_device_names(operation):
            save_ref = donor_name_to_ref.get(name) or generated_name_to_ref.get(name)
            if save_ref:
                touched_refs.add(save_ref)
    suspect_sections = list(STAGE_SUSPECT_SECTION_HINTS.get(stage_name, []))
    for save_ref in sorted(touched_refs):
        donor_device = donor_devices.get(save_ref)
        generated_device = generated_devices.get(save_ref)
        if donor_device is None or generated_device is None:
            continue
        device_name = generated_device.findtext("./ENGINE/NAME", default="").strip() or donor_device.findtext("./ENGINE/NAME", default=save_ref).strip()
        report = _subtree_diff_report(device_name, donor_device, generated_device)
        for section in report.runtime_suspects:
            if section not in suspect_sections:
                suspect_sections.append(section)
    return MutationStageResult(
        stage_name=stage_name,
        applied_operations=sorted(dict.fromkeys(applied_operations)),
        changed_devices=sorted(dict.fromkeys(changed_device_names), key=str.lower),
        changed_links=sorted(dict.fromkeys(changed_links), key=str.lower),
        blocked_mutations=blocked_mutations if stage_name in {"link_remove_only", "link_add_only", "wireless_only"} else [],
        suspect_sections=suspect_sections,
    )


def _build_acceptance_stage_plan(donor_root: ET.Element, adapted_plan: IntentPlan, blocked_mutations: list[str]) -> list[dict[str, object]]:
    stage_results: list[dict[str, object]] = []
    for stage_name in MUTATION_STAGE_ORDER:
        stage_plan = _stage_plan(adapted_plan, stage_name)
        stage_result = _stage_result(stage_name, donor_root, stage_plan, blocked_mutations)
        if stage_name == "baseline" or stage_result.applied_operations or stage_result.changed_devices or stage_result.changed_links:
            stage_results.append(asdict(stage_result))
    return stage_results


def _apply_safe_open_profile(
    donor_root: ET.Element,
    adapted_plan: IntentPlan,
) -> tuple[IntentPlan, IntentPlan]:
    safe_plan, blocked_mutations = _safe_open_plan(adapted_plan)
    profiled_plan = _copy_plan(adapted_plan)
    profile = asdict(_compatibility_profile())
    profiled_plan.compatibility_profile = profile
    profiled_plan.unsafe_mutations_requested = blocked_mutations
    profiled_plan.blocked_mutations = blocked_mutations
    profiled_plan.acceptance_stage_plan = _build_acceptance_stage_plan(donor_root, adapted_plan, blocked_mutations)
    for mutation in blocked_mutations:
        message = f"Open-first mode blocked unsafe mutation: {mutation}."
        if message not in profiled_plan.blocking_gaps:
            profiled_plan.blocking_gaps.append(message)
    safe_plan.compatibility_profile = profile
    safe_plan.unsafe_mutations_requested = blocked_mutations
    safe_plan.blocked_mutations = blocked_mutations
    safe_plan.acceptance_stage_plan = copy.deepcopy(profiled_plan.acceptance_stage_plan)
    return safe_plan, profiled_plan


def _apply_safe_open_preview(plan: IntentPlan) -> IntentPlan:
    preview_plan = _copy_plan(plan)
    _, blocked_mutations = _safe_open_plan(plan)
    profile = asdict(_compatibility_profile())
    preview_plan.compatibility_profile = profile
    preview_plan.unsafe_mutations_requested = blocked_mutations
    preview_plan.blocked_mutations = blocked_mutations
    preview_plan.acceptance_stage_plan = []
    for mutation in blocked_mutations:
        message = f"Open-first mode blocked unsafe mutation: {mutation}."
        if message not in preview_plan.blocking_gaps:
            preview_plan.blocking_gaps.append(message)
    return preview_plan


def _write_pkt_root(root: ET.Element, pkt_path: Path, xml_path: Path | None = None) -> None:
    xml_bytes = ET.tostring(root, encoding="utf-8", xml_declaration=False)
    pkt_path.parent.mkdir(parents=True, exist_ok=True)
    pkt_path.write_bytes(encode_pkt_modern(xml_bytes))
    if xml_path is not None:
        xml_path.parent.mkdir(parents=True, exist_ok=True)
        xml_path.write_bytes(xml_bytes)


def _choose_topology_archetype(plan: IntentPlan) -> str:
    explicit = str(plan.topology_requirements.get("uplink_topology") or "")
    if explicit == "chain":
        return "chain"
    if plan.department_groups:
        return "chain"
    if plan.network_style == "small_office":
        return "small_office"
    if explicit == "core_switch":
        return "core_access"
    if plan.device_requirements.get("Switch", 0) > 1:
        return "core_access"
    if "wireless_ap" in plan.capabilities and plan.device_requirements.get("Switch", 0) <= 1:
        return "wireless_branch"
    return "star"


def _topology_tags_for_plan(plan: IntentPlan, archetype: str) -> list[str]:
    tags = [archetype]
    if plan.department_groups:
        tags.append("department_lan")
    if plan.vlan_ids and plan.device_requirements.get("Router", 0):
        tags.append("router_on_a_stick")
    if any(cap in plan.capabilities for cap in ["dns", "server_dns", "server_http", "server_ftp"]):
        tags.append("server_services")
    if any(cap in plan.capabilities for cap in ["wireless_ap", "wireless_client"]):
        tags.append("wireless_edge")
    if "acl" in plan.capabilities:
        tags.append("acl_policy")
    return sorted(dict.fromkeys(tags))


def _seed_devices_from_plan(plan: IntentPlan) -> list[dict[str, object]]:
    devices = [dict(device) for device in plan.devices]
    current_counts: dict[str, int] = {}
    for device in devices:
        dtype = _device_kind(device)
        current_counts[dtype] = current_counts.get(dtype, 0) + 1

    total_switches = plan.device_requirements.get("Switch", 0)
    if plan.department_groups:
        for index, group in enumerate(plan.department_groups, start=1):
            switch_name = str(group.get("switch_name") or f"DEPT{index}-SW")
            if not any(str(device.get("name")) == switch_name for device in devices):
                devices.append(
                    {
                        "name": switch_name,
                        "type": "Switch",
                        "model": _choose_switch_model(index, max(total_switches, len(plan.department_groups)), plan.uplink_intent),
                        "group": group["name"],
                        "role": "department-switch",
                    }
                )
            for device_type, count in dict(group.get("devices") or {}).items():
                for inner_index in range(1, int(count) + 1):
                    name = _department_device_name(str(group["name"]), device_type, inner_index)
                    if any(str(device.get("name")) == name for device in devices):
                        continue
                    entry: dict[str, object] = {"name": name, "type": device_type, "group": group["name"]}
                    if device_type == "LightWeightAccessPoint":
                        entry["model"] = "AccessPoint-PT" if get_packet_tracer_compatibility_donor() is not None else "LAP-PT"
                    devices.append(entry)
        current_counts = {}
        for device in devices:
            dtype = _device_kind(device)
            current_counts[dtype] = current_counts.get(dtype, 0) + 1

    for device_type, count in plan.device_requirements.items():
        existing = current_counts.get(device_type, 0)
        for next_index in range(existing + 1, count + 1):
            device: dict[str, object] = {
                "name": _default_name_for_type(device_type, next_index),
                "type": device_type,
            }
            if device_type == "Switch":
                device["model"] = _choose_switch_model(next_index, count, plan.uplink_intent)
            elif device_type == "Router":
                device["model"] = _choose_router_model(plan)
            devices.append(device)
        current_counts[device_type] = count

    archetype = _choose_topology_archetype(plan)
    routers = [device for device in devices if _device_kind(device) == "Router"]
    switches = [device for device in devices if _device_kind(device) == "Switch"]
    hosts = [device for device in devices if _is_host_device(device)]

    if archetype == "chain" and plan.department_groups:
        if routers:
            routers[0].setdefault("x", 220)
            routers[0].setdefault("y", 120)
        for index, group in enumerate(plan.department_groups):
            base_x = 420 + index * 420
            switch = next((device for device in switches if device.get("group") == group["name"]), None)
            if switch is not None:
                switch.setdefault("x", base_x)
                switch.setdefault("y", 310)
            group_devices = [device for device in devices if device.get("group") == group["name"] and device is not switch]
            aps = [device for device in group_devices if _device_kind(device) == "LightWeightAccessPoint"]
            printers = [device for device in group_devices if _device_kind(device) == "Printer"]
            clients = [device for device in group_devices if _device_kind(device) in {"PC", "Tablet", "Laptop", "Smartphone", "Server"}]
            for ap_index, ap in enumerate(aps):
                ap.setdefault("x", base_x - 70 + ap_index * 120)
                ap.setdefault("y", 120)
            for printer_index, printer in enumerate(printers):
                printer.setdefault("x", base_x - 80 + printer_index * 140)
                printer.setdefault("y", 510)
            for client_index, client in enumerate(clients):
                row = client_index // 2
                column = client_index % 2
                client.setdefault("x", base_x - 140 + column * 190)
                client.setdefault("y", 660 + row * 155)
        standalone_servers = [device for device in devices if _device_kind(device) == "Server" and not device.get("group")]
        if standalone_servers:
            first_switch_x = int(switches[0].get("x", 420)) if switches else 420
            for index, server in enumerate(standalone_servers):
                server.setdefault("x", first_switch_x - 180 + index * 180)
                server.setdefault("y", 500)
        standalone_clients = [
            device
            for device in devices
            if not device.get("group") and _device_kind(device) not in {"Router", "Switch", "Server", "Power Distribution Device"}
        ]
        if standalone_clients:
            first_switch_x = int(switches[0].get("x", 420)) if switches else 420
            for index, client in enumerate(standalone_clients):
                client.setdefault("x", first_switch_x + 120 + index * 180)
                client.setdefault("y", 640 if _device_kind(client) == "Laptop" else 760)
    else:
        if routers:
            routers[0].setdefault("x", 520)
            routers[0].setdefault("y", 110)
            for index, router in enumerate(routers[1:], start=1):
                router.setdefault("x", 200 + index * 160)
                router.setdefault("y", 110)
        if switches:
            switches[0].setdefault("x", 520)
            switches[0].setdefault("y", 260)
            for index, switch in enumerate(switches[1:], start=1):
                switch.setdefault("x", 220 + (index - 1) * 220)
                switch.setdefault("y", 420)
        for index, host in enumerate(hosts):
            host.setdefault("x", 180 + (index % 6) * 150)
            host.setdefault("y", 610 + (index // 6) * 120)
    for index, device in enumerate(devices):
        device.setdefault("x", 200 + (index % 5) * 150)
        device.setdefault("y", 180 + (index // 5) * 130)
    return devices


def _plan_configs(plan: IntentPlan, devices: list[dict[str, object]]) -> dict[str, object]:
    configs: dict[str, object] = {}
    if plan.topology_requirements.get("needs_dhcp_pool") and not any(op.get("op") == "set_server_dhcp_pool" for op in plan.server_ops):
        for device in devices:
            if _device_kind(device) == "Router":
                port = _router_port(device, 1)
                configs[device["name"]] = [
                    f"hostname {device['name']}",
                    f"interface {port}",
                    " ip address 192.168.1.1 255.255.255.0",
                    " no shutdown",
                    "ip dhcp pool AUTOPOOL",
                    " network 192.168.1.0 255.255.255.0",
                    " default-router 192.168.1.1",
                    "end",
                ]
                break
    return configs


def _synthesize_links(plan: IntentPlan, devices: list[dict[str, object]]) -> list[dict[str, object]]:
    if plan.links:
        return list(plan.links)

    archetype = _choose_topology_archetype(plan)
    routers = [device for device in devices if _device_kind(device) == "Router"]
    switches = [device for device in devices if _device_kind(device) == "Switch"]
    hosts = [device for device in devices if _is_host_device(device)]
    if not switches:
        return []

    if archetype == "chain":
        links: list[dict[str, object]] = []
        router = routers[0] if routers else None
        ordered_switches = switches
        if plan.department_groups:
            ordered_switches = []
            for group in plan.department_groups:
                switch = next((device for device in switches if device.get("group") == group["name"]), None)
                if switch is not None:
                    ordered_switches.append(switch)
        if router and ordered_switches:
            links.append(
                {
                    "a": {"dev": ordered_switches[0]["name"], "port": _switch_uplink_port(ordered_switches[0], 1)},
                    "b": {"dev": router["name"], "port": _router_port(router, 1)},
                    "media": "straight-through",
                }
            )
        for index in range(len(ordered_switches) - 1):
            links.append(
                {
                    "a": {"dev": ordered_switches[index]["name"], "port": _switch_uplink_port(ordered_switches[index], 2)},
                    "b": {"dev": ordered_switches[index + 1]["name"], "port": _switch_uplink_port(ordered_switches[index + 1], 1)},
                    "media": "straight-through",
                }
            )
        access_port_index: dict[str, int] = {str(device["name"]): 1 for device in ordered_switches}
        for device in devices:
            if _is_wireless_client_device(device):
                continue
            if _device_kind(device) not in {"PC", "Server", "Printer", "Laptop", "LightWeightAccessPoint"}:
                continue
            group_name = str(device.get("group") or "")
            switch = next((item for item in ordered_switches if str(item.get("group") or "") == group_name), ordered_switches[0] if ordered_switches else None)
            if switch is None:
                continue
            switch_name = str(switch["name"])
            port_index = access_port_index[switch_name]
            access_port_index[switch_name] += 1
            links.append(
                {
                    "a": {"dev": device["name"], "port": _host_port(device)},
                    "b": {"dev": switch_name, "port": _switch_access_port(port_index)},
                    "media": "straight-through",
                }
            )
        return links

    core_switch = switches[0]
    access_switches = switches[1:] or [core_switch]
    links: list[dict[str, object]] = []
    uplink_media = "straight-through"

    if routers:
        router = routers[0]
        links.append(
            {
                "a": {"dev": core_switch["name"], "port": _switch_uplink_port(core_switch, len(access_switches) + 1 if switches[1:] else 1)},
                "b": {"dev": router["name"], "port": _router_port(router, 1)},
                "media": uplink_media,
            }
        )

    if switches[1:]:
        for index, switch in enumerate(switches[1:], start=1):
            links.append(
                {
                    "a": {"dev": core_switch["name"], "port": _switch_uplink_port(core_switch, index)},
                    "b": {"dev": switch["name"], "port": _switch_uplink_port(switch, 1)},
                    "media": uplink_media,
                }
            )

    host_port_index: dict[str, int] = {str(device["name"]): 1 for device in access_switches}
    for index, host in enumerate(hosts):
        target_switch = access_switches[index % len(access_switches)]
        switch_name = str(target_switch["name"])
        access_index = host_port_index[switch_name]
        host_port_index[switch_name] += 1
        links.append(
            {
                "a": {"dev": host["name"], "port": _host_port(host)},
                "b": {"dev": switch_name, "port": _switch_access_port(access_index)},
                "media": "straight-through",
            }
        )
    return links


def _synthesize_vlan_and_link_ops(plan: IntentPlan, devices: list[dict[str, object]], links: list[dict[str, object]]) -> None:
    if not plan.vlan_ids:
        return

    switches = [device for device in devices if _device_kind(device) == "Switch"]
    routers = [device for device in devices if _device_kind(device) == "Router"]
    server_dhcp_requested = any(op.get("op") == "set_server_dhcp_pool" for op in plan.server_ops)
    allowed = list(plan.vlan_ids)
    core_switch = switches[0] if switches else None

    for switch in switches:
        for vlan_id in plan.vlan_ids:
            _append_unique_op(plan.switch_ops, {"op": "set_vlan", "device": switch["name"], "vlan": vlan_id, "name": f"VLAN{vlan_id}"})

    if core_switch is not None:
        switch_names = {str(switch["name"]) for switch in switches}
        for link in links:
            left_name = str(link["a"]["dev"])
            right_name = str(link["b"]["dev"])
            left_port = str(link["a"]["port"])
            right_port = str(link["b"]["port"])
            if {left_name, right_name} & switch_names:
                if "GigabitEthernet" in left_port:
                    if left_name in switch_names:
                        _append_unique_op(plan.switch_ops, {"op": "set_trunk_port", "device": left_name, "port": left_port, "allowed": allowed, "native": None})
                if "GigabitEthernet" in right_port:
                    if right_name in switch_names:
                        _append_unique_op(plan.switch_ops, {"op": "set_trunk_port", "device": right_name, "port": right_port, "allowed": allowed, "native": None})

    if routers:
        router = routers[0]
        base_port = _router_port(router, 1)
        for vlan_id in plan.vlan_ids:
            _append_unique_op(
                plan.router_ops,
                {
                    "op": "set_subinterface",
                    "device": router["name"],
                    "subinterface": f"{base_port}.{vlan_id}",
                    "vlan": vlan_id,
                    "ip": f"192.168.{vlan_id}.1",
                    "prefix": 24,
                },
            )
            if plan.topology_requirements.get("needs_dhcp_pool") and not server_dhcp_requested:
                _append_unique_op(
                    plan.router_ops,
                    {
                        "op": "set_router_dhcp_pool",
                        "device": router["name"],
                        "name": f"VLAN{vlan_id}",
                        "network": f"192.168.{vlan_id}.0",
                        "prefix": 24,
                        "gateway": f"192.168.{vlan_id}.1",
                        "dns": None,
                        "start": f"192.168.{vlan_id}.100",
                        "max_users": 100,
                    },
                )

    if plan.host_vlan_assignment and not plan.department_groups:
        access_port_links = [link for link in links if "FastEthernet0/" in str(link["b"]["port"]) and _device_kind(next(device for device in devices if device["name"] == link["b"]["dev"])) == "Switch"]
        vlan_queue: list[int] = []
        for vlan_id, count in sorted(plan.host_vlan_assignment.items()):
            vlan_queue.extend([vlan_id] * count)
        for link, vlan_id in zip(access_port_links, vlan_queue):
            _append_unique_op(
                plan.switch_ops,
                {
                    "op": "set_access_port",
                    "device": str(link["b"]["dev"]),
                    "port": str(link["b"]["port"]),
                    "vlan": vlan_id,
                },
            )
    if plan.department_groups:
        switch_by_group = {str(device.get("group") or ""): str(device["name"]) for device in switches if device.get("group")}
        for group in plan.department_groups:
            vlan_id = group.get("vlan_id")
            switch_name = switch_by_group.get(str(group["name"]))
            if not vlan_id or not switch_name:
                continue
            for link in links:
                if str(link["b"]["dev"]) != switch_name or "FastEthernet0/" not in str(link["b"]["port"]):
                    continue
                if str(link["a"]["dev"]).startswith(str(group["name"])):
                    _append_unique_op(
                        plan.switch_ops,
                        {
                            "op": "set_access_port",
                            "device": switch_name,
                            "port": str(link["b"]["port"]),
                            "vlan": int(vlan_id),
                        },
                    )
        management_vlan = 99 if 99 in plan.vlan_ids else (int(plan.vlan_ids[-1]) if plan.vlan_ids else None)
        if management_vlan is not None:
            standalone_device_names = {
                str(device["name"])
                for device in devices
                if not device.get("group") and _device_kind(device) not in {"Router", "Switch", "Power Distribution Device"}
            }
            for link in links:
                if str(link["a"]["dev"]) not in standalone_device_names:
                    continue
                if "FastEthernet0/" not in str(link["b"]["port"]):
                    continue
                _append_unique_op(
                    plan.switch_ops,
                    {
                        "op": "set_access_port",
                        "device": str(link["b"]["dev"]),
                        "port": str(link["b"]["port"]),
                        "vlan": int(management_vlan),
                    },
                )


def _build_topology_plan(plan: IntentPlan, devices: list[dict[str, object]], links: list[dict[str, object]]) -> TopologyPlan:
    archetype = _choose_topology_archetype(plan)
    layout = {str(device["name"]): {"x": int(device.get("x", 0)), "y": int(device.get("y", 0))} for device in devices}
    port_map: dict[str, list[str]] = {}
    for link in links:
        for endpoint in ["a", "b"]:
            device_name = str(link[endpoint]["dev"])
            port_map.setdefault(device_name, []).append(str(link[endpoint]["port"]))
    return TopologyPlan(
        topology_archetype=archetype,
        devices=devices,
        links=links,
        layout=layout,
        port_map=port_map,
    )


def _build_config_plan(plan: IntentPlan) -> ConfigPlan:
    return ConfigPlan(
        switch_ops=plan.switch_ops,
        router_ops=plan.router_ops,
        server_ops=plan.server_ops,
        wireless_ops=plan.wireless_ops,
        end_device_ops=plan.end_device_ops,
        management_ops=plan.management_ops,
        assumptions_used=plan.assumptions_used,
    )


def _name_sort_key(name: str) -> tuple[object, ...]:
    parts = re.split(r"(\d+)", name)
    key: list[object] = []
    for part in parts:
        if not part:
            continue
        key.append(int(part) if part.isdigit() else part.lower())
    return tuple(key)


def _donor_group_prefix(name: str, device_type: str) -> str | None:
    if device_type == "Switch":
        for suffix in ["-SWITCH", "-SW"]:
            if name.upper().endswith(suffix):
                return name[: -len(suffix)]
    if "-" in name and device_type not in {"Router", "Power Distribution Device"}:
        return name.split("-", 1)[0]
    return None


def _fallback_group_member_type(device_type: str) -> bool:
    return device_type in {"PC", "Server", "Printer", "Laptop", "Tablet", "LightWeightAccessPoint", "Smartphone"}


def _collect_donor_groups(root: ET.Element) -> list[dict[str, object]]:
    devices = inventory_devices(root)
    groups: list[dict[str, object]] = []
    for device in devices:
        if device["type"] != "Switch":
            continue
        prefix = _donor_group_prefix(device["name"], device["type"])
        if not prefix:
            continue
        members = [
            candidate
            for candidate in devices
            if candidate["name"] != device["name"]
            and _donor_group_prefix(candidate["name"], candidate["type"]) == prefix
        ]
        members_by_type: dict[str, list[dict[str, str]]] = {}
        for member in members:
            members_by_type.setdefault(member["type"], []).append(member)
        for bucket in members_by_type.values():
            bucket.sort(key=lambda item: _name_sort_key(item["name"]))
        groups.append(
            {
                "group_name": prefix,
                "switch": device,
                "members": members,
                "members_by_type": members_by_type,
            }
        )
    if groups:
        groups.sort(key=lambda item: _name_sort_key(str(item["group_name"])))
        return groups

    links = inventory_links(root)
    by_name = {str(device["name"]): device for device in devices}
    switches = [device for device in devices if device["type"] == "Switch"]
    switch_map = {
        str(device["name"]): {"group_name": str(device["name"]), "switch": device, "members": [], "members_by_type": {}}
        for device in switches
    }
    for link in links:
        ports = [str(port) for port in link.get("ports", [])]
        media = str(link.get("media") or "")
        if media == "eRollOver" or any("console" in port.lower() for port in ports):
            continue
        left_name = str(link.get("from") or "")
        right_name = str(link.get("to") or "")
        left = by_name.get(left_name)
        right = by_name.get(right_name)
        if left is None or right is None:
            continue
        left_type = _device_kind(left)
        right_type = _device_kind(right)
        if left_type == "Switch" and _fallback_group_member_type(right_type):
            switch_map[left_name]["members"].append(right)
        elif right_type == "Switch" and _fallback_group_member_type(left_type):
            switch_map[right_name]["members"].append(left)
    groups = []
    for group in switch_map.values():
        members = sorted(group["members"], key=lambda item: _name_sort_key(str(item["name"])))
        members_by_type: dict[str, list[dict[str, str]]] = {}
        for member in members:
            members_by_type.setdefault(member["type"], []).append(member)
        group["members"] = members
        group["members_by_type"] = members_by_type
        groups.append(group)
    groups.sort(key=lambda item: _name_sort_key(str(item["group_name"])))
    return groups


def _target_groups_from_blueprint(plan: IntentPlan, blueprint: dict[str, object]) -> list[dict[str, object]]:
    devices = [dict(device) for device in blueprint.get("devices", [])]
    links = [dict(link) for link in blueprint.get("links", [])]
    switches = [device for device in devices if _device_kind(device) == "Switch"]
    if plan.department_groups:
        result: list[dict[str, object]] = []
        for group in plan.department_groups:
            group_name = str(group["name"])
            switch = next((device for device in switches if str(device.get("group") or "") == group_name), None)
            if switch is None:
                continue
            members = [device for device in devices if str(device.get("group") or "") == group_name and _device_kind(device) != "Switch"]
            result.append({"group_name": group_name, "switch": switch, "members": members})
        return result
    groups: list[dict[str, object]] = []
    by_name = {str(device["name"]): device for device in devices}
    switch_map = {str(device["name"]): {"group_name": str(device["name"]), "switch": device, "members": []} for device in switches}
    host_assignment: dict[str, str] = {}
    for link in links:
        left_name = str(link["a"]["dev"])
        right_name = str(link["b"]["dev"])
        left_type = _device_kind(by_name.get(left_name, {}))
        right_type = _device_kind(by_name.get(right_name, {}))
        if left_type == "Switch" and right_type != "Switch":
            host_assignment[right_name] = left_name
        elif right_type == "Switch" and left_type != "Switch":
            host_assignment[left_name] = right_name
    switch_names = list(switch_map)
    fallback_index = 0
    for device in devices:
        if _device_kind(device) == "Switch":
            continue
        assigned_switch = host_assignment.get(str(device["name"]))
        if assigned_switch is None and switch_names:
            assigned_switch = switch_names[fallback_index % len(switch_names)]
            fallback_index += 1
        if assigned_switch and assigned_switch in switch_map:
            switch_map[assigned_switch]["members"].append(device)
    for switch in switches:
        groups.append(switch_map[str(switch["name"])])
    return groups


def _donor_capacity(root: ET.Element, donor_groups: list[dict[str, object]]) -> dict[str, object]:
    counts: dict[str, int] = {}
    for device in inventory_devices(root):
        counts[device["type"]] = counts.get(device["type"], 0) + 1
    group_counts: list[dict[str, object]] = []
    for group in donor_groups:
        member_counts: dict[str, int] = {}
        for member in group["members"]:
            member_counts[member["type"]] = member_counts.get(member["type"], 0) + 1
        group_counts.append(
            {
                "group_name": group["group_name"],
                "switch": group["switch"]["name"],
                "members": member_counts,
            }
        )
    return {"device_counts": counts, "group_count": len(donor_groups), "groups": group_counts}


def _sanitize_scenario_runtime(root: ET.Element) -> None:
    # Packet Tracer 9.0 is sensitive to donor scenario/runtime state. Preserve
    # these sections verbatim for donor-prune generation unless a future
    # sanitizer proves a narrower cleanup is safe.
    return


def _sanitize_visual_runtime(root: ET.Element, preserve_global_sections: bool = True) -> None:
    if preserve_global_sections:
        for rectangle in root.findall("./RECTANGLES/RECTANGLE"):
            if rectangle.find("./TopLeftX") is not None:
                rectangle.find("./TopLeftX").text = str(OFFSCREEN_X)
            if rectangle.find("./TopLeftY") is not None:
                rectangle.find("./TopLeftY").text = str(OFFSCREEN_Y)
            if rectangle.find("./BottomRightX") is not None:
                rectangle.find("./BottomRightX").text = str(OFFSCREEN_X + 1)
            if rectangle.find("./BottomRightY") is not None:
                rectangle.find("./BottomRightY").text = str(OFFSCREEN_Y + 1)
        for ellipse in root.findall("./ELLIPSES/ELLIPSE"):
            for tag, value in [
                ("TopLeftX", str(OFFSCREEN_X)),
                ("TopLeftY", str(OFFSCREEN_Y)),
                ("BottomRightX", str(OFFSCREEN_X + 1)),
                ("BottomRightY", str(OFFSCREEN_Y + 1)),
                ("CenterX", str(OFFSCREEN_X)),
                ("CenterY", str(OFFSCREEN_Y)),
                ("RadiusX", "1"),
                ("RadiusY", "1"),
            ]:
                node = ellipse.find(f"./{tag}")
                if node is not None:
                    node.text = value
        for polygon in root.findall("./POLYGONS/POLYGON"):
            points = polygon.find("./POINTS")
            if points is not None:
                points.clear()
                point = ET.SubElement(points, "POINT")
                ET.SubElement(point, "X").text = str(OFFSCREEN_X)
                ET.SubElement(point, "Y").text = str(OFFSCREEN_Y)
        for notes in root.findall("./PHYSICALWORKSPACE//NOTES"):
            for note in notes.findall("./NOTE"):
                for tag in ["X", "Y"]:
                    node = note.find(f"./{tag}")
                    if node is not None:
                        node.text = str(OFFSCREEN_X if tag == "X" else OFFSCREEN_Y)
                text_node = note.find("./TEXT")
                if text_node is not None:
                    text_node.text = ""
        return
    for tag in ["FILTERS", "CLUSTERS", "LINES", "RECTANGLES", "ELLIPSES", "POLYGONS", "GEOVIEW_GRAPHICSITEMS", "NOTES"]:
        for node in root.findall(f".//{tag}"):
            node.clear()


def _sanitize_runtime_sections(root: ET.Element, preserve_global_sections: bool = True) -> None:
    _sanitize_scenario_runtime(root)
    _sanitize_visual_runtime(root, preserve_global_sections=preserve_global_sections)


def _unexpected_workspace_issues(donor_root: ET.Element, generated_root: ET.Element) -> list[str]:
    donor_result = inspect_workspace_integrity(donor_root)
    generated_result = inspect_workspace_integrity(generated_root)
    donor_issue_set = set(donor_result.blocking_issues)
    return [issue for issue in generated_result.blocking_issues if issue not in donor_issue_set]


def _build_donor_prune_plan_for_donor(plan: IntentPlan, blueprint: dict[str, object], compat_donor: Path) -> tuple[IntentPlan, DonorArchetypePlan]:
    donor_root = decode_pkt_to_root(compat_donor)
    donor_groups = _collect_donor_groups(donor_root)
    target_groups = _target_groups_from_blueprint(plan, blueprint)
    adapted_plan = copy.deepcopy(plan)
    adapted_plan.edit_operations = []
    donor_devices = inventory_devices(donor_root)
    donor_links = inventory_links(donor_root)
    donor_capacity = _donor_capacity(donor_root, donor_groups)
    if len(target_groups) > len(donor_groups):
        gap = f"Compatibility donor supports only {len(donor_groups)} switch groups; requested {len(target_groups)}."
        if gap not in adapted_plan.blocking_gaps:
            adapted_plan.blocking_gaps.append(gap)
        raise PlanningError("Prompt plan is incomplete; generation was skipped.", adapted_plan)

    kept_devices: set[str] = set()
    parked_devices: list[str] = []
    renamed_devices: list[dict[str, str]] = []
    mutation_groups: list[dict[str, object]] = []
    rename_map: dict[str, str] = {}
    spare_candidates_by_type: dict[str, list[dict[str, object]]] = {}

    def keep_name(old_name: str, new_name: str | None = None, x: int | None = None, y: int | None = None) -> None:
        kept_devices.add(old_name)
        final_name = new_name or old_name
        rename_map[old_name] = final_name
        if old_name != final_name:
            adapted_plan.edit_operations.append({"op": "rename_device", "device": old_name, "new_name": final_name})
            renamed_devices.append({"from": old_name, "to": final_name})
        if x is not None and y is not None:
            adapted_plan.edit_operations.append({"op": "reflow_layout", "device": final_name, "x": int(x), "y": int(y)})

    park_cursor = {"index": 0}

    def queue_spare(
        donor_member: dict[str, object],
        anchor_x: int,
        anchor_y: int,
        local_index: int,
        group_name: str | None,
    ) -> None:
        spare_candidates_by_type.setdefault(_device_kind(donor_member), []).append(
            {
                "device": donor_member,
                "anchor_x": anchor_x,
                "anchor_y": anchor_y,
                "local_index": local_index,
                "group_name": group_name,
            }
        )

    def park_device(
        old_name: str,
        anchor_x: int | None = None,
        anchor_y: int | None = None,
        local_index: int | None = None,
        parked_name: str | None = None,
    ) -> None:
        if old_name in kept_devices:
            return
        kept_devices.add(old_name)
        final_name = parked_name or old_name
        rename_map[old_name] = final_name
        if old_name != final_name:
            adapted_plan.edit_operations.append({"op": "rename_device", "device": old_name, "new_name": final_name})
            renamed_devices.append({"from": old_name, "to": final_name})
        if local_index is None:
            park_index = park_cursor["index"]
            park_cursor["index"] += 1
        else:
            park_index = local_index
        parked_devices.append(final_name)
        if anchor_x is None:
            anchor_x = 9000
        if anchor_y is None:
            anchor_y = 500
        col = park_index % 3
        row = park_index // 3
        adapted_plan.edit_operations.append(
            {
                "op": "reflow_layout",
                "device": final_name,
                "x": int(anchor_x + (-130 + col * 130)),
                "y": int(anchor_y + row * 115),
            }
        )

    target_router = next((device for device in blueprint.get("devices", []) if _device_kind(device) == "Router"), None)
    donor_router = next((device for device in donor_devices if device["type"] == "Router"), None)
    if target_router is not None:
        if donor_router is None:
            gap = "Compatibility donor does not contain a router prototype for prompt generation."
            if gap not in adapted_plan.blocking_gaps:
                adapted_plan.blocking_gaps.append(gap)
            raise PlanningError("Prompt plan is incomplete; generation was skipped.", adapted_plan)
        keep_name(str(donor_router["name"]), str(target_router["name"]), int(target_router.get("x", 0)), int(target_router.get("y", 0)))
    elif donor_router is not None:
        park_device(str(donor_router["name"]))

    grouped_donor_names = {
        str(group["switch"]["name"])
        for group in donor_groups
    } | {
        str(member["name"])
        for group in donor_groups
        for member in group["members"]
    }
    for donor_device in donor_devices:
        donor_name = str(donor_device["name"])
        donor_type = _device_kind(donor_device)
        if donor_name in grouped_donor_names or donor_name in kept_devices:
            continue
        if donor_type in {"Router", "Switch"}:
            continue
        if donor_type == "Power Distribution Device":
            keep_name(donor_name, donor_name, 2620, 120)
            continue
        queue_spare(donor_device, 9000, 500, park_cursor["index"], None)
        park_cursor["index"] += 1

    for donor_group, target_group in zip(donor_groups, target_groups):
        group_kept: list[str] = []
        group_park_index = 0
        donor_switch = donor_group["switch"]
        target_switch = target_group["switch"]
        switch_x = int(target_switch.get("x", 0))
        switch_y = int(target_switch.get("y", 0))
        park_anchor_x = 9000 + max(0, int((switch_x - 420) / 2))
        park_anchor_y = 500 + max(0, int((switch_y - 310) / 2))
        keep_name(str(donor_switch["name"]), str(target_switch["name"]), int(target_switch.get("x", 0)), int(target_switch.get("y", 0)))
        group_kept.append(str(target_switch["name"]))
        target_members_by_type: dict[str, list[dict[str, object]]] = {}
        for member in target_group["members"]:
            target_members_by_type.setdefault(_device_kind(member), []).append(member)
        for members in target_members_by_type.values():
            members.sort(key=lambda item: _name_sort_key(str(item["name"])))
        donor_members_by_type = donor_group["members_by_type"]
        for device_type, wanted in target_members_by_type.items():
            available = donor_members_by_type.get(device_type, [])
            if len(wanted) > len(available):
                gap = (
                    f"Compatibility donor group {donor_group['group_name']} has only {len(available)} {device_type} device(s); "
                    f"requested {len(wanted)} for {target_group['group_name']}."
                )
                if gap not in adapted_plan.blocking_gaps:
                    adapted_plan.blocking_gaps.append(gap)
                raise PlanningError("Prompt plan is incomplete; generation was skipped.", adapted_plan)
            for donor_member, target_member in zip(available, wanted):
                keep_name(
                    str(donor_member["name"]),
                    str(target_member["name"]),
                    int(target_member.get("x", 0)),
                    int(target_member.get("y", 0)),
                )
                group_kept.append(str(target_member["name"]))
            for donor_member in available[len(wanted) :]:
                queue_spare(donor_member, park_anchor_x, park_anchor_y, group_park_index, str(target_group["group_name"]))
                group_park_index += 1
        for device_type, available in donor_members_by_type.items():
            if device_type in target_members_by_type:
                continue
            for donor_member in available:
                queue_spare(donor_member, park_anchor_x, park_anchor_y, group_park_index, str(target_group["group_name"]))
                group_park_index += 1
        mutation_groups.append(
            {
                "donor_group": donor_group["group_name"],
                "target_group": target_group["group_name"],
                "kept_devices": group_kept,
            }
        )

    grouped_target_names = {
        str(group["switch"]["name"])
        for group in target_groups
    } | {
        str(member["name"])
        for group in target_groups
        for member in group["members"]
    }
    standalone_targets = [
        dict(device)
        for device in blueprint.get("devices", [])
        if str(device.get("name")) not in grouped_target_names and _device_kind(device) not in {"Router", "Switch", "Power Distribution Device"}
    ]
    standalone_targets.sort(key=lambda item: _name_sort_key(str(item["name"])))
    for target in standalone_targets:
        device_type = _device_kind(target)
        available_pool = spare_candidates_by_type.get(device_type, [])
        if not available_pool:
            gap = f"Compatibility donor does not have a spare {device_type} device for standalone target {target['name']}."
            if gap not in adapted_plan.blocking_gaps:
                adapted_plan.blocking_gaps.append(gap)
            raise PlanningError("Prompt plan is incomplete; generation was skipped.", adapted_plan)
        chosen = available_pool.pop(0)
        donor_member = chosen["device"]
        keep_name(
            str(donor_member["name"]),
            str(target["name"]),
            int(target.get("x", 0)),
            int(target.get("y", 0)),
        )

    spare_name_counts: dict[tuple[str | None, str], int] = {}
    for device_type, candidates in spare_candidates_by_type.items():
        for candidate in candidates:
            donor_member = candidate["device"]
            group_name = candidate.get("group_name")
            count_key = (str(group_name) if group_name is not None else None, device_type)
            spare_name_counts[count_key] = spare_name_counts.get(count_key, 0) + 1
            spare_index = spare_name_counts[count_key]
            spare_name = (
                f"{group_name}-SPARE-{device_type.upper()}{spare_index}"
                if group_name
                else f"UNUSED-{device_type.upper()}{spare_index}"
            )
            park_device(
                str(donor_member["name"]),
                int(candidate["anchor_x"]),
                int(candidate["anchor_y"]),
                int(candidate["local_index"]),
                spare_name,
            )

    for donor_group in donor_groups[len(target_groups) :]:
        names = [str(donor_group["switch"]["name"]), *[str(member["name"]) for member in donor_group["members"]]]
        donor_switch = donor_group["switch"]
        switch_x = 9800
        switch_y = 900
        group_park_index = 0
        for name in names:
            park_device(name, switch_x, switch_y + 650, group_park_index)
            group_park_index += 1
        mutation_groups.append({"donor_group": donor_group["group_name"], "target_group": None, "parked_devices": names})

    desired_device_names = {str(device["name"]) for device in blueprint.get("devices", [])}
    desired_pairs = {
        tuple(sorted((str(link["a"]["dev"]), str(link["b"]["dev"]))))
        for link in blueprint.get("links", [])
    }
    existing_links: dict[tuple[str, str], dict[str, object]] = {}
    for donor_link in donor_links:
        left_name = rename_map.get(str(donor_link["from"]), str(donor_link["from"]))
        right_name = rename_map.get(str(donor_link["to"]), str(donor_link["to"]))
        if not left_name or not right_name or left_name == right_name:
            continue
        pair = tuple(sorted((left_name, right_name)))
        existing_links[pair] = donor_link
    parked_name_set = set(parked_devices)
    removed_pairs: set[tuple[str, str]] = set()
    for donor_link in donor_links:
        left_name = rename_map.get(str(donor_link["from"]), str(donor_link["from"]))
        right_name = rename_map.get(str(donor_link["to"]), str(donor_link["to"]))
        if not left_name or not right_name or left_name == right_name:
            continue
        pair = tuple(sorted((left_name, right_name)))
        if pair in removed_pairs:
            continue
        if left_name in parked_name_set or right_name in parked_name_set:
            adapted_plan.edit_operations.append({"op": "remove_link", "a": {"dev": left_name}, "b": {"dev": right_name}})
            removed_pairs.add(pair)
            continue
        if left_name in desired_device_names and right_name in desired_device_names and pair not in desired_pairs:
            adapted_plan.edit_operations.append({"op": "remove_link", "a": {"dev": left_name}, "b": {"dev": right_name}})
            removed_pairs.add(pair)
    link_reuse_gaps: list[str] = []
    for link in blueprint.get("links", []):
        desired_left = str(link["a"]["dev"])
        desired_right = str(link["b"]["dev"])
        desired_pair = tuple(sorted((desired_left, desired_right)))
        existing = existing_links.get(desired_pair)
        desired_ports = [str(link["a"]["port"]), str(link["b"]["port"])]
        desired_media = str(link.get("media", "straight-through"))
        if existing is None:
            link_reuse_gaps.append(
                f"Open-first mode cannot create new donor link pair {desired_left} <-> {desired_right}; "
                "this donor does not contain that device-to-device link."
            )
            continue
        existing_ports = [str(port) for port in existing.get("ports", [])]
        existing_media = str(existing.get("media", ""))
        if not (
            len(existing_ports) >= 2
            and sorted(existing_ports[:2]) == sorted(desired_ports)
            and existing_media == desired_media
        ):
            link_reuse_gaps.append(
                f"Open-first mode requires donor link reuse for {desired_left} <-> {desired_right}; "
                f"donor ports/media are {existing_ports[:2]} / {existing_media}, requested {desired_ports} / {desired_media}."
            )
            continue
    if link_reuse_gaps:
        for gap in link_reuse_gaps:
            if gap not in adapted_plan.blocking_gaps:
                adapted_plan.blocking_gaps.append(gap)
        raise PlanningError("Prompt plan is incomplete; generation was skipped.", adapted_plan)
    archetype_plan = DonorArchetypePlan(
        compat_donor=str(compat_donor),
        donor_capacity=donor_capacity,
        kept_devices=sorted([name for name in rename_map.values() if name not in set(parked_devices)], key=_name_sort_key),
        pruned_devices=sorted(dict.fromkeys(parked_devices), key=_name_sort_key),
        renamed_devices=renamed_devices,
        mutation_groups=mutation_groups,
        layout_strategy="donor_park_clean",
    )
    return adapted_plan, archetype_plan


def _build_donor_prune_plan(
    plan: IntentPlan,
    blueprint: dict[str, object],
    donor_roots: list[Path] | None = None,
) -> tuple[IntentPlan, DonorArchetypePlan]:
    topology_tags = _topology_tags_for_plan(plan, str(blueprint.get("topology_archetype", "general")))
    _, _, donor_candidates = _rank_generation_donors(plan, topology_tags, donor_roots)
    donor_candidates = _rerank_candidates_for_blueprint(donor_candidates, blueprint)
    if not donor_candidates:
        blocked_plan = _copy_plan(plan)
        if STRICT_COMPATIBILITY_GAP not in blocked_plan.blocking_gaps:
            blocked_plan.blocking_gaps.append(STRICT_COMPATIBILITY_GAP)
        raise PlanningError("Prompt plan is incomplete; generation was skipped.", blocked_plan)

    evaluation, diagnostics = _evaluate_donor_prune_candidates(plan, blueprint, donor_candidates)
    if evaluation is not None:
        adapted_plan, archetype_plan, _, _ = evaluation
        return adapted_plan, archetype_plan

    blocked_plan = _copy_plan(plan)
    summary = "No ranked donor candidate passed donor-prune compatibility validation."
    failure_messages = [
        f"{item['relative_path']}: {'; '.join(item.get('rejection_reasons', [])[:3])}"
        for item in diagnostics
        if item.get("status") in {"rejected", "filtered"} and item.get("rejection_reasons")
    ]
    details = "; ".join(message for message in failure_messages[:5] if message)
    combined = f"{summary} {details}".strip()
    if combined not in blocked_plan.blocking_gaps:
        blocked_plan.blocking_gaps.append(combined)
    raise PlanningError("Prompt plan is incomplete; generation was skipped.", blocked_plan)


def _augment_coverage_gap_actions(
    coverage_gap: dict[str, object],
    *,
    donor_diagnostics: list[dict[str, object]] | None = None,
    donor_selection_summary: dict[str, object] | None = None,
    donor_blocking_reason: str | None = None,
) -> dict[str, object]:
    updated = copy.deepcopy(coverage_gap)
    actions = [str(item) for item in updated.get("recommended_next_actions", []) if str(item).strip()]
    if donor_blocking_reason and "Twofish" in donor_blocking_reason:
        actions.append("Configure PKT_TWOFISH_LIBRARY and use Python 3.14 so Packet Tracer 9.0 donor files can be decoded.")
    diagnostics = donor_diagnostics or []
    selection_summary = donor_selection_summary or {}
    if any(
        any("cannot create new donor link pair" in str(reason) or "requires donor link reuse" in str(reason) for reason in item.get("rejection_reasons", []))
        for item in diagnostics
    ):
        actions.append("Choose or import a donor whose existing link skeleton already contains the required device-to-device pairs.")
    if any(
        any("ports/media" in str(reason) or "port mismatch" in str(reason) or "media mismatch" in str(reason) for reason in item.get("rejection_reasons", []))
        for item in diagnostics
    ):
        actions.append("Adjust requested ports/media or select a donor whose existing cable and port layout already matches the prompt.")
    preferred_archetypes = [str(item) for item in selection_summary.get("preferred_donor_archetypes", []) if str(item).strip()]
    candidate_counts = selection_summary.get("candidate_counts", {})
    if preferred_archetypes and any(int(candidate_counts.get(key, 0)) > 0 for key in ["filtered", "rejected"]):
        actions.append(
            "Prefer a donor whose archetype matches the prompt shape: "
            + ", ".join(preferred_archetypes)
            + "."
        )
    best_layout_reuse_score = selection_summary.get("best_layout_reuse_score")
    if isinstance(best_layout_reuse_score, int) and best_layout_reuse_score <= 0:
        actions.append("Simplify the topology or import a donor with a closer reusable layout skeleton before generating.")
    top_rejection_reasons = [str(item) for item in selection_summary.get("top_rejection_reasons", []) if str(item).strip()]
    if any("archetype_gap:" in reason or "archetype does not align" in reason for reason in top_rejection_reasons):
        actions.append("Re-run with a donor family closer to the requested scenario, or reduce the prompt to the donor's existing archetype.")
    if updated.get("unsupported_capabilities"):
        actions.append("Use --blueprint-out to review unsupported capabilities, then import a donor that explicitly covers them.")
    scenario_readiness = updated.get("scenario_generate_readiness") or {}
    scenario_family = str(scenario_readiness.get("family") or "").strip()
    scenario_status = str(scenario_readiness.get("status") or "").strip()
    if scenario_family == "campus" and scenario_status in {"donor_limited", "acceptance_gated", "unsupported"}:
        actions.append("For campus prompts, prefer a campus/core donor with reusable router-switch-management skeleton before generating.")
    if scenario_family == "service_heavy" and scenario_status in {"donor_limited", "acceptance_gated", "unsupported"}:
        actions.append("For service-heavy prompts, prefer a donor that already contains the required server service family and core server layout.")
    if scenario_family == "home_iot" and scenario_status in {"donor_limited", "acceptance_gated", "unsupported"}:
        actions.append("For home IoT prompts, prefer a donor with Home Gateway plus existing IoT registration/control structure.")
        actions.append("For donor-backed Home IoT generate, explicitly name the thing, gateway/server target, and wireless client or SSID targets.")
    if scenario_family == "wan_security_edge" and scenario_status in {"donor_limited", "acceptance_gated", "unsupported"}:
        actions.append("For WAN/security prompts, prefer a donor with reusable serial/WAN or security-edge skeleton before generating.")
    if scenario_family in {"ipv6_routing", "l2_security_monitoring", "wireless_advanced", "automation_controller", "voice_collaboration", "industrial_iot", "physical_media_device"} and scenario_status in {"donor_limited", "acceptance_gated", "unsupported"}:
        actions.append("This feature family is atlas/report-first; keep it out of strict generate until donor-backed proof and acceptance fixtures exist.")
    updated["recommended_next_actions"] = list(dict.fromkeys(actions))
    return updated


def _scenario_generate_decision(
    coverage_gap: dict[str, object],
    *,
    donor_selection_summary: dict[str, object] | None = None,
    selected_donor_summary: dict[str, object] | None = None,
    runtime_blocked: bool = False,
    runtime_blocking_reason: str | None = None,
) -> dict[str, object]:
    readiness = dict(coverage_gap.get("scenario_generate_readiness") or {})
    family = str(readiness.get("family") or "").strip()
    readiness_status = str(readiness.get("status") or "").strip()
    candidate_counts = dict((donor_selection_summary or {}).get("candidate_counts", {}) or {})
    donor_state = "selected" if selected_donor_summary else "not_selected"
    if donor_state == "not_selected" and any(int(candidate_counts.get(key, 0) or 0) > 0 for key in ("rejected", "filtered")):
        donor_state = "candidate_pool_blocked"
    if donor_state == "not_selected" and int(candidate_counts.get("selected", 0) or 0) > 0:
        donor_state = "selection_pending"
    decision = {
        "family": family or None,
        "status": "not_classified",
        "readiness_status": readiness_status or "not_classified",
        "allow_generate": False,
        "blocking_reasons": [],
        "selected_donor_aligned": None,
        "notes": [],
        "runtime_blocked": runtime_blocked,
        "what_failed": None,
        "why_failed": None,
        "what_would_make_it_pass": None,
        "decision_confidence": 0.4,
        "blocking_layer": None,
    }
    if not family or readiness_status in {"", "not_classified", "partial"}:
        decision["status"] = "ready_without_selected_donor"
        decision["what_failed"] = "scenario classification"
        decision["why_failed"] = "Scenario family is not classified strongly enough for a strict generate verdict."
        decision["what_would_make_it_pass"] = "Provide a more explicit topology/service prompt so the scenario family and donor archetype are constrained."
        decision["decision_confidence"] = 0.45
        decision["blocking_layer"] = "capability"
        return decision

    family_label_map = {
        "campus": "campus/core",
        "service_heavy": "service-heavy",
        "home_iot": "home IoT",
        "wan_security_edge": "WAN/security edge",
        "ipv6_routing": "IPv6/routing",
        "l2_security_monitoring": "L2 security/monitoring",
        "wireless_advanced": "advanced wireless",
        "automation_controller": "automation/controller",
        "voice_collaboration": "voice/collaboration",
        "industrial_iot": "industrial IoT",
        "physical_media_device": "physical/media device",
    }
    expected_archetype_map = {
        "campus": "campus/core",
        "service_heavy": "service-heavy",
        "home_iot": "IoT/home gateway",
        "wan_security_edge": "WAN/security edge",
        "ipv6_routing": "IPv6/routing",
        "l2_security_monitoring": "L2 security/monitoring",
        "wireless_advanced": "advanced wireless",
        "automation_controller": "automation/controller",
        "voice_collaboration": "voice/collaboration",
        "industrial_iot": "industrial IoT",
        "physical_media_device": "physical/media device",
    }
    family_label = family_label_map.get(family, family)
    blocking_reasons: list[str] = []
    notes: list[str] = []
    what_failed = None
    why_failed = None
    what_would_make_it_pass = next(
        (str(item) for item in coverage_gap.get("recommended_next_actions", []) if str(item).strip()),
        None,
    )
    expected_archetype = expected_archetype_map.get(family)
    sample_archetypes = [str(item) for item in list((selected_donor_summary or {}).get("sample_archetypes", [])) if str(item).strip()]
    donor_graph_summary = dict((selected_donor_summary or {}).get("donor_graph_summary") or {})
    best_rejected_donor_class = str((donor_selection_summary or {}).get("best_rejected_donor_class") or "").strip() or None
    primary_rejection_code = str((donor_selection_summary or {}).get("primary_rejection_code") or "").strip() or None
    best_rejected_donor_summary = _best_rejected_donor_summary(
        best_rejected_donor_class,
        primary_rejection_code,
        [str(item) for item in list((donor_selection_summary or {}).get("top_rejection_reasons", [])) if str(item).strip()],
    )
    if expected_archetype and sample_archetypes:
        aligned = expected_archetype in sample_archetypes
        decision["selected_donor_aligned"] = aligned
        if aligned:
            notes.append(f"selected donor archetype aligns with {expected_archetype}")
        else:
            notes.append(f"selected donor archetypes ({', '.join(sample_archetypes)}) do not match expected {expected_archetype}")
    elif expected_archetype and selected_donor_summary:
        decision["selected_donor_aligned"] = False
        notes.append(f"selected donor summary is missing archetype tags for expected {expected_archetype}")

    if runtime_blocked:
        blocking_reasons.append(
            f"Scenario '{family_label}' is blocked by runtime prerequisites: {runtime_blocking_reason or 'runtime is not ready'}."
        )
        decision["status"] = "blocked_by_runtime"
        decision["blocking_layer"] = "runtime"
        decision["decision_confidence"] = 0.95
        what_failed = "runtime readiness"
        why_failed = runtime_blocking_reason or "Runtime prerequisites required for strict generate are not ready."
    elif readiness_status == "unsupported":
        blocking_reasons.append(
            f"Scenario '{family_label}' is not generate-ready in safe-open mode because critical capability coverage is still missing."
        )
        decision["status"] = "blocked_by_capability"
        decision["blocking_layer"] = "capability"
        decision["decision_confidence"] = 0.9
        what_failed = "critical capability coverage"
        why_failed = "; ".join(str(item) for item in list(readiness.get("reasons", [])) if str(item).strip()) or (
            f"Critical capabilities for {family_label} are still unsupported."
        )
    elif readiness_status == "acceptance_gated":
        blocking_reasons.append(
            f"Scenario '{family_label}' is still acceptance-gated; use edit/inventory flow or donor-backed validation before prompt generate."
        )
        decision["status"] = "blocked_by_acceptance"
        decision["blocking_layer"] = "acceptance"
        decision["decision_confidence"] = 0.85
        what_failed = "acceptance coverage"
        why_failed = "; ".join(str(item) for item in list(readiness.get("reasons", [])) if str(item).strip()) or (
            f"Critical capabilities for {family_label} are still acceptance-gated."
        )
    elif readiness_status == "donor_limited":
        if not selected_donor_summary and int(candidate_counts.get("selected", 0) or 0) <= 0:
            blocking_reasons.append(
                f"Scenario '{family_label}' depends on donor-limited safe-open coverage, but no compatible donor was selected."
            )
        if best_rejected_donor_summary:
            notes.append(best_rejected_donor_summary)
        layout_status = str(donor_graph_summary.get("layout_reuse_status") or "").strip()
        pair_coverage = donor_graph_summary.get("reusable_pair_coverage")
        if layout_status == "weak":
            blocking_reasons.append(
                f"Scenario '{family_label}' donor selection is too weak for safe-open generate; choose a donor with stronger reusable layout skeleton."
            )
        if isinstance(pair_coverage, int) and pair_coverage <= 0:
            blocking_reasons.append(
                f"Scenario '{family_label}' donor selection has no reusable link-pair coverage for prompt generate."
            )
        if primary_rejection_code == "archetype_misaligned":
            blocking_reasons.append(
                f"Scenario '{family_label}' best donor class is still archetype-misaligned with the requested prompt shape."
            )
        elif primary_rejection_code == "runtime_subtree_missing":
            blocking_reasons.append(
                f"Scenario '{family_label}' donor candidates are missing required runtime subtree coverage for strict reuse."
            )
        elif primary_rejection_code == "acceptance_evidence_too_weak":
            blocking_reasons.append(
                f"Scenario '{family_label}' donor candidates still lack strong enough acceptance evidence for strict prompt generate."
            )
        if layout_status in {"strong", "partial"} and isinstance(pair_coverage, int) and pair_coverage > 0:
            notes.append(f"selected donor provides {pair_coverage}% reusable link-pair coverage ({layout_status})")
        if selected_donor_summary and not blocking_reasons:
            decision["status"] = "ready_with_selected_donor"
            decision["decision_confidence"] = 0.92 if decision.get("selected_donor_aligned") is not False else 0.72
        else:
            decision["status"] = "blocked_by_donor_selection"
            decision["blocking_layer"] = "donor"
            decision["decision_confidence"] = 0.75
            what_failed = "donor selection"
            why_failed = "; ".join(blocking_reasons) or (
                f"{family_label} requires a stronger donor skeleton and acceptance evidence."
            )
    elif selected_donor_summary:
        decision["status"] = "ready_with_selected_donor"
        decision["decision_confidence"] = 0.95 if decision.get("selected_donor_aligned") is not False else 0.7
    else:
        decision["status"] = "ready_without_selected_donor"
        decision["blocking_layer"] = "donor"
        decision["decision_confidence"] = 0.55
        what_failed = "donor selection"
        why_failed = f"{family_label} capability coverage is ready, but a compatible donor has not been selected yet."

    if decision["status"] == "ready_with_selected_donor":
        decision["allow_generate"] = True
    else:
        decision["allow_generate"] = False

    if blocking_reasons:
        decision["blocking_reasons"] = blocking_reasons
    if not decision["allow_generate"] and what_failed is None:
        what_failed = "donor selection"
    if not decision["allow_generate"] and why_failed is None:
        why_failed = "; ".join(blocking_reasons) or "Strict generate prerequisites are not fully satisfied."
    if decision["allow_generate"] and what_would_make_it_pass is None:
        what_would_make_it_pass = "No additional action required."
    if decision["allow_generate"]:
        what_failed = None
        why_failed = None
    decision["notes"] = notes
    decision["what_failed"] = what_failed
    decision["why_failed"] = why_failed
    decision["what_would_make_it_pass"] = what_would_make_it_pass
    return decision


def _scenario_acceptance_summary(
    coverage_gap: dict[str, object],
    *,
    donor_selection_summary: dict[str, object] | None = None,
    selected_donor_summary: dict[str, object] | None = None,
    runtime_blocked: bool = False,
    runtime_blocking_reason: str | None = None,
) -> dict[str, object]:
    decision = _scenario_generate_decision(
        coverage_gap,
        donor_selection_summary=donor_selection_summary,
        selected_donor_summary=selected_donor_summary,
        runtime_blocked=runtime_blocked,
        runtime_blocking_reason=runtime_blocking_reason,
    )
    readiness = dict(coverage_gap.get("scenario_generate_readiness") or {})
    candidate_counts = dict((donor_selection_summary or {}).get("candidate_counts", {}) or {})
    donor_state = "selected" if selected_donor_summary else "not_selected"
    if donor_state == "not_selected" and any(int(candidate_counts.get(key, 0) or 0) > 0 for key in ("rejected", "filtered")):
        donor_state = "candidate_pool_blocked"
    if donor_state == "not_selected" and int(candidate_counts.get("selected", 0) or 0) > 0:
        donor_state = "selection_pending"
    key_reasons = [str(item) for item in decision.get("blocking_reasons", []) if str(item).strip()]
    if not key_reasons:
        key_reasons = [str(item) for item in decision.get("notes", []) if str(item).strip()]
    next_best_action = next(
        (str(item) for item in coverage_gap.get("recommended_next_actions", []) if str(item).strip()),
        None,
    )
    top_rejection_reasons = [str(item) for item in list((donor_selection_summary or {}).get("top_rejection_reasons", [])) if str(item).strip()]
    primary_rejection_code = str((donor_selection_summary or {}).get("primary_rejection_code") or "").strip() or _primary_rejection_code(top_rejection_reasons)
    primary_rejection_layer = str((donor_selection_summary or {}).get("primary_rejection_layer") or "").strip() or _primary_rejection_layer(primary_rejection_code)
    best_rejected_donor_class = str((donor_selection_summary or {}).get("best_rejected_donor_class") or "").strip() or None
    selection_failure_type = None
    if not selected_donor_summary:
        if primary_rejection_code == "archetype_misaligned":
            selection_failure_type = "viable_donor_found_but_archetype_misaligned"
        elif primary_rejection_code == "runtime_subtree_missing":
            selection_failure_type = "viable_donor_found_but_runtime_subtree_missing"
        elif donor_state in {"candidate_pool_blocked", "selection_pending"}:
            selection_failure_type = "viable_donor_found_but_acceptance_weak"
        else:
            selection_failure_type = "no_viable_donor_found"
    critical_capability_parity, critical_parity_mismatches = _critical_capability_parity(coverage_gap)
    best_available_donor_class = next(
        (
            str(item)
            for item in list((donor_selection_summary or {}).get("preferred_donor_archetypes", []))
            if str(item).strip()
        ),
        None,
    )
    if best_available_donor_class is None:
        family_donor_class_map = {
            "campus": "campus/core",
            "service_heavy": "service-heavy",
            "home_iot": "IoT/home gateway",
            "wan_security_edge": "WAN/security edge",
            "ipv6_routing": "IPv6/routing",
            "l2_security_monitoring": "L2 security/monitoring",
            "wireless_advanced": "advanced wireless",
            "automation_controller": "automation/controller",
            "voice_collaboration": "voice/collaboration",
            "industrial_iot": "industrial IoT",
            "physical_media_device": "physical/media device",
        }
        best_available_donor_class = family_donor_class_map.get(str(readiness.get("family") or "").strip())
    if selected_donor_summary:
        best_rejected_donor_class = None
        primary_rejection_code = None
        primary_rejection_layer = None
    elif best_rejected_donor_class is None:
        best_rejected_donor_class = best_available_donor_class
    remediation_steps = [
        str(item)
        for item in list(coverage_gap.get("recommended_next_actions", []))
        if str(item).strip()
    ][:3]
    best_rejected_donor_summary = _best_rejected_donor_summary(
        best_rejected_donor_class,
        primary_rejection_code,
        top_rejection_reasons,
    )
    if best_rejected_donor_summary:
        remediation_steps = [best_rejected_donor_summary, *remediation_steps][:3]
    missing_donor_classes = [best_available_donor_class] if selection_failure_type == "viable_donor_found_but_archetype_misaligned" and best_available_donor_class else []
    critical_runtime_requirements: list[str] = []
    if runtime_blocked:
        critical_runtime_requirements.append("decode/edit/generate runtime")
        if runtime_blocking_reason:
            critical_runtime_requirements.append(str(runtime_blocking_reason))
    return {
        "family": decision.get("family"),
        "readiness_status": readiness.get("status"),
        "decision_state": decision.get("status"),
        "generate_state": "allowed" if decision.get("allow_generate") else "blocked",
        "donor_state": donor_state,
        "selected_donor_aligned": decision.get("selected_donor_aligned"),
        "candidate_counts": candidate_counts,
        "selection_failure_type": selection_failure_type,
        "top_rejection_reasons": top_rejection_reasons[:3],
        "critical_capabilities": [str(item) for item in list(readiness.get("critical_capabilities", [])) if str(item).strip()],
        "missing_critical_capabilities": [str(item) for item in list(readiness.get("missing_critical_capabilities", [])) if str(item).strip()],
        "critical_capability_parity": critical_capability_parity,
        "critical_parity_mismatches": critical_parity_mismatches,
        "key_reasons": key_reasons[:3],
        "next_best_action": next_best_action,
        "remediation_steps": remediation_steps,
        "best_available_donor_class": best_available_donor_class,
        "best_rejected_donor_class": best_rejected_donor_class,
        "best_rejected_donor_summary": best_rejected_donor_summary,
        "missing_donor_classes": missing_donor_classes,
        "critical_runtime_requirements": critical_runtime_requirements,
        "decision_confidence": decision.get("decision_confidence"),
        "blocking_layer": decision.get("blocking_layer"),
        "primary_rejection_layer": primary_rejection_layer,
        "primary_rejection_code": primary_rejection_code,
    }


def _scenario_matrix_row(
    scenario_acceptance_summary: dict[str, object] | None,
    *,
    selected_donor_summary: dict[str, object] | None = None,
) -> dict[str, object]:
    summary = dict(scenario_acceptance_summary or {})
    donor_relative_path = str((selected_donor_summary or {}).get("relative_path") or "").strip() or None
    generate_state = str(summary.get("generate_state") or "").strip()
    donor_state = str(summary.get("donor_state") or "").strip()
    acceptance_label = str(summary.get("decision_state") or "").strip()
    if not acceptance_label:
        if generate_state == "allowed" and donor_state == "selected":
            acceptance_label = "ready_with_selected_donor"
        elif generate_state == "allowed":
            acceptance_label = "ready_without_selected_donor"
        elif donor_state in {"candidate_pool_blocked", "selection_pending"}:
            acceptance_label = "blocked_by_donor_selection"
        elif str(summary.get("readiness_status") or "").strip() == "acceptance_gated":
            acceptance_label = "blocked_by_acceptance"
        elif str(summary.get("readiness_status") or "").strip() == "unsupported":
            acceptance_label = "blocked_by_capability"
        else:
            acceptance_label = "blocked"
    acceptance_rank_map = {
        "ready_with_selected_donor": 3,
        "ready_without_selected_donor": 2,
        "blocked_by_donor_selection": 1,
        "blocked_by_capability": 0,
        "blocked_by_acceptance": 0,
        "blocked_by_runtime": 0,
    }
    acceptance_rank = acceptance_rank_map.get(acceptance_label, 0)
    critical_capability_count = len(list(summary.get("critical_capabilities", []) or []))
    missing_critical_capability_count = len(list(summary.get("missing_critical_capabilities", []) or []))
    parity_mismatch_count = len(list(summary.get("critical_parity_mismatches", []) or []))
    candidate_counts = dict(summary.get("candidate_counts", {}) or {})
    comparison_score = (
        (acceptance_rank * 100)
        - (missing_critical_capability_count * 10)
        - (parity_mismatch_count * 5)
        - int(candidate_counts.get("rejected", 0) or 0)
        - int(candidate_counts.get("filtered", 0) or 0)
    )
    selection_failure_type = summary.get("selection_failure_type")
    if selection_failure_type is None and donor_state in {"candidate_pool_blocked", "selection_pending"}:
        selection_failure_type = "viable_donor_found_but_acceptance_weak"
    if selection_failure_type is None and donor_state == "not_selected":
        selection_failure_type = "no_viable_donor_found"
    comparison_summary = (
        f"{summary.get('family')}: {acceptance_label}; "
        f"critical={critical_capability_count}, missing={missing_critical_capability_count}, "
        f"selected={int(candidate_counts.get('selected', 0) or 0)}, rejected={int(candidate_counts.get('rejected', 0) or 0)}, filtered={int(candidate_counts.get('filtered', 0) or 0)}"
    )
    return {
        "family": summary.get("family"),
        "readiness_status": summary.get("readiness_status"),
        "generate_state": generate_state,
        "donor_state": donor_state,
        "acceptance_rank": acceptance_rank,
        "acceptance_label": acceptance_label,
        "comparison_score": comparison_score,
        "comparison_summary": comparison_summary,
        "selected_donor_aligned": summary.get("selected_donor_aligned"),
        "selected_donor": donor_relative_path,
        "selection_failure_type": selection_failure_type,
        "critical_capability_count": critical_capability_count,
        "missing_critical_capability_count": missing_critical_capability_count,
        "parity_mismatch_count": parity_mismatch_count,
        "top_rejection_reason": next(
            (str(item) for item in list(summary.get("top_rejection_reasons", []) or []) if str(item).strip()),
            None,
        ),
        "next_best_action": summary.get("next_best_action"),
        "decision_confidence": summary.get("decision_confidence"),
        "blocking_layer": summary.get("blocking_layer"),
        "best_available_donor_class": summary.get("best_available_donor_class"),
        "primary_rejection_code": summary.get("primary_rejection_code"),
        "remediation_hint": next((str(item) for item in list(summary.get("remediation_steps", []) or []) if str(item).strip()), None),
    }


def _scenario_matrix_table(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    normalized_rows = [dict(row) for row in rows]
    normalized_rows.sort(
        key=lambda row: (
            -int(row.get("comparison_score", 0) or 0),
            int(row.get("missing_critical_capability_count", 0) or 0),
            str(row.get("family") or ""),
        )
    )
    return normalized_rows


def _write_json_artifact(payload: dict[str, object], output_path: Path | None) -> None:
    if output_path is None:
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def prepare_generation_plan(plan: IntentPlan) -> IntentPlan:
    enriched = _copy_plan(plan)
    if enriched.goal == "edit":
        return enriched

    if enriched.department_groups and not enriched.device_requirements.get("Router", 0):
        enriched.device_requirements["Router"] = 1
        enriched.assumptions_used.append("Added one router for department-based topology.")
    if enriched.department_groups and not enriched.vlan_ids:
        enriched.vlan_ids = [10 * (index + 1) for index in range(len(enriched.department_groups))]
        enriched.topology_requirements["vlan_ids"] = enriched.vlan_ids
        for index, group in enumerate(enriched.department_groups):
            group["vlan_id"] = enriched.vlan_ids[index]
            pc_count = int(group.get("devices", {}).get("PC", 0))
            if pc_count:
                enriched.host_vlan_assignment[enriched.vlan_ids[index]] = pc_count
        enriched.assumptions_used.append("Generated default VLAN IDs in 10-step increments for each department.")
    if enriched.device_requirements.get("Switch", 0) > 1:
        enriched.topology_requirements.setdefault("uplink_topology", "core_switch")
    if enriched.department_groups:
        enriched.topology_requirements["uplink_topology"] = "chain"
    if enriched.device_requirements.get("Switch", 0) and not enriched.host_link_intent and enriched.device_requirements.get("PC", 0):
        enriched.host_link_intent = "fastethernet"
        enriched.topology_requirements.setdefault("host_link_intent", "fastethernet")
        enriched.assumptions_used.append("Defaulted host links to FastEthernet.")
    if enriched.department_groups and any(
        any(device_type in {"Tablet", "Smartphone"} for device_type in dict(group.get("devices") or {}))
        for group in enriched.department_groups
    ):
        assumption = "Tablets and smartphones are treated as wireless clients and are not auto-wired."
        if assumption not in enriched.assumptions_used:
            enriched.assumptions_used.append(assumption)
    if enriched.device_requirements.get("Switch", 0) > 1 and not enriched.uplink_intent:
        enriched.uplink_intent = "gigabit"
        enriched.topology_requirements.setdefault("uplink_intent", "gigabit")
        enriched.assumptions_used.append("Defaulted switch uplinks to GigabitEthernet.")

    if enriched.vlan_ids and enriched.device_requirements.get("PC", 0) and not enriched.host_vlan_assignment and not any(op["op"] == "set_access_port" for op in enriched.switch_ops):
        gap = "Host-to-VLAN assignment is missing. Specify how many PCs belong to each VLAN."
        if gap not in enriched.blocking_gaps:
            enriched.blocking_gaps.append(gap)

    if any(cap in enriched.capabilities for cap in ["vlan", "trunk"]) or enriched.vlan_ids:
        for capability in ["vlan", "trunk", "access_port"]:
            if capability not in enriched.capabilities:
                enriched.capabilities.append(capability)
    if enriched.vlan_ids and enriched.device_requirements.get("Router", 0):
        for capability in ["router_on_a_stick"]:
            if capability not in enriched.capabilities:
                enriched.capabilities.append(capability)

    return enriched


def build_prompt_blueprint(plan: IntentPlan, donor_roots: list[Path] | None = None) -> tuple[dict[str, object], IntentPlan]:
    prepared = _apply_prompt_compatibility_requirements(plan, donor_roots)
    if prepared.blocking_gaps:
        prepared.blueprint_plan = asdict(build_blueprint_plan(prepared))
        raise PlanningError("Prompt plan is incomplete; generation was skipped.", prepared)

    devices = _seed_devices_from_plan(prepared)
    links = _synthesize_links(prepared, devices)
    prepared.links = links
    _synthesize_vlan_and_link_ops(prepared, devices, links)
    prepared.capabilities = sorted(dict.fromkeys(prepared.capabilities))
    topology_plan = _build_topology_plan(prepared, devices, links)
    config_plan = _build_config_plan(prepared)
    preferred_donor_archetypes = _preferred_donor_archetypes_for_plan(
        prepared,
        _topology_tags_for_plan(prepared, topology_plan.topology_archetype),
    )

    blueprint = {
        "name": "Generated from prompt",
        "capabilities": prepared.capabilities,
        "devices": devices,
        "links": links,
        "configs": _plan_configs(prepared, devices),
        "topology_archetype": topology_plan.topology_archetype,
        "preferred_donor_archetypes": preferred_donor_archetypes,
        "topology_plan": asdict(topology_plan),
        "config_plan": asdict(config_plan),
        "workspace_mode": "logical_only_safe",
    }
    prepared.blueprint_plan = asdict(build_blueprint_plan(prepared, blueprint))
    return blueprint, prepared


def generate_from_blueprint(blueprint_path: Path, output_path: Path, xml_out_path: Path | None = None) -> None:
    blueprint = json.loads(blueprint_path.read_text(encoding="utf-8"))
    xml_bytes = build_packet_tracer_xml(blueprint)
    if xml_out_path is not None:
        xml_out_path.parent.mkdir(parents=True, exist_ok=True)
        xml_out_path.write_bytes(xml_bytes)
    pkt_bytes = encode_pkt_modern(xml_bytes)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(pkt_bytes)
    print(f"PKT file created: {output_path}")
    print(f"XML bytes: {len(xml_bytes)}")
    print(f"PKT bytes: {len(pkt_bytes)}")


def generate_from_prompt(
    prompt: str,
    output_path: Path,
    xml_out_path: Path | None = None,
    reference_roots: list[Path] | None = None,
    donor_roots: list[Path] | None = None,
    *,
    search_remote: bool = False,
    remote_provider: str = "github",
    import_cache_root: Path | None = None,
    max_remote_results: int = 10,
    blueprint_out_path: Path | None = None,
) -> None:
    raw_plan = parse_intent(prompt)
    resolved_reference_roots, resolved_donor_roots, remote_results = _resolve_remote_sources(
        raw_plan,
        reference_roots,
        donor_roots,
        search_remote=search_remote,
        remote_provider=remote_provider,
        import_cache_root=import_cache_root,
        max_remote_results=max_remote_results,
    )
    raw_plan.remote_search_results = remote_results
    if raw_plan.goal == "edit" and raw_plan.pkt_path:
        edit_pkt_file(raw_plan.pkt_path, raw_plan, output_path, xml_out_path)
        print(f"Edited PKT file created: {output_path}")
        return

    try:
        blueprint, prepared_plan = build_prompt_blueprint(raw_plan, resolved_donor_roots)
    except PlanningError as exc:
        exc.plan.remote_search_results = remote_results
        if blueprint_out_path is not None and exc.plan.blueprint_plan:
            blueprint_out_path.parent.mkdir(parents=True, exist_ok=True)
            blueprint_out_path.write_text(json.dumps(exc.plan.blueprint_plan, indent=2, ensure_ascii=False), encoding="utf-8")
        raise
    reference_catalog = load_reference_catalog(resolved_reference_roots) if resolved_reference_roots else []
    topology_tags = _topology_tags_for_plan(prepared_plan, str(blueprint.get("topology_archetype", "general")))
    cisco_ranked, curated_ranked, _ = _rank_generation_donors(prepared_plan, topology_tags, resolved_donor_roots)
    cisco_ranked = _rerank_candidates_for_blueprint(cisco_ranked, blueprint)
    curated_ranked = _rerank_candidates_for_blueprint(curated_ranked, blueprint)
    matrix_hits, coverage_gap, blueprint_plan = _build_support_reports(
        prepared_plan,
        blueprint=blueprint,
        cisco_ranked=cisco_ranked,
        curated_ranked=curated_ranked,
        reference_catalog=reference_catalog,
    )
    coverage_gap = _augment_coverage_gap_actions(
        coverage_gap,
        donor_blocking_reason=inspect_packet_tracer_compatibility_donor().blocking_reason,
    )
    scenario_generate_decision = _scenario_generate_decision(coverage_gap)
    prepared_plan.remote_search_results = remote_results
    prepared_plan.capability_matrix_hits = matrix_hits
    prepared_plan.coverage_gap_report = coverage_gap
    prepared_plan.unsupported_capabilities = list(coverage_gap.get("unsupported_capabilities", []))
    prepared_plan.blueprint_plan = blueprint_plan
    if scenario_generate_decision["status"] in {"blocked_by_capability", "blocked_by_acceptance", "blocked_by_runtime"}:
        for reason in scenario_generate_decision["blocking_reasons"]:
            if reason not in prepared_plan.blocking_gaps:
                prepared_plan.blocking_gaps.append(reason)
        if blueprint_out_path is not None:
            blueprint_out_path.parent.mkdir(parents=True, exist_ok=True)
            blueprint_out_path.write_text(json.dumps(blueprint_plan, indent=2, ensure_ascii=False), encoding="utf-8")
        raise PlanningError("Scenario is not generate-ready in safe-open mode; generation was skipped.", prepared_plan)
    try:
        adapted_plan, donor_archetype = _build_donor_prune_plan(prepared_plan, blueprint, resolved_donor_roots)
    except PlanningError as exc:
        exc.plan.remote_search_results = remote_results
        exc.plan.capability_matrix_hits = matrix_hits
        exc.plan.coverage_gap_report = coverage_gap
        exc.plan.unsupported_capabilities = list(coverage_gap.get("unsupported_capabilities", []))
        exc.plan.blueprint_plan = blueprint_plan
        if blueprint_out_path is not None:
            blueprint_out_path.parent.mkdir(parents=True, exist_ok=True)
            blueprint_out_path.write_text(json.dumps(blueprint_plan, indent=2, ensure_ascii=False), encoding="utf-8")
        raise
    donor_root = decode_pkt_to_root(donor_archetype.compat_donor)
    safe_plan, profiled_plan = _apply_safe_open_profile(donor_root, adapted_plan)
    profiled_plan.remote_search_results = remote_results
    profiled_plan.capability_matrix_hits = matrix_hits
    profiled_plan.coverage_gap_report = coverage_gap
    profiled_plan.unsupported_capabilities = list(coverage_gap.get("unsupported_capabilities", []))
    profiled_plan.blueprint_plan = blueprint_plan
    if profiled_plan.blocked_mutations:
        if blueprint_out_path is not None:
            blueprint_out_path.parent.mkdir(parents=True, exist_ok=True)
            blueprint_out_path.write_text(json.dumps(blueprint_plan, indent=2, ensure_ascii=False), encoding="utf-8")
        raise PlanningError("Prompt plan requires unsafe donor mutations; generation was skipped in open-first mode.", profiled_plan)
    root = apply_plan_operations(donor_root, safe_plan)
    _sanitize_runtime_sections(root)
    unexpected_workspace_issues = _unexpected_workspace_issues(donor_root, root)
    if unexpected_workspace_issues:
        raise ValueError("; ".join(unexpected_workspace_issues))
    validate_donor_coherence(donor_root, root)
    xml_bytes = ET.tostring(root, encoding="utf-8", xml_declaration=False)
    if xml_out_path is not None:
        xml_out_path.parent.mkdir(parents=True, exist_ok=True)
        xml_out_path.write_bytes(xml_bytes)
    pkt_bytes = encode_pkt_modern(xml_bytes)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(pkt_bytes)
    print(f"Selected donor: {donor_archetype.compat_donor}")
    compat_donor, compat_donor_version = _compat_donor_details()
    if compat_donor is not None:
        print(f"Compatibility donor: {compat_donor} ({compat_donor_version or 'unknown'})")
    if blueprint_out_path is not None:
        blueprint_out_path.parent.mkdir(parents=True, exist_ok=True)
        blueprint_out_path.write_text(json.dumps(blueprint_plan, indent=2, ensure_ascii=False), encoding="utf-8")
    if resolved_reference_roots:
        references = load_reference_catalog(resolved_reference_roots)
        print(f"Loaded reference-only samples: {len(references)}")


def edit_from_prompt(
    pkt_path: Path,
    prompt: str,
    output_path: Path,
    xml_out_path: Path | None = None,
) -> None:
    plan = parse_intent(prompt)
    plan.goal = "edit"
    plan.pkt_path = str(pkt_path)
    edit_pkt_file(pkt_path, plan, output_path, xml_out_path)
    print(f"Edited PKT file created: {output_path}")


def _explain_plan_payload(
    prompt: str,
    reference_roots: list[Path] | None = None,
    donor_roots: list[Path] | None = None,
    *,
    search_remote: bool = False,
    remote_provider: str = "github",
    import_cache_root: Path | None = None,
    max_remote_results: int = 10,
) -> dict[str, object]:
    raw_plan = parse_intent(prompt)
    resolved_reference_roots, resolved_donor_roots, remote_results = _resolve_remote_sources(
        raw_plan,
        reference_roots,
        donor_roots,
        search_remote=search_remote,
        remote_provider=remote_provider,
        import_cache_root=import_cache_root,
        max_remote_results=max_remote_results,
    )
    plan = _apply_prompt_compatibility_requirements(raw_plan, resolved_donor_roots)
    plan.remote_search_results = remote_results
    donor_details = inspect_packet_tracer_compatibility_donor()
    compat_donor, compat_donor_version = donor_details.resolved_path, donor_details.donor_version
    topology_tags = _topology_tags_for_plan(plan, _choose_topology_archetype(plan))
    result: dict[str, object] = {
        "intent_plan": plan.to_dict(),
        "compatibility_mode": SAFE_OPEN_COMPATIBILITY_MODE,
        "compatibility_profile": asdict(_compatibility_profile()),
        "preferred_donor_archetypes": _preferred_donor_archetypes_for_plan(plan, topology_tags),
        "blocked_mutations": [],
        "unsafe_mutations_requested": [],
        "acceptance_stage_plan": [],
        "runtime_cleanup_mode": RUNTIME_CLEANUP_MODE,
        "preserved_visual_sections": PRESERVED_VISUAL_SECTIONS,
        "cleaned_visual_sections": CLEANED_SCENARIO_SECTIONS,
        "neutralized_visual_sections": NEUTRALIZED_VISUAL_SECTIONS,
        "compat_donor": str(compat_donor) if compat_donor is not None else None,
        "compat_donor_version": compat_donor_version,
        "compat_donor_source": donor_details.donor_source,
        "target_version": donor_details.target_version,
        "blocking_reason": donor_details.blocking_reason or None,
        "donor_candidates": [
            {"source": source, "path": str(path)}
            for source, path in donor_details.candidate_paths[:10]
        ],
        "donor_candidate_diagnostics": [],
        "donor_rejection_reasons": [],
        "donor_selection_summary": _summarize_candidate_pool([], _preferred_donor_archetypes_for_plan(plan, topology_tags)),
        "selected_donor_summary": None,
        "scenario_generate_decision": None,
        "scenario_acceptance_summary": None,
        "scenario_matrix_row": None,
        "capability_parity": [],
        "remote_search_results": remote_results,
    }
    cisco_ranked, curated_ranked, _ = _rank_generation_donors(plan, topology_tags, resolved_donor_roots)
    reference_catalog = load_reference_catalog(resolved_reference_roots) if resolved_reference_roots else []
    matrix_hits, coverage_gap, blueprint_plan = _build_support_reports(
        plan,
        cisco_ranked=cisco_ranked,
        curated_ranked=curated_ranked,
        reference_catalog=reference_catalog,
    )
    coverage_gap = _augment_coverage_gap_actions(
        coverage_gap,
        donor_blocking_reason=donor_details.blocking_reason,
    )
    result["capability_parity"] = list(coverage_gap.get("capability_parity", []))
    result["scenario_generate_decision"] = _scenario_generate_decision(
        coverage_gap,
        runtime_blocked=bool(donor_details.blocking_reason),
        runtime_blocking_reason=donor_details.blocking_reason,
    )
    result["scenario_acceptance_summary"] = _scenario_acceptance_summary(
        coverage_gap,
        runtime_blocked=bool(donor_details.blocking_reason),
        runtime_blocking_reason=donor_details.blocking_reason,
    )
    result["scenario_matrix_row"] = _scenario_matrix_row(result["scenario_acceptance_summary"])
    plan.capability_matrix_hits = matrix_hits
    plan.coverage_gap_report = coverage_gap
    plan.unsupported_capabilities = list(coverage_gap.get("unsupported_capabilities", []))
    plan.blueprint_plan = blueprint_plan
    result["intent_plan"] = plan.to_dict()
    if not plan.blocking_gaps and plan.goal != "edit":
        blueprint, prepared = build_prompt_blueprint(plan, resolved_donor_roots)
        prepared = _apply_safe_open_preview(prepared)
        topology_plan = TopologyPlan(**blueprint.get("topology_plan", {}))
        config_plan = ConfigPlan(**blueprint.get("config_plan", {}))
        topology_tags = _topology_tags_for_plan(prepared, str(blueprint.get("topology_archetype", "general")))
        cisco_ranked, curated_ranked, donor_ranked = _rank_generation_donors(prepared, topology_tags, resolved_donor_roots)
        cisco_ranked = _rerank_candidates_for_blueprint(cisco_ranked, blueprint)
        curated_ranked = _rerank_candidates_for_blueprint(curated_ranked, blueprint)
        donor_ranked = _rerank_candidates_for_blueprint(donor_ranked, blueprint)
        reference_catalog = load_reference_catalog(resolved_reference_roots) if resolved_reference_roots else []
        matrix_hits, coverage_gap, blueprint_plan = _build_support_reports(
            prepared,
            blueprint=blueprint,
            cisco_ranked=cisco_ranked,
            curated_ranked=curated_ranked,
            reference_catalog=reference_catalog,
        )
        prepared.capability_matrix_hits = matrix_hits
        prepared.coverage_gap_report = coverage_gap
        prepared.unsupported_capabilities = list(coverage_gap.get("unsupported_capabilities", []))
        prepared.blueprint_plan = blueprint_plan
        result["intent_plan"] = prepared.to_dict()
        result["compatibility_profile"] = prepared.compatibility_profile
        result["preferred_donor_archetypes"] = blueprint.get("preferred_donor_archetypes", [])
        result["blocked_mutations"] = prepared.blocked_mutations
        result["unsafe_mutations_requested"] = prepared.unsafe_mutations_requested
        validation = _preflight_validation(prepared, topology_plan, config_plan)
        selected_donor = None
        donor_capacity = None
        prune_plan = None
        evaluation, diagnostics = _evaluate_donor_prune_candidates(prepared, blueprint, donor_ranked)
        coverage_gap = _augment_coverage_gap_actions(
            coverage_gap,
            donor_diagnostics=diagnostics,
            donor_selection_summary=_summarize_candidate_pool(
                diagnostics,
                [str(item) for item in list(blueprint.get("preferred_donor_archetypes", [])) if item],
            ),
            donor_blocking_reason=donor_details.blocking_reason,
        )
        result["scenario_generate_decision"] = _scenario_generate_decision(coverage_gap)
        prepared.coverage_gap_report = coverage_gap
        result["donor_candidate_diagnostics"] = diagnostics[:10]
        result["donor_rejection_reasons"] = [
            {
                "relative_path": item["relative_path"],
                "rejection_reasons": item.get("rejection_reasons", []),
            }
            for item in diagnostics
            if item.get("status") == "rejected" and item.get("rejection_reasons")
        ][:10]
        result["donor_selection_summary"] = _summarize_candidate_pool(
            diagnostics,
            [str(item) for item in list(blueprint.get("preferred_donor_archetypes", [])) if item],
        )
        result["scenario_acceptance_summary"] = _scenario_acceptance_summary(
            coverage_gap,
            donor_selection_summary=result["donor_selection_summary"],
            runtime_blocked=bool(donor_details.blocking_reason),
            runtime_blocking_reason=donor_details.blocking_reason,
        )
        result["scenario_matrix_row"] = _scenario_matrix_row(result["scenario_acceptance_summary"])
        try:
            if evaluation is None:
                raise PlanningError("Prompt plan is incomplete; generation was skipped.", prepared)
            adapted_plan, donor_archetype, donor_root, selected_candidate = evaluation
            safe_plan, profiled_plan = _apply_safe_open_profile(donor_root, adapted_plan)
            matrix_hits, coverage_gap, blueprint_plan = _build_support_reports(
                profiled_plan,
                blueprint=blueprint,
                cisco_ranked=cisco_ranked,
                curated_ranked=curated_ranked,
                reference_catalog=reference_catalog,
                selected_donor=selected_candidate.sample.relative_path,
            )
            coverage_gap = _augment_coverage_gap_actions(
                coverage_gap,
                donor_diagnostics=diagnostics,
                donor_selection_summary=result["donor_selection_summary"],
                donor_blocking_reason=donor_details.blocking_reason,
            )
            profiled_plan.remote_search_results = remote_results
            profiled_plan.capability_matrix_hits = matrix_hits
            profiled_plan.coverage_gap_report = coverage_gap
            profiled_plan.unsupported_capabilities = list(coverage_gap.get("unsupported_capabilities", []))
            profiled_plan.blueprint_plan = blueprint_plan
            result["intent_plan"] = profiled_plan.to_dict()
            result["compatibility_profile"] = profiled_plan.compatibility_profile
            result["blocked_mutations"] = profiled_plan.blocked_mutations
            result["unsafe_mutations_requested"] = profiled_plan.unsafe_mutations_requested
            result["acceptance_stage_plan"] = profiled_plan.acceptance_stage_plan
            selected_donor = donor_archetype.compat_donor
            donor_capacity = donor_archetype.donor_capacity
            prune_plan = asdict(donor_archetype)
            if profiled_plan.blocked_mutations:
                result["validation_report"] = {
                    "status": "blocked",
                    "blocking_issues": profiled_plan.blocking_gaps,
                }
            else:
                candidate_root = apply_plan_operations(donor_root, safe_plan)
                _sanitize_runtime_sections(candidate_root)
                workspace_result = inspect_workspace_integrity(candidate_root)
                workspace_result.blocking_issues = _unexpected_workspace_issues(donor_root, candidate_root)
                workspace_result.logical_status = "invalid" if workspace_result.blocking_issues else "ok"
                coherence_result = inspect_donor_coherence(donor_root, candidate_root)
                result["validation_report"] = {
                    "workspace_mode": workspace_result.workspace_mode,
                    "logical_status": workspace_result.logical_status,
                    "physical_status": workspace_result.physical_status,
                    "device_metadata_status": coherence_result.device_metadata_status,
                    "scenario_status": coherence_result.scenario_status,
                    "physical_runtime_status": coherence_result.physical_runtime_status,
                    "visual_runtime_status": coherence_result.visual_runtime_status,
                    "blocking_issues": [*workspace_result.blocking_issues, *coherence_result.blocking_issues],
                }
            result["selected_donor_summary"] = _selected_donor_summary(diagnostics, donor_archetype)
            result["scenario_generate_decision"] = _scenario_generate_decision(
                coverage_gap,
                donor_selection_summary=result["donor_selection_summary"],
                selected_donor_summary=result["selected_donor_summary"],
                runtime_blocked=bool(donor_details.blocking_reason),
                runtime_blocking_reason=donor_details.blocking_reason,
            )
            result["scenario_acceptance_summary"] = _scenario_acceptance_summary(
                coverage_gap,
                donor_selection_summary=result["donor_selection_summary"],
                selected_donor_summary=result["selected_donor_summary"],
                runtime_blocked=bool(donor_details.blocking_reason),
                runtime_blocking_reason=donor_details.blocking_reason,
            )
            result["scenario_matrix_row"] = _scenario_matrix_row(
                result["scenario_acceptance_summary"],
                selected_donor_summary=result["selected_donor_summary"],
            )
            result["capability_matrix_hits"] = matrix_hits
            result["unsupported_capabilities"] = coverage_gap.get("unsupported_capabilities", [])
            result["coverage_gaps"] = coverage_gap
            result["capability_parity"] = list(coverage_gap.get("capability_parity", []))
            result["blueprint_plan"] = blueprint_plan
        except PlanningError as exc:
            if result["donor_rejection_reasons"]:
                for item in result["donor_rejection_reasons"]:
                    reasons = [str(reason) for reason in item.get("rejection_reasons", []) if reason]
                    if reasons:
                        combined = f"{item['relative_path']}: {'; '.join(reasons[:3])}"
                        if combined not in exc.plan.blocking_gaps:
                            exc.plan.blocking_gaps.append(combined)
            result["intent_plan"] = exc.plan.to_dict()
        except ValueError as exc:
            result["validation_report"] = {"status": "invalid", "blocking_issues": str(exc).split("; ")}
        result["topology_plan"] = blueprint.get("topology_plan")
        result["config_plan"] = blueprint.get("config_plan")
        result["estimate_plan"] = _estimate_plan(topology_plan, config_plan)
        result["preflight_validation"] = validation
        result["autofix_summary"] = _autofix_summary(prepared, validation)
        result["assumptions_used"] = prepared.assumptions_used
        result["workspace_mode"] = blueprint.get("workspace_mode", "logical_only_safe")
        result["selected_donor"] = selected_donor
        result["donor_capacity"] = donor_capacity
        result["prune_plan"] = prune_plan
        result["capability_matrix_hits"] = matrix_hits
        result["unsupported_capabilities"] = coverage_gap.get("unsupported_capabilities", [])
        result["coverage_gaps"] = coverage_gap
        result["capability_parity"] = list(coverage_gap.get("capability_parity", []))
        result["blueprint_plan"] = blueprint_plan
        candidates = [_candidate_to_dict(candidate, blueprint) for candidate in cisco_ranked[:5]]
        result["cisco_sample_candidates"] = candidates
        result["sample_candidates"] = candidates
        result["curated_external_donor_candidates"] = [_candidate_to_dict(candidate, blueprint) for candidate in curated_ranked[:5]]
    else:
        result["capability_matrix_hits"] = matrix_hits
        result["unsupported_capabilities"] = coverage_gap.get("unsupported_capabilities", [])
        result["coverage_gaps"] = coverage_gap
        result["capability_parity"] = list(coverage_gap.get("capability_parity", []))
        result["blueprint_plan"] = blueprint_plan
        result["cisco_sample_candidates"] = [_candidate_to_dict(candidate) for candidate in cisco_ranked[:5]]
        result["sample_candidates"] = result["cisco_sample_candidates"]
        result["curated_external_donor_candidates"] = [_candidate_to_dict(candidate) for candidate in curated_ranked[:5]]
    if resolved_reference_roots:
        reference_ranked = rank_reference_samples(
            reference_catalog,
            plan.capabilities,
            plan.device_requirements,
            topology_tags=_topology_tags_for_plan(plan, str(result.get("topology_plan", {}).get("topology_archetype", "general"))) if result.get("topology_plan") else None,
            wireless_mode=plan.wireless_mode,
            requested_services=[str(service) for service in plan.service_requirements.get("services", []) if service],
        )
        patterns = []
        for candidate in reference_ranked[:10]:
            pattern = ReferencePattern(
                relative_path=candidate.sample.relative_path,
                origin=candidate.sample.origin,
                capability_tags=candidate.sample.capability_tags,
                topology_tags=candidate.sample.topology_tags,
                device_summary=candidate.sample.normalized_device_counts(),
                wireless_mode_tags=candidate.sample.wireless_mode_tags,
            )
            pattern_dict = asdict(pattern)
            pattern_dict["score"] = candidate.total_score
            pattern_dict["reasons"] = candidate.reasons[:8]
            patterns.append(pattern_dict)
        result["external_reference_patterns"] = patterns
        result["reference_patterns"] = patterns
    result["scenario_matrix_row"]["fixture_name"] = _scenario_fixture_name(result["scenario_matrix_row"].get("family"))
    result["scenario_matrix_row"]["matrix_version"] = "2.1"
    result["scenario_matrix_row"].update(_parity_counts(_capability_parity_entries(result.get("coverage_gaps", {}))))
    fixture_status, fixture_gaps = _fixture_expectation_status(result)
    result["fixture_registry_version"] = _load_fixture_corpus().get("fixture_registry_version", "unknown")
    result["fixture_expectation_status"] = fixture_status
    result["fixture_expectation_gaps"] = fixture_gaps
    return result


def explain_plan(
    prompt: str,
    reference_roots: list[Path] | None = None,
    donor_roots: list[Path] | None = None,
    *,
    search_remote: bool = False,
    remote_provider: str = "github",
    import_cache_root: Path | None = None,
    max_remote_results: int = 10,
    acceptance_json_out: Path | None = None,
) -> None:
    result = _explain_plan_payload(
        prompt,
        reference_roots,
        donor_roots,
        search_remote=search_remote,
        remote_provider=remote_provider,
        import_cache_root=import_cache_root,
        max_remote_results=max_remote_results,
    )
    _write_json_artifact(result, acceptance_json_out)
    print(json.dumps(result, indent=2, ensure_ascii=False))


def inventory_pkt(
    pkt_path: Path,
    donor_roots: list[Path] | None = None,
    *,
    include_capabilities: bool = False,
    inventory_out: Path | None = None,
) -> None:
    root = ET.fromstring(decode_pkt_modern(pkt_path.read_bytes()))
    payload = inventory_root(root)
    workspace = inspect_workspace_integrity(root)
    donor_details = inspect_packet_tracer_compatibility_donor()
    compat_donor, compat_donor_version = donor_details.resolved_path, donor_details.donor_version
    payload["workspace_validation"] = {
        "workspace_mode": workspace.workspace_mode,
        "logical_status": workspace.logical_status,
        "physical_status": workspace.physical_status,
        "blocking_issues": workspace.blocking_issues,
    }
    payload["compatibility_mode"] = SAFE_OPEN_COMPATIBILITY_MODE
    payload["runtime_cleanup_mode"] = RUNTIME_CLEANUP_MODE
    payload["preserved_scenario_sections"] = PRESERVED_SCENARIO_SECTIONS
    payload["preserved_visual_sections"] = PRESERVED_VISUAL_SECTIONS
    payload["cleaned_visual_sections"] = CLEANED_SCENARIO_SECTIONS
    payload["neutralized_visual_sections"] = NEUTRALIZED_VISUAL_SECTIONS
    payload["compat_donor"] = str(compat_donor) if compat_donor is not None else None
    payload["compat_donor_version"] = compat_donor_version
    payload["compat_donor_source"] = donor_details.donor_source
    payload["target_version"] = donor_details.target_version
    payload["blocking_reason"] = donor_details.blocking_reason or None
    payload["donor_candidates"] = [
        {"source": source, "path": str(path)}
        for source, path in donor_details.candidate_paths[:10]
    ]
    payload["pkt_version"] = root.findtext("./VERSION")
    if compat_donor is not None and compat_donor.resolve() == pkt_path.resolve():
        donor_root = decode_pkt_to_root(compat_donor)
        coherence = inspect_donor_coherence(donor_root, root)
        payload["validation_report"] = {
            "device_metadata_status": coherence.device_metadata_status,
            "scenario_status": coherence.scenario_status,
            "physical_runtime_status": coherence.physical_runtime_status,
            "visual_runtime_status": coherence.visual_runtime_status,
            "blocking_issues": coherence.blocking_issues,
        }
    elif compat_donor is not None:
        payload["validation_report_note"] = "Skipped donor coherence report because the resolved compatibility donor does not match this file."
    if donor_roots:
        curated_match = next(
            (
                sample
                for sample in load_curated_donor_catalog(donor_roots)
                if Path(sample.path).resolve() == pkt_path.resolve()
            ),
            None,
        )
        if curated_match is None:
            for donor_root in donor_roots:
                try:
                    pkt_path.resolve().relative_to(donor_root.resolve())
                except Exception:
                    continue
                curated_match = summarize_pkt_descriptor(
                    pkt_path,
                    relative_path=str(pkt_path.name),
                    origin="external-curated",
                    prototype_eligible=True,
                    trust_level="curated",
                    role="secondary",
                    license_or_permission="local-import",
                    promotion_status="validated_curated",
                    validation_status="validated",
                    donor_eligible=True,
                )
                break
        if curated_match is not None:
            payload["curated_donor_validation"] = {
                "origin": curated_match.origin,
                "license_or_permission": curated_match.license_or_permission,
                "promotion_status": curated_match.promotion_status,
                "validation_status": curated_match.validation_status,
                "packet_tracer_version": curated_match.packet_tracer_version or curated_match.version,
                "donor_eligible": curated_match.donor_eligible,
                "wireless_mode_tags": curated_match.wireless_mode_tags,
            }
    if include_capabilities:
        payload["inventory_capabilities"] = build_inventory_capability_report(payload)
    payload.update(_link_schema_summary(root))
    rendered = json.dumps(payload, indent=2, ensure_ascii=False)
    if inventory_out is not None:
        inventory_out.parent.mkdir(parents=True, exist_ok=True)
        inventory_out.write_text(rendered, encoding="utf-8")
    print(rendered)


def validate_open(pkt_path: Path) -> None:
    packet_tracer_exe = require_packet_tracer_exe()
    process = subprocess.Popen([str(packet_tracer_exe), str(pkt_path)])
    print(json.dumps({"status": "launched", "pid": process.pid, "pkt": str(pkt_path)}, ensure_ascii=False))


def validate_open_debug(prompt: str, output_path: Path | None = None, donor_roots: list[Path] | None = None) -> None:
    raw_plan = parse_intent(prompt)
    if raw_plan.goal == "edit":
        raise PlanningError("Open-debug currently supports prompt generation only.", raw_plan)
    blueprint, prepared_plan = build_prompt_blueprint(raw_plan, donor_roots)
    adapted_plan, donor_archetype = _build_donor_prune_plan(prepared_plan, blueprint, donor_roots)
    donor_root = decode_pkt_to_root(donor_archetype.compat_donor)
    safe_plan, profiled_plan = _apply_safe_open_profile(donor_root, adapted_plan)
    report: dict[str, object] = {
        "compatibility_profile": profiled_plan.compatibility_profile,
        "selected_donor": donor_archetype.compat_donor,
        "blocked_mutations": profiled_plan.blocked_mutations,
        "unsafe_mutations_requested": profiled_plan.unsafe_mutations_requested,
        "acceptance_stage_plan": profiled_plan.acceptance_stage_plan,
        "changed_devices": sorted(
            {
                device_name
                for stage in profiled_plan.acceptance_stage_plan
                for device_name in stage.get("changed_devices", [])
            },
            key=str.lower,
        ),
        "changed_links": sorted(
            {
                link_name
                for stage in profiled_plan.acceptance_stage_plan
                for link_name in stage.get("changed_links", [])
            },
            key=str.lower,
        ),
    }
    if output_path is not None:
        base_dir = output_path.parent
        stem = output_path.stem if output_path.suffix else output_path.name
        report_path = output_path if output_path.suffix else base_dir / f"{stem}.json"
        baseline_pkt = base_dir / f"{stem}_baseline_roundtrip.pkt"
        baseline_xml = base_dir / f"{stem}_baseline_roundtrip.xml"
        _write_pkt_root(donor_root, baseline_pkt, baseline_xml)
        report["baseline_pkt"] = str(baseline_pkt)
        report["baseline_xml"] = str(baseline_xml)
        stage_files: list[dict[str, object]] = []
        for stage_name in MUTATION_STAGE_ORDER[1:]:
            stage_plan = _stage_plan(adapted_plan, stage_name)
            if not _plan_has_mutations(stage_plan):
                continue
            stage_root = apply_plan_operations(donor_root, stage_plan)
            _sanitize_runtime_sections(stage_root)
            stage_pkt = base_dir / f"{stem}_{stage_name}.pkt"
            stage_xml = base_dir / f"{stem}_{stage_name}.xml"
            _write_pkt_root(stage_root, stage_pkt, stage_xml)
            stage_files.append({"stage_name": stage_name, "pkt": str(stage_pkt), "xml": str(stage_xml)})
        report["stage_files"] = stage_files
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))


def coverage_report(
    reference_roots: list[Path] | None = None,
    donor_roots: list[Path] | None = None,
    *,
    device_family: str | None = None,
) -> None:
    samples: list[SampleDescriptor] = []
    samples.extend(load_catalog())
    if donor_roots:
        samples.extend(load_curated_donor_catalog(donor_roots))
    if reference_roots:
        samples.extend(load_reference_catalog(reference_roots))
    entries = coverage_asdict_list(build_capability_matrix(samples))
    if device_family:
        family_lower = device_family.strip().lower()
        entries = [entry for entry in entries if str(entry.get("device_family", "")).lower() == family_lower]
    print(json.dumps({"coverage_matrix": entries, "count": len(entries)}, indent=2, ensure_ascii=False))


def parity_report(
    prompt: str,
    reference_roots: list[Path] | None = None,
    donor_roots: list[Path] | None = None,
    *,
    search_remote: bool = False,
    remote_provider: str = "github",
    import_cache_root: Path | None = None,
    max_remote_results: int = 10,
    acceptance_json_out: Path | None = None,
) -> None:
    payload = _explain_plan_payload(
        prompt,
        reference_roots,
        donor_roots,
        search_remote=search_remote,
        remote_provider=remote_provider,
        import_cache_root=import_cache_root,
        max_remote_results=max_remote_results,
    )
    coverage_gap = dict(payload.get("coverage_gaps") or {})
    if "capability_parity" not in coverage_gap:
        coverage_gap["capability_parity"] = list(payload.get("capability_parity", []))
    critical_capability_parity, critical_parity_mismatches = _critical_capability_parity(coverage_gap)
    result = {
        "prompt": prompt,
        "scenario_family": coverage_gap.get("scenario_family"),
        "capability_parity": list(payload.get("capability_parity", [])),
        "critical_capability_parity": critical_capability_parity,
        "critical_parity_mismatches": critical_parity_mismatches,
        **_parity_counts(list(payload.get("capability_parity", []))),
    }
    _write_json_artifact(result, acceptance_json_out)
    print(json.dumps(result, indent=2, ensure_ascii=False))


def compare_scenarios(
    prompts: list[str],
    reference_roots: list[Path] | None = None,
    donor_roots: list[Path] | None = None,
    *,
    search_remote: bool = False,
    remote_provider: str = "github",
    import_cache_root: Path | None = None,
    max_remote_results: int = 10,
    matrix_out: Path | None = None,
    acceptance_json_out: Path | None = None,
) -> None:
    payloads: list[dict[str, object]] = []
    matrix_rows: list[dict[str, object]] = []
    for prompt in prompts:
        payload = _explain_plan_payload(
            prompt,
            reference_roots,
            donor_roots,
            search_remote=search_remote,
            remote_provider=remote_provider,
            import_cache_root=import_cache_root,
            max_remote_results=max_remote_results,
        )
        fixture_status, fixture_gaps = _fixture_expectation_status(payload)
        payloads.append(
            {
                "prompt": prompt,
                "scenario_matrix_row": payload.get("scenario_matrix_row"),
                "scenario_acceptance_summary": payload.get("scenario_acceptance_summary"),
                "scenario_generate_decision": payload.get("scenario_generate_decision"),
                "selected_donor_summary": payload.get("selected_donor_summary"),
                "donor_selection_summary": payload.get("donor_selection_summary"),
                "capability_parity": payload.get("capability_parity"),
                "fixture_name": _scenario_fixture_name((payload.get("scenario_matrix_row") or {}).get("family")),
                "fixture_expectation_status": fixture_status,
                "fixture_expectation_gaps": fixture_gaps,
            }
        )
        row = dict(payload.get("scenario_matrix_row") or {})
        row["prompt"] = prompt
        matrix_rows.append(row)
    fixture_registry = _load_fixture_corpus()
    result = {
        "matrix_version": "2.1",
        "fixture_registry_version": fixture_registry.get("fixture_registry_version", "unknown"),
        "scenario_count": len(prompts),
        "matrix": _scenario_matrix_table(matrix_rows),
        "scenarios": payloads,
    }
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    _write_json_artifact(result, matrix_out)
    _write_json_artifact(result, acceptance_json_out)
    print(rendered)


def feature_gap_report() -> None:
    print(json.dumps(build_feature_gap_report(), indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate or inspect Cisco Packet Tracer 9.0 .pkt files")
    parser.add_argument("--blueprint", help="Path to the topology blueprint JSON")
    parser.add_argument("--prompt", help="Natural language topology or edit request")
    parser.add_argument("--output", help="Path to the output .pkt file")
    parser.add_argument("--xml-out", help="Optional XML output path for generated or decoded XML")
    parser.add_argument("--decode", help="Decode an existing .pkt file")
    parser.add_argument("--inventory", help="Print device/link/service inventory for an existing .pkt file")
    parser.add_argument("--edit", help="Edit an existing .pkt file with --prompt and write the result to --output")
    parser.add_argument("--explain-plan", help="Print the parsed prompt plan as JSON")
    parser.add_argument("--compare-scenarios", action="append", help="Compare multiple prompts and print a scenario acceptance matrix")
    parser.add_argument("--parity-report", help="Print prompt-scoped capability parity JSON")
    parser.add_argument("--validate-open", help="Launch Packet Tracer with the given .pkt file")
    parser.add_argument("--validate-open-debug", help="Build staged donor compatibility debug report for a prompt")
    parser.add_argument("--compat-donor", help="Explicit Packet Tracer 9.0 donor .pkt path for strict compatibility mode")
    parser.add_argument("--reference-root", action="append", help="Optional local folder of imported external sample .pkt files")
    parser.add_argument("--donor-root", action="append", help="Optional local folder of curated external donor .pkt files")
    parser.add_argument("--search-remote", action="store_true", help="Search remote repositories for Packet Tracer labs and auto-import them into the local cache")
    parser.add_argument("--remote-provider", default="github", help="Remote search provider name (default: github)")
    parser.add_argument("--import-cache-root", help="Local cache folder used for remote search auto-imports")
    parser.add_argument("--max-remote-results", type=int, default=10, help="Maximum number of remote search results to fetch/import")
    parser.add_argument("--blueprint-out", help="Optional JSON output path for the generated blueprint plan or refusal blueprint")
    parser.add_argument("--coverage-report", action="store_true", help="Print the aggregated capability coverage matrix")
    parser.add_argument("--feature-gap-report", action="store_true", help="Print the Packet Tracer feature gap atlas report")
    parser.add_argument("--inventory-capabilities", action="store_true", help="Include inferred capability inventory when using --inventory")
    parser.add_argument("--inventory-out", help="Optional JSON output path when using --inventory")
    parser.add_argument("--matrix-out", help="Optional JSON output path when using --compare-scenarios")
    parser.add_argument("--acceptance-json-out", help="Optional JSON output path for explain/compare/parity payloads")
    parser.add_argument("--device-family", help="Optional device family filter for --coverage-report")
    args = parser.parse_args()
    if args.compat_donor:
        os.environ["PACKET_TRACER_COMPAT_DONOR"] = args.compat_donor
    reference_roots = [Path(path) for path in (args.reference_root or [])]
    donor_roots = [Path(path) for path in (args.donor_root or [])]
    import_cache_root = Path(args.import_cache_root) if args.import_cache_root else None

    if args.explain_plan:
        explain_plan(
            args.explain_plan,
            reference_roots,
            donor_roots,
            search_remote=args.search_remote,
            remote_provider=args.remote_provider,
            import_cache_root=import_cache_root,
            max_remote_results=args.max_remote_results,
            acceptance_json_out=Path(args.acceptance_json_out) if args.acceptance_json_out else None,
        )
        return
    if args.compare_scenarios:
        compare_scenarios(
            args.compare_scenarios,
            reference_roots,
            donor_roots,
            search_remote=args.search_remote,
            remote_provider=args.remote_provider,
            import_cache_root=import_cache_root,
            max_remote_results=args.max_remote_results,
            matrix_out=Path(args.matrix_out) if args.matrix_out else None,
            acceptance_json_out=Path(args.acceptance_json_out) if args.acceptance_json_out else None,
        )
        return
    if args.parity_report:
        parity_report(
            args.parity_report,
            reference_roots,
            donor_roots,
            search_remote=args.search_remote,
            remote_provider=args.remote_provider,
            import_cache_root=import_cache_root,
            max_remote_results=args.max_remote_results,
            acceptance_json_out=Path(args.acceptance_json_out) if args.acceptance_json_out else None,
        )
        return
    if args.inventory:
        inventory_pkt(
            Path(args.inventory),
            donor_roots,
            include_capabilities=args.inventory_capabilities,
            inventory_out=Path(args.inventory_out) if args.inventory_out else None,
        )
        return
    if args.edit:
        if not args.prompt:
            parser.error("--edit requires --prompt")
        if not args.output:
            parser.error("--edit requires --output")
        edit_from_prompt(Path(args.edit), args.prompt, Path(args.output), Path(args.xml_out) if args.xml_out else None)
        return
    if args.coverage_report:
        coverage_report(reference_roots, donor_roots, device_family=args.device_family)
        return
    if args.feature_gap_report:
        feature_gap_report()
        return
    if args.decode:
        if not args.xml_out:
            parser.error("--decode requires --xml-out")
        decode_pkt_file(args.decode, args.xml_out)
        print(f"Decoded XML written to {args.xml_out}")
        return
    if args.validate_open:
        validate_open(Path(args.validate_open))
        return
    if args.validate_open_debug:
        try:
            validate_open_debug(args.validate_open_debug, Path(args.output) if args.output else None, donor_roots)
        except PlanningError as exc:
            print(json.dumps(exc.to_dict(), indent=2, ensure_ascii=False))
            raise SystemExit(2) from exc
        return

    if not args.output:
        parser.error("generation requires --output")
    if args.prompt:
        try:
            generate_from_prompt(
                args.prompt,
                Path(args.output),
                Path(args.xml_out) if args.xml_out else None,
                reference_roots,
                donor_roots,
                search_remote=args.search_remote,
                remote_provider=args.remote_provider,
                import_cache_root=import_cache_root,
                max_remote_results=args.max_remote_results,
                blueprint_out_path=Path(args.blueprint_out) if args.blueprint_out else None,
            )
        except PlanningError as exc:
            print(json.dumps(exc.to_dict(), indent=2, ensure_ascii=False))
            raise SystemExit(2) from exc
        return
    if not args.blueprint:
        parser.error("generation requires either --blueprint or --prompt")
    generate_from_blueprint(Path(args.blueprint), Path(args.output), Path(args.xml_out) if args.xml_out else None)


if __name__ == "__main__":
    main()
