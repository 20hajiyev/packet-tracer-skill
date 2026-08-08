#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from functools import lru_cache
import json
import math
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
from intent_parser import SECURITY_TO_AUTH, IntentPlan, distribute_hosts_across_vlans, parse_intent, strict_vlan_assignment
from packet_tracer_env import (
    donor_compatibility,
    donor_tier_is_accepted,
    get_donor_policy,
    get_packet_tracer_compatibility_donor,
    get_packet_tracer_target_version,
    inspect_packet_tracer_compatibility_donor,
    require_packet_tracer_exe,
)
from pkt_builder import build_packet_tracer_xml
from pkt_codec import decode_pkt_file, decode_pkt_modern, encode_pkt_modern, serialize_pkt_xml
from pkt_editor import _align_hostname_with_name, _ensure_text, _profile_nodes, _set_config_block, apply_plan_operations, decode_pkt_to_root, edit_pkt_file, inventory_devices, inventory_links, inventory_root
from pkt_transformer import donor_interface_names, port_capacity, port_exists, transform_from_blueprint
import pkt_verify
import usage_ledger
from remote_search import (
    asdict_list as remote_asdict_list,
    auto_import_remote_candidates,
    candidate_is_curated_eligible,
    search_remote_candidates,
    write_remote_sample_audit,
)
from sample_catalog import ReferencePattern, SampleCandidate, SampleDescriptor, load_catalog, load_curated_donor_catalog, load_reference_catalog, normalize_device_type as _normalize_device_type, summarize_pkt_descriptor
from sample_selector import rank_curated_donor_samples, rank_reference_samples, rank_samples, select_best_sample
from workspace_repair import inspect_donor_coherence, inspect_workspace_integrity, validate_donor_coherence, validate_workspace_integrity

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_CORPUS_PATH = ROOT / "references" / "scenario-fixture-corpus.json"
PROOF_CARDS_PATH = ROOT / "examples" / "proof-cards.json"
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
    "IpPhone": "end devices",
    "HomeVoip": "end devices",
    "AnalogPhone": "end devices",
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


@lru_cache(maxsize=1)
def _inspect_packet_tracer_compatibility_donor_cached():
    return inspect_packet_tracer_compatibility_donor()


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
    "Strict generation requires a compatible Packet Tracer donor lab. "
    "Set PACKET_TRACER_COMPAT_DONOR explicitly, or provide --donor-root with validated local donor labs."
)


def _strict_compatibility_gap() -> str:
    """Say why no donor qualified, using the evaluation that actually ran.

    The fixed string above told users to "let the repo auto-detect one" when
    auto-detection had already run and rejected everything it found. The donor
    resolver knows the real reason -- usually that the only candidates are
    bundled Cisco samples carrying a build the local install refuses -- so
    report that instead of sending people to look for a switch to flip.
    """
    try:
        details = _inspect_packet_tracer_compatibility_donor_cached()
    except Exception:  # diagnosis must never mask the original refusal
        return STRICT_COMPATIBILITY_GAP
    if details.blocking_reason:
        return f"No donor lab can serve as a generation base: {details.blocking_reason}"
    return STRICT_COMPATIBILITY_GAP


def _compat_donor_details() -> tuple[Path | None, str | None]:
    details = _inspect_packet_tracer_compatibility_donor_cached()
    return details.resolved_path, details.donor_version


def _existing_ranked_candidates(ranked: list[SampleCandidate]) -> list[SampleCandidate]:
    """Candidates that exist on disk. No version filter.

    These feed capability and coverage reporting, which asks "what is possible
    with Packet Tracer" — a sample proves a capability whether or not it can
    serve as a generation base. Filtering here made every bundled sample vanish
    under the `exact` policy, and campus prompts started refusing with
    "critical capability coverage is still missing" even though the coverage was
    right there in the catalogue.
    """
    return [candidate for candidate in ranked if Path(candidate.sample.path).exists()]


def _base_donor_candidates(ranked: list[SampleCandidate]) -> list[SampleCandidate]:
    """Candidates usable as the base a generated lab is built from.

    Donor-prune inherits the base's `<VERSION>`, and Packet Tracer refuses a
    file whose build differs from its own, so this is where the version policy
    belongs — and only here.
    """
    target_version = get_packet_tracer_target_version()
    policy = get_donor_policy()
    return [
        candidate
        for candidate in ranked
        if donor_tier_is_accepted(donor_compatibility(candidate.sample.version, target_version), policy)
    ]


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


DEFAULT_LOCAL_DONOR_LIMIT = 4


def _spare_pool_for_type(
    pools: dict[str, list[dict[str, object]]], device_type: str
) -> list[dict[str, object]]:
    """Spares that can serve `device_type`, including equivalent models.

    Packet Tracer's type names are not the words a prompt uses, and they differ
    between device generations: a laptop is `WirelessEndDevice` in one lab and
    `Laptop` in another, a home router is `WirelessRouterNewGeneration`. Exact
    matching meant a donor full of wireless routers reported none.

    Selection already understood these equivalences; the planner did not, which
    is the same two-models-of-one-concept split that has caused every other
    defect here.
    """
    exact = pools.get(device_type)
    if exact:
        return exact
    try:
        from local_donors import TYPE_EQUIVALENTS
    except ImportError:  # pragma: no cover
        return []
    for name in TYPE_EQUIVALENTS.get(device_type, ()):  # ordered, closest first
        pool = pools.get(name)
        if pool:
            return pool
    return []


def _local_donor_candidates(
    *,
    exclude: set[str] | None = None,
    limit: int | None = None,
    required_types: dict[str, int] | None = None,
) -> list[SampleCandidate]:
    """The user's own labs, as generation bases.

    Bounded because summarising a lab costs ~770 ms: this machine holds 117
    eligible labs, and decoding all of them would take longer than ninety
    generation runs. The cap is on how many are *summarised*, not on how many
    are discovered -- discovery is a cached header read.
    """
    try:
        from local_donors import discover_local_donors
    except ImportError:  # pragma: no cover - the widening is optional
        return []

    excluded = {str(Path(item).resolve()).lower() for item in (exclude or set())}
    cap = limit if limit is not None else int(
        os.getenv("PACKET_TRACER_LOCAL_DONOR_LIMIT") or DEFAULT_LOCAL_DONOR_LIMIT
    )

    candidates: list[SampleCandidate] = []
    # Filtering on what a lab contains is what makes this useful: without it the
    # first `cap` labs in alphabetical order get summarised, and a request for a
    # wireless router happily decodes a dozen wired campus labs.
    discovered = discover_local_donors(
        required_types=required_types or None,
        stop_after=cap + len(excluded) if required_types else 0,
    )
    for donor in discovered:
        if len(candidates) >= cap:
            break
        if str(donor.path.resolve()).lower() in excluded:
            continue
        try:
            sample = summarize_pkt_descriptor(
                donor.path,
                relative_path=donor.path.name,
                origin="local-lab",
                prototype_eligible=True,
                trust_level="trusted",
                role="compatibility",
                license_or_permission="local-user",
                promotion_status="validated_compat",
                validation_status="validated",
                donor_eligible=True,
            )
        except Exception:  # noqa: BLE001 - an unreadable lab is simply skipped
            continue
        sample.version = donor.version
        sample.packet_tracer_version = donor.version
        candidates.append(
            SampleCandidate(
                sample=sample,
                capability_score=90,
                topology_score=0,
                total_score=90,
                reasons=["local-lab"],
            )
        )
    return candidates


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
    for bucket in [
        [candidate] if (candidate := _compat_donor_candidate()) is not None else [],
        _base_donor_candidates(cisco_ranked),
        _base_donor_candidates(curated_ranked),
    ]:
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
    remote_dry_run: bool = False,
    remote_audit_out: Path | None = None,
) -> tuple[list[Path], list[Path], list[dict[str, object]]]:
    resolved_reference_roots = list(reference_roots or [])
    resolved_donor_roots = list(donor_roots or [])
    if not search_remote:
        return resolved_reference_roots, resolved_donor_roots, []
    remote_candidates = search_remote_candidates(plan, provider=remote_provider, max_results=max_remote_results)
    cache_root = import_cache_root or _default_import_cache_root()
    imported_candidates = auto_import_remote_candidates(
        remote_candidates,
        cache_root,
        max_results=max_remote_results,
        dry_run=remote_dry_run,
    )
    write_remote_sample_audit(imported_candidates, cache_root, remote_audit_out)
    for candidate in imported_candidates:
        if candidate.path:
            imported_root = Path(candidate.path)
            if imported_root not in resolved_reference_roots:
                resolved_reference_roots.append(imported_root)
            if candidate_is_curated_eligible(candidate) and imported_root not in resolved_donor_roots:
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
    ipv4_routing_management_signal = plan.network_style == "ipv4_routing_management" or bool(capabilities & {"ospfv2", "eigrp_ipv4", "ripv2", "static_route", "default_route", "dhcp_relay", "nat_static", "nat_dynamic", "pat", "ssh_ios", "ntp_ios", "syslog_ios"})
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
    elif ipv4_routing_management_signal:
        family_hints.append("IPv4 routing/management")
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
    if capabilities & {"ospfv2", "eigrp_ipv4", "ripv2", "static_route", "default_route", "dhcp_relay", "nat_static", "nat_dynamic", "pat", "ssh_ios", "ntp_ios", "syslog_ios"}:
        features.add("ipv4_routing_management_runtime")
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
    counts = {"selected": 0, "rejected": 0, "filtered": 0, "deprioritized": 0}
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


# Assumptions the planner records when it picks link speeds the user never asked
# for. A defaulted value is a preference, not a requirement, so it must never be
# the reason a donor is rejected.
DEFAULTED_LINK_WIRING_ASSUMPTIONS = (
    "Defaulted host links to FastEthernet.",
    "Defaulted switch uplinks to GigabitEthernet.",
)


def _link_wiring_was_defaulted(plan: IntentPlan) -> bool:
    """Whether the planner, not the user, chose the interfaces.

    This only looked for two specific assumption strings, and most prompts never
    record either -- so a prompt that named no ports at all was treated as
    having demanded exact ones. The donor's own wiring was then rejected for
    disagreeing with a choice nobody made: `1 router 1 switch 1 server qur ntp
    olsun` was refused because the donor's router uses `GigabitEthernet0/0/1`
    and the planner had picked `0/0/0`. That single mismatch blocked ntp,
    syslog, snmp and aaa.

    A prompt with no explicit links has no wiring preference to violate, and
    `_synthesize_links` records that as an assumption when it invents the wiring
    -- checking `plan.links` here cannot work, because the blueprint has filled
    that list in by the time this is asked.
    """
    used = set(plan.assumptions_used)
    return any(assumption in used for assumption in DEFAULTED_LINK_WIRING_ASSUMPTIONS)


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
        "parity_donor_backed_ready_count": sum(1 for entry in parity_entries if bool(entry.get("donor_backed_ready"))),
        "parity_generate_ready_count": sum(1 for entry in parity_entries if bool(entry.get("generate_supported"))),
        "parity_acceptance_verified_count": sum(1 for entry in parity_entries if bool(entry.get("acceptance_verified"))),
        "parity_mismatch_count": sum(1 for entry in parity_entries if entry.get("generate_mismatch_reason")),
    }


def _critical_parity_counts(critical_entries: list[dict[str, object]]) -> dict[str, int]:
    return {
        "critical_parity_supported_count": sum(1 for entry in critical_entries if bool(entry.get("inventory_supported"))),
        "critical_parity_donor_backed_ready_count": sum(1 for entry in critical_entries if bool(entry.get("donor_backed_ready"))),
        "critical_parity_generate_ready_count": sum(1 for entry in critical_entries if bool(entry.get("generate_supported"))),
        "critical_parity_acceptance_verified_count": sum(1 for entry in critical_entries if bool(entry.get("acceptance_verified"))),
        "critical_parity_mismatch_count": sum(1 for entry in critical_entries if entry.get("generate_mismatch_reason")),
    }


@lru_cache(maxsize=1)
def _proof_cards_by_family() -> dict[str, list[dict[str, object]]]:
    if not PROOF_CARDS_PATH.exists():
        return {}
    payload = json.loads(PROOF_CARDS_PATH.read_text(encoding="utf-8"))
    cards = payload.get("proof_cards", []) if isinstance(payload, dict) else []
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for card in cards:
        if not isinstance(card, dict):
            continue
        family = str(card.get("scenario_family") or "").strip()
        if not family:
            continue
        grouped[family].append(
            {
                "title": card.get("title"),
                "support_level": card.get("support_level"),
                "proof_doc": card.get("proof_doc"),
                "try_command": card.get("try_command") or card.get("explicit_command"),
                "does_not_claim": card.get("does_not_claim") or card.get("refusal_boundary"),
            }
        )
    return dict(grouped)


def _proof_card_refs_for_family(family: object) -> list[dict[str, object]]:
    return _proof_cards_by_family().get(str(family or "").strip(), [])


def _first_recommended_action(entries: list[dict[str, object]]) -> str | None:
    return next(
        (str(entry.get("recommended_next_action")) for entry in entries if str(entry.get("recommended_next_action") or "").strip()),
        None,
    )


def _support_level_explanation(*, critical_generate_ready: int, critical_donor_ready: int, critical_supported: int, critical_mismatches: int) -> str:
    if critical_generate_ready > 0:
        return "At least one critical capability is generate-ready, but scenario-level generation still depends on donor/runtime acceptance."
    if critical_donor_ready > 0:
        return "Some critical capabilities have donor-backed edit readiness; this is not broad topology generation."
    if critical_supported > 0 and critical_mismatches > 0:
        return "Critical capabilities are recognized, but they remain report-only, edit-only, donor-limited, or acceptance-gated."
    if critical_supported > 0:
        return "Critical capabilities are recognized for this scenario, but no generate-ready claim is made."
    return "No critical scenario capabilities are generate-ready; use --explain-plan for donor/runtime/refusal detail."


def _parity_user_summary(result: dict[str, object]) -> dict[str, object]:
    family = result.get("scenario_family")
    critical_supported = int(result.get("critical_parity_supported_count", 0) or 0)
    critical_donor_ready = int(result.get("critical_parity_donor_backed_ready_count", 0) or 0)
    critical_generate_ready = int(result.get("critical_parity_generate_ready_count", 0) or 0)
    critical_mismatches = int(result.get("critical_parity_mismatch_count", 0) or 0)
    critical_entries = list(result.get("critical_capability_parity", []) or [])
    mismatches = list(result.get("critical_parity_mismatches", []) or [])
    explanation = _support_level_explanation(
        critical_generate_ready=critical_generate_ready,
        critical_donor_ready=critical_donor_ready,
        critical_supported=critical_supported,
        critical_mismatches=critical_mismatches,
    )
    if critical_generate_ready > 0:
        status = "has_generate_ready_capability"
    elif critical_donor_ready > 0:
        status = "donor_backed_edit_ready"
    elif critical_supported > 0:
        status = "recognized_but_not_generate_ready"
    else:
        status = "not_generate_ready"
    next_best_action = _first_recommended_action(mismatches) or _first_recommended_action(critical_entries)
    if not next_best_action:
        next_best_action = "Run --explain-plan for donor selection, runtime, and refusal details."
    return {
        "status": status,
        "message": explanation,
        "next_best_action": next_best_action,
        "critical_counts": {
            "supported": critical_supported,
            "donor_backed_ready": critical_donor_ready,
            "generate_ready": critical_generate_ready,
            "mismatches": critical_mismatches,
        },
        "proof_card_refs": _proof_card_refs_for_family(family),
    }


def _explain_user_summary(result: dict[str, object]) -> dict[str, object]:
    summary = dict(result.get("scenario_acceptance_summary") or {})
    decision = dict(result.get("scenario_generate_decision") or {})
    family = summary.get("family") or decision.get("family")
    generate_state = str(summary.get("generate_state") or ("allowed" if decision.get("allow_generate") else "blocked"))
    readiness = str(summary.get("readiness_status") or "")
    blocking_layer = summary.get("blocking_layer") or decision.get("blocking_layer")
    next_best_action = (
        summary.get("next_best_action")
        or next((step for step in list(summary.get("remediation_steps", []) or []) if str(step).strip()), None)
        or "Run --doctor and --parity-report to identify runtime, donor, and support blockers."
    )
    if generate_state == "allowed":
        status = "ready_with_current_constraints"
        message = "The plan passed current donor/runtime gates for the detected scenario."
    elif blocking_layer == "runtime":
        status = "blocked_by_runtime"
        message = "Generation is blocked by Packet Tracer runtime, donor, or Twofish bridge readiness."
    elif blocking_layer == "donor":
        status = "blocked_by_donor_selection"
        message = "Generation is blocked because no selected donor currently satisfies the prompt safely."
    elif readiness == "unsupported":
        status = "blocked_by_capability"
        message = "The prompt asks for capabilities that are not generate-ready for this scenario."
    else:
        status = "blocked_by_acceptance_or_proof"
        message = "The prompt is recognized, but strict acceptance, donor, or proof gates are not satisfied."
    return {
        "status": status,
        "message": message,
        "next_best_action": next_best_action,
        "support_level_explanation": "Feature recognition, edit proof, donor-backed readiness, and generate readiness are separate support levels.",
        "proof_card_refs": _proof_card_refs_for_family(family),
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
    deprioritized: list[SampleCandidate] = []
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
            # This is a cheap heuristic, not the transformer. It may reorder the
            # pool but it must never remove a candidate: only
            # `_evaluate_donor_prune_candidates` rejects, because only it actually
            # executes the transform and can therefore be right. Letting the whole
            # pool through costs about 110 ms per donor decode.
            deprioritized.append(candidate)
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
                    "status": "deprioritized",
                    "rejection_reasons": [*filter_reasons, *penalty_reasons],
                }
            )
            continue
        viable.append(candidate)
    # Heuristic-preferred candidates are tried first; the rest still get their turn.
    return [*viable, *deprioritized], filtered_diagnostics


def _learned_donor_scores(plan: IntentPlan, blueprint: dict[str, object]) -> dict[str, int]:
    """Donor preferences learned from previous runs. Never fatal."""
    try:
        family = str(blueprint.get("topology_archetype") or "general")
        return usage_ledger.donor_scores(family, usage_ledger.prompt_fingerprint(plan.prompt))
    except Exception:
        return {}


def _record_generation_outcome(
    *,
    prompt: str,
    scenario_decision: dict[str, object] | None,
    donor_archetype: DonorArchetypePlan,
    outcome: str,
) -> None:
    """Write one ledger entry. A ledger failure must never fail a generation."""
    try:
        decision = scenario_decision or {}
        usage_ledger.record(
            usage_ledger.LedgerEntry(
                scenario_family=str(decision.get("family") or "general"),
                prompt_shape=usage_ledger.prompt_fingerprint(prompt),
                donor=str(donor_archetype.compat_donor_relative_path or donor_archetype.compat_donor),
                donor_version=str(donor_archetype.donor_capacity.get("version", "") or ""),
                target_version=get_packet_tracer_target_version(),
                outcome=outcome,
            )
        )
    except Exception:
        return


def _switch_model_affinity(sample: object, blueprint: dict[str, object]) -> int:
    """How many of this donor's switches are the model the plan asked for.

    Donor-prune reuses the donor's devices, so the model in the blueprint is
    advisory: `_choose_switch_model` returns `2960-24TT` and the lab ships
    whatever the donor happened to hold. Measured across the corpus, 43 of 53
    switches came out on a different model than planned, and 42 of them were
    `IE-9320` -- an industrial switch, in labs asked for as plain campus
    networks.

    The material is there: of 70 bundled labs, 27 hold a `2960-24TT` and 36
    such switches exist in total. So this is a selection problem, not a
    scarcity one, and the donor that already owns the right model is the one to
    prefer.

    Counted rather than scored as a fraction: a donor with four matching
    switches serves a four-switch prompt better than one with a single match,
    and the count says so directly.
    """
    wanted = {
        str(device.get("model") or "").strip()
        for device in blueprint.get("devices", [])
        if str(device.get("type", "")).endswith("Switch")
    }
    wanted.discard("")
    if not wanted:
        return 0
    devices = getattr(sample, "devices", None) or []
    return sum(
        1
        for device in devices
        if str(device.get("type", "")).endswith("Switch")
        and str(device.get("model") or "").strip() in wanted
    )


def _rerank_candidates_for_blueprint(
    candidates: list[SampleCandidate],
    blueprint: dict[str, object],
    learned_scores: dict[str, int] | None = None,
) -> list[SampleCandidate]:
    # Evidence from previous runs outranks every heuristic below it: a donor that
    # has actually produced a working file for this kind of request is a better
    # bet than one that merely scores well on paper.
    learned = learned_scores or {}

    def _sort_key(candidate: SampleCandidate) -> tuple[int, int, int, int, int, int, int, int]:
        fit = build_donor_graph_fit(candidate.sample, blueprint)
        acceptance_penalty, _ = _candidate_acceptance_penalty(candidate, blueprint)
        adjusted_score = candidate.total_score - acceptance_penalty
        preferred_archetypes = [str(item) for item in list(blueprint.get("preferred_donor_archetypes", [])) if item]
        archetype_match_score, _, _ = _candidate_archetype_alignment(candidate.sample, preferred_archetypes)
        return (
            learned.get(candidate.sample.relative_path, 0),
            fit.layout_reuse_score,
            archetype_match_score,
            fit.fit_score - acceptance_penalty,
            -len(fit.port_media_conflicts),
            -len(fit.missing_pairs),
            # Below the fit signals on purpose: a donor that wires up correctly
            # matters more than one holding the right switch model, and a lab
            # that opens beats a lab with prettier hardware. This decides
            # between donors the checks above rate the same.
            _switch_model_affinity(candidate.sample, blueprint),
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


def _blueprint_wants_serial(blueprint: dict[str, object]) -> bool:
    for link in blueprint.get("links", []):
        if str(link.get("media", "")).lower() == "serial":
            return True
        for end in ("a", "b"):
            if str(link.get(end, {}).get("port", "")).startswith("Serial"):
                return True
    return False


def _root_has_serial_link(root: ET.Element) -> bool:
    """Whether a built lab actually carries a serial cable.

    A donor owning serial-capable routers does not mean the generated lab
    inherits a serial link: pruning may drop the very cable that used it.
    Five donors were probed by hand and the ones that produced a serial WAN
    could not be told apart by any count taken from the donor -- serial
    routers, routers also facing a switch, and router-to-router pairs were
    identical across the ones that worked and the ones that did not. The
    finished lab is the only place the answer is written down.

    The `eSerial` tag alone is not that answer. A pruned lab was measured
    carrying an `eSerial` cable whose two ends were `GigabitEthernet0/0/1` and
    `GigabitEthernet0/0/0`; `_reconcile_cable_media` then demoted it to copper,
    as it should, because Packet Tracer refuses a serial cable in an Ethernet
    socket. The ports are what make a link serial, so the ports are what is
    counted here.

    Nor is a serial-looking name enough. A lab pruned from
    `Senan_Haciyev_tapsiriq.pkt` was measured wiring `Serial0/0/0 <-> Serial0/0/0`
    between two routers whose only serial interfaces are `Serial2/0` and
    `Serial3/0`; `port_exists` accepts the name, but the devices' own interface
    lists do not have it. A cable between ports that do not exist is not a WAN,
    so both ends must name an interface the device actually owns.
    """
    order: list[ET.Element] = list(root.findall(".//DEVICES/DEVICE"))
    by_ref: dict[str, ET.Element] = {}
    for device in order:
        ref = (device.findtext("./ENGINE/SAVE_REF_ID") or "").strip()
        if ref:
            by_ref[ref] = device

    def resolve(value: str) -> ET.Element | None:
        value = value.strip()
        if value in by_ref:
            return by_ref[value]
        if value.isdigit() and int(value) < len(order):
            return order[int(value)]
        return None

    for link in root.findall(".//LINKS/LINK"):
        if (link.findtext("./TYPE") or "").strip() != "eSerial":
            continue
        cable = link.find("./CABLE")
        if cable is None:
            continue
        ports = [(node.text or "") for node in cable.findall("PORT")]
        if len(ports) < 2 or not all(port.startswith("Serial") for port in ports):
            continue
        ends = (
            (resolve(cable.findtext("FROM", default="")), ports[0]),
            (resolve(cable.findtext("TO", default="")), ports[1]),
        )
        if all(
            device is not None and port in donor_interface_names(device)
            for device, port in ends
        ):
            return True
    return False


def _adopt_blueprint(blueprint: dict[str, object], archetype_plan: DonorArchetypePlan) -> None:
    """Write a committed donor's adaptation back onto the caller's blueprint.

    Downstream stages read the blueprint expecting the ports and cable families
    that ended up in the file, so the adaptation still has to land -- just from
    the donor that was chosen, and only once the choice is made.
    """
    adapted = archetype_plan.adapted_blueprint
    if not adapted:
        return
    blueprint.clear()
    blueprint.update(adapted)


def _pool_selected_a_donor(diagnostics: list[dict[str, object]]) -> bool:
    """Whether a pool produced a donor it was happy with, rather than settling.

    The deferred fallback returns a candidate whose diagnostic stays labelled
    `deferred_no_serial`, so the absence of a `selected` entry is what tells
    the caller the pool made do.
    """
    return any(item.get("status") == "selected" for item in diagnostics)


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
    # A prompt asking for a serial WAN plans `R1 Serial0/0/0 <-> R2 Serial0/0/0`
    # correctly, and then the donor decides whether it can happen. Measured on
    # `iki noqte arasinda leased line`: the donor chosen had routers with no
    # serial ports at all, so the port repair moved the cable to Ethernet and
    # media reconciliation demoted it to copper -- every stage behaving as
    # designed, and the lab arriving without the WAN it was asked for.
    #
    # Serial donors are not scarce: 196 `eSmartSerial` and 110 `eSerial` ports
    # across the local pool. The check is free here because this loop already
    # decodes each candidate, and a donor that cannot serve the link is only
    # deferred, never rejected -- if none of them has a serial port, the first
    # workable candidate is still used and the lab still generates.
    wants_serial = _blueprint_wants_serial(blueprint)
    serial_deferred: tuple[IntentPlan, DonorArchetypePlan, ET.Element, SampleCandidate] | None = None
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
            # Adaptation rewrites the blueprint's links to the ports the donor
            # actually owns, and it used to do so on the caller's dict. Measured
            # on `iki noqte arasinda leased line`: the first donor tried could
            # not serve the WAN, so it rewrote the requirement itself --
            # `R1 Serial0/0/0 <-> R2 Serial0/0/0 (serial)` became
            # `R1 GigabitEthernet0/0 <-> R2 GigabitEthernet0/1 (eCrossOver)` --
            # and from that point no later donor, pool or check could tell the
            # prompt had asked for serial at all. A rejected donor must not be
            # able to edit what was asked for, so each one adapts a copy and
            # only the chosen one writes back.
            candidate_blueprint = copy.deepcopy(blueprint)
            adapted_plan, archetype_plan = _build_donor_prune_plan_for_donor(
                plan, candidate_blueprint, donor_path
            )
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
            archetype_plan.adapted_blueprint = candidate_blueprint
            diagnostic["status"] = "selected"
            diagnostic["rejection_reasons"] = []
            diagnostics.append(diagnostic)
            result = (adapted_plan, archetype_plan, donor_root, donor_candidate)
            if wants_serial and not _root_has_serial_link(candidate_root):
                # Workable, but it did not come out with the WAN that was asked
                # for. Hold it in case nothing better turns up.
                if serial_deferred is None:
                    serial_deferred = result
                # The diagnostic is already in the list; relabel it in place
                # rather than recording the same candidate twice.
                diagnostic["status"] = "deferred_no_serial"
                continue
            return result, diagnostics
        except PlanningError as exc:
            latest_plan = exc.plan
            diagnostic["status"] = "rejected"
            diagnostic["rejection_reasons"] = _summarize_rejection_issues(exc.plan.blocking_gaps)
        except Exception as exc:
            diagnostic["status"] = "rejected"
            diagnostic["rejection_reasons"] = _summarize_rejection_issues([str(exc)])
        diagnostics.append(diagnostic)
    if serial_deferred is not None:
        # No donor in the pool produced a serial link. A lab without the WAN
        # beats no lab at all, so the best workable candidate is used after all.
        return serial_deferred, diagnostics
    if latest_plan is not None:
        plan.blocking_gaps = list(dict.fromkeys([*plan.blocking_gaps, *latest_plan.blocking_gaps]))
    return None, diagnostics


def _apply_prompt_compatibility_requirements(plan: IntentPlan, donor_roots: list[Path] | None = None) -> IntentPlan:
    prepared = prepare_generation_plan(plan)
    if prepared.goal != "edit":
        topology_tags = _topology_tags_for_plan(prepared, _choose_topology_archetype(prepared))
        _, _, donor_candidates = _rank_generation_donors(prepared, topology_tags, donor_roots)
        if not donor_candidates:
            gap = _strict_compatibility_gap()
            if gap not in prepared.blocking_gaps:
                prepared.blocking_gaps.append(gap)
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
    # The blueprint as this donor rewrote it -- its real port names and cable
    # families. Candidates adapt a copy so that a donor which is not chosen
    # cannot edit the requirement out from under the ones tried after it; the
    # caller adopts this one only once it commits to the donor.
    adapted_blueprint: dict[str, object] | None = None


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


# Pruning is how donor-prune generation works: it takes a real Cisco lab, removes
# what the plan does not need, and renames and repositions the rest. Those
# operations are therefore *allowed* here, not blocked. What stays blocked is
# everything that invents structure the donor never had, because that is what
# produces files Packet Tracer refuses to open.
SAFE_OPEN_ALLOWED_MUTATIONS = [
    "device_rename",
    "layout_reposition",
    "config_mutation",
    "service_mutation",
    "device_prune",
    "link_prune",
    "donor_group_reduction",
    # Verified against a real Packet Tracer open: a duplicated switch with a
    # fresh identity, joined by a created switch-to-switch link, opens. This is
    # what lets a topology be larger than its donor.
    "device_duplicate",
]
# Measured 2026-08-03: see `_host_config_enabled`.
DEFAULT_HOST_CONFIG = True
# Measured 2026-08-03: see `_wireless_config_enabled`.
DEFAULT_WIRELESS_CONFIG = True

SAFE_OPEN_BLOCKED_MUTATIONS = [
    "link_rewrite",
    "port_reassignment",
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
        # Named in the switch series on purpose: it is one of the switches the
        # prompt counted, promoted to a multilayer model to fit the donors.
        "MultiLayerSwitch": f"SW{index}",
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


# What may be cabled to a switch. The list is short on purpose and every entry
# was measured across 120 local donors by asking whether instances of that kind
# actually carry a copper port:
#
#     IpPhone   4/4 copper      Tablet        0/11 copper, 11/11 wireless
#     HomeVoip  2/2 copper      AnalogPhone   0/2  copper
#     Sniffer   3/3 copper      IoT           0/1  copper
#
# A tablet has no Ethernet at all, an analog phone takes a phone line, and the
# IoT things in these donors are wireless, so none of them may be cabled to a
# switch: that would put a cable on a socket that does not exist, which is
# exactly what Packet Tracer refuses to open.
#
# The sniffer was left out at first: its ports are `eCopperEthernet`, which
# `port_capacity` counts as neither FastEthernet nor GigabitEthernet, so port
# selection fell through and put the cable on `Port-channel 5` and the lab was
# refused. It is back, because the missing piece was only the port's name.
# Scanning what donors actually cable, per kind, gives `Ethernet0` -- not the
# `FastEthernet0` the device palette reports for the same device.
#
# Before this, `1 switch 3 ip phone qur` produced a lab with four devices and
# zero cables, and reported success.
# The five after the sniffer come from the same scan and plug into a switch for
# the same reason a phone does. The access point and the Meraki server were
# tried once before and taken back out, because the cable arrived on
# `GigabitEthernet0/1` and `FastEthernet0/1` when each device carries a single
# unslotted port. That turned out not to be this table's fault: `port_exists`
# was answering that the real port was absent and the invented one present, so
# the port repair replaced the good name with the bad. With those kinds
# recognised as unslotted, both are back.
HOST_DEVICE_KINDS = {
    "PC",
    "Server",
    "Printer",
    "Laptop",
    "IpPhone",
    "HomeVoip",
    "Sniffer",
    "WirelessLanController",
    "NetworkController",
    "LightWeightAccessPoint",
    "MerakiServer",
    # Each of these arrived in the file with no cable on it. The port each
    # one uses is measured off real cables in 200 saved labs, below in
    # `_host_port`; `Wall Mount` is left out because not one lab cables it,
    # and guessing is what puts hardcoded port names back into the file.
    "Hub",
    "WiredEndDevice",
    "Patch Panel",
    "Bridge",
    "Repeater",
    "TV",
    # A firewall the prompt asked for used to arrive cabled to nothing:
    # present in the file, valid, and not part of the network. It is an
    # end device as far as the link synthesiser is concerned -- one cable,
    # to the switch.
    "ASA",
}


def _is_host_device(device: dict[str, object]) -> bool:
    return _device_kind(device) in HOST_DEVICE_KINDS


def _is_wireless_client_device(device: dict[str, object]) -> bool:
    return _device_kind(device) in {"Tablet", "Smartphone"}


WIRELESS_ROUTER_KINDS = {"WirelessRouter", "WirelessRouterNewGeneration"}


def _wireless_router_lan_port(index: int) -> str:
    """A home router's LAN port, counting from 1.

    Measured across 348 saved labs: the new-generation home router's cables sit
    on `GigabitEthernet 1` .. `GigabitEthernet 4`, twenty of them, and the older
    Linksys model's on `Ethernet 1` .. `Ethernet 4`, two. The space is part of
    the name. Both count from one, which is why the index is not offset.

    `Internet` is deliberately not reachable from here. Fourteen cables in those
    labs use it and every one is an uplink -- it is the WAN port, and a host
    plugged into it is on the wrong side of the router.
    """
    return f"GigabitEthernet {index}"


# Router interface naming, read off Packet Tracer's own device list rather
# than guessed from a prefix. The table used to know `2901` and `ISR` and fell
# back to FastEthernet for everything else, which is wrong for most of the
# modern models: a 2911 has `GigabitEthernet0/0` .. `0/2` and no FastEthernet
# at all.
#
# The cost of getting it wrong is not a rejected file. `FastEthernet0/0` on a
# 2911 is invalid, so the port repair relocates the cable to the first free
# valid interface -- `GigabitEthernet0/0`, the one addressing had already made
# the WAN uplink. The lab then carried its router-on-a-stick subinterfaces on
# `GigabitEthernet0/1`, which no cable reached: ten subinterfaces
# protocol-down, no gateway for any VLAN, and a lab that opened and read
# correctly throughout.
ROUTER_PORT_SHAPES = {
    "GigabitEthernet0/{n}": ("1941", "2901", "2911", "CGR1240"),
    "GigabitEthernet0/0/{n}": ("ISR4321", "ISR4331", "ISR"),
    "GigabitEthernet{n}": ("819HG", "819HGW", "829"),
}


def _router_port(device: dict[str, object], index: int = 1) -> str:
    model = str(device.get("model") or "")
    for shape, models in ROUTER_PORT_SHAPES.items():
        if any(model.startswith(prefix) for prefix in models):
            return shape.format(n=index - 1)
    # 1841, 2620XM, 2621XM, 2811 and the generic Router-PT.
    return f"FastEthernet0/{index - 1}"


# Uplink capacity by switch family. A 2960-24TT has exactly two gigabit
# interfaces, so a core switch fanning out to twenty access switches runs out
# after the second one.
SWITCH_GIGABIT_UPLINKS = {"3650": 24, "3560": 24}
DEFAULT_GIGABIT_UPLINKS = 2


def _switch_uplink_port(device: dict[str, object], index: int) -> str:
    """Name the nth uplink, staying inside the interfaces the model has.

    This returned `GigabitEthernet0/{index}` for any index, so a twenty-two
    switch topology asked a 2960 for `GigabitEthernet0/20`. Packet Tracer
    rejects a lab that names an interface the device does not have, which is why
    a 62-device lab opened and a 64-device one did not -- the size was never the
    problem, the twentieth uplink was.
    """
    model = str(device.get("model") or "")
    if model.startswith("3650"):
        return f"GigabitEthernet1/0/{index}"
    available = next(
        (count for prefix, count in SWITCH_GIGABIT_UPLINKS.items() if model.startswith(prefix)),
        DEFAULT_GIGABIT_UPLINKS,
    )
    if index <= available:
        return f"GigabitEthernet0/{index}"
    # Past the gigabit interfaces an engineer would use a copper access port.
    # Counting down from the top keeps the low numbers free for hosts, and the
    # port reconciliation pass moves anything that still collides.
    return f"FastEthernet0/{max(1, 24 - (index - available - 1))}"


# The widest access switch the generator uses has 24 copper ports. Past that
# there is nothing to skip to, so allocation stops searching and leaves the
# collision for the reconciliation pass to report rather than looping.
MAX_SWITCH_ACCESS_PORT = 24


def _switch_access_port(index: int) -> str:
    return f"FastEthernet0/{index}"


def _host_port(device: dict[str, object]) -> str:
    kind = _device_kind(device)
    if kind in {"Tablet", "Smartphone"}:
        return "Wireless0"
    # An IP phone's network socket is called `Switch`; the second one, `PC`, is
    # the pass-through a computer plugs into behind the phone. It has no
    # `FastEthernet0` at all. Measured: the donor's own phone links use `Switch`,
    # and a created link naming `FastEthernet0` was pushed to `FastEthernet1` by
    # port claiming and produced a lab Packet Tracer refused -- while the same
    # prompt with two PCs alongside opened, because there the phones kept the
    # donor's wiring and only the PCs got new cables.
    if kind == "IpPhone":
        return "Switch"
    # A home VoIP adapter is an ATA: `Ethernet` faces the network and `Phone`
    # takes the analog handset. Read off the donors that contain one -- every
    # working link in them uses those two names, and none uses `Switch`.
    if kind == "HomeVoip":
        return "Ethernet"
    # Measured the same way, by scanning every cable in 130 donor labs and
    # grouping the port names by device kind. Worth doing rather than trusting
    # the device palette, which reports `FastEthernet0` for a sniffer and
    # `Port 0`/`PC Port` for an IP phone -- neither of which appears on a single
    # cable in a saved lab.
    if kind == "Sniffer":
        return "Ethernet0"
    if kind in {"NetworkController", "LightWeightAccessPoint"}:
        return "GigabitEthernet0"
    if kind == "WirelessLanController":
        return "GigabitEthernet1"
    # Measured the same way, off the cables in 150 saved labs: every ASA
    # link uses `Ethernet0/N`, while the live device palette reports
    # `GigabitEthernet1/1` for a 5506-X. The models differ, so this is the
    # starting name and `_repair_invalid_link_ports` moves it to whatever
    # the chosen device really has -- the same way router and switch ports
    # are already corrected per model.
    if kind == "ASA":
        return "Ethernet0/0"
    # Read off the cables in 200 saved labs, the same way as the kinds
    # above. A hub is the strongest of them, cabled in six labs on
    # `FastEthernet0`; the rest appear once each, and the port repair
    # corrects any that do not fit the device that is finally chosen.
    if kind == "Patch Panel":
        return "PunchDown1"
    if kind == "Bridge":
        return "Ethernet0/1"
    if kind == "Repeater":
        return "Ethernet0"
    if kind == "TV":
        return "Port 0"
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
        if op_name in {"duplicate_device", "duplicate_group", "duplicate_host"}:
            return "device_duplicate"
        if op_name == "set_link":
            return "link_rewrite"
        if op_name == "remove_link":
            # Removing a donor link is a prune, not a port change. Calling it
            # `port_reassignment` put it on the blocked list and made donor-prune
            # generation forbid its own core operation.
            return "link_prune"
        if op_name == "apply_cli":
            # `cli R1: ...` writes IOS text into a device's configuration and
            # touches nothing else -- the same class as the switch and router
            # operations below. Falling through to the default named it a
            # physical workspace change, which is blocked in open-first mode, so
            # the first prompt that carried arbitrary CLI refused to generate.
            return "config_mutation"
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


def _host_config_enabled() -> bool:
    """Whether end-device configuration may be applied.

    On by default, and that default is a measurement. `end_device_mutation` sat
    on the blocked list with nothing in the repo recording why -- the same shape
    as `device_prune` and `remove_link`, which both turned out to be safe once
    somebody actually tested them.

    Two files generated with it enabled were opened in Packet Tracer: a flat
    router-DHCP lab (10.1s) and a three-VLAN lab with a DHCP pool per VLAN
    (10.2s). Both opened. Set `PACKET_TRACER_HOST_CONFIG=0` to restore the old
    behaviour.
    """
    raw = (os.getenv("PACKET_TRACER_HOST_CONFIG") or "").strip().lower()
    if raw in {"1", "on", "true", "yes"}:
        return True
    if raw in {"0", "off", "false", "no"}:
        return False
    return DEFAULT_HOST_CONFIG


def _wireless_config_enabled() -> bool:
    """Whether wireless configuration may be applied.

    On by default, and that default is a measurement. `wireless_mutation` and
    `wireless_client_association` were the last entries on the blocked list with
    nothing recording why -- and until the donor pool was widened there was no
    wireless donor to test them against.

    Two labs generated with it enabled were opened in Packet Tracer: a home
    network with a named WPA2 network and two laptops (13.5s), and one with
    three laptops, two tablets and an explicit channel (10.1s). Both opened,
    with the SSID and passphrase present in the saved file. Set
    `PACKET_TRACER_WIRELESS_CONFIG=0` to restore the old behaviour.
    """
    raw = (os.getenv("PACKET_TRACER_WIRELESS_CONFIG") or "").strip().lower()
    if raw in {"1", "on", "true", "yes"}:
        return True
    if raw in {"0", "off", "false", "no"}:
        return False
    return DEFAULT_WIRELESS_CONFIG


def _allowed_mutations() -> list[str]:
    """Allowed mutation categories for the active strategies."""
    allowed = list(SAFE_OPEN_ALLOWED_MUTATIONS)
    if _link_strategy() == "create":
        allowed.append("link_rewrite")
    if _host_config_enabled():
        allowed.append("end_device_mutation")
    if _wireless_config_enabled():
        allowed.extend(["wireless_mutation", "wireless_client_association"])
    return allowed


def _blocked_mutations() -> list[str]:
    allowed = set(_allowed_mutations())
    return [category for category in SAFE_OPEN_BLOCKED_MUTATIONS if category not in allowed]


def _safe_open_plan(plan: IntentPlan) -> tuple[IntentPlan, list[str]]:
    safe_plan = _empty_plan_like(plan)
    blocked: list[str] = []
    allowed_mutations = _allowed_mutations()
    blocked_mutations = _blocked_mutations()
    for bucket_name, operation in _bucket_operations(plan):
        category = _operation_category(bucket_name, operation)
        if category in allowed_mutations:
            getattr(safe_plan, bucket_name).append(copy.deepcopy(operation))
        elif category == "verification_only":
            continue
        elif category in blocked_mutations:
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


IMAGE_REFERENCE_TAGS = (
    "CUSTOM_IMAGE_LOGICAL",
    "CUSTOM_IMAGE_PHYSICAL",
    "CLUSTER_BG_IMAGE",
    "CLUSTER_EMBEDDED_BG_IMAGE",
    "CLUSTER_ICON_IMAGE",
)


def prune_unused_images(root: ET.Element) -> int:
    """Drop embedded pictures nothing in the lab points at.

    Donors carry a `PIXMAPBANK` of background images the original author
    imported. A generated lab inherits the whole bank however few devices
    survive: a four-device home network came out at 2.8 MB, of which 3.6 MB was
    thirty-five orphaned JPEGs and 58 KB was the devices.

    Size is the smaller problem. The bank also carries the *paths* those images
    came from -- `../../../Users/78-USER/Downloads/...` -- so every lab
    generated from that donor republished a stranger's photos and their account
    name. Anything still referenced is kept; only orphans go.

    Returns how many images were removed.
    """
    bank = root.find(".//PIXMAPBANK")
    if bank is None:
        return 0

    referenced: set[str] = set()
    for tag in IMAGE_REFERENCE_TAGS:
        for element in root.iter(tag):
            for node in element.iter():
                value = (node.text or "").strip()
                if value:
                    referenced.add(value)

    removed = 0
    for image in list(bank.findall("IMAGE")):
        path = (image.findtext("IMAGE_PATH") or "").strip()
        if not path:
            # A bank entry with no path carries no content either; leave the
            # structure alone rather than guess at what Packet Tracer expects.
            continue
        if any(path in value or value in path for value in referenced):
            continue
        bank.remove(image)
        removed += 1
    return removed


def _write_pkt_root(root: ET.Element, pkt_path: Path, xml_path: Path | None = None) -> None:
    # Both repairs guard the file, so they belong at the point every path
    # writes one. Putting them on the donor-prune path alone left `router_dhcp`
    # shipping SW1 FastEthernet0/2 on two cables -- that prompt takes the other
    # route, and the fix never ran for it.
    _repair_invalid_link_ports(root)
    _assign_unique_macs(root)
    _match_link_port_families(root)
    # After the families agree and before the addresses are handed out: a
    # copper cable in a fibre socket is dropped by Packet Tracer on load,
    # silently, in a file that still opens.
    _move_copper_cables_off_fibre_ports(root)
    _assign_unique_interface_addresses(root)
    _assign_unique_switch_management_ips(root)
    _reconcile_cable_media(root)
    # First of the configuration repairs: a block for hardware the device does
    # not have carries the donor's whole address plan into every pass that
    # reads the router's networks.
    _drop_config_for_absent_interfaces(root)
    _trunk_uplinks_in_file(root)
    # Before the access-VLAN pass, which would otherwise strip the tagging:
    # a switch port facing router subinterfaces has to be a trunk. The
    # subinterfaces move to the cabled port first, or there is nothing there
    # for the trunk to carry.
    _move_subinterfaces_to_the_cabled_port(root)
    _trunk_router_on_a_stick(root)
    _align_router_access_vlan(root)
    # After the router's own port is settled: a host whose address belongs to
    # one VLAN and whose port sits in another cannot reach its own subnet.
    _align_host_vlans_to_addresses(root)
    _align_router_gateway(root)
    # Last, because `_align_router_gateway` writes the gateway onto the
    # physical cabled interface -- correct for an access link, wrong for a
    # trunk, where every frame arrives tagged and the address has to sit on
    # the subinterface for its VLAN. Running before it left VLAN 10 with its
    # gateway stranded on `GigabitEthernet0/0` and no host able to reach it,
    # while every other VLAN routed.
    _move_subinterfaces_to_the_cabled_port(root)
    # A learned sticky MAC belongs to the donor's device, not to the one now
    # plugged in, and `restrict` drops every frame that does not match it.
    _drop_inherited_sticky_macs(root)
    # Both ends of every trunk must name the same native VLAN, or spanning
    # tree blocks the port and the cable carries nothing.
    _match_trunk_native_vlans(root)
    # After every trunk is settled: port security on a trunk cuts the switch
    # behind it off entirely.
    _drop_port_security_from_trunks(root)
    # After the trunks are settled: a channel-group naming ports the cable
    # never joined takes the switch behind it off the network.
    _align_etherchannels_with_cabling(root)
    _align_dhcp_pools_with_interfaces(root)
    # After the pools point at real networks: a pool with no client is not
    # DHCP, and the segmented path never emitted the client half.
    # Before the clients are switched over: a VLAN with hosts and no gateway
    # cannot serve any of them.
    # A port with no VLAN sits in VLAN 1, which the plan never gives a
    # gateway, so the host on it is isolated whatever else is right.
    _place_hosts_in_a_vlan(root)
    _serve_every_populated_vlan(root)
    # Again, now that new VLANs exist: the router-facing trunk lists the
    # VLANs it may carry, and it was written before those VLANs were
    # created -- so their hosts had a gateway the trunk would not pass.
    _trunk_router_on_a_stick(root)
    _put_workstations_on_dhcp(root)
    # Snooping without a trusted uplink eats every offer the router sends.
    _trust_uplinks_for_dhcp_snooping(root)
    # Last: the standby gateway takes the address the hosts already use,
    # so nothing written before it has to change.
    _add_hsrp_gateway_redundancy(root)
    # A router with no path to another router carries none of its routes.
    _mesh_routers_with_point_to_point_links(root)
    _group_hosts_under_their_switch(root)
    _separate_overlapping_devices(root)
    # After the separation pass, so a leftover nudged sideways is still pulled in.
    _compact_stray_devices(root)
    _save_running_config_to_startup(root)
    prune_unused_images(root)
    xml_bytes = serialize_pkt_xml(root)
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
            # A multilayer switch is still one of the switches the prompt asked
            # for, so it is numbered in the same series. `3 switch 1 router ve 4
            # komputer qur` is promoted to two switches plus one multilayer
            # switch to fit the donor pool, and the third one used to arrive
            # called `MultiLayerSwitch1`: the prompt asked for `SW3`, the lab
            # shipped without one, and the shortfall check reported a device
            # missing that was standing there under another name.
            name_index = next_index
            if device_type == "MultiLayerSwitch":
                # Counted once, not summed: whether the plain switches were
                # seeded before or after this loop reaches the multilayer one
                # depends on requirement ordering, and adding both counts gave
                # `SW5` for the third switch of three.
                name_index += max(
                    current_counts.get("Switch", 0),
                    plan.device_requirements.get("Switch", 0),
                )
            device: dict[str, object] = {
                "name": _default_name_for_type(device_type, name_index),
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
        _lay_out_switch_blocks(switches, hosts)
    for index, device in enumerate(devices):
        device.setdefault("x", 200 + (index % 5) * 150)
        device.setdefault("y", 180 + (index // 5) * 130)
    return devices


# Layout geometry. Values are Packet Tracer logical-workspace units; a device
# icon is roughly 60 wide, so 130 leaves a comfortable gap.
HOST_COLUMN_STEP = 130
HOST_ROW_STEP = 110
HOSTS_PER_BLOCK_ROW = 5
BLOCK_GAP = 120
BLOCK_ROW_GAP = 200
CORE_ROW_Y = 260
ACCESS_ROW_Y = 460
FIRST_HOST_Y = 600
MAX_BLOCKS_PER_ROW = 6


def _lay_out_switch_blocks(
    switches: list[dict[str, object]], hosts: list[dict[str, object]]
) -> None:
    """Place each access switch directly above the hosts that hang off it.

    Hosts used to be dealt into one global six-wide grid regardless of which
    switch they belonged to. On a 500-host lab that produced a column of devices
    ten thousand units tall, with a host and its switch hundreds of units apart
    -- structurally correct and impossible to read.

    Each access switch now owns a block: the switch on top, its hosts in a
    compact grid underneath, blocks laid left to right and wrapped into rows.
    Related devices stay together and the canvas stays roughly square.
    """
    if not switches:
        for index, host in enumerate(hosts):
            host.setdefault("x", 180 + (index % HOSTS_PER_BLOCK_ROW) * HOST_COLUMN_STEP)
            host.setdefault("y", FIRST_HOST_Y + (index // HOSTS_PER_BLOCK_ROW) * HOST_ROW_STEP)
        return

    core = switches[0]
    access = switches[1:] or switches
    # A lone switch is both core and access, and keeps its hosts beneath it.
    core_is_access = not switches[1:]

    # Deal hosts round-robin across the access switches, matching how the link
    # planner assigns them, so the picture agrees with the wiring.
    buckets: list[list[dict[str, object]]] = [[] for _ in access]
    for index, host in enumerate(hosts):
        buckets[index % len(access)].append(host)

    block_width = (HOSTS_PER_BLOCK_ROW - 1) * HOST_COLUMN_STEP + BLOCK_GAP
    tallest_rows = 0
    for block_index, (switch, block_hosts) in enumerate(zip(access, buckets)):
        column = block_index % MAX_BLOCKS_PER_ROW
        row = block_index // MAX_BLOCKS_PER_ROW
        origin_x = 180 + column * block_width
        rows_before = tallest_rows if row else 0
        origin_y = ACCESS_ROW_Y + row * (BLOCK_ROW_GAP + rows_before * HOST_ROW_STEP)

        switch.setdefault("x", origin_x + (HOSTS_PER_BLOCK_ROW - 1) * HOST_COLUMN_STEP // 2)
        switch.setdefault("y", origin_y)
        for host_index, host in enumerate(block_hosts):
            host.setdefault("x", origin_x + (host_index % HOSTS_PER_BLOCK_ROW) * HOST_COLUMN_STEP)
            host.setdefault("y", origin_y + 140 + (host_index // HOSTS_PER_BLOCK_ROW) * HOST_ROW_STEP)
        tallest_rows = max(tallest_rows, -(-len(block_hosts) // HOSTS_PER_BLOCK_ROW))

    if not core_is_access:
        # Centre the core over the first row of blocks.
        span = min(len(access), MAX_BLOCKS_PER_ROW)
        core.setdefault("x", 180 + (span - 1) * block_width // 2)
        core.setdefault("y", CORE_ROW_Y)


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

    # Every port below is the planner's choice, not the user's. Saying so is
    # what lets the donor's own wiring win later: without it, a donor router on
    # `GigabitEthernet0/0/1` was rejected for disagreeing with the `0/0/0` this
    # function had just picked, which refused ntp, syslog, snmp and aaa.
    for assumption in DEFAULTED_LINK_WIRING_ASSUMPTIONS:
        if assumption not in plan.assumptions_used:
            plan.assumptions_used.append(assumption)

    archetype = _choose_topology_archetype(plan)
    routers = [device for device in devices if _device_kind(device) == "Router"]
    # A multilayer switch is a switch. Counting only plain `Switch` left a
    # requested Layer-3 switch sitting in the lab wired to nothing at all --
    # `1 multilayer switch 3 switch 1 router ve 6 komputer qur` produced a
    # MultiLayerSwitch with no cable on it. It also belongs at the top of the
    # tree: that is what anyone asks a Layer-3 switch for, and it gives a large
    # lab the core/access split it should have instead of one model everywhere.
    switches = [
        device
        for device in devices
        if _device_kind(device) in {"Switch", "MultiLayerSwitch"}
    ]
    switches.sort(key=lambda device: _device_kind(device) != "MultiLayerSwitch")
    hosts = [device for device in devices if _is_host_device(device)]
    if not switches:
        # A home-router lab has no switch, and returning nothing here left both
        # `wireless_home` and `wireless_ssid` as devices with no path between
        # them: two laptops on 1.1.10.20 and .21, a router on 192.168.0.1, 0/4
        # twice over while the labs opened and every static check passed.
        #
        # The laptops are wired on purpose: a Laptop-PT arrives with a copper
        # port and no wireless card, so the cable is the only path it has.
        # Tablets and phones are skipped -- they associate instead.
        routers_wireless = [
            device for device in devices if _device_kind(device) in WIRELESS_ROUTER_KINDS
        ]
        if not routers_wireless:
            return []
        access_point = routers_wireless[0]
        wired_hosts = [device for device in hosts if not _is_wireless_client_device(device)]
        return [
            {
                "a": {"dev": device["name"], "port": _host_port(device)},
                "b": {"dev": access_point["name"], "port": _wireless_router_lan_port(index)},
                "media": "straight-through",
            }
            for index, device in enumerate(wired_hosts, start=1)
        ]

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
    # Reverted: putting hosts on the core switch as well as the access switch
    # looked like better use of a two-switch topology, but it made
    # `two_switch_chain` -- which opened before -- stop opening. Whatever Packet
    # Tracer objects to, a hostless core is the arrangement that works.
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
                    # Switch to switch is a crossover run; host and router links
                    # stay straight-through. Every cable in a generated lab used
                    # to be straight-through, which is not how any of these labs
                    # would be built and gave a 22-switch topology 62 identical
                    # cables. Verified in Packet Tracer: the crossover link comes
                    # up, and a control run confirmed the connectivity failure
                    # that showed up alongside it was never the cable's doing.
                    "media": "crossover",
                }
            )

    # Uplinks are wired above and can land on a low access port when the switch
    # model has no gigabit interfaces. Host allocation used to start at
    # FastEthernet0/1 regardless, so the first host collided with the uplink;
    # reconciliation then moved that host onto the *next* port, which the second
    # host already held. A 22-switch lab came out with nineteen interfaces
    # carrying two cables each. Skipping what is already wired avoids creating
    # the collision in the first place.
    occupied: dict[str, set[str]] = {}
    for link in links:
        for end in ("a", "b"):
            occupied.setdefault(str(link[end]["dev"]), set()).add(str(link[end]["port"]))

    host_port_index: dict[str, int] = {str(device["name"]): 1 for device in access_switches}
    for index, host in enumerate(hosts):
        target_switch = access_switches[index % len(access_switches)]
        switch_name = str(target_switch["name"])
        taken = occupied.setdefault(switch_name, set())
        port = _switch_access_port(host_port_index[switch_name])
        while port in taken and host_port_index[switch_name] <= MAX_SWITCH_ACCESS_PORT:
            host_port_index[switch_name] += 1
            port = _switch_access_port(host_port_index[switch_name])
        host_port_index[switch_name] += 1
        taken.add(port)
        links.append(
            {
                "a": {"dev": host["name"], "port": _host_port(host)},
                "b": {"dev": switch_name, "port": port},
                "media": "straight-through",
            }
        )
    _add_wan_link(plan, routers, links)
    return links


def _note_model_substitutions(plan: IntentPlan, devices: list[dict[str, object]]) -> None:
    """Say so when the lab uses a different device model than was asked for.

    A generated lab takes its device models from whichever donor supplied the
    prototype, and the local donors carry `PT8200` and `ISR4331` routers. Asking
    for a 2911 -- the model most CCNA material uses -- quietly produced a
    PT8200, which reads as the request having been honoured.
    """
    requested = [str(model) for model in getattr(plan, "requested_models", []) if model]
    if not requested:
        return
    supplied = {str(device.get("model") or "") for device in devices if device.get("model")}
    unmet = [
        model
        for model in requested
        if not any(model.upper() in given.upper() or given.upper() in model.upper() for given in supplied)
    ]
    if not unmet:
        return
    note = (
        f"Requested model(s) {', '.join(unmet)} were not available; used "
        f"{', '.join(sorted(supplied)) or 'the donor default'} instead. "
        "Device models come from the donor lab that supplied the prototype."
    )
    if note not in plan.assumptions_used:
        plan.assumptions_used.append(note)


def _synthesize_service_ops(plan: IntentPlan, devices: list[dict[str, object]]) -> None:
    """Emit the service operations that do not depend on VLANs.

    Every one of these already had a working implementation in `pkt_editor`;
    nothing here teaches it a new trick. They were simply never emitted, because
    the only place that built them was `_synthesize_vlan_and_link_ops`, which
    returns immediately when the prompt names no VLAN. So "dhcp routerden
    verilsin" produced a lab with no DHCP pool at all -- and it still opened, so
    nothing complained.

    The editor's vocabulary and the planner's emission were two models of what
    the skill can do, and only one of them was consulted when reporting.
    """
    routers = [device for device in devices if _device_kind(device) == "Router"]
    switches = [device for device in devices if _device_kind(device) == "Switch"]
    hosts = [device for device in devices if _fallback_group_member_type(_device_kind(device))]
    servers = [device for device in devices if _device_kind(device) == "Server"]
    capabilities = set(plan.capabilities)
    services = {str(item).lower() for item in (plan.service_requirements or {}).get("services", [])}

    # Router DHCP on a flat network. The VLAN path already covers the segmented
    # case, one pool per VLAN, so only fill the gap it leaves.
    if (
        routers
        and not plan.vlan_ids
        and plan.topology_requirements.get("needs_dhcp_pool")
        and not any(op.get("op") == "set_server_dhcp_pool" for op in plan.server_ops)
    ):
        _append_unique_op(
            plan.router_ops,
            {
                "op": "set_router_dhcp_pool",
                "device": routers[0]["name"],
                "name": "LAN",
                "network": "192.168.1.0",
                "prefix": 24,
                "gateway": "192.168.1.1",
                "dns": None,
                "start": "192.168.1.100",
                "max_users": 100,
            },
        )
        # A pool nothing asks for is not really DHCP, so put the hosts on it --
        # but only when end-device configuration is permitted. See
        # `_host_config_enabled` for what that block is worth.
        if _host_config_enabled():
            for host in hosts:
                _append_unique_op(plan.end_device_ops, {"op": "set_host_dhcp", "device": host["name"]})

    # Management VLAN and telnet, on every switch that will exist.
    management_vlan = _management_vlan_id(plan)
    if management_vlan is not None:
        for index, switch in enumerate(switches, start=1):
            _append_unique_op(
                plan.management_ops,
                {
                    "op": "set_management_vlan",
                    "device": switch["name"],
                    "vlan": management_vlan,
                    "ip": f"192.168.{management_vlan % 256}.{index + 1}",
                    "prefix": 24,
                    "gateway": f"192.168.{management_vlan % 256}.1",
                    "username": "admin",
                    "password": "cisco",
                },
            )

    if "telnet" in capabilities:
        for device in switches + routers:
            _append_unique_op(
                plan.management_ops,
                {
                    "op": "enable_telnet",
                    "device": device["name"],
                    "username": "admin",
                    "password": "cisco",
                },
            )

    # Server services. `enable_server_service` toggles the service in the
    # server's engine, which is what Packet Tracer reads -- config text alone
    # would not turn it on.
    if servers:
        server_name = servers[0]["name"]
        # `_set_enabled_service` knows dns, http, https, ftp, tftp, ntp, syslog,
        # aaa and email. Covering only the first five left a prompt asking for a
        # syslog or RADIUS server with a plain server and no service on it.
        for service in ("dns", "http", "https", "ftp", "tftp", "ntp", "syslog", "aaa", "email"):
            if service in services or f"server_{service}" in capabilities:
                _append_unique_op(
                    plan.server_ops,
                    {
                        "op": "enable_server_service",
                        "device": server_name,
                        "service": service,
                        "domain": "local",
                    },
                )
        if "aaa" in services or "server_aaa" in capabilities or "radius" in services:
            _append_unique_op(
                plan.server_ops,
                {"op": "set_server_aaa_auth_port", "device": server_name, "auth_port": 1645},
            )
        if "dns" in services or "server_dns" in capabilities:
            _append_unique_op(
                plan.server_ops,
                {
                    "op": "set_server_dns_record",
                    "device": server_name,
                    "record_type": "A",
                    "name": "www.local",
                    "value": "192.168.1.10",
                },
            )


WIRELESS_AP_KINDS = {"WirelessRouter", "LightWeightAccessPoint", "AccessPoint"}
WIRELESS_CLIENT_KINDS = {"Laptop", "Tablet", "Smartphone"}


def _synthesize_wireless_ops(plan: IntentPlan, devices: list[dict[str, object]]) -> None:
    """Name the network and put the wireless clients on it.

    `pkt_editor` has implemented `set_wireless_ssid` and
    `associate_wireless_client` all along, and `_extract_wireless_ops` reads
    them from the command form `set AP1 ssid TEST security wpa2-psk ...`. Nobody
    writes prompts that way, so an ordinary "ssid EvSebeke wpa2 sifre ..."
    produced a wireless lab with the donor's network name still on it.
    """
    settings = dict(plan.wireless_settings or {})
    access_points = [d for d in devices if _device_kind(d) in WIRELESS_AP_KINDS]
    if not access_points:
        return
    # With no SSID named there is nothing to apply: the donor's own network is
    # left alone rather than replaced with a guess.
    ssid = str(settings.get("ssid") or "").strip()
    if not ssid:
        return

    security = str(settings.get("security") or ("wpa2-psk" if settings.get("passphrase") else "open"))
    auth_type, encrypt_type = SECURITY_TO_AUTH.get(security, ("0", "0"))
    channel = int(settings.get("channel") or 1)

    for access_point in access_points:
        _append_unique_op(
            plan.wireless_ops,
            {
                "op": "set_wireless_ssid",
                "device": access_point["name"],
                "ssid": ssid,
                "security": security,
                "auth_type": auth_type,
                "encrypt_type": encrypt_type,
                "passphrase": str(settings.get("passphrase") or ""),
                "channel": channel,
            },
        )

    primary = str(access_points[0]["name"])
    for client in devices:
        if _device_kind(client) in WIRELESS_CLIENT_KINDS:
            _append_unique_op(
                plan.wireless_ops,
                {
                    "op": "associate_wireless_client",
                    "device": client["name"],
                    "ap": primary,
                    "ssid": ssid,
                    "ip_mode": "dhcp",
                },
            )


def _synthesize_routing_ops(plan: IntentPlan, devices: list[dict[str, object]]) -> None:
    """Emit the routing protocol the prompt asked for.

    `pkt_editor` has implemented `set_ospfv2_network`, `set_eigrp_ipv4_network`,
    `set_ripv2_network` and `set_static_route` all along, and the parser has
    recognised the words. Nothing joined them up, so "ospf olsun" produced a lab
    with no routing at all -- the same gap that hid behind DHCP and telnet.

    Networks come from the subnets the VLAN plan already uses, so the advertised
    routes match the addresses actually configured.
    """
    routers = [device for device in devices if _device_kind(device) == "Router"]
    if not routers:
        return
    protocol = str((plan.topology_requirements or {}).get("routing_protocol") or "")
    capabilities = set(plan.capabilities)
    if not protocol:
        protocol = next((name for name in ("ospf", "eigrp", "rip") if name in capabilities), "")

    # `192.168.<vlan>.0/24` is what `_synthesize_vlan_and_link_ops` addresses the
    # subinterfaces with; a flat network uses 192.168.1.0/24.
    networks = [f"192.168.{vlan}.0" for vlan in plan.vlan_ids] or ["192.168.1.0"]

    for router in routers:
        name = router["name"]
        if protocol == "ospf":
            # A multi-area request puts the first network in the backbone and
            # spreads the rest across areas 1..n, which is what "multi area
            # ospf" means; a single-area lab keeps everything in area 0.
            multiarea = "ospf_multiarea" in capabilities
            for area_index, network in enumerate(networks):
                _append_unique_op(
                    plan.router_ops,
                    {
                        "op": "set_ospfv2_network",
                        "device": name,
                        "process_id": 1,
                        "network": network,
                        "wildcard": "0.0.0.255",
                        "area": area_index if multiarea else 0,
                    },
                )
        elif protocol == "eigrp":
            for network in networks:
                _append_unique_op(
                    plan.router_ops,
                    {
                        "op": "set_eigrp_ipv4_network",
                        "device": name,
                        "asn": 100,
                        "network": network,
                        "wildcard": "0.0.0.255",
                    },
                )
        elif protocol == "rip":
            for network in networks:
                _append_unique_op(
                    plan.router_ops,
                    {"op": "set_ripv2_network", "device": name, "network": network},
                )

    # A default route out of the first router covers "default route" and
    # "static routing" requests without inventing a WAN that is not there.
    if "static_route" in capabilities or "default_route" in capabilities:
        _append_unique_op(
            plan.router_ops,
            {
                "op": "set_static_route",
                "device": routers[0]["name"],
                "network": "0.0.0.0",
                "prefix": 0,
                "next_hop": "192.168.1.254",
                "interface": "",
                "helper": "",
            },
        )


def _synthesize_security_ops(plan: IntentPlan, devices: list[dict[str, object]]) -> None:
    """Emit ACLs, NAT and the layer-2 hardening the prompt asked for.

    Every one of these already exists in `pkt_editor` -- `set_acl`,
    `add_acl_rule`, `apply_acl`, `set_pat_overload`, `set_stp`,
    `set_etherchannel`, `set_port_security`. The parser recognises the words.
    Nothing joined them, so "nat olsun" produced a lab with no NAT, the same gap
    that hid behind DHCP, telnet, wireless and routing.
    """
    routers = [device for device in devices if _device_kind(device) == "Router"]
    switches = [device for device in devices if _device_kind(device) == "Switch"]
    capabilities = set(plan.capabilities)
    lan = f"192.168.{plan.vlan_ids[0]}.0" if plan.vlan_ids else "192.168.1.0"

    if routers and {"acl", "acl_standard", "acl_extended"} & capabilities:
        router = routers[0]
        _append_unique_op(
            plan.router_ops,
            {"op": "set_acl", "device": router["name"], "acl_kind": "standard", "acl_name": "LAN-ACCESS"},
        )
        _append_unique_op(
            plan.router_ops,
            {
                "op": "add_acl_rule",
                "device": router["name"],
                "acl_name": "LAN-ACCESS",
                "acl_kind": "standard",
                "action": "permit",
                "source": f"{lan} 0.0.0.255",
                "destination": "any",
            },
        )

    # NAT and PAT both mean "let this LAN reach the outside" in a lab prompt.
    if routers and {"nat", "pat", "nat_dynamic", "nat_static"} & capabilities:
        router = routers[0]
        outside = _router_port(router, 1)
        _append_unique_op(
            plan.router_ops,
            {"op": "set_acl", "device": router["name"], "acl_kind": "standard", "acl_name": "NAT-POOL"},
        )
        _append_unique_op(
            plan.router_ops,
            {
                "op": "add_acl_rule",
                "device": router["name"],
                "acl_name": "NAT-POOL",
                "acl_kind": "standard",
                "action": "permit",
                "source": f"{lan} 0.0.0.255",
                "destination": "any",
            },
        )
        _append_unique_op(
            plan.router_ops,
            {
                "op": "set_pat_overload",
                "device": router["name"],
                "acl": "NAT-POOL",
                "interface": outside,
                "overload": True,
                "modulus": "",
                "domain": "",
                "username": "",
                "password": "",
            },
        )

    if switches and {"stp", "rstp", "pvst"} & capabilities:
        # Rapid PVST+ is what a modern campus runs, and the core is the root.
        for index, switch in enumerate(switches):
            _append_unique_op(
                plan.switch_ops,
                {
                    "op": "set_stp",
                    "device": switch["name"],
                    "mode": "rapid-pvst",
                    "vlan": plan.vlan_ids[0] if plan.vlan_ids else 1,
                    "root": index == 0,
                    "channel": 0,
                },
            )

    # These interface names are a guess -- no cable exists yet, so nothing here
    # can know which ports face the core or whether the peer bundles too. The
    # guess is deliberate and it is not the final word: it records the intent to
    # bundle, and `_align_etherchannels_with_cabling` decides against the real
    # cabling, keeping the members of a genuine two-cable bundle and removing
    # the rest. Left on its own the guess cost SW2 its uplink.
    if switches and {"etherchannel", "lacp", "pagp"} & capabilities and len(switches) >= 2:
        mode = "active" if "lacp" in capabilities else ("desirable" if "pagp" in capabilities else "on")
        for switch in switches[:2]:
            _append_unique_op(
                plan.switch_ops,
                {
                    "op": "set_etherchannel",
                    "device": switch["name"],
                    "channel": 1,
                    "mode": mode,
                    "interfaces": ["GigabitEthernet0/1", "GigabitEthernet0/2"],
                    "domain": "",
                    "version": "",
                },
            )

    # DHCP snooping protects the access layer from a rogue server; the uplink
    # to the core is the trusted port, because that is where the real one lives.
    if switches and capabilities & {"dhcp_snooping", "dai"}:
        for switch in switches:
            operation = {
                "op": "set_dai" if "dai" in capabilities else "set_dhcp_snooping",
                "device": switch["name"],
                "vlan": plan.vlan_ids[0] if plan.vlan_ids else 1,
                "trust_port": "GigabitEthernet0/1",
            }
            _append_unique_op(plan.switch_ops, operation)

    if switches and "port_security" in capabilities:
        for switch in switches:
            _append_unique_op(
                plan.switch_ops,
                {
                    "op": "set_port_security",
                    "device": switch["name"],
                    "port": "FastEthernet0/1",
                    "maximum": 2,
                    "violation": "restrict",
                },
            )


def _synthesize_resilience_ops(plan: IntentPlan, devices: list[dict[str, object]]) -> None:
    """Emit first-hop redundancy and the IPv6 side of a dual-stack lab.

    `set_hsrp_ipv6`, `enable_ipv6_unicast_routing`, `set_ipv6_address`,
    `set_ipv6_slaac` and `set_ospfv3_interface` all exist in `pkt_editor`. Only
    the joining was missing -- and `ipv6` on its own was not even a capability,
    so "ipv6 olsun" reached the planner with nothing attached to it.
    """
    routers = [device for device in devices if _device_kind(device) == "Router"]
    if not routers:
        return
    capabilities = set(plan.capabilities)

    # HSRP needs two routers to be worth anything: one active, one standby.
    if "hsrp" in capabilities and len(routers) >= 2:
        for index, router in enumerate(routers[:2]):
            _append_unique_op(
                plan.router_ops,
                {
                    "op": "set_hsrp_ipv6",
                    "device": router["name"],
                    "interface": _router_port(router, 1),
                    "group": 1,
                    # Both routers share one virtual address -- that is the
                    # whole point of a standby group.
                    "virtual_ipv6": "2001:db8:1::254",
                    # The first router wins the election; the second stands by.
                    "priority": 110 if index == 0 else 90,
                },
            )

    wants_ipv6 = capabilities & {"ipv6", "ipv6_slaac", "ospfv3", "dhcpv6_stateful", "dhcpv6_stateless"}
    if not wants_ipv6:
        return

    for index, router in enumerate(routers):
        interface = _router_port(router, 1)
        _append_unique_op(
            plan.router_ops,
            {
                "op": "enable_ipv6_unicast_routing",
                "device": router["name"],
                "interface": interface,
                "address": f"2001:db8:{index + 1}::1",
                "prefix": 64,
            },
        )
        _append_unique_op(
            plan.router_ops,
            {
                "op": "set_ipv6_address",
                "device": router["name"],
                "interface": interface,
                "address": f"2001:db8:{index + 1}::1",
                "prefix": 64,
            },
        )
        if "ipv6_slaac" in capabilities:
            _append_unique_op(
                plan.router_ops,
                {
                    "op": "set_ipv6_slaac",
                    "device": router["name"],
                    "interface": interface,
                    "prefix": f"2001:db8:{index + 1}::",
                    "prefix_len": 64,
                },
            )
        if "ospfv3" in capabilities:
            _append_unique_op(
                plan.router_ops,
                {
                    "op": "set_ospfv3_interface",
                    "device": router["name"],
                    "interface": interface,
                    "process_id": 1,
                    "asn": 1,
                    "area": 0,
                },
            )


ANNOTATION_BLOCK_COLORS = ("blue", "green", "purple", "orange", "red", "grey")


def _annotations_enabled() -> bool:
    """`PACKET_TRACER_ANNOTATE=0` turns the drawing off."""
    raw = (os.getenv("PACKET_TRACER_ANNOTATE") or "").strip().lower()
    return raw not in {"0", "off", "false", "no"}


def _annotate_generated_lab(
    root: ET.Element, blueprint: dict[str, object], plan: IntentPlan
) -> None:
    """Frame and label each switch block, and title the lab.

    A wide topology is hard to read even when the geometry is tidy: twenty-five
    switches look alike and nothing says which VLAN or department a block
    serves. Packet Tracer has had rectangles, ellipses, lines and notes all
    along -- the formats are measured from Cisco's own labs in `pkt_annotate` --
    and none of it was reachable from here.

    Inherited annotations are cleared first. The donor's frames were drawn for
    the donor's layout, so keeping them would box the wrong devices.
    """
    if not _annotations_enabled():
        return
    try:
        from pkt_annotate import add_note, add_rectangle, clear_annotations
    except ImportError:  # pragma: no cover - drawing is optional
        return

    try:
        _draw_lab_annotations(root, blueprint, plan, add_note, add_rectangle, clear_annotations)
    except Exception:  # noqa: BLE001
        # A wireless lab with no switches once divided by zero here and took the
        # whole generation down with it. Decoration is never worth a refusal.
        return


def _draw_lab_annotations(root, blueprint, plan, add_note, add_rectangle, clear_annotations) -> None:
    clear_annotations(root)

    # Both the positions and the membership are read from the assembled file,
    # not from the blueprint. The blueprint's coordinates are what was planned,
    # and later passes move devices -- overlap separation among them -- so a box
    # drawn from them frames where things were going to be. Membership was
    # worse: hosts were dealt to switches round-robin, on the assumption that
    # the layout had put each host under its own switch. Measured on
    # `four_switch`, one box held SW2 and MultiLayerSwitch1 with hosts belonging
    # to SW1 and SW2, and the other held hosts from all three switches.
    #
    # The cables say who belongs to whom, and the device nodes say where they
    # are. Both are in the file.
    placed: dict[str, tuple[float, float]] = {}
    kinds: dict[str, str] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = (device.findtext("./ENGINE/NAME") or "").strip()
        if not name:
            continue
        try:
            x = float((device.findtext("./WORKSPACE/LOGICAL/X") or "").strip())
            y = float((device.findtext("./WORKSPACE/LOGICAL/Y") or "").strip())
        except ValueError:
            continue
        if x >= PARKED_LOGICAL_X:
            continue
        placed[name] = (x, y)
        kinds[name] = (device.findtext("./ENGINE/TYPE") or "").strip()
    if not placed:
        return

    host_kinds = {"PC", "Pc", "PcPT", "Server", "ServerPT", "Printer", "Laptop", "IpPhone", "HomeVoip"}
    switch_kinds = {"Switch", "MultiLayerSwitch"}
    blocks: dict[str, list[str]] = {
        name: [] for name, kind in kinds.items() if kind in switch_kinds
    }
    for left, right in _link_device_pairs(root):
        for host, switch in ((left, right), (right, left)):
            if kinds.get(host) in host_kinds and switch in blocks:
                blocks[switch].append(host)
                break

    # A switch with nothing on it is not a block worth framing, and a home or
    # wireless lab has no switch at all -- dividing by that emptiness once
    # crashed generation outright, and annotation is decoration that must never
    # be what stops a lab being produced.
    blocks = {name: members for name, members in blocks.items() if members}

    vlan_ids = list(plan.vlan_ids)
    for index, (switch_name, members) in enumerate(blocks.items()):
        points = [placed[name] for name in [switch_name, *members] if name in placed]
        if len(points) < 2:
            continue
        margin = 45
        left = min(x for x, _ in points) - margin
        right = max(x for x, _ in points) + margin
        top = min(y for _, y in points) - margin - 25
        bottom = max(y for _, y in points) + margin
        colour = ANNOTATION_BLOCK_COLORS[index % len(ANNOTATION_BLOCK_COLORS)]
        add_rectangle(root, (left, top), (right, bottom), color=colour)
        label = switch_name
        if vlan_ids:
            label = f"{switch_name} - VLAN {vlan_ids[index % len(vlan_ids)]}"
        add_note(root, (left + 12, top + 6), label)

    # A title, placed above everything, saying what the lab is.
    summary = ", ".join(
        f"{count} {kind}" for kind, count in sorted(plan.device_requirements.items()) if count
    )
    top_y = min(y for _, y in placed.values())
    add_note(root, (150, max(20, top_y - 120)), f"{summary}\nGenerated by packet-tracer-skill")


def _synthesize_voice_ops(plan: IntentPlan, devices: list[dict[str, object]]) -> None:
    """Stand up Call Manager Express and give each phone an extension.

    `set_telephony_service`, `set_ephone_dn` and `set_ephone` all exist in
    `pkt_editor`. A telephony service with no directory numbers rings nowhere,
    so the three are emitted together or not at all.
    """
    routers = [device for device in devices if _device_kind(device) == "Router"]
    phones = [device for device in devices if _device_kind(device) in {"IpPhone", "IPPhone"}]
    capabilities = set(plan.capabilities)
    if not routers or not (capabilities & {"voip", "ip_phone", "call_manager"}):
        return

    router = routers[0]
    voice_vlan = 150
    _append_unique_op(
        plan.router_ops,
        {
            "op": "set_telephony_service",
            "device": router["name"],
            "max_ephones": max(len(phones), 4),
            "max_dn": max(len(phones), 4),
            "source_address": f"192.168.{voice_vlan % 256}.1",
            "port": 2000,
        },
    )
    # Extensions start at 1001, the convention every CCNA lab uses. A phone is
    # identified by MAC, so each gets a deterministic one derived from its index
    # rather than a random value that would change on every regeneration.
    for index, phone in enumerate(phones or [{"name": "IPPhone1"}]):
        mac = f"0001.0002.{index + 1:04X}"
        _append_unique_op(
            plan.router_ops,
            {
                "op": "set_ephone_dn",
                "device": router["name"],
                "dn_id": index + 1,
                "number": 1001 + index,
                "ephone_id": index + 1,
                "mac": mac,
                "button": 1,
            },
        )
        _append_unique_op(
            plan.router_ops,
            {
                "op": "set_ephone",
                "device": router["name"],
                "ephone_id": index + 1,
                "mac": mac,
                "button": 1,
            },
        )


def _synthesize_wan_ops(plan: IntentPlan, devices: list[dict[str, object]]) -> None:
    """Configure the serial and tunnel side of a two-site lab.

    `set_ppp_interface`, `set_gre_tunnel`, `set_ipsec_transform_set` and
    `set_crypto_map` all exist in `pkt_editor`. As with everything else here,
    the parser knew the words and nothing built the operations.

    All of these need two routers -- a PPP link, a tunnel or an IPsec peer with
    only one end is not a WAN.
    """
    routers = [device for device in devices if _device_kind(device) == "Router"]
    if len(routers) < 2:
        return
    capabilities = set(plan.capabilities)
    left, right = routers[0], routers[1]

    if "ppp" in capabilities:
        # CHAP unless the prompt says otherwise; PAP in a lab is a teaching
        # choice rather than a default.
        auth = "pap" if "pap" in plan.prompt.lower() else "chap"
        for router in (left, right):
            _append_unique_op(
                plan.router_ops,
                {
                    "op": "set_ppp_interface",
                    "device": router["name"],
                    "interface": "Serial0/0/0",
                    "authentication": auth,
                },
            )

    if capabilities & {"gre", "ipv6_tunneling"}:
        for index, (router, peer) in enumerate(((left, right), (right, left))):
            _append_unique_op(
                plan.router_ops,
                {
                    "op": "set_gre_tunnel",
                    "device": router["name"],
                    # The tunnel is its own interface; `source` is the physical
                    # one it rides on.
                    "interface": "Tunnel0",
                    "source": "Serial0/0/0",
                    "destination": f"10.0.0.{2 if index == 0 else 1}",
                    "ip": f"172.16.0.{index + 1}",
                    "prefix": 30,
                },
            )

    if capabilities & {"ipsec", "vpn"} and "gre" not in capabilities:
        for router in (left, right):
            _append_unique_op(
                plan.router_ops,
                {
                    "op": "set_ipsec_transform_set",
                    "device": router["name"],
                    "name": "VPN-SET",
                    "encryption": "esp-aes",
                    "integrity": "esp-sha-hmac",
                },
            )
        for index, (router, peer) in enumerate(((left, right), (right, left))):
            _append_unique_op(
                plan.router_ops,
                {
                    "op": "set_crypto_map",
                    "device": router["name"],
                    "map_name": "VPN-MAP",
                    "sequence": 10,
                    "peer": f"10.0.0.{2 if index == 0 else 1}",
                    "transform_set": "VPN-SET",
                    "acl_name": "VPN-TRAFFIC",
                },
            )


def _donor_service_segment(
    donor_root, preferred_router_ports: set[str] | None = None
) -> tuple[int, str, str] | None:
    """The VLAN a donor actually routes, taken from its live switch SVI.

    Returns (vlan id, /24 prefix, svi address), or None if no switch carries a
    routed VLAN interface.
    """
    import re

    for device in donor_root.findall(".//DEVICES/DEVICE"):
        for tag in ("RUNNINGCONFIG", "STARTUPCONFIG"):
            config = device.find(f"./ENGINE/{tag}")
            if config is None:
                continue
            lines = [(line.text or "") for line in config.findall("LINE")]
            for index, line in enumerate(lines):
                match = re.match(r"interface Vlan(\d+)\s*$", line.strip())
                if not match:
                    continue
                body: list[str] = []
                cursor = index + 1
                while cursor < len(lines) and lines[cursor].startswith(" "):
                    body.append(lines[cursor].strip())
                    cursor += 1
                if any(item == "shutdown" for item in body):
                    continue
                for item in body:
                    address = re.match(r"ip address (\d+\.\d+\.\d+\.\d+) ", item)
                    if address:
                        ip = address.group(1)
                        return int(match.group(1)), ip.rsplit(".", 1)[0], ip

    # No routed VLAN interface. An industrial donor has none, and returning
    # nothing here left every host holding the address its prototype was cloned
    # with -- three PCs all at 192.168.1.20, unable to reach anything. A router
    # interface that carries an address is a gateway just the same; it simply
    # names no VLAN, so no access-port change follows from it.
    #
    # Which interface matters. Taking the first addressed one put hosts in
    # 192.168.1.0/24 behind GigabitEthernet0/0/0 while the cable to their switch
    # ran from GigabitEthernet0/0/2, which carries 192.168.3.1. The gateway was
    # a real address on a real router and simply not reachable. When the caller
    # knows which router ports are cabled to a switch, only those count.
    candidates: list[tuple[bool, str]] = []
    for device in donor_root.findall(".//DEVICES/DEVICE"):
        for tag in ("RUNNINGCONFIG", "STARTUPCONFIG"):
            config = device.find(f"./ENGINE/{tag}")
            if config is None:
                continue
            lines = [(line.text or "") for line in config.findall("LINE")]
            for index, line in enumerate(lines):
                match = re.match(r"interface ((?:Gigabit|Fast)Ethernet\S*)\s*$", line.strip())
                if not match:
                    continue
                cursor = index + 1
                while cursor < len(lines) and lines[cursor].startswith(" "):
                    item = lines[cursor].strip()
                    address = re.match(r"ip address (\d+\.\d+\.\d+\.\d+) ", item)
                    if address:
                        connected = bool(
                            preferred_router_ports and match.group(1) in preferred_router_ports
                        )
                        candidates.append((connected, address.group(1)))
                        break
                    cursor += 1
            if candidates:
                break
    if not candidates:
        return None
    # A cabled interface wins; otherwise fall back to whatever carries an
    # address, which is still better than leaving hosts on the donor's own.
    if preferred_router_ports and not any(connected for connected, _ in candidates):
        return None
    ip = next(ip for connected, ip in candidates if connected or not preferred_router_ports)
    return None, ip.rsplit(".", 1)[0], ip


def _trunk_switch_uplinks(
    plan: IntentPlan, devices: list[dict[str, object]], links: list[dict[str, object]]
) -> None:
    """Make every switch-to-switch link a trunk.

    Uplinks were left as access ports, carrying whatever VLAN the donor's port
    happened to be in. In a 22-switch lab that meant `SW2:Fa0/1 <-> SW1:Fa0/1`
    both sat on `access vlan 5` while `SW1:Fa0/24 <-> SW4:Gi0/1` sat on the
    default, so a VLAN 1 host on SW2 had no way off its own switch. Hosts on one
    switch could reach each other and nothing beyond it.

    A trunk carries every VLAN and removes the whole class of problem, which is
    also what anyone building this by hand would do.
    """
    kinds = {str(device["name"]): _device_kind(device) for device in devices}
    switch_kinds = {"Switch", "MultiLayerSwitch"}
    for link in links:
        left, right = link["a"], link["b"]
        if kinds.get(str(left["dev"])) not in switch_kinds:
            continue
        if kinds.get(str(right["dev"])) not in switch_kinds:
            continue
        for end in (left, right):
            _append_unique_op(
                plan.switch_ops,
                {
                    "op": "set_trunk_port",
                    "device": str(end["dev"]),
                    "port": str(end["port"]),
                    "allowed": ["all"],
                },
            )


def _host_and_switch_ends(
    link: dict[str, object], host_names: set[str], devices: list[dict[str, object]]
) -> tuple[dict[str, object], dict[str, object]] | None:
    """Split a link into its host end and its switch end, whichever way round.

    Link endpoints are not stored host-first. Code that read only the `a` side
    silently skipped every reversed link, which is how two hosts on one switch
    ended up in different VLANs.
    """
    for host_key, switch_key in (("a", "b"), ("b", "a")):
        host_end = link[host_key]
        switch_end = link[switch_key]
        if str(host_end["dev"]) not in host_names:
            continue
        switch = next(
            (device for device in devices if str(device["name"]) == str(switch_end["dev"])),
            None,
        )
        if switch is not None and _device_kind(switch) == "Switch":
            return host_end, switch_end
    return None


def _address_hosts_per_vlan(
    plan: IntentPlan, devices: list[dict[str, object]], links: list[dict[str, object]]
) -> None:
    """Give each VLAN's hosts an address inside that VLAN's subnet.

    A segmented lab emitted VLANs and access ports but no addressing at all, so
    its hosts kept whatever the donor's hosts had: two of four PCs held the same
    192.168.20.10, on ports the generator had just moved to VLAN 10. The subnet
    follows the same 192.168.<vlan>.0/24 convention the DHCP pools already use,
    so a host and its gateway agree by construction.
    """
    if bool(plan.topology_requirements.get("needs_dhcp_pool")) or any(
        op.get("op") in {"set_router_dhcp_pool", "set_server_dhcp_pool"}
        for op in list(plan.router_ops) + list(plan.server_ops)
    ):
        return

    host_names = {
        str(device["name"]) for device in devices if _is_host_device(device)
    }
    port_to_host: dict[tuple[str, str], str] = {}
    for link in links:
        ends = _host_and_switch_ends(link, host_names, devices)
        if ends is None:
            continue
        host_end, switch_end = ends
        port_to_host[(str(switch_end["dev"]), str(switch_end["port"]))] = str(host_end["dev"])

    used: dict[int, int] = {}
    for operation in plan.switch_ops:
        if operation.get("op") != "set_access_port":
            continue
        host = port_to_host.get((str(operation["device"]), str(operation["port"])))
        if host is None:
            continue
        vlan_id = int(operation["vlan"])
        if not 1 <= vlan_id <= 254:
            continue
        offset = used.get(vlan_id, 10)
        used[vlan_id] = offset + 1
        _append_unique_op(
            plan.end_device_ops,
            {
                "op": "set_host_ip",
                "device": host,
                "ip": f"192.168.{vlan_id}.{offset}",
                "mask": "255.255.255.0",
                "gw": f"192.168.{vlan_id}.1",
                "ip_mode": "static",
            },
        )


def _unify_host_segment(
    plan: IntentPlan,
    devices: list[dict[str, object]],
    links: list[dict[str, object]],
    donor_root=None,
) -> None:
    """Put every host in one working segment: same VLAN, same subnet.

    Measured against a live Packet Tracer, a generated lab reported "healthy" --
    no down links, no duplicate IPs -- while no host could reach any other. Two
    separate defects, each invisible in the file:

    * hosts were left as DHCP clients at 0.0.0.0 with no server to answer them;
    * the switch inherited the donor's six VLANs, so the three PCs landed in
      VLAN 11, 11 and 20 and were silently partitioned.

    Two earlier attempts failed because addressing and VLAN were derived
    independently and disagreed -- addresses in 192.168.1.0/24 behind an SVI
    that only routes 192.168.20.0/24. Both now come from the same place: the one
    VLAN interface the donor has up. Confirmed live, PC1 -> 192.168.20.100.

    A prompt that asked for its own VLANs keeps that layout; its hosts are
    addressed per VLAN instead, which is the same principle applied per segment.
    """
    # Trunks are needed whichever way the hosts are addressed, so this runs
    # before the segmented path takes its own route out.
    _trunk_switch_uplinks(plan, devices, links)

    if plan.host_vlan_assignment or plan.department_groups or plan.vlan_ids:
        _address_hosts_per_vlan(plan, devices, links)
        return
    hosts = [device for device in devices if _is_host_device(device)]
    if not hosts or donor_root is None:
        return
    if bool(plan.topology_requirements.get("needs_dhcp_pool")) or any(
        op.get("op") in {"set_router_dhcp_pool", "set_server_dhcp_pool"}
        for op in list(plan.router_ops) + list(plan.server_ops)
    ):
        return

    # Which router interface the hosts sit behind is decided by the cabling, so
    # tell the segment lookup which ones are actually wired to a switch.
    kind_by_name = {str(device["name"]): _device_kind(device) for device in devices}
    cabled_router_ports = {
        str(link[router_key]["port"])
        for link in links
        for router_key, switch_key in (("a", "b"), ("b", "a"))
        if kind_by_name.get(str(link[router_key]["dev"])) == "Router"
        and kind_by_name.get(str(link[switch_key]["dev"])) == "Switch"
    }

    segment = _donor_service_segment(donor_root, cabled_router_ports or None)
    if segment is None:
        return
    vlan_id, prefix, svi_ip = segment

    # With no routed VLAN interface to name one, the segment is the switch
    # default. Skipping the VLAN pass entirely in that case left each host on
    # whatever its donor port happened to carry: in a 22-switch lab three hosts
    # sat on `access vlan 5` and the other thirty-seven on the untouched
    # default, so hosts sharing a switch and a subnet still could not reach
    # each other. Naming VLAN 1 moves the three, not the thirty-seven.
    access_vlan = vlan_id if vlan_id is not None else 1

    host_names = {str(device["name"]) for device in hosts}
    for link in links:
        # A link does not always store the host first. Reading only the `a`
        # side left the reversed ones untouched, so those access ports kept the
        # switch default while their neighbours were moved to the donor's VLAN:
        # in a 22-switch lab PC1 sat on `access vlan 5` and PC22, on the same
        # switch and the same subnet, had no VLAN line at all. Same wire, same
        # addresses, no connectivity.
        ends = _host_and_switch_ends(link, host_names, devices)
        if ends is None:
            continue
        _, switch_end = ends
        _append_unique_op(
            plan.switch_ops,
            {
                "op": "set_access_port",
                "device": str(switch_end["dev"]),
                "port": str(switch_end["port"]),
                "vlan": access_vlan,
            },
        )

    taken = {svi_ip}
    for device in donor_root.findall(".//DEVICES/DEVICE"):
        port = device.find("./ENGINE/MODULE/SLOT/MODULE/PORT")
        if port is None:
            continue
        address = (port.findtext("IP") or "").strip()
        if address and address != "0.0.0.0":
            taken.add(address)

    next_host = 20
    for host in hosts:
        while f"{prefix}.{next_host}" in taken and next_host < 250:
            next_host += 1
        address = f"{prefix}.{next_host}"
        taken.add(address)
        next_host += 1
        _append_unique_op(
            plan.end_device_ops,
            {
                "op": "set_host_ip",
                "device": str(host["name"]),
                "ip": address,
                "mask": "255.255.255.0",
                "gw": f"{prefix}.1",
                "ip_mode": "static",
            },
        )


def _management_vlan_id(plan: IntentPlan) -> int | None:
    """The VLAN reserved for switch management, if the prompt asked for one."""
    if "management_vlan" not in set(plan.capabilities):
        return None
    # A management VLAN is normally the highest one named -- 99 in the common
    # `management vlan 99` phrasing -- and must not steal a user data VLAN.
    if plan.vlan_ids:
        return max(plan.vlan_ids)
    return 99



def _add_wan_link(
    plan: IntentPlan, routers: list[dict[str, object]], links: list[dict[str, object]]
) -> None:
    """Join two routers over a serial link when the prompt asks for a WAN.

    A two-router PPP lab was being built with the PPP configuration in place and
    no cable between the routers -- two isolated sites and a serial encapsulation
    configured on an interface with nothing on the other end.

    Serial is the medium every CCNA WAN lab uses; `apply_cable_type` maps it to
    the `eSerial` link family.
    """
    if len(routers) < 2:
        return
    if not set(plan.capabilities) & {"ppp", "gre", "wan", "vpn", "ipsec", "static_route"}:
        return
    left, right = routers[0], routers[1]
    pair = {str(left["name"]), str(right["name"])}
    for link in links:
        if {str(link["a"]["dev"]), str(link["b"]["dev"])} == pair:
            return
    links.append(
        {
            "a": {"dev": left["name"], "port": "Serial0/0/0"},
            "b": {"dev": right["name"], "port": "Serial0/0/0"},
            "media": "serial",
        }
    )



def _same_media(left: str, right: str) -> bool:
    """Whether two cable names mean the same cable.

    `eStraightThrough` and `straight-through` are one cable in two vocabularies.
    """
    from pkt_transformer import CABLE_FAMILIES

    def canonical(value: str) -> str:
        text = str(value or "").strip().lower()
        if not text:
            return ""
        if text in CABLE_FAMILIES:
            family, subtype = CABLE_FAMILIES[text]
            return (subtype or family).lower()
        return text

    return canonical(left) == canonical(right)


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


def _collect_donor_groups(
    root: ET.Element, skip_anchor_names: frozenset[str] = frozenset()
) -> list[dict[str, object]]:
    """Donor switch groups. Names in `skip_anchor_names` never anchor one.

    A multilayer switch can anchor a group, and the plan may also want one as a
    *device*. There is only one of it, so the caller reserves what it needs and
    passes the names here.
    """
    devices = inventory_devices(root)
    groups: list[dict[str, object]] = []
    for device in devices:
        if device["type"] != "Switch":
            continue
        if str(device["name"]) in skip_anchor_names:
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
    # Prefix grouping only means anything when the prefixes actually gather
    # hosts. A donor whose switches are `SW-IDR`, `SW-MUH`, ... collapses into
    # one group named `SW` holding nothing, because its hosts are `PC-IDR1` and
    # `SRV-IDR` -- different prefixes. Those empty groups then suppressed the
    # link-based fallback below, which groups that donor correctly, and every
    # request for five switch groups was refused against a donor that had five.
    if groups and not any(
        any(_fallback_group_member_type(str(member["type"])) for member in group["members"])
        for group in groups
    ):
        groups = []

    if groups:
        groups.sort(key=lambda item: _name_sort_key(str(item["group_name"])))
        return groups

    links = inventory_links(root)
    by_name = {str(device["name"]): device for device in devices}
    # The fallback runs only when prefix grouping found nothing, and a donor
    # whose sole switch is Layer-3 lands here with no groups at all -- which is
    # how a VoIP lab carrying an analog phone could serve none of them.
    switches = [
        device
        for device in devices
        if device["type"] in {"Switch", "MultiLayerSwitch"}
        and str(device["name"]) not in skip_anchor_names
    ]
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
        switch_kinds = {"Switch", "MultiLayerSwitch"}
        if left_name in switch_map and left_type in switch_kinds and _fallback_group_member_type(right_type):
            switch_map[left_name]["members"].append(right)
        elif right_name in switch_map and right_type in switch_kinds and _fallback_group_member_type(left_type):
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
            members = [
                device
                for device in devices
                if str(device.get("group") or "") == group_name
                and _fallback_group_member_type(_device_kind(device))
            ]
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
        # Group membership must use the same predicate as `_collect_donor_groups`.
        # Routers are deliberately excluded: they are matched separately against
        # the donor router (see `target_router` / `donor_router` below). Counting a
        # router as a group member too made every target group demand a router that
        # no donor group can ever supply, which rejected every candidate donor.
        if left_type == "Switch" and _fallback_group_member_type(right_type):
            host_assignment[right_name] = left_name
        elif right_type == "Switch" and _fallback_group_member_type(left_type):
            host_assignment[left_name] = right_name
    switch_names = list(switch_map)
    fallback_index = 0
    for device in devices:
        if not _fallback_group_member_type(_device_kind(device)):
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


INFRASTRUCTURE_LINK_KINDS = {"Router", "Switch", "MultiLayerSwitch"}


def _link_may_be_created(left_kind: str, right_kind: str) -> bool:
    """Whether a link the donor lacks may be built between these device kinds.

    Measured against real Packet Tracer opens: every generated file whose only
    created links were `Switch <-> Switch` opened, and every file containing a
    created `Pc <-> Switch` link was rejected as "not compatible with this
    version". Uplinks between infrastructure devices can be built; a host's
    connection cannot, so a host must keep the switch the donor already gave it.
    """
    # Host links used to be refused here. The real cause was not the endpoint
    # kind but the invented MEM_ADDR values written into new links: building the
    # same host link with those fields omitted opens in Packet Tracer. With
    # `_ensure_link` no longer inventing them, any pair may be linked.
    return bool(left_kind) and bool(right_kind)


def _host_duplication_enabled() -> bool:
    """Whether a missing host may be cloned from one the donor group has.

    On by default. It became possible only once `_ensure_link` stopped writing
    invented MEM_ADDR values into new links; before that a cloned host's
    connection made Packet Tracer reject the file.
    """
    raw = (os.getenv("PACKET_TRACER_HOST_DUPLICATION") or "").strip().lower()
    return raw not in {"0", "off", "false", "no"}


def _group_duplication_enabled() -> bool:
    """Whether a switch group may be duplicated to exceed the donor's size.

    On by default: verified against a real Packet Tracer open. A four-switch
    topology built by duplicating a group on a three-switch donor opens in
    10.4 s.

    The operation order is what made it work. Duplicating first and renaming the
    copy afterwards produced a file Packet Tracer refused; duplicating last,
    from a device already carrying its final name and with final host names,
    matches the arrangement the donor already has.

    `PACKET_TRACER_GROUP_DUPLICATION=off` restricts topologies to the donor's
    own switch count again.
    """
    raw = (os.getenv("PACKET_TRACER_GROUP_DUPLICATION") or "").strip().lower()
    return raw not in {"0", "off", "false", "no"}


def _cross_group_borrowing_enabled() -> bool:
    """Whether a target switch may take hosts from another donor switch group.

    Off by default: verified against real Packet Tracer opens, borrowed devices
    produce a file Packet Tracer refuses. Set
    `PACKET_TRACER_CROSS_GROUP_BORROW=1` to experiment with it.
    """
    return (os.getenv("PACKET_TRACER_CROSS_GROUP_BORROW") or "").strip().lower() in {"1", "true", "yes", "on"}


LINK_STRATEGIES = ("reuse", "create")
DEFAULT_LINK_STRATEGY = "create"


def _link_strategy() -> str:
    """Whether a requested link the donor lacks may be built.

    `reuse` only rewires links the donor already has, so the achievable
    topologies are exactly the donor's own — a chain donor could never satisfy a
    star request. `create` builds the missing link with the same `set_link`
    operation the edit path uses, and is the default because it was verified
    against real Packet Tracer opens: a 3-switch VLAN star built on a chain
    donor opened in 10.1s, and the simple single-switch case still opens.

    The failure mode is naming a port the device does not have, which makes
    Packet Tracer reject the whole file as "not compatible with this version".
    `port_exists` and the structural port-conflict check both guard it.
    """
    raw = (os.getenv("PACKET_TRACER_LINK_STRATEGY") or "").strip().lower()
    return raw if raw in LINK_STRATEGIES else DEFAULT_LINK_STRATEGY


SPARE_STRATEGIES = ("park", "prune")
DEFAULT_SPARE_STRATEGY = "prune"


def _spare_strategy() -> str:
    """What to do with donor devices the plan does not need.

    `prune` deletes them, so the generated lab contains only what was asked for.
    `park` renames them `UNUSED-*` / `*-SPARE-*`, unlinks them and moves them
    offscreen — the older, more conservative behaviour, kept as an escape hatch
    via `PACKET_TRACER_SPARE_STRATEGY` in case a donor turns out to depend on a
    device staying present.
    """
    raw = (os.getenv("PACKET_TRACER_SPARE_STRATEGY") or "").strip().lower()
    return raw if raw in SPARE_STRATEGIES else DEFAULT_SPARE_STRATEGY


def _device_kind_of_blueprint(blueprint: dict[str, object], device_name: str) -> str:
    for device in blueprint.get("devices", []):
        if str(device.get("name")) == device_name:
            return _device_kind(device)
    return ""


def _device_kind_by_name(group: dict[str, object], host_name: str) -> str:
    for member in group.get("members", []):
        if str(member.get("name")) == host_name:
            return _device_kind(member)
    return "PC"


def _resolve_port_conflicts(
    adapted_plan: IntentPlan,
    *,
    donor_links: list[dict[str, object]],
    rename_map: dict[str, str],
    removed_pairs: set[tuple[str, str]],
    parked_names: set[str],
    donor_device_by_target: dict[str, ET.Element],
) -> None:
    """Make sure no interface ends up carrying two cables.

    Link ports come from two independent places: donor links that survive the
    prune keep their original wiring, and `set_link` operations carry ports the
    planner chose. Neither knows about the other, so a plan that is internally
    consistent could still put `PC1` and `R1` on `SW1 FastEthernet0/3`.

    Rather than teach both producers about each other — the mistake this repo
    keeps making — reconcile once, here, over the links that will actually exist.
    Surviving donor wiring wins, because it is known-good; `set_link` moves.
    """
    claimed: dict[tuple[str, str], str] = {}

    for donor_link in donor_links:
        left = rename_map.get(str(donor_link.get("from") or ""), str(donor_link.get("from") or ""))
        right = rename_map.get(str(donor_link.get("to") or ""), str(donor_link.get("to") or ""))
        if not left or not right or left == right:
            continue
        if left in parked_names or right in parked_names:
            continue
        if tuple(sorted((left, right))) in removed_pairs:
            continue
        ports = [str(port) for port in (donor_link.get("ports") or [])][:2]
        for device_name, port_name in zip((left, right), ports):
            if port_name:
                claimed.setdefault((device_name, port_name), f"donor link {left} <-> {right}")

    def free_port(device_name: str, port_name: str, label: str) -> str:
        if not port_name:
            return port_name
        device = donor_device_by_target.get(device_name)

        # Relocating only on a collision left the hole every refused file came
        # through: a port nobody else had claimed was accepted without asking
        # whether the device has it. A lab built from a bundled donor named
        # R1:FastEthernet0/1 on a router whose interfaces are
        # GigabitEthernet0/0/0..0/0/2, and Packet Tracer refused the file. An
        # invalid interface name blocks opening; a double-booked one does not.
        taken = (device_name, port_name) in claimed
        missing = device is not None and not port_exists(device, port_name)
        if not taken and not missing:
            claimed[(device_name, port_name)] = label
            return port_name

        if device is not None:
            # The old search only widened from gigabit to fast ethernet, so a
            # wrong FastEthernet name on a gigabit-only router had nowhere to
            # go. The device's own interface list needs no such direction.
            for candidate in donor_interface_names(device):
                if (device_name, candidate) in claimed:
                    continue
                claimed[(device_name, candidate)] = label
                return candidate

        match = re.match(r"^(.*?)(\d+)$", port_name)
        if device is None or not match:
            return port_name
        stems = [match.group(1)]
        if "gigabit" in match.group(1).lower():
            stems.append("FastEthernet0/")
        start = int(match.group(2))
        for stem in stems:
            first = start if stem != match.group(1) else start + 1
            for index in range(first, first + 48):
                candidate = f"{stem}{index}"
                if (device_name, candidate) in claimed:
                    continue
                if not port_exists(device, candidate):
                    break
                claimed[(device_name, candidate)] = label
                return candidate
        return port_name

    for operation in adapted_plan.edit_operations:
        if operation.get("op") != "set_link":
            continue
        left_name = str(operation["a"]["dev"])
        right_name = str(operation["b"]["dev"])
        label = f"set_link {left_name} <-> {right_name}"
        operation["a"]["port"] = free_port(left_name, str(operation["a"]["port"]), label)
        operation["b"]["port"] = free_port(right_name, str(operation["b"]["port"]), label)


def _trunk_uplinks_in_file(root: ET.Element) -> list[str]:
    """Trunk every switch-to-switch link, using the ports the file really has.

    The planner emits these too, but it names ports before reconciliation moves
    the cables, so its trunk lines can land on interfaces that end up carrying
    nothing. In a 22-switch lab that left two donor-inherited uplinks as access
    ports on VLAN 5 while the rest were trunks -- and a VLAN 1 host behind one
    of them could not leave its own switch.

    The assembled lab is where the cabling is final, so the trunks are written
    from it. Same reasoning as the port repair beside it.
    """
    devices = {
        (device.findtext("./ENGINE/SAVE_REF_ID") or ""): device
        for device in root.findall(".//DEVICES/DEVICE")
    }
    switch_kinds = {"Switch", "MultiLayerSwitch"}
    trunked: list[str] = []
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext("FROM") or "").strip(), (cable.findtext("TO") or "").strip()]
        ports = [node.text or "" for node in cable.findall("PORT")]
        if len(ports) < 2:
            continue
        if any(
            (devices.get(ref) is None)
            or ((devices[ref].findtext("./ENGINE/TYPE") or "") not in switch_kinds)
            for ref in refs
        ):
            continue
        for ref, port in zip(refs, ports):
            config = devices[ref].find("./ENGINE/RUNNINGCONFIG")
            if config is None or not port:
                continue
            _set_config_block(
                config,
                f"interface {port}",
                [" switchport mode trunk", " switchport trunk allowed vlan all"],
            )
            trunked.append(f"{devices[ref].findtext('./ENGINE/NAME') or ref}:{port}")
    return trunked


def _align_router_access_vlan(root: ET.Element) -> list[str]:
    """Put the router's switch port in the VLAN the hosts are in.

    The gateway can be up, addressed and cabled and still be unreachable if the
    switch port facing it sits in another VLAN. Measured: hosts on
    `switchport access vlan 1`, the router's port on SW1 still carrying the
    donor's `access vlan 5`. Different broadcast domains, so nothing could reach
    the gateway however correct the addressing was.

    This looked like a size threshold at first -- a 3-switch lab worked and an
    8-switch one did not -- because the two drew different donors, and only the
    larger one's donor had VLAN 5 ports to inherit.
    """
    devices = {
        (device.findtext("./ENGINE/SAVE_REF_ID") or ""): device
        for device in root.findall(".//DEVICES/DEVICE")
    }
    host_types = {"Pc", "PC", "Server", "Printer", "Laptop"}
    switch_types = {"Switch", "MultiLayerSwitch"}

    def kind(ref: str) -> str:
        device = devices.get(ref)
        return (device.findtext("./ENGINE/TYPE") or "") if device is not None else ""

    def access_vlan(device: ET.Element, port: str) -> str:
        config = device.find("./ENGINE/RUNNINGCONFIG")
        if config is None:
            return "1"
        lines = [(line.text or "") for line in config.findall("LINE")]
        for index, line in enumerate(lines):
            if line.strip() != f"interface {port}":
                continue
            cursor = index + 1
            while cursor < len(lines) and lines[cursor].startswith(" "):
                if lines[cursor].strip().startswith("switchport access vlan "):
                    return lines[cursor].strip().split()[-1]
                cursor += 1
        return "1"

    host_vlans: Counter[str] = Counter()
    router_ends: list[tuple[ET.Element, str]] = []
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext("FROM") or "").strip(), (cable.findtext("TO") or "").strip()]
        ports = [node.text or "" for node in cable.findall("PORT")]
        if len(ports) < 2:
            continue
        for near, far in ((0, 1), (1, 0)):
            if kind(refs[far]) not in switch_types:
                continue
            if kind(refs[near]) in host_types:
                host_vlans[access_vlan(devices[refs[far]], ports[far])] += 1
            elif kind(refs[near]) == "Router":
                # A router-on-a-stick end is a trunk, not an access port;
                # forcing it into the hosts' VLAN would strip the tagging every
                # other VLAN depends on.
                if _router_subinterface_vlans(devices[refs[near]], ports[near]):
                    continue
                router_ends.append((devices[refs[far]], ports[far]))

    if not host_vlans or not router_ends:
        return []
    wanted = host_vlans.most_common(1)[0][0]

    notes: list[str] = []
    for switch, port in router_ends:
        if access_vlan(switch, port) == wanted:
            continue
        config = switch.find("./ENGINE/RUNNINGCONFIG")
        if config is None:
            continue
        _set_config_block(
            config,
            f"interface {port}",
            [" switchport mode access", f" switchport access vlan {wanted}"],
        )
        notes.append(
            f"{switch.findtext('./ENGINE/NAME') or ''}:{port} moved to VLAN {wanted} (the hosts' VLAN)"
        )
    return notes


def _add_hsrp_gateway_redundancy(root: ET.Element) -> list[str]:
    """Give the VLAN gateways a standby router.

    `hsrp olsun` parsed, and nothing came of it: the only implementation here
    is `set_hsrp_ipv6`, so an IPv4 lab asked for HSRP and got a configuration
    with no `standby` line anywhere. Measured on the 140-device enterprise
    lab -- eight routers, five of them with no cable at all.

    The arrangement is the one the specification asks for and the one every
    textbook uses: the address the hosts already point at becomes the virtual
    one, and the two routers move aside to .2 and .3. Nothing the hosts or the
    DHCP pools say has to change, which is what makes it safe to add last.

        10.10.30.1   virtual, what the hosts use
        10.10.30.2   primary, priority 110, preempt
        10.10.30.3   standby

    The second router is one the topology already contains and left uncabled,
    trunked to the same switch as the first: a standby gateway on a different
    switch would be a different lab.
    """
    from pkt_editor import _ensure_link

    devices = {
        (device.findtext("./ENGINE/SAVE_REF_ID") or "").strip(): device
        for device in root.findall(".//DEVICES/DEVICE")
    }
    switch_types = {"Switch", "MultiLayerSwitch"}
    cabled: set[str] = set()
    used_ports: set[tuple[str, str]] = set()
    primary: tuple[ET.Element, str, ET.Element, str] | None = None
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext(tag) or "").strip() for tag in ("FROM", "TO")]
        ports = [node.text or "" for node in cable.findall("PORT")]
        if len(ports) < 2:
            continue
        for index, ref in enumerate(refs):
            device = devices.get(ref)
            if device is not None:
                cabled.add((device.findtext("./ENGINE/NAME") or "").strip())
                used_ports.add(((device.findtext("./ENGINE/NAME") or "").strip(), ports[index]))
        for near, far in ((0, 1), (1, 0)):
            router = devices.get(refs[near])
            switch = devices.get(refs[far])
            if router is None or switch is None or primary is not None:
                continue
            if (router.findtext("./ENGINE/TYPE") or "") != "Router":
                continue
            if (switch.findtext("./ENGINE/TYPE") or "") not in switch_types:
                continue
            if _router_subinterface_vlans(router, ports[near]):
                primary = (router, ports[near], switch, ports[far])

    if primary is None:
        return []
    router, router_port, switch, switch_port = primary
    spare = next(
        (
            device
            for device in root.findall(".//DEVICES/DEVICE")
            if (device.findtext("./ENGINE/TYPE") or "") == "Router"
            and (device.findtext("./ENGINE/NAME") or "").strip() not in cabled
            and port_exists(device, router_port)
        ),
        None,
    )
    if spare is None:
        return []

    vlans = _router_subinterface_vlans(router, router_port)
    subnets = _vlan_subnets_from_router(root)
    shared = [vlan for vlan in vlans if subnets.get(vlan)]
    if not shared:
        return []

    switch_name = (switch.findtext("./ENGINE/NAME") or "").strip()
    free = next(
        (
            f"FastEthernet0/{index}"
            for index in range(1, 25)
            if (switch_name, f"FastEthernet0/{index}") not in used_ports
            and port_exists(switch, f"FastEthernet0/{index}")
        ),
        "",
    )
    if not free:
        return []

    spare_name = (spare.findtext("./ENGINE/NAME") or "").strip()
    _ensure_link(root, spare_name, router_port, switch_name, free, "copper")

    allowed = ",".join(shared)
    body = [" switchport mode trunk", f" switchport trunk allowed vlan {allowed}"]
    if (switch.findtext("./ENGINE/TYPE") or "") == "MultiLayerSwitch":
        body.insert(0, " switchport trunk encapsulation dot1q")
    switch_config = switch.find("./ENGINE/RUNNINGCONFIG")
    if switch_config is not None:
        _set_config_block(switch_config, f"interface {free}", body)

    def standby_block(subnet: str, vlan: str, address: str, priority: int | None) -> list[str]:
        lines = [
            f" ip address {address} 255.255.255.0",
            f" standby {vlan} ip {subnet}.1",
        ]
        if priority is not None:
            lines.append(f" standby {vlan} priority {priority}")
            lines.append(f" standby {vlan} preempt")
        return lines

    config = router.find("./ENGINE/RUNNINGCONFIG")
    spare_config = spare.find("./ENGINE/RUNNINGCONFIG")
    if config is None or spare_config is None:
        return []
    for vlan in shared:
        subnet = subnets[vlan]
        _set_config_block(
            config, f"interface {router_port}.{vlan}", standby_block(subnet, vlan, f"{subnet}.2", 110)
        )
        for text in (
            f"interface {router_port}.{vlan}",
            f" description VLAN{vlan} standby",
            f" encapsulation dot1Q {vlan}",
            *standby_block(subnet, vlan, f"{subnet}.3", None),
            "!",
        ):
            node = ET.SubElement(spare_config, "LINE")
            node.text = text
    for text in (f"interface {router_port}", " no shutdown", "!"):
        node = ET.SubElement(spare_config, "LINE")
        node.text = text

    name = (router.findtext("./ENGINE/NAME") or "").strip()
    return [
        f"HSRP on {len(shared)} VLAN(s): {name} .2 priority 110, {spare_name} .3, "
        f"virtual .1 -- the address the hosts already use"
    ]


def _trust_uplinks_for_dhcp_snooping(root: ET.Element) -> list[str]:
    """A switch running DHCP snooping has to trust the way to the server.

    Snooping drops server-sourced DHCP messages arriving on untrusted ports,
    and every port is untrusted until told otherwise. Enabling it without
    trusting the uplink is therefore a switch that silently discards every
    offer the router sends back.

    Measured on the 140-device enterprise lab: `dhcp snooping olsun` turned it
    on across eighteen switches, no port was trusted, and every workstation
    fell to APIPA while the statically addressed servers beside them reached
    their gateway 4/4 -- the path was fine, only the offers were being eaten.

    The trunk is the way out of the switch, so the trunks are what get
    trusted; the access ports stay untrusted, which is the whole point of
    turning snooping on.
    """
    trusted: list[str] = []
    for device in root.findall(".//DEVICES/DEVICE"):
        if (device.findtext("./ENGINE/TYPE") or "") not in {"Switch", "MultiLayerSwitch"}:
            continue
        config = device.find("./ENGINE/RUNNINGCONFIG")
        if config is None:
            continue
        lines = [(node.text or "") for node in config.findall("LINE")]
        if not any(line.strip() == "ip dhcp snooping" for line in lines):
            continue
        current = ""
        trunks: list[str] = []
        for line in lines:
            text = line.strip()
            if text.startswith("interface "):
                current = text.split(None, 1)[1]
            elif text == "switchport mode trunk" and current:
                trunks.append(current)
        for port in dict.fromkeys(trunks):
            _set_config_block(config, f"interface {port}", [" ip dhcp snooping trust"])
            trusted.append(f"{device.findtext('./ENGINE/NAME') or ''}:{port}")
    if not trusted:
        return []
    return [f"DHCP snooping trusts {len(trusted)} uplink(s): " + ", ".join(trusted[:6])]


def _place_hosts_in_a_vlan(root: ET.Element) -> list[str]:
    """Every host port in a VLAN lab has to name a VLAN.

    A port with no `switchport access vlan` sits in VLAN 1, which the plan
    never gives a gateway, so the host on it is isolated however well the rest
    of the lab is configured. Measured on the 140-device enterprise lab: 50 of
    112 cabled host ports named no VLAN at all, and every host behind them was
    stranded.

    The switch decides which one. An access switch serves a department, so the
    VLAN most of its other host ports already use is the VLAN its bare ports
    belong to -- and a switch whose ports are all bare takes the lab's lowest
    VLAN rather than inventing one.
    """
    devices_by_ref = {
        (device.findtext("./ENGINE/SAVE_REF_ID") or "").strip(): device
        for device in root.findall(".//DEVICES/DEVICE")
    }
    switch_types = {"Switch", "MultiLayerSwitch"}

    def access_vlan(switch: ET.Element, port: str) -> str:
        inside = False
        for node in switch.findall("./ENGINE/RUNNINGCONFIG/LINE"):
            line = (node.text or "").strip()
            if line.startswith("interface "):
                inside = line == f"interface {port}"
            elif inside:
                if line.startswith("switchport access vlan "):
                    return line.split()[-1]
                if line.startswith("switchport mode trunk"):
                    return "TRUNK"
        return ""

    attachments: list[tuple[ET.Element, str, ET.Element]] = []
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext(tag) or "").strip() for tag in ("FROM", "TO")]
        ports = [node.text or "" for node in cable.findall("PORT")]
        if len(ports) < 2:
            continue
        for near, far in ((0, 1), (1, 0)):
            host = devices_by_ref.get(refs[near])
            switch = devices_by_ref.get(refs[far])
            if host is None or switch is None:
                continue
            if (switch.findtext("./ENGINE/TYPE") or "") not in switch_types:
                continue
            if not _is_host_device(
                {"type": _normalize_device_type(host.findtext("./ENGINE/TYPE") or "")}
            ):
                continue
            attachments.append((switch, ports[far], host))

    declared: set[str] = set()
    for device in root.findall(".//DEVICES/DEVICE"):
        for node in device.findall("./ENGINE/RUNNINGCONFIG/LINE"):
            text = (node.text or "")
            match = re.match(r"^vlan (\d+)$", text.strip())
            if match and not text.startswith(" "):
                declared.add(match.group(1))
    fallback = min(declared, key=int) if declared else ""

    votes: dict[str, Counter[str]] = {}
    for switch, port, _host in attachments:
        vlan = access_vlan(switch, port)
        if vlan and vlan != "TRUNK":
            name = (switch.findtext("./ENGINE/NAME") or "").strip()
            votes.setdefault(name, Counter())[vlan] += 1

    placed: list[str] = []
    for switch, port, host in attachments:
        if access_vlan(switch, port):
            continue
        name = (switch.findtext("./ENGINE/NAME") or "").strip()
        wanted = votes[name].most_common(1)[0][0] if votes.get(name) else fallback
        if not wanted:
            continue
        config = switch.find("./ENGINE/RUNNINGCONFIG")
        if config is None:
            continue
        _set_config_block(
            config,
            f"interface {port}",
            [" switchport mode access", f" switchport access vlan {wanted}"],
        )
        placed.append(f"{name}:{port} -> VLAN {wanted} ({host.findtext('./ENGINE/NAME') or ''})")
    return placed


def _mesh_routers_with_point_to_point_links(root: ET.Element) -> list[str]:
    """Join the routers to each other on /30 links.

    A campus drawing is mostly routers wired to each other -- `10.10.10.0/30`,
    `10.10.10.4/30`, `10.10.10.8/30` and so on -- and the generated labs had
    routers standing alone: eight of them in the enterprise lab, five with no
    cable at all. A router with no path to another router cannot carry a route
    from it, so OSPF had nothing to exchange.

    Each pair takes the next /30 and both ends are advertised, which is what
    makes the mesh do something rather than merely exist. Only interfaces the
    device really has are used, and a router already carrying the VLAN trunk
    keeps it -- the trunk is its job, and a second address on the same port
    would take it away.
    """
    from pkt_editor import _ensure_link

    routers = [
        device
        for device in root.findall(".//DEVICES/DEVICE")
        if (device.findtext("./ENGINE/TYPE") or "") == "Router"
    ]
    if len(routers) < 2:
        return []

    busy: set[tuple[str, str]] = set()
    devices_by_ref = {
        (device.findtext("./ENGINE/SAVE_REF_ID") or "").strip(): device
        for device in root.findall(".//DEVICES/DEVICE")
    }
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext(tag) or "").strip() for tag in ("FROM", "TO")]
        ports = [node.text or "" for node in cable.findall("PORT")]
        for index, ref in enumerate(refs):
            device = devices_by_ref.get(ref)
            if device is not None and index < len(ports):
                busy.add(((device.findtext("./ENGINE/NAME") or "").strip(), ports[index]))

    def free_port(router: ET.Element) -> str:
        name = (router.findtext("./ENGINE/NAME") or "").strip()
        for candidate in donor_interface_names(router) or []:
            if candidate.startswith(("GigabitEthernet", "FastEthernet")) and "." not in candidate:
                if (name, candidate) not in busy and port_exists(router, candidate):
                    return candidate
        for shape in ("GigabitEthernet0/{n}", "FastEthernet0/{n}"):
            for index in range(0, 4):
                candidate = shape.format(n=index)
                if (name, candidate) not in busy and port_exists(router, candidate):
                    return candidate
        return ""

    def octets(value: int) -> str:
        return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))

    base = _address_to_int("10.255.0.0") or 0
    notes: list[str] = []
    made = 0
    for position, left in enumerate(routers):
        for right in routers[position + 1 :]:
            left_port, right_port = free_port(left), free_port(right)
            if not left_port or not right_port:
                continue
            left_name = (left.findtext("./ENGINE/NAME") or "").strip()
            right_name = (right.findtext("./ENGINE/NAME") or "").strip()
            network = base + made * 4
            _ensure_link(root, left_name, left_port, right_name, right_port, "copper")
            busy.add((left_name, left_port))
            busy.add((right_name, right_port))
            for device, port, address in (
                (left, left_port, network + 1),
                (right, right_port, network + 2),
            ):
                config = device.find("./ENGINE/RUNNINGCONFIG")
                if config is None:
                    continue
                _set_config_block(
                    config,
                    f"interface {port}",
                    [
                        f" description point-to-point to {right_name if device is left else left_name}",
                        f" ip address {octets(address)} 255.255.255.252",
                        " ip ospf network point-to-point",
                        " no shutdown",
                    ],
                )
                if any(
                    (node.text or "").strip().startswith("router ospf")
                    for node in config.findall("LINE")
                ):
                    _set_config_block(
                        config,
                        "router ospf 1",
                        [f" network {octets(network)} 0.0.0.3 area 0"],
                    )
            notes.append(f"{left_name}:{left_port} <-> {right_name}:{right_port} {octets(network)}/30")
            made += 1
    if not notes:
        return []
    return [f"{made} point-to-point link(s): " + "; ".join(notes[:5])]


def _host_mask_on_port(device: ET.Element) -> str:
    """The mask a host is actually using, or an empty string."""
    for port in device.findall(".//PORT"):
        mask = (port.findtext("SUBNET") or "").strip()
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", mask) and mask != "0.0.0.0":
            return mask
    return ""


def _pool_window(network: str, mask: str) -> tuple[str, str, str]:
    """Where a pool's reserved range ends and its handout range begins.

    Half the subnet is kept back for the gateway, the servers and the printers
    that are addressed by hand, and the rest is handed out. On a /24 that is
    the familiar .1 to .99 reserved and .100 upwards served; on a /26 it is .1
    to .30 and .31 upwards, which is the point of doing the arithmetic rather
    than writing .99 everywhere -- a /26 has no .99, so the excluded range
    covered the whole subnet and the pool had nothing left to give.
    """
    base = _address_to_int(network + ".0") if network.count(".") == 2 else _address_to_int(network)
    mask_value = _address_to_int(mask)
    if base is None or mask_value is None:
        return "", "", ""
    size = (~mask_value) & 0xFFFFFFFF
    if size < 3:
        return "", "", ""
    start = (base & mask_value) + 1
    half = (base & mask_value) + max(2, size // 2)

    def text(value: int) -> str:
        return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))

    return text(start), text(half - 1), text(half)


def _serve_every_populated_vlan(root: ET.Element) -> list[str]:
    """Give every VLAN that carries hosts a gateway and a pool.

    A twenty-VLAN prompt produced a router with subinterfaces for seven of
    them. The other thirteen had hosts cabled into them, on access ports, in
    VLANs the router had never heard of -- so those hosts had no gateway, no
    pool, and no way off their own switch. Measured on a 140-device lab: 23
    distinct host subnets, half of them the donor's 192.168.x, none of which
    any router interface served.

    The VLAN plan is the statement of intent, and 10.10.<vlan>.0/24 is the
    scheme the rest of the generator already uses, so a VLAN that hosts sit in
    gets that network: a subinterface on the trunk the router already has, and
    a pool behind it. Nothing is invented for a VLAN nobody is plugged into.
    """
    devices_by_ref = {
        (device.findtext("./ENGINE/SAVE_REF_ID") or "").strip(): device
        for device in root.findall(".//DEVICES/DEVICE")
    }
    switch_types = {"Switch", "MultiLayerSwitch"}

    populated: set[str] = set()
    # What the hosts in a VLAN are already addressed as. Imposing a scheme here
    # is how a lab ends up with two address plans: this pass used
    # 10.10.<vlan>.0/24 while the addressing pass had put that VLAN's hosts on
    # 192.168.<vlan>.0/24, so the gateway it created served a network none of
    # them were on. The hosts decide; 10.10.<vlan> is only the fallback for a
    # VLAN whose hosts carry no address yet.
    host_subnets: dict[str, Counter[str]] = {}
    # And with what mask. A VLAN plan that uses /26 or /27 -- as a real one
    # does -- gets a gateway and a pool of that size rather than a /24 nobody
    # asked for.
    host_masks: dict[str, Counter[str]] = {}
    router_trunk: tuple[ET.Element, str] | None = None
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext(tag) or "").strip() for tag in ("FROM", "TO")]
        ports = [node.text or "" for node in cable.findall("PORT")]
        if len(ports) < 2:
            continue
        for near, far in ((0, 1), (1, 0)):
            near_device = devices_by_ref.get(refs[near])
            far_device = devices_by_ref.get(refs[far])
            if near_device is None or far_device is None:
                continue
            far_kind = (far_device.findtext("./ENGINE/TYPE") or "")
            near_kind = (near_device.findtext("./ENGINE/TYPE") or "")
            if far_kind not in switch_types:
                continue
            if near_kind == "Router" and router_trunk is None:
                if _router_subinterface_vlans(near_device, ports[near]):
                    router_trunk = (near_device, ports[near])
                continue
            if not _is_host_device({"type": _normalize_device_type(near_kind)}):
                continue
            inside = False
            for node in far_device.findall("./ENGINE/RUNNINGCONFIG/LINE"):
                line = (node.text or "").strip()
                if line.startswith("interface "):
                    inside = line == f"interface {ports[far]}"
                elif inside and line.startswith("switchport access vlan "):
                    vlan = line.split()[-1]
                    populated.add(vlan)
                    for candidate in near_device.iter():
                        text = (candidate.text or "").strip()
                        if candidate.tag.upper() == "IP" and re.fullmatch(
                            r"\d+\.\d+\.\d+\.\d+", text
                        ):
                            host_subnets.setdefault(vlan, Counter())[
                                text.rsplit(".", 1)[0]
                            ] += 1
                            mask = _host_mask_on_port(near_device)
                            if mask:
                                host_masks.setdefault(vlan, Counter())[mask] += 1
                            break
                    break
    if router_trunk is None:
        return []

    router, parent = router_trunk
    config = router.find("./ENGINE/RUNNINGCONFIG")
    if config is None:
        return []
    known = set(_router_subinterface_vlans(router, parent))
    # A subinterface without a pool is half the job: the VLAN routes but hands
    # out no addresses, and its workstations stay on whatever the donor gave
    # them. Both halves are counted separately for that reason.
    # Keyed by network, not by VLAN number: a pool's network says nothing about
    # which VLAN it serves unless the lab happens to number them alike, and
    # matching on `10.10.<vlan>` missed every 192.168 pool the addressing pass
    # had made.
    pooled_networks: set[str] = set()
    in_pool = False
    for node in config.findall("LINE"):
        text = (node.text or "").strip()
        if text.startswith("ip dhcp pool"):
            in_pool = True
            continue
        if in_pool:
            match = re.match(r"^network (\d+\.\d+\.\d+)\.\d+ ", text)
            if match:
                pooled_networks.add(match.group(1))
                in_pool = False
            elif text.startswith(("interface ", "ip dhcp pool", "router ")):
                in_pool = False

    # VLAN 1 is nobody's plan, and a number past the third octet has no place
    # in this scheme.
    wanted = sorted(
        (vlan for vlan in populated if vlan != "1" and int(vlan) <= 254), key=int
    )
    def already_pooled(vlan: str) -> bool:
        votes = host_subnets.get(vlan)
        network = votes.most_common(1)[0][0] if votes else f"10.10.{vlan}"
        return network in pooled_networks

    if not any(vlan not in known or not already_pooled(vlan) for vlan in wanted):
        return []

    added: list[str] = []
    for vlan in wanted:
        votes = host_subnets.get(vlan)
        network = votes.most_common(1)[0][0] if votes else f"10.10.{vlan}"
        masks = host_masks.get(vlan)
        mask = masks.most_common(1)[0][0] if masks else "255.255.255.0"
        first, last_reserved, first_served = _pool_window(network, mask)
        if not first:
            mask, = ("255.255.255.0",)
            first, last_reserved, first_served = _pool_window(network, mask)
        lines: list[str] = []
        if vlan not in known:
            lines += [
                f"interface {parent}.{vlan}",
                f" description VLAN{vlan}",
                f" encapsulation dot1Q {vlan}",
                f" ip address {first} {mask}",
                " ip nat inside",
                "!",
            ]
        if not already_pooled(vlan):
            lines += [
                f"ip dhcp excluded-address {first} {last_reserved}",
                f"ip dhcp pool VLAN{vlan}",
                f" network {network}.0 {mask}",
                f" default-router {first}",
            ]
        if not lines:
            continue
        for text in lines:
            node = ET.SubElement(config, "LINE")
            node.text = text
        added.append(
            f"VLAN {vlan}"
            + (" gateway" if vlan not in known else "")
            + (" pool" if not already_pooled(vlan) else "")
        )
    name = router.findtext("./ENGINE/NAME") or ""
    return [f"{name}: served {len(added)} VLAN(s) that had hosts and no gateway: " + "; ".join(added)]


def _put_workstations_on_dhcp(root: ET.Element) -> list[str]:
    """Let the pools actually serve someone.

    A DHCP pool and a DHCP client are two halves of one feature, and only the
    first half was ever emitted for a segmented lab: `_synthesize_service_ops`
    puts hosts on DHCP only when the prompt names no VLAN, so every VLAN lab
    shipped one pool per VLAN with not a single device asking for an address.
    The prompt said `dhcp olsun`, the configuration showed the pools, and every
    workstation sat on a static address typed by the generator.

    Workstations move; servers and printers do not. A real network gives the
    first group addresses and pins the second, so only PCs and laptops are
    switched over, and the pool is told to keep the low addresses free -- the
    gateway, the servers on .50, the printers on .60 -- and hand out from .100.
    """
    pools: list[tuple[ET.Element, str]] = []
    for device in root.findall(".//DEVICES/DEVICE"):
        if (device.findtext("./ENGINE/TYPE") or "") != "Router":
            continue
        config = device.find("./ENGINE/RUNNINGCONFIG")
        if config is None:
            continue
        in_pool = False
        for node in config.findall("LINE"):
            text = (node.text or "").strip()
            if text.startswith("ip dhcp pool"):
                in_pool = True
                continue
            if in_pool:
                match = re.match(r"^network (\d+\.\d+\.\d+)\.\d+ 255\.255\.255\.0$", text)
                if match:
                    pools.append((device, match.group(1)))
                    in_pool = False
                elif text.startswith(("interface ", "ip dhcp pool", "router ")):
                    in_pool = False
    if not pools:
        return []

    served = {subnet for _device, subnet in pools}
    for device, subnet in pools:
        config = device.find("./ENGINE/RUNNINGCONFIG")
        if config is None:
            continue
        first, last_reserved, _first_served = _pool_window(subnet, "255.255.255.0")
        wanted = f"ip dhcp excluded-address {first} {last_reserved}"
        if any((node.text or "").strip() == wanted for node in config.findall("LINE")):
            continue
        node = ET.Element("LINE")
        node.text = wanted
        children = list(config)
        first_pool = next(
            (
                child
                for child in children
                if (child.text or "").strip().startswith("ip dhcp pool")
            ),
            None,
        )
        config.insert(children.index(first_pool) if first_pool is not None else len(children), node)

    # A workstation's VLAN is the truth about which network it belongs to; its
    # address may still be the donor's. Pruning leaves hosts on the donor's
    # plan -- measured on a 140-device lab, 23 subnets across 95 hosts, half of
    # them 192.168.x that no router interface serves -- and re-addressing each
    # one by hand is a second address plan waiting to disagree with the first.
    # Reading the VLAN off the port and letting DHCP supply the address puts
    # every host on the network it is actually cabled into.
    vlan_subnets = _vlan_subnets_from_router(root)
    devices_by_ref = {
        (device.findtext("./ENGINE/SAVE_REF_ID") or "").strip(): device
        for device in root.findall(".//DEVICES/DEVICE")
    }
    switch_types = {"Switch", "MultiLayerSwitch"}

    def access_vlan(switch: ET.Element, port: str) -> str:
        inside = False
        for node in switch.findall("./ENGINE/RUNNINGCONFIG/LINE"):
            line = (node.text or "").strip()
            if line.startswith("interface "):
                inside = line == f"interface {port}"
            elif inside and line.startswith("switchport access vlan "):
                return line.split()[-1]
        return ""

    vlan_of_host: dict[str, str] = {}
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext(tag) or "").strip() for tag in ("FROM", "TO")]
        ports = [node.text or "" for node in cable.findall("PORT")]
        if len(ports) < 2:
            continue
        for near, far in ((0, 1), (1, 0)):
            host = devices_by_ref.get(refs[near])
            switch = devices_by_ref.get(refs[far])
            if host is None or switch is None:
                continue
            if (switch.findtext("./ENGINE/TYPE") or "") not in switch_types:
                continue
            vlan = access_vlan(switch, ports[far])
            if vlan:
                vlan_of_host[(host.findtext("./ENGINE/NAME") or "").strip()] = vlan

    moved: list[str] = []
    for device in root.findall(".//DEVICES/DEVICE"):
        kind = _normalize_device_type(device.findtext("./ENGINE/TYPE") or "")
        if kind not in {"PC", "Laptop"}:
            continue
        address = ""
        for node in device.iter():
            text = (node.text or "").strip()
            if node.tag.upper() == "IP" and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", text):
                address = text
                break
        vlan = vlan_of_host.get((device.findtext("./ENGINE/NAME") or "").strip(), "")
        served_by_vlan = vlan_subnets.get(vlan, "") in served if vlan else False
        if not served_by_vlan and (not address or address.rsplit(".", 1)[0] not in served):
            continue
        for port in device.findall(".//PORT"):
            if port.find("PORT_DHCP_ENABLE") is not None:
                _ensure_text(port, "PORT_DHCP_ENABLE", "true")
        engine = device.find("./ENGINE")
        if engine is not None:
            for profile in _profile_nodes(engine):
                _ensure_text(profile, "DHCP_ENABLED", "1")
        moved.append(f"{device.findtext('./ENGINE/NAME') or ''}: {address} -> DHCP")
    return moved


def _drop_config_for_absent_interfaces(root: ET.Element) -> list[str]:
    """Delete configuration for interfaces the device does not have.

    Pruning a donor leaves whole interface blocks behind for hardware that is
    no longer there. On the generated company lab R1 was a 2911 -- ports
    `GigabitEthernet0/0` .. `0/2` -- and still carried
    `GigabitEthernet0/0/0.10` through `.50`, an ISR's naming, each with a
    192.168.x address.

    They are not merely untidy. They are read as real interfaces by everything
    that reasons about the router's networks, and they carry the donor's whole
    address plan: `_align_dhcp_pools_with_interfaces` saw pools serving
    192.168.30.0 "matching an interface" and left them pointing at a network
    no cable reaches, so the lab had DHCP configured and handed out nothing.

    A block is removed only when the device's own port list says the parent
    does not exist, so a subinterface of a real port is never touched.
    """
    dropped: list[str] = []
    for device in root.findall(".//DEVICES/DEVICE"):
        for section in ("RUNNINGCONFIG", "STARTUPCONFIG"):
            config = device.find(f"./ENGINE/{section}")
            if config is None:
                continue
            removing = False
            removed_here: list[str] = []
            for node in list(config.findall("LINE")):
                text = (node.text or "")
                stripped = text.strip()
                if stripped.startswith("interface "):
                    name = stripped.split(None, 1)[1]
                    parent = name.split(".", 1)[0]
                    removing = not port_exists(device, parent)
                    if removing:
                        removed_here.append(name)
                        config.remove(node)
                    continue
                if removing and (text.startswith((" ", "\t")) or stripped == "!"):
                    config.remove(node)
                    continue
                removing = False
            if removed_here and section == "RUNNINGCONFIG":
                dropped.append(
                    f"{device.findtext('./ENGINE/NAME') or ''}: dropped {len(removed_here)} "
                    f"block(s) for absent interfaces ({', '.join(removed_here[:3])})"
                )
    return dropped


def _drop_port_security_from_trunks(root: ET.Element) -> list[str]:
    """Port security belongs on an access port, never on a trunk.

    A trunk carries every MAC address behind the switch on the other end, so
    `switchport port-security maximum 2` on one is a violation waiting for the
    third host to speak. Measured on the generated company lab: SW1's trunk to
    SW3 carried port security, SW3 was cut off from the rest of the network,
    and its whole VLAN 10 -- three workstations -- fell back to APIPA because
    no DHCP offer could reach them. Every other VLAN leased normally.

    The port-security operation is emitted against a port chosen before the
    trunks are settled, so the two decisions are made independently and only
    the cable knows which port ended up carrying a trunk.
    """
    dropped: list[str] = []
    for device in root.findall(".//DEVICES/DEVICE"):
        if (device.findtext("./ENGINE/TYPE") or "") not in {"Switch", "MultiLayerSwitch"}:
            continue
        for section in ("RUNNINGCONFIG", "STARTUPCONFIG"):
            config = device.find(f"./ENGINE/{section}")
            if config is None:
                continue
            blocks: dict[str, list[ET.Element]] = {}
            current = ""
            for node in config.findall("LINE"):
                text = (node.text or "").strip()
                if text.startswith("interface "):
                    current = text.split(None, 1)[1]
                    blocks.setdefault(current, [])
                elif current:
                    blocks.setdefault(current, []).append(node)
            for port, body in blocks.items():
                if not any((n.text or "").strip() == "switchport mode trunk" for n in body):
                    continue
                removed = [n for n in body if "port-security" in (n.text or "")]
                for node in removed:
                    if node in list(config):
                        config.remove(node)
                if removed and section == "RUNNINGCONFIG":
                    dropped.append(
                        f"{device.findtext('./ENGINE/NAME') or ''}:{port} port security "
                        f"removed ({len(removed)} line(s)) -- it is a trunk"
                    )
    return dropped


def _align_etherchannels_with_cabling(root: ET.Element) -> list[str]:
    """An EtherChannel is two or more cables between the same two switches.

    `_synthesize_security_ops` writes `channel-group 1 mode on` onto
    `GigabitEthernet0/1` and `GigabitEthernet0/2` of the first two switches it
    finds, without ever asking what those ports are cabled to. Measured on the
    153-device enterprise lab: SW2's `Gi0/1` is its only uplink to the core and
    `Gi0/2` has no cable at all, so the pass bundled a live trunk with a dead
    port towards a peer -- SW18 -- that was not bundling anything. The port
    joins a `Port-channel1` that no line in the file configures, the trunk
    settings stop applying, and the switch drops off the network: Printer6, the
    one routable host behind SW2, could not reach even its own gateway's real
    address on VLAN 50, while identical hosts behind SW3 and SW4 -- neither of
    which was given a channel-group -- answered normally.

    Which ports form a bundle is a fact about the cabling, and the plan settles
    it before any cable exists, so the two decisions are made independently and
    nothing compares them. This pass is the one that can see the cables.

    A pair asked to bundle needs two of them. Where only one exists and both
    switches still have a free port, the second is laid here -- the only place
    that knows both which pair was asked and which ports are still free -- and
    every cable between the pair becomes a member, with one channel number, one
    mode, the trunk settings copied onto the ports that were not trunks before,
    and the `interface Port-channelN` that holds them. Where the second cable
    cannot be laid the line goes, because a bundle of one is not a bundle: it is
    an ordinary port carrying configuration that stops it working.
    """
    switch_types = {"Switch", "MultiLayerSwitch"}
    devices_by_ref: dict[str, ET.Element] = {}
    devices_by_name: dict[str, ET.Element] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        devices_by_ref[(device.findtext("./ENGINE/SAVE_REF_ID") or "").strip()] = device
        devices_by_name[(device.findtext("./ENGINE/NAME") or "").strip()] = device

    members: dict[tuple[str, str], tuple[int, str]] = {}
    for name, device in devices_by_name.items():
        if (device.findtext("./ENGINE/TYPE") or "") not in switch_types:
            continue
        current = ""
        for node in device.findall("./ENGINE/RUNNINGCONFIG/LINE"):
            text = (node.text or "").strip()
            if text.startswith("interface "):
                current = text.split(None, 1)[1]
                continue
            match = re.match(r"^channel-group (\d+) mode (\S+)$", text)
            if match and current:
                members[(name, current)] = (int(match.group(1)), match.group(2))
    if not members:
        return []

    from pkt_editor import _ensure_link

    busy: set[tuple[str, str]] = set()
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext(tag) or "").strip() for tag in ("FROM", "TO")]
        ports = [node.text or "" for node in cable.findall("PORT")]
        for index, ref in enumerate(refs):
            device = devices_by_ref.get(ref)
            if device is not None and index < len(ports):
                busy.add(((device.findtext("./ENGINE/NAME") or "").strip(), ports[index]))

    bundles: dict[tuple[str, str], list[tuple[tuple[str, str], tuple[str, str]]]] = {}
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext(tag) or "").strip() for tag in ("FROM", "TO")]
        ports = [node.text or "" for node in cable.findall("PORT")]
        if len(ports) < 2:
            continue
        left, right = devices_by_ref.get(refs[0]), devices_by_ref.get(refs[1])
        if left is None or right is None:
            continue
        if (left.findtext("./ENGINE/TYPE") or "") not in switch_types:
            continue
        if (right.findtext("./ENGINE/TYPE") or "") not in switch_types:
            continue
        ends = (
            ((left.findtext("./ENGINE/NAME") or "").strip(), ports[0]),
            ((right.findtext("./ENGINE/NAME") or "").strip(), ports[1]),
        )
        # One end asking is enough to record the intent. Which end was given the
        # line is an accident of the order the planner walked the switches.
        if ends[0] not in members and ends[1] not in members:
            continue
        bundles.setdefault(tuple(sorted((ends[0][0], ends[1][0]))), []).append(ends)

    def trunk_body(name: str, port: str) -> list[str]:
        device = devices_by_name.get(name)
        wanted: list[str] = []
        if device is None:
            return wanted
        inside = False
        for node in device.findall("./ENGINE/RUNNINGCONFIG/LINE"):
            text = (node.text or "").strip()
            if text.startswith("interface "):
                inside = text == f"interface {port}"
            elif inside and text.startswith("switchport") and text not in wanted:
                wanted.append(text)
        return [f" {line}" for line in wanted]

    def drop_line(config: ET.Element, port: str, prefix: str) -> None:
        """`_set_config_block` matches on the first two words, so an access VLAN
        left on a port that is now a trunk survives writing `switchport mode
        trunk` beside it."""
        current = ""
        for node in list(config.findall("LINE")):
            text = (node.text or "").strip()
            if text.startswith("interface "):
                current = text.split(None, 1)[1]
            elif current == port and text.startswith(prefix):
                config.remove(node)

    def free_ports(name: str, family: str, count: int) -> list[str]:
        """Free sockets of one speed, because a bundle cannot mix them.

        A gigabit port bundled with a FastEthernet one is refused for speed
        mismatch, and the first attempt at this produced exactly that: SW3
        offered `GigabitEthernet0/1` to one neighbour and `FastEthernet0/1` to
        the next, because the search preferred gigabit rather than matching.
        """
        device = devices_by_name.get(name)
        if device is None or not family:
            return []
        found: list[str] = []
        for candidate in donor_interface_names(device) or []:
            if not candidate.startswith(family) or "." in candidate:
                continue
            if (name, candidate) not in busy and port_exists(device, candidate):
                found.append(candidate)
                if len(found) == count:
                    break
        return found

    def family_of(port: str) -> str:
        for prefix in ("GigabitEthernet", "FastEthernet"):
            if port.startswith(prefix):
                return prefix
        return ""

    # A switch in two bundles needs two channel numbers: members of different
    # neighbours cannot share one Port-channel. The planner writes `1` for
    # every switch it touches, so SW3 came out with four members of "channel 1"
    # facing two different neighbours.
    taken_channels: dict[str, set[int]] = {}

    keep: dict[tuple[str, str], tuple[int, str]] = {}
    notes: list[str] = []
    for pair, cables in sorted(bundles.items()):
        stated = [members[end] for cable in cables for end in cable if end in members]
        template = next((end for cable in cables for end in cable if trunk_body(*end)), cables[0][0])
        body = trunk_body(*template)

        def lay(left: tuple[str, str], right: tuple[str, str]) -> tuple[tuple[str, str], tuple[str, str]]:
            _ensure_link(root, left[0], left[1], right[0], right[1], "crossover", allow_parallel=True)
            busy.add(left)
            busy.add(right)
            return (left, right)

        if len(cables) == 1:
            # A bundle needs a second cable, and the pass that lays cables ran
            # long before anything asked for a bundle. Adding it here is the
            # only place both facts are known: which pair was asked to bundle,
            # and which of their ports are still free.
            (left_name, left_member), (right_name, right_member) = cables[0]
            family = family_of(left_member)
            if family == family_of(right_member):
                left_free = free_ports(left_name, family, 1)
                right_free = free_ports(right_name, family, 1)
                if left_free and right_free:
                    cables.append(lay((left_name, left_free[0]), (right_name, right_free[0])))
        if len(cables) == 1:
            # The member's own speed has no socket left -- on a 2960 both
            # gigabit ports are usually the two uplinks. A bundle can still be
            # built beside it out of two cables of a speed that does have room;
            # the original cable stays an ordinary trunk and loses its line.
            (left_name, _), (right_name, _) = cables[0]
            for family in ("GigabitEthernet", "FastEthernet"):
                left_free = free_ports(left_name, family, 2)
                right_free = free_ports(right_name, family, 2)
                if len(left_free) == 2 and len(right_free) == 2:
                    cables = [
                        lay((left_name, left_free[index]), (right_name, right_free[index]))
                        for index in range(2)
                    ]
                    break
        if len(cables) < 2:
            continue
        mode = stated[0][1]
        used = taken_channels.setdefault(pair[0], set()) | taken_channels.setdefault(pair[1], set())
        channel = next(
            number
            for number in [min(n for n, _ in stated), *range(1, 65)]
            if number not in used
        )
        taken_channels[pair[0]].add(channel)
        taken_channels[pair[1]].add(channel)
        for cable in cables:
            for end in cable:
                keep[end] = (channel, mode)
                if end in members:
                    continue
                # A port that was never a trunk -- either the far end of the
                # intent, or the one just cabled -- has to carry what the rest
                # of the bundle carries, or the two halves disagree.
                config = devices_by_name[end[0]].find("./ENGINE/RUNNINGCONFIG")
                if config is not None and body:
                    _set_config_block(config, f"interface {end[1]}", body)
                    drop_line(config, end[1], "switchport access vlan")
        notes.append(
            f"{pair[0]} <-> {pair[1]} bundled on Port-channel{channel} "
            f"({len(cables)} cables, mode {mode})"
        )

    for (name, port), (channel, mode) in sorted(keep.items()):
        device = devices_by_name.get(name)
        config = device.find("./ENGINE/RUNNINGCONFIG") if device is not None else None
        if config is None:
            continue
        _set_config_block(config, f"interface {port}", [f" channel-group {channel} mode {mode}"])
        body = trunk_body(name, port)
        if body:
            _set_config_block(config, f"interface Port-channel{channel}", body)

    removed = 0
    for name, device in sorted(devices_by_name.items()):
        if (device.findtext("./ENGINE/TYPE") or "") not in switch_types:
            continue
        for section in ("RUNNINGCONFIG", "STARTUPCONFIG"):
            config = device.find(f"./ENGINE/{section}")
            if config is None:
                continue
            current = ""
            doomed: list[ET.Element] = []
            for node in config.findall("LINE"):
                text = (node.text or "").strip()
                if text.startswith("interface "):
                    current = text.split(None, 1)[1]
                elif text.startswith("channel-group ") and (name, current) not in keep:
                    doomed.append(node)
            for node in doomed:
                if node in list(config):
                    config.remove(node)
            if doomed and section == "RUNNINGCONFIG":
                removed += len(doomed)
    if removed:
        notes.append(f"{removed} channel-group line(s) removed -- no bundle on the other end")
    return notes


def _match_trunk_native_vlans(root: ET.Element) -> list[str]:
    """Both ends of a trunk have to agree on the native VLAN.

    One end saying `switchport trunk native vlan 99` while the other says
    nothing -- which means VLAN 1 -- is a mismatch, and Packet Tracer does not
    let it pass quietly. Measured on the generated company lab, in SW2's own
    log:

        %CDP-4-NATIVE_VLAN_MISMATCH: ... Gi0/1 (99), with SW5 Fa0/2 (1)
        %SPANTREE-2-BLOCK_PVID_LOCAL: Blocking Gi0/1 on VLAN0099

    Spanning tree blocks the port, so the switch is cabled, configured, shown
    as up, and carrying nothing. Three of the four inter-switch trunks were
    like that: the access switches took `native vlan 99` from the plan and the
    core's side of the same cable was written by the uplink pass, which never
    mentioned a native VLAN.

    The end that names one wins, because that is the deliberate choice; VLAN 1
    is only ever the default nobody asked for.
    """
    devices = {
        (device.findtext("./ENGINE/SAVE_REF_ID") or "").strip(): device
        for device in root.findall(".//DEVICES/DEVICE")
    }
    switch_types = {"Switch", "MultiLayerSwitch"}

    def native_of(device: ET.Element, port: str) -> str:
        inside = False
        for node in device.findall("./ENGINE/RUNNINGCONFIG/LINE"):
            line = (node.text or "").strip()
            if line.startswith("interface "):
                inside = line == f"interface {port}"
            elif inside:
                match = re.match(r"^switchport trunk native vlan (\d+)$", line)
                if match:
                    return match.group(1)
        return ""

    notes: list[str] = []
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext(tag) or "").strip() for tag in ("FROM", "TO")]
        ports = [node.text or "" for node in cable.findall("PORT")]
        if len(ports) < 2:
            continue
        left, right = devices.get(refs[0]), devices.get(refs[1])
        if left is None or right is None:
            continue
        if (left.findtext("./ENGINE/TYPE") or "") not in switch_types:
            continue
        if (right.findtext("./ENGINE/TYPE") or "") not in switch_types:
            continue
        natives = [native_of(left, ports[0]), native_of(right, ports[1])]
        if natives[0] == natives[1]:
            continue
        wanted = natives[0] or natives[1]
        if not wanted:
            continue
        for device, port, current in ((left, ports[0], natives[0]), (right, ports[1], natives[1])):
            if current == wanted:
                continue
            config = device.find("./ENGINE/RUNNINGCONFIG")
            if config is None:
                continue
            _set_config_block(
                config,
                f"interface {port}",
                [" switchport mode trunk", f" switchport trunk native vlan {wanted}"],
            )
            notes.append(
                f"{device.findtext('./ENGINE/NAME') or ''}:{port} native VLAN "
                f"{current or '1'} -> {wanted}"
            )
    return notes


def _drop_inherited_sticky_macs(root: ET.Element) -> list[str]:
    """Remove sticky MAC addresses the donor's devices left behind.

    `switchport port-security mac-address sticky` is a directive: learn the
    address of whatever is plugged in. `... sticky 00E0.F925.3A9E` is the
    result of that learning on the donor's hardware, and a generated lab plugs
    a different device into the port. The address no longer matches, every
    frame is a violation, and `restrict` drops them all.

    Measured on the company lab the skill generated: PC1's port on SW1 carried
    the donor's learned address, PC2's port on SW2 carried none. PC2 reached
    its gateway and routed across VLANs; PC1 could not reach anything outside
    its own switch. Same generator, same prompt, one stale line apart.

    The directive stays -- port security is what the prompt asked for. Only the
    learned address goes, and Packet Tracer learns the new one on first frame.
    """
    dropped: list[str] = []
    for device in root.findall(".//DEVICES/DEVICE"):
        for section in ("RUNNINGCONFIG", "STARTUPCONFIG"):
            config = device.find(f"./ENGINE/{section}")
            if config is None:
                continue
            for node in list(config.findall("LINE")):
                text = (node.text or "").strip()
                if re.fullmatch(
                    r"switchport port-security mac-address sticky [0-9A-Fa-f.:-]{12,}", text
                ):
                    config.remove(node)
                    if section == "RUNNINGCONFIG":
                        dropped.append(f"{device.findtext('./ENGINE/NAME') or ''}: {text}")
    return dropped


def _router_subinterface_vlans(device: ET.Element, physical_port: str) -> list[str]:
    """VLANs the router carries as subinterfaces of `physical_port`."""
    vlans: list[str] = []
    on_port = False
    for node in device.findall("./ENGINE/RUNNINGCONFIG/LINE"):
        line = (node.text or "").strip()
        if line.startswith("interface "):
            name = line.split(None, 1)[1]
            on_port = name.startswith(f"{physical_port}.")
            continue
        if not on_port:
            continue
        match = re.match(r"^encapsulation dot1Q (\d+)", line)
        if match and match.group(1) not in vlans:
            vlans.append(match.group(1))
    return sorted(vlans, key=int)


def _move_subinterfaces_to_the_cabled_port(root: ET.Element) -> list[str]:
    """Put the router's dot1Q subinterfaces on the port the switch cable uses.

    Addressing writes the subinterfaces onto one interface while the link
    synthesiser and port reconciliation settle the cable onto another. Measured
    on a five-switch lab the skill generated: R1 carried
    `GigabitEthernet0/1.10` .. `.99` and its only cable ran from
    `GigabitEthernet0/0`. Packet Tracer showed one linked port and ten
    subinterfaces protocol-down, so every VLAN except the one the access port
    happened to be in was unreachable.

    The cable is the harder fact -- it exists in the topology and in Packet
    Tracer's own model -- so the configuration moves to meet it.
    """
    devices = {
        (device.findtext("./ENGINE/SAVE_REF_ID") or "").strip(): device
        for device in root.findall(".//DEVICES/DEVICE")
    }
    switch_types = {"Switch", "MultiLayerSwitch"}
    cabled_to_switch: dict[str, str] = {}
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext(tag) or "").strip() for tag in ("FROM", "TO")]
        ports = [node.text or "" for node in cable.findall("PORT")]
        if len(ports) < 2:
            continue
        for near, far in ((0, 1), (1, 0)):
            router = devices.get(refs[near])
            switch = devices.get(refs[far])
            if router is None or switch is None:
                continue
            if (router.findtext("./ENGINE/TYPE") or "") != "Router":
                continue
            if (switch.findtext("./ENGINE/TYPE") or "") in switch_types:
                cabled_to_switch.setdefault(refs[near], ports[near])

    notes: list[str] = []
    for ref, cabled_port in cabled_to_switch.items():
        router = devices[ref]
        configured = ""
        for node in router.findall("./ENGINE/RUNNINGCONFIG/LINE"):
            line = (node.text or "").strip()
            if not line.startswith("interface ") or "." not in line:
                continue
            parent = line.split(None, 1)[1].split(".", 1)[0]
            if parent != cabled_port and port_exists(router, parent):
                configured = parent
                break
        if not configured or not _router_subinterface_vlans(router, configured):
            continue
        for node in router.findall("./ENGINE/RUNNINGCONFIG/LINE"):
            line = (node.text or "")
            stripped = line.strip()
            if stripped.startswith(f"interface {configured}."):
                node.text = line.replace(f"interface {configured}.", f"interface {cabled_port}.", 1)
        notes.append(
            f"{router.findtext('./ENGINE/NAME') or ''}: subinterfaces moved from "
            f"{configured} to {cabled_port} (where the switch cable is)"
        )

    # Once the link is a trunk, an address on the physical port is unreachable:
    # every frame arrives tagged. Measured on the same lab -- VLAN 10's
    # subinterface carried `encapsulation dot1Q 10` and no address at all,
    # while `GigabitEthernet0/0` held 10.10.10.1, so VLAN 10 had no gateway.
    # Moved only when the pairing is unambiguous: one addressless subinterface
    # and one address stranded on its parent.
    for ref, cabled_port in cabled_to_switch.items():
        router = devices[ref]
        lines = list(router.findall("./ENGINE/RUNNINGCONFIG/LINE"))
        blocks: dict[str, list[ET.Element]] = {}
        current = ""
        for node in lines:
            text = (node.text or "").strip()
            if text.startswith("interface "):
                current = text.split(None, 1)[1]
                blocks.setdefault(current, [])
            elif current:
                blocks.setdefault(current, []).append(node)

        def address_node(name: str) -> ET.Element | None:
            for node in blocks.get(name, []):
                if (node.text or "").strip().startswith("ip address "):
                    return node
            return None

        parent_address = address_node(cabled_port)
        if parent_address is None:
            continue
        orphans = [
            name
            for name in blocks
            if name.startswith(f"{cabled_port}.") and address_node(name) is None
        ]
        if len(orphans) != 1:
            continue
        moved_text = (parent_address.text or "").strip()
        # The subinterface is addressless because it carries `no ip address`.
        # Leaving that line in place lets IOS apply the address and then wipe
        # it -- measured: VLAN 10's gateway read 0.0.0.0 in Packet Tracer while
        # the configuration plainly showed 10.10.10.1 three lines above.
        for node in list(blocks.get(orphans[0], [])):
            if (node.text or "").strip() == "no ip address":
                config_parent = router.find("./ENGINE/RUNNINGCONFIG")
                if config_parent is not None and node in list(config_parent):
                    config_parent.remove(node)
                blocks[orphans[0]].remove(node)
        blocks[orphans[0]].append(parent_address)
        config = router.find("./ENGINE/RUNNINGCONFIG")
        if config is None:
            continue
        index = list(config).index(parent_address)
        config.remove(parent_address)
        # After `encapsulation dot1Q`, not straight after the header. IOS
        # refuses an address on a subinterface that has no encapsulation yet,
        # and the refusal is silent in a saved file: measured, VLAN 10's
        # gateway read 0.0.0.0 in Packet Tracer while `ip address 10.10.10.1`
        # sat two lines above `encapsulation dot1Q 10`. The subinterfaces that
        # worked all carry the address after the encapsulation.
        anchor = next(
            (
                node
                for node in blocks.get(orphans[0], [])
                if (node.text or "").strip().startswith("encapsulation ")
            ),
            None,
        )
        if anchor is None:
            anchor = next(
                (
                    node
                    for node in config.findall("LINE")
                    if (node.text or "").strip() == f"interface {orphans[0]}"
                ),
                None,
            )
        if anchor is None:
            config.insert(index, parent_address)
            continue
        config.insert(list(config).index(anchor) + 1, parent_address)
        notes.append(
            f"{router.findtext('./ENGINE/NAME') or ''}: '{moved_text}' moved from "
            f"{cabled_port} to {orphans[0]}, which had none"
        )

    # A trunk parent cannot also be the WAN uplink. Pruning leaves the donor's
    # `ip nat outside` and its address on the physical interface, and once the
    # subinterfaces live there the same port is described as both sides of the
    # network at once: measured on the company lab, every subinterface came up
    # and no host could still reach its gateway.
    for ref, cabled_port in cabled_to_switch.items():
        router = devices[ref]
        if not _router_subinterface_vlans(router, cabled_port):
            continue
        config = router.find("./ENGINE/RUNNINGCONFIG")
        if config is None:
            continue
        inside = False
        for node in list(config.findall("LINE")):
            text = (node.text or "").strip()
            if text.startswith("interface "):
                inside = text == f"interface {cabled_port}"
                continue
            if not inside:
                continue
            if text in {"ip nat outside", "ip nat inside"} or text.startswith("ip address "):
                config.remove(node)
                notes.append(
                    f"{router.findtext('./ENGINE/NAME') or ''}: '{text}' removed from "
                    f"{cabled_port}, which is the trunk parent"
                )
    return notes


def _trunk_router_on_a_stick(root: ET.Element) -> list[str]:
    """A switch port facing router subinterfaces has to be a trunk.

    Measured on a five-switch lab the skill generated: R1 carried eight dot1Q
    subinterfaces for VLANs 10 to 99, and its single cable landed on an access
    port in VLAN 10. Packet Tracer reported one linked port on the router and
    every subinterface protocol-down, so no host could reach its gateway and
    nothing crossed a VLAN boundary -- while the lab opened and read correctly.

    The router's configuration is the statement of intent here: subinterfaces
    with `encapsulation dot1Q` mean the link is a trunk.
    """
    devices = {
        (device.findtext("./ENGINE/SAVE_REF_ID") or "").strip(): device
        for device in root.findall(".//DEVICES/DEVICE")
    }
    switch_types = {"Switch", "MultiLayerSwitch"}
    notes: list[str] = []
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext(tag) or "").strip() for tag in ("FROM", "TO")]
        ports = [node.text or "" for node in cable.findall("PORT")]
        if len(ports) < 2:
            continue
        for near, far in ((0, 1), (1, 0)):
            router = devices.get(refs[near])
            switch = devices.get(refs[far])
            if router is None or switch is None:
                continue
            if (router.findtext("./ENGINE/TYPE") or "") != "Router":
                continue
            if (switch.findtext("./ENGINE/TYPE") or "") not in switch_types:
                continue
            vlans = _router_subinterface_vlans(router, ports[near])
            if not vlans:
                continue
            config = switch.find("./ENGINE/RUNNINGCONFIG")
            if config is None:
                continue
            body = [" switchport mode trunk", f" switchport trunk allowed vlan {','.join(vlans)}"]
            if (switch.findtext("./ENGINE/TYPE") or "") == "MultiLayerSwitch":
                body.insert(0, " switchport trunk encapsulation dot1q")
            _set_config_block(config, f"interface {ports[far]}", body)
            notes.append(
                f"{switch.findtext('./ENGINE/NAME') or ''}:{ports[far]} -> trunk for VLAN "
                f"{','.join(vlans)} ({router.findtext('./ENGINE/NAME') or ''})"
            )
    return notes


def _vlan_subnets_from_router(root: ET.Element) -> dict[str, str]:
    """VLAN number -> the /24 its gateway sits in, read off the subinterfaces.

    A router-on-a-stick writes the mapping down: `encapsulation dot1Q 20`
    followed by `ip address 10.10.20.1` says VLAN 20 is 10.10.20.0. Nothing
    else in the file states it, and guessing it from the third octet only works
    for labs that happen to number that way.

    A router keeps subinterfaces the pruning left behind, so the same VLAN can
    appear twice with different addresses: one lab carried
    `GigabitEthernet0/0/0.20` on 192.168.20.1 from its donor alongside the live
    `GigabitEthernet0/1.20` on 10.10.20.1 -- and the stale one named an
    interface a 2911 does not even have. Only subinterfaces whose parent the
    device really owns are read.
    """
    subnets: dict[str, str] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        if (device.findtext("./ENGINE/TYPE") or "") != "Router":
            continue
        vlan = ""
        parent_is_real = False
        for node in device.findall("./ENGINE/RUNNINGCONFIG/LINE"):
            line = (node.text or "").strip()
            if line.startswith("interface "):
                name = line.split(None, 1)[1]
                parent_is_real = port_exists(device, name.split(".", 1)[0])
                vlan = ""
                continue
            if not parent_is_real:
                continue
            match = re.match(r"^encapsulation dot1Q (\d+)", line)
            if match:
                vlan = match.group(1)
                continue
            address = re.match(r"^ip address (\d+\.\d+\.\d+)\.\d+ ", line)
            if address and vlan:
                subnets[vlan] = address.group(1)
                vlan = ""
    return subnets


def _align_host_vlans_to_addresses(root: ET.Element) -> list[str]:
    """Put each host's access port in the VLAN its address belongs to.

    Addressing and VLAN assignment are decided by different passes, and nothing
    made them agree. Measured on a five-switch lab the skill generated: PC5 on
    10.10.10.12 sat in VLAN 30 while PC1 on 10.10.10.11 sat in VLAN 10 -- same
    subnet, different broadcast domains -- and PC2 on 10.10.20.11 sat in VLAN
    10. Six of twelve hosts were in the wrong VLAN for their address. The lab
    opened, every static check passed, and PC1 could not reach PC5.

    The same shape as every other defect here: two independent models of one
    concept that disagree where nothing looks.

    The address wins, because it is what the router's subinterfaces already
    agree with -- a host moved to another VLAN would need a new address, a new
    gateway, and a DHCP pool to match.
    """
    by_subnet = {subnet: vlan for vlan, subnet in _vlan_subnets_from_router(root).items()}

    devices = {
        (device.findtext("./ENGINE/SAVE_REF_ID") or "").strip(): device
        for device in root.findall(".//DEVICES/DEVICE")
    }
    switch_types = {"Switch", "MultiLayerSwitch"}

    def host_subnet(device: ET.Element) -> str:
        for node in device.iter():
            text = (node.text or "").strip()
            if node.tag.upper() in {"IP", "IPADDRESS", "ADDRESS"} and re.fullmatch(
                r"\d+\.\d+\.\d+\.\d+", text
            ):
                return text.rsplit(".", 1)[0]
        return ""

    def current_vlan(switch: ET.Element, port: str) -> str:
        inside = False
        for node in switch.findall("./ENGINE/RUNNINGCONFIG/LINE"):
            line = (node.text or "").strip()
            if line.startswith("interface "):
                inside = line == f"interface {port}"
            elif inside and line.startswith("switchport access vlan "):
                return line.split()[-1]
        return ""

    attachments: list[tuple[ET.Element, str, ET.Element, str]] = []
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext(tag) or "").strip() for tag in ("FROM", "TO")]
        ports = [node.text or "" for node in cable.findall("PORT")]
        if len(ports) < 2:
            continue
        for near, far in ((0, 1), (1, 0)):
            host = devices.get(refs[near])
            switch = devices.get(refs[far])
            if host is None or switch is None:
                continue
            if (switch.findtext("./ENGINE/TYPE") or "") not in switch_types:
                continue
            # Saved files spell it `Pc`; `HOST_DEVICE_KINDS` holds `PC`. Asking
            # without normalising skipped every PC in the lab and left eight of
            # fourteen hosts unexamined.
            if not _is_host_device(
                {"type": _normalize_device_type(host.findtext("./ENGINE/TYPE") or "")}
            ):
                continue
            subnet = host_subnet(host)
            if subnet:
                attachments.append((host, subnet, switch, ports[far]))

    # A subnet the router does not map still has to end up in one VLAN, or its
    # hosts cannot reach each other. The VLAN most of them already sit in is
    # the one that needs the fewest ports moved.
    votes: dict[str, Counter[str]] = {}
    for _host, subnet, switch, port in attachments:
        vlan = current_vlan(switch, port)
        if vlan:
            votes.setdefault(subnet, Counter())[vlan] += 1
    wanted_for: dict[str, str] = {}
    for _host, subnet, _switch, _port in attachments:
        if subnet in wanted_for:
            continue
        chosen = by_subnet.get(subnet)
        if not chosen and subnet in votes:
            chosen = votes[subnet].most_common(1)[0][0]
        if chosen:
            wanted_for[subnet] = chosen

    notes: list[str] = []
    for host, subnet, switch, port in attachments:
        wanted = wanted_for.get(subnet)
        if not wanted or current_vlan(switch, port) == wanted:
            continue
        config = switch.find("./ENGINE/RUNNINGCONFIG")
        if config is None:
            continue
        _set_config_block(
            config,
            f"interface {port}",
            [" switchport mode access", f" switchport access vlan {wanted}"],
        )
        notes.append(
            f"{switch.findtext('./ENGINE/NAME') or ''}:{port} -> VLAN {wanted} "
            f"({host.findtext('./ENGINE/NAME') or ''})"
        )
    return notes


def _align_router_gateway(root: ET.Element) -> list[str]:
    """Put the hosts' gateway address on the router interface they reach it by.

    Host addressing is decided while planning, from the router interface the
    plan plugs into the switch. Port reconciliation then moves that cable: the
    plan had GigabitEthernet0/0/0, carrying 192.168.1.1, and the finished lab
    ran the cable from GigabitEthernet0/0/2, carrying 192.168.3.1. Hosts were
    addressed 192.168.1.x with a gateway that existed, on an interface attached
    to nothing.

    Adjusting the hosts to follow the cable was the first attempt and it did
    nothing, because at planning time the two still agreed. The cabling is what
    changes last, so the address has to follow it: whichever interface ends up
    facing the switch is given the gateway the hosts were told to use.
    """
    devices = {
        (device.findtext("./ENGINE/SAVE_REF_ID") or ""): device
        for device in root.findall(".//DEVICES/DEVICE")
    }
    kinds = {
        ref: (device.findtext("./ENGINE/TYPE") or "") for ref, device in devices.items()
    }

    gateways = [
        (port.findtext("PORT_GATEWAY") or "").strip()
        for device in devices.values()
        if (device.findtext("./ENGINE/TYPE") or "") in {"Pc", "PC"}
        for port in device.findall("./ENGINE/MODULE/SLOT/MODULE/PORT")
    ]
    gateway = next((value for value in gateways if value and value != "0.0.0.0"), "")
    if not gateway:
        return []

    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext("FROM") or "").strip(), (cable.findtext("TO") or "").strip()]
        ports = [node.text or "" for node in cable.findall("PORT")]
        for router_index, switch_index in ((0, 1), (1, 0)):
            if kinds.get(refs[router_index]) != "Router":
                continue
            if kinds.get(refs[switch_index]) not in {"Switch", "MultiLayerSwitch"}:
                continue
            router = devices[refs[router_index]]
            config = router.find("./ENGINE/RUNNINGCONFIG")
            if config is None:
                continue
            # Another interface may already hold an address in this subnet --
            # the one the plan originally chose. Two interfaces on one router
            # cannot share a subnet, so the stale one gives up its address.
            prefix = gateway.rsplit(".", 1)[0]
            lines = [(line.text or "") for line in config.findall("LINE")]
            cleared: list[str] = []
            for index, line in enumerate(lines):
                match = re.match(r"interface ((?:Gigabit|Fast)Ethernet\S*)\s*$", line.strip())
                if not match or match.group(1) == ports[router_index]:
                    continue
                cursor = index + 1
                while cursor < len(lines) and lines[cursor].startswith(" "):
                    address = re.match(
                        r"ip address (\d+\.\d+\.\d+\.\d+) ", lines[cursor].strip()
                    )
                    if address and address.group(1).rsplit(".", 1)[0] == prefix:
                        cleared.append(match.group(1))
                        break
                    cursor += 1
            for interface in cleared:
                _set_config_block(config, f"interface {interface}", [" no ip address"])

            _set_config_block(
                config,
                f"interface {ports[router_index]}",
                [f" ip address {gateway} 255.255.255.0", " no shutdown"],
            )
            name = router.findtext("./ENGINE/NAME") or ""
            note = f"{name}: {ports[router_index]} set to {gateway} (gateway the hosts use)"
            if cleared:
                note += f"; cleared overlapping address on {', '.join(cleared)}"
            return [note]
    return []


_SVI_ADDRESS_PATTERN = re.compile(r"^ip address (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)$")


def _address_to_int(address: str) -> int | None:
    parts = address.split(".")
    if len(parts) != 4:
        return None
    value = 0
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return None
        value = (value << 8) | int(part)
    return value


def _same_subnet(left: str, right: str, mask: str) -> bool:
    left_value = _address_to_int(left)
    right_value = _address_to_int(right)
    mask_value = _address_to_int(mask)
    if left_value is None or right_value is None or mask_value is None:
        return False
    return left_value & mask_value == right_value & mask_value


def _align_dhcp_pools_with_interfaces(root: ET.Element) -> list[str]:
    """Point a DHCP pool at a network the router is actually on.

    The pool was emitted with a hardcoded 192.168.1.0/24 whatever the lab's
    addressing turned out to be. Measured on `router_dhcp`: the router's LAN
    interface is 1.1.1.1/24, the hosts sit on 1.1.1.0/24 with DHCP enabled, and
    the pool served 192.168.1.0/24 -- a network that exists nowhere in the lab.
    A request arriving on the LAN interface matches no pool, so nothing is ever
    handed out. The lab has DHCP configured and DHCP does not work.

    The same shape as the rest of this file's repairs: the host segment and the
    pool's network were computed independently and disagreed.

    Only pools that serve none of their own router's interfaces are touched. A
    donor's own pool, matching a donor interface, is left exactly as it was.
    """
    repaired: list[str] = []
    for device in root.findall(".//DEVICES/DEVICE"):
        if (device.findtext("./ENGINE/TYPE") or "").strip() != "Router":
            continue
        config = device.find("./ENGINE/RUNNINGCONFIG")
        if config is None:
            continue
        lines = config.findall("LINE")

        interfaces: list[tuple[str, str]] = []
        current_header = ""
        for line in lines:
            text = (line.text or "").rstrip()
            stripped = text.strip()
            if not text.startswith((" ", "\t")):
                current_header = stripped
                continue
            if current_header.startswith("interface ") and stripped.startswith("ip address "):
                parts = stripped.split()
                if len(parts) == 4:
                    interfaces.append((parts[2], parts[3]))
        if not interfaces:
            continue

        # A pool serves a LAN. A /30 is a router-to-router link and never has a
        # client on it, so it must not be offered as a home for a pool that has
        # nowhere else to go: measured, a workstation was handed 200.10.0.1/30
        # -- the ISP's own WAN address -- and two more got /30 masks on a /24
        # segment, because the search took the first free interface of any
        # shape.
        lan_interfaces = [
            (address, mask)
            for address, mask in interfaces
            if (_address_to_int(mask) or 0) <= _address_to_int("255.255.255.0")
        ]

        pools: list[tuple[str, ET.Element, ET.Element | None, list[ET.Element]]] = []
        pool_name = ""
        network_node: ET.Element | None = None
        gateway_node: ET.Element | None = None
        block: list[ET.Element] = []
        for line in lines:
            text = (line.text or "").rstrip()
            stripped = text.strip()
            if not text.startswith((" ", "\t")):
                if pool_name and network_node is not None:
                    pools.append((pool_name, network_node, gateway_node, block))
                pool_name = stripped[len("ip dhcp pool ") :] if stripped.startswith("ip dhcp pool ") else ""
                network_node = None
                gateway_node = None
                block = [line] if pool_name else []
                continue
            if not pool_name:
                continue
            block.append(line)
            if stripped.startswith("network "):
                network_node = line
            elif stripped.startswith("default-router "):
                gateway_node = line
        if pool_name and network_node is not None:
            pools.append((pool_name, network_node, gateway_node, block))

        for name, network_line, gateway_line, block in pools:
            parts = (network_line.text or "").split()
            if len(parts) != 3:
                continue
            network, mask = parts[1], parts[2]
            if any(_same_subnet(address, network, mask) for address, _ in interfaces):
                continue
            served = {
                (address, interface_mask)
                for other_name, other_network, _gateway, _block in pools
                if other_name != name
                for address, interface_mask in lan_interfaces
                if _same_subnet(address, (other_network.text or "").split()[1], interface_mask)
            }
            replacement = next((pair for pair in lan_interfaces if pair not in served), None)
            if replacement is None:
                # More pools than LANs to serve. A pool with nowhere to live is
                # not harmless: left pointing at a link, it hands a workstation
                # the address of a router-to-router segment.
                for node in block:
                    if node in list(config):
                        config.remove(node)
                repaired.append(
                    f"{device.findtext('./ENGINE/NAME') or ''}: pool {name} removed, "
                    f"no LAN left for it to serve"
                )
                continue
            address, interface_mask = replacement
            address_value = _address_to_int(address)
            mask_value = _address_to_int(interface_mask)
            if address_value is None or mask_value is None:
                continue
            base = address_value & mask_value
            base_text = ".".join(str((base >> shift) & 0xFF) for shift in (24, 16, 8, 0))
            network_line.text = f" network {base_text} {interface_mask}"
            if gateway_line is not None:
                gateway_line.text = f" default-router {address}"
            repaired.append(
                f"{device.findtext('./ENGINE/NAME') or ''}: pool {name} {network} -> {base_text}"
            )
    return repaired


def _link_device_pairs(root: ET.Element) -> list[tuple[str, str]]:
    """Every cable in the file, as the two device names it joins.

    Endpoints come in two spellings. Most donors give devices a `SAVE_REF_ID`
    and links refer to that; some do not, and then a link addresses its
    endpoints by position in the DEVICES list. Anything reading the wiring has
    to handle both, which is why this is shared rather than written out again at
    each call site.
    """
    order: list[str] = []
    by_ref: dict[str, str] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = (device.findtext("./ENGINE/NAME") or "").strip()
        order.append(name)
        ref = (device.findtext("./ENGINE/SAVE_REF_ID") or "").strip()
        if ref:
            by_ref[ref] = name

    def resolve(value: str) -> str:
        value = value.strip()
        if value in by_ref:
            return by_ref[value]
        if value.isdigit() and int(value) < len(order):
            return order[int(value)]
        return ""

    pairs: list[tuple[str, str]] = []
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        left = resolve(cable.findtext("FROM", default=""))
        right = resolve(cable.findtext("TO", default=""))
        if left and right:
            pairs.append((left, right))
    return pairs


def _save_running_config_to_startup(root: ET.Element) -> list[str]:
    """Save each device's configuration, the way `write memory` would.

    Reported from a screenshot of a generated lab: opening a switch's CLI shows
    the boot sequence ending at "Press RETURN to get started!", with no
    hostname and no configuration -- while the interfaces the lab wired come up
    fine. A device applies its *startup* config when it boots, and the generated
    labs left that empty: 82 devices across the corpus had a running config and
    no saved one, so every one of them booted blank.

    The note on `_config_targets` explains why the editor refuses to write into
    an empty startup config: it used to add only the new lines, which turned a
    router's saved configuration into the three lines someone had just added, so
    a reload wiped every interface. It also names the right answer, which is
    this one -- copy the whole running config rather than a stub.

    A donor that already saved something used to keep it, which was wrong for a
    different reason than the empty case. Measured on a WAN lab: the router's
    saved configuration still carried the donor's addressing --
    `ip address 170.18.10.33` and `shutdown` -- while generation had given the
    running config `ip address 170.18.10.1` and `no shutdown`. The device would
    have reverted to the donor's network on reload. Whatever a donor saved
    describes the donor's lab, not this one, so the running config wins
    outright.
    """
    saved: list[str] = []
    for device in root.findall(".//DEVICES/DEVICE"):
        running = device.find("./ENGINE/RUNNINGCONFIG")
        startup = device.find("./ENGINE/STARTUPCONFIG")
        if running is None or startup is None:
            continue
        running_lines = running.findall("LINE")
        if not running_lines:
            continue
        existing = [(line.text or "") for line in startup.findall("LINE")]
        wanted = [(line.text or "") for line in running_lines]
        if existing == wanted:
            continue
        for stale in list(startup):
            startup.remove(stale)
        for line in running_lines:
            copied = ET.SubElement(startup, "LINE")
            copied.text = line.text
        saved.append(f"{device.findtext('./ENGINE/NAME') or ''}: {len(running_lines)} line(s)")
    return saved


def _next_free_address(address: str, taken: set[str]) -> str:
    """The next address on the same subnet that nothing else is using."""
    head, _, last = address.rpartition(".")
    try:
        start = int(last)
    except ValueError:
        return ""
    for step in range(1, 254):
        candidate = f"{head}.{((start + step - 1) % 254) + 1}"
        if candidate not in taken:
            return candidate
    return ""


def _assign_unique_interface_addresses(root: ET.Element) -> list[str]:
    """Stop two devices from answering to the same address.

    A cloned device is a deep copy, so it arrives holding the prototype's
    interface addresses. Measured across the corpus: 7 of 32 labs carried a
    duplicate. `multiarea_ospf` had R1, R2 and R3 all on 192.168.1.1, .2.1 and
    .3.1; `router_dhcp` had three PCs all on 1.1.1.3.

    The same defect as the MAC addresses and the switch management addresses,
    one layer out, and it is the reason those were fixed here too: cloning
    happens on several paths and the written file is where they all meet.

    A device's address lives in two places at once -- the PORT node and the
    `ip address` line in its configuration -- so both are moved together.
    Anything else leaves the device disagreeing with itself. The first holder
    keeps the address, so the gateway hosts were told to use stays put.
    """
    taken: set[str] = set()
    renumbered: list[str] = []
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME") or ""
        for port in device.iter("PORT"):
            node = port.find("IP")
            address = (node.text or "").strip() if node is not None else ""
            if not address or address == "0.0.0.0":
                continue
            if address not in taken:
                taken.add(address)
                continue
            candidate = _next_free_address(address, taken)
            if not candidate:
                continue
            taken.add(candidate)
            node.text = candidate
            # The configuration carries the same address; leaving it behind
            # would make `show running-config` disagree with the interface.
            for tag in ("RUNNINGCONFIG", "STARTUPCONFIG"):
                config = device.find(f"./ENGINE/{tag}")
                if config is None:
                    continue
                for line in config.findall("LINE"):
                    match = _SVI_ADDRESS_PATTERN.match((line.text or "").strip())
                    if match is not None and match.group(1) == address:
                        line.text = f"ip address {candidate} {match.group(2)}"
            renumbered.append(f"{name}: {address} -> {candidate}")
    return renumbered


# How far apart two device icons have to be before they stop reading as one.
# The generator already spaces hosts 130 apart, so this is a floor rather than a
# grid: it moves what collides and leaves everything else where it was put.
LOGICAL_ICON_SPACING = 110
# Spare donor devices are deliberately parked far off-canvas, in their own grid.
PARKED_LOGICAL_X = 9000


def _group_hosts_under_their_switch(root: ET.Element) -> list[str]:
    """Lay each switch's hosts out beneath it, one block per switch.

    Hosts were placed in a single row across the lab regardless of which switch
    they were cabled to. Measured on `four_switch`: SW1's three hosts sat at x
    180, 570 and 950 with other blocks' hosts between them, so no rectangle
    could frame a block without swallowing its neighbours -- one box held two
    switches and hosts belonging to both.

    A reader follows the cables with their eyes, and crossing them for no reason
    is what makes a generated lab look like a tangle. Blocks are laid out left
    to right in the order the switches already appear, so the shape the topology
    chose is kept; only the hosts move.

    Routers, the core, and anything not cabled to an access switch are left
    where they are: they sit above this row and the reader expects them there.
    """
    kinds: dict[str, str] = {}
    nodes: dict[str, tuple[ET.Element, ET.Element]] = {}
    position: dict[str, tuple[float, float]] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = (device.findtext("./ENGINE/NAME") or "").strip()
        x_node = device.find("./WORKSPACE/LOGICAL/X")
        y_node = device.find("./WORKSPACE/LOGICAL/Y")
        if not name or x_node is None or y_node is None:
            continue
        try:
            x = float((x_node.text or "").strip())
            y = float((y_node.text or "").strip())
        except ValueError:
            continue
        if x >= PARKED_LOGICAL_X:
            continue
        kinds[name] = (device.findtext("./ENGINE/TYPE") or "").strip()
        nodes[name] = (x_node, y_node)
        position[name] = (x, y)

    host_kinds = {"PC", "Pc", "PcPT", "Server", "ServerPT", "Printer", "Laptop", "IpPhone", "HomeVoip"}
    switch_kinds = {"Switch", "MultiLayerSwitch"}
    blocks: dict[str, list[str]] = {}
    for left, right in _link_device_pairs(root):
        for host, switch in ((left, right), (right, left)):
            if kinds.get(host) in host_kinds and kinds.get(switch) in switch_kinds:
                blocks.setdefault(switch, [])
                if host not in blocks[switch]:
                    blocks[switch].append(host)
                break

    blocks = {name: members for name, members in blocks.items() if members}
    if len(blocks) < 2:
        return []

    ordered = sorted(blocks, key=lambda name: position[name][0])
    host_row = max(position[host][1] for members in blocks.values() for host in members)
    moved: list[str] = []
    cursor = min(position[name][0] for name in ordered) - LOGICAL_ICON_SPACING

    for switch_name in ordered:
        members = sorted(blocks[switch_name], key=lambda name: _name_sort_key(name))
        width = max(len(members) - 1, 0) * LOGICAL_ICON_SPACING
        start = cursor + LOGICAL_ICON_SPACING
        for index, host in enumerate(members):
            target = (start + index * LOGICAL_ICON_SPACING, host_row)
            if position[host] == target:
                continue
            x_node, y_node = nodes[host]
            x_node.text = str(int(target[0]))
            y_node.text = str(int(target[1]))
            moved.append(f"{host}: -> {switch_name} block")
            position[host] = target
        # The switch sits centred over the hosts it serves, so the block reads
        # as one shape rather than a row with a label somewhere off to the side.
        centre = start + width / 2
        x_node, y_node = nodes[switch_name]
        x_node.text = str(int(centre))
        position[switch_name] = (centre, position[switch_name][1])
        cursor = start + width + LOGICAL_ICON_SPACING
    return moved


# How far a cable-less leftover may sit outside the wired lab before it is
# pulled in. Wide enough that a device merely sitting at the edge is left alone.
STRAY_DEVICE_MARGIN = 400


def _adopt_planned_names(root: ET.Element, blueprint: dict[str, object]) -> list[str]:
    """Give a device the plan's name when it is doing the plan's job.

    Four corpus labs came out one device short of their blueprint, always the
    last switch. The device was never missing. `hosts_across_switches` planned
    `SW1, SW2, SW3` and the file held `SW1`, `SW2` and `MultiLayerSwitch1` --
    and that third switch is the core of the topology: the router connects to
    it, and it connects to the other two. It had simply kept the donor's name.

    Whether the rename lands depends on the donor. Applying the same plan
    against `Senan_K231.pkt` by hand produced `SW3` correctly; the donor the
    corpus picked has its own `MultiLayerSwitch` devices, and one of them was
    reused without being renamed.

    So rather than chase the donor-specific path, the name is adopted here: a
    device the plan did not name, of the kind the plan is missing, and already
    cabled into the lab, takes the missing name. Cabled matters -- an idle
    spare parked off to the side is not doing the job the plan described, and
    handing it the name would produce a lab whose `SW3` connects to nothing.
    """
    planned_names: list[str] = []
    for device in blueprint.get("devices", []):
        name = str(device.get("name") or "").strip()
        if name:
            planned_names.append(name)
    if not planned_names:
        return []

    by_name: dict[str, ET.Element] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = (device.findtext("./ENGINE/NAME") or "").strip()
        if name:
            by_name[name] = device

    missing = [name for name in planned_names if name not in by_name]
    if not missing:
        return []

    cabled = {name for pair in _link_device_pairs(root) for name in pair}
    spare = [
        name
        for name in by_name
        if name not in planned_names and name in cabled
    ]
    if not spare:
        return []

    def family(kind: str) -> str:
        lowered = kind.lower()
        if "switch" in lowered:
            return "switch"
        if "router" in lowered:
            return "router"
        return lowered

    adopted: list[str] = []
    for wanted in missing:
        wanted_family = family(_device_kind_of_blueprint(blueprint, wanted))
        if not wanted_family:
            continue
        match = next(
            (
                name
                for name in spare
                if family((by_name[name].findtext("./ENGINE/TYPE") or "").strip()) == wanted_family
            ),
            None,
        )
        if match is None:
            continue
        spare.remove(match)
        device = by_name.pop(match)
        name_node = device.find("./ENGINE/NAME")
        if name_node is None:
            continue
        name_node.text = wanted
        by_name[wanted] = device
        _align_hostname_with_name(device, wanted)
        adopted.append(f"{match} answers to {wanted}, the name the plan gave its job")
    return adopted


def _report_unwired_devices(root: ET.Element, blueprint: dict[str, object]) -> list[str]:
    """Name any requested device that arrived with no cable on it.

    `1 router 1 switch 3 komputer ve 1 firewall qur` produces a lab holding an
    ASA, and Packet Tracer opens it, and the ASA is connected to nothing. The
    same is true of a requested patch panel. The device count is right, the file
    is valid, and the thing the prompt asked for does not participate in the
    network.

    The link synthesiser cables the kinds in `HOST_DEVICE_KINDS`, each with a
    port name measured off real donor cables rather than taken from the device
    palette. Extending it to these kinds needs the same evidence, and the
    measurement says it is not there yet: across 150 labs, ASA cables use
    `Ethernet0/0` on a 5505 while the palette reports `GigabitEthernet1/1` for
    the 5506-X, and patch panels, bridges, repeaters and wired end devices carry
    no cable at all in any of them. Guessing one constant per kind is how a
    hardcoded port name gets into the file, which is the defect this project
    spent a long time removing.

    So the gap is reported rather than papered over. A lab whose firewall is
    unplugged should say so.
    """
    requested = {
        str(device.get("name") or "").strip(): str(device.get("type") or "").strip()
        for device in blueprint.get("devices", [])
        if str(device.get("name") or "").strip()
    }
    if not requested:
        return []
    present = {
        (device.findtext("./ENGINE/NAME") or "").strip()
        for device in root.findall(".//DEVICES/DEVICE")
    }
    cabled = {name for pair in _link_device_pairs(root) for name in pair}
    # A lab with no cables at all is a wireless scenario, not a wiring failure.
    if not cabled:
        return []
    stranded = sorted(
        name for name in requested if name in present and name not in cabled
    )
    if not stranded:
        return []
    described = ", ".join(f"{name} ({requested[name]})" if requested[name] else name for name in stranded[:6])
    if len(stranded) > 6:
        described += f", and {len(stranded) - 6} more"
    return [f"WARNING: {len(stranded)} requested device(s) have no cable: {described}"]


def _report_undelivered_devices(root: ET.Element, blueprint: dict[str, object]) -> list[str]:
    """Name any device the plan asked for that is not in the written file.

    Generation reported success for `2 router serial WAN, 2 switch, 8 komputer,
    1 server`: the blueprint held thirteen devices and the file held three, with
    the eight PCs and the server simply absent. Nothing said so. Silence is the
    worst of the three outcomes here -- a refusal explains itself, a working lab
    needs no explanation, and a lab quietly missing most of what was asked for
    looks like the tool worked.

    Auditing the corpus found four labs short by one device each, always a
    switch, and always one that kept its donor name instead of being renamed.
    That number moves with donor selection, so this reports rather than refuses:
    failing labs that open and mostly serve the prompt would cost more than it
    saves. The point is that the gap is now visible on every run.
    """
    planned = {
        str(device.get("name")).strip()
        for device in blueprint.get("devices", [])
        if str(device.get("name") or "").strip()
    }
    if not planned:
        return []
    present = {
        (device.findtext("./ENGINE/NAME") or "").strip()
        for device in root.findall(".//DEVICES/DEVICE")
    }
    missing = sorted(planned - present)
    if not missing:
        return []
    shown = ", ".join(missing[:8])
    if len(missing) > 8:
        shown += f", and {len(missing) - 8} more"
    return [
        f"WARNING: {len(missing)} of {len(planned)} planned device(s) are not in the file: {shown}"
    ]


def _compact_stray_devices(root: ET.Element) -> list[str]:
    """Pull cable-less donor leftovers back beside the lab that was asked for.

    Every corpus lab measured between 2440 and 2550 units wide, including
    `minimal`, which is one router, one switch and three PCs. Those five sit in
    340 units; the width came from two `Power Distribution Device` nodes still
    at their donor coordinates, x=2620 and x=2730, roughly 2100 units to the
    right of anything cabled. Packet Tracer shows about 1500 units at the
    default zoom, so the lab opened on an empty patch of canvas with the real
    topology off to the left.

    They are not pruned here. They came with the donor, nothing is wired to
    them, and removing devices is the kind of change that has broken donor
    coherence before. Moving them is enough: the canvas shrinks to the lab.

    A lab with fewer than two cabled devices has no bounding box worth
    speaking of -- the wireless scenarios have no cables at all -- so those are
    left exactly as they are.
    """
    positions: dict[str, tuple[ET.Element, ET.Element, float, float]] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = (device.findtext("./ENGINE/NAME") or "").strip()
        x_node = device.find("./WORKSPACE/LOGICAL/X")
        y_node = device.find("./WORKSPACE/LOGICAL/Y")
        if not name or x_node is None or y_node is None:
            continue
        try:
            x = float((x_node.text or "").strip())
            y = float((y_node.text or "").strip())
        except ValueError:
            continue
        if x >= PARKED_LOGICAL_X:
            continue
        positions[name] = (x_node, y_node, x, y)

    cabled = {name for pair in _link_device_pairs(root) for name in pair}
    anchored = [positions[name] for name in cabled if name in positions]
    if len(anchored) < 2:
        return []

    right = max(entry[2] for entry in anchored)
    top = min(entry[3] for entry in anchored)
    bottom = max(entry[3] for entry in anchored)

    strays = sorted(
        (name for name, entry in positions.items() if name not in cabled and entry[2] > right + STRAY_DEVICE_MARGIN),
        key=lambda name: positions[name][2],
    )
    moved: list[str] = []
    for index, name in enumerate(strays):
        x_node, y_node, _, _ = positions[name]
        x = int(right + 140 + (index % 2) * 120)
        y = int(top + (index // 2) * 110)
        if y > bottom:
            y = int(bottom)
        x_node.text = str(x)
        y_node.text = str(y)
        moved.append(f"{name}: pulled beside the lab at {x},{y}")
    return moved


def _separate_overlapping_devices(root: ET.Element) -> list[str]:
    """Move devices that were placed on top of each other.

    Measured across the corpus: 22 of 32 labs had at least one overlapping pair,
    and several were exactly coincident. Three separate causes, all landing in
    the same place -- a lab that looks like a tangle:

    - every Power Distribution Device is kept at one hardcoded point, so a donor
      carrying two stacks them precisely;
    - a duplicated host or group inherits coordinates from its source, which is
      how `PC3` and `PC6` ended up at the same pixel;
    - routers matched one-to-one can be handed the same target position.

    Fixed here rather than at each source for the reason the other file-level
    passes exist: the placements come from several paths and the written file is
    where they all meet. It runs before the annotation pass so the group boxes
    are drawn around where the devices actually end up.
    """

    def too_close(x: float, y: float, placed: list[tuple[float, float]]) -> bool:
        return any(
            math.hypot(x - other_x, y - other_y) < LOGICAL_ICON_SPACING
            for other_x, other_y in placed
        )

    placed: list[tuple[float, float]] = []
    moved: list[str] = []
    for device in root.findall(".//DEVICES/DEVICE"):
        x_node = device.find("./WORKSPACE/LOGICAL/X")
        y_node = device.find("./WORKSPACE/LOGICAL/Y")
        if x_node is None or y_node is None:
            continue
        try:
            x = float((x_node.text or "").strip())
            y = float((y_node.text or "").strip())
        except ValueError:
            continue
        if x >= PARKED_LOGICAL_X:
            continue
        if not too_close(x, y, placed):
            placed.append((x, y))
            continue

        name = device.findtext("./ENGINE/NAME") or ""
        spot: tuple[float, float] | None = None
        for ring in range(1, 10):
            for step_x, step_y in ((1, 0), (0, 1), (-1, 0), (0, -1), (1, 1), (1, -1), (-1, 1), (-1, -1)):
                candidate_x = x + step_x * ring * LOGICAL_ICON_SPACING
                candidate_y = y + step_y * ring * LOGICAL_ICON_SPACING
                if candidate_x < 60 or candidate_y < 60 or candidate_x >= PARKED_LOGICAL_X:
                    continue
                if not too_close(candidate_x, candidate_y, placed):
                    spot = (candidate_x, candidate_y)
                    break
            if spot is not None:
                break
        if spot is None:
            placed.append((x, y))
            continue
        x_node.text = str(int(spot[0]))
        y_node.text = str(int(spot[1]))
        placed.append(spot)
        moved.append(f"{name}: ({x:.0f},{y:.0f}) -> ({spot[0]:.0f},{spot[1]:.0f})")
    return moved


def _assign_unique_switch_management_ips(root: ET.Element) -> list[str]:
    """Give every switch its own management address.

    A duplicated switch is a deep copy, so it inherits the prototype's `Vlan1`
    address along with everything else. Measured on `4 switch 1 router 8
    komputer`: SW1, SW3 and MultiLayerSwitch1 all answered to 2.1.1.6, and
    Packet Tracer's own health check reported the collision.

    Nothing else catches it. The lab opens, every host pings every other host,
    and the duplicate only bites whoever tries to manage the switches -- which
    is exactly the kind of fault that survives a green test suite. It is fixed
    here, at the file level, for the same reason MAC uniqueness is: cloning
    happens on several paths and the file is the one place they all meet.

    Only the host part is changed, so the address stays on the subnet the donor
    put it on, and every address already in the lab is avoided -- including the
    hosts', which sit in the same range.
    """
    taken: set[str] = set()
    for device in root.findall(".//DEVICES/DEVICE"):
        for port in device.iter("PORT"):
            address = (port.findtext("IP") or "").strip()
            if address:
                taken.add(address)

    renumbered: list[str] = []
    seen: set[str] = set()
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME") or ""
        for tag in ("RUNNINGCONFIG", "STARTUPCONFIG"):
            config = device.find(f"./ENGINE/{tag}")
            if config is None:
                continue
            inside_svi = False
            for line in config.findall("LINE"):
                text = (line.text or "").strip()
                if text.startswith("interface "):
                    inside_svi = text.lower().startswith("interface vlan")
                    continue
                if not inside_svi:
                    continue
                match = _SVI_ADDRESS_PATTERN.match(text)
                if match is None:
                    continue
                address, mask = match.group(1), match.group(2)
                if address not in seen and address not in taken:
                    seen.add(address)
                    taken.add(address)
                    continue
                head, _, last = address.rpartition(".")
                try:
                    start = int(last)
                except ValueError:
                    continue
                candidate = ""
                for step in range(1, 254):
                    value = ((start + step - 1) % 254) + 1
                    trial = f"{head}.{value}"
                    if trial not in taken:
                        candidate = trial
                        break
                if not candidate:
                    continue
                seen.add(candidate)
                taken.add(candidate)
                line.text = f"ip address {candidate} {mask}"
                renumbered.append(f"{name}: Vlan management {address} -> {candidate}")
    return renumbered


def _match_link_port_families(root: ET.Element) -> list[str]:
    """A cable's two ends must be the same kind of socket.

    `_reconcile_cable_media` settles what the cable *is*; this settles what it
    lands on. Measured once a serial-capable donor was finally reachable: the
    port repair moved one end of the WAN to `Serial3/0` and the other to
    `FastEthernet1/0`, and Packet Tracer refused the file. Demoting the cable to
    copper does not help -- copper between a serial socket and an Ethernet one
    is no more real than serial was.

    A mismatch is resolved towards serial when the other device has a free
    serial interface, since a serial link is what was asked for, and away from
    it otherwise. Both directions keep the pair consistent, which is the whole
    requirement.
    """
    device_order = list(root.findall(".//DEVICES/DEVICE"))
    device_by_ref: dict[str, ET.Element] = {}
    for index, device in enumerate(device_order):
        ref = (device.findtext("./ENGINE/SAVE_REF_ID") or "").strip()
        if ref:
            device_by_ref[ref] = device
        device_by_ref.setdefault(str(index), device)

    used: set[tuple[str, str]] = set()
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext("FROM") or "").strip(), (cable.findtext("TO") or "").strip()]
        for ref, node in zip(refs, cable.findall("PORT")):
            used.add((ref, node.text or ""))

    def free_port(device: ET.Element, ref: str, wanted_serial: bool) -> str:
        names = donor_interface_names(device)
        if not names:
            names = [f"Serial{slot}/0" for slot in range(0, 8)] if wanted_serial else []
            names += [f"FastEthernet0/{index}" for index in range(1, 25)]
        for name in names:
            if name.startswith("Serial") != wanted_serial:
                continue
            if (ref, name) in used or not port_exists(device, name):
                continue
            return name
        return ""

    changed: list[str] = []
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext("FROM") or "").strip(), (cable.findtext("TO") or "").strip()]
        nodes = cable.findall("PORT")
        if len(nodes) < 2:
            continue
        ports = [(node.text or "") for node in nodes]
        serial = [port.startswith("Serial") for port in ports]
        if serial[0] == serial[1]:
            continue
        odd = 0 if not serial[0] else 1
        device = device_by_ref.get(refs[odd])
        if device is None:
            continue
        replacement = free_port(device, refs[odd], wanted_serial=True)
        if replacement:
            used.add((refs[odd], replacement))
            changed.append(f"{ports[odd]} -> {replacement} (matching the serial end)")
            nodes[odd].text = replacement
            continue
        # No serial socket on that device, so the pair becomes Ethernet.
        other = 1 - odd
        device = device_by_ref.get(refs[other])
        if device is None:
            continue
        replacement = free_port(device, refs[other], wanted_serial=False)
        if replacement:
            used.add((refs[other], replacement))
            changed.append(f"{ports[other]} -> {replacement} (no serial socket to match)")
            nodes[other].text = replacement
    return changed


def _ordered_port_media(device: ET.Element) -> dict[str, list[str]]:
    """This device's sockets, in Packet Tracer's own order, grouped by kind.

    The PORT nodes carry a media type and no name, and the document order is
    the order Packet Tracer numbers them in: an IE-9320's twenty-eight nodes are
    `GigabitEthernet1/0/1` .. `1/0/28`, a 2960's twenty-six are
    `FastEthernet0/1` .. `0/24` followed by `GigabitEthernet0/1` .. `0/2`.
    Verified against the live device listing for both.

    Zipping the nodes against `donor_interface_names` looks like the obvious
    way to get names and does not work: that returns 29 entries for a
    twenty-eight port switch, because a configuration also mentions interfaces
    the hardware does not have, and the pairing silently slips. Grouping by kind
    and counting within the kind survives that.
    """
    grouped: dict[str, list[str]] = {}
    for port in device.findall(".//PORT"):
        media = (port.findtext("./TYPE") or "").strip()
        if "FastEthernet" in media:
            grouped.setdefault("FastEthernet", []).append(media)
        elif "GigabitEthernet" in media:
            grouped.setdefault("GigabitEthernet", []).append(media)
    return grouped


def _port_is_fiber(device: ET.Element, port_name: str) -> bool:
    """Whether that named socket takes fibre rather than copper."""
    name = (port_name or "").strip()
    for kind in ("GigabitEthernet", "FastEthernet"):
        if not name.startswith(kind):
            continue
        tail = name[len(kind):].strip()
        if "/" not in tail:
            return False
        try:
            index = int(tail.rsplit("/", 1)[-1])
        except ValueError:
            return False
        media = _ordered_port_media(device).get(kind, [])
        if 1 <= index <= len(media):
            return "Fiber" in media[index - 1]
        return False
    return False


def _move_copper_cables_off_fibre_ports(root: ET.Element) -> list[str]:
    """Keep a copper cable out of a socket that only takes fibre.

    Packet Tracer does not refuse such a file. It opens it and silently drops
    the cable. Measured on a three-switch lab: sixteen links in the file,
    thirteen in the running topology, and the three missing ones all landed on
    `GigabitEthernet1/0/1` or `1/0/2` of an IE-9320 -- that switch's only two
    fibre ports. One of them was the router uplink, so nothing could reach the
    DHCP pool and every host fell back to an APIPA address. The open check
    reported `opened` throughout.

    That is worth stating plainly: a lab opening is not the same as Packet
    Tracer having loaded the topology that was written.

    The cable is moved rather than the media changed. A copper cable between
    two switches is what the topology asked for; the fibre socket is an
    accident of which port was free first.
    """
    device_order = list(root.findall(".//DEVICES/DEVICE"))
    device_by_ref: dict[str, ET.Element] = {}
    for index, device in enumerate(device_order):
        ref = (device.findtext("./ENGINE/SAVE_REF_ID") or "").strip()
        if ref:
            device_by_ref[ref] = device
        device_by_ref.setdefault(str(index), device)

    taken: set[tuple[str, str]] = set()
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext("FROM") or "").strip(), (cable.findtext("TO") or "").strip()]
        for ref, node in zip(refs, cable.findall("PORT")):
            taken.add((ref, (node.text or "").strip()))

    moved: list[str] = []
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None or (link.findtext("TYPE") or "").strip() != "eCopper":
            continue
        refs = [(cable.findtext("FROM") or "").strip(), (cable.findtext("TO") or "").strip()]
        nodes = cable.findall("PORT")
        if len(nodes) < 2:
            continue
        for ref, node in zip(refs, nodes):
            device = device_by_ref.get(ref)
            name = (node.text or "").strip()
            if device is None or not name or not _port_is_fiber(device, name):
                continue
            kind = "GigabitEthernet" if name.startswith("GigabitEthernet") else "FastEthernet"
            replacement = ""
            for candidate in donor_interface_names(device):
                # Same kind of interface, so a gigabit uplink stays gigabit.
                if not candidate.startswith(kind) or candidate == name:
                    continue
                if (ref, candidate) in taken:
                    continue
                if not port_exists(device, candidate) or _port_is_fiber(device, candidate):
                    continue
                replacement = candidate
                break
            if not replacement:
                continue
            taken.discard((ref, name))
            taken.add((ref, replacement))
            node.text = replacement
            moved.append(f"{name} -> {replacement} (copper cable off a fibre socket)")
    return moved


def _reconcile_cable_media(root: ET.Element) -> list[str]:
    """Make each cable's family agree with the interfaces it ends on.

    The port repair renames an interface the device does not have, and a serial
    link on a router with no serial card lands on an Ethernet port -- leaving a
    serial cable plugged into GigabitEthernet0/0/0. Packet Tracer refuses to
    open that, measured: the lab built fine and would not load.

    A cable is serial only when both ends are; otherwise it is copper.
    """
    changed: list[str] = []
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        ports = [(node.text or "") for node in cable.findall("PORT")]
        if len(ports) < 2:
            continue
        family = (link.findtext("TYPE") or "").strip()
        both_serial = all(port.startswith("Serial") for port in ports)
        if both_serial and family != "eSerial":
            _set_link_family(link, cable, "eSerial", "")
            changed.append(f"{ports[0]} <-> {ports[1]}: -> eSerial")
        elif not both_serial and family == "eSerial":
            _set_link_family(link, cable, "eCopper", "eStraightThrough")
            changed.append(f"{ports[0]} <-> {ports[1]}: eSerial -> eCopper")
    return changed


def _set_link_family(
    link: ET.Element, cable: ET.Element, family: str, subtype: str
) -> None:
    node = link.find("TYPE")
    if node is None:
        node = ET.SubElement(link, "TYPE")
    node.text = family
    sub = cable.find("TYPE")
    if sub is None:
        sub = ET.SubElement(cable, "TYPE")
    sub.text = subtype


def _declare_serial_dce_ends(root: ET.Element) -> list[str]:
    """Give every serial cable the DCE end Packet Tracer expects.

    A serial line has one side that supplies clocking, and the file records it
    as `DCEDEV` and `DCEPORT` on the cable. Every serial link in every donor
    carries both; links this generator built carried neither, and that is the
    whole reason a lab with a WAN was refused.

    Measured by holding the topology fixed and changing one thing at a time:
    the same lab opens with no second cable, opens with a *copper* cable
    between the same two routers, and is refused with a serial cable on any of
    `Serial2/0 <-> Serial2/0`, `Serial3/0 <-> 3/0` or `2/0 <-> 3/0`. So it was
    neither the ports nor the second router being cabled -- it was the medium.
    Adding `DCEDEV` and `DCEPORT` to that refused file opens it.

    The `FROM` end is named as DCE, which is what the donors do: every serial
    link in `Senan_Haciyev_tapsiriq.pkt` names its `FROM` device and port.
    """
    changed: list[str] = []
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        is_serial = (link.findtext("TYPE") or "").strip() == "eSerial"
        existing_dev = cable.find("DCEDEV")
        existing_port = cable.find("DCEPORT")

        if not is_serial:
            # Media reconciliation can demote a serial cable to copper, and a
            # copper cable has no clocking end to declare.
            for node in (existing_dev, existing_port):
                if node is not None:
                    cable.remove(node)
                    changed.append("removed a DCE end from a cable that is no longer serial")
            continue

        from_ref = (cable.findtext("FROM") or "").strip()
        ports = [(node.text or "").strip() for node in cable.findall("PORT")]
        if not from_ref or not ports:
            continue
        if existing_dev is not None and existing_port is not None:
            continue

        anchor = cable.find("TO_PORT_MEM_ADDR")
        position = list(cable).index(anchor) + 1 if anchor is not None else len(list(cable))
        if existing_dev is None:
            node = ET.Element("DCEDEV")
            node.text = from_ref
            cable.insert(position, node)
            position += 1
        if existing_port is None:
            node = ET.Element("DCEPORT")
            node.text = ports[0]
            cable.insert(position, node)
        changed.append(f"{ports[0]} declared as the DCE end of a serial cable")
    return changed


def _assign_unique_macs(root: ET.Element) -> list[str]:
    """Give every interface in the lab its own MAC address.

    A lab larger than its donor is filled by cloning, and a clone is a deep copy
    -- including the prototype's MAC. Three PCs cloned from one donor PC all
    carried 0060.5C02.3E05.

    Two hosts with the same MAC cannot talk through a switch. Packet Tracer's
    own packet trace shows why: PC2 answers PC1's ARP request, the switch
    receives the reply and reports "The old entry in the MAC table is on a
    different port than the receiving port", moves the entry, then drops the
    frame "because outgoing port and incoming port are the same". The address
    ping-pongs between ports and nothing is ever delivered.

    Nothing static could see this. The file opens, `pt_health_check` reports
    healthy, no address is duplicated, and every host reaches its gateway --
    because the gateway's MAC is its own. Only host-to-host traffic dies.

    The vendor prefix is kept so the address still looks like the hardware it
    belongs to; only the low three octets are reassigned.
    """
    seen: set[str] = set()
    renamed: list[str] = []
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME") or ""
        for port in device.iter("PORT"):
            node = port.find("MACADDRESS")
            if node is None or not (node.text or "").strip():
                continue
            address = node.text.strip()
            if address not in seen:
                seen.add(address)
                continue
            groups = address.split(".")
            if len(groups) != 3:
                continue
            head = groups[0]
            try:
                low = int(groups[1] + groups[2], 16)
            except ValueError:
                continue
            for step in range(1, 1 << 20):
                value = (low + step) & 0xFFFFFFFF
                candidate = f"{head}.{value >> 16:04X}.{value & 0xFFFF:04X}"
                if candidate not in seen:
                    break
            else:  # pragma: no cover - a million collisions is not reachable
                continue
            seen.add(candidate)
            node.text = candidate
            bia = port.find("BIA")
            if bia is not None:
                bia.text = candidate
            renamed.append(f"{name}: {address} -> {candidate}")

    # A switch also carries a device-level address, `BUILD_IN_ADDR`, and every
    # clone inherited the prototype's. Spanning tree builds its bridge ID from
    # it, so SW2, SW3 and SW4 all announced themselves as bridge
    # 0001.63C6.7232: to the core they were one switch, and only one of them
    # could reach it. The port addresses being unique was not enough, which is
    # why this looked like a trunking problem and then like a size threshold.
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME") or ""
        for node in device.iter("BUILD_IN_ADDR"):
            address = (node.text or "").strip()
            if not address:
                continue
            if address not in seen:
                seen.add(address)
                continue
            groups = address.split(".")
            if len(groups) != 3:
                continue
            head = groups[0]
            try:
                low = int(groups[1] + groups[2], 16)
            except ValueError:
                continue
            for step in range(1, 1 << 20):
                value = (low + step) & 0xFFFFFFFF
                candidate = f"{head}.{value >> 16:04X}.{value & 0xFFFF:04X}"
                if candidate not in seen:
                    break
            else:  # pragma: no cover - a million collisions is not reachable
                continue
            seen.add(candidate)
            node.text = candidate
            renamed.append(f"{name}: bridge address {address} -> {candidate}")
    return renamed


def _repair_invalid_link_ports(root: ET.Element) -> list[str]:
    """Rename any cabled interface the finished lab does not actually have.

    Every earlier guard validated a *guess* about the hardware: the planner
    against a model-name table, reconciliation against whichever donor device
    the rename map pointed at. Both can disagree with the device that ends up in
    the file, and when they do Packet Tracer refuses to open it -- an invalid
    interface name blocks opening, while a double-booked one does not.

    The assembled lab is the only place the hardware is known for certain, so
    the last word belongs here. Measured: a lab built from a bundled donor named
    R1:FastEthernet0/1 on a router whose interfaces are GigabitEthernet0/0/0
    through 0/0/2, and was refused; the blueprint had planned the correct
    interface and reconciliation had replaced it.

    Returns a description of every rename, for the generation report.
    """
    # Endpoints come in two spellings, and this pass only understood one. A
    # donor whose devices carry no `SAVE_REF_ID` addresses its links by position
    # instead, and every lookup here returned nothing -- so the repair skipped
    # every link and reported no work to do. Measured on a sniffer lab: four
    # devices, none with a save ref, three positional links, and a cable sitting
    # on `Port-channel 5`, which the repair walked straight past.
    device_order = list(root.findall(".//DEVICES/DEVICE"))
    device_by_ref: dict[str, ET.Element] = {}
    for index, device in enumerate(device_order):
        ref = (device.findtext("./ENGINE/SAVE_REF_ID") or "").strip()
        if ref:
            device_by_ref[ref] = device
        device_by_ref.setdefault(str(index), device)

    used: set[tuple[str, str]] = set()
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        for ref, port in zip(
            (cable.findtext("FROM") or "", cable.findtext("TO") or ""),
            [node.text or "" for node in cable.findall("PORT")],
        ):
            used.add((ref.strip(), port))

    repairs: list[str] = []
    seen: set[tuple[str, str]] = set()
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext("FROM") or "").strip(), (cable.findtext("TO") or "").strip()]
        ports = cable.findall("PORT")
        for ref, port_node in zip(refs, ports):
            device = device_by_ref.get(ref)
            port = port_node.text or ""
            if device is None or not port:
                continue
            # One interface carries one cable. A double-booked port does not stop
            # the file opening, which is why it survived every open test -- it
            # just silently leaves a host unable to reach anything.
            duplicated = (ref, port) in seen
            if not duplicated and port_exists(device, port):
                seen.add((ref, port))
                continue
            if duplicated and port_exists(device, port):
                reason = "interface already carries a cable"
            else:
                reason = "interface does not exist"
            name = device.findtext("./ENGINE/NAME") or ref
            candidates = donor_interface_names(device)
            if not candidates:
                # Some devices carry no running config to read interfaces from,
                # and a repair with nothing to offer leaves the fault in place:
                # `router_dhcp` still shipped SW1 FastEthernet0/2 on two cables.
                # Probing the usual names costs nothing and port_exists is the
                # authority on which of them the device really has.
                candidates = [f"FastEthernet0/{index}" for index in range(1, 25)]
                candidates += [f"GigabitEthernet0/{index}" for index in range(1, 5)]
                candidates += [f"GigabitEthernet0/0/{index}" for index in range(0, 4)]
            # Try the original's own family first. A serial link whose port is
            # missing used to land on the first free Ethernet interface, and the
            # cable then had to be downgraded to copper to stay openable -- even
            # on a router that has other serial ports. Same family keeps the
            # link the kind the prompt asked for.
            def _family_of(port_name: str) -> str:
                for prefix in ("Serial", "GigabitEthernet", "FastEthernet"):
                    if port_name.startswith(prefix):
                        return prefix
                return ""

            wanted_family = _family_of(port)
            ordered = sorted(
                candidates, key=lambda item: _family_of(item) != wanted_family
            )
            replacement = next(
                (
                    candidate
                    for candidate in ordered
                    if (ref, candidate) not in used and port_exists(device, candidate)
                ),
                None,
            )
            if replacement is None:
                repairs.append(f"{name}: {port} unusable ({reason}) and no free interface was available")
                seen.add((ref, port))
                continue
            if not duplicated:
                # A nonexistent port frees nothing, but it was never real, so
                # drop it. A duplicated one must stay claimed: the first cable
                # still holds it. Discarding it here made the port look free,
                # and the next repair moved a third cable onto it -- the fix
                # recreating the very fault it had just removed.
                used.discard((ref, port))
            used.add((ref, replacement))
            seen.add((ref, replacement))
            port_node.text = replacement
            repairs.append(f"{name}: {port} -> {replacement} ({reason})")
    return repairs


def _stamp_target_version(root: ET.Element) -> None:
    """Write the running Packet Tracer build into the generated file.

    Donor-prune inherits the donor's `<VERSION>`, and Packet Tracer refuses a
    file whose build differs from its own: "This file requires Cisco Packet
    Tracer version 9.0.0.0000. Your current version is 9.0.0.0810." Generating
    from a bundled `9.0.0.0000` sample therefore produced a file the very
    Packet Tracer that supplied the donor would not open.

    Only a full four-field build is stamped; a three-field release detected from
    an install directory name is not a build and must not be written.
    """
    target = get_packet_tracer_target_version()
    if len(target.split(".")) < 4:
        return
    node = root.find("./VERSION")
    if node is not None:
        node.text = target


def _switch_carrying_router_uplink(
    devices_by_name: dict[str, str],
    links: list[dict[str, object]],
) -> str | None:
    """The name of the switch that is actually wired to a router."""
    for link in links:
        left, right = str(link.get("from") or ""), str(link.get("to") or "")
        left_kind, right_kind = devices_by_name.get(left), devices_by_name.get(right)
        if left_kind == "Router" and right_kind == "Switch":
            return right
        if right_kind == "Router" and left_kind == "Switch":
            return left
    return None


def _switch_hops_from_router(
    kinds: dict[str, str],
    links: list[dict[str, object]],
) -> dict[str, int]:
    """Hop count from the nearest router to each switch, over switch links.

    A campus donor is usually a chain or a star rooted at the router, and so is
    the requested topology. Ranking both sides by distance from the router lines
    the two up without needing subgraph isomorphism.
    """
    adjacency: dict[str, set[str]] = {}
    roots: set[str] = set()
    for link in links:
        left, right = str(link.get("from") or ""), str(link.get("to") or "")
        left_kind, right_kind = kinds.get(left), kinds.get(right)
        if left_kind == "Switch" and right_kind == "Switch":
            adjacency.setdefault(left, set()).add(right)
            adjacency.setdefault(right, set()).add(left)
        elif left_kind == "Router" and right_kind == "Switch":
            roots.add(right)
        elif right_kind == "Router" and left_kind == "Switch":
            roots.add(left)

    switches = {name for name, kind in kinds.items() if kind == "Switch"}
    if not roots:
        return {name: 0 for name in switches}

    hops = {name: 1 for name in roots}
    frontier = list(roots)
    while frontier:
        current = frontier.pop(0)
        for neighbour in adjacency.get(current, ()):  # noqa: B007
            if neighbour not in hops:
                hops[neighbour] = hops[current] + 1
                frontier.append(neighbour)

    # Switches with no path to a router sort last.
    unreachable = len(switches) + 1
    return {name: hops.get(name, unreachable) for name in switches}


def _seat_surplus_donor_groups(
    ranked_donors: list[dict[str, object]],
    target_groups: list[dict[str, object]],
    target_order: list[str],
) -> list[dict[str, object]]:
    """Move donor groups that can supply their target's hosts to the front.

    Only called when the donor has more switch groups than the topology needs.
    The caller zips donor groups against targets, so everything past
    `len(target_groups)` is never consulted -- and hop order alone decides who
    lands inside that window.

    Measured on a donor whose router-facing group carries the exotic devices and
    whose second switch carries the PCs: `1 router 1 switch 1 patch panel 2
    komputer` refused with "donor switch group 'SW1' has 0 PC device(s)". The
    donor had two, one group over, past the end of the zip.

    Groups that cannot cover their target keep their relative hop order, so a
    donor with nothing to offer anywhere produces the same seating as before.
    """
    targets_by_name = {str(group["switch"]["name"]): group for group in target_groups}
    remaining = list(ranked_donors)
    seated: list[dict[str, object]] = []

    for target_name in target_order[: len(target_groups)]:
        target_group = targets_by_name.get(target_name)
        if target_group is None or not remaining:
            continue
        needed: Counter[str] = Counter(
            _device_kind(member) for member in target_group.get("members", [])
        )
        covering = next(
            (
                group
                for group in remaining
                if all(
                    len(group["members_by_type"].get(kind, [])) >= count
                    for kind, count in needed.items()
                )
            ),
            None,
        )
        chosen = covering if covering is not None else remaining[0]
        seated.append(chosen)
        remaining.remove(chosen)

    seated.extend(remaining)
    return seated


def _align_donor_groups_to_targets(
    donor_groups: list[dict[str, object]],
    target_groups: list[dict[str, object]],
    donor_devices: list[dict[str, str]],
    donor_links: list[dict[str, object]],
    blueprint: dict[str, object],
) -> list[dict[str, object]]:
    """Order donor switch groups to match the requested switch topology.

    Groups were zipped in name order, which broke two ways. A target switch
    carrying the router uplink could be matched to a donor switch with no router
    link, and in a multi-switch chain the requested `SW1 <-> SW2` could land on
    two donor switches that are not adjacent. Both produced the same misleading
    refusal: the donor "does not contain that device-to-device link", when it did
    contain it, on different switches.

    `Senan_K231.pkt` is Router-Mertebe3-Mertebe2-Mertebe1. Name order gave
    SW2 -> Mertebe 1, so `SW1 <-> SW2` mapped to a pair with no link. Distance
    ordering gives SW1/SW2/SW3 -> Mertebe 3/2/1, which follows the real chain.
    """
    if len(donor_groups) < 2 or not target_groups:
        return donor_groups

    donor_kinds = {str(device["name"]): _device_kind(device) for device in donor_devices}
    blueprint_kinds = {str(device["name"]): _device_kind(device) for device in blueprint.get("devices", [])}
    blueprint_links = [
        {"from": str(link["a"]["dev"]), "to": str(link["b"]["dev"])}
        for link in blueprint.get("links", [])
    ]

    donor_hops = _switch_hops_from_router(donor_kinds, donor_links)
    target_hops = _switch_hops_from_router(blueprint_kinds, blueprint_links)
    if not donor_hops or not target_hops:
        return donor_groups

    # Host capacity outranks router adjacency. A host link cannot be created, so
    # a target switch is hard-limited by the hosts its donor group already has;
    # a router uplink *can* be created, so which switch faces the router is a
    # preference. Matching the router-facing pair first put a 4-host target on
    # the donor's 3-host switch while two 4-host groups sat unused.
    # Reverted to distance-from-router ordering. A kind-aware greedy match fixed
    # `vlan_uneven` but stopped `four_switch` from opening, and a case that opens
    # outranks a case that merely generates.
    target_order = [
        str(group["switch"]["name"])
        for group in sorted(
            target_groups,
            key=lambda group: (
                target_hops.get(str(group["switch"]["name"]), 0),
                _name_sort_key(str(group["switch"]["name"])),
            ),
        )
    ]
    # Preferring the switch model the plan named was tried here, between hop
    # distance and name, so it could only choose between switches the same
    # distance from the router. It did what it was meant to -- `voice_devices`
    # came out on the `2960-24TT` the plan asked for instead of an `IE-9320` --
    # and Packet Tracer then refused that lab, taking the corpus from 32 open
    # to 31. The whole gain across the corpus was one switch, 10 matching to
    # 11 of 53. A case that opens outranks a case that merely carries the right
    # model, so it is not here.
    ranked_donors = sorted(
        donor_groups,
        key=lambda group: (
            donor_hops.get(str(group["switch"]["name"]), 0),
            _name_sort_key(str(group["switch"]["name"])),
        ),
    )

    # A donor with more switch groups than the topology needs has spare seats,
    # and hop order alone decides who fills them. Prefer the groups that can
    # actually supply their target's hosts; see `_seat_surplus_donor_groups`.
    # Equal counts are left alone, so the chain ordering `four_switch` relies on
    # is untouched -- a kind-aware match across *all* groups was tried before
    # and stopped that case from opening.
    if len(ranked_donors) > len(target_groups):
        ranked_donors = _seat_surplus_donor_groups(ranked_donors, target_groups, target_order)

    # `target_groups` is consumed in its own order, so map back into it. The
    # output must always contain exactly the donor groups that came in: an
    # earlier version dropped entries when there were more targets than donors,
    # and the caller then reported "supports only 0 switch groups" for a donor
    # with three switches.
    position_of_target = {
        str(group["switch"]["name"]): index for index, group in enumerate(target_groups)
    }
    rank_by_target_index: dict[int, int] = {}
    for rank, target_name in enumerate(target_order):
        target_index = position_of_target.get(target_name)
        if target_index is not None:
            rank_by_target_index[target_index] = rank

    aligned: list[dict[str, object]] = []
    used_ranks: set[int] = set()
    for target_index in range(len(target_groups)):
        rank = rank_by_target_index.get(target_index)
        if rank is not None and rank < len(ranked_donors) and rank not in used_ranks:
            aligned.append(ranked_donors[rank])
            used_ranks.add(rank)
    aligned.extend(group for rank, group in enumerate(ranked_donors) if rank not in used_ranks)

    assert len(aligned) == len(donor_groups)
    return aligned


def _build_donor_prune_plan_for_donor(plan: IntentPlan, blueprint: dict[str, object], compat_donor: Path) -> tuple[IntentPlan, DonorArchetypePlan]:
    donor_root = decode_pkt_to_root(compat_donor)
    donor_groups = _collect_donor_groups(donor_root)
    target_groups = _target_groups_from_blueprint(plan, blueprint)
    adapted_plan = copy.deepcopy(plan)
    # The donor-shaping operations are rebuilt from scratch below, so the
    # list is cleared -- but it also holds what the *user* asked for, and
    # `cli R1: ...` was being thrown away with it. The parser produced the
    # operation correctly and the plan reaching the file contained none, so
    # arbitrary IOS never arrived. Held aside here and appended after the
    # renames, since it addresses devices by their final name.
    carried_operations = [
        operation
        for operation in adapted_plan.edit_operations
        if operation.get("op") == "apply_cli"
    ]
    adapted_plan.edit_operations = []
    donor_devices = inventory_devices(donor_root)
    donor_links = inventory_links(donor_root)
    donor_capacity = _donor_capacity(donor_root, donor_groups)
    donor_groups = _align_donor_groups_to_targets(donor_groups, target_groups, donor_devices, donor_links, blueprint)
    if len(target_groups) > len(donor_groups) and donor_groups and _group_duplication_enabled():
        # The donor caps how many switches exist, not how many the topology may
        # have: duplicating a switch was verified to open in Packet Tracer.
        # Copies are seeded from the richest existing group so the duplicate
        # arrives with a usable port layout.
        # `donor_groups` grows inside this loop, so the base length must be
        # captured first or the target index walks off the end.
        pending_duplications: list[dict[str, object]] = []
        base_group_count = len(donor_groups)
        shortfall = len(target_groups) - base_group_count
        seed_group = max(donor_groups, key=lambda group: len(group.get("members", [])))
        seed_name = str(seed_group["switch"]["name"])
        seed_members = list(seed_group.get("members", []))
        for index in range(shortfall):
            duplicate_name = f"{seed_name}-COPY{index + 1}"
            target_group = target_groups[base_group_count + index]
            target_switch = target_group["switch"]
            # Clone only what the target group actually needs, by kind. Cloning
            # the whole seed group meant copying six devices — including servers
            # — to use two, and every extra clone is another device to prune and
            # another way for the copy to differ from the original.
            wanted_by_kind: dict[str, int] = {}
            for member in target_group.get("members", []):
                kind = _device_kind(member)
                wanted_by_kind[kind] = wanted_by_kind.get(kind, 0) + 1
            seed_hosts: list[str] = []
            for kind, count in wanted_by_kind.items():
                matching = [
                    str(member["name"])
                    for member in seed_members
                    if _device_kind(member) == kind
                ]
                # Truncated on purpose. A seed group with three PCs cannot fill
                # a target that wants eight, and cloning the same member twice
                # to make up the difference was measured and reverted: it took
                # the 100-PC lab from 140 devices to 65 and from 13 undelivered
                # devices to 88. Whatever consumes these names downstream
                # cannot have one source duplicated twice in a batch, so the
                # shortfall belongs in the donor -- a group with more hosts --
                # rather than here.
                seed_hosts.extend(matching[:count])
            # Emitted after the rename/prune pass, not here. The verified
            # experiment duplicated a group *after* all other mutations, from a
            # device already carrying its final name; duplicating first and then
            # renaming the copy is a different operation order and produced a
            # file Packet Tracer refused.
            pending_duplications.append(
                {
                    "seed": seed_name,
                    "new_name": str(target_switch["name"]),
                    "wanted": dict(wanted_by_kind),
                    "target_hosts": [str(m["name"]) for m in target_group.get("members", [])],
                    "x": int(target_switch.get("x", 0)),
                    "y": int(target_switch.get("y", 0)),
                }
            )
            cloned_members = [
                {"name": f"{duplicate_name}-H{index + 1}", "type": _device_kind_by_name(seed_group, host)}
                for index, host in enumerate(seed_hosts)
            ]
            # The clone's links exist in the output but not in `donor_links`,
            # which was read before duplication. Register them so the rename and
            # link-reuse logic downstream sees the copies as donor-provided —
            # otherwise it asks to *create* a host link, which is refused.
            # `enumerate`, not `.index`: a seed member cloned twice appears
            # twice in `seed_hosts`, and looking the name up returns the first
            # position both times -- so the second clone would be registered
            # under the first one's name and arrive with no cable.
            for position, host in enumerate(seed_hosts):
                original = next(
                    (
                        link
                        for link in donor_links
                        if {str(link.get("from") or ""), str(link.get("to") or "")} == {seed_name, host}
                    ),
                    None,
                )
                if original is None:
                    continue
                cloned = dict(original)
                cloned["from"] = duplicate_name
                cloned["to"] = f"{duplicate_name}-H{position + 1}"
                donor_links.append(cloned)
            members_by_type: dict[str, list[dict[str, object]]] = {}
            for member in cloned_members:
                members_by_type.setdefault(str(member["type"]), []).append(member)
            donor_groups.append(
                {
                    "group_name": duplicate_name,
                    "switch": {"name": duplicate_name, "type": "Switch"},
                    "members": cloned_members,
                    "members_by_type": members_by_type,
                }
            )
        adapted_plan.assumptions_used.append(
            f"Duplicated {seed_name} {shortfall} time(s): the donor has "
            f"{base_group_count} switch group(s) and the topology needs {len(target_groups)}."
        )

    if len(target_groups) > len(donor_groups):
        gap = (
            f"Donor {Path(compat_donor).name} has {len(donor_groups)} switch group(s); "
            f"requested {len(target_groups)}. Donor-prune reuses the donor's switches, "
            "so a topology needs a donor with at least that many."
        )
        if gap not in adapted_plan.blocking_gaps:
            adapted_plan.blocking_gaps.append(gap)
        raise PlanningError("Prompt plan is incomplete; generation was skipped.", adapted_plan)

    kept_devices: set[str] = set()
    parked_devices: list[str] = []
    renamed_devices: list[dict[str, str]] = []
    mutation_groups: list[dict[str, object]] = []
    rename_map: dict[str, str] = {}
    spare_candidates_by_type: dict[str, list[dict[str, object]]] = {}
    pruned_spares: list[str] = []

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
        if _spare_strategy() == "prune":
            # Delete the donor's leftovers instead of hiding them offscreen, so a
            # five-device request yields a five-device lab. Verified against a
            # real Packet Tracer open before being made the default.
            kept_devices.add(old_name)
            adapted_plan.edit_operations.append({"op": "prune_device", "device": old_name})
            pruned_spares.append(old_name)
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

    # Routers were matched one-to-one and singular: `next(...)` on both sides.
    # A prompt asking for two routers produced one, the file opened, and nothing
    # reported the loss -- the second router belonged to no path at all, because
    # `standalone_targets` below excludes Router by kind.
    target_routers = [device for device in blueprint.get("devices", []) if _device_kind(device) == "Router"]
    donor_routers = [device for device in donor_devices if device["type"] == "Router"]
    pending_router_clones: list[dict[str, object]] = []
    if target_routers:
        if not donor_routers:
            gap = "Compatibility donor does not contain a router prototype for prompt generation."
            if gap not in adapted_plan.blocking_gaps:
                adapted_plan.blocking_gaps.append(gap)
            raise PlanningError("Prompt plan is incomplete; generation was skipped.", adapted_plan)
        for index, target_router in enumerate(target_routers):
            if index < len(donor_routers):
                donor_router = donor_routers[index]
                keep_name(
                    str(donor_router["name"]),
                    str(target_router["name"]),
                    int(target_router.get("x", 0)),
                    int(target_router.get("y", 0)),
                )
                continue
            # More routers than the donor has. Clone one, the same way a switch
            # shortfall is met -- `duplicate_device` on a bare infrastructure
            # device is already verified against a real open. Emitted after the
            # rename pass, from the source's final name, because duplicating
            # first and renaming the copy produces a file Packet Tracer refuses.
            if not _group_duplication_enabled():
                gap = (
                    f"Compatibility donor has {len(donor_routers)} router(s); "
                    f"{len(target_routers)} were requested, and router duplication is disabled."
                )
                if gap not in adapted_plan.blocking_gaps:
                    adapted_plan.blocking_gaps.append(gap)
                raise PlanningError("Prompt plan is incomplete; generation was skipped.", adapted_plan)
            pending_router_clones.append(
                {
                    "source": str(donor_routers[0]["name"]),
                    "new_name": str(target_router["name"]),
                    "x": int(target_router.get("x", 0)),
                    "y": int(target_router.get("y", 0)),
                }
            )
        # Donor routers past the ones the topology asked for belong to no path
        # at all. The sweep further down skips Router and Switch by kind, so
        # they survive untouched, in the middle of the canvas: `1 central office
        # server 1 router` against a five-router donor produced all five. The
        # branch below already parks every donor router when the prompt asks for
        # none, and this is that same decision applied to the surplus.
        for donor_router in donor_routers[len(target_routers) :]:
            park_device(str(donor_router["name"]))
    else:
        for donor_router in donor_routers:
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

    # Donor devices are pooled across groups. A target switch used to be limited
    # to the hosts its *matched* donor switch happened to have, so "1 switch and
    # 5 PCs" was refused against a donor holding 11 PCs spread over three
    # switches — every one of which was about to be pruned anyway.
    pending_host_clones: list[dict[str, object]] = []
    unclaimed_by_type: dict[str, list[dict[str, object]]] = {}
    for spare_group in donor_groups[len(target_groups) :]:
        for member in spare_group["members"]:
            unclaimed_by_type.setdefault(_device_kind(member), []).append(member)

    def borrow(device_type: str, count: int) -> list[dict[str, object]]:
        # Measured: files built with borrowed devices are rejected by Packet
        # Tracer as "not compatible with this version". Every corpus case whose
        # target switch needed more hosts than its aligned donor switch had
        # failed to open (4, 5 and 7 hosts), and every case that stayed within
        # the donor group's own hosts opened (2 and 3). Moving a device between
        # switch groups evidently leaves state this code does not fix up.
        #
        # A refusal beats a file that looks generated and will not open, so
        # borrowing is off unless explicitly asked for.
        if not _cross_group_borrowing_enabled():
            return []
        pool = unclaimed_by_type.get(device_type, [])
        taken, unclaimed_by_type[device_type] = pool[:count], pool[count:]
        return taken

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
            available = list(donor_members_by_type.get(device_type, []))
            if len(wanted) > len(available):
                borrowed = borrow(device_type, len(wanted) - len(available))
                available.extend(borrowed)
            if len(wanted) > len(available) and available and _host_duplication_enabled():
                # Clone the shortfall from a host the donor group already has.
                # Recorded here and emitted after the rename/prune pass, because
                # duplication has to run last, from devices carrying their final
                # names — the same ordering group duplication needs.
                shortfall_count = len(wanted) - len(available)
                for offset in range(shortfall_count):
                    source_member = available[offset % len(available)]
                    target_member = wanted[len(available) + offset]
                    pending_host_clones.append(
                        {
                            "source": str(source_member["name"]),
                            "new_name": str(target_member["name"]),
                            "switch": str(target_group["switch"]["name"]),
                            "x": int(target_member.get("x", 0)),
                            "y": int(target_member.get("y", 0)),
                        }
                    )
                available = list(available) + [
                    {"name": str(wanted[len(available) + offset]["name"]), "type": device_type}
                    for offset in range(shortfall_count)
                ]

            if len(wanted) > len(available):
                total_shortfall = len(wanted) - len(available)
                gap = (
                    f"Donor switch group '{donor_group['group_name']}' has {len(available)} "
                    f"{device_type} device(s); {target_group['group_name']} needs {len(wanted)} "
                    f"(short by {total_shortfall}). A generated lab reuses the hosts already attached "
                    "to a donor switch, so pick a prompt that fits, or save a Packet Tracer lab with "
                    f"at least {len(wanted)} {device_type} device(s) on one switch and use it as the donor."
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
        available_pool = _spare_pool_for_type(spare_candidates_by_type, device_type)
        if not available_pool:
            # A device outside every switch group is still a device. The spare
            # pool is built from switch-group members, so a donor whose WLC or
            # access point hangs off no switch offered nothing at all -- and
            # `1 wlc 2 access point qur` was refused by the very donor chosen
            # for carrying a WLC. Adopt an unused one directly.
            adopted = next(
                (
                    str(device["name"])
                    for device in donor_devices
                    if _device_kind(device) == device_type
                    and str(device["name"]) not in kept_devices
                    and str(device["name"]) not in parked_devices
                ),
                "",
            )
            if adopted:
                keep_name(
                    adopted,
                    str(target["name"]),
                    int(target.get("x", 0)),
                    int(target.get("y", 0)),
                )
                continue

            # Same shortfall as inside a switch group, on the path for devices
            # that hang off no switch. Clone one the donor already has rather
            # than refusing: "1 wireless router 2 laptop" failed here because the
            # donor carries a single laptop.
            source = next(
                (
                    str(device["name"])
                    for device in donor_devices
                    if _device_kind(device) == device_type and str(device["name"]) in rename_map
                ),
                "",
            )
            if source and _host_duplication_enabled():
                pending_host_clones.append(
                    {
                        "source": source,
                        "new_name": str(target["name"]),
                        "switch": "",
                        "x": int(target.get("x", 0)),
                        "y": int(target.get("y", 0)),
                    }
                )
                continue
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
    # A donor device the plan prunes must not go on claiming its name here.
    # `rename_map.get(name, name)` falls back to the donor's own name, so a
    # pruned SW1 still registered its router cable under the target name SW1 --
    # the very name a *different* donor switch was being renamed into. The
    # planner read `R1 <-> SW1` as already wired, created nothing, and the prune
    # then took the cable away with the old switch. The lab generated, opened,
    # and had its router connected to nothing.
    pruned_spare_set = set(pruned_spares)

    def touches_pruned_spare(donor_link: dict[str, object]) -> bool:
        return (
            str(donor_link["from"]) in pruned_spare_set
            or str(donor_link["to"]) in pruned_spare_set
        )

    existing_links: dict[tuple[str, str], dict[str, object]] = {}
    for donor_link in donor_links:
        if touches_pruned_spare(donor_link):
            continue
        left_name = rename_map.get(str(donor_link["from"]), str(donor_link["from"]))
        right_name = rename_map.get(str(donor_link["to"]), str(donor_link["to"]))
        if not left_name or not right_name or left_name == right_name:
            continue
        pair = tuple(sorted((left_name, right_name)))
        existing_links[pair] = donor_link
    parked_name_set = set(parked_devices)
    removed_pairs: set[tuple[str, str]] = set()
    for donor_link in donor_links:
        if touches_pruned_spare(donor_link):
            # Pruning removes the cable with the device. Emitting a removal by
            # name here could strike the link of whichever device now answers
            # to that name instead.
            continue
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
    # One physical interface carries one cable. Adopting donor wiring for some
    # links while planning others from the blueprint can land two cables on the
    # same port, which produces a lab that looks right and is wired wrongly.
    claimed_ports: set[tuple[str, str]] = set()

    donor_device_by_target = {
        rename_map.get(str(device.findtext("./ENGINE/NAME") or ""), str(device.findtext("./ENGINE/NAME") or "")): device
        for device in donor_root.findall(".//DEVICES/DEVICE")
    }

    # A lab larger than its donor is filled by cloning, and a clone has no donor
    # device of its own name. Port reconciliation looked itself up in this map,
    # found nothing, and returned the colliding port unchanged -- so every cloned
    # switch kept two cables on one interface. A 22-switch lab came out with
    # nineteen such interfaces. A clone carries its prototype's hardware, so any
    # donor device of the same type answers "does this port exist" correctly.
    donor_by_type: dict[str, ET.Element] = {}
    for device in donor_root.findall(".//DEVICES/DEVICE"):
        kind = (device.findtext("./ENGINE/TYPE") or "").strip()
        if kind:
            donor_by_type.setdefault(kind, device)
    for planned in blueprint.get("devices", []):
        name = str(planned.get("name") or "")
        if not name or name in donor_device_by_target:
            continue
        prototype = donor_by_type.get(str(planned.get("type") or ""))
        if prototype is not None:
            donor_device_by_target[name] = prototype

    def claim_port(device_name: str, port_name: str) -> str:
        """Return `port_name` if free, otherwise the next free port that exists.

        Alternatives are validated against the donor device via
        `port_exists`, which counts the device's real interfaces.
        Incrementing the index blindly invented ports like `GigabitEthernet0/3`
        on a 2960-24TT, which has only two gigabit interfaces; Packet Tracer
        rejected the whole file as incompatible.
        """
        if not port_name:
            return port_name
        if (device_name, port_name) not in claimed_ports:
            claimed_ports.add((device_name, port_name))
            return port_name

        device = donor_device_by_target.get(device_name)
        match = re.match(r"^(.*?)(\d+)$", port_name)
        if device is None or not match:
            return port_name

        stems = [match.group(1)]
        # A 2960-24TT has two gigabit interfaces. A core switch wanting three
        # uplinks must put one on FastEthernet, which is what an engineer would
        # do rather than declare the topology impossible.
        if "gigabit" in match.group(1).lower():
            stems.append("FastEthernet0/")
        start = int(match.group(2))
        for stem in stems:
            first = start if stem != match.group(1) else start + 1
            for index in range(first, first + 48):
                candidate = f"{stem}{index}"
                if (device_name, candidate) in claimed_ports:
                    continue
                if not port_exists(device, candidate):
                    break  # ran past the ports this device actually has
                claimed_ports.add((device_name, candidate))
                return candidate
        # Nothing free that this device actually has. Handing the requested name
        # back put `GigabitEthernet0/20` on a switch with two gigabit
        # interfaces, and Packet Tracer rejects a lab naming an interface that
        # does not exist. Report the exhaustion instead.
        return ""

    for link in blueprint.get("links", []):
        desired_left = str(link["a"]["dev"])
        desired_right = str(link["b"]["dev"])
        desired_pair = tuple(sorted((desired_left, desired_right)))
        existing = existing_links.get(desired_pair)
        desired_ports = [str(link["a"]["port"]), str(link["b"]["port"])]
        desired_media = str(link.get("media", "straight-through"))
        if existing is None:
            # Reuse-only means the skill can only ever rebuild topologies the
            # donor already has: a chain donor can never satisfy a star request.
            # Creating the missing link uses the same `set_link` machinery the
            # edit path already relies on.
            blueprint_kinds = {
                str(device.get("name")): _device_kind(device)
                for device in blueprint.get("devices", [])
            }
            left_kind = blueprint_kinds.get(desired_left, "")
            right_kind = blueprint_kinds.get(desired_right, "")
            if _link_strategy() == "create" and not _link_may_be_created(left_kind, right_kind):
                link_reuse_gaps.append(
                    f"The donor has no link between {desired_left} and {desired_right}, and a "
                    f"{left_kind}-to-{right_kind} link cannot be built: Packet Tracer rejects files "
                    "with a created host connection. Hosts must stay on the switch the donor gave them."
                )
                continue
            if _link_strategy() == "create":
                left_port = claim_port(desired_left, desired_ports[0])
                right_port = claim_port(desired_right, desired_ports[1])
                if not left_port or not right_port:
                    exhausted = desired_left if not left_port else desired_right
                    link_reuse_gaps.append(
                        f"{exhausted} has no free interface left for the link to "
                        f"{desired_right if not left_port else desired_left}. A 24-port switch "
                        "cannot terminate more cables than it has ports; a topology this wide "
                        "needs a larger core switch or another distribution layer."
                    )
                    continue
                adapted_plan.edit_operations.append(
                    {
                        "op": "set_link",
                        "a": {"dev": desired_left, "port": left_port},
                        "b": {"dev": desired_right, "port": right_port},
                        "media": desired_media,
                    }
                )
                creation = (
                    f"Created donor link {desired_left} <-> {desired_right}; "
                    "the donor did not contain this device-to-device link."
                )
                if creation not in adapted_plan.assumptions_used:
                    adapted_plan.assumptions_used.append(creation)
                continue
            link_reuse_gaps.append(
                f"Open-first mode cannot create new donor link pair {desired_left} <-> {desired_right}; "
                "this donor does not contain that device-to-device link. "
                "Set PACKET_TRACER_LINK_STRATEGY=create to build it instead."
            )
            continue
        existing_ports = [str(port) for port in existing.get("ports", [])]
        existing_media = str(existing.get("media", ""))
        # The donor speaks Packet Tracer's vocabulary (`eStraightThrough`) and
        # the planner speaks the prompt's (`straight-through`). Comparing the
        # raw strings made every identical cable look like a mismatch, which
        # refused four capabilities -- ntp, syslog, snmp and aaa -- with
        # "requires donor link reuse" on a link that already matched.
        ports_match = len(existing_ports) >= 2 and sorted(existing_ports[:2]) == sorted(desired_ports)
        media_matches = _same_media(existing_media, desired_media)
        if ports_match and media_matches:
            # The claim can still come back changed: an earlier link that adopted
            # donor wiring may already hold this port. Writing the result back is
            # what keeps two cables off one interface — discarding it silently
            # produced a lab with PC1 and R1 both on SW1 FastEthernet0/3.
            link["a"]["port"] = claim_port(desired_left, desired_ports[0]) or desired_ports[0]
            link["b"]["port"] = claim_port(desired_right, desired_ports[1]) or desired_ports[1]
            continue
        # A port or media value the user never asked for must not reject a donor.
        # When the planner defaulted it, the donor's own wiring is the better
        # answer: adopt it and record the adaptation as an assumption.
        if _link_wiring_was_defaulted(adapted_plan):
            if len(existing_ports) >= 2:
                # `existing_ports` is in the donor's own from/to order, which does
                # not have to match the blueprint's a/b order. Align by device name
                # (after renaming) or the two ends get swapped, which shows up later
                # as a spurious `port_reassignment` unsafe mutation.
                donor_from = rename_map.get(str(existing.get("from", "")), str(existing.get("from", "")))
                if donor_from == desired_left:
                    left_port, right_port = existing_ports[0], existing_ports[1]
                else:
                    left_port, right_port = existing_ports[1], existing_ports[0]
                link["a"]["port"] = claim_port(desired_left, left_port) or left_port
                link["b"]["port"] = claim_port(desired_right, right_port) or right_port
            if existing_media:
                link["media"] = existing_media
            adaptation = (
                f"Adopted donor wiring for {desired_left} <-> {desired_right}: "
                f"ports {existing_ports[:2]}, media {existing_media or 'donor default'}."
            )
            if adaptation not in adapted_plan.assumptions_used:
                adapted_plan.assumptions_used.append(adaptation)
            continue
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

    parked_set = set(parked_devices)
    for pending in locals().get("pending_duplications", []) or []:
        seed_final = rename_map.get(str(pending["seed"]), str(pending["seed"]))
        # Clone the hosts that actually survive on the seed switch, under their
        # final names. Cloning by donor name copied devices this very plan was
        # about to delete.
        # Pick the seed by what survives, not by donor membership. The richest
        # donor group can map onto the core switch, which ends up carrying no
        # hosts at all — cloning that gives an empty group.
        def kept_hosts_of(group: dict[str, object]) -> list[str]:
            names: list[str] = []
            for member in group.get("members", []):
                final = rename_map.get(str(member["name"]), "")
                if final and final not in parked_set:
                    names.append(final)
            return names

        candidates = [
            (kept_hosts_of(group), group)
            for group in donor_groups
            if str(group["switch"]["name"]) in rename_map
        ]
        kept_hosts, best_group = max(candidates, key=lambda item: len(item[0]), default=([], None))
        if best_group is not None:
            seed_final = rename_map.get(str(best_group["switch"]["name"]), seed_final)
        needed = sum(int(count) for count in dict(pending["wanted"]).values())
        adapted_plan.edit_operations.append(
            {
                "op": "duplicate_group",
                "device": seed_final,
                "new_name": str(pending["new_name"]),
                "hosts": kept_hosts[:needed],
                "new_hosts": [str(name) for name in pending["target_hosts"]][:needed],
                "x": int(pending["x"]),
                "y": int(pending["y"]),
            }
        )
        # The clone's uplink has to be built after the clone exists. The
        # link-reuse pass ran earlier and its `set_link` for this pair was a
        # no-op, which left the new switch with hosts but no path to the rest
        # of the topology.
        new_switch = str(pending["new_name"])
        for link in blueprint.get("links", []):
            left, right = str(link["a"]["dev"]), str(link["b"]["dev"])
            if new_switch not in (left, right):
                continue
            other = right if left == new_switch else left
            if not _link_may_be_created(
                _device_kind_of_blueprint(blueprint, left),
                _device_kind_of_blueprint(blueprint, right),
            ):
                continue
            # Reserve through the same allocator the rest of the wiring uses.
            # Writing the blueprint port straight out meant a cloned switch's
            # uplink could take an interface the core had already given to an
            # earlier one -- `SW1 FastEthernet0/7` carrying both SW3 and SW21.
            left_port = claim_port(left, str(link["a"]["port"]))
            right_port = claim_port(right, str(link["b"]["port"]))
            if not left_port or not right_port:
                exhausted = left if not left_port else right
                gap = (
                    f"{exhausted} has no free interface for the uplink to "
                    f"{right if not left_port else left}; the core switch cannot "
                    "terminate this many uplinks."
                )
                if gap not in adapted_plan.blocking_gaps:
                    adapted_plan.blocking_gaps.append(gap)
                continue
            adapted_plan.edit_operations.append(
                {
                    "op": "set_link",
                    "a": {"dev": left, "port": left_port},
                    "b": {"dev": right, "port": right_port},
                    "media": str(link.get("media", "straight-through")),
                }
            )

    for clone in locals().get("pending_router_clones", []) or []:
        source_final = rename_map.get(str(clone["source"]), str(clone["source"]))
        if source_final in parked_set:
            continue
        # `duplicate_device` copies the device alone, with no attached hosts --
        # which is exactly right for a router. Its links come from the normal
        # link pass, like any other device in the blueprint.
        adapted_plan.edit_operations.append(
            {
                "op": "duplicate_device",
                "device": source_final,
                "new_name": str(clone["new_name"]),
                "x": int(clone["x"]),
                "y": int(clone["y"]),
            }
        )

    # A clone whose name is already taken is dropped in silence: duplication
    # returns early when a device of that name exists. The donor for
    # `1 router 1 switch 3 komputer` holds PC0..PC3, and only PC0 was pruned --
    # so the plan kept the donor's own PC2 and PC3 *and* asked for clones called
    # PC2 and PC3. The clones never happened, and the surviving donor hosts were
    # wireless: no Ethernet interface, cabled to the switch on FastEthernet0,
    # holding APIPA addresses. The plan has to agree with itself first.
    clone_names = {str(clone["new_name"]) for clone in pending_host_clones}
    clone_sources = {
        rename_map.get(str(clone["source"]), str(clone["source"]))
        for clone in pending_host_clones
    }
    already_pruned = {
        str(operation.get("device"))
        for operation in adapted_plan.edit_operations
        if operation.get("op") == "prune_device"
    }
    # Only the ones that cannot do the job. Pruning every colliding name was
    # too broad: it removed donor devices the rest of the plan still referred
    # to, donor-prune validation then failed, and generation quietly fell back
    # to the blueprint path -- which writes links by positional index and left
    # `hosts_only` and `nat_internet` failing the structural check. A device
    # that can take a cable is a perfectly good host; only one with no wired
    # interface has to give way to a clone.
    cabled_donor_names = {
        (device.findtext("./ENGINE/NAME") or "")
        for device in donor_root.findall(".//DEVICES/DEVICE")
        if any("copper" in (port.findtext("TYPE") or "").lower() for port in device.iter("PORT"))
    }
    for donor_device in donor_devices:
        donor_name = str(donor_device["name"])
        final_name = rename_map.get(donor_name, donor_name)
        if (
            final_name in clone_names
            and final_name not in clone_sources
            and final_name not in already_pruned
            and donor_name not in cabled_donor_names
        ):
            adapted_plan.edit_operations.append({"op": "prune_device", "device": final_name})
            already_pruned.add(final_name)

    # Every switch port a clone has been given, so a port planned for one is
    # not handed to another.
    clone_ports_taken: set[tuple[str, str]] = set()
    for clone in pending_host_clones:
        source_final = rename_map.get(str(clone["source"]), str(clone["source"]))
        if source_final in parked_set:
            continue
        switch_name = str(clone["switch"])
        if not switch_name:
            # Standalone target: clone the device, leave it unattached. Whatever
            # link the topology wants is handled by the normal link pass.
            adapted_plan.edit_operations.append(
                {
                    "op": "duplicate_host",
                    "device": source_final,
                    "new_name": str(clone["new_name"]),
                    "switch": "",
                    "x": int(clone["x"]),
                    "y": int(clone["y"]),
                }
            )
            continue
        # The blueprint has usually already planned this host's connection, with
        # a port of its own. Allocating a second one here meant every clone on a
        # switch was wired twice -- and because the search scanned only ports
        # already in the blueprint, all of them landed on `FastEthernet0/1`. At
        # 100 hosts that was 16 cables on one interface and a lab Packet Tracer
        # refused to open.
        clone_name = str(clone["new_name"])
        planned_port = ""
        planned_link = None
        for link in blueprint.get("links", []):
            ends = {str(link[end]["dev"]): str(link[end]["port"]) for end in ("a", "b")}
            if clone_name in ends and switch_name in ends:
                planned_port = ends[switch_name]
                planned_link = link
                break

        # A planned port is only good if no earlier clone has taken it. Two
        # clones can be planned onto the same interface, and trusting the plan
        # without checking put three pairs of hosts on one port once the donor
        # grew enough groups for a hundred-host lab to reach this path.
        if planned_port and (switch_name, planned_port) not in clone_ports_taken:
            switch_port = planned_port
        else:
            planned_link = None
            used_ports = {
                str(link[end]["port"])
                for link in blueprint.get("links", [])
                for end in ("a", "b")
                if str(link[end]["dev"]) == switch_name
            }
            used_ports |= {port for switch, port in clone_ports_taken if switch == switch_name}
            switch_port = next(
                (
                    candidate
                    for index in range(1, 49)
                    for candidate in (f"FastEthernet0/{index}",)
                    if candidate not in used_ports
                ),
                "",
            )
            if not switch_port:
                gap = (
                    f"{switch_name} has no free access port for {clone_name}. "
                    "A switch cannot carry more hosts than it has interfaces; "
                    "ask for more switches or fewer hosts each."
                )
                if gap not in adapted_plan.blocking_gaps:
                    adapted_plan.blocking_gaps.append(gap)
                continue
        clone_ports_taken.add((switch_name, switch_port))
        adapted_plan.edit_operations.append(
            {
                "op": "duplicate_host",
                "device": source_final,
                "new_name": clone_name,
                "switch": switch_name,
                "switch_port": switch_port,
                "host_port": "FastEthernet0",
                "x": int(clone["x"]),
                "y": int(clone["y"]),
            }
        )
        if planned_link is None:
            blueprint.setdefault("links", []).append(
                {
                    "a": {"dev": switch_name, "port": switch_port},
                    "b": {"dev": clone_name, "port": "FastEthernet0"},
                    "media": "straight-through",
                }
            )

    _unify_host_segment(
        adapted_plan, blueprint.get("devices", []), blueprint.get("links", []), donor_root
    )

    _resolve_port_conflicts(
        adapted_plan,
        donor_links=donor_links,
        rename_map=rename_map,
        removed_pairs=removed_pairs,
        parked_names=set(parked_devices),
        donor_device_by_target=donor_device_by_target,
    )

    archetype_plan = DonorArchetypePlan(
        compat_donor=str(compat_donor),
        donor_capacity=donor_capacity,
        kept_devices=sorted([name for name in rename_map.values() if name not in set(parked_devices)], key=_name_sort_key),
        # Under the default `prune` strategy devices are deleted rather than
        # parked, so reporting only `parked_devices` said "0 pruned" for a run
        # that removed fourteen of them.
        pruned_devices=sorted(dict.fromkeys([*parked_devices, *pruned_spares]), key=_name_sort_key),
        renamed_devices=renamed_devices,
        mutation_groups=mutation_groups,
        layout_strategy="donor_park_clean",
    )
    # Last, so every rename the plan makes has already happened and the
    # device the user named exists under that name.
    adapted_plan.edit_operations.extend(carried_operations)
    return adapted_plan, archetype_plan


def _build_donor_prune_plan(
    plan: IntentPlan,
    blueprint: dict[str, object],
    donor_roots: list[Path] | None = None,
) -> tuple[IntentPlan, DonorArchetypePlan]:
    topology_tags = _topology_tags_for_plan(plan, str(blueprint.get("topology_archetype", "general")))
    _, _, donor_candidates = _rank_generation_donors(plan, topology_tags, donor_roots)
    donor_candidates = _rerank_candidates_for_blueprint(
        donor_candidates, blueprint, _learned_donor_scores(plan, blueprint)
    )
    if not donor_candidates:
        blocked_plan = _copy_plan(plan)
        gap = _strict_compatibility_gap()
        if gap not in blocked_plan.blocking_gaps:
            blocked_plan.blocking_gaps.append(gap)
        raise PlanningError("Prompt plan is incomplete; generation was skipped.", blocked_plan)

    evaluation, diagnostics = _evaluate_donor_prune_candidates(plan, blueprint, donor_candidates)
    # A serial prompt that no ranked donor could serve comes back as a workable
    # lab without its WAN -- the deferred fallback, which leaves no diagnostic
    # marked "selected". Measured on `iki noqte arasinda leased line`: the
    # ranked pool settled for copper while `company_network.pkt`, which yields a
    # real serial link, sat in the widened pool below and was never reached.
    # Settling is still the right ending, just not before looking there.
    settled_without_the_wan = evaluation is not None and not _pool_selected_a_donor(diagnostics)
    if evaluation is not None and not settled_without_the_wan:
        adapted_plan, archetype_plan, _, _ = evaluation
        _adopt_blueprint(blueprint, archetype_plan)
        return adapted_plan, archetype_plan

    # Nothing in the ranked pool worked. That pool is one file in practice: the
    # resolved compatibility donor, since bundled samples fail the exact-build
    # policy and curated roots are empty unless `--donor-root` was passed. So a
    # request the chosen donor could not serve was reported as impossible --
    # `1 wireless router 2 laptop qur` came back as a donor limitation while
    # this machine held labs with wireless routers, access points and laptops.
    #
    # Widening happens only here, on the failure path, because summarising a
    # lab costs ~770 ms and the common case already succeeded above.
    extra_candidates = _local_donor_candidates(
        exclude={str(candidate.sample.path) for candidate in donor_candidates},
        required_types=dict(plan.device_requirements),
    )
    if extra_candidates:
        widened = _rerank_candidates_for_blueprint(extra_candidates, blueprint)
        widened_evaluation, more_diagnostics = _evaluate_donor_prune_candidates(plan, blueprint, widened)
        diagnostics = list(diagnostics) + list(more_diagnostics)
        if widened_evaluation is not None:
            if _pool_selected_a_donor(more_diagnostics):
                adapted_plan, archetype_plan, _, _ = widened_evaluation
                _adopt_blueprint(blueprint, archetype_plan)
                return adapted_plan, archetype_plan
            if evaluation is None:
                evaluation = widened_evaluation

    # Both pools are capped at four summarised labs and stop discovery as soon
    # as four match, so a serial request spends its whole budget on labs that
    # have no serial port anywhere. Measured: `company_network.pkt`, the one lab
    # on this machine known to yield a working serial WAN, appeared in neither
    # pool -- the eight ranked candidates were Meraki and firewall samples, and
    # the four widened ones were whatever matched first.
    #
    # `__serial_routers__` is the count the catalogue already measures, so
    # asking discovery for it skips the labs that cannot help instead of letting
    # them use up the cap. Only a prompt that asked for a WAN and did not get
    # one pays for this pass.
    #
    # This pass was held out for a while: the donor it reaches on this machine
    # is `Senan_Haciyev_tapsiriq.pkt`, and Packet Tracer refused the lab built
    # from it -- an unwired device costs one device, a refused file costs the
    # whole lab. That refusal is fixed now. It was a serial cable with no DCE
    # end declared, plus two port names taken from an assumed switch model.
    if _blueprint_wants_serial(blueprint):
        serial_requirements = dict(plan.device_requirements)
        serial_requirements["__serial_routers__"] = 2
        serial_candidates = _local_donor_candidates(
            exclude={str(candidate.sample.path) for candidate in donor_candidates},
            required_types=serial_requirements,
        )
        if serial_candidates:
            serial_ranked = _rerank_candidates_for_blueprint(serial_candidates, blueprint)
            serial_evaluation, serial_diagnostics = _evaluate_donor_prune_candidates(
                plan, blueprint, serial_ranked
            )
            diagnostics = list(diagnostics) + list(serial_diagnostics)
            if serial_evaluation is not None:
                if _pool_selected_a_donor(serial_diagnostics) or evaluation is None:
                    adapted_plan, archetype_plan, _, _ = serial_evaluation
                    _adopt_blueprint(blueprint, archetype_plan)
                    return adapted_plan, archetype_plan

    if evaluation is not None:
        # Every pool was asked and none could carry the WAN. A lab without it
        # beats no lab at all.
        adapted_plan, archetype_plan, _, _ = evaluation
        _adopt_blueprint(blueprint, archetype_plan)
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
    intent_blocking_gaps: list[str] | None = None,
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
    # An incomplete prompt is not a donor problem. When the intent plan has gaps,
    # donor evaluation never runs, so reporting "donor selection" with zero
    # candidate counts told the user to go fix a donor that was never consulted.
    gaps = [str(gap) for gap in (intent_blocking_gaps or []) if str(gap).strip()]
    if gaps:
        decision["status"] = "blocked_by_intent"
        decision["blocking_reasons"] = gaps
        decision["what_failed"] = "prompt completeness"
        decision["why_failed"] = gaps[0]
        decision["what_would_make_it_pass"] = (
            "Answer the missing detail in the prompt. Donor selection has not run yet, "
            "so no donor is implicated."
        )
        decision["decision_confidence"] = 0.95
        decision["blocking_layer"] = "intent"
        return decision

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
        # Name the capabilities. The generic sentence sent users looking for a
        # donor or a runtime problem when the answer was a specific feature the
        # prompt asked for and the planner produced no operations for.
        detail = "; ".join(str(item) for item in list(readiness.get("reasons", [])) if str(item).strip())
        blocking_reasons.append(
            f"Scenario '{family_label}' is not generate-ready in safe-open mode: {detail}"
            if detail
            else f"Scenario '{family_label}' is not generate-ready in safe-open mode because critical capability coverage is still missing."
        )
        decision["status"] = "blocked_by_capability"
        decision["blocking_layer"] = "capability"
        decision["decision_confidence"] = 0.9
        what_failed = "critical capability coverage"
        why_failed = "; ".join(str(item) for item in list(readiness.get("reasons", [])) if str(item).strip()) or (
            f"Critical capabilities for {family_label} are still unsupported."
        )
    elif readiness_status == "acceptance_gated":
        # Advisory, not blocking. This gate comes from a hand-maintained maturity
        # table -- the same kind of unmeasured claim this repo has been unwinding
        # -- and it refused scenarios that demonstrably work. Measured
        # 2026-08-03: an OSPF lab built through this path contains `router ospf`
        # with its network statements and opens in Packet Tracer in 13.4s.
        #
        # The corpus is the evidence mechanism now: if a routing scenario ever
        # stops opening, a corpus case fails and says so, which a table cannot.
        decision["status"] = "acceptance_gated_advisory"
        decision["blocking_layer"] = ""
        decision["decision_confidence"] = 0.7
        decision["advisory_note"] = (
            f"Scenario '{family_label}' is marked acceptance-gated in the capability table. "
            "Generation proceeded because the operations it needs are emitted and the result is "
            "verified by the corpus; treat the configuration as unreviewed rather than unsupported."
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
        **_critical_parity_counts(critical_capability_parity),
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
        # The parser owns this decision (`intent_parser.distribute_hosts_across_vlans`).
        # Keeping a second copy here is what produced the class of bug this repo
        # kept hitting, so this branch only mirrors the parser's strict mode.
        if strict_vlan_assignment():
            gap = "Host-to-VLAN assignment is missing. Specify how many PCs belong to each VLAN."
            if gap not in enriched.blocking_gaps:
                enriched.blocking_gaps.append(gap)
        else:
            enriched.host_vlan_assignment = distribute_hosts_across_vlans(
                int(enriched.device_requirements.get("PC", 0)),
                enriched.vlan_ids,
            )

    if any(cap in enriched.capabilities for cap in ["vlan", "trunk"]) or enriched.vlan_ids:
        for capability in ["vlan", "trunk", "access_port"]:
            if capability not in enriched.capabilities:
                enriched.capabilities.append(capability)
    if enriched.vlan_ids and enriched.device_requirements.get("Router", 0):
        for capability in ["router_on_a_stick"]:
            if capability not in enriched.capabilities:
                enriched.capabilities.append(capability)

    return enriched


# Below this many switches a lab is a single closet and one model is honest.
# At or above it, a core that can route is what anyone would actually build.
LAYER3_CORE_SWITCH_THRESHOLD = 3


def _promote_layer3_core(plan: IntentPlan) -> IntentPlan | None:
    """Trade one plain switch for a multilayer one, when a donor can serve it.

    A prompt that just asks for switches gets the same model everywhere, which
    is the complaint this answers. Asking for a Layer-3 switch already works, so
    the only thing missing was asking.

    The decision is made *before* planning, on purpose. The obvious shape --
    plan with the promotion, fall back on PlanningError -- was tried and had to
    be reverted: planning mutates state outside the plan it is given, so a
    refused attempt leaves the process unable to plan the same prompt again, and
    an 8-switch lab stopped generating at all. Asking the donor index first
    costs a cached lookup and cannot fail that way.

    Returns None when there is nothing to promote or nothing to promote onto.
    """
    if plan.device_requirements.get("MultiLayerSwitch"):
        return None
    switches = int(plan.device_requirements.get("Switch", 0) or 0)
    if switches < LAYER3_CORE_SWITCH_THRESHOLD:
        return None

    try:
        from local_donors import discover_local_donors

        candidates = discover_local_donors(
            required_types={"MultiLayerSwitch": 1}, stop_after=25
        )
    except Exception:  # noqa: BLE001 - a preference must never fail a run
        return None
    # `required_types` asks whether a donor *has* a kind, not how many, so the
    # count has to be checked here. Passing `Switch: 21` through it matched any
    # donor with a single switch, which is how the 21-switch prompt got promoted
    # and then refused. Measured on this machine, the roomiest Layer-3 donor
    # carries ten switches, so large labs correctly get no promotion.
    # Hosts count too. Donor-prune reuses the hosts already attached to a donor
    # switch, so a donor with seven switches and six PCs cannot serve a prompt
    # wanting twelve -- the groups it hands out come up empty and the whole lab
    # is refused. `company_network.pkt` is exactly that shape, which is why the
    # switch count alone still let an 8-switch prompt through and lose.
    wanted_hosts = int(plan.device_requirements.get("PC", 0) or 0)
    if not any(
        (donor.device_counts or {}).get("Switch", 0) >= switches - 1
        and (donor.device_counts or {}).get("PC", 0)
        + (donor.device_counts or {}).get("Pc", 0)
        >= wanted_hosts
        for donor in candidates
    ):
        return None

    promoted = copy.deepcopy(plan)
    promoted.device_requirements["Switch"] = switches - 1
    promoted.device_requirements["MultiLayerSwitch"] = 1
    return promoted


def build_prompt_blueprint(plan: IntentPlan, donor_roots: list[Path] | None = None) -> tuple[dict[str, object], IntentPlan]:
    prepared = _apply_prompt_compatibility_requirements(plan, donor_roots)
    if prepared.blocking_gaps:
        prepared.blueprint_plan = asdict(build_blueprint_plan(prepared))
        raise PlanningError("Prompt plan is incomplete; generation was skipped.", prepared)

    devices = _seed_devices_from_plan(prepared)
    links = _synthesize_links(prepared, devices)
    prepared.links = links
    _synthesize_vlan_and_link_ops(prepared, devices, links)
    _synthesize_service_ops(prepared, devices)
    _synthesize_wireless_ops(prepared, devices)
    _synthesize_routing_ops(prepared, devices)
    _synthesize_security_ops(prepared, devices)
    _synthesize_resilience_ops(prepared, devices)
    _synthesize_voice_ops(prepared, devices)
    _synthesize_wan_ops(prepared, devices)


    _note_model_substitutions(prepared, devices)
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
    remote_dry_run: bool = False,
    remote_audit_out: Path | None = None,
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
        remote_dry_run=remote_dry_run,
        remote_audit_out=remote_audit_out,
    )
    raw_plan.remote_search_results = remote_results
    if raw_plan.goal == "edit" and raw_plan.pkt_path:
        edit_pkt_file(raw_plan.pkt_path, raw_plan, output_path, xml_out_path)
        print(f"Edited PKT file created: {output_path}")
        return

    promoted_plan = _promote_layer3_core(raw_plan)
    try:
        blueprint, prepared_plan = build_prompt_blueprint(
            promoted_plan if promoted_plan is not None else raw_plan, resolved_donor_roots
        )
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
        donor_blocking_reason=_inspect_packet_tracer_compatibility_donor_cached().blocking_reason,
    )
    scenario_generate_decision = _scenario_generate_decision(coverage_gap)
    advisory = str(scenario_generate_decision.get("advisory_note") or "")
    if advisory and advisory not in prepared_plan.assumptions_used:
        prepared_plan.assumptions_used.append(advisory)
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
    # What the prompt asked things to be called, kept before donor adaptation
    # gets to rewrite it. The chosen donor substitutes its own device names into
    # the blueprint -- `SW3` became `MultiLayerSwitch1` -- and the file then
    # honours the rewritten plan, so a lab asked for `SW3` ships without one.
    # Both checks below measure against the request, not against what the donor
    # turned it into.
    requested_devices = {
        "devices": [dict(device) for device in blueprint.get("devices", [])]
    }
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
    port_repairs = _repair_invalid_link_ports(root)
    mac_repairs = _assign_unique_macs(root)
    _match_link_port_families(root)
    # After the families agree and before the addresses are handed out: a
    # copper cable in a fibre socket is dropped by Packet Tracer on load,
    # silently, in a file that still opens.
    _move_copper_cables_off_fibre_ports(root)
    _assign_unique_interface_addresses(root)
    _assign_unique_switch_management_ips(root)
    media_notes = _reconcile_cable_media(root)
    # After reconciliation, because that is what settles which cables are
    # serial: a cable demoted to copper must lose its clocking end, and one
    # promoted to serial must gain one.
    _declare_serial_dce_ends(root)
    # First of the configuration repairs: a block for hardware the device does
    # not have carries the donor's whole address plan into every pass that
    # reads the router's networks.
    absent_notes = _drop_config_for_absent_interfaces(root)
    trunk_notes = _trunk_uplinks_in_file(root)
    trunk_notes += absent_notes
    # Before the access-VLAN pass, which would otherwise strip the tagging:
    # a switch port facing router subinterfaces has to be a trunk. The
    # subinterfaces move to the cabled port first, or there is nothing there
    # for the trunk to carry.
    trunk_notes += _move_subinterfaces_to_the_cabled_port(root)
    trunk_notes += _trunk_router_on_a_stick(root)
    vlan_notes = _align_router_access_vlan(root)
    # After the router's own port is settled: a host whose address belongs to
    # one VLAN and whose port sits in another cannot reach its own subnet.
    vlan_notes += _align_host_vlans_to_addresses(root)
    gateway_repairs = _align_router_gateway(root)
    # Last, because `_align_router_gateway` writes the gateway onto the
    # physical cabled interface -- correct for an access link, wrong for a
    # trunk, where the address has to sit on the subinterface for its VLAN.
    trunk_notes += _move_subinterfaces_to_the_cabled_port(root)
    # A learned sticky MAC belongs to the donor's device, not to the one now
    # plugged in, and `restrict` drops every frame that does not match it.
    trunk_notes += _drop_inherited_sticky_macs(root)
    # Both ends of every trunk must name the same native VLAN, or spanning
    # tree blocks the port and the cable carries nothing.
    trunk_notes += _match_trunk_native_vlans(root)
    # After every trunk is settled: port security on a trunk cuts the switch
    # behind it off entirely.
    trunk_notes += _drop_port_security_from_trunks(root)
    # After the trunks are settled: a channel-group naming ports the cable
    # never joined takes the switch behind it off the network.
    trunk_notes += _align_etherchannels_with_cabling(root)
    _stamp_target_version(root)
    unexpected_workspace_issues = _unexpected_workspace_issues(donor_root, root)
    if unexpected_workspace_issues:
        raise ValueError("; ".join(unexpected_workspace_issues))
    validate_donor_coherence(donor_root, root)
    _align_dhcp_pools_with_interfaces(root)
    # After the pools point at real networks: a pool with no client is not
    # DHCP, and the segmented path never emitted the client half.
    # Before the clients are switched over: a VLAN with hosts and no gateway
    # cannot serve any of them.
    # A port with no VLAN sits in VLAN 1, which the plan never gives a
    # gateway, so the host on it is isolated whatever else is right.
    _place_hosts_in_a_vlan(root)
    _serve_every_populated_vlan(root)
    # Again, now that new VLANs exist: the router-facing trunk lists the
    # VLANs it may carry, and it was written before those VLANs were
    # created -- so their hosts had a gateway the trunk would not pass.
    _trunk_router_on_a_stick(root)
    _put_workstations_on_dhcp(root)
    # Snooping without a trusted uplink eats every offer the router sends.
    _trust_uplinks_for_dhcp_snooping(root)
    # Last: the standby gateway takes the address the hosts already use,
    # so nothing written before it has to change.
    _add_hsrp_gateway_redundancy(root)
    # A router with no path to another router carries none of its routes.
    _mesh_routers_with_point_to_point_links(root)
    _group_hosts_under_their_switch(root)
    _separate_overlapping_devices(root)
    # After the separation pass, so a leftover nudged sideways is still pulled in.
    _compact_stray_devices(root)
    _save_running_config_to_startup(root)
    # Before the annotation and the serialisation: the annotation names the
    # devices, and a rename after `serialize_pkt_xml` would change nothing
    # in the file that was written.
    for _note in _adopt_planned_names(root, requested_devices):
        print(_note)
    _annotate_generated_lab(root, blueprint, prepared_plan)
    prune_unused_images(root)
    xml_bytes = serialize_pkt_xml(root)
    if xml_out_path is not None:
        xml_out_path.parent.mkdir(parents=True, exist_ok=True)
        xml_out_path.write_bytes(xml_bytes)
    pkt_bytes = encode_pkt_modern(xml_bytes)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(pkt_bytes)
    for note in _report_undelivered_devices(root, requested_devices):
        print(note)
    for note in _report_unwired_devices(root, requested_devices):
        print(note)
    print(f"Selected donor: {donor_archetype.compat_donor}")
    compat_donor, compat_donor_version = _compat_donor_details()
    if compat_donor is not None:
        print(f"Compatibility donor: {compat_donor} ({compat_donor_version or 'unknown'})")
    _record_generation_outcome(
        prompt=prompt,
        scenario_decision=scenario_generate_decision,
        donor_archetype=donor_archetype,
        outcome=usage_ledger.OUTCOME_GENERATED_UNVERIFIED,
    )
    if blueprint_out_path is not None:
        blueprint_out_path.parent.mkdir(parents=True, exist_ok=True)
        blueprint_out_path.write_text(json.dumps(blueprint_plan, indent=2, ensure_ascii=False), encoding="utf-8")
    if resolved_reference_roots:
        references = load_reference_catalog(resolved_reference_roots)
        print(f"Loaded reference-only samples: {len(references)}")


def _resolve_edit_link_ports(pkt_path: Path, plan: IntentPlan) -> None:
    """Fill in real, free ports on link edits phrased without them.

    A sentence like `SW1 ve SW2 arasinda link qur` names no interface, so the
    operation arrives with empty port names. Writing that out produced a file
    Packet Tracer refuses to open -- naming a port a device does not have is a
    measured way to break a lab, and an empty name is exactly that.

    Ports are resolved against the file being edited: existing links tell us
    what is taken, and the device's own port list tells us what exists. A link
    whose ports cannot be resolved is dropped, with the reason recorded, rather
    than written out broken.
    """
    link_ops = [
        op
        for op in plan.edit_operations
        if op.get("op") == "set_link"
        and (not str(op.get("a", {}).get("port") or "") or not str(op.get("b", {}).get("port") or ""))
    ]
    if not link_ops:
        return

    from pkt_codec import parse_pkt_xml
    from pkt_transformer import port_capacity, port_exists

    root = parse_pkt_xml(decode_pkt_modern(pkt_path.read_bytes()))
    devices = {
        (device.findtext("./ENGINE/NAME") or ""): device
        for device in root.findall(".//DEVICES/DEVICE")
    }
    taken: set[tuple[str, str]] = set()
    save_ref_to_name = {
        device.findtext("./ENGINE/SAVE_REF_ID") or "": name for name, device in devices.items()
    }
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        ends = [save_ref_to_name.get(cable.findtext(tag) or "", "") for tag in ("FROM", "TO")]
        ports = [port.text or "" for port in cable.findall("PORT")]
        for name, port in zip(ends, ports):
            if name and port:
                taken.add((name, port))

    def pick(device_name: str) -> str:
        """A free interface the device actually has.

        Candidate names follow the same per-kind rules generation uses, and each
        is confirmed with `port_exists`. Two rounds of guessing at name patterns
        produced `FastEthernet0` for a switch and `FastEthernet0/1` for a PC --
        neither device has those, and Packet Tracer rejects a lab referencing an
        interface that does not exist.
        """
        device = devices.get(device_name)
        if device is None:
            return ""
        kind = (device.findtext("./ENGINE/TYPE") or "").strip()
        capacity = port_capacity(device)

        if kind in {"Pc", "PC", "Server", "Printer", "Laptop", "WirelessEndDevice"}:
            candidates = ["FastEthernet0", "GigabitEthernet0"]
        elif kind in {"Tablet", "Smartphone", "TabletPC", "Pda"}:
            candidates = ["Wireless0"]
        else:
            # Infrastructure port names vary by model: a 2960 has
            # `GigabitEthernet0/1` and an ISR router has `GigabitEthernet0/0/1`.
            # Guessing the shape produced a name R1 does not have, and the lab
            # would not open. Take the shape from ports this device is already
            # using in this very file, and only vary the last number.
            candidates = []
            for used_device, used_port in sorted(taken):
                if used_device != device_name:
                    continue
                match = re.match(r"^(.*?)(\d+)$", used_port)
                if not match:
                    continue
                prefix, last = match.group(1), int(match.group(2))
                for offset in range(1, max(capacity.values(), default=8) + 2):
                    candidates.append(f"{prefix}{last + offset}")
            if not candidates:
                candidates = [
                    f"{family}0/{index}"
                    for family in ("GigabitEthernet", "FastEthernet")
                    for index in range(1, capacity.get(family, 0) + 1)
                ]

        for candidate in candidates:
            if (device_name, candidate) in taken:
                continue
            if port_exists(device, candidate):
                taken.add((device_name, candidate))
                return candidate
        return ""

    for operation in list(link_ops):
        left, right = operation["a"], operation["b"]
        left["port"] = str(left.get("port") or "") or pick(str(left["dev"]))
        right["port"] = str(right.get("port") or "") or pick(str(right["dev"]))
        if not left["port"] or not right["port"]:
            plan.edit_operations.remove(operation)
            gap = (
                f"Could not find a free port for the link between {left['dev']} and "
                f"{right['dev']}; name the interfaces explicitly."
            )
            if gap not in plan.blocking_gaps:
                plan.blocking_gaps.append(gap)


def edit_from_prompt(
    pkt_path: Path,
    prompt: str,
    output_path: Path,
    xml_out_path: Path | None = None,
) -> None:
    plan = parse_intent(prompt)
    plan.goal = "edit"
    plan.pkt_path = str(pkt_path)

    # An edit request nobody understood used to write an unchanged copy and
    # report success. The file opened, because it was the original -- the same
    # trap the corpus fell into, where "it opened" was read as "it worked".
    operation_buckets = (
        plan.edit_operations,
        plan.switch_ops,
        plan.router_ops,
        plan.server_ops,
        plan.wireless_ops,
        plan.end_device_ops,
        plan.management_ops,
    )
    _resolve_edit_link_ports(pkt_path, plan)

    if not any(operation_buckets):
        raise PlanningError(
            "No edit was understood from that request, so the file was left alone. "
            "Name the device and what to change, for example "
            "'rename PC1 to PC-Ofis', 'PC1 adini PC-Ofis et', or 'SW1 de vlan 20 yarat'.",
            plan,
        )

    edit_pkt_file(pkt_path, plan, output_path, xml_out_path, repair=_align_etherchannels_with_cabling)
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
    remote_dry_run: bool = False,
    remote_audit_out: Path | None = None,
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
        remote_dry_run=remote_dry_run,
        remote_audit_out=remote_audit_out,
    )
    plan = _apply_prompt_compatibility_requirements(raw_plan, resolved_donor_roots)
    plan.remote_search_results = remote_results
    donor_details = _inspect_packet_tracer_compatibility_donor_cached()
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
        intent_blocking_gaps=list(plan.blocking_gaps),
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
    critical_capability_parity, _critical_parity_mismatches = _critical_capability_parity(dict(result.get("coverage_gaps") or {}))
    result["scenario_matrix_row"].update(_critical_parity_counts(critical_capability_parity))
    fixture_status, fixture_gaps = _fixture_expectation_status(result)
    result["fixture_registry_version"] = _load_fixture_corpus().get("fixture_registry_version", "unknown")
    result["fixture_expectation_status"] = fixture_status
    result["fixture_expectation_gaps"] = fixture_gaps
    result["user_summary"] = _explain_user_summary(result)
    result["next_best_action"] = result["user_summary"]["next_best_action"]
    result["support_level_explanation"] = result["user_summary"]["support_level_explanation"]
    result["proof_card_refs"] = result["user_summary"]["proof_card_refs"]
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
    remote_dry_run: bool = False,
    remote_audit_out: Path | None = None,
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
        remote_dry_run=remote_dry_run,
        remote_audit_out=remote_audit_out,
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
    donor_details = _inspect_packet_tracer_compatibility_donor_cached()
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
    """Structurally verify the file, then confirm Packet Tracer really opens it.

    This used to launch Packet Tracer and print `{"status": "launched"}` without
    waiting for or observing anything, so a corrupt file reported the same
    result as a working one.
    """
    require_packet_tracer_exe()
    structural = pkt_verify.structural_check(pkt_path)
    payload: dict[str, object] = {"structural": structural.to_json()}
    if structural.passed:
        payload["open"] = pkt_verify.open_check(pkt_path).to_json()
    else:
        payload["open"] = {
            "tier": "open",
            "status": "skipped",
            "opened": False,
            "detail": "structural check failed; not launching Packet Tracer",
        }
    print(json.dumps(payload, ensure_ascii=False))


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
    remote_dry_run: bool = False,
    remote_audit_out: Path | None = None,
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
        remote_dry_run=remote_dry_run,
        remote_audit_out=remote_audit_out,
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
        **_critical_parity_counts(critical_capability_parity),
    }
    result["user_summary"] = _parity_user_summary(result)
    result["next_best_action"] = result["user_summary"]["next_best_action"]
    result["support_level_explanation"] = result["user_summary"]["message"]
    result["proof_card_refs"] = result["user_summary"]["proof_card_refs"]
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
    remote_dry_run: bool = False,
    remote_audit_out: Path | None = None,
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
            remote_dry_run=remote_dry_run,
            remote_audit_out=remote_audit_out,
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


LOCAL_AUDIT_PATTERNS = {
    "ospfv2": r"(?mi)^\s*router\s+ospf\s+\d+",
    "eigrp_ipv4": r"(?mi)^\s*router\s+eigrp\s+\d+",
    "ripv2": r"(?mi)^\s*router\s+rip\s*$",
    "static_route": r"(?mi)^\s*ip\s+route\s+\S+\s+\S+\s+\S+",
    "default_route": r"(?mi)^\s*ip\s+route\s+0\.0\.0\.0\s+0\.0\.0\.0\s+\S+",
    "dhcp_relay": r"(?mi)^\s*ip\s+helper-address\s+\d+\.\d+\.\d+\.\d+",
    "nat_static": r"(?mi)^\s*ip\s+nat\s+inside\s+source\s+static\b",
    "nat_dynamic": r"(?mi)^\s*ip\s+nat\s+inside\s+source\s+(?:list|route-map)\b",
    "pat": r"(?mi)^\s*ip\s+nat\s+inside\s+source\s+list\s+\S+\s+interface\s+\S+\s+overload\b",
    "ssh_ios": r"(?mi)^\s*(?:ip\s+ssh|crypto\s+key\s+generate|ip\s+domain-name)\b",
    "ntp_ios": r"(?mi)^\s*ntp\s+server\s+\d+\.\d+\.\d+\.\d+",
    "syslog_ios": r"(?mi)^\s*logging\s+host\s+\d+\.\d+\.\d+\.\d+",
    "bgp": r"(?mi)^\s*router\s+bgp\s+\d+",
    "stp": r"(?mi)^\s*spanning-tree\b",
    "etherchannel": r"(?mi)^\s*(?:channel-group\s+\d+|interface\s+Port-channel)",
    "hsrp": r"(?mi)^\s*standby\s+\d+",
    "acl": r"(?mi)^\s*(?:access-list\s+\d+|ip\s+access-list\s+(?:standard|extended))\b",
    "dhcp_pool": r"(?mi)^\s*ip\s+dhcp\s+pool\b",
}


def build_local_sample_audit(root: Path) -> dict[str, object]:
    files = sorted([*root.rglob("*.pkt"), *root.rglob("*.pka")])
    capability_counts: Counter[str] = Counter()
    capability_examples: dict[str, list[str]] = defaultdict(list)
    device_counts: Counter[str] = Counter()
    decode_failures: list[dict[str, str]] = []
    for pkt_path in files:
        rel = str(pkt_path.relative_to(root))
        try:
            pkt_root = decode_pkt_to_root(pkt_path)
        except Exception as exc:
            decode_failures.append({"path": rel, "error_type": type(exc).__name__, "message": str(exc)[:200]})
            continue
        try:
            inventory = inventory_root(pkt_root)
            for device_type, count in inventory.get("topology_summary", {}).get("device_counts", {}).items():
                device_counts[str(device_type)] += int(count)
        except Exception:
            pass
        running = "\n".join(line.text or "" for line in pkt_root.findall(".//ENGINE/RUNNINGCONFIG/LINE"))
        for capability, pattern in LOCAL_AUDIT_PATTERNS.items():
            if re.search(pattern, running):
                capability_counts[capability] += 1
                if len(capability_examples[capability]) < 5:
                    capability_examples[capability].append(rel)
    promotion_candidates = [
        {
            "capability": capability,
            "sample_count": count,
            "candidate_status": "local_evidence_only",
            "next_safe_action": "Add parser/inventory/editor roundtrip proof before public readiness promotion.",
        }
        for capability, count in capability_counts.most_common()
    ]
    return {
        "audit_version": "1.0",
        "source_root": str(root),
        "policy": "Local user-supplied Packet Tracer files are evidence inputs only; raw .pkt/.pka files are not public package content.",
        "total_files": len(files),
        "decode_success_count": len(files) - len(decode_failures),
        "decode_fail_count": len(decode_failures),
        "decode_failures": decode_failures[:20],
        "detected_config_capabilities": {
            capability: {
                "sample_count": count,
                "examples": capability_examples.get(capability, []),
            }
            for capability, count in capability_counts.most_common()
        },
        "top_device_types": [{"device_type": device_type, "count": count} for device_type, count in device_counts.most_common(30)],
        "promotion_candidates": promotion_candidates,
    }


def local_sample_audit(root: Path, audit_out: Path | None = None) -> None:
    payload = build_local_sample_audit(root)
    target = audit_out or (Path("output") / "local-sample-audit.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))


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
    parser.add_argument("--remote-dry-run", action="store_true", help="Preview remote GitHub sample candidates and write an audit without downloading archives")
    parser.add_argument("--remote-audit-out", help="Optional JSON path for the local-only remote sample audit report")
    parser.add_argument("--blueprint-out", help="Optional JSON output path for the generated blueprint plan or refusal blueprint")
    parser.add_argument("--coverage-report", action="store_true", help="Print the aggregated capability coverage matrix")
    parser.add_argument("--feature-gap-report", action="store_true", help="Print the Packet Tracer feature gap atlas report")
    parser.add_argument("--local-sample-audit-root", help="Local user-supplied Packet Tracer sample folder to audit without importing raw files")
    parser.add_argument("--local-sample-audit-out", help="Optional JSON path for --local-sample-audit-root output")
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
    remote_audit_out = Path(args.remote_audit_out) if args.remote_audit_out else None

    if args.explain_plan:
        explain_plan(
            args.explain_plan,
            reference_roots,
            donor_roots,
            search_remote=args.search_remote,
            remote_provider=args.remote_provider,
            import_cache_root=import_cache_root,
            max_remote_results=args.max_remote_results,
            remote_dry_run=args.remote_dry_run,
            remote_audit_out=remote_audit_out,
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
            remote_dry_run=args.remote_dry_run,
            remote_audit_out=remote_audit_out,
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
            remote_dry_run=args.remote_dry_run,
            remote_audit_out=remote_audit_out,
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
        try:
            edit_from_prompt(Path(args.edit), args.prompt, Path(args.output), Path(args.xml_out) if args.xml_out else None)
        except PlanningError as exc:
            # Report a refused edit the same way a refused generation is
            # reported, rather than as a traceback.
            print(json.dumps(exc.to_dict(), indent=2, ensure_ascii=False))
            raise SystemExit(2) from exc
        return
    if args.coverage_report:
        coverage_report(reference_roots, donor_roots, device_family=args.device_family)
        return
    if args.feature_gap_report:
        feature_gap_report()
        return
    if args.local_sample_audit_root:
        local_sample_audit(Path(args.local_sample_audit_root), Path(args.local_sample_audit_out) if args.local_sample_audit_out else None)
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
                remote_dry_run=args.remote_dry_run,
                remote_audit_out=remote_audit_out,
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
