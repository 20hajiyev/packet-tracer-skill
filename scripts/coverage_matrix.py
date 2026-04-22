from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from intent_parser import IntentPlan
from sample_catalog import SampleDescriptor

MATURITY_LEVELS = [
    "reference-known",
    "inventory-supported",
    "edit-supported",
    "config-mutation-supported",
    "safe-open-generate-supported",
    "acceptance-verified",
]
MATURITY_RANK = {level: index for index, level in enumerate(MATURITY_LEVELS)}

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

DEFAULT_FAMILY_LIMITATIONS = {
    "access points": ["wireless client association requires donor-backed acceptance"],
    "home/wireless routers": ["wireless client association and local NAT flows are acceptance-gated"],
    "iot devices": ["iot registration/control is not acceptance-verified yet"],
    "wan/cloud/dsl/cable devices": ["advanced wan/cloud patterns depend on donor availability"],
    "security devices": ["advanced security devices remain donor-limited"],
}

CAPABILITY_PROVIDER_FAMILIES = {
    "access_port": {"switches", "multilayer switches"},
    "trunk": {"switches", "multilayer switches"},
    "native_vlan": {"switches", "multilayer switches"},
    "vlan": {"switches", "multilayer switches", "routers"},
    "switching": {"switches", "multilayer switches"},
    "router_on_a_stick": {"routers", "multilayer switches"},
    "management": {"switches", "multilayer switches", "routers"},
    "management_vlan": {"switches", "multilayer switches"},
    "telnet": {"switches", "multilayer switches", "routers"},
    "ssh": {"switches", "multilayer switches", "routers"},
    "nat": {"routers", "home/wireless routers", "security devices"},
    "pat": {"routers", "home/wireless routers", "security devices"},
    "acl": {"routers", "multilayer switches", "switches", "security devices"},
    "vpn": {"routers", "security devices", "wan/cloud/dsl/cable devices"},
    "ipsec": {"routers", "security devices", "wan/cloud/dsl/cable devices"},
    "gre": {"routers", "wan/cloud/dsl/cable devices"},
    "ppp": {"routers", "wan/cloud/dsl/cable devices"},
    "multilayer_switching": {"multilayer switches"},
    "wan": {"wan/cloud/dsl/cable devices", "routers"},
    "security_edge": {"security devices", "routers"},
    "wireless": {"access points", "home/wireless routers", "end devices"},
    "wireless_ap": {"access points", "home/wireless routers"},
    "wireless_mutation": {"access points", "home/wireless routers"},
    "wireless_client": {"end devices", "access points", "home/wireless routers"},
    "wireless_client_association": {"end devices", "access points", "home/wireless routers"},
    "end_device_mutation": {"end devices"},
    "dhcp": {"routers", "servers", "home/wireless routers"},
    "dhcp_pool": {"routers", "servers", "home/wireless routers"},
    "router_dhcp": {"routers", "home/wireless routers"},
    "server_dhcp": {"servers"},
    "dns": {"servers", "routers"},
    "server_dns": {"servers"},
    "server_http": {"servers"},
    "server_ftp": {"servers"},
    "server_https": {"servers"},
    "server_tftp": {"servers"},
    "server_email": {"servers"},
    "server_syslog": {"servers"},
    "server_aaa": {"servers"},
    "ntp": {"servers", "routers", "switches", "multilayer switches"},
    "iot": {"iot devices"},
    "iot_registration": {"iot devices"},
    "iot_control": {"iot devices"},
    "tablet": {"end devices"},
    "printer": {"end devices"},
    "verification": {"routers", "switches", "multilayer switches", "servers", "end devices", "access points"},
}


@dataclass
class CapabilityMatrixEntry:
    device_family: str
    capability: str
    maturity_level: str
    accepted_donors: list[str]
    known_limitations: list[str]


@dataclass
class CoverageGapReport:
    requested_capabilities: list[str]
    supported_capabilities: list[str]
    unsupported_capabilities: list[str]
    requested_device_families: list[str]
    unsupported_device_families: list[str]
    requires_curated_donor: list[str]
    requires_manual_acceptance: list[str]
    capability_statuses: list[dict[str, object]]
    capability_parity: list[dict[str, object]]
    scenario_family: str | None = None
    scenario_generate_readiness: dict[str, object] = field(default_factory=dict)
    recommended_next_actions: list[str] = field(default_factory=list)


@dataclass
class BlueprintPlan:
    requested_devices: list[dict[str, object]]
    requested_links: list[dict[str, object]]
    required_capabilities: list[str]
    required_donor_capacity: dict[str, int]
    required_link_pairs: list[str]


@dataclass
class DonorGraphFit:
    matched_pairs: list[str]
    missing_pairs: list[str]
    port_media_conflicts: list[str]
    fit_score: int
    layout_reuse_score: int


def _device_family_for_type(device_type: str) -> str:
    return DEVICE_FAMILY_MAP.get(device_type, "pt-specific edge/utility devices")


def _sample_maturity(sample: SampleDescriptor) -> str:
    if sample.origin == "cisco-local" and sample.prototype_eligible and sample.version.startswith("9."):
        structural = "acceptance-verified"
    elif sample.origin in {"compat-donor", "external-curated"} and sample.donor_eligible and sample.prototype_eligible:
        structural = "safe-open-generate-supported"
    elif sample.capability_tags:
        structural = "config-mutation-supported"
    elif sample.devices:
        structural = "inventory-supported"
    else:
        structural = "reference-known"
    declared = sample.apply_safety_level if sample.apply_safety_level in MATURITY_RANK else "reference-known"
    if MATURITY_RANK[declared] > MATURITY_RANK[structural]:
        return declared
    return structural


def _merge_limitations(existing: list[str], new_items: list[str]) -> list[str]:
    merged = list(existing)
    for item in new_items:
        if item and item not in merged:
            merged.append(item)
    return merged


def _expanded_sample_capabilities(sample: SampleDescriptor, device_families: list[str]) -> list[str]:
    capabilities = set(sample.capability_tags)
    service_capability_map = {
        "dhcp": {"dhcp", "server_dhcp"},
        "dns": {"dns", "server_dns"},
        "http": {"server_http"},
        "https": {"server_https"},
        "ftp": {"server_ftp"},
        "tftp": {"server_tftp"},
        "email": {"server_email"},
        "syslog": {"server_syslog"},
        "aaa": {"server_aaa"},
        "ntp": {"ntp"},
    }
    for service in sample.service_support:
        capabilities.add(service)
        capabilities.update(service_capability_map.get(service, set()))
    families = set(device_families)
    topology_tags = set(sample.topology_tags)
    normalized_counts = sample.normalized_device_counts()
    iot_roles = set(sample.iot_roles)

    if "vlan" in capabilities and families & {"switches", "multilayer switches"}:
        capabilities.update({"trunk", "access_port"})
    if (
        "router_on_a_stick" in capabilities
        or "router_on_a_stick" in topology_tags
        or ("vlan" in capabilities and {"routers", "switches"} <= families)
    ):
        capabilities.add("router_on_a_stick")
    if "management_vlan" in capabilities:
        capabilities.add("telnet")
    if "telnet" in capabilities and families & {"switches", "multilayer switches"}:
        capabilities.add("management_vlan")
    if normalized_counts.get("Printer", 0) > 0 or ("end devices" in families and "host_server" in capabilities):
        capabilities.add("printer")
    if "end devices" in families:
        capabilities.add("end_device_mutation")
    if sample.wireless_mode_tags and {"access points", "home/wireless routers"} & families and "wireless_ap" in capabilities:
        capabilities.add("wireless_mutation")
        capabilities.add("wireless_client")
        capabilities.add("wireless_client_association")
    if iot_roles:
        capabilities.add("iot")
    if "thing" in iot_roles and ("server" in iot_roles or "gateway" in iot_roles):
        capabilities.add("iot_registration")
    if "thing" in iot_roles and ("gateway" in iot_roles or "server" in iot_roles):
        capabilities.add("iot_control")
    if sample.link_count > 0 and families & {"routers", "switches", "multilayer switches", "servers", "end devices", "access points"}:
        capabilities.add("verification")
    if "multilayer switches" in families:
        capabilities.add("multilayer_switching")
    if "wan/cloud/dsl/cable devices" in families:
        capabilities.add("wan")
    if "security devices" in families:
        capabilities.add("security_edge")
    if "vpn" in capabilities:
        capabilities.update({"ipsec", "gre"})
    return sorted(capabilities)


def build_capability_matrix(samples: list[SampleDescriptor]) -> list[CapabilityMatrixEntry]:
    entries: dict[tuple[str, str], CapabilityMatrixEntry] = {}
    for sample in samples:
        maturity = _sample_maturity(sample)
        device_families = sorted({_device_family_for_type(device.get("type", "")) for device in sample.devices if device.get("type")})
        capabilities = _expanded_sample_capabilities(sample, device_families)
        limitations: list[str] = []
        if not sample.donor_eligible:
            limitations.append("not donor-eligible")
        if not sample.prototype_eligible:
            limitations.append("reference-only")
        for family in device_families or ["pt-specific edge/utility devices"]:
            known_family_limitations = DEFAULT_FAMILY_LIMITATIONS.get(family, [])
            for capability in capabilities or ["inventory"]:
                key = (family, capability)
                donor_label = sample.relative_path
                if key not in entries:
                    entries[key] = CapabilityMatrixEntry(
                        device_family=family,
                        capability=capability,
                        maturity_level=maturity,
                        accepted_donors=[donor_label],
                        known_limitations=_merge_limitations([], [*known_family_limitations, *limitations]),
                    )
                    continue
                current = entries[key]
                if MATURITY_RANK[maturity] > MATURITY_RANK[current.maturity_level]:
                    current.maturity_level = maturity
                if donor_label not in current.accepted_donors:
                    current.accepted_donors.append(donor_label)
                current.known_limitations = _merge_limitations(current.known_limitations, [*known_family_limitations, *limitations])
    return sorted(entries.values(), key=lambda item: (item.device_family, item.capability))


def _requested_device_families(plan: IntentPlan) -> list[str]:
    families = {_device_family_for_type(device_type) for device_type, count in plan.device_requirements.items() if count}
    return sorted(families)


def _scenario_family_for_plan(plan: IntentPlan, requested_families: list[str]) -> str | None:
    capabilities = set(plan.capabilities)
    requested_services = {str(service) for service in plan.service_requirements.get("services", []) if service}
    if capabilities & {"iot", "iot_registration", "iot_control"} or {"iot devices", "home/wireless routers"} & set(requested_families):
        return "home_iot"
    if (
        plan.network_style == "wan_security"
        or capabilities & {"vpn", "ipsec", "gre", "ppp", "multilayer_switching", "security_edge"}
        or {"wan/cloud/dsl/cable devices", "security devices"} & set(requested_families)
    ):
        return "wan_security_edge"
    if (
        requested_services & {"dns", "dhcp", "http", "https", "ftp", "tftp", "email", "syslog", "aaa", "ntp"}
        or capabilities & {"server_dns", "server_dhcp", "server_http", "server_https", "server_ftp", "server_tftp", "server_email", "server_syslog", "server_aaa"}
        or "servers" in requested_families
    ) and not (plan.department_groups or {"switches", "multilayer switches"} & set(requested_families) and capabilities & {"vlan", "router_on_a_stick", "management_vlan", "telnet"}):
        return "service_heavy"
    if (
        plan.department_groups
        or {"switches", "multilayer switches"} & set(requested_families)
        or capabilities & {"vlan", "router_on_a_stick", "management_vlan", "telnet", "acl", "nat", "pat"}
    ):
        return "campus"
    return None


SCENARIO_CAPABILITY_SETS = {
    "campus": {"router_on_a_stick", "trunk", "access_port", "management_vlan", "telnet", "verification", "acl", "nat"},
    "service_heavy": {"server_dns", "server_dhcp", "server_http", "server_https", "server_ftp", "server_tftp", "server_email", "server_syslog", "server_aaa", "ntp"},
    "home_iot": {"iot", "iot_registration", "iot_control", "wireless_ap", "wireless_mutation"},
    "wan_security_edge": {"vpn", "ipsec", "gre", "ppp", "acl", "nat"},
}

CAPABILITY_REQUIRED_ARCHETYPES = {
    "router_on_a_stick": ["campus/core"],
    "management_vlan": ["campus/core"],
    "telnet": ["campus/core"],
    "server_dns": ["service-heavy"],
    "server_dhcp": ["service-heavy"],
    "server_http": ["service-heavy"],
    "server_https": ["service-heavy"],
    "server_ftp": ["service-heavy"],
    "server_tftp": ["service-heavy"],
    "server_email": ["service-heavy"],
    "server_syslog": ["service-heavy"],
    "server_aaa": ["service-heavy"],
    "iot_registration": ["IoT/home gateway"],
    "iot_control": ["IoT/home gateway"],
    "wireless_mutation": ["wireless-heavy"],
    "wireless_client_association": ["wireless-heavy", "IoT/home gateway"],
    "vpn": ["WAN/security edge"],
    "ipsec": ["WAN/security edge"],
    "gre": ["WAN/security edge"],
    "ppp": ["WAN/security edge"],
    "multilayer_switching": ["WAN/security edge", "campus/core"],
    "security_edge": ["WAN/security edge"],
}

CAPABILITY_REQUIRED_RUNTIME_FEATURES = {
    "server_dns": ["workspace_validated", "server_runtime"],
    "server_dhcp": ["workspace_validated", "server_runtime"],
    "server_http": ["workspace_validated", "server_runtime"],
    "server_https": ["workspace_validated", "server_runtime"],
    "server_ftp": ["workspace_validated", "server_runtime"],
    "server_tftp": ["workspace_validated", "server_runtime"],
    "server_email": ["workspace_validated", "server_runtime"],
    "server_syslog": ["workspace_validated", "server_runtime"],
    "server_aaa": ["workspace_validated", "server_runtime"],
    "wireless_mutation": ["workspace_validated", "wireless_runtime"],
    "wireless_client_association": ["workspace_validated", "wireless_runtime"],
    "iot_registration": ["workspace_validated", "iot_runtime"],
    "iot_control": ["workspace_validated", "iot_runtime"],
}


def _generate_mismatch_reason(status: dict[str, object]) -> str | None:
    if not bool(status.get("inventory_supported")):
        return "unsupported"
    if bool(status.get("edit_supported")) and not bool(status.get("safe_open_generate_supported")):
        return "supported_in_edit_only"
    if bool(status.get("safe_open_generate_supported")) and bool(status.get("requires_curated_donor")):
        return "supported_but_donor_limited"
    if bool(status.get("safe_open_generate_supported")) and bool(status.get("requires_manual_acceptance")) and not bool(status.get("acceptance_verified")):
        return "supported_but_acceptance_gated"
    if bool(status.get("safe_open_generate_supported")):
        return None
    return "unsupported"


def _best_maturity_level(status: dict[str, object]) -> str:
    level = str(status.get("best_maturity_level") or "").strip()
    if level in MATURITY_RANK:
        return level
    if bool(status.get("acceptance_verified")):
        return "acceptance-verified"
    if bool(status.get("safe_open_generate_supported")):
        return "safe-open-generate-supported"
    if bool(status.get("config_mutation_supported")):
        return "config-mutation-supported"
    if bool(status.get("edit_supported")):
        return "edit-supported"
    if bool(status.get("inventory_supported")):
        return "inventory-supported"
    return "reference-known"


def _recommended_next_action_for_capability(capability: str, mismatch_reason: str | None) -> str:
    if mismatch_reason == "supported_in_edit_only":
        return f"Use donor-backed edit flow for {capability} until safe-open generate coverage is raised."
    if mismatch_reason == "supported_but_donor_limited":
        return f"Provide or curate a donor whose skeleton explicitly covers {capability}."
    if mismatch_reason == "supported_but_acceptance_gated":
        return f"Keep {capability} in explain/edit flow until acceptance evidence is promoted."
    return f"Import or curate donor coverage for {capability} before strict generate."


def _scenario_generate_readiness(
    scenario_family: str | None,
    capability_statuses: list[dict[str, object]],
    unsupported_capabilities: list[str],
    requires_curated_donor: list[str],
    requires_manual_acceptance: list[str],
) -> dict[str, object]:
    if not scenario_family:
        return {
            "family": None,
            "status": "not_classified",
            "critical_capabilities": [],
            "missing_critical_capabilities": [],
            "reasons": [],
        }
    critical_set = SCENARIO_CAPABILITY_SETS.get(scenario_family, set())
    status_by_capability = {str(item.get("capability")): item for item in capability_statuses}
    relevant_capabilities = [cap for cap in status_by_capability if cap in critical_set]
    missing_critical = [cap for cap in unsupported_capabilities if cap in critical_set]
    donor_limited_critical = [cap for cap in requires_curated_donor if cap in critical_set]
    gated_critical = [cap for cap in requires_manual_acceptance if cap in critical_set and cap not in donor_limited_critical]
    reasons: list[str] = []
    if missing_critical:
        reasons.append(f"missing critical capability coverage: {', '.join(missing_critical)}")
    if donor_limited_critical:
        reasons.append(f"critical capabilities depend on donor-limited safe-open coverage: {', '.join(donor_limited_critical)}")
    if gated_critical:
        reasons.append(f"critical capabilities remain acceptance-gated: {', '.join(gated_critical)}")
    if missing_critical:
        status = "unsupported"
    elif donor_limited_critical:
        status = "donor_limited"
    elif gated_critical:
        status = "acceptance_gated"
    elif relevant_capabilities:
        status = "ready"
    else:
        status = "partial"
        reasons.append("scenario family is recognized, but no critical capability set was requested explicitly.")
    return {
        "family": scenario_family,
        "status": status,
        "critical_capabilities": relevant_capabilities,
        "missing_critical_capabilities": missing_critical,
        "reasons": reasons,
    }


def _provider_families_for_capability(capability: str, requested_families: list[str]) -> set[str]:
    mapped = CAPABILITY_PROVIDER_FAMILIES.get(capability)
    if mapped:
        return set(mapped)
    return set(requested_families)


def _normalize_media_name(value: str) -> str:
    media = value.strip().lower().replace("_", "-").replace(" ", "-")
    aliases = {
        "estraightthrough": "straight-through",
        "copper-straight-through": "straight-through",
        "straight-through": "straight-through",
        "ecrossover": "crossover",
        "copper-crossover": "crossover",
        "crossover": "crossover",
        "fiber": "fiber",
        "efiber": "fiber",
        "serial": "serial",
        "eserialdce": "serial-dce",
        "serial-dce": "serial-dce",
        "eserialdte": "serial-dte",
        "serial-dte": "serial-dte",
    }
    compact = media.replace("-", "")
    return aliases.get(media, aliases.get(compact, media))


def _pair_key(left: str, right: str) -> str:
    return " <-> ".join(sorted((left, right)))


def select_capability_matrix_hits(
    plan: IntentPlan,
    samples: list[SampleDescriptor],
) -> list[CapabilityMatrixEntry]:
    matrix = build_capability_matrix(samples)
    requested_capabilities = set(plan.capabilities)
    if not requested_capabilities:
        return []
    requested_families = _requested_device_families(plan)
    hits: list[CapabilityMatrixEntry] = []
    seen: set[tuple[str, str]] = set()
    for entry in matrix:
        if entry.capability not in requested_capabilities:
            continue
        provider_families = _provider_families_for_capability(entry.capability, requested_families)
        if provider_families and entry.device_family not in provider_families:
            continue
        key = (entry.device_family, entry.capability)
        if key in seen:
            continue
        hits.append(entry)
        seen.add(key)
    return hits


def build_blueprint_plan(plan: IntentPlan, blueprint: dict[str, object] | None = None) -> BlueprintPlan:
    devices = [dict(device) for device in (blueprint or {}).get("devices", [])]
    if not devices:
        devices = [
            {"type": device_type, "count": count}
            for device_type, count in sorted(plan.device_requirements.items())
            if count
        ]
    links = [dict(link) for link in (blueprint or {}).get("links", [])]
    if not links:
        links = [dict(link) for link in plan.links]
    required_pairs: list[str] = []
    for link in links:
        left = str(link.get("a", {}).get("dev", ""))
        right = str(link.get("b", {}).get("dev", ""))
        if left and right:
            required_pairs.append(" <-> ".join(sorted((left, right))))
    return BlueprintPlan(
        requested_devices=devices,
        requested_links=links,
        required_capabilities=sorted(dict.fromkeys(plan.capabilities)),
        required_donor_capacity={key: value for key, value in sorted(plan.device_requirements.items()) if value},
        required_link_pairs=sorted(dict.fromkeys(required_pairs)),
    )


def build_coverage_gap_report(
    plan: IntentPlan,
    samples: list[SampleDescriptor],
    *,
    selected_donor: str | None = None,
) -> CoverageGapReport:
    iot_acceptance_gated = {"iot", "iot_registration", "iot_control"}
    matrix = build_capability_matrix(samples)
    by_capability: dict[str, list[CapabilityMatrixEntry]] = {}
    by_family: dict[str, list[CapabilityMatrixEntry]] = {}
    for entry in matrix:
        by_capability.setdefault(entry.capability, []).append(entry)
        by_family.setdefault(entry.device_family, []).append(entry)

    requested_families = _requested_device_families(plan)
    requested_capabilities = sorted(dict.fromkeys(plan.capabilities))
    supported_capabilities: list[str] = []
    unsupported_capabilities: list[str] = []
    requires_curated_donor: list[str] = []
    requires_manual_acceptance: list[str] = []
    capability_statuses: list[dict[str, object]] = []
    for capability in requested_capabilities:
        provider_families = _provider_families_for_capability(capability, requested_families)
        matching_entries = [
            entry
            for entry in by_capability.get(capability, [])
            if not provider_families or entry.device_family in provider_families
        ]
        if matching_entries:
            supported_capabilities.append(capability)
            best_entry = max(matching_entries, key=lambda entry: MATURITY_RANK[entry.maturity_level])
            acceptance_verified = any(entry.maturity_level == "acceptance-verified" for entry in matching_entries) and capability not in iot_acceptance_gated
            if best_entry.maturity_level == "safe-open-generate-supported":
                requires_curated_donor.append(capability)
            if not acceptance_verified:
                requires_manual_acceptance.append(capability)
            capability_statuses.append(
                {
                    "capability": capability,
                    "provider_families": sorted(provider_families),
                    "matching_device_families": sorted({entry.device_family for entry in matching_entries}),
                    "best_maturity_level": best_entry.maturity_level,
                    "inventory_supported": any(MATURITY_RANK[entry.maturity_level] >= MATURITY_RANK["inventory-supported"] for entry in matching_entries),
                    "edit_supported": any(MATURITY_RANK[entry.maturity_level] >= MATURITY_RANK["config-mutation-supported"] for entry in matching_entries),
                    "config_mutation_supported": any(MATURITY_RANK[entry.maturity_level] >= MATURITY_RANK["config-mutation-supported"] for entry in matching_entries),
                    "safe_open_generate_supported": any(MATURITY_RANK[entry.maturity_level] >= MATURITY_RANK["safe-open-generate-supported"] for entry in matching_entries),
                    "acceptance_verified": acceptance_verified,
                    "requires_curated_donor": best_entry.maturity_level == "safe-open-generate-supported",
                    "requires_manual_acceptance": not acceptance_verified,
                    "recommended_donors": list(dict.fromkeys(donor for entry in matching_entries for donor in entry.accepted_donors))[:10],
                    "known_limitations": list(dict.fromkeys(item for entry in matching_entries for item in entry.known_limitations)),
                }
            )
        else:
            unsupported_capabilities.append(capability)
            capability_statuses.append(
                {
                    "capability": capability,
                    "provider_families": sorted(provider_families),
                    "matching_device_families": [],
                    "best_maturity_level": "reference-known",
                    "inventory_supported": False,
                    "edit_supported": False,
                    "config_mutation_supported": False,
                    "safe_open_generate_supported": False,
                    "acceptance_verified": False,
                    "requires_curated_donor": False,
                    "requires_manual_acceptance": True,
                    "recommended_donors": [],
                    "known_limitations": ["no matching donor coverage found"],
                }
            )

    unsupported_families = [family for family in requested_families if family not in by_family]

    requires_curated_donor = sorted(dict.fromkeys(requires_curated_donor))
    requires_manual_acceptance = sorted(dict.fromkeys(requires_manual_acceptance))
    capability_parity = [
        {
            "capability": str(status.get("capability")),
            "inventory_supported": bool(status.get("inventory_supported")),
            "edit_supported": bool(status.get("edit_supported")),
            "generate_supported": bool(status.get("safe_open_generate_supported")),
            "acceptance_verified": bool(status.get("acceptance_verified")),
            "best_maturity_level": _best_maturity_level(status),
            "generate_mismatch_reason": _generate_mismatch_reason(status),
            "required_donor_families": sorted(_provider_families_for_capability(str(status.get("capability")), requested_families)),
            "required_archetypes": CAPABILITY_REQUIRED_ARCHETYPES.get(str(status.get("capability")), []),
            "required_runtime_features": CAPABILITY_REQUIRED_RUNTIME_FEATURES.get(str(status.get("capability")), []),
            "recommended_next_action": _recommended_next_action_for_capability(
                str(status.get("capability")),
                _generate_mismatch_reason(status),
            ),
        }
        for status in capability_statuses
    ]
    scenario_family = _scenario_family_for_plan(plan, requested_families)
    if selected_donor is None and plan.blocked_mutations:
        requires_manual_acceptance = sorted(dict.fromkeys([*requires_manual_acceptance, *plan.blocked_mutations]))
    scenario_generate_readiness = _scenario_generate_readiness(
        scenario_family,
        capability_statuses,
        unsupported_capabilities,
        requires_curated_donor,
        requires_manual_acceptance,
    )
    recommended_next_actions: list[str] = []
    if unsupported_capabilities or unsupported_families:
        recommended_next_actions.append(
            "Inspect the blueprint and import or provide a donor that contains the missing capabilities or device families."
        )
    if requires_manual_acceptance:
        recommended_next_actions.append(
            "Run explain-plan or validate-open-debug before enabling the acceptance-gated capability set."
        )
    if not requested_capabilities and not requested_families:
        recommended_next_actions.append("Add explicit device, service, or topology requirements so donor ranking can be constrained.")

    return CoverageGapReport(
        requested_capabilities=requested_capabilities,
        supported_capabilities=supported_capabilities,
        unsupported_capabilities=unsupported_capabilities,
        requested_device_families=requested_families,
        unsupported_device_families=unsupported_families,
        requires_curated_donor=requires_curated_donor,
        requires_manual_acceptance=requires_manual_acceptance,
        capability_statuses=capability_statuses,
        capability_parity=capability_parity,
        scenario_family=scenario_family,
        scenario_generate_readiness=scenario_generate_readiness,
        recommended_next_actions=recommended_next_actions,
    )


def build_inventory_capability_report(payload: dict[str, Any]) -> dict[str, object]:
    device_counts = dict(payload.get("topology_summary", {}).get("device_counts", {}))
    families = sorted({_device_family_for_type(device_type) for device_type in device_counts})
    capabilities: set[str] = set()
    if "multilayer switches" in families:
        capabilities.add("multilayer_switching")
    if "wan/cloud/dsl/cable devices" in families:
        capabilities.add("wan")
    if "security devices" in families:
        capabilities.add("security_edge")
    if payload.get("vlans"):
        capabilities.update(["vlan", "trunk", "access_port"])
    if payload.get("dhcp_pools"):
        capabilities.update(["dhcp_pool", "router_dhcp", "server_dhcp"])
    if payload.get("services"):
        capabilities.update(
            {
                "dns" if "dns_server" in service else service
                for service_names in payload["services"].values()
                for service in service_names
            }
        )
    if payload.get("wireless"):
        capabilities.update(["wireless_ap", "wireless_mutation", "wireless_client"])
        if any(family == "end devices" for family in families):
            capabilities.add("wireless_client_association")
    if payload.get("iot"):
        capabilities.add("iot")
        iot_roles = {str(entry.get("role", "")).strip() for entry in payload["iot"].values() if str(entry.get("role", "")).strip()}
        if "thing" in iot_roles and ("gateway" in iot_roles or "server" in iot_roles):
            capabilities.add("iot_registration")
        if "thing" in iot_roles and ("gateway" in iot_roles or "server" in iot_roles):
            capabilities.add("iot_control")
    if any(family == "end devices" for family in families):
        capabilities.add("end_device_mutation")
    if payload.get("acl_names"):
        capabilities.add("acl")
    if payload.get("topology_summary", {}).get("network_style") == "wan_security":
        capabilities.update({"vpn", "ipsec", "gre", "ppp"})
    return {
        "device_families": families,
        "capabilities": sorted(capabilities),
        "device_counts": device_counts,
    }


def build_donor_graph_fit(sample: SampleDescriptor, blueprint: dict[str, object] | None = None) -> DonorGraphFit:
    expected_pairs: list[str] = []
    expected_media: dict[str, str] = {}
    expected_ports: dict[str, set[str]] = {}
    blueprint_archetype = ""
    blueprint_device_count = 0
    if blueprint:
        blueprint_archetype = str(blueprint.get("topology_archetype", "")).strip()
        blueprint_device_count = len(list(blueprint.get("devices", [])))
        for link in blueprint.get("links", []):
            left = str(link.get("a", {}).get("dev", ""))
            right = str(link.get("b", {}).get("dev", ""))
            if left and right:
                pair = _pair_key(left, right)
                expected_pairs.append(pair)
                media = _normalize_media_name(str(link.get("media", "")))
                if media:
                    expected_media[pair] = media
                ports = {
                    str(link.get("a", {}).get("port", "")).strip(),
                    str(link.get("b", {}).get("port", "")).strip(),
                }
                expected_ports[pair] = {port for port in ports if port}
    sample_pairs: set[str] = set()
    sample_media: dict[str, str] = {}
    sample_ports: dict[str, set[str]] = {}
    for link in sample.links:
        left = str(link.get("from", "")).strip()
        right = str(link.get("to", "")).strip()
        if left and right:
            pair = _pair_key(left, right)
            sample_pairs.add(pair)
            media = _normalize_media_name(str(link.get("media", "") or link.get("cable_type", "")))
            if media and pair not in sample_media:
                sample_media[pair] = media
            ports = {str(port).strip() for port in link.get("ports", []) if str(port).strip()}
            if ports:
                sample_ports.setdefault(pair, set()).update(ports)
    matched_pairs = [pair for pair in expected_pairs if pair in sample_pairs]
    missing_pairs = [pair for pair in expected_pairs if pair not in sample_pairs]
    port_media_conflicts: list[str] = []
    for pair in matched_pairs:
        expected_pair_media = expected_media.get(pair)
        sample_pair_media = sample_media.get(pair)
        if expected_pair_media and sample_pair_media and expected_pair_media != sample_pair_media:
            port_media_conflicts.append(f"{pair} media mismatch ({expected_pair_media} != {sample_pair_media})")
        expected_pair_ports = expected_ports.get(pair, set())
        sample_pair_ports = sample_ports.get(pair, set())
        if expected_pair_ports and sample_pair_ports and not expected_pair_ports.issubset(sample_pair_ports):
            port_media_conflicts.append(
                f"{pair} port mismatch (expected {sorted(expected_pair_ports)}, available {sorted(sample_pair_ports)})"
            )
    fit_score = max(0, len(matched_pairs) * 10 - len(missing_pairs) * 5 - len(port_media_conflicts) * 3)
    topology_bonus = 0
    if blueprint_archetype:
        sample_topology = set(sample.topology_tags)
        if blueprint_archetype in sample_topology:
            topology_bonus += 18
        elif blueprint_archetype == "chain" and sample_topology & {"department_lan", "core_access"}:
            topology_bonus += 12
        elif blueprint_archetype == "core_access" and sample_topology & {"department_lan", "router_on_a_stick"}:
            topology_bonus += 10
        elif blueprint_archetype == "wireless_branch" and sample_topology & {"wireless_edge", "small_office"}:
            topology_bonus += 10
    capacity_penalty = max(0, blueprint_device_count - sample.device_count) * 2
    layout_reuse_score = max(
        0,
        len(matched_pairs) * 12 + topology_bonus - len(missing_pairs) * 6 - len(port_media_conflicts) * 4 - capacity_penalty,
    )
    return DonorGraphFit(
        matched_pairs=matched_pairs,
        missing_pairs=missing_pairs,
        port_media_conflicts=port_media_conflicts,
        fit_score=fit_score,
        layout_reuse_score=layout_reuse_score,
    )


def asdict_list(items: list[Any]) -> list[dict[str, object]]:
    return [asdict(item) for item in items]
