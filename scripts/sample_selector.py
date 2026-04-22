from __future__ import annotations

from coverage_matrix import _expanded_sample_capabilities
from sample_catalog import SampleCandidate, SampleDescriptor

APPLY_SAFETY_SCORES = {
    "reference-known": 0,
    "inventory-supported": 2,
    "config-mutation-supported": 5,
    "safe-open-generate-supported": 9,
    "acceptance-verified": 12,
}

PROMOTION_STATUS_SCORES = {
    "validated_compat": 14,
    "validated_primary": 11,
    "acceptance_verified_curated": 10,
    "validated_curated": 9,
    "reference_only": 0,
}


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


def _sample_device_families(sample: SampleDescriptor) -> list[str]:
    if sample.device_families:
        return sample.device_families
    families = {
        DEVICE_FAMILY_MAP.get(str(device.get("type", "")), "pt-specific edge/utility devices")
        for device in sample.devices
        if device.get("type")
    }
    return sorted(families)


def _available_capabilities(sample: SampleDescriptor) -> set[str]:
    return set(_expanded_sample_capabilities(sample, _sample_device_families(sample)))


def _curated_promotion_rank(sample: SampleDescriptor) -> int:
    return PROMOTION_STATUS_SCORES.get(sample.promotion_status, 0)


def _curated_acceptance_evidence_score(sample: SampleDescriptor) -> int:
    score = 0
    evidence = {str(item) for item in sample.promotion_evidence if str(item).strip()}
    for item in evidence:
        if item.startswith("acceptance_fixture:"):
            score += 4
        elif item.startswith("apply_safety:acceptance-verified"):
            score += 4
        elif item.startswith("validation:validated"):
            score += 2
        elif item == "workspace_validated":
            score += 2
    return score


def _acceptance_fixture_overlap_score(sample: SampleDescriptor, required_fixtures: list[str] | None) -> tuple[int, list[str]]:
    if not required_fixtures:
        return 0, []
    sample_fixtures = {
        str(item).strip()
        for item in list(sample.acceptance_fixtures or [])
        if str(item).strip()
    }
    if not sample_fixtures:
        sample_fixtures = {
            str(item).split(":", 1)[1]
            for item in list(sample.promotion_evidence or [])
            if str(item).startswith("acceptance_fixture:")
        }
    overlap = sorted(sample_fixtures & {str(item).strip() for item in required_fixtures if str(item).strip()})
    if not overlap:
        return 0, []
    return len(overlap) * 6, [f"fixture:{item}" for item in overlap]


def _runtime_feature_overlap_score(sample: SampleDescriptor, required_runtime_features: list[str] | None) -> tuple[int, list[str]]:
    if not required_runtime_features:
        return 0, []
    required = {str(item).strip() for item in required_runtime_features if str(item).strip()}
    overlap = sorted(required & {str(item).strip() for item in list(sample.runtime_features or []) if str(item).strip()})
    if not overlap:
        return 0, []
    return len(overlap) * 3, [f"runtime:{item}" for item in overlap]


def _device_fit_score(sample: SampleDescriptor, device_requirements: dict[str, int]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    counts = sample.normalized_device_counts()
    for device_type, needed in device_requirements.items():
        available = counts.get(device_type, 0)
        if available >= needed:
            score += 5 + needed
            reasons.append(f"device:{device_type}")
        elif available > 0:
            score += available
            reasons.append(f"partial-device:{device_type}")
    return score, reasons


def _score_sample(
    sample: SampleDescriptor,
    capabilities: list[str],
    device_requirements: dict[str, int],
    topology_tags: list[str] | None = None,
    *,
    wireless_mode: str | None = None,
    requested_services: list[str] | None = None,
    required_acceptance_fixtures: list[str] | None = None,
    required_runtime_features: list[str] | None = None,
) -> SampleCandidate:
    score = 0
    topology_score = 0
    reasons: list[str] = []
    tags = _available_capabilities(sample)
    for capability in capabilities:
        if capability in tags:
            score += 10
            reasons.append(f"capability:{capability}")
    available_services = set(sample.service_support)
    for service in requested_services or []:
        if service in available_services:
            score += 8
            reasons.append(f"service:{service}")
    if any(role in sample.preferred_roles for role in ["preferred_wireless", "preferred_management", "preferred_server"]):
        score += 4
        reasons.append("preferred-role")
    device_score, device_reasons = _device_fit_score(sample, device_requirements)
    score += device_score
    reasons.extend(device_reasons)
    counts = sample.normalized_device_counts()
    if sample.version.startswith("9."):
        score += 2
        reasons.append("version:9.x")
    score += min(sample.link_count, 10)
    if sample.origin == "cisco-local":
        score += 20
        reasons.append("origin:cisco-local")
    elif sample.origin == "compat-donor":
        score += 24
        reasons.append("origin:compat-donor")
    elif sample.origin == "external-curated":
        score += 8
        reasons.append("origin:external-curated")
    if sample.prototype_eligible:
        score += 10
        reasons.append("prototype-eligible")
    else:
        score -= 50
    if sample.donor_eligible:
        score += 8
        reasons.append("donor-eligible")
    else:
        score -= 25
    if sample.trust_level == "curated":
        score += 3
        reasons.append("trust:curated")
    promotion_bonus = _curated_promotion_rank(sample)
    if promotion_bonus:
        score += promotion_bonus
        reasons.append(f"promotion:{sample.promotion_status}")
    acceptance_evidence_score = _curated_acceptance_evidence_score(sample)
    if acceptance_evidence_score:
        score += acceptance_evidence_score
        reasons.append(f"acceptance-evidence:{acceptance_evidence_score}")
    if sample.validated_edit_capabilities:
        score += min(len(sample.validated_edit_capabilities), 8)
        reasons.append(f"edit-evidence:{min(len(sample.validated_edit_capabilities), 8)}")
    fixture_score, fixture_reasons = _acceptance_fixture_overlap_score(sample, required_acceptance_fixtures)
    if fixture_score:
        score += fixture_score
        reasons.extend(fixture_reasons)
    runtime_score, runtime_reasons = _runtime_feature_overlap_score(sample, required_runtime_features)
    if runtime_score:
        score += runtime_score
        reasons.extend(runtime_reasons)
    if wireless_mode and wireless_mode in set(sample.wireless_mode_tags):
        score += 10
        reasons.append(f"wireless-mode:{wireless_mode}")
    safety_bonus = APPLY_SAFETY_SCORES.get(sample.apply_safety_level, 0)
    if safety_bonus:
        score += safety_bonus
        reasons.append(f"apply-safety:{sample.apply_safety_level}")
    wanted_topology = set(topology_tags or [])
    available_topology = set(sample.topology_tags)
    for tag in wanted_topology:
        if tag in available_topology:
            topology_score += 12
            reasons.append(f"topology:{tag}")
    total_score = score + topology_score
    return SampleCandidate(
        sample=sample,
        capability_score=score,
        topology_score=topology_score,
        total_score=total_score,
        reasons=reasons,
    )


def _score_reference_sample(
    sample: SampleDescriptor,
    capabilities: list[str],
    device_requirements: dict[str, int],
    topology_tags: list[str] | None = None,
    *,
    wireless_mode: str | None = None,
    requested_services: list[str] | None = None,
) -> SampleCandidate:
    score = 0
    topology_score = 0
    reasons: list[str] = []
    tags = _available_capabilities(sample)
    for capability in capabilities:
        if capability in tags:
            score += 8
            reasons.append(f"capability:{capability}")
    available_services = set(sample.service_support)
    for service in requested_services or []:
        if service in available_services:
            score += 6
            reasons.append(f"service:{service}")
    device_score, device_reasons = _device_fit_score(sample, device_requirements)
    score += device_score
    reasons.extend(device_reasons)
    wanted_topology = set(topology_tags or [])
    available_topology = set(sample.topology_tags)
    for tag in wanted_topology:
        if tag in available_topology:
            topology_score += 14
            reasons.append(f"topology:{tag}")
    if sample.origin == "external-reference":
        score += 6
        reasons.append("origin:external-reference")
    if wireless_mode and wireless_mode in set(sample.wireless_mode_tags):
        score += 8
        reasons.append(f"wireless-mode:{wireless_mode}")
    if not sample.prototype_eligible:
        reasons.append("reference-only")
    total_score = score + topology_score
    return SampleCandidate(
        sample=sample,
        capability_score=score,
        topology_score=topology_score,
        total_score=total_score,
        reasons=reasons,
    )


def rank_samples(
    samples: list[SampleDescriptor],
    capabilities: list[str],
    device_requirements: dict[str, int],
    topology_tags: list[str] | None = None,
    prototype_only: bool = True,
    *,
    wireless_mode: str | None = None,
    requested_services: list[str] | None = None,
    required_acceptance_fixtures: list[str] | None = None,
    required_runtime_features: list[str] | None = None,
) -> list[SampleCandidate]:
    filtered: list[SampleDescriptor] = []
    for sample in samples:
        if prototype_only and not sample.prototype_eligible:
            continue
        counts = sample.normalized_device_counts()
        if all(counts.get(device_type, 0) >= needed for device_type, needed in device_requirements.items()):
            filtered.append(sample)
    candidates = filtered or samples
    ranked = sorted(
        (
            _score_sample(
                sample,
                capabilities,
                device_requirements,
                topology_tags,
                wireless_mode=wireless_mode,
                requested_services=requested_services,
                required_acceptance_fixtures=required_acceptance_fixtures,
                required_runtime_features=required_runtime_features,
            )
            for sample in candidates
            if (sample.prototype_eligible or not prototype_only)
        ),
        key=lambda candidate: (candidate.total_score, candidate.sample.device_count, candidate.sample.link_count),
        reverse=True,
    )
    return ranked


def rank_reference_samples(
    samples: list[SampleDescriptor],
    capabilities: list[str],
    device_requirements: dict[str, int],
    topology_tags: list[str] | None = None,
    *,
    wireless_mode: str | None = None,
    requested_services: list[str] | None = None,
) -> list[SampleCandidate]:
    external_only = [sample for sample in samples if sample.origin == "external-reference"]
    candidates = external_only or samples
    ranked = sorted(
        (
            _score_reference_sample(
                sample,
                capabilities,
                device_requirements,
                topology_tags,
                wireless_mode=wireless_mode,
                requested_services=requested_services,
            )
            for sample in candidates
        ),
        key=lambda candidate: (candidate.total_score, candidate.sample.device_count, candidate.sample.link_count),
        reverse=True,
    )
    return ranked


def rank_curated_donor_samples(
    samples: list[SampleDescriptor],
    capabilities: list[str],
    device_requirements: dict[str, int],
    topology_tags: list[str] | None = None,
    *,
    wireless_mode: str | None = None,
    requested_services: list[str] | None = None,
    required_acceptance_fixtures: list[str] | None = None,
    required_runtime_features: list[str] | None = None,
) -> list[SampleCandidate]:
    curated_only = [sample for sample in samples if sample.origin == "external-curated" and sample.donor_eligible]
    candidates = curated_only or [sample for sample in samples if sample.donor_eligible]
    ranked = sorted(
        (
            _score_sample(
                sample,
                capabilities,
                device_requirements,
                topology_tags,
                wireless_mode=wireless_mode,
                requested_services=requested_services,
                required_acceptance_fixtures=required_acceptance_fixtures,
                required_runtime_features=required_runtime_features,
            )
            for sample in candidates
        ),
        key=lambda candidate: (candidate.total_score, candidate.sample.device_count, candidate.sample.link_count),
        reverse=True,
    )
    return ranked


def select_best_sample(
    samples: list[SampleDescriptor],
    capabilities: list[str],
    device_requirements: dict[str, int],
    topology_tags: list[str] | None = None,
    *,
    wireless_mode: str | None = None,
    requested_services: list[str] | None = None,
) -> SampleDescriptor:
    ranked = rank_samples(
        samples,
        capabilities,
        device_requirements,
        topology_tags=topology_tags,
        prototype_only=True,
        wireless_mode=wireless_mode,
        requested_services=requested_services,
    )
    if not ranked:
        raise ValueError("No Packet Tracer sample is available for selection")
    return ranked[0].sample
