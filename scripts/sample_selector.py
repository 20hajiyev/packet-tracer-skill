from __future__ import annotations

from sample_catalog import SampleCandidate, SampleDescriptor


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
) -> SampleCandidate:
    score = 0
    topology_score = 0
    reasons: list[str] = []
    tags = set(sample.capability_tags)
    for capability in capabilities:
        if capability in tags:
            score += 10
            reasons.append(f"capability:{capability}")
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
    if sample.prototype_eligible:
        score += 10
        reasons.append("prototype-eligible")
    else:
        score -= 50
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
) -> SampleCandidate:
    score = 0
    topology_score = 0
    reasons: list[str] = []
    tags = set(sample.capability_tags)
    for capability in capabilities:
        if capability in tags:
            score += 8
            reasons.append(f"capability:{capability}")
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
        (_score_sample(sample, capabilities, device_requirements, topology_tags) for sample in candidates if (sample.prototype_eligible or not prototype_only)),
        key=lambda candidate: (candidate.total_score, candidate.sample.device_count, candidate.sample.link_count),
        reverse=True,
    )
    return ranked


def rank_reference_samples(
    samples: list[SampleDescriptor],
    capabilities: list[str],
    device_requirements: dict[str, int],
    topology_tags: list[str] | None = None,
) -> list[SampleCandidate]:
    external_only = [sample for sample in samples if sample.origin == "external-reference"]
    candidates = external_only or samples
    ranked = sorted(
        (_score_reference_sample(sample, capabilities, device_requirements, topology_tags) for sample in candidates),
        key=lambda candidate: (candidate.total_score, candidate.sample.device_count, candidate.sample.link_count),
        reverse=True,
    )
    return ranked


def select_best_sample(
    samples: list[SampleDescriptor],
    capabilities: list[str],
    device_requirements: dict[str, int],
    topology_tags: list[str] | None = None,
) -> SampleDescriptor:
    ranked = rank_samples(samples, capabilities, device_requirements, topology_tags=topology_tags, prototype_only=True)
    if not ranked:
        raise ValueError("No Packet Tracer sample is available for selection")
    return ranked[0].sample
