from __future__ import annotations

from pkt_transformer import transform_from_blueprint
from sample_catalog import load_catalog
from sample_selector import select_best_sample


def build_packet_tracer_xml(blueprint: dict) -> bytes:
    samples = load_catalog()
    device_requirements: dict[str, int] = {}
    for device in blueprint.get("devices", []):
        device_type = str(device["type"])
        device_requirements[device_type] = device_requirements.get(device_type, 0) + 1
    selected = select_best_sample(samples, list(blueprint.get("capabilities", [])), device_requirements)
    return transform_from_blueprint(blueprint, selected)
