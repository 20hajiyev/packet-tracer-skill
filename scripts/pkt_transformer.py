from __future__ import annotations

import copy
from functools import lru_cache
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from packet_tracer_env import get_packet_tracer_compatibility_donor, get_packet_tracer_target_version, require_packet_tracer_compatibility_donor, resolve_sample_path
from pkt_codec import decode_pkt_modern
from sample_catalog import SampleDescriptor, load_catalog, normalize_device_type
from workspace_repair import sanitize_generated_physical_workspace, validate_workspace_integrity

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_ROOT = SCRIPT_DIR.parent
TEMPLATE_DIR = SKILL_ROOT / "templates" / "pt900" / "device_library"
BASE_TEMPLATE_ROOT = SKILL_ROOT / "templates" / "pt900" / "base_empty.xml"
FALLBACK_PROTOTYPE_SAMPLE = r"01 Networking\FTP\FTP.pkt"
DEVICE_TEMPLATE_FILES = {
    "PC": "pc.xml",
    "Printer": "printer.xml",
    "Router": "router.xml",
    "Switch": "switch.xml",
}
GENERIC_COPPER_HOST_TYPES = {"PC", "Server", "Printer", "Laptop"}


def load_sample_root(sample_path: str | Path) -> ET.Element:
    return copy.deepcopy(_load_sample_root_cached(str(sample_path)))


@lru_cache(maxsize=512)
def _load_sample_root_cached(sample_path: str) -> ET.Element:
    path = Path(sample_path)
    if path.suffix.lower() == ".xml":
        xml_bytes = path.read_bytes()
    else:
        xml_bytes = decode_pkt_modern(path.read_bytes())
    return ET.fromstring(xml_bytes)


@lru_cache(maxsize=1)
def generation_root_sample() -> str:
    donor = get_packet_tracer_compatibility_donor()
    if donor is not None:
        return str(donor)
    try:
        fallback = resolve_sample_path(FALLBACK_PROTOTYPE_SAMPLE)
    except FileNotFoundError:
        fallback = None
    if fallback is not None and fallback.exists():
        return str(fallback)
    return str(BASE_TEMPLATE_ROOT)


def generation_root_version() -> str:
    donor = get_packet_tracer_compatibility_donor()
    if donor is not None:
        root = _load_sample_root_cached(str(donor))
        return root.findtext("./VERSION", default=get_packet_tracer_target_version())
    return get_packet_tracer_target_version()


def strict_compatibility_mode() -> bool:
    root_sample = Path(generation_root_sample())
    return root_sample.suffix.lower() == ".pkt" and generation_root_version().startswith("9.")


def _device_type(device: ET.Element) -> str:
    return normalize_device_type(device.findtext("./ENGINE/TYPE", default=""))


def _device_model(device: ET.Element) -> str:
    node = device.find("./ENGINE/TYPE")
    return node.get("model", "") if node is not None else ""


def _logical_position(device: ET.Element) -> tuple[int, int]:
    x_node = device.find("./WORKSPACE/LOGICAL/X")
    y_node = device.find("./WORKSPACE/LOGICAL/Y")
    x_val = float(x_node.text) if x_node is not None and x_node.text else 200.0
    y_val = float(y_node.text) if y_node is not None and y_node.text else 200.0
    return int(round(x_val)), int(round(y_val))


def _set_device_name(device: ET.Element, new_name: str) -> None:
    node = device.find("./ENGINE/NAME")
    if node is not None:
        node.text = new_name


def _set_device_model(device: ET.Element, model: str) -> None:
    node = device.find("./ENGINE/TYPE")
    if node is not None:
        node.set("model", model)


def _set_position(device: ET.Element, x_pos: int, y_pos: int) -> None:
    x_node = device.find("./WORKSPACE/LOGICAL/X")
    y_node = device.find("./WORKSPACE/LOGICAL/Y")
    if x_node is not None:
        x_node.text = str(x_pos)
    if y_node is not None:
        y_node.text = str(y_pos)


def _set_workspace_ids(device: ET.Element, index: int) -> None:
    mem_node = device.find("./WORKSPACE/LOGICAL/MEM_ADDR")
    dev_node = device.find("./WORKSPACE/LOGICAL/DEV_ADDR")
    if mem_node is not None:
        mem_node.text = str(3_000_000_000_000 + index * 32)
    if dev_node is not None:
        dev_node.text = str(3_100_000_000_000 + index * 32)


def _set_runtime_ids(device: ET.Element, index: int) -> None:
    save_ref = device.find("./ENGINE/SAVE_REF_ID")
    serial = device.find("./ENGINE/SERIALNUMBER")
    start_time = device.find("./ENGINE/STARTTIME")
    coord_x = device.find("./ENGINE/COORD_SETTINGS/X_COORD")
    coord_y = device.find("./ENGINE/COORD_SETTINGS/Y_COORD")
    logical_x = device.findtext("./WORKSPACE/LOGICAL/X", default="")
    logical_y = device.findtext("./WORKSPACE/LOGICAL/Y", default="")
    if save_ref is not None:
        save_ref.text = f"save-ref-id:{9_000_000_000_000_000_000 + index}"
    if serial is not None:
        prefix = (serial.text or "AUTO").split("-")[0][:8] or "AUTO"
        serial.text = f"{prefix}{index:04d}-"
    if start_time is not None:
        start_time.text = str(800_000_000_000 + index)
    if coord_x is not None and logical_x:
        coord_x.text = logical_x
    if coord_y is not None and logical_y:
        coord_y.text = logical_y


def _build_workspace_reference_library(root: ET.Element) -> dict[str, list[ET.Element]]:
    buckets: dict[str, list[ET.Element]] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        workspace = device.find("./WORKSPACE")
        if workspace is None:
            continue
        buckets.setdefault(_device_type(device), []).append(workspace)
    return buckets


def _normalize_workspace_physical(device: ET.Element, requested_type: str, reference_workspaces: dict[str, list[ET.Element]], usage_index: int) -> None:
    candidates = reference_workspaces.get(requested_type, [])
    if not candidates:
        return
    reference = copy.deepcopy(candidates[(usage_index - 1) % len(candidates)])
    target_workspace = device.find("./WORKSPACE")
    if target_workspace is None:
        return

    logical = target_workspace.find("./LOGICAL")
    logical_copy = copy.deepcopy(logical) if logical is not None else None
    target_workspace.clear()
    for child in list(reference):
        target_workspace.append(copy.deepcopy(child))
    if logical_copy is not None:
        logical_target = target_workspace.find("./LOGICAL")
        if logical_target is not None:
            target_workspace.remove(logical_target)
        target_workspace.insert(0, logical_copy)


def _find_switch_config(device: ET.Element) -> ET.Element | None:
    for node in device.findall(".//FILE_CONTENT/CONFIG"):
        rendered = "\n".join(line.text or "" for line in node.findall("./LINE"))
        if "interface FastEthernet0/1" in rendered:
            return node
    return None


def apply_host_ip(device: ET.Element, config: dict[str, Any]) -> None:
    port = device.find("./ENGINE/MODULE/SLOT/MODULE/PORT")
    if port is None:
        return
    for source_key, xml_key in [("ip", "IP"), ("mask", "SUBNET")]:
        if source_key in config:
            node = port.find(xml_key)
            if node is not None:
                node.text = str(config[source_key])
    if "gw" in config:
        node = device.find("./ENGINE/GATEWAY")
        if node is not None:
            node.text = str(config["gw"])
    if "dns" in config:
        node = device.find("./ENGINE/DNS_CLIENT/SERVER_IP")
        if node is not None:
            node.text = str(config["dns"])
        port_dns = port.find("PORT_DNS")
        if port_dns is not None:
            port_dns.text = str(config["dns"])


def apply_router_config(device: ET.Element, lines: list[str]) -> None:
    for target in [device.find("./ENGINE/RUNNINGCONFIG"), device.find("./ENGINE/STARTUPCONFIG")]:
        if target is None:
            continue
        target.clear()
        final_lines = [str(line) for line in lines]
        if final_lines and final_lines[-1].strip().lower() != "end":
            final_lines.append("end")
        for line in final_lines:
            node = ET.SubElement(target, "LINE")
            node.text = line


def apply_switch_config(device: ET.Element, lines: list[str]) -> None:
    target = _find_switch_config(device)
    if target is None:
        return
    target.clear()
    final_lines = [str(line) for line in lines]
    if final_lines and final_lines[-1].strip().lower() != "end":
        final_lines.append("end")
    for line in final_lines:
        node = ET.SubElement(target, "LINE")
        node.text = line


def build_device_library(source_root: ET.Element) -> dict[str, list[ET.Element]]:
    buckets: dict[str, list[ET.Element]] = {}
    for device in source_root.findall(".//DEVICES/DEVICE"):
        buckets.setdefault(_device_type(device), []).append(device)
    return buckets


def _load_device_template(device_type: str, model: str | None = None) -> ET.Element | None:
    normalized = normalize_device_type(device_type)
    template_name = DEVICE_TEMPLATE_FILES.get(normalized, f"{normalized.lower()}.xml")
    if not template_name:
        return None
    template_path = TEMPLATE_DIR / template_name
    if not template_path.exists():
        return None
    root = ET.fromstring(template_path.read_text(encoding="utf-8"))
    actual_type = _device_type(root)
    actual_model = _device_model(root)
    if actual_type != normalized and not (not actual_type and actual_model):
        return None
    if model and actual_model.lower() != str(model).lower():
        return None
    return root


def _existing_sample_path(sample_path: str | Path) -> Path | None:
    path = Path(sample_path)
    return path if path.exists() else None


def _generic_link_prototype() -> ET.Element:
    return ET.fromstring(
        """
<LINK>
  <TYPE>Cable</TYPE>
  <CABLE>
    <FROM>0</FROM>
    <TO>1</TO>
    <PORT>FastEthernet0</PORT>
    <PORT>FastEthernet0/1</PORT>
    <TYPE>eStraightThrough</TYPE>
    <FROM_DEVICE_MEM_ADDR>0</FROM_DEVICE_MEM_ADDR>
    <TO_DEVICE_MEM_ADDR>1</TO_DEVICE_MEM_ADDR>
    <FROM_PORT_MEM_ADDR>0</FROM_PORT_MEM_ADDR>
    <TO_PORT_MEM_ADDR>1</TO_PORT_MEM_ADDR>
    <FUNCTIONAL>true</FUNCTIONAL>
    <GEO_VIEW_COLOR>#6ba72e</GEO_VIEW_COLOR>
    <IS_MANAGED_IN_RACK_VIEW>false</IS_MANAGED_IN_RACK_VIEW>
  </CABLE>
</LINK>
        """.strip()
    )


def find_device_prototype(device_type: str, model: str | None, preferred_sample: SampleDescriptor) -> ET.Element:
    return ET.fromstring(_find_device_prototype_xml(device_type, model, preferred_sample.path))


@lru_cache(maxsize=512)
def _find_device_prototype_xml(device_type: str, model: str | None, preferred_sample_path: str) -> str:
    compatibility_root = generation_root_sample()
    visited_paths: set[str] = set()
    normalized_target = normalize_device_type(device_type)
    wanted_model = (model or "").lower()
    if strict_compatibility_mode():
        candidate_paths = [compatibility_root]
    else:
        candidate_paths = [compatibility_root, preferred_sample_path]
        candidate_paths.extend(sample.path for sample in load_catalog())
    for candidate_path in candidate_paths:
        if candidate_path in visited_paths:
            continue
        visited_paths.add(candidate_path)
        if not _existing_sample_path(candidate_path):
            continue
        root = _load_sample_root_cached(candidate_path)
        for device in root.findall(".//DEVICES/DEVICE"):
            if _device_type(device) != normalized_target:
                continue
            actual_model = _device_model(device).lower()
            if wanted_model and actual_model != wanted_model:
                continue
            return ET.tostring(device, encoding="unicode")
    if strict_compatibility_mode():
        donor = require_packet_tracer_compatibility_donor()
        target = f"{device_type} with model {model}" if model else device_type
        raise ValueError(f"Strict 9.0 donor {donor} does not contain a prototype for {target}")
    template = _load_device_template(normalized_target, model)
    if template is not None:
        return ET.tostring(template, encoding="unicode")
    if model:
        raise ValueError(f"No prototype found for device type {device_type} with model {model}")
    raise ValueError(f"No prototype found for device type {device_type}")


def infer_default_links(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    routers = [device for device in devices if device["type"] == "Router"]
    switches = [device for device in devices if device["type"] == "Switch"]
    hosts = [device for device in devices if device["type"] in {"PC", "Server"}]
    links: list[dict[str, Any]] = []
    if switches:
        uplink_switch = switches[0]
        for index, host in enumerate(hosts, start=1):
            links.append({"a": {"dev": host["name"], "port": "FastEthernet0"}, "b": {"dev": uplink_switch["name"], "port": f"FastEthernet0/{min(index, 24)}"}, "media": "copper"})
        if routers:
            links.append({"a": {"dev": uplink_switch["name"], "port": "FastEthernet0/24"}, "b": {"dev": routers[0]["name"], "port": "FastEthernet0/0"}, "media": "copper"})
        for prev, nxt in zip(switches, switches[1:]):
            links.append({"a": {"dev": prev["name"], "port": "FastEthernet0/23"}, "b": {"dev": nxt["name"], "port": "FastEthernet0/24"}, "media": "copper"})
    elif len(routers) >= 2:
        for prev, nxt in zip(routers, routers[1:]):
            links.append({"a": {"dev": prev["name"], "port": "FastEthernet0/0"}, "b": {"dev": nxt["name"], "port": "FastEthernet0/1"}, "media": "copper"})
    return links


def _effective_link_type(device_type: str) -> str:
    normalized = normalize_device_type(device_type)
    if normalized in GENERIC_COPPER_HOST_TYPES:
        return "PC"
    return normalized


def _prototype_link_by_pair(source_sample_path: str | Path, left_type: str, right_type: str) -> ET.Element:
    return ET.fromstring(_prototype_link_xml(str(source_sample_path), left_type, right_type))


@lru_cache(maxsize=512)
def _prototype_link_xml(source_sample_path: str, left_type: str, right_type: str) -> str:
    compatibility_root = generation_root_sample()
    if strict_compatibility_mode():
        candidate_paths = [str(compatibility_root)]
    else:
        candidate_paths = [str(compatibility_root), str(source_sample_path)]
        try:
            candidate_paths.append(str(resolve_sample_path(FALLBACK_PROTOTYPE_SAMPLE)))
        except FileNotFoundError:
            pass
        candidate_paths.extend(sample.path for sample in load_catalog())
    visited_paths: set[str] = set()
    wanted_left = _effective_link_type(left_type)
    wanted_right = _effective_link_type(right_type)
    for candidate in candidate_paths:
        root_key = str(candidate)
        if root_key in visited_paths:
            continue
        visited_paths.add(root_key)
        if not _existing_sample_path(root_key):
            continue
        root = _load_sample_root_cached(root_key)
        devices = root.findall(".//DEVICES/DEVICE")
        index_to_type = {str(index): _effective_link_type(_device_type(device)) for index, device in enumerate(devices)}
        save_ref_to_type = {
            device.findtext("./ENGINE/SAVE_REF_ID", default=""): _effective_link_type(_device_type(device))
            for device in devices
            if device.findtext("./ENGINE/SAVE_REF_ID", default="")
        }
        for link in root.findall(".//LINKS/LINK"):
            cable = link.find("./CABLE")
            if cable is None:
                continue
            from_ref = cable.findtext("FROM", default="")
            to_ref = cable.findtext("TO", default="")
            from_type = save_ref_to_type.get(from_ref) or index_to_type.get(from_ref)
            to_type = save_ref_to_type.get(to_ref) or index_to_type.get(to_ref)
            if from_type == wanted_left and to_type == wanted_right:
                return ET.tostring(link, encoding="unicode")
            if from_type == wanted_right and to_type == wanted_left:
                return ET.tostring(link, encoding="unicode")
    if strict_compatibility_mode():
        donor = require_packet_tracer_compatibility_donor()
        raise ValueError(f"Strict 9.0 donor {donor} does not contain a prototype link for {left_type} <-> {right_type}")
    return ET.tostring(_generic_link_prototype(), encoding="unicode")


def apply_cable_type(cable: ET.Element, media: str) -> None:
    media_key = media.lower()
    node = cable.find("TYPE")
    if node is None:
        return
    mapping = {
        "copper": "eStraightThrough",
        "straight-through": "eStraightThrough",
        "straight": "eStraightThrough",
        "crossover": "eCrossOver",
        "cross-over": "eCrossOver",
        "serial": "eSerialDCE",
        "fiber": "eFiber",
    }
    node.text = mapping.get(media_key, node.text or "eStraightThrough")


def _port_nodes(device: ET.Element) -> list[ET.Element]:
    return [port for port in device.findall(".//PORT") if port.findtext("TYPE", "").startswith("eCopper")]


def _parse_port_index(port_name: str) -> int | None:
    match = re.search(r"(\d+)$", port_name)
    return int(match.group(1)) if match else None


def _canonical_port_name(port_name: str) -> str:
    lowered = port_name.strip()
    if lowered.lower().startswith("fa"):
        return "FastEthernet" + lowered[2:]
    if lowered.lower().startswith("gi"):
        return "GigabitEthernet" + lowered[2:]
    return lowered


def _port_address_for_name(device: ET.Element, port_name: str) -> str | None:
    canonical = _canonical_port_name(port_name)
    fast_nodes = [port for port in _port_nodes(device) if "FastEthernet" in port.findtext("TYPE", "")]
    gig_nodes = [port for port in _port_nodes(device) if "GigabitEthernet" in port.findtext("TYPE", "")]
    target: ET.Element | None = None
    if canonical == "FastEthernet0":
        target = fast_nodes[0] if fast_nodes else None
    elif canonical.startswith("FastEthernet"):
        index = _parse_port_index(canonical)
        if index is not None and fast_nodes:
            if _device_type(device) == "Router":
                target = fast_nodes[index] if index < len(fast_nodes) else None
            else:
                target = fast_nodes[index - 1] if 0 < index <= len(fast_nodes) else None
    elif canonical.startswith("GigabitEthernet"):
        index = _parse_port_index(canonical)
        if index is not None and gig_nodes:
            if _device_type(device) == "Router" and "/" in canonical and canonical.count("/") == 1:
                target = gig_nodes[index] if index < len(gig_nodes) else None
            else:
                target = gig_nodes[index - 1] if 0 < index <= len(gig_nodes) else None
    if target is None:
        return None
    return target.findtext("MEM_ADDR")


def _sanitize_generated_runtime_sections(root: ET.Element) -> None:
    scenario_set = root.find("./SCENARIOSET")
    if scenario_set is not None:
        scenario_set.clear()
        scenario = ET.SubElement(scenario_set, "SCENARIO")
        name = ET.SubElement(scenario, "NAME")
        name.set("translate", "true")
        name.text = "Scenario 0"
        description = ET.SubElement(scenario, "DESCRIPTION")
        description.set("translate", "true")
    command_logs = root.find("./COMMAND_LOGS")
    if command_logs is not None:
        command_logs.clear()
    ceps = root.find("./CEPS")
    if ceps is not None:
        ceps.clear()


def transform_from_blueprint(blueprint: dict[str, Any], sample: SampleDescriptor) -> bytes:
    root_sample_path = generation_root_sample()
    target_root = copy.deepcopy(load_sample_root(root_sample_path))
    version_node = target_root.find("./VERSION")
    if version_node is not None:
        version_node.text = generation_root_version()
    devices_parent = target_root.find(".//DEVICES")
    links_parent = target_root.find(".//LINKS")
    if devices_parent is None or links_parent is None:
        raise ValueError("Sample XML is missing DEVICES or LINKS")
    devices_parent.clear()
    links_parent.clear()
    for tag in ["LINES", "RECTANGLES", "ELLIPSES", "POLYGONS", "GEOVIEW_GRAPHICSITEMS", "NOTES"]:
        node = target_root.find(tag)
        if node is not None:
            node.clear()
    compatibility_mode = strict_compatibility_mode()
    preferred_source = _existing_sample_path(sample.path)
    library_source_root = load_sample_root(root_sample_path)
    if not compatibility_mode and preferred_source is not None:
        library_source_root = load_sample_root(preferred_source)
    reference_workspaces = _build_workspace_reference_library(load_sample_root(root_sample_path))

    device_library = build_device_library(library_source_root)
    requested_devices = blueprint.get("devices", [])
    if not requested_devices:
        raise ValueError("Blueprint must include devices")
    requested_links = blueprint.get("links") or infer_default_links(requested_devices)
    configs = blueprint.get("configs", {})

    built_devices: list[ET.Element] = []
    name_to_device: dict[str, ET.Element] = {}
    name_to_index: dict[str, int] = {}
    type_usage: dict[str, int] = {}
    workspace_usage: dict[str, int] = {}

    for requested in requested_devices:
        requested_type = normalize_device_type(str(requested["type"]))
        requested_model = requested.get("model")
        prototypes = device_library.get(requested_type, [])
        use_index = type_usage.get(requested_type, 0)
        workspace_index = workspace_usage.get(requested_type, 0) + 1
        workspace_usage[requested_type] = workspace_index
        matching_prototypes = prototypes
        if requested_model:
            matching_prototypes = [prototype for prototype in prototypes if _device_model(prototype).lower() == str(requested_model).lower()]
        if use_index < len(matching_prototypes):
            built = copy.deepcopy(matching_prototypes[use_index])
            type_usage[requested_type] = use_index + 1
        else:
            if compatibility_mode:
                donor = require_packet_tracer_compatibility_donor()
                target = f"{requested_type} with model {requested_model}" if requested_model else requested_type
                raise ValueError(
                    f"Strict 9.0 donor {donor} has only {len(matching_prototypes)} prototype(s) for {target}; requested more devices than donor supports."
                )
            if requested_model:
                built = copy.deepcopy(find_device_prototype(requested_type, str(requested_model), sample))
            else:
                built = copy.deepcopy(find_device_prototype(requested_type, None, sample))
        name = str(requested["name"])
        _set_device_name(built, name)
        if requested_model:
            _set_device_model(built, str(requested_model))
        default_x, default_y = _logical_position(built)
        _set_position(built, int(requested.get("x", default_x)), int(requested.get("y", default_y)))
        if not compatibility_mode:
            _normalize_workspace_physical(built, requested_type, reference_workspaces, workspace_index)
            _set_workspace_ids(built, len(built_devices) + 1)
            _set_runtime_ids(built, len(built_devices) + 1)
        device_config = configs.get(name, {})
        if requested_type in {"PC", "Server"} and isinstance(device_config, dict):
            apply_host_ip(built, device_config)
        elif requested_type == "Router" and isinstance(device_config, list):
            apply_router_config(built, device_config)
        elif requested_type == "Switch" and isinstance(device_config, list):
            apply_switch_config(built, device_config)
        name_to_index[name] = len(built_devices)
        name_to_device[name] = built
        built_devices.append(built)
        devices_parent.append(built)

    requested_lookup = {str(device["name"]): normalize_device_type(str(device["type"])) for device in requested_devices}
    for requested_link in requested_links:
        left_name = str(requested_link["a"]["dev"])
        right_name = str(requested_link["b"]["dev"])
        prototype = copy.deepcopy(_prototype_link_by_pair(sample.path, requested_lookup[left_name], requested_lookup[right_name]))
        cable = prototype.find("./CABLE")
        if cable is None:
            continue
        from_device = name_to_device[left_name]
        to_device = name_to_device[right_name]
        if compatibility_mode:
            cable.find("FROM").text = from_device.findtext("./ENGINE/SAVE_REF_ID", default=str(name_to_index[left_name]))
            cable.find("TO").text = to_device.findtext("./ENGINE/SAVE_REF_ID", default=str(name_to_index[right_name]))
        else:
            cable.find("FROM").text = str(name_to_index[left_name])
            cable.find("TO").text = str(name_to_index[right_name])
        ports = cable.findall("PORT")
        if len(ports) >= 2:
            ports[0].text = str(requested_link["a"]["port"])
            ports[1].text = str(requested_link["b"]["port"])
        mappings = [
            ("FROM_DEVICE_MEM_ADDR", from_device.findtext("./WORKSPACE/LOGICAL/MEM_ADDR")),
            ("TO_DEVICE_MEM_ADDR", to_device.findtext("./WORKSPACE/LOGICAL/MEM_ADDR")),
            ("FROM_PORT_MEM_ADDR", _port_address_for_name(from_device, str(requested_link["a"]["port"]))),
            ("TO_PORT_MEM_ADDR", _port_address_for_name(to_device, str(requested_link["b"]["port"]))),
        ]
        for node_name, value in mappings:
            node = cable.find(node_name)
            if node is not None and value:
                node.text = value
        apply_cable_type(cable, str(requested_link.get("media", "copper")))
        links_parent.append(prototype)

    _sanitize_generated_runtime_sections(target_root)
    sanitize_generated_physical_workspace(target_root)
    validate_workspace_integrity(target_root)
    return ET.tostring(target_root, encoding="utf-8", xml_declaration=False)
