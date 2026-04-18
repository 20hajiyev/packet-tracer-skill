from __future__ import annotations

import copy
from dataclasses import dataclass
import xml.etree.ElementTree as ET

PHYSICAL_HOME_PATH = ["Intercity", "Home City", "Corporate Office", "Main Wiring Closet"]


@dataclass
class WorkspaceValidationResult:
    workspace_mode: str
    logical_status: str
    physical_status: str
    blocking_issues: list[str]


@dataclass
class DonorCoherenceResult:
    device_metadata_status: str
    scenario_status: str
    physical_runtime_status: str
    visual_runtime_status: str
    blocking_issues: list[str]


def _make_workspace_node(name: str, node_type: int, x_pos: int, y_pos: int, width: int, height: int, path: str = "") -> ET.Element:
    node = ET.Element("NODE")
    for tag, value in [
        ("X", str(x_pos)),
        ("Y", str(y_pos)),
        ("TYPE", str(node_type)),
    ]:
        child = ET.SubElement(node, tag)
        child.text = value
    name_node = ET.SubElement(node, "NAME")
    name_node.set("translate", "true")
    name_node.text = name
    for tag, value in [
        ("SX", "1"),
        ("SY", "1"),
        ("W", str(width)),
        ("H", str(height)),
        ("PATH", path),
    ]:
        child = ET.SubElement(node, tag)
        child.text = value
    ET.SubElement(node, "CHILDREN")
    for tag, value in [
        ("MANUAL_SCALING", "false"),
        ("SCALED_PIXMAP_WIDTH", "-842150451"),
        ("SCALED_PIXMAP_HEIGHT", "-842150451"),
        ("INIT_WIDTH", str(width)),
        ("INIT_HEIGHT", str(height)),
        ("INIT_SX", "1"),
        ("INIT_SY", "1"),
    ]:
        child = ET.SubElement(node, tag)
        child.text = value
    return node


def _build_minimal_physical_workspace() -> tuple[ET.Element, ET.Element, ET.Element]:
    physical = ET.Element("PHYSICALWORKSPACE")
    homerack = ET.SubElement(physical, "HOMERACK")
    homerack.set("translate", "true")
    homerack.text = ",".join(PHYSICAL_HOME_PATH)

    intercity = _make_workspace_node("Intercity", 0, 0, 0, 20000, 12416, "../art/Background/gGeoViewInterCity.png")
    city = _make_workspace_node("Home City", 1, 200, 200, 2000, 1238, "../art/Background/gGeoViewCity.png")
    building = _make_workspace_node("Corporate Office", 2, 100, 100, 200, 125, "../art/Background/gGeoViewBuilding.png")
    closet = _make_workspace_node("Main Wiring Closet", 3, 50, 50, 20, 20, "")
    table = _make_workspace_node("Table", 5, 0, 0, 0, 0, "")
    rack = _make_workspace_node("Rack", 4, 0, 0, 0, 0, "")

    intercity.find("./CHILDREN").append(city)
    city.find("./CHILDREN").append(building)
    building.find("./CHILDREN").append(closet)
    closet.find("./CHILDREN").extend([table, rack])
    physical.append(intercity)
    return physical, table, rack


def _closet_node_from_physical_root(physical_root: ET.Element) -> ET.Element | None:
    path = "./NODE/CHILDREN/NODE/CHILDREN/NODE/CHILDREN/NODE"
    closet = physical_root.find(path)
    if closet is not None and closet.findtext("./NAME", default="") == PHYSICAL_HOME_PATH[-1]:
        return closet
    for node in physical_root.findall(".//NODE"):
        if node.findtext("./NAME", default="") == PHYSICAL_HOME_PATH[-1]:
            return node
    return None


def _container_node(closet: ET.Element, container_name: str, node_type: int) -> ET.Element:
    children = closet.find("./CHILDREN")
    if children is None:
        children = ET.SubElement(closet, "CHILDREN")
    for node in children.findall("./NODE"):
        if node.findtext("./NAME", default="") == container_name:
            target = node.find("./TYPE")
            if target is not None:
                target.text = str(node_type)
            return node
    node = _make_workspace_node(container_name, node_type, 0, 0, 0, 0, "")
    children.append(node)
    return node


def _leaf_template(container: ET.Element, default_name: str) -> ET.Element:
    for node in container.findall("./CHILDREN/NODE"):
        if node.findtext("./TYPE", default="") == "6":
            return copy.deepcopy(node)
    return _make_workspace_node(default_name, 6, 0, 0, 0, 0, "")


def _clone_leaf(template: ET.Element, name: str, index: int) -> ET.Element:
    leaf = copy.deepcopy(template)
    for child in list(leaf):
        if child.tag == "CHILDREN":
            child.clear()
    name_node = leaf.find("./NAME")
    if name_node is None:
        name_node = ET.SubElement(leaf, "NAME")
    name_node.set("translate", "true")
    name_node.text = name
    x_node = leaf.find("./X")
    y_node = leaf.find("./Y")
    if x_node is None:
        x_node = ET.SubElement(leaf, "X")
    if y_node is None:
        y_node = ET.SubElement(leaf, "Y")
    x_node.text = str((index % 8) * 8)
    y_node.text = str((index // 8) * 8)
    return leaf


def _physical_leaf_path(device_name: str, container_name: str) -> str:
    return ",".join([*PHYSICAL_HOME_PATH, container_name, device_name])


def _device_physical_container(device: ET.Element) -> str:
    device_type = device.findtext("./ENGINE/TYPE", default="")
    if device_type in {"Router", "Switch", "MultiLayerSwitch", "Server", "WirelessRouter", "WirelessLanController", "LightWeightAccessPoint"}:
        return "Rack"
    return "Table"


def sanitize_generated_physical_workspace(root: ET.Element) -> None:
    devices_parent = root.find(".//DEVICES")
    if devices_parent is None:
        return
    version = root.findtext("./VERSION", default="")
    if version.startswith("9.") and any(device.find("./WORKSPACE/PHYSICAL_CPUR") is not None for device in devices_parent.findall("./DEVICE")):
        return

    physical_root = root.find("./PHYSICALWORKSPACE")
    if physical_root is None:
        physical_root, _, _ = _build_minimal_physical_workspace()
        insert_at = 1 if root.find("./VERSION") is not None else 0
        root.insert(insert_at, physical_root)

    closet = _closet_node_from_physical_root(physical_root)
    if closet is None:
        replacement_root, _, _ = _build_minimal_physical_workspace()
        existing = root.find("./PHYSICALWORKSPACE")
        if existing is not None:
            root.remove(existing)
        insert_at = 1 if root.find("./VERSION") is not None else 0
        root.insert(insert_at, replacement_root)
        physical_root = replacement_root
        closet = _closet_node_from_physical_root(physical_root)
        if closet is None:
            return

    table = _container_node(closet, "Table", 5)
    rack = _container_node(closet, "Rack", 4)
    table_template = _leaf_template(table, "PC0")
    rack_template = _leaf_template(rack, "Server0")
    table_children = table.find("./CHILDREN")
    rack_children = rack.find("./CHILDREN")
    assert table_children is not None and rack_children is not None
    table_children.clear()
    rack_children.clear()

    for index, device in enumerate(devices_parent.findall("./DEVICE"), start=1):
        name = device.findtext("./ENGINE/NAME", default=f"Device{index}")
        container_name = _device_physical_container(device)
        template = rack_template if container_name == "Rack" else table_template
        leaf = _clone_leaf(template, name, index - 1)
        if container_name == "Rack":
            rack_children.append(leaf)
        else:
            table_children.append(leaf)

        workspace = device.find("./WORKSPACE")
        if workspace is None:
            workspace = ET.SubElement(device, "WORKSPACE")
        logical = workspace.find("./LOGICAL")
        logical_copy = ET.fromstring(ET.tostring(logical, encoding="unicode")) if logical is not None else ET.Element("LOGICAL")
        for child in list(workspace):
            workspace.remove(child)
        workspace.append(logical_copy)
        physical = ET.SubElement(workspace, "PHYSICAL")
        physical.set("translate", "true")
        physical.text = _physical_leaf_path(name, container_name)


def _collect_physical_paths(root: ET.Element) -> set[str]:
    physical_root = root.find("./PHYSICALWORKSPACE")
    if physical_root is None:
        return set()
    paths: set[str] = set()
    for top in physical_root.findall("./NODE"):
        _walk_physical_node(top, [], paths)
    return paths


def _walk_physical_node(node: ET.Element, ancestors: list[str], sink: set[str]) -> None:
    name = node.findtext("./NAME", default="")
    if not name:
        return
    current = [*ancestors, name]
    sink.add(",".join(current))
    for child in node.findall("./CHILDREN/NODE"):
        _walk_physical_node(child, current, sink)


def inspect_workspace_integrity(root: ET.Element) -> WorkspaceValidationResult:
    issues: list[str] = []
    if root.tag != "PACKETTRACER5":
        issues.append("Root element must be PACKETTRACER5")
    if root.find("VERSION") is None:
        issues.append("Packet Tracer XML is missing VERSION")

    devices_parent = root.find(".//DEVICES")
    links_parent = root.find(".//LINKS")
    if devices_parent is None or links_parent is None:
        issues.append("Packet Tracer XML is missing DEVICES or LINKS container")
        return WorkspaceValidationResult("unknown", "invalid", "invalid", issues)

    devices = devices_parent.findall("./DEVICE")
    links = links_parent.findall("./LINK")
    if not devices:
        issues.append("No devices remain in generated Packet Tracer XML")

    logical_mem_addrs: list[str] = []
    save_ref_ids: list[str] = []
    for device in devices:
        if device.find("./WORKSPACE/LOGICAL/X") is None or device.find("./WORKSPACE/LOGICAL/Y") is None:
            issues.append("Device is missing logical workspace coordinates")
        mem_addr = device.findtext("./WORKSPACE/LOGICAL/MEM_ADDR", default="")
        if not mem_addr:
            issues.append("Device is missing logical workspace MEM_ADDR")
        else:
            logical_mem_addrs.append(mem_addr)
        save_ref = device.findtext("./ENGINE/SAVE_REF_ID", default="")
        if save_ref:
            save_ref_ids.append(save_ref)

    device_count = len(devices)
    for link in links:
        cable = link.find("./CABLE")
        if cable is None:
            issues.append("Link is missing CABLE node")
            continue
        from_idx = cable.findtext("FROM", default="")
        to_idx = cable.findtext("TO", default="")
        if not from_idx or not to_idx:
            issues.append("Link is missing FROM or TO index")
            continue
        if from_idx.isdigit() and to_idx.isdigit():
            if int(from_idx) >= device_count or int(to_idx) >= device_count:
                issues.append("Link references a device index outside the DEVICES list")
        elif save_ref_ids:
            if from_idx not in save_ref_ids or to_idx not in save_ref_ids:
                issues.append("Link references device SAVE_REF_ID values not present in DEVICES")
        else:
            issues.append("Link FROM or TO index is not numeric")
            continue

        ports = [port.text or "" for port in cable.findall("PORT")]
        if len(ports) < 2 or not ports[0] or not ports[1]:
            issues.append("Link is missing endpoint port names")

        from_device_mem = cable.findtext("FROM_DEVICE_MEM_ADDR", default="")
        to_device_mem = cable.findtext("TO_DEVICE_MEM_ADDR", default="")
        if not from_device_mem or not to_device_mem:
            issues.append("Link is missing device MEM_ADDR references")
        elif from_device_mem not in logical_mem_addrs or to_device_mem not in logical_mem_addrs:
            issues.append("Link device MEM_ADDR references do not match device workspace records")

    physical_paths = _collect_physical_paths(root)
    if not physical_paths:
        issues.append("Packet Tracer XML is missing PHYSICALWORKSPACE tree")
    all_physical_values = [device.findtext("./WORKSPACE/PHYSICAL", default="") for device in devices]
    legacy_uuid_physical = any("{" in value and "}" in value for value in all_physical_values if value)
    for device in devices:
        physical = device.findtext("./WORKSPACE/PHYSICAL", default="")
        if not physical:
            issues.append("Device is missing physical workspace path")
            continue
        if not legacy_uuid_physical and physical not in physical_paths:
            issues.append(f"Device physical path does not exist in PHYSICALWORKSPACE: {physical}")

    if all(device.find("./WORKSPACE/PHYSICAL_CPUR") is None for device in devices):
        workspace_mode = "logical_only_safe"
    elif legacy_uuid_physical:
        workspace_mode = "legacy_uuid_physical"
    else:
        workspace_mode = "mixed_physical"
    logical_status = "ok" if not any("logical" in issue.lower() or "mem_addr" in issue.lower() for issue in issues) else "invalid"
    physical_status = "ok" if not any("physical" in issue.lower() for issue in issues) else "invalid"
    return WorkspaceValidationResult(workspace_mode, logical_status, physical_status, issues)


def validate_workspace_integrity(root: ET.Element) -> WorkspaceValidationResult:
    result = inspect_workspace_integrity(root)
    if result.blocking_issues:
        raise ValueError("; ".join(result.blocking_issues))
    return result


def _section_xml(root: ET.Element, path: str) -> str:
    node = root.find(path)
    if node is None:
        return ""
    return ET.tostring(node, encoding="unicode")


def _section_content_score(node: ET.Element | None) -> int:
    if node is None:
        return 0
    score = len(node.attrib)
    if (node.text or "").strip():
        score += 1
    score += sum(1 for _ in node.iter()) - 1
    return score


def _section_content_score_many(nodes: list[ET.Element]) -> int:
    return sum(_section_content_score(node) for node in nodes)


def _device_by_save_ref(root: ET.Element) -> dict[str, ET.Element]:
    devices: dict[str, ET.Element] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        save_ref = device.findtext("./ENGINE/SAVE_REF_ID", default="").strip()
        if save_ref:
            devices[save_ref] = device
    return devices


def _device_leaf_uuid(device: ET.Element) -> str:
    physical = device.findtext("./WORKSPACE/PHYSICAL", default="").strip()
    if not physical:
        return ""
    token = physical.split(",")[-1].strip()
    if token.startswith("{") and token.endswith("}"):
        return token
    return ""


def _physical_leaf_index(root: ET.Element) -> dict[str, ET.Element]:
    nodes: dict[str, ET.Element] = {}
    for node in root.findall(".//PHYSICALWORKSPACE//NODE"):
        uuid = node.findtext("./UUID_STR", default="").strip()
        if uuid:
            nodes[uuid] = node
    return nodes


def _config_hostname_hits(device: ET.Element, old_name: str) -> bool:
    target = f"hostname {old_name}"
    for line in device.findall("./ENGINE/RUNNINGCONFIG/LINE"):
        if (line.text or "").strip() == target:
            return True
    for line in device.findall("./ENGINE/STARTUPCONFIG/LINE"):
        if (line.text or "").strip() == target:
            return True
    for line in device.findall(".//FILE_CONTENT/CONFIG/LINE"):
        if (line.text or "").strip() == target:
            return True
    return False


def inspect_donor_coherence(donor_root: ET.Element, generated_root: ET.Element) -> DonorCoherenceResult:
    issues: list[str] = []
    donor_devices = _device_by_save_ref(donor_root)
    generated_devices = _device_by_save_ref(generated_root)

    scenario_sections = {
        "SCENARIOSET": _section_xml(generated_root, "./SCENARIOSET"),
        "COMMAND_LOGS": _section_xml(generated_root, "./COMMAND_LOGS"),
        "CEPS": _section_xml(generated_root, "./CEPS"),
        "FILTERS": _section_xml(generated_root, "./FILTERS"),
    }
    physical_sections = {
        "PHYSICALWORKSPACE": _section_xml(generated_root, "./PHYSICALWORKSPACE"),
        "GEOVIEW_GRAPHICSITEMS": _section_xml(generated_root, "./GEOVIEW_GRAPHICSITEMS"),
        "CLUSTERS": _section_xml(generated_root, "./CLUSTERS"),
    }
    global_visual_paths = {
        "FILTERS": "./FILTERS",
        "CLUSTERS": "./CLUSTERS",
        "GEOVIEW_GRAPHICSITEMS": "./GEOVIEW_GRAPHICSITEMS",
        "RECTANGLES": "./RECTANGLES",
        "ELLIPSES": "./ELLIPSES",
        "POLYGONS": "./POLYGONS",
    }
    preserved_scenario_paths = {
        "SCENARIOSET": "./SCENARIOSET",
        "COMMAND_LOGS": "./COMMAND_LOGS",
        "CEPS": "./CEPS",
    }
    for section_name, path in preserved_scenario_paths.items():
        donor_score = _section_content_score(donor_root.find(path))
        generated_score = _section_content_score(generated_root.find(path))
        if donor_score > 0 and generated_score == 0:
            issues.append(f"Generated file unexpectedly emptied donor runtime section {section_name}")
    for section_name, path in global_visual_paths.items():
        donor_score = _section_content_score(donor_root.find(path))
        generated_score = _section_content_score(generated_root.find(path))
        if donor_score > 0 and generated_score == 0:
            issues.append(f"Generated file unexpectedly emptied donor visual section {section_name}")

    donor_notes_score = _section_content_score_many(donor_root.findall("./PHYSICALWORKSPACE//NOTES"))
    generated_notes_score = _section_content_score_many(generated_root.findall("./PHYSICALWORKSPACE//NOTES"))
    if donor_notes_score > 0 and generated_notes_score == 0:
        issues.append("Generated file unexpectedly emptied donor visual section PHYSICALWORKSPACE/NOTES")

    for tag in ["ANSWER_TREE_SELECTED", "PHYSICALALIGN", "HIDEPHYSICAL", "CABLE_POPUP_IN_PHYSICAL"]:
        donor_value = donor_root.findtext(f"./{tag}", default="").strip()
        generated_value = generated_root.findtext(f"./{tag}", default="").strip()
        if donor_value != generated_value:
            issues.append(f"Generated file changed donor physical view state {tag} from {donor_value} to {generated_value}")

    pruned_ids = sorted(set(donor_devices) - set(generated_devices))
    for save_ref in pruned_ids:
        donor_device = donor_devices[save_ref]
        donor_name = donor_device.findtext("./ENGINE/NAME", default="").strip()
        original_uuid = donor_device.findtext(".//ORIGINAL_DEVICE_UUID", default="").strip()
        physical_uuid = _device_leaf_uuid(donor_device)
        for section_name, text in scenario_sections.items():
            for label, value in [("save-ref-id", save_ref), ("device-name", donor_name), ("original-uuid", original_uuid)]:
                if value and value in text:
                    issues.append(f"Pruned device {donor_name} still appears in {section_name} via {label}")
        for section_name, text in physical_sections.items():
            for label, value in [("save-ref-id", save_ref), ("device-name", donor_name), ("original-uuid", original_uuid), ("physical-leaf", physical_uuid)]:
                if value and value in text:
                    issues.append(f"Pruned device {donor_name} still appears in {section_name} via {label}")

    physical_index = _physical_leaf_index(generated_root)
    for save_ref in sorted(set(donor_devices) & set(generated_devices)):
        donor_device = donor_devices[save_ref]
        generated_device = generated_devices[save_ref]
        donor_name = donor_device.findtext("./ENGINE/NAME", default="").strip()
        generated_name = generated_device.findtext("./ENGINE/NAME", default="").strip()
        sys_name = generated_device.findtext("./ENGINE/SYS_NAME", default="").strip()
        if donor_name != generated_name and sys_name == donor_name:
            issues.append(f"Renamed device {generated_name} still keeps donor SYS_NAME {donor_name}")
        if donor_name != generated_name and _config_hostname_hits(generated_device, donor_name):
            issues.append(f"Renamed device {generated_name} still keeps donor hostname {donor_name} in config")
        leaf_uuid = _device_leaf_uuid(generated_device)
        if leaf_uuid:
            leaf = physical_index.get(leaf_uuid)
            if leaf is None:
                issues.append(f"Generated device {generated_name} references missing physical leaf {leaf_uuid}")
            else:
                leaf_name = leaf.findtext("./NAME", default="").strip()
                if leaf_name != generated_name:
                    issues.append(f"Generated device {generated_name} physical leaf name is {leaf_name}")

    device_issues = [issue for issue in issues if "SYS_NAME" in issue or "hostname" in issue]
    scenario_issues = [issue for issue in issues if any(section in issue for section in ["SCENARIOSET", "COMMAND_LOGS", "CEPS"])]
    physical_issues = [issue for issue in issues if any(section in issue for section in ["PHYSICALWORKSPACE", "physical leaf"])]
    visual_issues = [
        issue
        for issue in issues
        if any(
            section in issue
            for section in [
                "FILTERS",
                "CLUSTERS",
                "GEOVIEW_GRAPHICSITEMS",
                "RECTANGLES",
                "ELLIPSES",
                "POLYGONS",
                "PHYSICALWORKSPACE/NOTES",
                "physical view state",
            ]
        )
    ]

    return DonorCoherenceResult(
        device_metadata_status="ok" if not device_issues else "invalid",
        scenario_status="ok" if not scenario_issues else "invalid",
        physical_runtime_status="ok" if not physical_issues else "invalid",
        visual_runtime_status="ok" if not visual_issues else "invalid",
        blocking_issues=issues,
    )


def validate_donor_coherence(donor_root: ET.Element, generated_root: ET.Element) -> DonorCoherenceResult:
    result = inspect_donor_coherence(donor_root, generated_root)
    if result.blocking_issues:
        raise ValueError("; ".join(result.blocking_issues))
    return result
