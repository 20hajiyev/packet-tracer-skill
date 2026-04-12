from __future__ import annotations

import sys
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from workspace_repair import inspect_donor_coherence, inspect_workspace_integrity, sanitize_generated_physical_workspace  # noqa: E402


def _make_physical_leaf(name: str) -> ET.Element:
    node = ET.Element("NODE")
    for tag, value in [("X", "0"), ("Y", "0"), ("TYPE", "6")]:
        child = ET.SubElement(node, tag)
        child.text = value
    label = ET.SubElement(node, "NAME")
    label.set("translate", "true")
    label.text = name
    for tag, value in [("SX", "1"), ("SY", "1"), ("W", "0"), ("H", "0"), ("PATH", "")]:
        child = ET.SubElement(node, tag)
        child.text = value
    ET.SubElement(node, "CHILDREN")
    for tag, value in [
        ("MANUAL_SCALING", "false"),
        ("SCALED_PIXMAP_WIDTH", "-842150451"),
        ("SCALED_PIXMAP_HEIGHT", "-842150451"),
        ("INIT_WIDTH", "0"),
        ("INIT_HEIGHT", "0"),
        ("INIT_SX", "1"),
        ("INIT_SY", "1"),
    ]:
        child = ET.SubElement(node, tag)
        child.text = value
    return node


def _append_workspace_node(parent: ET.Element, name: str, node_type: str) -> ET.Element:
    node = ET.SubElement(parent, "NODE")
    for tag, value in [("X", "0"), ("Y", "0"), ("TYPE", node_type)]:
        child = ET.SubElement(node, tag)
        child.text = value
    label = ET.SubElement(node, "NAME")
    label.set("translate", "true")
    label.text = name
    for tag, value in [("SX", "1"), ("SY", "1"), ("W", "0"), ("H", "0"), ("PATH", "")]:
        child = ET.SubElement(node, tag)
        child.text = value
    ET.SubElement(node, "CHILDREN")
    for tag, value in [
        ("MANUAL_SCALING", "false"),
        ("SCALED_PIXMAP_WIDTH", "-842150451"),
        ("SCALED_PIXMAP_HEIGHT", "-842150451"),
        ("INIT_WIDTH", "0"),
        ("INIT_HEIGHT", "0"),
        ("INIT_SX", "1"),
        ("INIT_SY", "1"),
    ]:
        child = ET.SubElement(node, tag)
        child.text = value
    return node


def _make_donor_physical_root() -> ET.Element:
    physical = ET.Element("PHYSICALWORKSPACE")
    homerack = ET.SubElement(physical, "HOMERACK")
    homerack.set("translate", "true")
    homerack.text = "Intercity,Home City,Corporate Office,Main Wiring Closet"
    intercity = _append_workspace_node(physical, "Intercity", "0")
    city = _append_workspace_node(intercity.find("./CHILDREN"), "Home City", "1")
    building = _append_workspace_node(city.find("./CHILDREN"), "Corporate Office", "2")
    closet = _append_workspace_node(building.find("./CHILDREN"), "Main Wiring Closet", "3")
    table = _append_workspace_node(closet.find("./CHILDREN"), "Table", "5")
    rack = _append_workspace_node(closet.find("./CHILDREN"), "Rack", "4")
    table.find("./CHILDREN").append(_make_physical_leaf("PC0"))
    rack.find("./CHILDREN").append(_make_physical_leaf("Server0"))
    return physical


def _make_device(name: str) -> ET.Element:
    device = ET.Element("DEVICE")
    engine = ET.SubElement(device, "ENGINE")
    dtype = ET.SubElement(engine, "TYPE")
    dtype.text = "PC"
    dtype.set("model", "PC-PT")
    dname = ET.SubElement(engine, "NAME")
    dname.text = name
    workspace = ET.SubElement(device, "WORKSPACE")
    logical = ET.SubElement(workspace, "LOGICAL")
    for tag, value in [("X", "100"), ("Y", "120"), ("MEM_ADDR", "1000"), ("DEV_ADDR", "2000")]:
        node = ET.SubElement(logical, tag)
        node.text = value
    physical = ET.SubElement(workspace, "PHYSICAL")
    physical.text = "{legacy}"
    cpu = ET.SubElement(workspace, "PHYSICAL_CPUR")
    ET.SubElement(cpu, "PARENT_PATH").text = "{legacy}"
    return device


def _make_donor_ready_device(name: str, save_ref: str, original_uuid: str, leaf_uuid: str) -> ET.Element:
    device = ET.Element("DEVICE")
    engine = ET.SubElement(device, "ENGINE")
    dtype = ET.SubElement(engine, "TYPE")
    dtype.text = "PC"
    dtype.set("model", "PC-PT")
    dname = ET.SubElement(engine, "NAME")
    dname.text = name
    sys_name = ET.SubElement(engine, "SYS_NAME")
    sys_name.text = name
    save_ref_node = ET.SubElement(engine, "SAVE_REF_ID")
    save_ref_node.text = save_ref
    running = ET.SubElement(engine, "RUNNINGCONFIG")
    ET.SubElement(running, "LINE").text = f"hostname {name}"
    startup = ET.SubElement(engine, "STARTUPCONFIG")
    ET.SubElement(startup, "LINE").text = f"hostname {name}"
    ET.SubElement(engine, "ORIGINAL_DEVICE_UUID").text = original_uuid
    ET.SubElement(engine, "CONTAINER_ID").text = "{container}"
    ET.SubElement(engine, "PARENT_PATH").text = "{parent}"
    workspace = ET.SubElement(device, "WORKSPACE")
    logical = ET.SubElement(workspace, "LOGICAL")
    for tag, value in [("X", "100"), ("Y", "120"), ("MEM_ADDR", "1000"), ("DEV_ADDR", "2000")]:
        node = ET.SubElement(logical, tag)
        node.text = value
    physical = ET.SubElement(workspace, "PHYSICAL")
    physical.text = "{root},{city},{building},{closet}," + leaf_uuid
    ET.SubElement(workspace, "PHYSICAL_CPUR")
    return device


def test_sanitize_generated_physical_workspace_rewrites_device_paths() -> None:
    root = ET.Element("PACKETTRACER5")
    ET.SubElement(root, "VERSION").text = "5.3.0.0011"
    root.append(_make_donor_physical_root())
    network = ET.SubElement(root, "NETWORK")
    devices = ET.SubElement(network, "DEVICES")
    devices.append(_make_device("PC0"))
    ET.SubElement(network, "LINKS")

    sanitize_generated_physical_workspace(root)
    result = inspect_workspace_integrity(root)

    assert result.workspace_mode == "logical_only_safe"
    assert result.physical_status == "ok"
    device = root.find(".//DEVICES/DEVICE")
    assert device is not None
    assert device.find("./WORKSPACE/PHYSICAL_CPUR") is None
    assert device.findtext("./WORKSPACE/PHYSICAL", default="").endswith("Table,PC0")
    assert root.findtext("./PHYSICALWORKSPACE/NODE/NAME", default="") == "Intercity"


def test_inspect_donor_coherence_flags_stale_device_metadata() -> None:
    donor_root = ET.Element("PACKETTRACER5")
    ET.SubElement(donor_root, "VERSION").text = "9.0.0.0810"
    physical = _make_donor_physical_root()
    rack_children = physical.find("./NODE/CHILDREN/NODE/CHILDREN/NODE/CHILDREN/NODE/CHILDREN/NODE/CHILDREN")
    assert rack_children is not None
    leaf = _make_physical_leaf("DONOR-PC")
    ET.SubElement(leaf, "UUID_STR").text = "{leaf-uuid}"
    rack_children.append(leaf)
    donor_root.append(physical)
    network = ET.SubElement(donor_root, "NETWORK")
    devices = ET.SubElement(network, "DEVICES")
    devices.append(_make_donor_ready_device("DONOR-PC", "save-ref-id:1", "{orig-uuid}", "{leaf-uuid}"))
    ET.SubElement(network, "LINKS")

    generated_root = ET.fromstring(ET.tostring(donor_root, encoding="unicode"))
    generated_device = generated_root.find(".//DEVICES/DEVICE")
    assert generated_device is not None
    generated_device.find("./ENGINE/NAME").text = "NEW-PC"

    result = inspect_donor_coherence(donor_root, generated_root)
    assert result.device_metadata_status == "invalid"
    assert any("donor hostname DONOR-PC" in issue or "physical leaf name is DONOR-PC" in issue for issue in result.blocking_issues)
