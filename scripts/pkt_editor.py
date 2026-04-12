from __future__ import annotations

import copy
import re
from pathlib import Path
import xml.etree.ElementTree as ET

from intent_parser import IntentPlan
from packet_tracer_env import resolve_sample_path
from pkt_codec import decode_pkt_modern, encode_pkt_modern
from pkt_transformer import _device_type, _port_address_for_name, apply_cable_type, apply_host_ip, load_sample_root


FTP_SAMPLE = r"01 Networking\FTP\FTP.pkt"
SERVER_SAMPLE = r"01 Networking\DNS\Multilevel_DNS.pkt"
WIRELESS_SAMPLE = r"01 Networking\DHCP\dhcp_reservation.pkt"


def decode_pkt_to_root(pkt_path: str | Path) -> ET.Element:
    return ET.fromstring(decode_pkt_modern(Path(pkt_path).read_bytes()))


def inventory_devices(root: ET.Element) -> list[dict[str, str]]:
    devices: list[dict[str, str]] = []
    for device in root.findall(".//DEVICES/DEVICE"):
        devices.append(
            {
                "name": device.findtext("./ENGINE/NAME", default=""),
                "type": _device_type(device),
                "model": device.find("./ENGINE/TYPE").get("model", "") if device.find("./ENGINE/TYPE") is not None else "",
            }
        )
    return devices


def inventory_links(root: ET.Element) -> list[dict[str, object]]:
    devices = root.findall(".//DEVICES/DEVICE")
    index_to_name = {str(index): device.findtext("./ENGINE/NAME", default="") for index, device in enumerate(devices)}
    save_ref_to_name = {
        device.findtext("./ENGINE/SAVE_REF_ID", default=""): device.findtext("./ENGINE/NAME", default="")
        for device in devices
        if device.findtext("./ENGINE/SAVE_REF_ID", default="")
    }
    result: list[dict[str, object]] = []
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        ports = cable.findall("PORT")
        from_ref = cable.findtext("FROM", default="")
        to_ref = cable.findtext("TO", default="")
        result.append(
            {
                "from": save_ref_to_name.get(from_ref, index_to_name.get(from_ref, "")),
                "to": save_ref_to_name.get(to_ref, index_to_name.get(to_ref, "")),
                "ports": [port.text or "" for port in ports],
                "media": cable.findtext("TYPE", default=""),
            }
        )
    return result


def inventory_services(root: ET.Element) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME", default="")
        engine = device.find("./ENGINE")
        if engine is None:
            continue
        enabled: list[str] = []
        for tag, enabled_tag in [
            ("HTTP_SERVER", "ENABLED"),
            ("HTTPS_SERVER", "HTTPSENABLED"),
            ("DNS_SERVER", "ENABLED"),
            ("DHCP_SERVER", "ENABLED"),
            ("TFTP_SERVER", "ENABLED"),
            ("NTP_SERVER", "ENABLED"),
        ]:
            node = engine.find(tag)
            if node is not None and node.findtext(enabled_tag, default="0") in {"1", "true", "True"}:
                enabled.append(tag.lower())
        if enabled:
            result[name] = enabled
    return result


def inventory_wireless(root: ET.Element) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME", default="")
        engine = device.find("./ENGINE")
        if engine is None:
            continue
        if engine.find("WIRELESS_SERVER") is not None:
            common = engine.find("./WIRELESS_SERVER/WIRELESS_COMMON")
            result[name] = {
                "mode": "ap",
                "ssid": common.findtext("SSID", default="") if common is not None else "",
            }
        if engine.find("WIRELESS_CLIENT") is not None:
            common = engine.find("./WIRELESS_CLIENT/WIRELESS_COMMON")
            result[name] = {
                "mode": "client",
                "ssid": common.findtext("SSID", default="") if common is not None else "",
            }
    return result


def inventory_vlans(root: ET.Element) -> dict[str, list[dict[str, str]]]:
    result: dict[str, list[dict[str, str]]] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME", default="")
        vlans: list[dict[str, str]] = []
        for vlan in device.findall(".//VLANS/VLAN"):
            vlan_id = vlan.get("number") or vlan.findtext("ID", default="")
            vlan_name = vlan.get("name") or vlan.findtext("NAME", default="")
            if vlan_id:
                vlans.append({"id": vlan_id, "name": vlan_name})
        if vlans:
            result[name] = vlans
            continue
        running = "\n".join(line.text or "" for line in device.findall(".//LINE"))
        inferred: list[dict[str, str]] = []
        for match in re.finditer(r"(?mi)^vlan\s+(\d+)\s*$", running):
            vlan_id = match.group(1)
            name_match = re.search(rf"(?mi)^vlan\s+{re.escape(vlan_id)}\s*$\n^\s*name\s+(.+?)\s*$", running)
            inferred.append({"id": vlan_id, "name": name_match.group(1).strip() if name_match else ""})
        if inferred:
            unique: dict[str, dict[str, str]] = {entry["id"]: entry for entry in inferred}
            result[name] = list(unique.values())
    return result


def inventory_dhcp_pools(root: ET.Element) -> dict[str, list[str]]:
    pools: dict[str, list[str]] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME", default="")
        device_pools: list[str] = []
        for pool in device.findall(".//DHCP_SERVER/POOLS/POOL/NAME"):
            if pool.text:
                device_pools.append(pool.text)
        running = "\n".join(line.text or "" for line in device.findall("./ENGINE/RUNNINGCONFIG/LINE"))
        for match in re.findall(r"ip dhcp pool\s+([A-Za-z0-9_-]+)", running):
            if match not in device_pools:
                device_pools.append(match)
        if device_pools:
            pools[name] = device_pools
    return pools


def inventory_acl_names(root: ET.Element) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME", default="")
        running = "\n".join(line.text or "" for line in device.findall("./ENGINE/RUNNINGCONFIG/LINE"))
        matches = re.findall(r"ip access-list\s+(?:standard|extended)\s+([A-Za-z0-9_-]+)", running)
        if matches:
            result[name] = sorted(dict.fromkeys(matches))
    return result


def inventory_topology_summary(root: ET.Element) -> dict[str, object]:
    devices = inventory_devices(root)
    counts: dict[str, int] = {}
    for device in devices:
        counts[device["type"]] = counts.get(device["type"], 0) + 1
    return {
        "device_counts": counts,
        "link_count": len(inventory_links(root)),
        "has_wireless": bool(inventory_wireless(root)),
        "has_services": bool(inventory_services(root)),
        "has_vlans": bool(inventory_vlans(root)),
    }


def inventory_root(root: ET.Element) -> dict[str, object]:
    return {
        "devices": inventory_devices(root),
        "links": inventory_links(root),
        "services": inventory_services(root),
        "wireless": inventory_wireless(root),
        "vlans": inventory_vlans(root),
        "dhcp_pools": inventory_dhcp_pools(root),
        "acl_names": inventory_acl_names(root),
        "topology_summary": inventory_topology_summary(root),
    }


def _find_device(root: ET.Element, name: str) -> ET.Element | None:
    for device in root.findall(".//DEVICES/DEVICE"):
        if device.findtext("./ENGINE/NAME", default="") == name:
            return device
    return None


def _ensure_text(parent: ET.Element, tag: str, value: str) -> ET.Element:
    node = parent.find(tag)
    if node is None:
        node = ET.SubElement(parent, tag)
    node.text = value
    return node


def _replace_lines(target: ET.Element, lines: list[str]) -> None:
    target.clear()
    for line in lines:
        node = ET.SubElement(target, "LINE")
        node.text = line


def _append_unique_config_lines(parent: ET.Element | None, lines: list[str]) -> None:
    if parent is None:
        return
    existing = [line.text or "" for line in parent.findall("./LINE")]
    merged = list(existing)
    for line in lines:
        if line not in merged:
            merged.append(line)
    _replace_lines(parent, merged)


def _append_config_block(parent: ET.Element | None, header: str, body: list[str]) -> None:
    if parent is None:
        return
    existing = [line.text or "" for line in parent.findall("./LINE")]
    block = [header, *body]
    for index in range(0, max(len(existing) - len(block) + 1, 0)):
        if existing[index : index + len(block)] == block:
            return
    _replace_lines(parent, [*existing, *block])


def _device_index_map(root: ET.Element) -> dict[str, int]:
    return {device.findtext("./ENGINE/NAME", default=""): index for index, device in enumerate(root.findall(".//DEVICES/DEVICE"))}


def _device_refs(root: ET.Element) -> tuple[dict[str, str], dict[str, str]]:
    index_map = _device_index_map(root)
    index_refs = {name: str(index) for name, index in index_map.items()}
    save_refs = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME", default="")
        save_ref = device.findtext("./ENGINE/SAVE_REF_ID", default="")
        if name and save_ref:
            save_refs[name] = save_ref
    return index_refs, save_refs


def _find_link_by_devices(root: ET.Element, left_name: str, right_name: str) -> ET.Element | None:
    index_refs, save_refs = _device_refs(root)
    left_candidates = {index_refs.get(left_name, ""), save_refs.get(left_name, "")}
    right_candidates = {index_refs.get(right_name, ""), save_refs.get(right_name, "")}
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        from_idx = cable.findtext("FROM", default="")
        to_idx = cable.findtext("TO", default="")
        if from_idx in left_candidates and to_idx in right_candidates:
            return link
        if from_idx in right_candidates and to_idx in left_candidates:
            return link
    return None


def _remove_links_for_device(root: ET.Element, device_name: str) -> None:
    index_refs, save_refs = _device_refs(root)
    refs = {index_refs.get(device_name, ""), save_refs.get(device_name, "")}
    links_parent = root.find(".//LINKS")
    if links_parent is None:
        return
    for link in list(links_parent.findall("./LINK")):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        if cable.findtext("FROM", default="") in refs or cable.findtext("TO", default="") in refs:
            links_parent.remove(link)


def _find_parent_of_node(root: ET.Element, target: ET.Element) -> ET.Element | None:
    for parent in root.iter():
        for child in list(parent):
            if child is target:
                return parent
    return None


def _remove_physical_leaf(root: ET.Element, device: ET.Element) -> None:
    physical_path = device.findtext("./WORKSPACE/PHYSICAL", default="")
    if not physical_path:
        return
    tokens = [token.strip() for token in physical_path.split(",") if token.strip()]
    if not tokens:
        return
    leaf_token = tokens[-1]
    for node in root.findall(".//PHYSICALWORKSPACE//NODE"):
        uuid = node.findtext("UUID_STR", default="").strip()
        if uuid == leaf_token:
            parent = _find_parent_of_node(root, node)
            if parent is not None:
                parent.remove(node)
            return


def _prune_device(root: ET.Element, device_name: str) -> None:
    device = _find_device(root, device_name)
    if device is None:
        return
    _remove_links_for_device(root, device_name)
    _remove_physical_leaf(root, device)
    parent = _find_parent_of_node(root, device)
    if parent is not None:
        parent.remove(device)


def _remove_link(root: ET.Element, left_name: str, right_name: str) -> None:
    links_parent = root.find(".//LINKS")
    if links_parent is None:
        return
    link = _find_link_by_devices(root, left_name, right_name)
    if link is not None:
        links_parent.remove(link)


def _ensure_link(root: ET.Element, left_name: str, left_port: str, right_name: str, right_port: str, media: str) -> None:
    existing = _find_link_by_devices(root, left_name, right_name)
    devices = {device.findtext("./ENGINE/NAME", default=""): device for device in root.findall(".//DEVICES/DEVICE")}
    index_refs, save_refs = _device_refs(root)
    left_device = devices.get(left_name)
    right_device = devices.get(right_name)
    if left_device is None or right_device is None:
        return
    link = existing
    if link is None:
        left_type = _device_type(left_device)
        right_type = _device_type(right_device)
        prototype = None
        for candidate in root.findall(".//LINKS/LINK"):
            cable = candidate.find("./CABLE")
            if cable is None:
                continue
            from_ref = cable.findtext("FROM", default="")
            to_ref = cable.findtext("TO", default="")
            from_name = next((name for name, ref in save_refs.items() if ref == from_ref), next((name for name, ref in index_refs.items() if ref == from_ref), ""))
            to_name = next((name for name, ref in save_refs.items() if ref == to_ref), next((name for name, ref in index_refs.items() if ref == to_ref), ""))
            if not from_name or not to_name:
                continue
            from_type = _device_type(devices[from_name])
            to_type = _device_type(devices[to_name])
            if {from_type, to_type} == {left_type, right_type}:
                prototype = candidate
                break
        if prototype is None:
            prototype_root = load_sample_root(resolve_sample_path(FTP_SAMPLE))
            prototype = prototype_root.find(".//LINKS/LINK")
        link = copy.deepcopy(prototype)
        if link is None:
            return
        links_parent = root.find(".//LINKS")
        if links_parent is None:
            return
        links_parent.append(link)
    cable = link.find("./CABLE")
    if cable is None:
        return
    _ensure_text(cable, "FROM", save_refs.get(left_name, index_refs[left_name]))
    _ensure_text(cable, "TO", save_refs.get(right_name, index_refs[right_name]))
    ports = cable.findall("PORT")
    if len(ports) < 2:
        while len(ports) < 2:
            ports.append(ET.SubElement(cable, "PORT"))
    ports[0].text = left_port
    ports[1].text = right_port
    for node_name, value in [
        ("FROM_DEVICE_MEM_ADDR", left_device.findtext("./WORKSPACE/LOGICAL/MEM_ADDR", default="")),
        ("TO_DEVICE_MEM_ADDR", right_device.findtext("./WORKSPACE/LOGICAL/MEM_ADDR", default="")),
        ("FROM_PORT_MEM_ADDR", _port_address_for_name(left_device, left_port) or ""),
        ("TO_PORT_MEM_ADDR", _port_address_for_name(right_device, right_port) or ""),
    ]:
        _ensure_text(cable, node_name, value)
    apply_cable_type(cable, media)


def _prefix_to_mask(prefix: int) -> str:
    bits = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return ".".join(str((bits >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def _set_device_name(root: ET.Element, device: ET.Element, new_name: str) -> None:
    old_name = device.findtext("./ENGINE/NAME", default="")
    node = device.find("./ENGINE/NAME")
    if node is not None:
        node.text = new_name
    sys_name = device.find("./ENGINE/SYS_NAME")
    if sys_name is not None and (sys_name.text or "").strip() == old_name:
        sys_name.text = new_name

    for line in device.findall("./ENGINE/RUNNINGCONFIG/LINE"):
        text = line.text or ""
        if old_name and text == f"hostname {old_name}":
            line.text = f"hostname {new_name}"
    for line in device.findall("./ENGINE/STARTUPCONFIG/LINE"):
        text = line.text or ""
        if old_name and text == f"hostname {old_name}":
            line.text = f"hostname {new_name}"
    for line in device.findall(".//FILE_CONTENT/CONFIG/LINE"):
        text = line.text or ""
        if old_name and text == f"hostname {old_name}":
            line.text = f"hostname {new_name}"

    physical = device.findtext("./WORKSPACE/PHYSICAL", default="")
    leaf_uuid = physical.split(",")[-1].strip() if physical else ""
    if leaf_uuid:
        for node in root.findall(".//PHYSICALWORKSPACE//NODE"):
            uuid = node.findtext("UUID_STR", default="").strip()
            if uuid == leaf_uuid:
                leaf_name = node.find("./NAME")
                if leaf_name is not None:
                    leaf_name.text = new_name
                break


def _set_device_position(device: ET.Element, x: int, y: int) -> None:
    workspace = device.find("./WORKSPACE/LOGICAL")
    if workspace is None:
        return
    _ensure_text(workspace, "X", str(x))
    _ensure_text(workspace, "Y", str(y))


def _config_targets(device: ET.Element) -> list[ET.Element]:
    targets: list[ET.Element] = []
    for path in ["./ENGINE/RUNNINGCONFIG", "./ENGINE/STARTUPCONFIG"]:
        node = device.find(path)
        if node is not None:
            targets.append(node)
    for node in device.findall(".//FILE_CONTENT/CONFIG"):
        targets.append(node)
    return targets


def _ensure_vlan_state(device: ET.Element, vlan_id: int, vlan_name: str) -> None:
    vlans = device.find(".//VLANS")
    if vlans is None:
        engine = device.find("./ENGINE")
        if engine is None:
            return
        vlans = ET.SubElement(engine, "VLANS")
    existing = next((node for node in vlans.findall("./VLAN") if node.get("number") == str(vlan_id)), None)
    if existing is None:
        existing = ET.SubElement(vlans, "VLAN")
        existing.set("number", str(vlan_id))
        existing.set("rspan", "0")
    existing.set("name", vlan_name)


def _apply_switch_op(device: ET.Element, operation: dict[str, object]) -> None:
    if operation["op"] == "set_vlan":
        lines = [f"vlan {operation['vlan']}", f" name {operation['name']}"]
        for target in _config_targets(device):
            _append_unique_config_lines(target, lines)
        _ensure_vlan_state(device, int(operation["vlan"]), str(operation["name"]))
        return
    elif operation["op"] == "set_access_port":
        for target in _config_targets(device):
            _append_config_block(
                target,
                f"interface {operation['port']}",
                [" switchport mode access", f" switchport access vlan {operation['vlan']}"],
            )
        return
    elif operation["op"] == "set_trunk_port":
        allowed = ",".join(str(vlan) for vlan in operation["allowed"])
        body = [" switchport mode trunk", f" switchport trunk allowed vlan {allowed}"]
        if operation.get("native"):
            body.append(f" switchport trunk native vlan {operation['native']}")
        for target in _config_targets(device):
            _append_config_block(target, f"interface {operation['port']}", body)
        return
    else:
        return


def _apply_router_op(device: ET.Element, operation: dict[str, object]) -> None:
    if operation["op"] == "set_subinterface":
        for target in _config_targets(device):
            _append_config_block(
                target,
                f"interface {operation['subinterface']}",
                [
                    f" encapsulation dot1Q {operation['vlan']}",
                    f" ip address {operation['ip']} {_prefix_to_mask(int(operation['prefix']))}",
                    " no shutdown",
                ],
            )
        return
    elif operation["op"] == "set_router_dhcp_pool":
        lines = [
            f"ip dhcp pool {operation['name']}",
            f" network {operation['network']} {_prefix_to_mask(int(operation['prefix']))}",
            f" default-router {operation['gateway']}",
        ]
        if operation.get("dns"):
            lines.append(f" dns-server {operation['dns']}")
    elif operation["op"] == "set_acl":
        lines = [f"ip access-list {operation['acl_kind']} {operation['acl_name']}"]
    elif operation["op"] == "add_acl_rule":
        acl_kind = str(operation.get("acl_kind") or "standard")
        for target in _config_targets(device):
            _append_config_block(
                target,
                f"ip access-list {acl_kind} {operation['acl_name']}",
                [f" {operation['action']} {operation['source']} {operation['destination']}"] if operation.get("destination") else [f" {operation['action']} {operation['source']}"],
            )
        return
    elif operation["op"] == "apply_acl":
        for target in _config_targets(device):
            _append_config_block(target, f"interface {operation['interface']}", [f" ip access-group {operation['acl_name']} {operation['direction']}"])
        return
    else:
        return
    for target in _config_targets(device):
        _append_unique_config_lines(target, lines)


def _apply_management_op(device: ET.Element, operation: dict[str, object]) -> None:
    if operation["op"] == "set_management_vlan":
        for target in _config_targets(device):
            _append_config_block(
                target,
                f"interface Vlan{operation['vlan']}",
                [f" ip address {operation['ip']} {_prefix_to_mask(int(operation['prefix']))}", " no shutdown"],
            )
            _append_unique_config_lines(target, [f"ip default-gateway {operation['gateway']}"])
        return
    elif operation["op"] == "enable_telnet":
        for target in _config_targets(device):
            _append_unique_config_lines(target, [f"username {operation['username']} secret {operation['password']}", f"enable secret {operation['password']}"])
            _append_config_block(target, "line vty 0 4", [" login local", " transport input telnet"])
        return
    else:
        return


def _set_enabled_service(engine: ET.Element, service_name: str) -> None:
    mapping = {
        "dns": ("DNS_SERVER", "ENABLED"),
        "http": ("HTTP_SERVER", "ENABLED"),
        "https": ("HTTPS_SERVER", "HTTPSENABLED"),
        "ftp": ("FTP_SERVER", "ENABLED"),
        "tftp": ("TFTP_SERVER", "ENABLED"),
        "ntp": ("NTP_SERVER", "ENABLED"),
    }
    tag, enabled_tag = mapping[service_name]
    node = engine.find(tag)
    if node is None:
        sample_root = load_sample_root(resolve_sample_path(SERVER_SAMPLE))
        prototype = sample_root.find(f".//DEVICES/DEVICE[ENGINE/TYPE='Server']/ENGINE/{tag}")
        node = copy.deepcopy(prototype) if prototype is not None else ET.SubElement(engine, tag)
    if node not in list(engine):
        engine.append(node)
    _ensure_text(node, enabled_tag, "1")


def _apply_server_op(device: ET.Element, operation: dict[str, object]) -> None:
    engine = device.find("./ENGINE")
    if engine is None:
        return
    if operation["op"] == "set_server_dns_record":
        dns_server = engine.find("DNS_SERVER")
        if dns_server is None:
            sample_root = load_sample_root(resolve_sample_path(SERVER_SAMPLE))
            prototype = sample_root.find(".//DEVICES/DEVICE[ENGINE/TYPE='Server']/ENGINE/DNS_SERVER")
            dns_server = copy.deepcopy(prototype) if prototype is not None else ET.SubElement(engine, "DNS_SERVER")
            engine.append(dns_server)
        _ensure_text(dns_server, "ENABLED", "1")
        database = dns_server.find("NAMESERVER-DATABASE")
        if database is None:
            database = ET.SubElement(dns_server, "NAMESERVER-DATABASE")
        record = ET.SubElement(database, "RESOURCE-RECORD")
        if operation["record_type"] == "A":
            _ensure_text(record, "TYPE", "A-REC")
            _ensure_text(record, "NAME", str(operation["name"]))
            _ensure_text(record, "TTL", "86400")
            _ensure_text(record, "IPADDRESS", str(operation["value"]))
        else:
            _ensure_text(record, "TYPE", "CNAME")
            _ensure_text(record, "NAME", str(operation["name"]))
            _ensure_text(record, "TTL", "86400")
            _ensure_text(record, "SERVER-NAME", str(operation["value"]))
    elif operation["op"] == "set_server_dhcp_pool":
        dhcp_server = engine.find("DHCP_SERVER")
        if dhcp_server is None:
            sample_root = load_sample_root(resolve_sample_path(SERVER_SAMPLE))
            prototype = sample_root.find(".//DEVICES/DEVICE[ENGINE/TYPE='Server']/ENGINE/DHCP_SERVER")
            dhcp_server = copy.deepcopy(prototype) if prototype is not None else ET.SubElement(engine, "DHCP_SERVER")
            engine.append(dhcp_server)
        _ensure_text(dhcp_server, "ENABLED", "1")
        pools = dhcp_server.find("POOLS")
        if pools is None:
            pools = ET.SubElement(dhcp_server, "POOLS")
        pool = ET.SubElement(pools, "POOL")
        _ensure_text(pool, "NAME", str(operation["name"]))
        _ensure_text(pool, "NETWORK", str(operation["network"]))
        _ensure_text(pool, "MASK", _prefix_to_mask(int(operation["prefix"])))
        _ensure_text(pool, "DEFAULT_ROUTER", str(operation["gateway"]))
        _ensure_text(pool, "START_IP", str(operation.get("start") or operation["network"]))
        _ensure_text(pool, "END_IP", str(operation.get("start") or operation["network"]))
        _ensure_text(pool, "DNS_SERVER", str(operation.get("dns") or "0.0.0.0"))
        _ensure_text(pool, "MAX_USERS", str(operation.get("max_users") or 0))
    elif operation["op"] == "enable_server_service":
        _set_enabled_service(engine, str(operation["service"]))


def _wireless_common_nodes(engine: ET.Element) -> list[ET.Element]:
    nodes: list[ET.Element] = []
    for path in [
        "./WIRELESS_SERVER/WIRELESS_COMMON",
        "./WIRELESS_CLIENT/WIRELESS_COMMON",
        "./WLC/WLANS/WLAN_CONFIG",
    ]:
        node = engine.find(path)
        if node is not None:
            nodes.append(node)
    return nodes


def _profile_nodes(engine: ET.Element) -> list[ET.Element]:
    return engine.findall("./WIRELESS_CLIENT/PROFILES/WIRELESS_PROFILE") + engine.findall("./WIRELESS_CLIENT/CURRENT_PROFILE/WIRELESS_PROFILE")


def _apply_wireless_op(device: ET.Element, operation: dict[str, object]) -> None:
    engine = device.find("./ENGINE")
    if engine is None:
        return
    if operation["op"] == "set_wireless_ssid":
        for node in _wireless_common_nodes(engine):
            _ensure_text(node, "SSID", str(operation["ssid"]))
            _ensure_text(node, "AUTHEN_TYPE", str(operation["auth_type"]))
            _ensure_text(node, "ENCRYPT_TYPE", str(operation["encrypt_type"]))
            if node.find("STANDARD_CHANNEL") is not None:
                _ensure_text(node, "STANDARD_CHANNEL", str(operation["channel"]))
            if node.find("CHANNEL") is not None:
                _ensure_text(node, "CHANNEL", str(operation["channel"]))
            if operation.get("passphrase"):
                if node.find("WEP_KEY") is not None:
                    _ensure_text(node, "WEP_KEY", str(operation["passphrase"]))
                if node.find("WPA_PASSPHRASE") is not None:
                    _ensure_text(node, "WPA_PASSPHRASE", str(operation["passphrase"]))
        for profile in _profile_nodes(engine):
            _ensure_text(profile, "NAME", str(operation["ssid"]))
            _ensure_text(profile, "SSID", str(operation["ssid"]))
            _ensure_text(profile, "AUTHEN_TYPE", str(operation["auth_type"]))
            _ensure_text(profile, "ENCRYPT_TYPE", str(operation["encrypt_type"]))
            _ensure_text(profile, "CHANNEL", str(operation["channel"]))
            if profile.find("WEP_KEY") is not None:
                _ensure_text(profile, "WEP_KEY", str(operation.get("passphrase") or ""))
    elif operation["op"] == "associate_wireless_client":
        for node in _wireless_common_nodes(engine):
            _ensure_text(node, "SSID", str(operation["ssid"]))
        for profile in _profile_nodes(engine):
            _ensure_text(profile, "NAME", str(operation["ssid"]))
            _ensure_text(profile, "SSID", str(operation["ssid"]))
            _ensure_text(profile, "DHCP_ENABLED", "1" if operation.get("ip_mode", "dhcp") == "dhcp" else "0")
        for port in device.findall(".//PORT"):
            if port.findtext("TYPE", default="").startswith("eHostWireless"):
                _ensure_text(port, "PORT_DHCP_ENABLE", "true" if operation.get("ip_mode", "dhcp") == "dhcp" else "false")


def _apply_end_device_op(device: ET.Element, operation: dict[str, object]) -> None:
    if operation["op"] == "set_host_ip":
        apply_host_ip(device, operation)
    elif operation["op"] == "set_host_dhcp":
        for port in device.findall(".//PORT"):
            if port.find("PORT_DHCP_ENABLE") is not None:
                _ensure_text(port, "PORT_DHCP_ENABLE", "true")
        for profile in _profile_nodes(device.find("./ENGINE") or ET.Element("ENGINE")):
            _ensure_text(profile, "DHCP_ENABLED", "1")
    elif operation["op"] == "set_host_dns":
        apply_host_ip(device, operation)


def apply_plan_operations(root: ET.Element, plan: IntentPlan) -> ET.Element:
    updated = copy.deepcopy(root)
    acl_kind_map: dict[str, str] = {}
    acl_device_map: dict[str, str] = {}
    for operation in plan.router_ops:
        if operation["op"] == "set_acl":
            acl_kind_map[str(operation["acl_name"])] = str(operation["acl_kind"])
            acl_device_map[str(operation["acl_name"])] = str(operation["device"])
    for operation in plan.router_ops:
        if operation["op"] == "add_acl_rule" and operation.get("acl_name") in acl_kind_map:
            operation["acl_kind"] = acl_kind_map[str(operation["acl_name"])]
        if operation["op"] == "add_acl_rule" and operation.get("acl_name") in acl_device_map:
            operation["device"] = acl_device_map[str(operation["acl_name"])]
    for operation in plan.edit_operations:
        if operation["op"] == "prune_device":
            _prune_device(updated, str(operation["device"]))
            continue
        if operation["op"] == "remove_link":
            _remove_link(updated, str(operation["a"]["dev"]), str(operation["b"]["dev"]))
            continue
        if operation["op"] == "set_link":
            _ensure_link(
                updated,
                str(operation["a"]["dev"]),
                str(operation["a"]["port"]),
                str(operation["b"]["dev"]),
                str(operation["b"]["port"]),
                str(operation.get("media", "copper")),
            )
            continue
        device = _find_device(updated, str(operation["device"]))
        if device is None:
            continue
        if operation["op"] == "rename_device":
            _set_device_name(updated, device, str(operation["new_name"]))
        elif operation["op"] == "reflow_layout":
            _set_device_position(device, int(operation["x"]), int(operation["y"]))

    for bucket, handler in [
        (plan.switch_ops, _apply_switch_op),
        (plan.router_ops, _apply_router_op),
        (plan.server_ops, _apply_server_op),
        (plan.wireless_ops, _apply_wireless_op),
        (plan.end_device_ops, _apply_end_device_op),
        (plan.management_ops, _apply_management_op),
    ]:
        for operation in bucket:
            device = _find_device(updated, str(operation["device"]))
            if device is None:
                continue
            handler(device, operation)
    return updated


def apply_edit_operations(root: ET.Element, plan: IntentPlan) -> ET.Element:
    return apply_plan_operations(root, plan)


def edit_pkt_file(pkt_path: str | Path, plan: IntentPlan, output_path: str | Path, xml_out_path: str | Path | None = None) -> Path:
    root = decode_pkt_to_root(pkt_path)
    updated = apply_plan_operations(root, plan)
    xml_bytes = ET.tostring(updated, encoding="utf-8", xml_declaration=False)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(encode_pkt_modern(xml_bytes))
    if xml_out_path is not None:
        xml_path = Path(xml_out_path)
        xml_path.parent.mkdir(parents=True, exist_ok=True)
        xml_path.write_bytes(xml_bytes)
    return output_path
