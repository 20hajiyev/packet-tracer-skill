#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

from intent_parser import IntentPlan, parse_intent
from packet_tracer_env import get_packet_tracer_compatibility_donor, require_packet_tracer_exe
from pkt_builder import build_packet_tracer_xml
from pkt_codec import decode_pkt_file, decode_pkt_modern, encode_pkt_modern
from pkt_editor import apply_plan_operations, decode_pkt_to_root, edit_pkt_file, inventory_devices, inventory_links, inventory_root
from pkt_transformer import transform_from_blueprint
from sample_catalog import ReferencePattern, load_catalog, load_reference_catalog
from sample_selector import rank_reference_samples, rank_samples, select_best_sample
from workspace_repair import inspect_donor_coherence, inspect_workspace_integrity, validate_donor_coherence, validate_workspace_integrity


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
        }


STRICT_COMPATIBILITY_GAP = "Strict 9.0 generation requires PACKET_TRACER_COMPAT_DONOR to point to a local Packet Tracer 9.0 donor lab."


def _compat_donor_details() -> tuple[Path | None, str | None]:
    donor = get_packet_tracer_compatibility_donor()
    if donor is None:
        return None, None
    try:
        root = ET.fromstring(decode_pkt_modern(donor.read_bytes()))
    except Exception:
        return donor, None
    return donor, root.findtext("./VERSION")


def _apply_prompt_compatibility_requirements(plan: IntentPlan) -> IntentPlan:
    prepared = prepare_generation_plan(plan)
    if prepared.goal != "edit":
        donor, _ = _compat_donor_details()
        if donor is None and STRICT_COMPATIBILITY_GAP not in prepared.blocking_gaps:
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
            routers[0].setdefault("x", 180)
            routers[0].setdefault("y", 120)
        for index, group in enumerate(plan.department_groups):
            base_x = 320 + index * 340
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
                client.setdefault("x", base_x - 120 + column * 160)
                client.setdefault("y", 660 + row * 155)
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
    if plan.topology_requirements.get("needs_dhcp_pool"):
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
            if plan.topology_requirements.get("needs_dhcp_pool"):
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


def _sanitize_runtime_sections(root: ET.Element) -> None:
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


def _unexpected_workspace_issues(donor_root: ET.Element, generated_root: ET.Element) -> list[str]:
    donor_result = inspect_workspace_integrity(donor_root)
    generated_result = inspect_workspace_integrity(generated_root)
    donor_issue_set = set(donor_result.blocking_issues)
    return [issue for issue in generated_result.blocking_issues if issue not in donor_issue_set]


def _build_donor_prune_plan(plan: IntentPlan, blueprint: dict[str, object]) -> tuple[IntentPlan, DonorArchetypePlan]:
    compat_donor, _ = _compat_donor_details()
    if compat_donor is None:
        raise PlanningError("Prompt plan is incomplete; generation was skipped.", plan)
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
            anchor_x = 1820
        if anchor_y is None:
            anchor_y = 180
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

    for donor_group, target_group in zip(donor_groups, target_groups):
        group_kept: list[str] = []
        group_park_index = 0
        donor_switch = donor_group["switch"]
        target_switch = target_group["switch"]
        switch_x = int(target_switch.get("x", 0))
        switch_y = int(target_switch.get("y", 0))
        park_anchor_x = switch_x
        park_anchor_y = switch_y + 650
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
            for spare_offset, donor_member in enumerate(available[len(wanted) :], start=1):
                spare_name = f"{target_group['group_name']}-SPARE-{device_type.upper()}{spare_offset}"
                park_device(str(donor_member["name"]), park_anchor_x, park_anchor_y, group_park_index, spare_name)
                group_park_index += 1
        for device_type, available in donor_members_by_type.items():
            if device_type in target_members_by_type:
                continue
            for spare_offset, donor_member in enumerate(available, start=1):
                spare_name = f"{target_group['group_name']}-SPARE-{device_type.upper()}{spare_offset}"
                park_device(str(donor_member["name"]), park_anchor_x, park_anchor_y, group_park_index, spare_name)
                group_park_index += 1
        mutation_groups.append(
            {
                "donor_group": donor_group["group_name"],
                "target_group": target_group["group_name"],
                "kept_devices": group_kept,
            }
        )

    for donor_group in donor_groups[len(target_groups) :]:
        names = [str(donor_group["switch"]["name"]), *[str(member["name"]) for member in donor_group["members"]]]
        donor_switch = donor_group["switch"]
        switch_x = int(donor_switch.get("x", 0))
        switch_y = int(donor_switch.get("y", 0))
        group_park_index = 0
        for name in names:
            park_device(name, switch_x, switch_y + 650, group_park_index)
            group_park_index += 1
        mutation_groups.append({"donor_group": donor_group["group_name"], "target_group": None, "parked_devices": names})

    archetype_plan = DonorArchetypePlan(
        compat_donor=str(compat_donor),
        donor_capacity=donor_capacity,
        kept_devices=sorted(rename_map.values(), key=_name_sort_key),
        pruned_devices=sorted(dict.fromkeys(parked_devices), key=_name_sort_key),
        renamed_devices=renamed_devices,
        mutation_groups=mutation_groups,
        layout_strategy="donor_preserve_park_unused",
    )
    return adapted_plan, archetype_plan


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


def build_prompt_blueprint(plan: IntentPlan) -> tuple[dict[str, object], IntentPlan]:
    prepared = _apply_prompt_compatibility_requirements(plan)
    if prepared.blocking_gaps:
        raise PlanningError("Prompt plan is incomplete; generation was skipped.", prepared)

    devices = _seed_devices_from_plan(prepared)
    links = _synthesize_links(prepared, devices)
    prepared.links = links
    _synthesize_vlan_and_link_ops(prepared, devices, links)
    prepared.capabilities = sorted(dict.fromkeys(prepared.capabilities))
    topology_plan = _build_topology_plan(prepared, devices, links)
    config_plan = _build_config_plan(prepared)

    blueprint = {
        "name": "Generated from prompt",
        "capabilities": prepared.capabilities,
        "devices": devices,
        "links": links,
        "configs": _plan_configs(prepared, devices),
        "topology_archetype": topology_plan.topology_archetype,
        "topology_plan": asdict(topology_plan),
        "config_plan": asdict(config_plan),
        "workspace_mode": "logical_only_safe",
    }
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


def generate_from_prompt(prompt: str, output_path: Path, xml_out_path: Path | None = None, reference_roots: list[Path] | None = None) -> None:
    raw_plan = parse_intent(prompt)
    if raw_plan.goal == "edit" and raw_plan.pkt_path:
        edit_pkt_file(raw_plan.pkt_path, raw_plan, output_path, xml_out_path)
        print(f"Edited PKT file created: {output_path}")
        return

    blueprint, prepared_plan = build_prompt_blueprint(raw_plan)
    adapted_plan, donor_archetype = _build_donor_prune_plan(prepared_plan, blueprint)
    donor_root = decode_pkt_to_root(donor_archetype.compat_donor)
    root = apply_plan_operations(donor_root, adapted_plan)
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
    if reference_roots:
        references = load_reference_catalog(reference_roots)
        print(f"Loaded reference-only samples: {len(references)}")
    print(f"PKT file created: {output_path}")


def explain_plan(prompt: str, reference_roots: list[Path] | None = None) -> None:
    plan = _apply_prompt_compatibility_requirements(parse_intent(prompt))
    compat_donor, compat_donor_version = _compat_donor_details()
    result: dict[str, object] = {
        "intent_plan": plan.to_dict(),
        "compatibility_mode": "donor_prune_strict_9_0",
        "compat_donor": str(compat_donor) if compat_donor is not None else None,
        "compat_donor_version": compat_donor_version,
    }
    if not plan.blocking_gaps and plan.goal != "edit":
        blueprint, prepared = build_prompt_blueprint(plan)
        topology_plan = TopologyPlan(**blueprint.get("topology_plan", {}))
        config_plan = ConfigPlan(**blueprint.get("config_plan", {}))
        topology_tags = _topology_tags_for_plan(prepared, str(blueprint.get("topology_archetype", "general")))
        ranked = rank_samples(load_catalog(), prepared.capabilities, prepared.device_requirements, topology_tags=topology_tags, prototype_only=True)
        validation = _preflight_validation(prepared, topology_plan, config_plan)
        selected_donor = None
        donor_capacity = None
        prune_plan = None
        try:
            adapted_plan, donor_archetype = _build_donor_prune_plan(prepared, blueprint)
            selected_donor = donor_archetype.compat_donor
            donor_capacity = donor_archetype.donor_capacity
            prune_plan = asdict(donor_archetype)
            donor_root = decode_pkt_to_root(donor_archetype.compat_donor)
            candidate_root = apply_plan_operations(donor_root, adapted_plan)
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
                "blocking_issues": [*workspace_result.blocking_issues, *coherence_result.blocking_issues],
            }
        except PlanningError as exc:
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
        candidates = [
            {
                "relative_path": candidate.sample.relative_path,
                "origin": candidate.sample.origin,
                "total_score": candidate.total_score,
                "capability_score": candidate.capability_score,
                "topology_score": candidate.topology_score,
                "reasons": candidate.reasons[:8],
            }
            for candidate in ranked[:5]
        ]
        result["cisco_sample_candidates"] = candidates
        result["sample_candidates"] = candidates
    if reference_roots:
        reference_catalog = load_reference_catalog(reference_roots)
        reference_ranked = rank_reference_samples(
            reference_catalog,
            plan.capabilities,
            plan.device_requirements,
            topology_tags=_topology_tags_for_plan(plan, str(result.get("topology_plan", {}).get("topology_archetype", "general"))) if result.get("topology_plan") else None,
        )
        patterns = []
        for candidate in reference_ranked[:10]:
            pattern = ReferencePattern(
                relative_path=candidate.sample.relative_path,
                origin=candidate.sample.origin,
                capability_tags=candidate.sample.capability_tags,
                topology_tags=candidate.sample.topology_tags,
                device_summary=candidate.sample.normalized_device_counts(),
            )
            pattern_dict = asdict(pattern)
            pattern_dict["score"] = candidate.total_score
            pattern_dict["reasons"] = candidate.reasons[:8]
            patterns.append(pattern_dict)
        result["external_reference_patterns"] = patterns
        result["reference_patterns"] = patterns
    print(json.dumps(result, indent=2, ensure_ascii=False))


def inventory_pkt(pkt_path: Path) -> None:
    root = ET.fromstring(decode_pkt_modern(pkt_path.read_bytes()))
    payload = inventory_root(root)
    workspace = inspect_workspace_integrity(root)
    compat_donor, compat_donor_version = _compat_donor_details()
    payload["workspace_validation"] = {
        "workspace_mode": workspace.workspace_mode,
        "logical_status": workspace.logical_status,
        "physical_status": workspace.physical_status,
        "blocking_issues": workspace.blocking_issues,
    }
    payload["compatibility_mode"] = "strict_9_0"
    payload["compat_donor"] = str(compat_donor) if compat_donor is not None else None
    payload["compat_donor_version"] = compat_donor_version
    payload["pkt_version"] = root.findtext("./VERSION")
    if compat_donor is not None:
        donor_root = decode_pkt_to_root(compat_donor)
        coherence = inspect_donor_coherence(donor_root, root)
        payload["validation_report"] = {
            "device_metadata_status": coherence.device_metadata_status,
            "scenario_status": coherence.scenario_status,
            "physical_runtime_status": coherence.physical_runtime_status,
            "blocking_issues": coherence.blocking_issues,
        }
    payload.update(_link_schema_summary(root))
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def validate_open(pkt_path: Path) -> None:
    packet_tracer_exe = require_packet_tracer_exe()
    process = subprocess.Popen([str(packet_tracer_exe), str(pkt_path)])
    print(json.dumps({"status": "launched", "pid": process.pid, "pkt": str(pkt_path)}, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate or inspect Cisco Packet Tracer 9.0 .pkt files")
    parser.add_argument("--blueprint", help="Path to the topology blueprint JSON")
    parser.add_argument("--prompt", help="Natural language topology or edit request")
    parser.add_argument("--output", help="Path to the output .pkt file")
    parser.add_argument("--xml-out", help="Optional XML output path for generated or decoded XML")
    parser.add_argument("--decode", help="Decode an existing .pkt file")
    parser.add_argument("--inventory", help="Print device/link/service inventory for an existing .pkt file")
    parser.add_argument("--explain-plan", help="Print the parsed prompt plan as JSON")
    parser.add_argument("--validate-open", help="Launch Packet Tracer with the given .pkt file")
    parser.add_argument("--compat-donor", help="Explicit Packet Tracer 9.0 donor .pkt path for strict compatibility mode")
    parser.add_argument("--reference-root", action="append", help="Optional local folder of imported external sample .pkt files")
    args = parser.parse_args()
    if args.compat_donor:
        os.environ["PACKET_TRACER_COMPAT_DONOR"] = args.compat_donor
    reference_roots = [Path(path) for path in (args.reference_root or [])]

    if args.explain_plan:
        explain_plan(args.explain_plan, reference_roots)
        return
    if args.inventory:
        inventory_pkt(Path(args.inventory))
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

    if not args.output:
        parser.error("generation requires --output")
    if args.prompt:
        try:
            generate_from_prompt(args.prompt, Path(args.output), Path(args.xml_out) if args.xml_out else None, reference_roots)
        except PlanningError as exc:
            print(json.dumps(exc.to_dict(), indent=2, ensure_ascii=False))
            raise SystemExit(2) from exc
        return
    if not args.blueprint:
        parser.error("generation requires either --blueprint or --prompt")
    generate_from_blueprint(Path(args.blueprint), Path(args.output), Path(args.xml_out) if args.xml_out else None)


if __name__ == "__main__":
    main()
