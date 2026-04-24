from __future__ import annotations

import json
from functools import lru_cache
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

from packet_tracer_env import get_packet_tracer_saves_root, get_packet_tracer_target_version
from pkt_codec import decode_pkt_modern
from workspace_repair import inspect_workspace_integrity

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_ROOT = SCRIPT_DIR.parent
DEFAULT_CATALOG_JSON = SKILL_ROOT / "references" / "packettracer-sample-catalog.json"
DEFAULT_CATALOG_MD = SKILL_ROOT / "references" / "packettracer-sample-catalog.md"
DEFAULT_CURATED_DONOR_REGISTRY = SKILL_ROOT / "references" / "curated-donor-registry.json"

CAPABILITY_KEYWORDS = {
    "vlan": ["vlan", "trunk", "access"],
    "trunk": ["trunk"],
    "access_port": ["access"],
    "dhcp_pool": ["dhcp", "reservation", "apipa"],
    "router_dhcp": ["dhcp", "reservation", "apipa"],
    "server_dhcp": ["dhcp", "reservation", "apipa"],
    "dhcpv6_stateful": ["dhcpv6", "stateful_dhcpv6"],
    "dhcpv6_stateless": ["stateless_dhcpv6"],
    "ipv6_slaac": ["slaac"],
    "ipv6_prefix_delegation": ["prefix_delegation"],
    "ipv6_dns_aaaa": ["aaaa"],
    "ipv6_tunneling": ["ipv6ip", "ipv6 tunneling"],
    "isatap": ["isatap"],
    "dhcp_snooping": ["dhcp snooping", "option_82", "trusted_untrusted"],
    "ospf": ["ospf"],
    "ospfv3": ["ospfv3", "ipv6_ospf"],
    "eigrp": ["eigrp"],
    "eigrp_ipv6": ["ipv6_eigrp"],
    "rip": ["rip"],
    "ripng": ["ripng", "ipv6 rip"],
    "hsrp": ["hsrp"],
    "nat": ["nat"],
    "acl": ["acl", "access-list"],
    "dai": ["dai", "dynamic arp inspection"],
    "dot1x": ["dot1x", "802.1x", "port-based nac"],
    "lldp": ["lldp"],
    "rep": ["rep_"],
    "snmp": ["snmp"],
    "netflow": ["netflow"],
    "span": ["span", "rspan"],
    "qos": ["qos"],
    "port_security": ["port security", "port-security"],
    "vpn": ["vpn", "ipsec", "gre"],
    "ipsec": ["ipsec", "ike"],
    "gre": ["gre"],
    "ppp": ["ppp", "chap", "pap"],
    "wan": ["wan", "cloud", "serial", "pppoe", "ppp"],
    "security_edge": ["asa", "firewall", "security appliance"],
    "asa_acl_nat": ["asa_acl_nat"],
    "asa_service_policy": ["asa_service_policy", "service policy"],
    "clientless_vpn": ["clientless_vpn"],
    "cbac": ["cbac"],
    "zfw": ["zfw", "zone based firewall"],
    "sniffer": ["sniffer"],
    "multilayer_switching": ["multilayer", "layer 3", "3560", "svi"],
    "wireless": ["wireless", "wlan", "wlc", "wifi", "ssid", "wpa", "wep", "5g", "bluetooth", "cellular"],
    "wireless_ap": ["wireless", "wlan", "wlc", "wifi", "ssid", "wpa", "wep"],
    "wireless_client": ["wireless", "wifi", "tablet", "smartphone", "laptop"],
    "wlc": ["wlc", "wireless lan controller"],
    "wpa_enterprise": ["wpa_radius", "wpa2_enterprise"],
    "wep": ["wep"],
    "guest_wifi": ["guest"],
    "beamforming": ["beamforming"],
    "meraki": ["meraki"],
    "cellular_5g": ["5g", "cellular", "cell tower"],
    "bluetooth": ["bluetooth"],
    "network_controller": ["network controller", "netcon"],
    "python_programming": ["python"],
    "javascript_programming": ["javascript"],
    "blockly_programming": ["blockly"],
    "tcp_udp_app": ["tcp_test_app", "udp_test_app"],
    "vm_iox": ["iox", "uploading_and_running_vm"],
    "voip": ["voip"],
    "ip_phone": ["ip phone", "phone"],
    "call_manager": ["call manager", "telephony", "voip"],
    "linksys_voice": ["voip linksys"],
    "mqtt": ["mqtt"],
    "real_http": ["real-http", "real http"],
    "real_websocket": ["real-websocket", "real websocket"],
    "visual_scripting": ["visual-scripting", "visual scripting"],
    "ptp": ["ptp"],
    "profinet": ["profinet"],
    "l2nat": ["l2nat"],
    "cyberobserver": ["cyberobserver"],
    "industrial_firewall": ["isa3000", "industrial cybersecurity"],
    "coaxial": ["coaxial"],
    "cable_dsl": ["cable modem", "dsl modem"],
    "central_office": ["centraloffice", "central office"],
    "cell_tower": ["cell tower"],
    "power_distribution": ["power distribution"],
    "hot_swappable": ["hotswappable", "hot swappable"],
    "ios_license": ["ios_15", "license"],
    "ntp": ["ntp"],
    "dns": ["dns"],
    "server_dns": ["dns"],
    "server_http": ["http", "https", "websocket"],
    "server_ftp": ["ftp", "tftp"],
    "ftp_http_https": ["ftp", "http", "https", "websocket"],
    "iot": ["iot", "sensor", "led", "arduino", "mqtt", "environment"],
    "switching": ["switch", "switching", "lldp", "rep"],
    "router_on_a_stick": ["router-on-a-stick", "dot1q"],
    "host_server": ["server", "pc", "client", "host"],
    "management_vlan": ["management", "vlan99", "telnet"],
    "telnet": ["telnet", "terminal server"],
    "tablet": ["tablet", "pda"],
    "printer": ["printer"],
}

REPORT_ONLY_CAPABILITIES = {
    "ipv6_slaac",
    "dhcpv6_stateful",
    "dhcpv6_stateless",
    "ipv6_prefix_delegation",
    "ipv6_dns_aaaa",
    "ipv6_tunneling",
    "isatap",
    "ospfv3",
    "eigrp_ipv6",
    "ripng",
    "hsrp",
    "dhcp_snooping",
    "dai",
    "dot1x",
    "lldp",
    "rep",
    "snmp",
    "netflow",
    "span",
    "qos",
    "port_security",
    "asa_acl_nat",
    "asa_service_policy",
    "clientless_vpn",
    "cbac",
    "zfw",
    "sniffer",
    "wlc",
    "wpa_enterprise",
    "wep",
    "guest_wifi",
    "beamforming",
    "meraki",
    "cellular_5g",
    "bluetooth",
    "network_controller",
    "python_programming",
    "javascript_programming",
    "blockly_programming",
    "tcp_udp_app",
    "vm_iox",
    "voip",
    "ip_phone",
    "call_manager",
    "linksys_voice",
    "mqtt",
    "real_http",
    "real_websocket",
    "visual_scripting",
    "ptp",
    "profinet",
    "l2nat",
    "cyberobserver",
    "industrial_firewall",
    "coaxial",
    "cable_dsl",
    "central_office",
    "cell_tower",
    "power_distribution",
    "hot_swappable",
    "ios_license",
}

TYPE_NORMALIZATION = {
    "pc": "PC",
    "pc-pt": "PC",
    "server": "Server",
    "server-pt": "Server",
    "router": "Router",
    "switch": "Switch",
    "multilayerswitch": "MultiLayerSwitch",
    "layer3switch": "MultiLayerSwitch",
    "wirelessrouter": "WirelessRouter",
    "wirelessrouternewgeneration": "WirelessRouter",
    "homegateway": "WirelessRouter",
    "wirelesslancontroller": "LightWeightAccessPoint",
    "lightweightaccesspoint": "LightWeightAccessPoint",
    "accesspoint": "LightWeightAccessPoint",
    "pda": "Tablet",
    "tabletpc": "Tablet",
    "tablet": "Tablet",
    "laptop": "Laptop",
    "printer": "Printer",
    "smartphone": "Smartphone",
    "mcucomponent": "IoT",
    "networkcontroller": "NetworkController",
    "centralofficeserver": "CentralOfficeServer",
    "celltower": "CellTower",
}

LICENSE_FILENAMES = [
    "LICENSE",
    "LICENSE.txt",
    "LICENSE.md",
    "COPYING",
    "COPYING.txt",
    "NOTICE",
]


@dataclass
class SampleDescriptor:
    path: str
    relative_path: str
    version: str
    device_count: int
    link_count: int
    devices: list[dict[str, Any]]
    links: list[dict[str, Any]]
    capability_tags: list[str]
    topology_tags: list[str]
    preferred_roles: list[str]
    trust_level: str = "trusted"
    origin: str = "cisco-local"
    role: str = "primary"
    prototype_eligible: bool = True
    license_or_permission: str = "local-cisco"
    promotion_status: str = "validated_primary"
    validation_status: str = "validated"
    packet_tracer_version: str = ""
    wireless_mode_tags: list[str] = field(default_factory=list)
    donor_eligible: bool = True
    device_families: list[str] = field(default_factory=list)
    model_families: list[str] = field(default_factory=list)
    port_media_types: list[str] = field(default_factory=list)
    service_support: list[str] = field(default_factory=list)
    iot_roles: list[str] = field(default_factory=list)
    runtime_features: list[str] = field(default_factory=list)
    donor_graph_fingerprint: dict[str, Any] = field(default_factory=dict)
    apply_safety_level: str = "reference-known"
    promotion_evidence: list[str] = field(default_factory=list)
    validated_edit_capabilities: list[str] = field(default_factory=list)
    acceptance_notes: list[str] = field(default_factory=list)
    archetype_tags: list[str] = field(default_factory=list)
    acceptance_fixtures: list[str] = field(default_factory=list)
    provenance: str = ""
    workspace_validation_status: str = ""
    evidence_source: str = "inferred"

    def normalized_device_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for device in self.devices:
            normalized = normalize_device_type(device.get("type", ""))
            if normalized:
                counts[normalized] = counts.get(normalized, 0) + 1
        return counts


@dataclass
class SampleCandidate:
    sample: SampleDescriptor
    capability_score: int
    topology_score: int
    total_score: int
    reasons: list[str]


@dataclass
class ReferencePattern:
    relative_path: str
    origin: str
    capability_tags: list[str]
    topology_tags: list[str]
    device_summary: dict[str, int]
    wireless_mode_tags: list[str] = field(default_factory=list)


@dataclass
class DonorValidationResult:
    packet_tracer_version: str
    validation_status: str
    promotion_status: str
    donor_eligible: bool
    issues: list[str]


@dataclass
class CuratedDonorRecord:
    sample: SampleDescriptor
    validation: DonorValidationResult


def _normalize_registry_key(value: str) -> str:
    return value.strip().replace("\\", "/").lower()


@lru_cache(maxsize=4)
def _load_curated_donor_registry_cached(path_str: str) -> dict[str, dict[str, Any]]:
    path = Path(path_str)
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    donors = list(payload.get("donors", [])) if isinstance(payload, dict) else []
    registry: dict[str, dict[str, Any]] = {}
    for item in donors:
        if not isinstance(item, dict):
            continue
        key = _normalize_registry_key(str(item.get("relative_path", "")))
        if not key:
            continue
        registry[key] = dict(item)
    return registry


def load_curated_donor_registry(path: Path | None = None) -> dict[str, dict[str, Any]]:
    return dict(_load_curated_donor_registry_cached(str(path or DEFAULT_CURATED_DONOR_REGISTRY)))


def normalize_device_type(raw_type: str) -> str:
    key = raw_type.strip().lower().replace(" ", "")
    return TYPE_NORMALIZATION.get(key, raw_type.strip())


def _normalized_counts_for_item(item: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for device in item.get("devices", []):
        normalized = normalize_device_type(device.get("type", ""))
        if normalized:
            counts[normalized] = counts.get(normalized, 0) + 1
    return counts


def infer_capability_tags(item: dict[str, Any]) -> list[str]:
    tags: set[str] = set()
    rel = item.get("relative_path", "").lower().replace("\\", "/")
    rel_flat = rel.replace("/", " ")
    devices = item.get("devices", [])
    raw_types = {str(device.get("type", "")).strip() for device in devices if str(device.get("type", "")).strip()}
    normalized_types = [normalize_device_type(device.get("type", "")) for device in devices]
    router_count = normalized_types.count("Router")
    switch_count = normalized_types.count("Switch")
    host_count = sum(1 for dtype in normalized_types if dtype in {"PC", "Server"})

    for tag, words in CAPABILITY_KEYWORDS.items():
        if any(word in rel or word in rel_flat for word in words):
            tags.add(tag)
    if router_count >= 2:
        tags.add("multi_router")
    if switch_count >= 1:
        tags.add("switching")
    if host_count >= 1:
        tags.add("host_server")
    if any(dtype in {"WirelessRouter", "LightWeightAccessPoint"} for dtype in normalized_types):
        tags.add("wireless")
        tags.add("wireless_ap")
    if "HomeGateway" in raw_types or any(dtype == "IoT" for dtype in normalized_types):
        tags.add("iot")
    if any(dtype in {"ASA", "Security Appliance"} for dtype in normalized_types) or raw_types & {"ASA", "Security Appliance"}:
        tags.add("security_edge")
        tags.add("acl")
    if any(dtype in {"Cloud", "Cable Modem", "Dsl Modem"} for dtype in normalized_types):
        tags.add("wan")
    if any(dtype == "MultiLayerSwitch" for dtype in normalized_types):
        tags.add("multilayer_switching")
    if any(dtype in {"Tablet", "Laptop", "Smartphone"} for dtype in normalized_types):
        tags.add("wireless_client")
    if any(dtype == "Tablet" for dtype in normalized_types):
        tags.add("tablet")
    if any(dtype == "Printer" for dtype in normalized_types):
        tags.add("printer")
    if "telnet" in rel or "terminal server" in rel_flat:
        tags.add("telnet")
    if "management" in rel_flat:
        tags.add("management_vlan")
    return sorted(tags or {"switching"})


def infer_topology_tags(item: dict[str, Any]) -> list[str]:
    tags: set[str] = set()
    rel = item.get("relative_path", "").lower().replace("\\", "/")
    counts = _normalized_counts_for_item(item)
    link_count = int(item.get("link_count", 0))
    switch_count = counts.get("Switch", 0)
    router_count = counts.get("Router", 0)
    wireless_count = counts.get("LightWeightAccessPoint", 0) + counts.get("WirelessRouter", 0)
    server_count = counts.get("Server", 0)

    if "router_on_a_stick" in item.get("capability_tags", []):
        tags.add("router_on_a_stick")
    if "acl" in item.get("capability_tags", []):
        tags.add("acl_policy")
    if wireless_count:
        tags.add("wireless_edge")
    if server_count:
        tags.add("server_services")
    if switch_count >= 3 and router_count >= 1:
        tags.add("department_lan")
    if switch_count >= 2 and router_count >= 1:
        tags.add("core_access")
    if switch_count >= 2 and link_count >= switch_count:
        tags.add("chain")
    if router_count == 1 and switch_count <= 1 and wireless_count:
        tags.add("small_office")
    if "campus" in rel or "department" in rel or "vlan" in rel:
        tags.add("department_lan")
    return sorted(tags or {"general"})


def infer_preferred_roles(item: dict[str, Any]) -> list[str]:
    roles: list[str] = []
    tags = set(item.get("capability_tags", []))
    if "vlan" in tags:
        roles.append("preferred_vlan")
    if "dhcp_pool" in tags:
        roles.append("preferred_dhcp")
    if {"ospf", "eigrp", "rip"} & tags:
        roles.append("preferred_routing")
    if {"nat", "acl", "vpn"} & tags:
        roles.append("preferred_security")
    if {"vpn", "ipsec", "gre", "ppp", "multilayer_switching"} & tags:
        roles.append("preferred_wan")
    if "wireless" in tags:
        roles.append("preferred_wireless")
    if "telnet" in tags or "management_vlan" in tags:
        roles.append("preferred_management")
    if "server_dns" in tags or "server_dhcp" in tags:
        roles.append("preferred_server")
    if "iot" in tags:
        roles.append("preferred_iot")
    if not roles:
        roles.append("preferred_general")
    return roles


def infer_wireless_mode_tags(item: dict[str, Any]) -> list[str]:
    normalized_types = [normalize_device_type(device.get("type", "")) for device in item.get("devices", [])]
    tags: set[str] = set()
    if "LightWeightAccessPoint" in normalized_types:
        tags.add("ap_bridge")
    if "WirelessRouter" in normalized_types:
        tags.add("home_router_edge")
    if len(tags) > 1:
        tags.add("mixed")
    return sorted(tags)


def infer_iot_roles(item: dict[str, Any]) -> list[str]:
    roles = {str(role).strip() for role in item.get("iot_roles", []) if str(role).strip()}
    raw_types = {str(device.get("type", "")).strip() for device in item.get("devices", []) if str(device.get("type", "")).strip()}
    normalized_types = {normalize_device_type(device.get("type", "")) for device in item.get("devices", []) if device.get("type")}
    families = set(item.get("device_families", []) or infer_device_families(item))
    has_thing = bool(raw_types & {"MCUComponent", "Board", "Sensor", "Actuator"}) or "iot devices" in families
    has_gateway = "HomeGateway" in raw_types or ("home/wireless routers" in families and has_thing)
    has_server = "Server" in normalized_types or "servers" in families
    if has_thing:
        roles.add("thing")
    if has_gateway:
        roles.add("gateway")
    if has_server:
        roles.add("server")
    return sorted(roles)


def infer_device_families(item: dict[str, Any]) -> list[str]:
    family_map = {
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
        "NetworkController": "network controllers",
        "CentralOfficeServer": "wan/cloud/dsl/cable devices",
        "CellTower": "wan/cloud/dsl/cable devices",
        "IoT": "iot devices",
        "Sensor": "iot devices",
        "Actuator": "iot devices",
        "MCUComponent": "iot devices",
    }
    families = {
        family_map.get(normalize_device_type(device.get("type", "")), "pt-specific edge/utility devices")
        for device in item.get("devices", [])
        if device.get("type")
    }
    return sorted(families)


def infer_model_families(item: dict[str, Any]) -> list[str]:
    return sorted(
        {
            str(device.get("model", "")).strip()
            for device in item.get("devices", [])
            if str(device.get("model", "")).strip()
        }
    )


def infer_port_media_types(item: dict[str, Any]) -> list[str]:
    media = {
        str(link.get("cable_type") or link.get("media") or link.get("type") or "").strip()
        for link in item.get("links", [])
        if str(link.get("cable_type") or link.get("media") or link.get("type") or "").strip()
    }
    return sorted(media)


def infer_service_support(item: dict[str, Any]) -> list[str]:
    tags = set(item.get("capability_tags", []))
    services: set[str] = set()
    service_map = {
        "server_dhcp": "dhcp",
        "dhcp_pool": "dhcp",
        "dns": "dns",
        "server_dns": "dns",
        "server_http": "http",
        "server_https": "https",
        "server_ftp": "ftp",
        "server_tftp": "tftp",
        "ntp": "ntp",
        "server_email": "email",
        "server_syslog": "syslog",
        "server_aaa": "aaa",
        "ftp_http_https": "http",
        "telnet": "telnet",
        "management_vlan": "management",
    }
    for tag in tags:
        service = service_map.get(tag)
        if service:
            services.add(service)
    return sorted(services)


def infer_runtime_features(item: dict[str, Any]) -> list[str]:
    features: set[str] = set()
    tags = set(item.get("capability_tags", []))
    families = set(item.get("device_families", []) or infer_device_families(item))
    if item.get("wireless_mode_tags"):
        features.add("wireless_runtime")
    if item.get("service_support"):
        features.add("service_runtime")
    if infer_iot_roles(item):
        features.add("iot_runtime")
    if families & {"wan/cloud/dsl/cable devices"} or tags & {"wan", "ppp"}:
        features.add("wan_runtime")
    if families & {"security devices"} or tags & {"security_edge", "acl", "nat"}:
        features.add("security_runtime")
    if tags & {"vpn", "ipsec", "gre"}:
        features.add("tunnel_runtime")
    if families & {"multilayer switches"} or tags & {"multilayer_switching"}:
        features.add("multilayer_runtime")
    if item.get("workspace_validation"):
        features.add("workspace_validated")
    if any(str(link.get("from", "")) and str(link.get("to", "")) for link in item.get("links", [])):
        features.add("named_link_graph")
    return sorted(features)


def infer_archetype_tags(item: dict[str, Any]) -> list[str]:
    tags: set[str] = set()
    topology = set(item.get("topology_tags", []))
    families = set(item.get("device_families", []))
    services = set(item.get("service_support", []))
    wireless_modes = set(item.get("wireless_mode_tags", []))
    iot_roles = set(infer_iot_roles(item))

    if topology & {"chain", "core_access", "department_lan", "router_on_a_stick"} or (
        families & {"routers", "switches", "multilayer switches"}
        and set(item.get("capability_tags", [])) & {"vlan", "router_on_a_stick", "management_vlan", "telnet"}
    ):
        tags.add("campus/core")
    if services or "servers" in families or "server_services" in topology:
        tags.add("service-heavy")
    if wireless_modes or families & {"access points", "home/wireless routers"}:
        tags.add("wireless-heavy")
    if iot_roles or "iot devices" in families or "HomeGateway" in set(item.get("model_families", [])):
        tags.add("IoT/home gateway")
    if families & {"wan/cloud/dsl/cable devices", "security devices"} or set(item.get("capability_tags", [])) & {
        "vpn",
        "ipsec",
        "gre",
        "ppp",
        "wan",
        "security_edge",
        "multilayer_switching",
        "nat",
        "acl",
    }:
        tags.add("WAN/security edge")
    capability_tags = set(item.get("capability_tags", []))
    if capability_tags & {"ipv6_slaac", "dhcpv6_stateful", "dhcpv6_stateless", "ipv6_prefix_delegation", "ipv6_dns_aaaa", "ipv6_tunneling", "isatap", "ospfv3", "eigrp_ipv6", "ripng", "hsrp"}:
        tags.add("IPv6/routing")
    if capability_tags & {"dhcp_snooping", "dai", "dot1x", "lldp", "rep", "snmp", "netflow", "span", "qos", "port_security"}:
        tags.add("L2 security/monitoring")
    if capability_tags & {"wlc", "wpa_enterprise", "wep", "guest_wifi", "beamforming", "meraki", "cellular_5g", "bluetooth"}:
        tags.add("advanced wireless")
    if capability_tags & {"network_controller", "python_programming", "javascript_programming", "blockly_programming", "tcp_udp_app", "vm_iox"} or "network controllers" in families:
        tags.add("automation/controller")
    if capability_tags & {"voip", "ip_phone", "call_manager", "linksys_voice"}:
        tags.add("voice/collaboration")
    if capability_tags & {"mqtt", "real_http", "real_websocket", "visual_scripting", "ptp", "profinet", "l2nat", "cyberobserver", "industrial_firewall"}:
        tags.add("industrial IoT")
    return sorted(tags)


def infer_donor_graph_fingerprint(item: dict[str, Any]) -> dict[str, Any]:
    pairs: list[str] = []
    media_types = infer_port_media_types(item)
    for link in item.get("links", []):
        left = str(link.get("from", "")).strip()
        right = str(link.get("to", "")).strip()
        if left and right:
            pairs.append(" <-> ".join(sorted((left, right))))
    return {
        "link_count": int(item.get("link_count", 0)),
        "named_pairs": sorted(dict.fromkeys(pairs)),
        "media_types": media_types,
    }


def infer_apply_safety_level(item: dict[str, Any]) -> str:
    if item.get("origin") == "cisco-local" and item.get("prototype_eligible", True) and str(item.get("version", "")).startswith("9."):
        return "acceptance-verified"
    if item.get("donor_eligible") and item.get("prototype_eligible", False):
        return "safe-open-generate-supported"
    if item.get("capability_tags"):
        return "config-mutation-supported"
    if item.get("devices"):
        return "inventory-supported"
    return "reference-known"


def infer_validated_edit_capabilities(item: dict[str, Any]) -> list[str]:
    capabilities: set[str] = {str(tag) for tag in item.get("capability_tags", []) if str(tag).strip()}
    inferred_iot_roles = set(infer_iot_roles(item))
    families = set(item.get("device_families", []) or infer_device_families(item))
    service_capability_map = {
        "dhcp": "server_dhcp",
        "dns": "server_dns",
        "http": "server_http",
        "https": "server_https",
        "ftp": "server_ftp",
        "tftp": "server_tftp",
        "ntp": "server_ntp",
        "email": "server_email",
        "syslog": "server_syslog",
        "aaa": "server_aaa",
    }
    for service in item.get("service_support", []):
        mapped = service_capability_map.get(str(service))
        if mapped:
            capabilities.add(mapped)
    if item.get("wireless_mode_tags"):
        capabilities.add("wireless_mutation")
    if any(device_family == "end devices" for device_family in item.get("device_families", [])):
        capabilities.add("end_device_mutation")
    if inferred_iot_roles:
        capabilities.add("iot")
        capabilities.add("iot_registration")
        if {"server", "gateway"} & inferred_iot_roles:
            capabilities.add("iot_control")
    if capabilities & {"vpn", "ipsec", "gre"}:
        capabilities.update({"vpn", "ipsec", "gre"})
    if capabilities & {"ppp", "wan"} or families & {"wan/cloud/dsl/cable devices"}:
        capabilities.add("wan")
        if "ppp" in capabilities:
            capabilities.add("ppp")
    if capabilities & {"acl", "nat", "security_edge"} or families & {"security devices"}:
        capabilities.add("security_edge")
    if "multilayer switches" in families or "multilayer_switching" in capabilities:
        capabilities.add("multilayer_switching")
    if item.get("apply_safety_level") == "inventory-supported":
        return []
    capabilities -= REPORT_ONLY_CAPABILITIES
    return sorted(capabilities)


def infer_promotion_evidence(item: dict[str, Any]) -> list[str]:
    evidence: list[str] = []
    version = str(item.get("packet_tracer_version") or item.get("version") or "").strip()
    target_version = get_packet_tracer_target_version()
    if version and version == target_version:
        evidence.append(f"version:{version}")
    validation_status = str(item.get("validation_status", "")).strip()
    if validation_status:
        evidence.append(f"validation:{validation_status}")
    promotion_status = str(item.get("promotion_status", "")).strip()
    if promotion_status:
        evidence.append(f"promotion:{promotion_status}")
    if item.get("donor_eligible"):
        evidence.append("donor_eligible")
    runtime_features = set(item.get("runtime_features", []))
    if "workspace_validated" in runtime_features:
        evidence.append("workspace_validated")
    workspace_validation_status = str(item.get("workspace_validation_status", "")).strip()
    if workspace_validation_status:
        evidence.append(f"workspace_validation:{workspace_validation_status}")
    apply_safety_level = str(item.get("apply_safety_level", "")).strip()
    if apply_safety_level:
        evidence.append(f"apply_safety:{apply_safety_level}")
    validated_edit_capabilities = list(item.get("validated_edit_capabilities", []))
    if validated_edit_capabilities:
        evidence.append(f"edit_capabilities:{len(validated_edit_capabilities)}")
    explicit_fixtures = [str(fixture) for fixture in item.get("acceptance_fixtures", []) if str(fixture).strip()]
    for fixture in explicit_fixtures:
        evidence.append(f"acceptance_fixture:{fixture}")
    archetype_to_fixture = {
        "campus/core": "campus",
        "service-heavy": "service_heavy",
        "IoT/home gateway": "home_iot",
        "WAN/security edge": "wan_security_edge",
    }
    if not explicit_fixtures and promotion_status in {"validated_primary", "validated_compat", "acceptance_verified_curated"}:
        for archetype in item.get("archetype_tags", []):
            fixture = archetype_to_fixture.get(str(archetype))
            if fixture:
                evidence.append(f"acceptance_fixture:{fixture}")
    provenance = str(item.get("provenance", "")).strip()
    if provenance:
        evidence.append(f"provenance:{provenance}")
    evidence_source = str(item.get("evidence_source", "")).strip()
    if evidence_source:
        evidence.append(f"evidence_source:{evidence_source}")
    return evidence


def infer_acceptance_notes(item: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    workspace_validation = item.get("workspace_validation", {})
    if isinstance(workspace_validation, dict):
        logical_status = str(workspace_validation.get("logical_status", "")).strip()
        physical_status = str(workspace_validation.get("physical_status", "")).strip()
        if logical_status or physical_status:
            notes.append(f"workspace logical={logical_status or 'unknown'} physical={physical_status or 'unknown'}")
    wireless_modes = [str(item) for item in item.get("wireless_mode_tags", []) if str(item).strip()]
    if wireless_modes:
        notes.append(f"wireless modes: {', '.join(wireless_modes)}")
    archetypes = [str(item) for item in item.get("archetype_tags", []) if str(item).strip()]
    if archetypes:
        notes.append(f"archetypes: {', '.join(archetypes)}")
    acceptance_fixtures = [str(item) for item in item.get("acceptance_fixtures", []) if str(item).strip()]
    if acceptance_fixtures:
        notes.append(f"acceptance fixtures: {', '.join(acceptance_fixtures)}")
    provenance = str(item.get("provenance", "")).strip()
    if provenance:
        notes.append(f"provenance: {provenance}")
    return notes


def _detect_license_or_permission(root: Path) -> str:
    for filename in LICENSE_FILENAMES:
        candidate = root / filename
        if not candidate.exists():
            continue
        try:
            text = candidate.read_text(encoding="utf-8", errors="ignore").lower()
        except Exception:
            return f"present:{candidate.name}"
        if "mit license" in text:
            return "MIT"
        if "apache license" in text and "version 2.0" in text:
            return "Apache-2.0"
        if "bsd" in text:
            return "BSD"
        if "creative commons" in text and "noncommercial" in text:
            return "CC-BY-NC"
        if "creative commons" in text:
            return "CC"
        return f"present:{candidate.name}"
    return "unknown"


def validate_external_sample_summary(item: dict[str, Any], curated: bool) -> DonorValidationResult:
    target_version = get_packet_tracer_target_version()
    packet_tracer_version = str(item.get("version", ""))
    issues: list[str] = []
    if packet_tracer_version != target_version:
        issues.append(f"version_mismatch:{packet_tracer_version or 'unknown'}")
    if int(item.get("device_count", 0)) < 2:
        issues.append("insufficient_devices")
    if int(item.get("link_count", 0)) < 1:
        issues.append("insufficient_links")
    counts = _normalized_counts_for_item(item)
    if curated and not any(counts.get(kind, 0) for kind in ("Switch", "Router")):
        issues.append("missing_network_core")
    workspace_validation = item.get("workspace_validation", {})
    if curated and isinstance(workspace_validation, dict):
        workspace_mode = str(workspace_validation.get("workspace_mode", ""))
        logical_status = str(workspace_validation.get("logical_status", ""))
        physical_status = str(workspace_validation.get("physical_status", ""))
        blocking_issues = [str(issue) for issue in workspace_validation.get("blocking_issues", []) if str(issue)]
        legacy_memaddr_only = (
            workspace_mode == "legacy_uuid_physical"
            and physical_status == "ok"
            and logical_status == "invalid"
            and bool(blocking_issues)
            and all(issue == "Link device MEM_ADDR references do not match device workspace records" for issue in blocking_issues)
        )
        if physical_status != "ok":
            issues.append("workspace_physical_invalid")
        elif logical_status != "ok" and not legacy_memaddr_only:
            issues.append("workspace_logical_invalid")
    donor_eligible = curated and not issues
    validation_status = "validated" if not issues else "blocked"
    promotion_status = "validated_curated" if donor_eligible else "reference_only"
    return DonorValidationResult(
        packet_tracer_version=packet_tracer_version,
        validation_status=validation_status,
        promotion_status=promotion_status,
        donor_eligible=donor_eligible,
        issues=issues,
    )


def _merge_curated_registry_entry(
    item: dict[str, Any],
    registry_entry: dict[str, Any] | None,
    validation: DonorValidationResult,
) -> dict[str, Any]:
    merged = dict(item)
    if not registry_entry:
        return merged
    for field in [
        "packet_tracer_version",
        "apply_safety_level",
        "archetype_tags",
        "validated_edit_capabilities",
        "acceptance_fixtures",
        "acceptance_notes",
        "provenance",
    ]:
        if field in registry_entry:
            merged[field] = registry_entry[field]
    requested_promotion = str(registry_entry.get("promotion_status", "")).strip()
    if requested_promotion and validation.donor_eligible:
        merged["promotion_status"] = requested_promotion
    if not validation.donor_eligible:
        merged["promotion_status"] = "reference_only"
        merged["donor_eligible"] = False
    if registry_entry:
        merged["evidence_source"] = "registry+inferred"
        workspace_validation_status = str(registry_entry.get("workspace_validation", "")).strip()
        if workspace_validation_status:
            merged["workspace_validation_status"] = workspace_validation_status
    return merged


def _descriptor_from_item(item: dict[str, Any]) -> SampleDescriptor:
    return SampleDescriptor(
        path=item["path"],
        relative_path=item["relative_path"],
        version=item.get("version", ""),
        device_count=item.get("device_count", 0),
        link_count=item.get("link_count", 0),
        devices=item.get("devices", []),
        links=item.get("links", []),
        capability_tags=item.get("capability_tags", []),
        topology_tags=item.get("topology_tags", []),
        preferred_roles=item.get("preferred_roles", []),
        trust_level=item.get("trust_level", "trusted"),
        origin=item.get("origin", "cisco-local"),
        role=item.get("role", "primary"),
        prototype_eligible=bool(item.get("prototype_eligible", True)),
        license_or_permission=item.get("license_or_permission", "local-cisco"),
        promotion_status=item.get("promotion_status", "validated_primary"),
        validation_status=item.get("validation_status", "validated"),
        packet_tracer_version=item.get("packet_tracer_version", item.get("version", "")),
        wireless_mode_tags=item.get("wireless_mode_tags", []),
        donor_eligible=bool(item.get("donor_eligible", item.get("prototype_eligible", True))),
        device_families=item.get("device_families", []),
        model_families=item.get("model_families", []),
        port_media_types=item.get("port_media_types", []),
        service_support=item.get("service_support", []),
        iot_roles=item.get("iot_roles", []),
        runtime_features=item.get("runtime_features", []),
        donor_graph_fingerprint=item.get("donor_graph_fingerprint", {}),
        apply_safety_level=item.get("apply_safety_level", "reference-known"),
        promotion_evidence=item.get("promotion_evidence", []),
        validated_edit_capabilities=item.get("validated_edit_capabilities", []),
        acceptance_notes=item.get("acceptance_notes", []),
        archetype_tags=item.get("archetype_tags", []),
        acceptance_fixtures=item.get("acceptance_fixtures", []),
        provenance=item.get("provenance", ""),
        workspace_validation_status=item.get("workspace_validation_status", ""),
        evidence_source=item.get("evidence_source", "inferred"),
    )


def enrich_catalog_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for item in items:
        if "error" in item:
            enriched.append(item)
            continue
        new_item = dict(item)
        new_item["capability_tags"] = infer_capability_tags(new_item)
        new_item["topology_tags"] = infer_topology_tags(new_item)
        new_item["preferred_roles"] = infer_preferred_roles(new_item)
        new_item["wireless_mode_tags"] = infer_wireless_mode_tags(new_item)
        new_item.setdefault("trust_level", "trusted")
        new_item.setdefault("origin", "cisco-local")
        new_item.setdefault("role", "primary")
        new_item.setdefault("prototype_eligible", True)
        new_item.setdefault("license_or_permission", "local-cisco")
        new_item.setdefault("promotion_status", "validated_primary")
        new_item.setdefault("validation_status", "validated")
        new_item.setdefault("packet_tracer_version", new_item.get("version", ""))
        new_item.setdefault("donor_eligible", bool(new_item.get("prototype_eligible", True)))
        new_item.setdefault("device_families", infer_device_families(new_item))
        new_item.setdefault("model_families", infer_model_families(new_item))
        new_item.setdefault("port_media_types", infer_port_media_types(new_item))
        new_item.setdefault("service_support", infer_service_support(new_item))
        new_item.setdefault("iot_roles", infer_iot_roles(new_item))
        new_item.setdefault("runtime_features", infer_runtime_features(new_item))
        new_item.setdefault("donor_graph_fingerprint", infer_donor_graph_fingerprint(new_item))
        new_item.setdefault("apply_safety_level", infer_apply_safety_level(new_item))
        new_item.setdefault("archetype_tags", infer_archetype_tags(new_item))
        new_item.setdefault("validated_edit_capabilities", infer_validated_edit_capabilities(new_item))
        new_item.setdefault("acceptance_fixtures", [])
        new_item.setdefault("provenance", "")
        new_item.setdefault("promotion_evidence", infer_promotion_evidence(new_item))
        new_item.setdefault("acceptance_notes", infer_acceptance_notes(new_item))
        new_item.setdefault("workspace_validation_status", "")
        new_item.setdefault("evidence_source", "inferred")
        enriched.append(new_item)
    return enriched


@lru_cache(maxsize=8)
def _load_catalog_cached(path_str: str) -> tuple[SampleDescriptor, ...]:
    raw_items = json.loads(Path(path_str).read_text(encoding="utf-8"))
    items = enrich_catalog_items(raw_items)
    saves_root = get_packet_tracer_saves_root()
    return tuple(
        _descriptor_from_item(
            {
                **item,
                "path": str((saves_root / item["relative_path"]) if saves_root is not None else item.get("path", item["relative_path"])),
            }
        )
        for item in items
        if "error" not in item
    )


def load_catalog(path: Path | None = None) -> list[SampleDescriptor]:
    return list(_load_catalog_cached(str(path or DEFAULT_CATALOG_JSON)))


def _summarize_pkt(path: Path, relative_path: str, origin: str, prototype_eligible: bool) -> dict[str, Any]:
    xml = decode_pkt_modern(path.read_bytes())
    root = ET.fromstring(xml)
    from pkt_editor import inventory_root

    inventory = inventory_root(root)
    workspace_result = inspect_workspace_integrity(root)
    devices = []
    indexed_devices = root.findall(".//DEVICES/DEVICE")
    index_to_name = {str(index): device.findtext("./ENGINE/NAME", default="") for index, device in enumerate(indexed_devices)}
    save_ref_to_name = {
        device.findtext("./ENGINE/SAVE_REF_ID", default=""): device.findtext("./ENGINE/NAME", default="")
        for device in indexed_devices
        if device.findtext("./ENGINE/SAVE_REF_ID", default="")
    }
    for device in root.findall(".//DEVICES/DEVICE"):
        type_node = device.find("./ENGINE/TYPE")
        devices.append(
            {
                "name": device.findtext("./ENGINE/NAME", default=""),
                "type": device.findtext("./ENGINE/TYPE", default=""),
                "model": type_node.get("model", "") if type_node is not None else "",
            }
        )
    links = []
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        ports = cable.findall("PORT") if cable is not None else []
        from_ref = cable.findtext("FROM", default="") if cable is not None else ""
        to_ref = cable.findtext("TO", default="") if cable is not None else ""
        links.append(
            {
                "from": save_ref_to_name.get(from_ref, index_to_name.get(from_ref, "")),
                "to": save_ref_to_name.get(to_ref, index_to_name.get(to_ref, "")),
                "type": link.findtext("./TYPE", default=""),
                "cable_type": cable.findtext("./TYPE", default="") if cable is not None else "",
                "media": cable.findtext("./TYPE", default="") if cable is not None else "",
                "ports": [port.text or "" for port in ports[:2]],
            }
        )
    service_aliases = {
        "dhcp_server": "dhcp",
        "dns_server": "dns",
        "http_server": "http",
        "https_server": "https",
        "ftp_server": "ftp",
        "tftp_server": "tftp",
        "ntp_server": "ntp",
        "email_server": "email",
        "syslog_server": "syslog",
        "acs_server": "aaa",
    }
    service_support = sorted(
        {
            service_aliases[service]
            for services in inventory.get("services", {}).values()
            for service in services
            if service in service_aliases
        }
    )
    iot_roles = sorted({str(entry.get("role", "")).strip() for entry in inventory.get("iot", {}).values() if str(entry.get("role", "")).strip()})
    return {
        "path": str(path),
        "relative_path": relative_path,
        "version": root.findtext("./VERSION", default=""),
        "device_count": len(devices),
        "link_count": len(links),
        "devices": devices,
        "links": links,
        "origin": origin,
        "trust_level": "reference-only" if origin != "cisco-local" else "trusted",
        "role": "reference" if origin != "cisco-local" else "primary",
        "prototype_eligible": prototype_eligible,
        "service_support": service_support,
        "iot_roles": iot_roles,
        "workspace_validation": {
            "workspace_mode": workspace_result.workspace_mode,
            "logical_status": workspace_result.logical_status,
            "physical_status": workspace_result.physical_status,
            "blocking_issue_count": len(workspace_result.blocking_issues),
            "blocking_issues": workspace_result.blocking_issues,
        },
    }


def summarize_pkt_descriptor(
    path: Path,
    relative_path: str | None = None,
    *,
    origin: str = "external-reference",
    prototype_eligible: bool = False,
    trust_level: str | None = None,
    role: str | None = None,
    license_or_permission: str | None = None,
    promotion_status: str | None = None,
    validation_status: str | None = None,
    donor_eligible: bool | None = None,
) -> SampleDescriptor:
    item = _summarize_pkt(path, relative_path or path.name, origin, prototype_eligible)
    if trust_level is not None:
        item["trust_level"] = trust_level
    if role is not None:
        item["role"] = role
    if license_or_permission is not None:
        item["license_or_permission"] = license_or_permission
    if promotion_status is not None:
        item["promotion_status"] = promotion_status
    if validation_status is not None:
        item["validation_status"] = validation_status
    if donor_eligible is not None:
        item["donor_eligible"] = donor_eligible
    enriched = enrich_catalog_items([item])[0]
    return _descriptor_from_item(enriched)


@lru_cache(maxsize=4)
def _load_reference_catalog_cached(roots_key: tuple[str, ...]) -> tuple[SampleDescriptor, ...]:
    items: list[dict[str, Any]] = []
    for root_str in roots_key:
        root = Path(root_str)
        if not root.exists():
            continue
        for pkt_path in sorted(root.rglob("*.pkt")):
            try:
                rel = str(pkt_path.relative_to(root))
                item = _summarize_pkt(pkt_path, rel, "external-reference", False)
                validation = validate_external_sample_summary(item, curated=False)
                item["license_or_permission"] = _detect_license_or_permission(root)
                item["validation_status"] = validation.validation_status
                item["promotion_status"] = validation.promotion_status
                item["donor_eligible"] = validation.donor_eligible
                items.append(item)
            except Exception:
                continue
    enriched = enrich_catalog_items(items)
    return tuple(_descriptor_from_item(item) for item in enriched)


def load_reference_catalog(reference_roots: list[Path] | None = None) -> list[SampleDescriptor]:
    if not reference_roots:
        return []
    roots_key = tuple(sorted(str(path) for path in reference_roots))
    return list(_load_reference_catalog_cached(roots_key))


@lru_cache(maxsize=4)
def _load_curated_donor_catalog_cached(roots_key: tuple[str, ...]) -> tuple[SampleDescriptor, ...]:
    items: list[dict[str, Any]] = []
    registry = load_curated_donor_registry()
    for root_str in roots_key:
        root = Path(root_str)
        if not root.exists():
            continue
        license_or_permission = _detect_license_or_permission(root)
        for pkt_path in sorted(root.rglob("*.pkt")):
            try:
                rel = str(pkt_path.relative_to(root))
                item = _summarize_pkt(pkt_path, rel, "external-curated", True)
                validation = validate_external_sample_summary(item, curated=True)
                item["trust_level"] = "curated" if validation.donor_eligible else "reference-only"
                item["role"] = "secondary" if validation.donor_eligible else "reference"
                item["prototype_eligible"] = validation.donor_eligible
                item["license_or_permission"] = license_or_permission
                item["validation_status"] = validation.validation_status
                item["promotion_status"] = validation.promotion_status
                item["packet_tracer_version"] = validation.packet_tracer_version
                item["donor_eligible"] = validation.donor_eligible
                registry_entry = registry.get(_normalize_registry_key(rel)) or registry.get(_normalize_registry_key(pkt_path.name))
                item = _merge_curated_registry_entry(item, registry_entry, validation)
                items.append(item)
            except Exception:
                continue
    enriched = enrich_catalog_items(items)
    return tuple(_descriptor_from_item(item) for item in enriched)


def load_curated_donor_catalog(donor_roots: list[Path] | None = None) -> list[SampleDescriptor]:
    if not donor_roots:
        return []
    roots_key = tuple(sorted(str(path) for path in donor_roots))
    return list(_load_curated_donor_catalog_cached(roots_key))


def extract_reference_patterns(samples: list[SampleDescriptor]) -> list[ReferencePattern]:
    patterns: list[ReferencePattern] = []
    for sample in samples:
        patterns.append(
            ReferencePattern(
                relative_path=sample.relative_path,
                origin=sample.origin,
                capability_tags=sample.capability_tags,
                topology_tags=sample.topology_tags,
                device_summary=sample.normalized_device_counts(),
                wireless_mode_tags=sample.wireless_mode_tags,
            )
        )
    return patterns


def write_catalog_outputs(items: list[dict[str, Any]], json_path: Path | None = None, md_path: Path | None = None) -> None:
    enriched = enrich_catalog_items(items)
    compact_items: list[dict[str, Any]] = []
    for item in enriched:
        saved = dict(item)
        saved.pop("path", None)
        compact_items.append(saved)
    (json_path or DEFAULT_CATALOG_JSON).write_text(json.dumps(compact_items, indent=2, ensure_ascii=False), encoding="utf-8")
    root_label = "<PACKET_TRACER_SAVES_ROOT>"
    lines = ["# Packet Tracer Installed Sample Catalog", "", f"Source root: `{root_label}`", ""]
    for item in enriched:
        if "error" in item:
            lines.append(f"- `{item['relative_path']}`")
            lines.append(f"  decode error: `{item['error']}`")
            continue
        labels = ", ".join(f"{device['name']} ({device['type']}/{device['model']})" for device in item["devices"])
        lines.append(f"- `{item['relative_path']}`")
        lines.append(f"  version: `{item['version']}`, devices: `{item['device_count']}`, links: `{item['link_count']}`")
        lines.append(f"  tags: {', '.join(item.get('capability_tags', []))}")
        lines.append(f"  topology: {', '.join(item.get('topology_tags', []))}")
        lines.append(f"  devices: {labels}")
    (md_path or DEFAULT_CATALOG_MD).write_text("\n".join(lines) + "\n", encoding="utf-8")
