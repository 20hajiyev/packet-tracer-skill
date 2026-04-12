from __future__ import annotations

import json
from functools import lru_cache
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

from packet_tracer_env import get_packet_tracer_saves_root
from pkt_codec import decode_pkt_modern

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_ROOT = SCRIPT_DIR.parent
DEFAULT_CATALOG_JSON = SKILL_ROOT / "references" / "packettracer-sample-catalog.json"
DEFAULT_CATALOG_MD = SKILL_ROOT / "references" / "packettracer-sample-catalog.md"

CAPABILITY_KEYWORDS = {
    "vlan": ["vlan", "trunk", "access"],
    "trunk": ["trunk"],
    "access_port": ["access"],
    "dhcp_pool": ["dhcp", "reservation", "apipa"],
    "router_dhcp": ["dhcp", "reservation", "apipa"],
    "server_dhcp": ["dhcp", "reservation", "apipa"],
    "dhcp_snooping": ["dhcp snooping", "option_82", "trusted_untrusted"],
    "ospf": ["ospf"],
    "eigrp": ["eigrp"],
    "rip": ["rip"],
    "nat": ["nat"],
    "acl": ["acl", "access-list"],
    "vpn": ["vpn", "ipsec", "gre"],
    "wireless": ["wireless", "wlan", "wlc", "wifi", "ssid", "wpa", "wep", "5g", "bluetooth", "cellular"],
    "wireless_ap": ["wireless", "wlan", "wlc", "wifi", "ssid", "wpa", "wep"],
    "wireless_client": ["wireless", "wifi", "tablet", "smartphone", "laptop"],
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

TYPE_NORMALIZATION = {
    "pc": "PC",
    "pc-pt": "PC",
    "server": "Server",
    "server-pt": "Server",
    "router": "Router",
    "switch": "Switch",
    "multilayerswitch": "Switch",
    "wirelessrouter": "WirelessRouter",
    "lightweightaccesspoint": "LightWeightAccessPoint",
    "accesspoint": "LightWeightAccessPoint",
    "pda": "Tablet",
    "tabletpc": "Tablet",
    "tablet": "Tablet",
    "laptop": "Laptop",
    "printer": "Printer",
    "smartphone": "Smartphone",
}


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
        new_item.setdefault("trust_level", "trusted")
        new_item.setdefault("origin", "cisco-local")
        new_item.setdefault("role", "primary")
        new_item.setdefault("prototype_eligible", True)
        enriched.append(new_item)
    return enriched


@lru_cache(maxsize=8)
def _load_catalog_cached(path_str: str) -> tuple[SampleDescriptor, ...]:
    raw_items = json.loads(Path(path_str).read_text(encoding="utf-8"))
    items = enrich_catalog_items(raw_items)
    saves_root = get_packet_tracer_saves_root()
    return tuple(
        SampleDescriptor(
            path=str((saves_root / item["relative_path"]) if saves_root is not None else item.get("path", item["relative_path"])),
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
        )
        for item in items
        if "error" not in item
    )


def load_catalog(path: Path | None = None) -> list[SampleDescriptor]:
    return list(_load_catalog_cached(str(path or DEFAULT_CATALOG_JSON)))


def _summarize_pkt(path: Path, relative_path: str, origin: str, prototype_eligible: bool) -> dict[str, Any]:
    xml = decode_pkt_modern(path.read_bytes())
    root = ET.fromstring(xml)
    devices = []
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
        links.append(
            {
                "type": link.findtext("./TYPE", default=""),
                "cable_type": cable.findtext("./TYPE", default="") if cable is not None else "",
                "ports": [port.text or "" for port in ports[:2]],
            }
        )
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
    }


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
                items.append(_summarize_pkt(pkt_path, rel, "external-reference", False))
            except Exception:
                continue
    enriched = enrich_catalog_items(items)
    return tuple(
        SampleDescriptor(
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
            trust_level=item.get("trust_level", "reference-only"),
            origin=item.get("origin", "external-reference"),
            role=item.get("role", "reference"),
            prototype_eligible=bool(item.get("prototype_eligible", False)),
        )
        for item in enriched
    )


def load_reference_catalog(reference_roots: list[Path] | None = None) -> list[SampleDescriptor]:
    if not reference_roots:
        return []
    roots_key = tuple(sorted(str(path) for path in reference_roots))
    return list(_load_reference_catalog_cached(roots_key))


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
