from __future__ import annotations

import copy
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
import xml.etree.ElementTree as ET
from functools import lru_cache

from intent_parser import IntentPlan
from packet_tracer_env import resolve_sample_path
from sample_catalog import normalize_device_type
from pkt_codec import decode_pkt_auto, decode_pkt_modern, encode_pkt_modern, parse_pkt_xml, serialize_pkt_xml
from pkt_transformer import _device_type, _port_address_for_name, apply_cable_type, apply_host_ip, load_sample_root


FTP_SAMPLE = r"01 Networking\FTP\FTP.pkt"
SERVER_SAMPLE = r"01 Networking\DNS\Multilevel_DNS.pkt"
WIRELESS_SAMPLE = r"01 Networking\DHCP\dhcp_reservation.pkt"


@lru_cache(maxsize=32)
def _decoded_pkt_xml(path_key: str, size: int, mtime_ns: int) -> bytes:
    """Decoded XML for a `.pkt`, cached on the file's identity.

    Donor evaluation decodes the same donor several times per run, and decoding
    costs ~42x more than parsing the result. Only the immutable bytes are
    cached; every caller still gets a fresh tree, because callers mutate it.
    """
    xml, _container = decode_pkt_auto(Path(path_key).read_bytes())
    return xml


def decode_pkt_to_root(pkt_path: str | Path) -> ET.Element:
    path = Path(pkt_path)
    try:
        stat = path.stat()
    except OSError:
        return parse_pkt_xml(decode_pkt_auto(path.read_bytes())[0])
    return parse_pkt_xml(_decoded_pkt_xml(str(path), stat.st_size, stat.st_mtime_ns))


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
            ("FTP_SERVER", "ENABLED"),
            ("NTP_SERVER", "ENABLED"),
            ("SYSLOG_SERVER", "ENABLED"),
            ("ACS_SERVER", "ENABLED"),
        ]:
            node = engine.find(tag)
            if node is not None and node.findtext(enabled_tag, default="0") in {"1", "true", "True"}:
                enabled.append(tag.lower())
        email_server = engine.find("EMAIL_SERVER")
        if email_server is not None and any(
            email_server.findtext(tag, default="0") in {"1", "true", "True"}
            for tag in ["SMTP_ENABLED", "POP3_ENABLED"]
        ):
            enabled.append("email_server")
        if enabled:
            result[name] = enabled
    return result


def inventory_service_details(root: ET.Element) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME", default="")
        engine = device.find("./ENGINE")
        if engine is None:
            continue
        details: dict[str, object] = {}
        email_server = engine.find("EMAIL_SERVER")
        if email_server is not None:
            domain = email_server.findtext("SMTP_DOMAIN", default="")
            if domain:
                details["email_domain"] = domain
            user_count = email_server.findtext("NO_OF_USERS", default="")
            if user_count:
                details["email_user_count"] = user_count
        acs_server = engine.find("ACS_SERVER")
        if acs_server is not None:
            auth_port = acs_server.findtext("./RADIUS_SETTINGS/AUTH_PORT", default="")
            if auth_port:
                details["aaa_auth_port"] = auth_port
        if details:
            result[name] = details
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
        if engine.find("./CAPWAP_AC/WLANS/WLAN_CONFIG") is not None:
            wlan = engine.find("./CAPWAP_AC/WLANS/WLAN_CONFIG")
            result[name] = {
                "mode": "controller",
                "ssid": wlan.findtext("SSID", default="") if wlan is not None else "",
            }
        if engine.find("WIRELESS_CLIENT") is not None:
            common = engine.find("./WIRELESS_CLIENT/WIRELESS_COMMON")
            result[name] = {
                "mode": "client",
                "ssid": common.findtext("SSID", default="") if common is not None else "",
            }
    return result


def inventory_iot(root: ET.Element) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME", default="")
        engine = device.find("./ENGINE")
        if engine is None:
            continue
        raw_type = engine.findtext("TYPE", default="")
        tags = {child.tag for child in list(engine)}
        iot_role = None
        if raw_type in {"HomeGateway", "WirelessRouterNewGeneration"}:
            iot_role = "gateway"
        elif raw_type in {"IoT", "MCUComponent", "Board", "Sensor", "Actuator"}:
            iot_role = "thing"
        elif {"IOE_USER_MANAGER", "IOX_SEVICE", "IOX_VM_MANAGER"} & tags:
            iot_role = "server"
        if iot_role is None:
            continue
        result[name] = {
            "role": iot_role,
            "type": raw_type,
            "wireless_ssid": engine.findtext("./WIRELESS_CLIENT/WIRELESS_COMMON/SSID", default=""),
            "http_enabled": engine.findtext("./HTTP_SERVER/ENABLED", default="0") in {"1", "true", "True"},
            "client_mode": engine.findtext("./IOE_CLIENT/CLIENT_MODE", default=""),
            "server_address": engine.findtext("./IOE_CLIENT/SERVER_ADDRESS", default=""),
            "username": engine.findtext("./IOE_CLIENT/USERNAME", default=""),
        }
        if iot_role == "server":
            rules: list[dict[str, object]] = []
            for node in engine.findall("./IOE_USER_MANAGER/USERS/USER/IOE_RULES/IOE_RULE/JSON"):
                try:
                    payload = json.loads(node.text or "{}")
                except json.JSONDecodeError:
                    continue
                if payload.get("name"):
                    rules.append({"name": str(payload["name"]), "enabled": bool(payload.get("enabled", False))})
            if rules:
                result[name]["rules"] = rules
    return result


def _script_language(app_name: str, file_name: str, content: str) -> str:
    lowered = " ".join([app_name.lower(), file_name.lower(), content[:500].lower()])
    if file_name.lower().endswith(".py") or "python" in lowered:
        return "python"
    if file_name.lower().endswith(".js") or "javascript" in lowered:
        return "javascript"
    if file_name.lower().endswith(".visual") or "<xml" in lowered or "blockly" in lowered:
        return "visual"
    return "unknown"


def _script_feature_tags(app_name: str, file_name: str, content: str) -> list[str]:
    lowered = " ".join([app_name.lower(), file_name.lower(), content.lower()])
    tags: set[str] = set()
    if "mqtt" in lowered:
        tags.add("mqtt")
    if "realhttp" in lowered or "real http" in lowered:
        tags.add("real_http")
    if "realws" in lowered or "websocket" in lowered:
        tags.add("real_websocket")
    language = _script_language(app_name, file_name, content)
    if language == "python":
        tags.add("python_programming")
    if language == "javascript":
        tags.add("javascript_programming")
    if language == "visual":
        tags.add("blockly_programming")
    if "tcp" in lowered or "udp" in lowered:
        tags.add("tcp_udp_app")
    return sorted(tags)


def _file_text(file_node: ET.Element) -> str:
    return file_node.findtext("./FILE_CONTENT/TEXT", default="")


def inventory_programming(root: ET.Element) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        device_name = device.findtext("./ENGINE/NAME", default="")
        apps: list[dict[str, object]] = []
        for directory in device.findall(".//FILE[@class='CDirectory']"):
            app_name = directory.findtext("NAME", default="").strip()
            if not app_name:
                continue
            files: list[dict[str, object]] = []
            app_tags: set[str] = set()
            for file_node in directory.findall(".//FILE[@class='CFile']"):
                file_name = file_node.findtext("NAME", default="").strip()
                content = _file_text(file_node)
                if not file_name or not content:
                    continue
                language = _script_language(app_name, file_name, content)
                feature_tags = _script_feature_tags(app_name, file_name, content)
                app_tags.update(feature_tags)
                files.append(
                    {
                        "name": file_name,
                        "language": language,
                        "content_length": len(content),
                        "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                        "feature_tags": feature_tags,
                    }
                )
            if files:
                apps.append(
                    {
                        "app_name": app_name,
                        "file_count": len(files),
                        "feature_tags": sorted(app_tags),
                        "files": files,
                    }
                )
        if apps:
            result[device_name] = {
                "app_count": len(apps),
                "feature_tags": sorted({tag for app in apps for tag in list(app.get("feature_tags", []))}),
                "apps": apps,
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


def inventory_management(root: ET.Element) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME", default="")
        running = "\n".join(line.text or "" for line in device.findall("./ENGINE/RUNNINGCONFIG/LINE"))
        if not running:
            continue
        management_vlans = sorted(
            {
                match.group(1)
                for match in re.finditer(r"(?mi)^interface\s+Vlan(\d+)\s*$", running)
            },
            key=int,
        )
        usernames = sorted(
            {
                match.group(1)
                for match in re.finditer(r"(?mi)^username\s+(\S+)\s+(?:password|secret)\s+\S+\s*$", running)
            }
        )
        default_gateway_match = re.search(r"(?mi)^ip default-gateway\s+(\S+)\s*$", running)
        telnet_enabled = bool(re.search(r"(?mi)^\s*transport input .*telnet.*$", running))
        enable_secret_present = bool(re.search(r"(?mi)^enable secret\s+\S+\s*$", running))
        if not any([management_vlans, usernames, default_gateway_match, telnet_enabled, enable_secret_present]):
            continue
        result[name] = {
            "management_vlans": management_vlans,
            "default_gateway": default_gateway_match.group(1) if default_gateway_match else "",
            "telnet_enabled": telnet_enabled,
            "usernames": usernames,
            "enable_secret_present": enable_secret_present,
        }
    return result


def inventory_routing(root: ET.Element) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME", default="")
        running = "\n".join(line.text or "" for line in device.findall("./ENGINE/RUNNINGCONFIG/LINE"))
        if not running:
            continue
        capabilities: set[str] = set()
        if re.search(r"(?mi)^\s*ipv6\s+unicast-routing\s*$", running) or re.search(r"(?mi)^\s*ipv6\s+(?:enable|address)\b", running):
            capabilities.add("ipv6_slaac")
        if re.search(r"(?mi)^\s*ipv6\s+dhcp\s+pool\b", running) or re.search(r"(?mi)^\s*ipv6\s+dhcp\s+server\b", running):
            capabilities.add("dhcpv6_stateful")
        if re.search(r"(?mi)^\s*ipv6\s+ospf\b", running) or re.search(r"(?mi)^\s*ipv6\s+router\s+ospf\b", running):
            capabilities.add("ospfv3")
        if re.search(r"(?mi)^\s*ipv6\s+eigrp\b", running) or re.search(r"(?mi)^\s*ipv6\s+router\s+eigrp\b", running):
            capabilities.add("eigrp_ipv6")
        if re.search(r"(?mi)^\s*ipv6\s+rip\b", running):
            capabilities.add("ripng")
        if re.search(r"(?mi)^\s*standby\s+\d+\s+ipv6\b", running):
            capabilities.add("hsrp")
        if re.search(r"(?mi)^\s*interface\s+Tunnel\d+\b", running) or re.search(r"(?mi)^\s*tunnel\s+(?:source|destination|mode\s+gre)\b", running):
            capabilities.add("gre")
        if re.search(r"(?mi)^\s*encapsulation\s+ppp\b", running):
            capabilities.add("ppp")
        if re.search(r"(?mi)^\s*crypto\s+ipsec\s+transform-set\b", running) or re.search(r"(?mi)^\s*crypto\s+map\b", running):
            capabilities.add("ipsec")
        if re.search(r"(?mi)^\s*crypto\s+map\b", running):
            capabilities.add("vpn")
        if re.search(r"(?mi)^\s*ip\s+inspect\s+name\b", running):
            capabilities.add("cbac")
        if (
            re.search(r"(?mi)^zone\s+security\b", running)
            or re.search(r"(?mi)^zone-pair\s+security\b", running)
            or re.search(r"(?mi)^class-map\s+type\s+inspect\b", running)
            or re.search(r"(?mi)^policy-map\s+type\s+inspect\b", running)
        ):
            capabilities.add("zfw")
        if capabilities:
            result[name] = {"capabilities": sorted(capabilities)}
    return result


def inventory_ipv4_routing_management(root: ET.Element) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME", default="")
        running = "\n".join(line.text or "" for line in device.findall("./ENGINE/RUNNINGCONFIG/LINE"))
        if not running:
            continue
        capabilities: set[str] = set()
        if re.search(r"(?mi)^\s*router\s+ospf\s+\d+\s*$", running):
            capabilities.add("ospfv2")
        if re.search(r"(?mi)^\s*router\s+eigrp\s+\d+\s*$", running):
            capabilities.add("eigrp_ipv4")
        if re.search(r"(?mi)^\s*router\s+rip\s*$", running):
            capabilities.add("ripv2")
        if re.search(r"(?mi)^\s*ip\s+route\s+\S+\s+\S+\s+\S+", running):
            capabilities.add("static_route")
        if re.search(r"(?mi)^\s*ip\s+route\s+0\.0\.0\.0\s+0\.0\.0\.0\s+\S+", running):
            capabilities.add("default_route")
        if re.search(r"(?mi)^\s*ip\s+helper-address\s+\d+\.\d+\.\d+\.\d+\s*$", running):
            capabilities.add("dhcp_relay")
        if re.search(r"(?mi)^\s*ip\s+nat\s+inside\s+source\s+static\b", running):
            capabilities.update({"nat_static", "nat"})
        if re.search(r"(?mi)^\s*ip\s+nat\s+inside\s+source\s+(?:list|route-map)\b", running):
            capabilities.update({"nat_dynamic", "nat"})
        if re.search(r"(?mi)^\s*ip\s+nat\s+inside\s+source\s+list\s+\S+\s+interface\s+\S+\s+overload\b", running):
            capabilities.update({"pat", "nat"})
        if re.search(r"(?mi)^\s*ip\s+ssh\b", running) or re.search(r"(?mi)^\s*crypto\s+key\s+generate\s+rsa\b", running):
            capabilities.add("ssh_ios")
        if re.search(r"(?mi)^\s*ntp\s+server\s+\d+\.\d+\.\d+\.\d+\s*$", running):
            capabilities.add("ntp_ios")
        if re.search(r"(?mi)^\s*logging\s+host\s+\d+\.\d+\.\d+\.\d+\s*$", running):
            capabilities.add("syslog_ios")
        if capabilities:
            result[name] = {"capabilities": sorted(capabilities)}
    return result


def inventory_l2_security_monitoring(root: ET.Element) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME", default="")
        running = "\n".join(line.text or "" for line in device.findall("./ENGINE/RUNNINGCONFIG/LINE"))
        if not running:
            continue
        capabilities: set[str] = set()
        if re.search(r"(?mi)^\s*ip\s+dhcp\s+snooping\b", running):
            capabilities.add("dhcp_snooping")
        if re.search(r"(?mi)^\s*ip\s+arp\s+inspection\b", running):
            capabilities.add("dai")
        if re.search(r"(?mi)^\s*(?:aaa\s+new-model|radius-server\s+host|authentication\s+port-control|dot1x\b)", running):
            capabilities.add("dot1x")
        if re.search(r"(?mi)^\s*lldp\s+run\b", running):
            capabilities.add("lldp")
        if re.search(r"(?mi)^\s*rep\s+segment\b", running):
            capabilities.add("rep")
        if re.search(r"(?mi)^\s*snmp-server\b", running):
            capabilities.add("snmp")
        if re.search(r"(?mi)^\s*ip\s+flow-export\b", running) or re.search(r"(?mi)^\s*ip\s+flow\s+(?:ingress|egress)\b", running):
            capabilities.add("netflow")
        if re.search(r"(?mi)^\s*monitor\s+session\b", running):
            capabilities.add("span")
        if re.search(r"(?mi)^\s*(?:mls\s+qos|auto\s+qos|class-map|policy-map|service-policy)\b", running):
            capabilities.add("qos")
        if re.search(r"(?mi)^\s*switchport\s+port-security\b", running):
            capabilities.add("port_security")
        if capabilities:
            result[name] = {"capabilities": sorted(capabilities)}
    return result


def inventory_l2_resiliency_routing(root: ET.Element) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME", default="")
        running = "\n".join(line.text or "" for line in device.findall("./ENGINE/RUNNINGCONFIG/LINE"))
        if not running:
            continue
        capabilities: set[str] = set()
        if re.search(r"(?mi)^\s*router\s+bgp\s+\d+\s*$", running) or re.search(r"(?mi)^\s*neighbor\s+\S+\s+remote-as\s+\d+\s*$", running):
            capabilities.add("bgp")
        if re.search(r"(?mi)^\s*spanning-tree\b", running):
            capabilities.add("stp")
        if re.search(r"(?mi)^\s*spanning-tree\s+mode\s+(?:rapid-pvst|rstp)\b", running) or re.search(r"(?mi)\brapid-pvst\b", running):
            capabilities.add("rstp")
        if re.search(r"(?mi)^\s*interface\s+Port-channel\d+\b", running) or re.search(r"(?mi)^\s*channel-group\s+\d+\s+mode\b", running):
            capabilities.add("etherchannel")
        if re.search(r"(?mi)^\s*channel-group\s+\d+\s+mode\s+(?:active|passive)\b", running):
            capabilities.add("lacp")
        if re.search(r"(?mi)^\s*channel-group\s+\d+\s+mode\s+(?:desirable|auto)\b", running):
            capabilities.add("pagp")
        if re.search(r"(?mi)^\s*vtp\s+(?:domain|mode|version)\b", running):
            capabilities.add("vtp")
        if re.search(r"(?mi)^\s*switchport\s+mode\s+dynamic\s+(?:desirable|auto)\b", running) or re.search(r"(?mi)^\s*switchport\s+nonegotiate\b", running):
            capabilities.add("dtp")
        if capabilities:
            result[name] = {"capabilities": sorted(capabilities)}
    return result


def inventory_voice(root: ET.Element) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for device in root.findall(".//DEVICES/DEVICE"):
        name = device.findtext("./ENGINE/NAME", default="")
        device_type = _device_type(device)
        model = device.find("./ENGINE/TYPE").get("model", "") if device.find("./ENGINE/TYPE") is not None else ""
        running = "\n".join(line.text or "" for line in device.findall("./ENGINE/RUNNINGCONFIG/LINE"))
        capabilities: set[str] = set()
        details: dict[str, object] = {"device_type": device_type, "model": model}
        if device_type in {"IpPhone", "HomeVoip", "AnalogPhone"}:
            capabilities.add("voip")
            if device_type == "IpPhone":
                capabilities.add("ip_phone")
        if running:
            extensions = sorted(dict.fromkeys(re.findall(r"(?mi)^\s*number\s+([A-Za-z0-9*+#.-]+)\s*$", running)))
            ephones = sorted(dict.fromkeys(re.findall(r"(?mi)^ephone\s+(\d+)\s*$", running)), key=int)
            dial_peers = sorted(dict.fromkeys(re.findall(r"(?mi)^dial-peer\s+voice\s+(\d+)\b", running)), key=int)
            source_match = re.search(r"(?mi)^\s*ip\s+source-address\s+(\d+\.\d+\.\d+\.\d+)\s+port\s+(\d+)\s*$", running)
            if re.search(r"(?mi)^telephony-service\s*$", running) or extensions or ephones:
                capabilities.update({"voip", "call_manager", "ip_phone"})
            if dial_peers:
                capabilities.add("voip")
            if extensions:
                details["extensions"] = extensions
            if ephones:
                details["ephones"] = ephones
            if dial_peers:
                details["dial_peers"] = dial_peers
            if source_match:
                details["source_address"] = source_match.group(1)
                details["source_port"] = int(source_match.group(2))
        if capabilities:
            details["capabilities"] = sorted(capabilities)
            result[name] = details
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
        "service_details": inventory_service_details(root),
        "wireless": inventory_wireless(root),
        "iot": inventory_iot(root),
        "vlans": inventory_vlans(root),
        "dhcp_pools": inventory_dhcp_pools(root),
        "acl_names": inventory_acl_names(root),
        "management": inventory_management(root),
        "routing": inventory_routing(root),
        "ipv4_routing_management": inventory_ipv4_routing_management(root),
        "l2_security_monitoring": inventory_l2_security_monitoring(root),
        "l2_resiliency_routing": inventory_l2_resiliency_routing(root),
        "voice": inventory_voice(root),
        "programming": inventory_programming(root),
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


def _splice_into_config(existing: list[str], additions: list[str]) -> list[str]:
    """Place new configuration where IOS will actually read it.

    A running config ends with `end`, and everything appended after it is
    ignored. Measured live: a generated lab carried

        end
        ip dhcp pool LAN
         network 192.168.1.0 255.255.255.0
         default-router 192.168.1.1

    and its hosts sat on APIPA addresses, because the router had no pool at all.
    The file looked configured; the device was not.

    Interface settings were never affected -- those are written into a block
    that already exists, ahead of `end` -- so the fault only ever showed on
    newly added global configuration, which is why it looked intermittent.
    """
    if not additions:
        return list(existing)

    # Before `end` is not far enough. Splicing there put `ip dhcp pool LAN`
    # after `line vty 0 4 / login`, and the pool still did nothing: the parser
    # is replaying a config, and a global command arriving while it is inside a
    # `line` submode has nowhere sensible to go. Cisco's own labs put the pool
    # near the top -- line 13 of a 68-line config, with the first interface at
    # line 36 -- so that is where new configuration belongs.
    for index, line in enumerate(existing):
        if line.startswith("interface "):
            return [*existing[:index], *additions, *existing[index:]]
    for index in range(len(existing) - 1, -1, -1):
        if existing[index].strip() == "end":
            return [*existing[:index], *additions, *existing[index:]]
    return [*existing, *additions]


# Globals a device can only have one of. Everything else at the top level --
# `ip route`, `access-list`, `network`, `snmp-server host` -- legitimately
# repeats, so replacement has to be by name rather than a blanket rule.
_SINGLETON_GLOBALS = (
    "hostname",
    "ip domain-name",
    "ip domain name",
    "enable secret",
    "enable password",
    "banner motd",
)


def _singleton_global_prefix(line: str) -> str:
    text = line.strip()
    for prefix in sorted(_SINGLETON_GLOBALS, key=len, reverse=True):
        if text.startswith(prefix + " "):
            return prefix
    return ""


def _append_unique_config_lines(parent: ET.Element | None, lines: list[str]) -> None:
    if parent is None:
        return
    existing = [line.text or "" for line in parent.findall("./LINE")]

    # A device can only have one hostname, so a new one has to replace the old
    # rather than sit beside it. `cli R1: hostname CORE-R1` used to leave both
    # `hostname Router` and `hostname CORE-R1` in the running config: IOS
    # applies the last, so it worked, and the configuration still contradicted
    # itself. Only the settings that genuinely cannot repeat are replaced.
    replaced: set[int] = set()
    for line in lines:
        prefix = _singleton_global_prefix(line)
        if not prefix:
            continue
        for index, current in enumerate(existing):
            if index in replaced or current.startswith(" ") or current.startswith("\t"):
                continue
            if _singleton_global_prefix(current) == prefix:
                existing[index] = line
                replaced.add(index)
                break

    additions = [line for line in lines if line not in existing]
    _replace_lines(parent, _splice_into_config(existing, additions))


# Settings whose value is a word rather than a number, so stripping numeric
# tails cannot find where the name ends. `switchport mode access` and
# `switchport mode trunk` are the same setting and must replace each other.
_WORD_VALUED_SETTINGS = (
    "switchport port-security violation",
    "switchport mode",
    "duplex",
    "speed",
)


def _setting_name(line: str) -> str:
    """The part of a config line that identifies *which* setting it is.

    Two lines share a name when one should overwrite the other. Most IOS
    settings end in their value, so dropping the trailing tokens that carry
    digits separates `switchport trunk allowed vlan 10,99` from
    `switchport trunk native vlan 99` -- which a first attempt, keying on the
    first two words alone, silently merged into one.
    """
    text = line.strip()
    if text.startswith("no "):
        text = text[3:]
    for prefix in sorted(_WORD_VALUED_SETTINGS, key=len, reverse=True):
        if text == prefix or text.startswith(prefix + " "):
            return prefix
    tokens = text.split()
    while tokens and any(character.isdigit() for character in tokens[-1]):
        tokens.pop()
    return " ".join(tokens) or text


def _set_config_block(parent: ET.Element | None, header: str, body: list[str]) -> None:
    """Write settings into an interface's existing block instead of beside it.

    `_append_config_block` skips only when the whole block already matches, so
    re-stating one setting with a different value leaves both copies:

        interface FastEthernet0/1
         switchport access vlan 11     <- donor's
        ...
        interface FastEthernet0/1
         switchport access vlan 20     <- ours

    A lab generated that way opened fine and looked configured, but hosts could
    not reach each other. Each body line replaces the line in the block that
    shares its first two words, so a re-stated setting overwrites rather than
    accumulates.
    """
    if parent is None:
        return
    lines = [line.text or "" for line in parent.findall("./LINE")]
    try:
        start = lines.index(header)
    except ValueError:
        _append_config_block(parent, header, body)
        return

    end = start + 1
    while end < len(lines) and lines[end].startswith(" "):
        end += 1
    block = lines[start + 1 : end]

    for line in body:
        name = _setting_name(line)
        for index, existing in enumerate(block):
            if _setting_name(existing) == name:
                block[index] = line
                break
        else:
            block.append(line)

    _replace_lines(parent, [*lines[:start], header, *block, *lines[end:]])


def _append_config_block(parent: ET.Element | None, header: str, body: list[str]) -> None:
    if parent is None:
        return
    existing = [line.text or "" for line in parent.findall("./LINE")]
    block = [header, *body]
    for index in range(0, max(len(existing) - len(block) + 1, 0)):
        if existing[index : index + len(block)] == block:
            return
    _replace_lines(parent, _splice_into_config(existing, block))


def apply_cli_lines(device: ET.Element, lines: list[str]) -> None:
    """Merge verbatim IOS configuration into a device that already has some.

    `apply_router_config` replaces a device's whole configuration, which is what
    the blueprint path wants and exactly wrong for "also run these commands".
    This merges instead, and puts each piece where the parser will read it:
    interface bodies go into the block for that interface, and everything else
    is spliced ahead of the first interface, where Cisco's own labs keep global
    configuration. Appending to the end would put it after `end`, where it is
    ignored.

    Indentation is normalised, since a user typing commands rarely reproduces
    the single leading space a saved config uses.
    """
    # Any unindented line can open a block, not just `interface`. Treating only
    # interfaces as headers flattened `ip dhcp pool OFFICE` and its two indented
    # lines into three globals, and a pool whose body is not indented under it
    # is not a pool.
    units: list[tuple[str, list[str]]] = []
    for raw in lines:
        text = str(raw).rstrip()
        if not text.strip():
            continue
        stripped = text.strip()
        if text.startswith((" ", "	")) and units:
            units[-1][1].append(f" {stripped}")
            continue
        units.append((stripped, []))

    for target in _config_targets(device):
        for header, body in units:
            if header.startswith("interface "):
                # Merge into the block the device already has, so a description
                # added here does not displace the address already on it.
                _set_config_block(target, header, body)
            else:
                _append_unique_config_lines(target, [header, *body])


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


def _link_port_mem_map(root: ET.Element) -> dict[tuple[str, str], str]:
    mapping: dict[tuple[str, str], str] = {}
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        ports = cable.findall("PORT")
        if len(ports) < 2:
            continue
        from_ref = cable.findtext("FROM", default="")
        to_ref = cable.findtext("TO", default="")
        from_port = ports[0].text or ""
        to_port = ports[1].text or ""
        from_mem = cable.findtext("FROM_PORT_MEM_ADDR", default="").strip()
        to_mem = cable.findtext("TO_PORT_MEM_ADDR", default="").strip()
        if from_ref and from_port and from_mem:
            mapping[(from_ref, from_port)] = from_mem
        if to_ref and to_port and to_mem:
            mapping[(to_ref, to_port)] = to_mem
    return mapping


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


@lru_cache(maxsize=1)
def _modern_link_prototype_xml() -> str | None:
    """A cable copied from a lab the installed Packet Tracer wrote itself.

    A new link is cloned from one the file already has. When the file has none,
    the fallback was a cable from the bundled `FTP.pkt`, and that sample is old
    enough to predate the fields a 9.x cable carries: it refers to its devices
    by index rather than by `save-ref-id`, and has no `FUNCTIONAL`,
    `GEO_VIEW_COLOR` or `IS_MANAGED_IN_RACK_VIEW` at all.

    Measured: adding one link to `minimal`, which has cables to copy, takes it
    from four links to five and it opens. Adding one link to `wireless_home`,
    which has none, produces a file Packet Tracer refuses -- and that is why
    both wireless labs ship uncabled. Same writer, same ports, same devices;
    the only difference is which cable was cloned.

    The compatibility donor is the right source because it is already the file
    this skill trusts for the installed version, so its cables are the shape
    this Packet Tracer writes.
    """
    from packet_tracer_env import get_packet_tracer_compatibility_donor

    donor = get_packet_tracer_compatibility_donor()
    if donor is None:
        return None
    try:
        root = decode_pkt_to_root(donor)
    except Exception:  # pragma: no cover - a donor that no longer decodes
        return None
    prototype = _first_link_prototype(root)
    if prototype is None:
        return None
    return ET.tostring(prototype, encoding="unicode")


def _fallback_link_prototype() -> ET.Element | None:
    xml = _modern_link_prototype_xml()
    if xml is not None:
        return ET.fromstring(xml)
    prototype_root = load_sample_root(resolve_sample_path(FTP_SAMPLE))
    return prototype_root.find(".//LINKS/LINK")


def _first_link_prototype(root: ET.Element) -> ET.Element | None:
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        if cable.find("FUNCTIONAL") is not None and cable.find("GEO_VIEW_COLOR") is not None and cable.find("IS_MANAGED_IN_RACK_VIEW") is not None:
            return link
    return root.find(".//LINKS/LINK")


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


def _node_contains_tokens(node: ET.Element, tokens: list[str]) -> bool:
    if any(token and token in ((node.text or "").strip()) for token in tokens):
        return True
    for value in node.attrib.values():
        if any(token and token in value for token in tokens):
            return True
    for child in list(node):
        if _node_contains_tokens(child, tokens):
            return True
    return False


def _remove_runtime_references(root: ET.Element, device: ET.Element) -> None:
    tokens = [
        device.findtext("./ENGINE/SAVE_REF_ID", default="").strip(),
        device.findtext("./ENGINE/NAME", default="").strip(),
        device.findtext("./ENGINE/ORIGINAL_DEVICE_UUID", default="").strip(),
    ]
    physical_path = device.findtext("./WORKSPACE/PHYSICAL", default="").strip()
    if physical_path:
        tokens.append(physical_path.split(",")[-1].strip())
    tokens = [token for token in tokens if token]
    if not tokens:
        return
    protected_tags = {"SCENARIOSET", "SCENARIO", "COMMAND_LOGS", "CEPS"}
    for section_path in ["./SCENARIOSET", "./COMMAND_LOGS", "./CEPS"]:
        section = root.find(section_path)
        if section is None:
            continue
        stack = [section]
        while stack:
            parent = stack.pop()
            for child in list(parent):
                if child.tag in protected_tags:
                    stack.append(child)
                    continue
                if _node_contains_tokens(child, tokens):
                    parent.remove(child)
                    continue
                stack.append(child)


DUPLICABLE_DEVICE_TYPES = {"Router", "Switch", "MultiLayerSwitch"}


def _align_hostname_with_name(device: ET.Element, name: str) -> None:
    """Make the device's CLI prompt say what the topology calls it.

    The rename used to match on the old *device* name, which never fired: a
    donor switch called `Multilayer Switch0` carries `hostname Switch`, so the
    two never agreed and the line was left behind. Measured across the corpus,
    84 of 90 configured devices answered to a hostname that was not their name,
    and in a two-switch lab both prompts read `Switch`.

    A clone needs this as much as a rename does -- it is a deep copy, so it
    arrives announcing itself as its prototype. `R2` called itself `R1` and
    `SW3` called itself `SW1` until this ran for them too.

    A hostname the user asked for still wins, because `apply_cli_lines` runs
    after both and replaces the line it finds. Names with whitespace --
    `Patch Panel1`, `Power Distribution Device0` -- are not valid IOS hostnames,
    and those devices carry no configuration anyway.
    """
    if not name or any(character.isspace() for character in name):
        return
    for path in (
        "./ENGINE/RUNNINGCONFIG/LINE",
        "./ENGINE/STARTUPCONFIG/LINE",
        ".//FILE_CONTENT/CONFIG/LINE",
    ):
        for line in device.findall(path):
            if (line.text or "").startswith("hostname "):
                line.text = f"hostname {name}"
                break


def _duplicate_device(root: ET.Element, source_name: str, new_name: str, x: int, y: int) -> None:
    """Copy an infrastructure device, giving the copy a fresh identity.

    Donor-prune can only reuse what the donor contains, so a four-switch request
    against a three-switch donor was impossible. Duplicating a switch removes
    that cap. Verified against a real Packet Tracer open: a duplicated switch
    with a fresh `SAVE_REF_ID`, `MEM_ADDR`, name and position, joined by a
    created switch-to-switch link, opens.

    Restricted to infrastructure devices on purpose. Hosts cannot take a created
    connection (see `_link_may_be_created`), so a duplicated host would have
    nothing valid to attach to.
    """
    source = _find_device(root, source_name)
    if source is None or _find_device(root, new_name) is not None:
        return
    device_type = normalize_device_type(source.findtext("./ENGINE/TYPE", default=""))
    if device_type not in DUPLICABLE_DEVICE_TYPES:
        return

    devices_parent = _find_parent_of_node(root, source)
    if devices_parent is None:
        return

    used_refs = {
        device.findtext("./ENGINE/SAVE_REF_ID", default="")
        for device in root.findall(".//DEVICES/DEVICE")
    }
    used_mems: list[int] = []
    for device in root.findall(".//DEVICES/DEVICE"):
        logical = device.find("./WORKSPACE/LOGICAL")
        if logical is None:
            continue
        try:
            used_mems.append(int(logical.findtext("MEM_ADDR", default="0") or 0))
        except ValueError:
            continue

    duplicate = copy.deepcopy(source)
    name_node = duplicate.find("./ENGINE/NAME")
    if name_node is not None:
        name_node.text = new_name
    _align_hostname_with_name(duplicate, new_name)

    ref_node = duplicate.find("./ENGINE/SAVE_REF_ID")
    if ref_node is not None:
        candidate = f"save-ref-id:{_stable_ref_seed(new_name)}"
        while candidate in used_refs:
            candidate = f"save-ref-id:{_stable_ref_seed(new_name + candidate)}"
        ref_node.text = candidate

    logical = duplicate.find("./WORKSPACE/LOGICAL")
    if logical is not None:
        mem_node = logical.find("MEM_ADDR")
        if mem_node is not None and used_mems:
            mem_node.text = str(max(used_mems) + 4096)
        for tag, value in (("X", x), ("Y", y)):
            node = logical.find(tag)
            if node is not None:
                node.text = str(value)

    devices_parent.append(duplicate)
    _clone_physical_leaf(root, source, duplicate, new_name)


def _fresh_guid(seed_text: str, taken: set[str]) -> str:
    """A deterministic, correctly shaped `{8-4-4-4-12}` GUID not already in use."""
    attempt = 0
    while True:
        digest = hashlib.sha256(f"{seed_text}:{attempt}".encode("utf-8")).hexdigest()
        # Shape it as a RFC 4122 version-4 GUID: the donor's identifiers all
        # carry the `4` version nibble and an `8`-`b` variant nibble, so a
        # hash-shaped id with arbitrary nibbles is not the same kind of value.
        variant = "89ab"[int(digest[16], 16) % 4]
        candidate = (
            "{" + digest[0:8] + "-" + digest[8:12] + "-4" + digest[13:16]
            + "-" + variant + digest[17:20] + "-" + digest[20:32] + "}"
        )
        if candidate not in taken:
            return candidate
        attempt += 1


def _clone_physical_leaf(root: ET.Element, source: ET.Element, duplicate: ET.Element, new_name: str) -> None:
    """Give a duplicated device its own node in the physical workspace.

    A device lives twice: in `DEVICES` and as a leaf in `PHYSICALWORKSPACE`,
    joined by the UUID path in `WORKSPACE/PHYSICAL`. Copying only the logical
    half left the clone pointing at the original's leaf, and workspace
    validation then reported "Generated device SW1 physical leaf name is SW4".
    """
    physical_path = source.findtext("./WORKSPACE/PHYSICAL", default="")
    tokens = [token.strip() for token in physical_path.split(",") if token.strip()]
    if not tokens:
        return
    leaf_token = tokens[-1]

    for node in root.findall(".//PHYSICALWORKSPACE//NODE"):
        if node.findtext("UUID_STR", default="").strip() != leaf_token:
            continue
        parent = _find_parent_of_node(root, node)
        if parent is None:
            return
        clone_node = copy.deepcopy(node)
        # Every UUID inside the copied subtree must be fresh, and must keep the
        # braced `{8-4-4-4-12}` shape Packet Tracer writes. A bare hex id, or a
        # nested UUID reused from the original, makes Packet Tracer refuse the
        # file with "File contains corrupted Physical Workspace data".
        #
        # The identifier must also not merely extend the original's: workspace
        # validation matches by substring, so `<original>-1234` made a pruned
        # device look like it was still present.
        taken = {
            existing.findtext("UUID_STR", default="").strip()
            for existing in root.findall(".//PHYSICALWORKSPACE//NODE")
        }
        new_uuid = ""
        for nested in clone_node.iter("UUID_STR"):
            replacement = _fresh_guid(new_name + (nested.text or ""), taken)
            taken.add(replacement)
            nested.text = replacement
            if not new_uuid:
                new_uuid = replacement
        if not new_uuid:
            return
        name_node = clone_node.find("NAME")
        if name_node is not None:
            name_node.text = new_name
        parent.append(clone_node)

        physical_node = duplicate.find("./WORKSPACE/PHYSICAL")
        if physical_node is not None:
            # Packet Tracer writes this list with no space after the comma.
            # A space made the leaf token parse as " {uuid}" and the file was
            # rejected with "File contains corrupted Physical Workspace data".
            physical_node.text = ",".join([*tokens[:-1], new_uuid])
        return


def _duplicate_group(
    root: ET.Element,
    switch_name: str,
    new_switch_name: str,
    host_names: list[str],
    x: int,
    y: int,
    new_host_names: list[str] | None = None,
) -> None:
    """Copy a switch together with its hosts and the links between them.

    Duplicating the switch alone leaves a group with no hosts, so a request for
    more switches than the donor has still failed on host capacity. Copying the
    whole working unit — switch, its hosts, and the donor links joining them —
    was verified to open in Packet Tracer.

    The distinction that matters: replicating an arrangement the donor already
    has is safe, while *moving* a host onto a different switch is not, because
    that needs a created host connection Packet Tracer rejects.
    """
    source = _find_device(root, switch_name)
    if source is None or _find_device(root, new_switch_name) is not None:
        return

    _duplicate_device(root, switch_name, new_switch_name, x, y)
    clone = _find_device(root, new_switch_name)
    if clone is None:
        return

    source_ref = source.findtext("./ENGINE/SAVE_REF_ID", default="")
    clone_ref = clone.findtext("./ENGINE/SAVE_REF_ID", default="")
    links_parent = root.find(".//LINKS")
    if links_parent is None:
        return

    for offset, host_name in enumerate(host_names):
        host = _find_device(root, host_name)
        if host is None:
            continue
        # Do not embed the source host's name: workspace validation matches by
        # substring, so `SW-COPY1-Admin` read as the pruned `Admin` still present.
        if new_host_names and offset < len(new_host_names):
            new_host_name = new_host_names[offset]
        else:
            new_host_name = f"{new_switch_name}-H{offset + 1}"
        _duplicate_host_for_group(root, host_name, new_host_name, x + offset * 90, y + 140)
        new_host = _find_device(root, new_host_name)
        if new_host is None:
            continue
        template = _find_link_between_refs(root, source_ref, host.findtext("./ENGINE/SAVE_REF_ID", default=""))
        if template is None:
            continue
        duplicate_link = copy.deepcopy(template)
        cable = duplicate_link.find("./CABLE")
        if cable is None:
            continue
        host_ref = new_host.findtext("./ENGINE/SAVE_REF_ID", default="")
        if cable.findtext("FROM", default="") == source_ref:
            cable.find("FROM").text = clone_ref
            cable.find("TO").text = host_ref
        else:
            cable.find("FROM").text = host_ref
            cable.find("TO").text = clone_ref
        links_parent.append(duplicate_link)


def _duplicate_host_for_group(root: ET.Element, source_name: str, new_name: str, x: int, y: int) -> None:
    """Clone a host device. Only valid as part of `_duplicate_group`."""
    source = _find_device(root, source_name)
    if source is None or _find_device(root, new_name) is not None:
        return
    devices_parent = _find_parent_of_node(root, source)
    if devices_parent is None:
        return

    used_refs = {d.findtext("./ENGINE/SAVE_REF_ID", default="") for d in root.findall(".//DEVICES/DEVICE")}
    mems: list[int] = []
    for device in root.findall(".//DEVICES/DEVICE"):
        logical = device.find("./WORKSPACE/LOGICAL")
        if logical is None:
            continue
        try:
            mems.append(int(logical.findtext("MEM_ADDR", default="0") or 0))
        except ValueError:
            continue

    duplicate = copy.deepcopy(source)
    duplicate.find("./ENGINE/NAME").text = new_name
    _align_hostname_with_name(duplicate, new_name)
    ref_node = duplicate.find("./ENGINE/SAVE_REF_ID")
    if ref_node is not None:
        candidate = f"save-ref-id:{_stable_ref_seed(new_name)}"
        while candidate in used_refs:
            candidate = f"save-ref-id:{_stable_ref_seed(new_name + candidate)}"
        ref_node.text = candidate
    logical = duplicate.find("./WORKSPACE/LOGICAL")
    if logical is not None:
        mem_node = logical.find("MEM_ADDR")
        if mem_node is not None and mems:
            mem_node.text = str(max(mems) + 4096)
        for tag, value in (("X", x), ("Y", y)):
            node = logical.find(tag)
            if node is not None:
                node.text = str(value)
    devices_parent.append(duplicate)
    _clone_physical_leaf(root, source, duplicate, new_name)


def _duplicate_host_onto_switch(
    root: ET.Element,
    source_name: str,
    new_name: str,
    switch_name: str,
    switch_port: str,
    host_port: str,
    x: int,
    y: int,
) -> None:
    """Clone a host and attach the copy to a switch.

    A target switch cannot carry more hosts than its donor group has, because
    donor-prune only reuses what the donor contains. Cloning a host and linking
    the copy lifts that: the link is new, which is fine now that `_ensure_link`
    no longer writes invented MEM_ADDR values into new links.
    """
    _duplicate_host_for_group(root, source_name, new_name, x, y)
    if _find_device(root, new_name) is None:
        return
    if not switch_name:
        return  # standalone clone: the topology's own link pass attaches it
    _ensure_link(root, switch_name, switch_port, new_name, host_port, "straight-through")


def _find_link_between_refs(root: ET.Element, left_ref: str, right_ref: str) -> ET.Element | None:
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        ends = {cable.findtext("FROM", default=""), cable.findtext("TO", default="")}
        if ends == {left_ref, right_ref}:
            return link
    return None


def _stable_ref_seed(text: str) -> int:
    """A deterministic 63-bit id, so the same plan yields the same file."""
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") >> 1


def _renumber_index_links_after_removal(root: ET.Element, removed_index: int) -> None:
    """Shift positional link endpoints down past a device that just went.

    Not every donor gives its devices a `SAVE_REF_ID`. Where they do not, links
    address their endpoints by position in the DEVICES list, and removing a
    device silently re-points every cable that referred to a later one.

    Measured on `1 router 1 switch 2 komputer 2 ip phone 1 home voip`: the
    generated lab carried a cable from the switch to the Power Distribution
    Device, which has no ports at all. The link had meant PC1. Packet Tracer
    refused the file, and the structural check saw nothing wrong -- every index
    was still inside the list, just pointing one device to the left.
    """
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        for tag in ("FROM", "TO"):
            node = cable.find(tag)
            if node is None or not (node.text or "").strip().isdigit():
                continue
            index = int(node.text.strip())
            if index > removed_index:
                node.text = str(index - 1)


def _prune_device(root: ET.Element, device_name: str) -> None:
    device = _find_device(root, device_name)
    if device is None:
        return
    devices = root.findall(".//DEVICES/DEVICE")
    try:
        removed_index = devices.index(device)
    except ValueError:  # pragma: no cover - the device came from this list
        removed_index = -1
    _remove_links_for_device(root, device_name)
    _remove_physical_leaf(root, device)
    _remove_runtime_references(root, device)
    parent = _find_parent_of_node(root, device)
    if parent is not None:
        parent.remove(device)
    if removed_index >= 0:
        _renumber_index_links_after_removal(root, removed_index)


def _remove_link(root: ET.Element, left_name: str, right_name: str) -> None:
    links_parent = root.find(".//LINKS")
    if links_parent is None:
        return
    link = _find_link_by_devices(root, left_name, right_name)
    if link is not None:
        links_parent.remove(link)


def _ensure_link(
    root: ET.Element,
    left_name: str,
    left_port: str,
    right_name: str,
    right_port: str,
    media: str,
    port_mem_map: dict[tuple[str, str], str] | None = None,
) -> None:
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
            prototype = _first_link_prototype(root)
        if prototype is None:
            prototype = _fallback_link_prototype()
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
    from_ref = save_refs.get(left_name, index_refs[left_name])
    to_ref = save_refs.get(right_name, index_refs[right_name])
    _ensure_text(cable, "FROM", from_ref)
    _ensure_text(cable, "TO", to_ref)
    ports = cable.findall("PORT")
    if len(ports) < 2:
        while len(ports) < 2:
            ports.append(ET.SubElement(cable, "PORT"))
    ports[0].text = left_port
    ports[1].text = right_port
    # These four are runtime pointers from the session that saved the file, not
    # references into it: in working donors they match no device. Writing
    # invented values into a *new* link is what made Packet Tracer reject the
    # result — verified by building the same link with the fields omitted, which
    # opens. On an existing link they are left exactly as the donor wrote them.
    if existing is None:
        for node_name in (
            "FROM_DEVICE_MEM_ADDR",
            "TO_DEVICE_MEM_ADDR",
            "FROM_PORT_MEM_ADDR",
            "TO_PORT_MEM_ADDR",
        ):
            stale = cable.find(node_name)
            if stale is not None:
                cable.remove(stale)
    else:
        resolved_port_mem_map = port_mem_map or {}
        for node_name, value in [
            ("FROM_DEVICE_MEM_ADDR", left_device.findtext("./WORKSPACE/LOGICAL/MEM_ADDR", default="")),
            ("TO_DEVICE_MEM_ADDR", right_device.findtext("./WORKSPACE/LOGICAL/MEM_ADDR", default="")),
            (
                "FROM_PORT_MEM_ADDR",
                _port_address_for_name(left_device, left_port)
                or resolved_port_mem_map.get((from_ref, left_port), ""),
            ),
            (
                "TO_PORT_MEM_ADDR",
                _port_address_for_name(right_device, right_port)
                or resolved_port_mem_map.get((to_ref, right_port), ""),
            ),
        ]:
            if value:
                _ensure_text(cable, node_name, value)
    _ensure_text(cable, "FUNCTIONAL", cable.findtext("FUNCTIONAL", default="true") or "true")
    _ensure_text(cable, "GEO_VIEW_COLOR", cable.findtext("GEO_VIEW_COLOR", default="#6ba72e") or "#6ba72e")
    _ensure_text(
        cable,
        "IS_MANAGED_IN_RACK_VIEW",
        cable.findtext("IS_MANAGED_IN_RACK_VIEW", default="false") or "false",
    )
    apply_cable_type(cable, media, link)


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

    _align_hostname_with_name(device, new_name)

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
        if node is None:
            continue
        # A donor can ship a device with an empty startup config. Writing into
        # it turned the router's saved configuration into three lines -- just
        # the DHCP pool that had been added -- so a reload would have wiped
        # every interface. An empty startup config is the donor's state; a stub
        # is worse than either leaving it alone or copying the whole running
        # config, so leave it alone.
        if path.endswith("STARTUPCONFIG") and not node.findall("./LINE"):
            continue
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
            _set_config_block(
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
            _set_config_block(target, f"interface {operation['port']}", body)
        return
    elif operation["op"] == "set_dhcp_snooping":
        for target in _config_targets(device):
            _append_unique_config_lines(target, ["ip dhcp snooping", f"ip dhcp snooping vlan {operation['vlan']}"])
            if operation.get("trust_port"):
                _append_config_block(target, f"interface {operation['trust_port']}", [" ip dhcp snooping trust"])
        return
    elif operation["op"] == "set_dai":
        for target in _config_targets(device):
            _append_unique_config_lines(target, ["ip dhcp snooping", f"ip dhcp snooping vlan {operation['vlan']}", f"ip arp inspection vlan {operation['vlan']}"])
            if operation.get("trust_port"):
                _append_config_block(target, f"interface {operation['trust_port']}", [" ip arp inspection trust", " ip dhcp snooping trust"])
        return
    elif operation["op"] == "set_port_security":
        body = [" switchport mode access", " switchport port-security"]
        if operation.get("maximum"):
            body.append(f" switchport port-security maximum {operation['maximum']}")
        if operation.get("violation"):
            body.append(f" switchport port-security violation {operation['violation']}")
        for target in _config_targets(device):
            _append_config_block(target, f"interface {operation['port']}", body)
        return
    elif operation["op"] == "set_lldp":
        for target in _config_targets(device):
            _append_unique_config_lines(target, ["lldp run"])
        return
    elif operation["op"] == "set_rep":
        for target in _config_targets(device):
            _append_config_block(target, f"interface {operation['interface']}", [f" rep segment {operation['segment']}"])
        return
    elif operation["op"] == "set_span":
        for target in _config_targets(device):
            _append_unique_config_lines(
                target,
                [
                    f"monitor session {operation['session']} source interface {operation['source']}",
                    f"monitor session {operation['session']} destination interface {operation['destination']}",
                ],
            )
        return
    elif operation["op"] == "set_dot1x":
        global_lines = ["aaa new-model", "dot1x system-auth-control"]
        if operation.get("radius_host") and operation.get("radius_key"):
            global_lines.append(f"radius-server host {operation['radius_host']} key {operation['radius_key']}")
        mode = str(operation.get("mode") or "auto")
        for target in _config_targets(device):
            _append_unique_config_lines(target, global_lines)
            _append_config_block(
                target,
                f"interface {operation['interface']}",
                [f" authentication port-control {mode}", " dot1x pae authenticator"],
            )
        return
    elif operation["op"] == "set_qos_policy":
        action = str(operation.get("action") or "priority")
        for target in _config_targets(device):
            _append_unique_config_lines(target, ["mls qos"])
            _append_config_block(
                target,
                f"class-map match-any {operation['class_map']}",
                [f" match {operation['match']}"],
            )
            _append_config_block(
                target,
                f"policy-map {operation['policy_map']}",
                [f" class {operation['class_map']}", f"  {action}"],
            )
            _append_config_block(
                target,
                f"interface {operation['interface']}",
                [f" service-policy {operation['direction']} {operation['policy_map']}"],
            )
        return
    elif operation["op"] == "set_stp":
        lines = [f"spanning-tree mode {operation['mode']}"]
        if operation.get("vlan") and operation.get("root"):
            lines.append(f"spanning-tree vlan {operation['vlan']} root {operation['root']}")
        for target in _config_targets(device):
            _append_unique_config_lines(target, lines)
        return
    elif operation["op"] == "set_etherchannel":
        channel = int(operation["channel"])
        mode = str(operation.get("mode") or "active")
        interfaces = [str(interface) for interface in operation.get("interfaces", []) if str(interface).strip()]
        for target in _config_targets(device):
            for interface_name in interfaces:
                _append_config_block(target, f"interface {interface_name}", [f" channel-group {channel} mode {mode}"])
            _append_config_block(target, f"interface Port-channel{channel}", [" no shutdown"])
        return
    elif operation["op"] == "set_vtp":
        lines = [f"vtp domain {operation['domain']}", f"vtp mode {operation['mode']}"]
        if operation.get("version"):
            lines.append(f"vtp version {operation['version']}")
        for target in _config_targets(device):
            _append_unique_config_lines(target, lines)
        return
    elif operation["op"] == "set_dtp":
        for target in _config_targets(device):
            _append_config_block(target, f"interface {operation['interface']}", [f" switchport mode {operation['mode']}"])
        return
    else:
        return


def _apply_router_op(device: ET.Element, operation: dict[str, object]) -> None:
    """Apply one router operation.

    A missing field used to escape as a bare `KeyError` from inside donor
    validation, so `'DNS'`, `'virtual_ipv6'` and `'interface'` all surfaced as
    "no ranked donor candidate passed compatibility validation" -- three
    separate hours spent looking at donors when the fault was in the operation.
    """
    try:
        return _apply_router_op_inner(device, operation)
    except KeyError as missing:
        raise KeyError(
            f"operation {operation.get('op', '?')!r} is missing field {missing.args[0]!r}"
        ) from missing


def _apply_router_op_inner(device: ET.Element, operation: dict[str, object]) -> None:
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
    elif operation["op"] == "enable_ipv6_unicast_routing":
        for target in _config_targets(device):
            _append_unique_config_lines(target, ["ipv6 unicast-routing"])
        return
    elif operation["op"] == "set_ipv6_address":
        for target in _config_targets(device):
            _append_unique_config_lines(target, ["ipv6 unicast-routing"])
            _append_config_block(
                target,
                f"interface {operation['interface']}",
                [f" ipv6 address {operation['address']}/{operation['prefix']}", " no shutdown"],
            )
        return
    elif operation["op"] == "set_ipv6_slaac":
        body = [" ipv6 enable", " no shutdown"]
        if operation.get("prefix") and operation.get("prefix_len"):
            body.insert(1, f" ipv6 nd prefix {operation['prefix']}/{operation['prefix_len']}")
        for target in _config_targets(device):
            _append_unique_config_lines(target, ["ipv6 unicast-routing"])
            _append_config_block(target, f"interface {operation['interface']}", body)
        return
    elif operation["op"] == "set_dhcpv6_pool":
        pool_body = [f" address prefix {operation['prefix']}/{operation['prefix_len']}"]
        if operation.get("dns"):
            pool_body.append(f" dns-server {operation['dns']}")
        if operation.get("domain"):
            pool_body.append(f" domain-name {operation['domain']}")
        interface_body = [f" ipv6 dhcp server {operation['name']}", " ipv6 nd managed-config-flag", " no shutdown"]
        for target in _config_targets(device):
            _append_unique_config_lines(target, ["ipv6 unicast-routing"])
            _append_config_block(target, f"ipv6 dhcp pool {operation['name']}", pool_body)
            _append_config_block(target, f"interface {operation['interface']}", interface_body)
        return
    elif operation["op"] == "set_ospfv3_interface":
        process_id = operation["process_id"]
        for target in _config_targets(device):
            _append_unique_config_lines(target, ["ipv6 unicast-routing"])
            _append_config_block(target, f"interface {operation['interface']}", [f" ipv6 ospf {process_id} area {operation['area']}", " no shutdown"])
            _append_config_block(target, f"ipv6 router ospf {process_id}", [])
        return
    elif operation["op"] == "set_eigrp_ipv6_interface":
        asn = operation["asn"]
        for target in _config_targets(device):
            _append_unique_config_lines(target, ["ipv6 unicast-routing", "no ipv6 cef"])
            _append_config_block(target, f"interface {operation['interface']}", [f" ipv6 eigrp {asn}", " no shutdown"])
            _append_config_block(target, f"ipv6 router eigrp {asn}", [" no shutdown"])
        return
    elif operation["op"] == "set_ripng_interface":
        for target in _config_targets(device):
            _append_unique_config_lines(target, ["ipv6 unicast-routing"])
            _append_config_block(target, f"interface {operation['interface']}", [f" ipv6 rip {operation['process_name']} enable", " no shutdown"])
        return
    elif operation["op"] == "set_hsrp_ipv6":
        # A standby group with no virtual address configures nothing, and the
        # KeyError surfaced as "no ranked donor candidate passed compatibility
        # validation: 'virtual_ipv6'" -- pointing at the donor rather than the
        # operation. Same shape as the `DNS` service-name failure.
        virtual = str(operation.get("virtual_ipv6") or "").strip()
        if not virtual:
            return
        body = [" standby version 2", f" standby {operation['group']} ipv6 {virtual}"]
        if operation.get("priority"):
            body.append(f" standby {operation['group']} priority {operation['priority']}")
            body.append(f" standby {operation['group']} preempt")
        for target in _config_targets(device):
            _append_unique_config_lines(target, ["ipv6 unicast-routing"])
            _append_config_block(target, f"interface {operation['interface']}", body)
        return
    elif operation["op"] == "set_ospfv2_network":
        for target in _config_targets(device):
            _append_config_block(
                target,
                f"router ospf {operation['process_id']}",
                [f" network {operation['network']} {operation['wildcard']} area {operation['area']}"],
            )
        return
    elif operation["op"] == "set_eigrp_ipv4_network":
        body = [f" network {operation['network']} {operation['wildcard']}"]
        if operation.get("no_auto_summary"):
            body.append(" no auto-summary")
        for target in _config_targets(device):
            _append_config_block(target, f"router eigrp {operation['asn']}", body)
        return
    elif operation["op"] == "set_ripv2_network":
        body = [" version 2", f" network {operation['network']}"]
        if operation.get("no_auto_summary"):
            body.append(" no auto-summary")
        for target in _config_targets(device):
            _append_config_block(target, "router rip", body)
        return
    elif operation["op"] == "set_static_route":
        for target in _config_targets(device):
            _append_unique_config_lines(target, [f"ip route {operation['network']} {_prefix_to_mask(int(operation['prefix']))} {operation['next_hop']}"])
        return
    elif operation["op"] == "set_dhcp_relay":
        for target in _config_targets(device):
            _append_config_block(target, f"interface {operation['interface']}", [f" ip helper-address {operation['helper']}"])
        return
    elif operation["op"] == "set_nat_interface":
        for target in _config_targets(device):
            _append_config_block(target, f"interface {operation['interface']}", [f" ip nat {operation['role']}"])
        return
    elif operation["op"] == "set_nat_static":
        for target in _config_targets(device):
            _append_unique_config_lines(target, [f"ip nat inside source static {operation['inside_local']} {operation['inside_global']}"])
        return
    elif operation["op"] == "set_pat_overload":
        suffix = " overload" if operation.get("overload") else ""
        for target in _config_targets(device):
            _append_unique_config_lines(target, [f"ip nat inside source list {operation['acl']} interface {operation['interface']}{suffix}"])
        return
    elif operation["op"] == "set_ssh_ios":
        lines = [
            f"ip domain-name {operation['domain']}",
            f"username {operation['username']} password {operation['password']}",
            f"crypto key generate rsa modulus {operation['modulus']}",
            "ip ssh version 2",
        ]
        for target in _config_targets(device):
            _append_unique_config_lines(target, lines)
        return
    elif operation["op"] == "set_ntp_server":
        for target in _config_targets(device):
            _append_unique_config_lines(target, [f"ntp server {operation['server']}"])
        return
    elif operation["op"] == "set_syslog_server":
        for target in _config_targets(device):
            _append_unique_config_lines(target, [f"logging host {operation['server']}"])
        return
    elif operation["op"] == "set_bgp_neighbor":
        body = [f" neighbor {operation['neighbor']} remote-as {operation['remote_as']}"]
        if operation.get("network") and operation.get("mask"):
            body.append(f" network {operation['network']} mask {operation['mask']}")
        for target in _config_targets(device):
            _append_config_block(target, f"router bgp {operation['asn']}", body)
        return
    elif operation["op"] == "set_snmp_community":
        for target in _config_targets(device):
            _append_unique_config_lines(target, [f"snmp-server community {operation['community']} {operation['mode']}"])
        return
    elif operation["op"] == "set_netflow":
        global_lines = [
            f"ip flow-export destination {operation['destination']} {operation['port']}",
            f"ip flow-export version {operation['version']}",
        ]
        for target in _config_targets(device):
            _append_unique_config_lines(target, global_lines)
            if operation.get("interface") and operation.get("direction"):
                _append_config_block(target, f"interface {operation['interface']}", [f" ip flow {operation['direction']}"])
        return
    elif operation["op"] == "set_gre_tunnel":
        body = []
        if operation.get("ip") and operation.get("prefix"):
            body.append(f" ip address {operation['ip']} {_prefix_to_mask(int(operation['prefix']))}")
        body.extend(
            [
                f" tunnel source {operation['source']}",
                f" tunnel destination {operation['destination']}",
                " tunnel mode gre ip",
                " no shutdown",
            ]
        )
        for target in _config_targets(device):
            _append_config_block(target, f"interface {operation['interface']}", body)
        return
    elif operation["op"] == "set_ppp_interface":
        body = [" encapsulation ppp"]
        if operation.get("authentication"):
            body.append(f" ppp authentication {operation['authentication']}")
        body.append(" no shutdown")
        for target in _config_targets(device):
            _append_config_block(target, f"interface {operation['interface']}", body)
        return
    elif operation["op"] == "set_ipsec_transform_set":
        for target in _config_targets(device):
            _append_unique_config_lines(
                target,
                [f"crypto ipsec transform-set {operation['name']} {operation['encryption']} {operation['integrity']}"],
            )
        return
    elif operation["op"] == "set_crypto_map":
        for target in _config_targets(device):
            _append_config_block(
                target,
                f"crypto map {operation['map_name']} {operation['sequence']} ipsec-isakmp",
                [
                    f" set peer {operation['peer']}",
                    f" set transform-set {operation['transform_set']}",
                    f" match address {operation['acl_name']}",
                ],
            )
            if operation.get("interface"):
                _append_config_block(target, f"interface {operation['interface']}", [f" crypto map {operation['map_name']}"])
        return
    elif operation["op"] == "set_cbac_inspect":
        for target in _config_targets(device):
            _append_unique_config_lines(target, [f"ip inspect name {operation['name']} {operation['protocol']}"])
            _append_config_block(target, f"interface {operation['interface']}", [f" ip inspect {operation['name']} {operation['direction']}"])
        return
    elif operation["op"] == "set_zfw_zone_interface":
        for target in _config_targets(device):
            _append_config_block(target, f"zone security {operation['zone']}", [])
            _append_config_block(target, f"interface {operation['interface']}", [f" zone-member security {operation['zone']}"])
        return
    elif operation["op"] == "set_zfw_zone_pair":
        for target in _config_targets(device):
            _append_config_block(
                target,
                f"zone-pair security {operation['pair_name']} source {operation['source']} destination {operation['destination']}",
                [f" service-policy type inspect {operation['policy']}"],
            )
        return
    elif operation["op"] == "set_zfw_policy":
        for target in _config_targets(device):
            _append_config_block(
                target,
                f"class-map type inspect match-any {operation['class_map']}",
                [f" match protocol {operation['protocol']}"],
            )
            _append_config_block(
                target,
                f"policy-map type inspect {operation['policy_map']}",
                [f" class type inspect {operation['class_map']}", f"  {operation['action']}"],
            )
        return
    elif operation["op"] == "set_telephony_service":
        body = [" no auto-reg-ephone"]
        if operation.get("max_ephones"):
            body.append(f" max-ephones {operation['max_ephones']}")
        if operation.get("max_dn"):
            body.append(f" max-dn {operation['max_dn']}")
        body.append(f" ip source-address {operation['source_address']} port {operation['port']}")
        for target in _config_targets(device):
            _append_config_block(target, "telephony-service", body)
        return
    elif operation["op"] == "set_ephone_dn":
        for target in _config_targets(device):
            _append_config_block(target, f"ephone-dn {operation['dn_id']}", [f" number {operation['number']}"])
        return
    elif operation["op"] == "set_ephone":
        for target in _config_targets(device):
            _append_config_block(
                target,
                f"ephone {operation['ephone_id']}",
                [f" mac-address {operation['mac']}", f" button {operation['button']}"],
            )
        return
    elif operation["op"] == "set_dial_peer_voice":
        for target in _config_targets(device):
            _append_config_block(
                target,
                f"dial-peer voice {operation['peer_id']} voip",
                [
                    f" destination-pattern {operation['destination_pattern']}",
                    f" session target ipv4:{operation['session_target']}",
                ],
            )
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
        "syslog": ("SYSLOG_SERVER", "ENABLED"),
        "aaa": ("ACS_SERVER", "ENABLED"),
    }
    service_name = service_name.strip().lower()
    if service_name == "email":
        email = engine.find("EMAIL_SERVER")
        if email is None:
            prototype = _server_engine_prototype_child("EMAIL_SERVER")
            email = copy.deepcopy(prototype) if prototype is not None else ET.SubElement(engine, "EMAIL_SERVER")
        if email not in list(engine):
            engine.append(email)
        _ensure_text(email, "SMTP_ENABLED", "1")
        _ensure_text(email, "POP3_ENABLED", "1")
        return
    # Callers reach this with whatever the prompt produced, and an unknown name
    # used to raise KeyError out of the middle of donor validation -- surfacing
    # as "no ranked donor candidate passed compatibility validation: 'DNS'",
    # which points at the donor rather than at the service name.
    entry = mapping.get(service_name.strip().lower())
    if entry is None:
        return
    tag, enabled_tag = entry
    node = engine.find(tag)
    if node is None:
        prototype = _server_engine_prototype_child(tag)
        node = copy.deepcopy(prototype) if prototype is not None else ET.SubElement(engine, tag)
    if node not in list(engine):
        engine.append(node)
    _ensure_text(node, enabled_tag, "1")


def _server_engine_prototype_child(tag: str) -> ET.Element | None:
    sample_root = load_sample_root(resolve_sample_path(SERVER_SAMPLE))
    for device in sample_root.findall(".//DEVICES/DEVICE"):
        engine = device.find("ENGINE")
        if engine is None or _device_type(device) != "Server":
            continue
        child = engine.find(tag)
        if child is not None:
            return child
    return None


def _apply_server_op(device: ET.Element, operation: dict[str, object]) -> None:
    engine = device.find("./ENGINE")
    if engine is None:
        return
    if operation["op"] == "set_server_dns_record":
        dns_server = engine.find("DNS_SERVER")
        if dns_server is None:
            prototype = _server_engine_prototype_child("DNS_SERVER")
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
            prototype = _server_engine_prototype_child("DHCP_SERVER")
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
    elif operation["op"] == "set_server_email_domain":
        email_server = engine.find("EMAIL_SERVER")
        if email_server is None:
            prototype = _server_engine_prototype_child("EMAIL_SERVER")
            email_server = copy.deepcopy(prototype) if prototype is not None else ET.SubElement(engine, "EMAIL_SERVER")
            engine.append(email_server)
        _ensure_text(email_server, "SMTP_ENABLED", "1")
        _ensure_text(email_server, "POP3_ENABLED", "1")
        _ensure_text(email_server, "SMTP_DOMAIN", str(operation["domain"]))
    elif operation["op"] == "set_server_aaa_auth_port":
        acs_server = engine.find("ACS_SERVER")
        if acs_server is None:
            prototype = _server_engine_prototype_child("ACS_SERVER")
            acs_server = copy.deepcopy(prototype) if prototype is not None else ET.SubElement(engine, "ACS_SERVER")
            engine.append(acs_server)
        _ensure_text(acs_server, "ENABLED", "1")
        radius_settings = acs_server.find("RADIUS_SETTINGS")
        if radius_settings is None:
            radius_settings = ET.SubElement(acs_server, "RADIUS_SETTINGS")
        _ensure_text(radius_settings, "AUTH_PORT", str(operation["auth_port"]))


def _wireless_common_nodes(engine: ET.Element) -> list[ET.Element]:
    nodes: list[ET.Element] = []
    for path in [
        "./WIRELESS_SERVER/WIRELESS_COMMON",
        "./WIRELESS_CLIENT/WIRELESS_COMMON",
        "./WLC/WLANS/WLAN_CONFIG",
        "./CAPWAP_AC/WLANS/WLAN_CONFIG",
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


def _apply_iot_op(device: ET.Element, operation: dict[str, object]) -> None:
    engine = device.find("./ENGINE")
    if engine is None:
        return
    if operation["op"] == "set_iot_registration":
        client = engine.find("IOE_CLIENT")
        if client is None:
            client = ET.SubElement(engine, "IOE_CLIENT")
        if operation.get("mode"):
            _ensure_text(client, "CLIENT_MODE", str(operation["mode"]))
        if operation.get("server_address"):
            _ensure_text(client, "SERVER_ADDRESS", str(operation["server_address"]))
        if operation.get("username"):
            _ensure_text(client, "USERNAME", str(operation["username"]))
        if operation.get("password"):
            _ensure_text(client, "PASSWORD", str(operation["password"]))
        return
    if operation["op"] == "set_iot_rule_state":
        for node in engine.findall("./IOE_USER_MANAGER/USERS/USER/IOE_RULES/IOE_RULE/JSON"):
            try:
                payload = json.loads(node.text or "{}")
            except json.JSONDecodeError:
                continue
            if str(payload.get("name", "")).strip() != str(operation["rule_name"]).strip():
                continue
            payload["enabled"] = bool(operation["enabled"])
            node.text = json.dumps(payload)
            return


def _find_script_file(device: ET.Element, app_name: str, file_name: str) -> ET.Element:
    app_matches = [
        directory
        for directory in device.findall(".//FILE[@class='CDirectory']")
        if directory.findtext("NAME", default="").strip() == app_name
    ]
    if not app_matches:
        device_name = device.findtext("./ENGINE/NAME", default="")
        raise ValueError(f"Script app {app_name!r} was not found on device {device_name!r}.")
    file_matches: list[ET.Element] = []
    for directory in app_matches:
        file_matches.extend(
            file_node
            for file_node in directory.findall(".//FILE[@class='CFile']")
            if file_node.findtext("NAME", default="").strip() == file_name
        )
    if not file_matches:
        raise ValueError(f"Script file {file_name!r} was not found in app {app_name!r}.")
    if len(file_matches) > 1:
        raise ValueError(f"Script file {file_name!r} in app {app_name!r} is ambiguous.")
    return file_matches[0]


def _apply_programming_op(device: ET.Element, operation: dict[str, object]) -> None:
    if operation["op"] != "set_script_file_content":
        return
    file_node = _find_script_file(device, str(operation["app_name"]), str(operation["file_name"]))
    content_node = file_node.find("FILE_CONTENT")
    if content_node is None:
        content_node = ET.SubElement(file_node, "FILE_CONTENT", {"class": "CTextFileContent"})
    _ensure_text(content_node, "TEXT", str(operation["content"]))


def apply_plan_operations(root: ET.Element, plan: IntentPlan) -> ET.Element:
    updated = copy.deepcopy(root)
    port_mem_map = _link_port_mem_map(updated)
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
    # Renaming a device onto a name another device still holds leaves two
    # devices answering to it, and every later lookup by name becomes a coin
    # toss. Measured: a plan renamed SWP1 to SW1 while the donor's own SW1 was
    # still there, waiting to be pruned two operations later. The prune then
    # stripped the *new* SW1's cables -- its two PCs ended up with no links at
    # all -- and left the old SW1's link pointing at a device that no longer
    # existed, which is the dangling SAVE_REF the workspace check reports.
    #
    # Prunes cannot simply run first: the ones recorded for clone collisions
    # name devices by their *final* name, so they depend on the renames. Pull
    # forward only the prune that a rename is about to collide with, and let
    # the original operation no-op when its turn comes.
    pending_prunes = Counter(
        str(operation.get("device"))
        for operation in plan.edit_operations
        if operation.get("op") == "prune_device"
    )
    prunes_pulled_forward: Counter[str] = Counter()

    for operation in plan.edit_operations:
        if operation["op"] == "duplicate_host":
            _duplicate_host_onto_switch(
                updated,
                str(operation["device"]),
                str(operation["new_name"]),
                str(operation["switch"]),
                str(operation.get("switch_port", "")),
                str(operation.get("host_port", "FastEthernet0")),
                int(operation.get("x", 0)),
                int(operation.get("y", 0)),
            )
            continue
        if operation["op"] == "duplicate_group":
            _duplicate_group(
                updated,
                str(operation["device"]),
                str(operation["new_name"]),
                [str(name) for name in operation.get("hosts", [])],
                int(operation.get("x", 0)),
                int(operation.get("y", 0)),
                [str(name) for name in operation.get("new_hosts", [])] or None,
            )
            continue
        if operation["op"] == "duplicate_device":
            _duplicate_device(
                updated,
                str(operation["device"]),
                str(operation["new_name"]),
                int(operation.get("x", 0)),
                int(operation.get("y", 0)),
            )
            continue
        if operation["op"] == "prune_device":
            prune_name = str(operation["device"])
            pending_prunes[prune_name] -= 1
            if prunes_pulled_forward[prune_name] > 0:
                # Already done, ahead of the rename that needed it gone. Running
                # it again here would delete the device that now carries the
                # name -- the very device the plan renamed into place.
                prunes_pulled_forward[prune_name] -= 1
                continue
            _prune_device(updated, prune_name)
            continue
        if operation["op"] == "remove_link":
            _remove_link(updated, str(operation["a"]["dev"]), str(operation["b"]["dev"]))
            continue
        if operation["op"] == "apply_cli":
            device = _find_device(updated, str(operation["device"]))
            if device is not None:
                apply_cli_lines(device, [str(line) for line in operation.get("lines", [])])
            continue
        if operation["op"] == "set_link":
            _ensure_link(
                updated,
                str(operation["a"]["dev"]),
                str(operation["a"]["port"]),
                str(operation["b"]["dev"]),
                str(operation["b"]["port"]),
                str(operation.get("media", "copper")),
                port_mem_map=port_mem_map,
            )
            continue
        device = _find_device(updated, str(operation["device"]))
        if device is None:
            continue
        if operation["op"] == "rename_device":
            new_name = str(operation["new_name"])
            occupant = _find_device(updated, new_name)
            if (
                occupant is not None
                and occupant is not device
                and pending_prunes[new_name] > 0
            ):
                _prune_device(updated, new_name)
                pending_prunes[new_name] -= 1
                prunes_pulled_forward[new_name] += 1
            _set_device_name(updated, device, new_name)
        elif operation["op"] == "reflow_layout":
            _set_device_position(device, int(operation["x"]), int(operation["y"]))

    # Duplication has to run last, from devices carrying their final names, so
    # a link to a duplicated device is attempted before that device exists.
    # `_ensure_link` returns in silence when an endpoint is missing, and a
    # 22-switch lab lost every one of its nineteen core uplinks that way: 62
    # planned links arrived as 43, with no error anywhere. Re-running the link
    # pass once every device exists costs nothing, because `_ensure_link`
    # updates the link it already made for a pair rather than adding a second.
    for operation in plan.edit_operations:
        if operation.get("op") != "set_link":
            continue
        _ensure_link(
            updated,
            str(operation["a"]["dev"]),
            str(operation["a"]["port"]),
            str(operation["b"]["dev"]),
            str(operation["b"]["port"]),
            str(operation.get("media", "copper")),
            port_mem_map=port_mem_map,
        )

    for bucket, handler in [
        (plan.switch_ops, _apply_switch_op),
        (plan.router_ops, _apply_router_op),
        (plan.server_ops, _apply_server_op),
        (plan.wireless_ops, _apply_wireless_op),
        (plan.end_device_ops, _apply_end_device_op),
        (plan.management_ops, _apply_management_op),
        (plan.iot_ops, _apply_iot_op),
        (plan.programming_ops, _apply_programming_op),
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
    xml_bytes = serialize_pkt_xml(updated)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(encode_pkt_modern(xml_bytes))
    if xml_out_path is not None:
        xml_path = Path(xml_out_path)
        xml_path.parent.mkdir(parents=True, exist_ok=True)
        xml_path.write_bytes(xml_bytes)
    return output_path
