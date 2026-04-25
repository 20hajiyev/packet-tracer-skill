from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass, field


CAPABILITY_PATTERNS = {
    "vlan": [r"\bvlan(?:larda|lar|da|de|a|e)?\b", r"\btrunk\b", r"\baccess port\b", r"\brouter-on-a-stick\b", r"\bdot1q\b"],
    "trunk": [r"\btrunk\b", r"\ballowed vlan\b", r"\bnative vlan\b"],
    "access_port": [r"\baccess port\b", r"\baccess-port\b"],
    "router_on_a_stick": [r"\brouter-on-a-stick\b", r"\bsubinterface\b", r"\bdot1q\b"],
    "dhcp_pool": [r"\bdhcp\b", r"\bdhcp pool\b"],
    "router_dhcp": [r"\bdhcp\b", r"\bdhcp pool\b", r"\bdefault-router\b"],
    "server_dhcp": [r"\bserver dhcp\b", r"\bdhcp server\b"],
    "dns": [r"\bdns\b", r"\ba record\b", r"\bcname\b"],
    "server_dns": [r"\bdns\b", r"\ba record\b", r"\bcname\b"],
    "server_http": [r"\bhttp\b", r"\bweb\b"],
    "server_ftp": [r"\bftp\b", r"\btftp\b"],
    "server_https": [r"\bhttps\b"],
    "server_tftp": [r"\btftp\b"],
    "server_email": [r"\bemail\b", r"\bsmtp\b", r"\bpop3\b"],
    "server_syslog": [r"\bsyslog\b"],
    "server_aaa": [r"\baaa\b", r"\bacs\b", r"\bradius\b"],
    "iot": [r"\biot\b", r"\bhome gateway\b", r"\bsmart home\b", r"\bsensor\b", r"\bactuator\b", r"\bmcu\b"],
    "iot_registration": [r"\biot registration\b", r"\bregister\b", r"\bregistration server\b"],
    "iot_control": [r"\biot control\b", r"\bcontrol\b", r"\btrigger\b", r"\bturn on\b", r"\bturn off\b", r"\block\b", r"\bunlock\b"],
    "management_vlan": [r"\bmanagement vlan\b", r"\bvlan 99\b", r"\bdefault-gateway\b"],
    "telnet": [r"\btelnet\b", r"\bvty\b", r"\btransport input telnet\b"],
    "wireless_ap": [r"\bssid\b", r"\bwifi\b", r"\bwpa\b", r"\bwpa2\b", r"\bwireless\b", r"\baccess point\b", r"\bap\b"],
    "wireless_mutation": [r"\bset\s+[A-Za-z0-9_ -]+?\s+ssid\b", r"\bsecurity\s+(?:wpa|wpa2|wep|open|802\.1x)\b", r"\bpassphrase\b", r"\bchannel\s+\d+\b"],
    "wireless_client": [r"\btablet\b", r"\blaptop\b", r"\bsmartphone\b", r"\bassociate\b", r"\bjoin\b"],
    "wireless_client_association": [r"\bassociate\b", r"\bjoin\b"],
    "tablet": [r"\btablet\b"],
    "printer": [r"\bprinter\b"],
    "end_device_mutation": [r"\bset\s+[A-Za-z0-9_-]+\s+ip\b", r"\bset\s+[A-Za-z0-9_-]+\s+ipv4\s+dhcp\b", r"\bset\s+[A-Za-z0-9_-]+\s+dns\b"],
    "verification": [r"\bshow vlan brief\b", r"\bshow interfaces trunk\b", r"\bshow ip interface brief\b", r"\bshow ip dhcp binding\b", r"\bping\b", r"\btelnet\b"],
    "ospf": [r"\bospf\b"],
    "eigrp": [r"\beigrp\b"],
    "rip": [r"\brip\b"],
    "ipv6_slaac": [r"\bslaac\b", r"\bipv6\s+slaac\b"],
    "dhcpv6_stateful": [r"\bdhcpv6\b", r"\bstateful dhcpv6\b", r"\bipv6 stateful\b"],
    "dhcpv6_stateless": [r"\bstateless dhcpv6\b", r"\bipv6 stateless\b"],
    "ipv6_prefix_delegation": [r"\bprefix delegation\b", r"\bipv6 prefix\b"],
    "ipv6_dns_aaaa": [r"\baaaa\b", r"\bipv6 dns\b"],
    "ipv6_tunneling": [r"\bipv6ip\b", r"\bipv6 tunnel\b", r"\bipv6 tunneling\b"],
    "isatap": [r"\bisatap\b"],
    "ospfv3": [r"\bospfv3\b", r"\bipv6 ospf\b"],
    "eigrp_ipv6": [r"\bipv6 eigrp\b", r"\beigrp ipv6\b"],
    "ripng": [r"\bripng\b", r"\bipv6 rip\b"],
    "hsrp": [r"\bhsrp\b"],
    "nat": [r"\bnat\b"],
    "acl": [r"\bacl\b", r"\baccess-list\b"],
    "dhcp_snooping": [r"\bdhcp snooping\b"],
    "dai": [r"\bdai\b", r"\bdynamic arp inspection\b"],
    "dot1x": [r"\bdot1x\b", r"\b802\.1x\b", r"\bnac\b"],
    "lldp": [r"\blldp\b"],
    "rep": [r"\brep\b"],
    "snmp": [r"\bsnmp\b"],
    "netflow": [r"\bnetflow\b"],
    "span": [r"\bspan\b", r"\brspan\b"],
    "qos": [r"\bqos policy\b", r"\bqos class\b", r"\bclass-map\b", r"\bpolicy-map\b", r"\bquality of service\b"],
    "port_security": [r"\bport security\b", r"\bport-security\b"],
    "vpn": [r"\bvpn\b", r"\bsite-to-site\b", r"\bipsec\b", r"\btunnel\b"],
    "ipsec": [r"\bipsec\b", r"\bike\b", r"\bphase 1\b", r"\bphase 2\b"],
    "gre": [r"\bgre\b", r"\bgre tunnel\b"],
    "ppp": [r"\bppp\b", r"\bchap\b", r"\bpap\b"],
    "security_edge": [r"\bsecurity edge\b", r"\bsecurity appliance\b", r"\bfirewall\b", r"\basa\b"],
    "asa_acl_nat": [r"\basa acl\b", r"\basa nat\b", r"\basa acl nat\b"],
    "asa_service_policy": [r"\basa service policy\b", r"\bservice policy\b"],
    "clientless_vpn": [r"\bclientless vpn\b"],
    "cbac": [r"\bcbac\b"],
    "zfw": [r"\bzfw\b", r"\bzone based firewall\b", r"\bzone-based firewall\b"],
    "sniffer": [r"\bsniffer\b"],
    "multilayer_switching": [r"\bmultilayer switch\b", r"\blayer 3 switch\b", r"\b3560\b", r"\bsvi\b"],
    "wlc": [r"\bwlc\b", r"\bwireless lan controller\b"],
    "wpa_enterprise": [r"\bwpa enterprise\b", r"\bwpa2 enterprise\b", r"\bradius\b"],
    "wep": [r"\bwep\b"],
    "guest_wifi": [r"\bguest wifi\b", r"\bguest wlan\b"],
    "beamforming": [r"\bbeamforming\b"],
    "meraki": [r"\bmeraki\b"],
    "cellular_5g": [r"\b5g\b", r"\bcellular\b", r"\bcell tower\b"],
    "bluetooth": [r"\bbluetooth\b"],
    "network_controller": [r"\bnetwork controller\b", r"\bnetcon\b"],
    "python_programming": [r"\bpython programming\b", r"\bpython app\b"],
    "javascript_programming": [r"\bjavascript\b", r"\bjs app\b"],
    "blockly_programming": [r"\bblockly\b"],
    "tcp_udp_app": [r"\btcp test app\b", r"\budp test app\b", r"\btcp app\b", r"\budp app\b"],
    "vm_iox": [r"\biox\b", r"\bvm\b", r"\bvirtual machine\b"],
    "voip": [r"\bvoip\b"],
    "ip_phone": [r"\bip phone\b", r"\bphone\b"],
    "call_manager": [r"\bcall manager\b", r"\btelephony\b"],
    "linksys_voice": [r"\blinksys voice\b"],
    "mqtt": [r"\bmqtt\b"],
    "real_http": [r"\breal http\b"],
    "real_websocket": [r"\bwebsocket\b", r"\breal websocket\b"],
    "visual_scripting": [r"\bvisual scripting\b"],
    "ptp": [r"\bptp\b", r"\bprecision time protocol\b"],
    "profinet": [r"\bprofinet\b"],
    "l2nat": [r"\bl2nat\b", r"\bl2 nat\b"],
    "cyberobserver": [r"\bcyberobserver\b"],
    "industrial_firewall": [r"\bindustrial firewall\b", r"\bisa3000\b"],
    "coaxial": [r"\bcoaxial\b"],
    "cable_dsl": [r"\bcable modem\b", r"\bdsl\b", r"\bdsl modem\b"],
    "central_office": [r"\bcentral office\b"],
    "cell_tower": [r"\bcell tower\b"],
    "power_distribution": [r"\bpower distribution\b"],
    "hot_swappable": [r"\bhot swappable\b", r"\bhot-swappable\b"],
    "ios_license": [r"\bios license\b", r"\blicense\b", r"\bios15\b", r"\bios 15\b"],
}

DEVICE_SYNONYMS = {
    "router": "Router",
    "switch": "Switch",
    "pc": "PC",
    "server": "Server",
    "access-point": "LightWeightAccessPoint",
    "accesspoint": "LightWeightAccessPoint",
    "ap": "LightWeightAccessPoint",
    "wireless-router": "WirelessRouter",
    "wirelessrouter": "WirelessRouter",
    "home-router": "WirelessRouter",
    "homerouter": "WirelessRouter",
    "tablet": "Tablet",
    "laptop": "Laptop",
    "smartphone": "Smartphone",
    "printer": "Printer",
    "multilayer-switch": "MultiLayerSwitch",
    "multilayerswitch": "MultiLayerSwitch",
    "layer3-switch": "MultiLayerSwitch",
    "layer-3-switch": "MultiLayerSwitch",
    "cloud": "Cloud",
    "cable-modem": "Cable Modem",
    "cablemodem": "Cable Modem",
    "dsl-modem": "Dsl Modem",
    "dslmodem": "Dsl Modem",
    "security-appliance": "Security Appliance",
    "securityappliance": "Security Appliance",
    "asa": "ASA",
}

NATURAL_DEVICE_ALIASES = {
    "Router": ["router", "routerler", "routerlerin"],
    "Switch": ["switch", "switchler", "switchlerin"],
    "PC": ["pc", "pcs", "computer", "computers", "komputer", "komputerler", "kompyuter", "kompyuterler"],
    "Server": ["server", "serverler"],
    "WirelessRouter": ["wireless router", "wireless-router", "wirelessrouter", "home router", "home-router", "wrt"],
    "Tablet": ["tablet", "tabletler"],
    "Laptop": ["laptop", "laptoplar"],
    "Printer": ["printer", "printerler"],
    "LightWeightAccessPoint": ["ap", "aps", "accesspoint", "access-point", "access point", "apler"],
    "MultiLayerSwitch": ["multilayer switch", "multilayer-switch", "multilayerswitch", "layer 3 switch", "layer3 switch", "3560"],
    "Cloud": ["cloud", "wan cloud"],
    "Cable Modem": ["cable modem", "cable-modem", "cablemodem"],
    "Dsl Modem": ["dsl modem", "dsl-modem", "dslmodem"],
    "ASA": ["asa", "security appliance", "security-appliance", "firewall"],
}

NETWORK_STYLE_PATTERNS = {
    "campus": [r"\bcampus\b", r"\bkampus\b", r"\bsobeli\b", r"\bdepart", r"\bdepartment\b"],
    "branch": [r"\bbranch\b", r"\bfilial\b"],
    "ipv6_routing": [r"\bipv6\b", r"\bslaac\b", r"\bdhcpv6\b", r"\bospfv3\b", r"\bhsrp\b"],
    "l2_security_monitoring": [r"\bdhcp snooping\b", r"\bdai\b", r"\bdot1x\b", r"\b802\.1x\b", r"\bsnmp\b", r"\bnetflow\b", r"\bspan\b", r"\bqos policy\b", r"\bquality of service\b", r"\blldp\b", r"\brep\b"],
    "wireless_advanced": [r"\bwlc\b", r"\bwireless lan controller\b", r"\bmeraki\b", r"\bbluetooth\b", r"\b5g\b", r"\bcellular\b", r"\bwpa enterprise\b"],
    "automation_controller": [r"\bnetwork controller\b", r"\bnetcon\b", r"\bblockly\b", r"\bjavascript\b", r"\bpython programming\b", r"\biox\b"],
    "voice_collaboration": [r"\bvoip\b", r"\bip phone\b", r"\bcall manager\b", r"\btelephony\b"],
    "industrial_iot": [r"\bmqtt\b", r"\bwebsocket\b", r"\bprofinet\b", r"\bl2nat\b", r"\bptp\b", r"\bcyberobserver\b", r"\bindustrial\b"],
    "physical_media_device": [r"\bcoaxial\b", r"\bcable modem\b", r"\bdsl modem\b", r"\bcentral office\b", r"\bcell tower\b", r"\bpower distribution\b"],
    "small_office": [r"\bsmall office\b", r"\bhome\b", r"\bofis\b"],
    "wireless_branch": [r"\bwireless\b", r"\bwifi\b", r"\bssid\b"],
    "wan_security": [r"\bwan\b", r"\bgre\b", r"\bppp\b", r"\bipsec\b", r"\bvpn\b", r"\bsecurity edge\b", r"\bfirewall\b", r"\basa\b"],
}

PER_DEPARTMENT_DEVICE_ALIASES = {
    "PC": ["pc", "komputer", "computer"],
    "Printer": ["printer"],
    "LightWeightAccessPoint": ["ap", "access point", "accesspoint"],
    "Tablet": ["tablet"],
    "Laptop": ["laptop"],
    "Server": ["server"],
}

TOPOLOGY_HINT_WORDS = [
    "switch",
    "switchler",
    "router",
    "komputer",
    "pc",
    "server",
    "printer",
    "ap",
    "tablet",
    "qosul",
    "qo",
    "gig",
    "fastethernet",
    "vlan",
]

SECURITY_TO_AUTH = {
    "open": ("0", "0"),
    "wep": ("1", "1"),
    "wpa-psk": ("3", "3"),
    "wpa2-psk": ("4", "4"),
    "wpa": ("2", "2"),
    "wpa2": ("4", "4"),
    "802.1x": ("5", "5"),
}

TRANSLITERATION_TABLE = str.maketrans(
    {
        "ə": "e",
        "Ə": "e",
        "ş": "s",
        "Ş": "s",
        "ı": "i",
        "İ": "i",
        "ç": "c",
        "Ç": "c",
        "ö": "o",
        "Ö": "o",
        "ü": "u",
        "Ü": "u",
        "ğ": "g",
        "Ğ": "g",
        "â": "a",
        "Â": "a",
        "ê": "e",
        "Ê": "e",
    }
)


def _command_segments(prompt: str) -> list[str]:
    parts = re.split(r"(?=\b(?:device|connect|link|set|enable|associate|change|update|rename|apply)\b)", prompt, flags=re.IGNORECASE)
    return [part.strip() for part in parts if part.strip()]


def _normalize_prompt(prompt: str) -> str:
    text = prompt.translate(TRANSLITERATION_TABLE)
    for source, target in {
        "É™": "e",
        "Æ": "e",
        "ÅŸ": "s",
        "Å": "s",
        "Ä±": "i",
        "Ä°": "i",
        "Ã§": "c",
        "Ã‡": "c",
        "Ã¶": "o",
        "Ã–": "o",
        "Ã¼": "u",
        "Ãœ": "u",
        "ÄŸ": "g",
        "Ä": "g",
    }.items():
        text = text.replace(source, target)
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    text = text.lower()
    text = re.sub(r"[^a-z0-9./\\,:_-]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


@dataclass
class IntentPlan:
    goal: str
    prompt: str
    pkt_path: str | None = None
    capabilities: list[str] = field(default_factory=list)
    network_style: str | None = None
    wireless_mode: str | None = None
    device_requirements: dict[str, int] = field(default_factory=dict)
    device_counts: dict[str, int] = field(default_factory=dict)
    department_groups: list[dict[str, object]] = field(default_factory=list)
    service_requirements: dict[str, object] = field(default_factory=dict)
    topology_requirements: dict[str, object] = field(default_factory=dict)
    vlan_ids: list[int] = field(default_factory=list)
    uplink_intent: str | None = None
    host_link_intent: str | None = None
    host_vlan_assignment: dict[int, int] = field(default_factory=dict)
    assumptions_used: list[str] = field(default_factory=list)
    confidence_score: float = 0.0
    parse_warnings: list[str] = field(default_factory=list)
    blocking_gaps: list[str] = field(default_factory=list)
    compatibility_profile: dict[str, object] = field(default_factory=dict)
    unsafe_mutations_requested: list[str] = field(default_factory=list)
    blocked_mutations: list[str] = field(default_factory=list)
    acceptance_stage_plan: list[dict[str, object]] = field(default_factory=list)
    capability_matrix_hits: list[dict[str, object]] = field(default_factory=list)
    unsupported_capabilities: list[str] = field(default_factory=list)
    coverage_gap_report: dict[str, object] = field(default_factory=dict)
    blueprint_plan: dict[str, object] = field(default_factory=dict)
    remote_search_results: list[dict[str, object]] = field(default_factory=list)
    edit_operations: list[dict[str, object]] = field(default_factory=list)
    devices: list[dict[str, object]] = field(default_factory=list)
    links: list[dict[str, object]] = field(default_factory=list)
    switch_ops: list[dict[str, object]] = field(default_factory=list)
    router_ops: list[dict[str, object]] = field(default_factory=list)
    server_ops: list[dict[str, object]] = field(default_factory=list)
    wireless_ops: list[dict[str, object]] = field(default_factory=list)
    end_device_ops: list[dict[str, object]] = field(default_factory=list)
    management_ops: list[dict[str, object]] = field(default_factory=list)
    verification_ops: list[dict[str, object]] = field(default_factory=list)
    iot_ops: list[dict[str, object]] = field(default_factory=list)

    def all_operations(self) -> list[dict[str, object]]:
        merged: list[dict[str, object]] = []
        for bucket in [
            self.edit_operations,
            self.switch_ops,
            self.router_ops,
            self.server_ops,
            self.wireless_ops,
            self.end_device_ops,
            self.management_ops,
            self.verification_ops,
            self.iot_ops,
        ]:
            merged.extend(bucket)
        return merged

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["all_operations"] = self.all_operations()
        return data


def _normalize_device_type(raw_type: str) -> str:
    return DEVICE_SYNONYMS.get(raw_type.strip().lower(), raw_type.strip())


def _extract_natural_device_counts(normalized_prompt: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for device_type, aliases in NATURAL_DEVICE_ALIASES.items():
        alias_pattern = "|".join(re.escape(alias) for alias in aliases)
        patterns = [
            re.compile(rf"(?<![,/])\b(\d+)\s*(?:dene|dene?|eded|eded|tane)?\s*(?:{alias_pattern})\b"),
            re.compile(rf"\b(?:{alias_pattern})\s+(\d+)\b"),
        ]
        values: list[int] = []
        for pattern in patterns:
            values.extend(int(value) for value in pattern.findall(normalized_prompt))
        if values:
            counts[device_type] = max(values)
    return counts


def _extract_vlan_ids(normalized_prompt: str) -> list[int]:
    vlan_ids: list[int] = []
    for match in re.findall(r"\bvlan(?:larda|lar|da|de|a|e)?\s+([0-9,\s/veand]+)", normalized_prompt):
        vlan_ids.extend(int(value) for value in re.findall(r"\d+", match))
    return sorted(dict.fromkeys(vlan_ids))


def _extract_host_vlan_assignment(normalized_prompt: str) -> dict[int, int]:
    assignments: dict[int, int] = {}
    patterns = [
        re.compile(r"\bvlan\s+(\d+)\s*(?:da|de|a|e)?\s+(\d+)\s+(?:pc|komputer|computer)\b"),
        re.compile(r"\b(\d+)\s+(?:pc|komputer|computer)\s+vlan(?:da|de|a|e)?\s+(\d+)\b"),
    ]
    for pattern_index, pattern in enumerate(patterns):
        for first, second in pattern.findall(normalized_prompt):
            if pattern_index == 0:
                vlan_id, count = int(first), int(second)
            else:
                count, vlan_id = int(first), int(second)
            assignments[vlan_id] = assignments.get(vlan_id, 0) + count
    return assignments


def _extract_uplink_intent(normalized_prompt: str) -> str | None:
    if any(token in normalized_prompt for token in ["gig port", "gigabit", " gig ", "gi0", "routerle aralarinda gig", "switchlerin oz aralarinda"]):
        return "gigabit"
    return None


def _extract_host_link_intent(normalized_prompt: str) -> str | None:
    if any(token in normalized_prompt for token in ["fa port", "fastethernet", " fa ", "pc ler ise fa", "komputerler ise fa"]):
        return "fastethernet"
    return None


def _extract_network_style(normalized_prompt: str) -> str | None:
    for style, patterns in NETWORK_STYLE_PATTERNS.items():
        if any(re.search(pattern, normalized_prompt) for pattern in patterns):
            return style
    return None


def _extract_department_count(normalized_prompt: str) -> int:
    patterns = [
        re.compile(r"\b(\d+)\s+(?:sobeli|sobe|department|departamentli)\b"),
        re.compile(r"\b(\d+)\s+(?:depart(?:ment)?|bolme)\b"),
    ]
    for pattern in patterns:
        match = pattern.search(normalized_prompt)
        if match:
            return int(match.group(1))
    return 0


def _extract_per_department_devices(normalized_prompt: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    group_segment = ""
    segment_match = re.search(
        r"\bher\s+(?:sobede|bolmede|departmentda)\s+(.+?)(?=\b(?:router|dhcp|vlan|ssid|acl|telnet|ospf|eigrp|rip|nat)\b|$)",
        normalized_prompt,
    )
    if segment_match:
        group_segment = segment_match.group(1)
    for device_type, aliases in PER_DEPARTMENT_DEVICE_ALIASES.items():
        alias_pattern = "|".join(re.escape(alias) for alias in aliases)
        patterns = [
            re.compile(rf"\bher\s+(?:sobede|bolmede|departmentda)\s+(\d+)\s+(?:dene\s+)?(?:{alias_pattern})\b"),
            re.compile(rf"\beach\s+(?:department|group)\s+(\d+)\s+(?:{alias_pattern})\b"),
            re.compile(rf"\b(\d+)\s+(?:dene\s+)?(?:{alias_pattern})\b"),
        ]
        values: list[int] = []
        for pattern in patterns:
            target_text = group_segment if pattern.pattern.startswith(r"\b(\d+)") and group_segment else normalized_prompt
            values.extend(int(value) for value in pattern.findall(target_text))
        if values:
            counts[device_type] = max(values)
    return counts


def _build_department_groups(
    normalized_prompt: str,
    department_count: int,
    per_department_devices: dict[str, int],
    vlan_ids: list[int],
) -> list[dict[str, object]]:
    if department_count <= 0:
        return []
    groups: list[dict[str, object]] = []
    for index in range(department_count):
        group_name = f"DEPT{index + 1}"
        groups.append(
            {
                "name": group_name,
                "switch_name": f"{group_name}-SW",
                "vlan_id": vlan_ids[index] if index < len(vlan_ids) else None,
                "devices": dict(per_department_devices),
            }
        )
    return groups


def _extract_service_requirements(capabilities: list[str], prompt: str) -> dict[str, object]:
    lowered = prompt.lower()
    requirements: dict[str, object] = {
        "routing": next((cap for cap in ["ospf", "eigrp", "rip"] if cap in capabilities), None),
        "services": [],
        "security": [],
    }
    for service in ["dhcp", "dns", "http", "https", "ftp", "tftp", "ntp", "email", "syslog", "aaa"]:
        if service in lowered:
            requirements["services"].append(service)
    for security in ["acl", "telnet", "wpa2", "wpa", "wep", "nat", "vpn", "ipsec", "gre", "ppp", "security_edge", "ssh"]:
        if security in lowered:
            requirements["security"].append(security)
    return requirements


def _extract_wireless_mode(
    normalized_prompt: str,
    capabilities: list[str],
    device_requirements: dict[str, int],
    network_style: str | None,
) -> str | None:
    has_wireless = any(cap in capabilities for cap in ["wireless_ap", "wireless_client"])
    if not has_wireless and not device_requirements.get("WirelessRouter", 0):
        return None
    mentions_home_router = any(token in normalized_prompt for token in ["home router", "wireless router", "wirelessrouter", "wrt"])
    campus_like = network_style in {"campus", "branch", "wireless_branch"} or "department" in normalized_prompt or "sobeli" in normalized_prompt
    if mentions_home_router and campus_like:
        return "mixed"
    if mentions_home_router or "nat" in capabilities or network_style == "small_office" or device_requirements.get("WirelessRouter", 0):
        return "home_router_edge"
    return "ap_bridge"


def _estimate_confidence(
    device_requirements: dict[str, int],
    capabilities: list[str],
    parse_warnings: list[str],
    blocking_gaps: list[str],
    explicit_devices: list[dict[str, object]],
    links: list[dict[str, object]],
) -> float:
    score = 0.2
    if device_requirements or explicit_devices:
        score += 0.25
    if capabilities:
        score += 0.2
    if links:
        score += 0.15
    score -= min(len(parse_warnings) * 0.08, 0.16)
    score -= min(len(blocking_gaps) * 0.2, 0.4)
    return max(0.0, min(1.0, round(score, 2)))


def _extract_explicit_devices(prompt: str) -> list[dict[str, object]]:
    devices: list[dict[str, object]] = []
    pattern = re.compile(
        r"(?:device\s+)?([A-Za-z][A-Za-z0-9_-]*)\s+type\s+([A-Za-z-]+)(?:\s+model\s+([A-Za-z0-9._-]+))?",
        flags=re.IGNORECASE,
    )
    for segment in _command_segments(prompt):
        for name, raw_type, model in pattern.findall(segment):
            devices.append({"name": name, "type": _normalize_device_type(raw_type), "model": model or None})
    return devices


def _extract_explicit_links(prompt: str) -> list[dict[str, object]]:
    links: list[dict[str, object]] = []
    pattern = re.compile(
        r"(?:connect|link)\s+([A-Za-z][A-Za-z0-9_-]*):([A-Za-z0-9/._-]+)\s+(?:to|->)\s+([A-Za-z][A-Za-z0-9_-]*):([A-Za-z0-9/._-]+)"
        r"(?:\s+with\s+([A-Za-z0-9._-]+))?",
        flags=re.IGNORECASE,
    )
    for segment in _command_segments(prompt):
        for left_dev, left_port, right_dev, right_port, cable in pattern.findall(segment):
            links.append(
                {
                    "a": {"dev": left_dev, "port": left_port},
                    "b": {"dev": right_dev, "port": right_port},
                    "media": (cable or "copper").lower(),
                }
            )
    deduped: list[dict[str, object]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for link in links:
        key = (
            str(link["a"]["dev"]),
            str(link["a"]["port"]),
            str(link["b"]["dev"]),
            str(link["b"]["port"]),
            str(link["media"]),
        )
        if key not in seen:
            seen.add(key)
            deduped.append(link)
    return deduped


def _extract_link_edit_operations(links: list[dict[str, object]]) -> list[dict[str, object]]:
    return [{"op": "set_link", **link} for link in links]


def _extract_switch_ops(prompt: str) -> list[dict[str, object]]:
    ops: list[dict[str, object]] = []
    for segment in _command_segments(prompt):
        for device, vlan_id, name in re.findall(r"set\s+([A-Za-z0-9_-]+)\s+vlan\s+(\d+)\s+name\s+([A-Za-z0-9_-]+)", segment, flags=re.IGNORECASE):
            ops.append({"op": "set_vlan", "device": device, "vlan": int(vlan_id), "name": name})
        for device, port, vlan_id in re.findall(r"set\s+([A-Za-z0-9_-]+)\s+access-port\s+([A-Za-z0-9/._-]+)\s+vlan\s+(\d+)", segment, flags=re.IGNORECASE):
            ops.append({"op": "set_access_port", "device": device, "port": port, "vlan": int(vlan_id)})
    trunk_pattern = re.compile(
        r"set\s+([A-Za-z0-9_-]+)\s+trunk-port\s+([A-Za-z0-9/._-]+)\s+allowed\s+([0-9,\s]+?)(?:\s+native\s+(\d+))?(?=\s+set\s+|$)",
        flags=re.IGNORECASE,
    )
    for segment in _command_segments(prompt):
        for device, port, allowed, native in trunk_pattern.findall(segment):
            ops.append(
                {
                    "op": "set_trunk_port",
                    "device": device,
                    "port": port,
                    "allowed": [int(value) for value in re.findall(r"\d+", allowed)],
                    "native": int(native) if native else None,
                }
            )
    return ops


def _extract_router_ops(prompt: str) -> list[dict[str, object]]:
    ops: list[dict[str, object]] = []
    subif_pattern = re.compile(
        r"set\s+([A-Za-z0-9_-]+)\s+subinterface\s+([A-Za-z0-9/._-]+)\s+encapsulation\s+dot1q\s+(\d+)\s+ip\s+(\d+\.\d+\.\d+\.\d+)/(\d+)",
        flags=re.IGNORECASE,
    )
    for segment in _command_segments(prompt):
        for device, subinterface, vlan_id, ip, prefix in subif_pattern.findall(segment):
            ops.append({"op": "set_subinterface", "device": device, "subinterface": subinterface, "vlan": int(vlan_id), "ip": ip, "prefix": int(prefix)})
    dhcp_pattern = re.compile(
        r"set\s+([A-Za-z0-9_-]+)\s+dhcp\s+pool\s+([A-Za-z0-9_-]+)\s+network\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\s+gateway\s+(\d+\.\d+\.\d+\.\d+)"
        r"(?:\s+dns\s+(\d+\.\d+\.\d+\.\d+))?(?:\s+start\s+(\d+\.\d+\.\d+\.\d+))?(?:\s+max\s+(\d+))?",
        flags=re.IGNORECASE,
    )
    for segment in _command_segments(prompt):
        for device, name, network, prefix, gateway, dns, start, max_users in dhcp_pattern.findall(segment):
            if str(device).strip().lower().startswith("server"):
                continue
            ops.append(
                {
                    "op": "set_router_dhcp_pool",
                    "device": device,
                    "name": name,
                    "network": network,
                    "prefix": int(prefix),
                    "gateway": gateway,
                    "dns": dns or None,
                    "start": start or None,
                    "max_users": int(max_users) if max_users else None,
                }
            )
    acl_create_pattern = re.compile(r"set\s+([A-Za-z0-9_ -]+?)\s+acl\s+(standard|extended)\s+([A-Za-z0-9_-]+)", flags=re.IGNORECASE)
    for segment in _command_segments(prompt):
        for device, acl_kind, acl_name in acl_create_pattern.findall(segment):
            ops.append({"op": "set_acl", "device": device.strip(), "acl_kind": acl_kind.lower(), "acl_name": acl_name})
    acl_create_simple_pattern = re.compile(
        r"create\s+acl\s+([A-Za-z0-9_-]+)\s+on\s+([A-Za-z0-9_ -]+?)(?:\s+kind\s+(standard|extended))?(?=\s+(?:acl\b|apply\b|enable\b|set\b|associate\b|register\b|disable\b)|$)",
        flags=re.IGNORECASE,
    )
    for segment in _command_segments(prompt):
        for acl_name, device, acl_kind in acl_create_simple_pattern.findall(segment):
            ops.append(
                {
                    "op": "set_acl",
                    "device": device.strip(),
                    "acl_kind": (acl_kind or "standard").lower(),
                    "acl_name": acl_name,
                }
            )
    acl_rule_pattern = re.compile(
        r"acl\s+([A-Za-z0-9_-]+)\s+(permit|deny)\s+(host\s+\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+|any)"
        r"(?:\s+(host\s+\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+|any))?",
        flags=re.IGNORECASE,
    )
    for segment in _command_segments(prompt):
        for acl_name, action, source, destination in acl_rule_pattern.findall(segment):
            ops.append({"op": "add_acl_rule", "acl_name": acl_name, "action": action.lower(), "source": source.strip(), "destination": destination.strip() if destination else None})
    acl_apply_pattern = re.compile(
        r"apply\s+acl\s+([A-Za-z0-9_-]+)\s+(in|out)\s+on\s+([A-Za-z0-9_ -]+?)(?:\s+interface)?\s+([A-Za-z0-9/._-]+)",
        flags=re.IGNORECASE,
    )
    for segment in _command_segments(prompt):
        for acl_name, direction, device, interface_name in acl_apply_pattern.findall(segment):
            ops.append({"op": "apply_acl", "device": device.strip(), "acl_name": acl_name, "direction": direction.lower(), "interface": interface_name})
    ipv6_unicast_pattern = re.compile(r"set\s+([A-Za-z0-9_-]+)\s+ipv6\s+unicast-routing", flags=re.IGNORECASE)
    ipv6_address_pattern = re.compile(
        r"set\s+([A-Za-z0-9_-]+)\s+(?:interface\s+)?([A-Za-z0-9/._-]+)\s+ipv6\s+([0-9A-Fa-f:]+)/(\d+)",
        flags=re.IGNORECASE,
    )
    ipv6_slaac_pattern = re.compile(
        r"set\s+([A-Za-z0-9_-]+)\s+slaac\s+on\s+([A-Za-z0-9/._-]+)(?:\s+prefix\s+([0-9A-Fa-f:]+)/(\d+))?",
        flags=re.IGNORECASE,
    )
    dhcpv6_pattern = re.compile(
        r"set\s+([A-Za-z0-9_-]+)\s+dhcpv6\s+pool\s+([A-Za-z0-9_-]+)\s+prefix\s+([0-9A-Fa-f:]+)/(\d+)\s+interface\s+([A-Za-z0-9/._-]+)"
        r"(?:\s+dns\s+([0-9A-Fa-f:]+))?(?:\s+domain\s+([A-Za-z0-9._-]+))?",
        flags=re.IGNORECASE,
    )
    ospfv3_pattern = re.compile(r"set\s+([A-Za-z0-9_-]+)\s+ospfv3\s+(\d+)\s+area\s+(\d+)\s+interface\s+([A-Za-z0-9/._-]+)", flags=re.IGNORECASE)
    eigrp_ipv6_pattern = re.compile(r"set\s+([A-Za-z0-9_-]+)\s+eigrp\s+ipv6\s+(\d+)\s+interface\s+([A-Za-z0-9/._-]+)", flags=re.IGNORECASE)
    ripng_pattern = re.compile(r"set\s+([A-Za-z0-9_-]+)\s+ripng\s+([A-Za-z0-9_-]+)\s+interface\s+([A-Za-z0-9/._-]+)", flags=re.IGNORECASE)
    hsrp_pattern = re.compile(
        r"set\s+([A-Za-z0-9_-]+)\s+hsrp\s+(\d+)\s+ipv6\s+([0-9A-Fa-f:]+)\s+interface\s+([A-Za-z0-9/._-]+)(?:\s+priority\s+(\d+))?",
        flags=re.IGNORECASE,
    )
    for segment in _command_segments(prompt):
        for device in ipv6_unicast_pattern.findall(segment):
            ops.append({"op": "enable_ipv6_unicast_routing", "device": device})
        for device, interface_name, address, prefix in ipv6_address_pattern.findall(segment):
            ops.append({"op": "set_ipv6_address", "device": device, "interface": interface_name, "address": address, "prefix": int(prefix)})
        for device, interface_name, prefix_address, prefix_len in ipv6_slaac_pattern.findall(segment):
            ops.append(
                {
                    "op": "set_ipv6_slaac",
                    "device": device,
                    "interface": interface_name,
                    "prefix": prefix_address or None,
                    "prefix_len": int(prefix_len) if prefix_len else None,
                }
            )
        for device, name, prefix_address, prefix_len, interface_name, dns, domain in dhcpv6_pattern.findall(segment):
            ops.append(
                {
                    "op": "set_dhcpv6_pool",
                    "device": device,
                    "name": name,
                    "prefix": prefix_address,
                    "prefix_len": int(prefix_len),
                    "interface": interface_name,
                    "dns": dns or None,
                    "domain": domain or None,
                }
            )
        for device, process_id, area, interface_name in ospfv3_pattern.findall(segment):
            ops.append({"op": "set_ospfv3_interface", "device": device, "process_id": int(process_id), "area": int(area), "interface": interface_name})
        for device, asn, interface_name in eigrp_ipv6_pattern.findall(segment):
            ops.append({"op": "set_eigrp_ipv6_interface", "device": device, "asn": int(asn), "interface": interface_name})
        for device, process_name, interface_name in ripng_pattern.findall(segment):
            ops.append({"op": "set_ripng_interface", "device": device, "process_name": process_name, "interface": interface_name})
        for device, group, virtual_ipv6, interface_name, priority in hsrp_pattern.findall(segment):
            ops.append(
                {
                    "op": "set_hsrp_ipv6",
                    "device": device,
                    "group": int(group),
                    "virtual_ipv6": virtual_ipv6,
                    "interface": interface_name,
                    "priority": int(priority) if priority else None,
                }
            )
    return ops


def _extract_server_ops(prompt: str) -> list[dict[str, object]]:
    ops: list[dict[str, object]] = []
    dns_pattern = re.compile(r"set\s+([A-Za-z0-9_-]+)\s+dns\s+(A|CNAME)\s+([A-Za-z0-9._-]+)\s+([A-Za-z0-9._-]+)", flags=re.IGNORECASE)
    for segment in _command_segments(prompt):
        for device, record_type, name, value in dns_pattern.findall(segment):
            ops.append({"op": "set_server_dns_record", "device": device, "record_type": record_type.upper(), "name": name, "value": value})
    email_domain_pattern = re.compile(r"set\s+([A-Za-z0-9_-]+)\s+email\s+domain\s+([A-Za-z0-9._-]+)", flags=re.IGNORECASE)
    for segment in _command_segments(prompt):
        for device, domain in email_domain_pattern.findall(segment):
            ops.append({"op": "set_server_email_domain", "device": device, "domain": domain})
    aaa_auth_port_pattern = re.compile(r"set\s+([A-Za-z0-9_-]+)\s+aaa\s+auth-port\s+(\d+)", flags=re.IGNORECASE)
    for segment in _command_segments(prompt):
        for device, port in aaa_auth_port_pattern.findall(segment):
            ops.append({"op": "set_server_aaa_auth_port", "device": device, "auth_port": int(port)})
    dhcp_pattern = re.compile(
        r"set\s+([A-Za-z0-9_-]+)\s+(server-dhcp|dhcp)\s+pool\s+([A-Za-z0-9_-]+)\s+network\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\s+gateway\s+(\d+\.\d+\.\d+\.\d+)"
        r"(?:\s+dns\s+(\d+\.\d+\.\d+\.\d+))?(?:\s+start\s+(\d+\.\d+\.\d+\.\d+))?(?:\s+max\s+(\d+))?",
        flags=re.IGNORECASE,
    )
    for segment in _command_segments(prompt):
        for device, mode, name, network, prefix, gateway, dns, start, max_users in dhcp_pattern.findall(segment):
            if mode.lower() != "server-dhcp" and not str(device).strip().lower().startswith("server"):
                continue
            ops.append(
                {
                    "op": "set_server_dhcp_pool",
                    "device": device,
                    "name": name,
                    "network": network,
                    "prefix": int(prefix),
                    "gateway": gateway,
                    "dns": dns or None,
                    "start": start or None,
                    "max_users": int(max_users) if max_users else 0,
                }
            )
        for service, device in re.findall(r"enable\s+(dns|http|https|ftp|tftp|ntp|email|syslog|aaa)\s+on\s+([A-Za-z0-9_ -]+)", segment, flags=re.IGNORECASE):
            ops.append({"op": "enable_server_service", "device": device.strip(), "service": service.lower()})
    return ops


def _extract_management_ops(prompt: str) -> list[dict[str, object]]:
    ops: list[dict[str, object]] = []
    mgmt_pattern = re.compile(r"set\s+([A-Za-z0-9_ -]+?)\s+management\s+vlan\s+(\d+)\s+ip\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\s+gateway\s+(\d+\.\d+\.\d+\.\d+)", flags=re.IGNORECASE)
    for segment in _command_segments(prompt):
        for device, vlan_id, ip, prefix, gateway in mgmt_pattern.findall(segment):
            ops.append({"op": "set_management_vlan", "device": device.strip(), "vlan": int(vlan_id), "ip": ip, "prefix": int(prefix), "gateway": gateway})
    telnet_pattern = re.compile(r"enable\s+telnet\s+on\s+([A-Za-z0-9_ -]+?)\s+username\s+([A-Za-z0-9._-]+)\s+password\s+([A-Za-z0-9._-]+)", flags=re.IGNORECASE)
    for segment in _command_segments(prompt):
        for device, username, password in telnet_pattern.findall(segment):
            ops.append({"op": "enable_telnet", "device": device.strip(), "username": username, "password": password})
    return ops


def _extract_wireless_ops(prompt: str) -> list[dict[str, object]]:
    ops: list[dict[str, object]] = []
    ssid_pattern = re.compile(
        r"set\s+([A-Za-z0-9_ -]+?)\s+ssid\s+([A-Za-z0-9._-]+)(?:\s+security\s+([A-Za-z0-9.-]+))?(?:\s+passphrase\s+([A-Za-z0-9._-]+))?(?:\s+channel\s+(\d+))?",
        flags=re.IGNORECASE,
    )
    for segment in _command_segments(prompt):
        for device, ssid, security, passphrase, channel in ssid_pattern.findall(segment):
            security_key = (security or "open").lower()
            auth_type, encrypt_type = SECURITY_TO_AUTH.get(security_key, ("0", "0"))
            ops.append({"op": "set_wireless_ssid", "device": device.strip(), "ssid": ssid, "security": security_key, "auth_type": auth_type, "encrypt_type": encrypt_type, "passphrase": passphrase or "", "channel": int(channel) if channel else 1})
    assoc_pattern = re.compile(r"associate\s+([A-Za-z0-9_ -]+?)\s+to\s+([A-Za-z0-9_ -]+?)\s+ssid\s+([A-Za-z0-9._-]+)(?:\s+(dhcp|static))?", flags=re.IGNORECASE)
    for segment in _command_segments(prompt):
        for client, ap, ssid, ip_mode in assoc_pattern.findall(segment):
            ops.append({"op": "associate_wireless_client", "device": client.strip(), "ap": ap.strip(), "ssid": ssid, "ip_mode": (ip_mode or "dhcp").lower()})
    return ops


def _extract_end_device_ops(prompt: str) -> list[dict[str, object]]:
    ops: list[dict[str, object]] = []
    ip_pattern = re.compile(
        r"(?:set|change|update)\s+([A-Za-z0-9_-]+)\s+ip\s+(\d+\.\d+\.\d+\.\d+)"
        r"(?:\s+mask\s+(\d+\.\d+\.\d+\.\d+))?"
        r"(?:\s+gw\s+(\d+\.\d+\.\d+\.\d+))?"
        r"(?:\s+dns\s+(\d+\.\d+\.\d+\.\d+))?",
        flags=re.IGNORECASE,
    )
    for segment in _command_segments(prompt):
        for device, ip, mask, gw, dns in ip_pattern.findall(segment):
            operation: dict[str, object] = {"op": "set_host_ip", "device": device, "ip": ip}
            if mask:
                operation["mask"] = mask
            if gw:
                operation["gw"] = gw
            if dns:
                operation["dns"] = dns
            ops.append(operation)
        for device in re.findall(r"set\s+([A-Za-z0-9_-]+)\s+ipv4\s+dhcp", segment, flags=re.IGNORECASE):
            ops.append({"op": "set_host_dhcp", "device": device})
        for device, dns in re.findall(r"set\s+([A-Za-z0-9_-]+)\s+dns\s+(\d+\.\d+\.\d+\.\d+)", segment, flags=re.IGNORECASE):
            ops.append({"op": "set_host_dns", "device": device, "dns": dns})
    return ops


def _extract_verification_ops(prompt: str) -> list[dict[str, object]]:
    ops: list[dict[str, object]] = []
    lowered = prompt.lower()
    for command in ["show vlan brief", "show interfaces trunk", "show ip interface brief", "show ip dhcp binding"]:
        if command in lowered:
            ops.append({"op": "verify_command", "command": command})
    if "ping" in lowered:
        ops.append({"op": "verify_ping"})
    if "telnet" in lowered:
        ops.append({"op": "verify_telnet"})
    return ops


def _extract_iot_ops(prompt: str) -> list[dict[str, object]]:
    ops: list[dict[str, object]] = []
    registration_pattern = re.compile(
        r"register\s+([A-Za-z0-9_ -]+?)\s+to\s+([A-Za-z0-9_ -]+?)(?=\s+(?:mode|server(?:-address)?|username|password)\b|$)"
        r"(?:\s+mode\s+(lan_server|remote_server))?"
        r"(?:\s+server(?:-address)?\s+(\d+\.\d+\.\d+\.\d+))?"
        r"(?:\s+username\s+([A-Za-z0-9._-]+))?"
        r"(?:\s+password\s+([A-Za-z0-9._-]+))?",
        flags=re.IGNORECASE,
    )
    for segment in _command_segments(prompt):
        for device, target, mode, server_address, username, password in registration_pattern.findall(segment):
            ops.append(
                {
                    "op": "set_iot_registration",
                    "device": device.strip(),
                    "target": target.strip(),
                    "mode": (mode or "").upper() or None,
                    "server_address": server_address or None,
                    "username": username or None,
                    "password": password or None,
                }
            )
        rule_pattern = re.compile(
            r"(enable|disable)\s+iot\s+rule\s+(?:\"([^\"]+)\"|'([^']+)'|([A-Za-z0-9_ -]+?))\s+on\s+([A-Za-z0-9_ -]+)",
            flags=re.IGNORECASE,
        )
        for action, quoted_name, single_quoted_name, plain_name, device in rule_pattern.findall(segment):
            rule_name = quoted_name or single_quoted_name or plain_name
            ops.append(
                {
                    "op": "set_iot_rule_state",
                    "device": device.strip(),
                    "rule_name": rule_name.strip(),
                    "enabled": action.lower() == "enable",
                }
            )
    return ops


def parse_intent(prompt: str) -> IntentPlan:
    pkt_path_match = re.search(r"([A-Za-z]:\\[^\"\n]+?\.pkt)\b", prompt, flags=re.IGNORECASE)
    pkt_path = pkt_path_match.group(1) if pkt_path_match else None
    lowered = prompt.lower()
    normalized_prompt = _normalize_prompt(prompt)

    capability_set = {capability for capability, patterns in CAPABILITY_PATTERNS.items() if any(re.search(pattern, lowered) for pattern in patterns)}
    devices = _extract_explicit_devices(prompt)
    links = _extract_explicit_links(prompt)
    device_counts = _extract_natural_device_counts(normalized_prompt)
    vlan_ids = _extract_vlan_ids(normalized_prompt)
    uplink_intent = _extract_uplink_intent(normalized_prompt)
    host_link_intent = _extract_host_link_intent(normalized_prompt)
    host_vlan_assignment = _extract_host_vlan_assignment(normalized_prompt)
    network_style = _extract_network_style(normalized_prompt)
    department_count = _extract_department_count(normalized_prompt)
    per_department_devices = _extract_per_department_devices(normalized_prompt)

    device_requirements = dict(device_counts)
    for device in devices:
        device_type = str(device["type"])
        device_requirements[device_type] = device_requirements.get(device_type, 0) + 1

    department_groups = _build_department_groups(normalized_prompt, department_count, per_department_devices, vlan_ids)
    if department_groups:
        device_requirements["Switch"] = max(device_requirements.get("Switch", 0), department_count)
        for device_type, per_group_count in per_department_devices.items():
            device_requirements[device_type] = max(device_requirements.get(device_type, 0), department_count * per_group_count)

    topology_requirements: dict[str, object] = {}
    if vlan_ids:
        topology_requirements["vlan_ids"] = vlan_ids
    if uplink_intent:
        topology_requirements["uplink_intent"] = uplink_intent
    if host_link_intent:
        topology_requirements["host_link_intent"] = host_link_intent
    if host_vlan_assignment:
        topology_requirements["host_vlan_assignment"] = host_vlan_assignment
    if device_requirements.get("Switch", 0) > 1:
        topology_requirements["uplink_topology"] = "core_switch"
    if department_groups:
        topology_requirements["uplink_topology"] = "chain"
        topology_requirements["department_count"] = department_count
    if "router_dhcp" in capability_set or "dhcp_pool" in capability_set:
        topology_requirements["needs_dhcp_pool"] = True
    routing = next((cap for cap in ["ospf", "eigrp", "rip"] if cap in capability_set), None)
    if routing:
        topology_requirements["routing_protocol"] = routing
    service_requirements = _extract_service_requirements(sorted(capability_set), prompt)
    wireless_mode = _extract_wireless_mode(normalized_prompt, sorted(capability_set), device_requirements, network_style)

    edit_operations: list[dict[str, object]] = []
    for old_name, new_name in re.findall(r"rename\s+([A-Za-z0-9_-]+)\s+to\s+([A-Za-z0-9_-]+)", prompt, flags=re.IGNORECASE):
        edit_operations.append({"op": "rename_device", "device": old_name, "new_name": new_name})
    edit_operations.extend(_extract_link_edit_operations(links))

    switch_ops = _extract_switch_ops(prompt)
    router_ops = _extract_router_ops(prompt)
    server_ops = _extract_server_ops(prompt)
    wireless_ops = _extract_wireless_ops(prompt)
    end_device_ops = _extract_end_device_ops(prompt)
    management_ops = _extract_management_ops(prompt)
    verification_ops = _extract_verification_ops(prompt)
    iot_ops = _extract_iot_ops(prompt)

    if any(op["op"] == "associate_wireless_client" for op in wireless_ops):
        capability_set.update({"wireless_client", "wireless_client_association"})
    if any(op["op"] == "set_wireless_ssid" for op in wireless_ops):
        capability_set.update({"wireless_ap", "wireless_mutation"})
    if end_device_ops:
        capability_set.add("end_device_mutation")
    if iot_ops:
        capability_set.update({"iot", "iot_registration"})
    router_op_names = {str(op.get("op")) for op in router_ops}
    if router_op_names & {"enable_ipv6_unicast_routing", "set_ipv6_address", "set_ipv6_slaac"}:
        capability_set.add("ipv6_slaac")
    if "set_dhcpv6_pool" in router_op_names:
        capability_set.add("dhcpv6_stateful")
    if "set_ospfv3_interface" in router_op_names:
        capability_set.add("ospfv3")
    if "set_eigrp_ipv6_interface" in router_op_names:
        capability_set.add("eigrp_ipv6")
    if "set_ripng_interface" in router_op_names:
        capability_set.add("ripng")
    if "set_hsrp_ipv6" in router_op_names:
        capability_set.add("hsrp")
    if capability_set & {"vpn", "ipsec", "gre", "ppp", "security_edge"}:
        network_style = network_style or "wan_security"
    if capability_set & {"ipv6_slaac", "dhcpv6_stateful", "dhcpv6_stateless", "ospfv3", "eigrp_ipv6", "ripng", "hsrp"}:
        network_style = network_style or "ipv6_routing"
    if capability_set & {"mqtt", "real_http", "real_websocket", "visual_scripting", "ptp", "profinet", "l2nat", "cyberobserver", "industrial_firewall"}:
        network_style = "industrial_iot"

    capabilities = sorted(capability_set)

    parse_warnings: list[str] = []
    blocking_gaps: list[str] = []
    assumptions_used: list[str] = []
    if any(word in normalized_prompt for word in TOPOLOGY_HINT_WORDS) and not device_requirements and not devices:
        parse_warnings.append("Prompt includes topology words but no stable device counts were parsed.")
    if any(op["op"] == "set_management_vlan" for op in management_ops):
        topology_requirements["management_vlan"] = True

    pc_count = device_requirements.get("PC", 0)
    if department_groups and vlan_ids and len(vlan_ids) >= len(department_groups) and not host_vlan_assignment:
        for index, group in enumerate(department_groups):
            vlan_id = vlan_ids[index]
            host_vlan_assignment[vlan_id] = host_vlan_assignment.get(vlan_id, 0) + int(group["devices"].get("PC", 0))
        assumptions_used.append("Assigned each department's PCs to the matching VLAN order.")
    if vlan_ids and pc_count and not host_vlan_assignment and not any(op["op"] == "set_access_port" for op in switch_ops):
        blocking_gaps.append("Host-to-VLAN assignment is missing. Specify how many PCs belong to each VLAN.")
    if vlan_ids and not device_requirements.get("Switch", 0) and not any(device.get("type") == "Switch" for device in devices):
        blocking_gaps.append("VLAN planning requires at least one switch.")
    if department_groups and vlan_ids and len(vlan_ids) < len(department_groups):
        blocking_gaps.append("Department count is larger than provided VLAN IDs.")

    if department_groups and "Switch" not in device_counts:
        assumptions_used.append("Added one switch per department group.")
    if department_groups and not network_style:
        network_style = "campus"
        assumptions_used.append("Interpreted department-based prompt as campus style.")
    if network_style == "wan_security":
        assumptions_used.append("Interpreted VPN/WAN/security wording as WAN-security edge style.")

    goal = "edit" if pkt_path or any(word in normalized_prompt for word in ["deyis", "edit", "modify", "change", "rename", "update"]) else "generate"
    confidence_score = _estimate_confidence(device_requirements, capabilities, parse_warnings, blocking_gaps, devices, links)
    return IntentPlan(
        goal=goal,
        prompt=prompt,
        pkt_path=pkt_path,
        capabilities=capabilities,
        network_style=network_style,
        wireless_mode=wireless_mode,
        device_requirements=device_requirements,
        device_counts=device_counts,
        department_groups=department_groups,
        service_requirements=service_requirements,
        topology_requirements=topology_requirements,
        vlan_ids=vlan_ids,
        uplink_intent=uplink_intent,
        host_link_intent=host_link_intent,
        host_vlan_assignment=host_vlan_assignment,
        assumptions_used=assumptions_used,
        confidence_score=confidence_score,
        parse_warnings=parse_warnings,
        blocking_gaps=blocking_gaps,
        edit_operations=edit_operations,
        devices=devices,
        links=links,
        switch_ops=switch_ops,
        router_ops=router_ops,
        server_ops=server_ops,
        wireless_ops=wireless_ops,
        end_device_ops=end_device_ops,
        management_ops=management_ops,
        verification_ops=verification_ops,
        iot_ops=iot_ops,
    )
