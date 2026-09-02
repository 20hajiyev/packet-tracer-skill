"""Cross-check the facts a lab states about itself in more than one place.

Every defect this project has paid for has the same shape: one fact derived
twice, in two passes, with nothing comparing the derivations. A port's VLAN and
its host's address. A pool's network and the interface that serves it. A
bundle's members and the cables that join them. Each half read correctly on its
own, the lab opened, every static check passed, and nothing could reach
anything.

The checks below are not a style guide. Each one is a contradiction that was
measured in a generated lab and cost a working network:

  * a printer in VLAN 200 holding a 192.168.110.x address, because the port's
    VLAN and the host's address were assigned by different passes
  * four routers carrying 10.10.10.1 as a real interface address while it is
    also the HSRP virtual address on a fifth
  * `channel-group 1 mode on` on a port whose peer was not bundling, which took
    the switch behind it off the network
  * a DHCP pool for a network no interface serves
  * two cables on one switch port
  * a config block for an interface the device does not have

Findings are reported, never repaired: a checker that fixes what it finds stops
being able to tell you whether the thing it checks is working.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

SWITCH_TYPES = {"Switch", "MultiLayerSwitch"}
HOST_TYPES = {"Pc", "Laptop", "Server", "Printer", "IpPhone", "Tablet", "Smartphone"}


@dataclass(frozen=True)
class Finding:
    """One contradiction, named by the two things that disagree."""

    kind: str
    where: str
    detail: str

    def __str__(self) -> str:
        return f"{self.kind}: {self.where} -- {self.detail}"


def _address_to_int(text: str) -> int | None:
    parts = (text or "").strip().split(".")
    if len(parts) != 4:
        return None
    value = 0
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return None
        value = (value << 8) | int(part)
    return value


def _network_of(address: str, mask: str) -> tuple[int, int] | None:
    left, right = _address_to_int(address), _address_to_int(mask)
    if left is None or right is None:
        return None
    return left & right, right


def _name(device: ET.Element) -> str:
    return (device.findtext("./ENGINE/NAME") or "").strip()


def _kind(device: ET.Element) -> str:
    return (device.findtext("./ENGINE/TYPE") or "").strip()


def _config_blocks(device: ET.Element) -> dict[str, list[str]]:
    """Interface name -> the lines inside its block, in file order."""
    blocks: dict[str, list[str]] = {}
    current = ""
    for node in device.findall("./ENGINE/RUNNINGCONFIG/LINE"):
        text = (node.text or "").strip()
        if text.startswith("interface "):
            current = text.split(None, 1)[1]
            blocks.setdefault(current, [])
        elif current and text and not text.startswith("!"):
            blocks.setdefault(current, []).append(text)
        elif text.startswith("!"):
            current = ""
    return blocks


def _interface_addresses(device: ET.Element) -> list[tuple[str, str, str]]:
    """(port, address, mask) for every configured interface address."""
    found: list[tuple[str, str, str]] = []
    for port, body in _config_blocks(device).items():
        for line in body:
            match = re.match(r"^ip address (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)$", line)
            if match:
                found.append((port, match.group(1), match.group(2)))
    return found


def _standby_addresses(device: ET.Element) -> list[tuple[str, str]]:
    """(port, virtual address) for every HSRP group."""
    found: list[tuple[str, str]] = []
    for port, body in _config_blocks(device).items():
        for line in body:
            match = re.match(r"^standby \d+ ip (\d+\.\d+\.\d+\.\d+)$", line)
            if match:
                found.append((port, match.group(1)))
    return found


def _host_addresses(device: ET.Element) -> list[tuple[str, str, str]]:
    """(port name, address, mask) a host carries on its sockets."""
    found: list[tuple[str, str, str]] = []
    for port in device.findall(".//PORT"):
        address = (port.findtext("IP") or "").strip()
        mask = (port.findtext("SUBNET") or "").strip()
        if address and address != "0.0.0.0":
            found.append(((port.findtext("NAME") or "").strip(), address, mask))
    return found


def _cabled_ports(root: ET.Element) -> dict[tuple[str, str], list[tuple[str, str]]]:
    """(device, port) -> the far ends cabled to it. More than one is a defect."""
    by_ref = {
        (device.findtext("./ENGINE/SAVE_REF_ID") or "").strip(): device
        for device in root.findall(".//DEVICES/DEVICE")
    }
    ends: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for link in root.findall(".//LINKS/LINK"):
        cable = link.find("./CABLE")
        if cable is None:
            continue
        refs = [(cable.findtext(tag) or "").strip() for tag in ("FROM", "TO")]
        ports = [node.text or "" for node in cable.findall("PORT")]
        if len(ports) < 2:
            continue
        left, right = by_ref.get(refs[0]), by_ref.get(refs[1])
        if left is None or right is None:
            continue
        ends.setdefault((_name(left), ports[0]), []).append((_name(right), ports[1]))
        ends.setdefault((_name(right), ports[1]), []).append((_name(left), ports[0]))
    return ends


def _check_addresses_are_unique(devices: list[ET.Element]) -> list[Finding]:
    """No address may be held by two interfaces, or double as a virtual one.

    Measured on the enterprise lab: R6, R7 and R8 each carried 10.10.10.1 on a
    real subinterface while R1 offered the same address as its HSRP virtual
    gateway. Nothing complained, because the pass that wrote the subinterfaces
    and the pass that wrote HSRP each read correctly on its own.
    """
    real: dict[str, list[str]] = {}
    virtual: dict[str, list[str]] = {}
    for device in devices:
        for port, address, _mask in _interface_addresses(device):
            real.setdefault(address, []).append(f"{_name(device)}:{port}")
        if _kind(device) in HOST_TYPES:
            # A router's PORT node mirrors the address its config already
            # states. Counting both made every router interface look like two
            # holders of one address -- the checker's own version of the defect
            # it looks for.
            for _port, address, _mask in _host_addresses(device):
                real.setdefault(address, []).append(_name(device))
        for port, address in _standby_addresses(device):
            virtual.setdefault(address, []).append(f"{_name(device)}:{port}")

    findings: list[Finding] = []
    for address, holders in sorted(real.items()):
        if len(holders) > 1:
            findings.append(
                Finding("duplicate_address", address, f"held by {', '.join(sorted(holders))}")
            )
        if address in virtual:
            findings.append(
                Finding(
                    "real_address_is_also_virtual",
                    address,
                    f"real on {', '.join(sorted(holders))}; HSRP virtual on "
                    f"{', '.join(sorted(virtual[address]))}",
                )
            )
    return findings


def _check_ports_carry_one_cable(root: ET.Element) -> list[Finding]:
    """One socket, one cable. Two clones once shared a port and the lab refused."""
    findings: list[Finding] = []
    for (device, port), ends in sorted(_cabled_ports(root).items()):
        if len(ends) > 1:
            joined = ", ".join(f"{name}:{far}" for name, far in sorted(ends))
            findings.append(Finding("port_double_booked", f"{device}:{port}", f"cabled to {joined}"))
    return findings


def _check_config_names_real_ports(devices: list[ET.Element]) -> list[Finding]:
    """Packet Tracer refuses a lab naming an interface the device does not have."""
    from pkt_transformer import port_exists

    findings: list[Finding] = []
    for device in devices:
        for port in _config_blocks(device):
            if port.startswith(("Vlan", "Loopback", "Port-channel", "Tunnel")) or "." in port:
                continue
            if not port_exists(device, port):
                findings.append(
                    Finding("port_not_on_device", f"{_name(device)}:{port}", f"a {_kind(device)} has no such interface")
                )
    return findings


def _check_trunk_ends_agree(root: ET.Element, devices: list[ET.Element]) -> list[Finding]:
    """A native VLAN mismatch makes spanning tree block a cabled, configured port."""
    by_name = {_name(device): device for device in devices}
    blocks = {name: _config_blocks(device) for name, device in by_name.items()}

    def native(name: str, port: str) -> str:
        for line in blocks.get(name, {}).get(port, []):
            match = re.match(r"^switchport trunk native vlan (\d+)$", line)
            if match:
                return match.group(1)
        return "1"

    def is_trunk(name: str, port: str) -> bool:
        return "switchport mode trunk" in blocks.get(name, {}).get(port, [])

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for (device, port), ends in sorted(_cabled_ports(root).items()):
        for far_device, far_port in ends:
            key = tuple(sorted(((device, port), (far_device, far_port))))
            if key in seen:
                continue
            seen.add(key)
            if _kind(by_name.get(device, ET.Element("x"))) not in SWITCH_TYPES:
                continue
            if _kind(by_name.get(far_device, ET.Element("x"))) not in SWITCH_TYPES:
                continue
            if not (is_trunk(device, port) and is_trunk(far_device, far_port)):
                continue
            here, there = native(device, port), native(far_device, far_port)
            if here != there:
                findings.append(
                    Finding(
                        "native_vlan_mismatch",
                        f"{device}:{port} <-> {far_device}:{far_port}",
                        f"native VLAN {here} against {there}",
                    )
                )
    return findings


def _check_etherchannel_members_are_paired(root: ET.Element, devices: list[ET.Element]) -> list[Finding]:
    """A channel-group whose peer does not bundle takes the switch off the network."""
    blocks = {_name(device): _config_blocks(device) for device in devices}

    def bundles(name: str, port: str) -> bool:
        return any(line.startswith("channel-group ") for line in blocks.get(name, {}).get(port, []))

    findings: list[Finding] = []
    cabled = _cabled_ports(root)
    for (device, port), ends in sorted(cabled.items()):
        if not bundles(device, port):
            continue
        if not ends:
            findings.append(Finding("etherchannel_member_uncabled", f"{device}:{port}", "bundled but no cable"))
            continue
        for far_device, far_port in ends:
            if not bundles(far_device, far_port):
                findings.append(
                    Finding(
                        "etherchannel_peer_does_not_bundle",
                        f"{device}:{port}",
                        f"peer {far_device}:{far_port} carries no channel-group",
                    )
                )
    for device in devices:
        for port, body in _config_blocks(device).items():
            if any(line.startswith("channel-group ") for line in body) and (_name(device), port) not in cabled:
                findings.append(
                    Finding("etherchannel_member_uncabled", f"{_name(device)}:{port}", "bundled but no cable")
                )
    return findings


def _check_hosts_can_reach_their_gateway(devices: list[ET.Element]) -> list[Finding]:
    """A host's address, its mask and its gateway have to describe one network.

    Measured on the enterprise lab: a workstation sat on a port in VLAN 200 and
    carried 192.168.110.12, because the pass that placed ports in VLANs and the
    pass that handed out addresses each had its own plan and neither read the
    other's. The lab opened and the host could reach nothing off its subnet.
    """
    served: set[tuple[int, int]] = set()
    gateways: set[str] = set()
    for device in devices:
        for _port, address, mask in _interface_addresses(device):
            network = _network_of(address, mask)
            if network is not None:
                served.add(network)
            gateways.add(address)
        for _port, address in _standby_addresses(device):
            gateways.add(address)

    findings: list[Finding] = []
    for device in devices:
        if _kind(device) not in HOST_TYPES:
            continue
        gateway = (device.findtext(".//GATEWAY") or "").strip()
        for _port, address, mask in _host_addresses(device):
            if not gateway or gateway == "0.0.0.0":
                findings.append(Finding("host_without_gateway", _name(device), f"{address} has no default gateway"))
                continue
            here, there = _network_of(address, mask), _network_of(gateway, mask)
            if here is None or there is None or here != there:
                findings.append(
                    Finding(
                        "gateway_off_host_subnet",
                        _name(device),
                        f"{address}/{mask} cannot reach gateway {gateway}",
                    )
                )
                continue
            if gateway not in gateways:
                findings.append(
                    Finding("gateway_answers_for_nobody", _name(device), f"no interface holds {gateway}")
                )
    return findings


def _check_pools_have_an_interface(devices: list[ET.Element]) -> list[Finding]:
    """A pool for a network no interface serves hands out unreachable addresses."""
    served: set[tuple[int, int]] = set()
    for device in devices:
        for _port, address, mask in _interface_addresses(device):
            network = _network_of(address, mask)
            if network is not None:
                served.add(network)

    findings: list[Finding] = []
    for device in devices:
        pool = ""
        for node in device.findall("./ENGINE/RUNNINGCONFIG/LINE"):
            text = (node.text or "").strip()
            if text.startswith("ip dhcp pool "):
                pool = text.split(None, 3)[3] if len(text.split()) > 3 else text
                continue
            match = re.match(r"^network (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)$", text)
            if match and pool:
                network = _network_of(match.group(1), match.group(2))
                if network is not None and network not in served:
                    findings.append(
                        Finding(
                            "pool_without_interface",
                            f"{_name(device)} pool {pool}",
                            f"{match.group(1)} {match.group(2)} matches no interface",
                        )
                    )
                pool = ""
    return findings


def _check_no_interface_is_declared_twice(devices: list[ET.Element]) -> list[Finding]:
    """One interface, one block.

    IOS applies repeated blocks in order and keeps the last; every reader that
    scans for the first sees a different device. Measured on the enterprise
    lab: the standby router had each subinterface written five times, once per
    build, because a generated lab becomes the donor for the next one and the
    HSRP pass appended instead of merging. `10.10.40.1`, then `10.10.40.3`,
    then `10.10.40.1` again -- all of them true of the same file.
    """
    findings: list[Finding] = []
    for device in devices:
        counts: dict[str, int] = {}
        for node in device.findall("./ENGINE/RUNNINGCONFIG/LINE"):
            text = (node.text or "").strip()
            if text.startswith("interface "):
                port = text.split(None, 1)[1]
                counts[port] = counts.get(port, 0) + 1
        for port, count in sorted(counts.items()):
            if count > 1:
                findings.append(
                    Finding("interface_declared_twice", f"{_name(device)}:{port}", f"{count} blocks")
                )
    return findings


def check_lab_coherence(root: ET.Element) -> list[Finding]:
    """Every contradiction the lab states about itself, most structural first."""
    devices = root.findall(".//DEVICES/DEVICE")
    return [
        *_check_no_interface_is_declared_twice(devices),
        *_check_config_names_real_ports(devices),
        *_check_ports_carry_one_cable(root),
        *_check_addresses_are_unique(devices),
        *_check_trunk_ends_agree(root, devices),
        *_check_etherchannel_members_are_paired(root, devices),
        *_check_hosts_can_reach_their_gateway(devices),
        *_check_pools_have_an_interface(devices),
    ]


def summarise(findings: list[Finding]) -> str:
    if not findings:
        return "coherent: no contradictions found"
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.kind] = counts.get(finding.kind, 0) + 1
    parts = ", ".join(f"{kind} {count}" for kind, count in sorted(counts.items()))
    return f"{len(findings)} contradiction(s): {parts}"
