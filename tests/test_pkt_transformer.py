from __future__ import annotations

import sys
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from packet_tracer_env import get_packet_tracer_compatibility_donor, get_packet_tracer_saves_root  # noqa: E402
from pkt_transformer import _canonical_port_name, _load_device_template, _port_address_for_name, _prototype_link_by_pair, load_sample_root  # noqa: E402


def _require_saves_root() -> Path:
    saves_root = get_packet_tracer_saves_root()
    if saves_root is None:
        pytest.skip("Packet Tracer sample saves not found")
    return saves_root


def test_canonical_port_name_expands_short_forms() -> None:
    assert _canonical_port_name("Fa0/1") == "FastEthernet0/1"
    assert _canonical_port_name("Gi0/1") == "GigabitEthernet0/1"


def test_port_address_for_gigabit_ports_does_not_raise() -> None:
    saves_root = _require_saves_root()
    switch_root = load_sample_root(saves_root / r"01 Networking\3650\HotSwappablePower.pkt")
    router_root = load_sample_root(saves_root / r"02 Infrastructure Automation\Network Controller\netcon.pkt")
    switch = next(device for device in switch_root.findall(".//DEVICES/DEVICE") if device.find("./ENGINE/TYPE") is not None and device.find("./ENGINE/TYPE").get("model", "") == "3650-24PS")
    router = next(device for device in router_root.findall(".//DEVICES/DEVICE") if device.find("./ENGINE/TYPE") is not None and device.find("./ENGINE/TYPE").get("model", "") == "2901")
    assert _port_address_for_name(switch, "GigabitEthernet1/0/1") in {None, "", _port_address_for_name(switch, "Gi1/0/1")}
    assert _port_address_for_name(router, "GigabitEthernet0/0") in {None, "", _port_address_for_name(router, "Gi0/0")}


def test_printer_template_exists_for_secondary_fallback() -> None:
    printer = _load_device_template("Printer")
    assert printer is not None
    assert printer.findtext("./ENGINE/TYPE") == "Printer"


def test_pc_template_is_synthesized_into_packet_tracer_device_shape() -> None:
    pc = _load_device_template("PC")
    assert pc is not None
    assert pc.findtext("./ENGINE/TYPE") == "PC"
    assert pc.findtext("./WORKSPACE/LOGICAL/X") is not None
    assert pc.findtext("./WORKSPACE/LOGICAL/MEM_ADDR") is not None


def test_router_and_switch_templates_are_synthesized_without_placeholders() -> None:
    router = _load_device_template("Router")
    switch = _load_device_template("Switch")

    assert router is not None
    assert switch is not None
    assert router.findtext("./ENGINE/TYPE") == "Router"
    assert switch.findtext("./ENGINE/TYPE") == "Switch"
    assert router.findtext("./WORKSPACE/LOGICAL/X") == "200"
    assert switch.findtext("./WORKSPACE/LOGICAL/Y") == "200"
    assert router.findtext("./ENGINE/RUNNINGCONFIG/LINE") == "hostname Router0"
    assert switch.findtext("./ENGINE/FILE_CONTENT/CONFIG/LINE") == "hostname Switch0"
    assert "__X__" not in ET.tostring(router, encoding="unicode")
    assert "__Y__" not in ET.tostring(switch, encoding="unicode")


def test_strict_9_donor_link_preserves_save_ref_schema() -> None:
    donor = get_packet_tracer_compatibility_donor()
    if donor is None:
        pytest.skip("Compatibility donor not found")
    link = _prototype_link_by_pair(str(donor), "Switch", "Router")
    cable = link.find("./CABLE")
    assert cable is not None
    assert cable.findtext("FROM", "").startswith("save-ref-id:")
    assert cable.find("FUNCTIONAL") is not None
    assert cable.find("GEO_VIEW_COLOR") is not None
    assert cable.find("IS_MANAGED_IN_RACK_VIEW") is not None
