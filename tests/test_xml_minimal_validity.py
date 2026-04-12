from __future__ import annotations

import json
import sys
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from pkt_builder import build_packet_tracer_xml  # noqa: E402


def test_builder_emits_expected_sections() -> None:
    blueprint = json.loads((ROOT / "examples" / "blueprint_minimal.json").read_text(encoding="utf-8"))
    xml_bytes = build_packet_tracer_xml(blueprint)
    root = ET.fromstring(xml_bytes)
    assert root.tag == "PACKETTRACER5"
    assert root.findtext("VERSION") is not None
    assert root.find("NETWORK/DEVICES") is not None
    assert root.find("NETWORK/LINKS") is not None
    assert root.find("NETWORK/DEVICES/DEVICE") is not None
    assert root.find("NETWORK/LINKS/LINK") is not None
