from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET

from packet_tracer_env import require_packet_tracer_saves_root
from pkt_codec import decode_pkt_modern
from sample_catalog import write_catalog_outputs


def summarize_pkt(path: Path) -> dict:
    saves_root = require_packet_tracer_saves_root()
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
        "relative_path": str(path.relative_to(saves_root)),
        "version": root.findtext("./VERSION", default=""),
        "device_count": len(devices),
        "link_count": len(links),
        "devices": devices,
        "links": links,
    }


def build_catalog() -> list[dict]:
    saves_root = require_packet_tracer_saves_root()
    items = []
    for path in sorted(saves_root.rglob("*.pkt")):
        try:
            items.append(summarize_pkt(path))
        except Exception as exc:
            items.append({"relative_path": str(path.relative_to(saves_root)), "error": f"{type(exc).__name__}: {exc}"})
    return items


def main() -> None:
    require_packet_tracer_saves_root()
    items = build_catalog()
    write_catalog_outputs(items)
    print(f"Wrote {len(items)} sample entries")


if __name__ == "__main__":
    main()
