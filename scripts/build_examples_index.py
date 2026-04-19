from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = ROOT / "examples"
SCREENSHOTS_DIR = EXAMPLES_DIR / "screenshots"
INDEX_PATH = EXAMPLES_DIR / "index.json"
GALLERY_PATH = EXAMPLES_DIR / "gallery.md"


TITLE_BY_FAMILY = {
    "campus": "Complex Campus",
    "home_iot": "Home IoT",
    "service_heavy": "Service Heavy",
}

SUMMARY_BY_FAMILY = {
    "campus": "Management VLAN, Telnet, ACL, DNS, email, AAA, and multi-SSID wireless campus edit.",
    "home_iot": "Home gateway and IoT device onboarding with gateway-backed registration state.",
    "service_heavy": "Service-rich server lab with DNS, DHCP, FTP, email, syslog, AAA, and detailed service metadata.",
}

CAPABILITIES_BY_FAMILY = {
    "campus": [
        "management_vlan",
        "telnet",
        "acl",
        "server_dns",
        "server_email",
        "server_aaa",
        "wireless_mutation",
    ],
    "home_iot": [
        "iot",
        "iot_registration",
        "wireless_ap",
    ],
    "service_heavy": [
        "server_dns",
        "server_dhcp",
        "server_ftp",
        "server_email",
        "server_syslog",
        "server_aaa",
    ],
}


def _manifest_files() -> list[Path]:
    return sorted(
        path
        for path in EXAMPLES_DIR.glob("*.inventory.json")
        if path.is_file()
    )


def _detect_screenshot(example_name: str) -> str | None:
    candidate = SCREENSHOTS_DIR / f"{example_name}.png"
    if candidate.exists():
        return candidate.relative_to(ROOT).as_posix()
    return None


def _build_entry(manifest_path: Path) -> dict[str, object]:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    name = str(payload["example_name"])
    family = str(payload.get("scenario_family") or payload.get("topology_summary", {}).get("network_style") or "general")
    return {
        "name": name,
        "title": TITLE_BY_FAMILY.get(family, name.replace("_", " ").title()),
        "scenario_family": family,
        "summary": SUMMARY_BY_FAMILY.get(family, f"Curated {family} example manifest."),
        "capabilities": CAPABILITIES_BY_FAMILY.get(family, []),
        "inventory_json": manifest_path.relative_to(ROOT).as_posix(),
        "screenshot": _detect_screenshot(name),
    }


def build_examples_index() -> dict[str, object]:
    return {
        "curated_examples": [
            _build_entry(path)
            for path in _manifest_files()
        ]
    }


def build_examples_gallery_markdown(payload: dict[str, object]) -> str:
    pending_screenshots: list[str] = []
    lines = [
        "## Curated Example Gallery",
        "",
        "| Title | Family | Capabilities | Screenshot | Inventory |",
        "| --- | --- | --- | --- | --- |",
    ]
    for entry in payload["curated_examples"]:
        screenshot_path = entry.get("screenshot")
        if screenshot_path:
            screenshot_rel = Path(str(screenshot_path)).relative_to("examples").as_posix()
            screenshot = f"[image]({screenshot_rel})"
        else:
            screenshot = "pending"
            pending_screenshots.append(str(entry["name"]))
        inventory_rel = Path(str(entry["inventory_json"])).relative_to("examples").as_posix()
        inventory = f"[manifest]({inventory_rel})"
        capabilities = ", ".join(entry.get("capabilities") or [])
        lines.append(
            f"| {entry['title']} | `{entry['scenario_family']}` | {capabilities} | {screenshot} | {inventory} |"
        )
        lines.append(f"|  |  | {entry['summary']} |  |  |")
    if pending_screenshots:
        lines.extend(
            [
                "",
                "### Pending Screenshots",
                "",
            ]
        )
        for name in pending_screenshots:
            lines.append(f"- `{name}`")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    payload = build_examples_index()
    INDEX_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    GALLERY_PATH.write_text(build_examples_gallery_markdown(payload) + "\n", encoding="utf-8")
    print(f"Wrote {INDEX_PATH}")
    print(f"Wrote {GALLERY_PATH}")


if __name__ == "__main__":
    main()
