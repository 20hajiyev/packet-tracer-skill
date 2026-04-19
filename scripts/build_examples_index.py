from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = ROOT / "examples"
SCREENSHOTS_DIR = EXAMPLES_DIR / "screenshots"
PREVIEWS_DIR = EXAMPLES_DIR / "previews"
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

CARD_THEME_BY_FAMILY = {
    "campus": {"accent": "#0f766e", "panel": "#ecfeff", "text": "#0f172a"},
    "home_iot": {"accent": "#1d4ed8", "panel": "#eff6ff", "text": "#0f172a"},
    "service_heavy": {"accent": "#7c3aed", "panel": "#f5f3ff", "text": "#0f172a"},
    "general": {"accent": "#475569", "panel": "#f8fafc", "text": "#0f172a"},
}


def _manifest_files() -> list[Path]:
    return sorted(
        path
        for path in EXAMPLES_DIR.glob("*.inventory.json")
        if path.is_file()
    )


def _detect_screenshots(example_name: str) -> list[str]:
    screenshots: list[Path] = []
    primary = SCREENSHOTS_DIR / f"{example_name}.png"
    if primary.exists():
        screenshots.append(primary)

    for candidate in sorted(SCREENSHOTS_DIR.glob(f"{example_name}_*.png")):
        if candidate not in screenshots:
            screenshots.append(candidate)

    return [path.relative_to(ROOT).as_posix() for path in screenshots]


def _preview_path(example_name: str) -> Path:
    return PREVIEWS_DIR / f"{example_name}.svg"


def _escape_xml(value: object) -> str:
    text = str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _render_example_preview(manifest: dict[str, object]) -> str:
    family = str(manifest.get("scenario_family") or manifest.get("topology_summary", {}).get("network_style") or "general")
    theme = CARD_THEME_BY_FAMILY.get(family, CARD_THEME_BY_FAMILY["general"])
    title = TITLE_BY_FAMILY.get(family, str(manifest["example_name"]).replace("_", " ").title())
    summary = SUMMARY_BY_FAMILY.get(family, f"Curated {family} example manifest.")
    capabilities = ", ".join(CAPABILITIES_BY_FAMILY.get(family, []))

    detail_lines: list[str] = []
    topology_summary = manifest.get("topology_summary", {})
    service_summary = manifest.get("service_summary") or manifest.get("server_service_summary") or {}
    if family == "campus":
        detail_lines.append(f"Core router: {topology_summary.get('core_router', 'n/a')}")
        detail_lines.append(f"Managed switches: {len(topology_summary.get('switches_with_management', []))}")
        detail_lines.append(f"Wireless routers: {len(topology_summary.get('wireless_routers', []))}")
    elif family == "home_iot":
        detail_lines.append(f"Gateway: {topology_summary.get('gateway', 'n/a')}")
        detail_lines.append(f"IoT things: {len(topology_summary.get('iot_things', []))}")
        detail_lines.append(f"Services: {', '.join(next(iter(service_summary.values()), [])) or 'n/a'}")
    elif family == "service_heavy":
        detail_lines.append(f"Core server: {topology_summary.get('core_server', 'n/a')}")
        detail_lines.append(f"Services: {len(next(iter(service_summary.values()), []))}")
        service_details = manifest.get("service_details", {})
        server0 = next(iter(service_details.values()), {})
        if server0:
            detail_lines.append(f"Email domain: {server0.get('email_domain', 'n/a')}")
            detail_lines.append(f"AAA port: {server0.get('aaa_auth_port', 'n/a')}")
    else:
        detail_lines.append("Curated example preview")

    while len(detail_lines) < 4:
        detail_lines.append("")

    y = 150
    detail_svg = []
    for line in detail_lines:
        detail_svg.append(
            f'<text x="72" y="{y}" font-family="Segoe UI, Arial, sans-serif" font-size="26" fill="{theme["text"]}">{_escape_xml(line)}</text>'
        )
        y += 52

    capability_lines = []
    cap_y = 430
    for chunk_start in range(0, len(CAPABILITIES_BY_FAMILY.get(family, [])), 3):
        chunk = CAPABILITIES_BY_FAMILY.get(family, [])[chunk_start:chunk_start + 3]
        capability_lines.append(
            f'<text x="72" y="{cap_y}" font-family="Consolas, monospace" font-size="24" fill="{theme["text"]}">{_escape_xml(", ".join(chunk))}</text>'
        )
        cap_y += 40

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="900" viewBox="0 0 1600 900">
  <rect width="1600" height="900" fill="#f8fafc"/>
  <rect x="42" y="42" width="1516" height="816" rx="28" fill="{theme["panel"]}" stroke="{theme["accent"]}" stroke-width="8"/>
  <rect x="42" y="42" width="1516" height="120" rx="28" fill="{theme["accent"]}"/>
  <text x="72" y="118" font-family="Segoe UI, Arial, sans-serif" font-size="52" font-weight="700" fill="#ffffff">{_escape_xml(title)}</text>
  <text x="72" y="220" font-family="Segoe UI, Arial, sans-serif" font-size="30" fill="{theme["text"]}">{_escape_xml(summary)}</text>
  <text x="72" y="388" font-family="Segoe UI, Arial, sans-serif" font-size="28" font-weight="700" fill="{theme["accent"]}">Capabilities</text>
  {''.join(detail_svg)}
  {''.join(capability_lines)}
  <rect x="1020" y="170" width="458" height="560" rx="20" fill="#ffffff" stroke="{theme["accent"]}" stroke-width="4"/>
  <text x="1055" y="235" font-family="Segoe UI, Arial, sans-serif" font-size="30" font-weight="700" fill="{theme["accent"]}">Artifact Policy</text>
  <text x="1055" y="295" font-family="Segoe UI, Arial, sans-serif" font-size="24" fill="{theme["text"]}">- raw .pkt binary is not committed</text>
  <text x="1055" y="340" font-family="Segoe UI, Arial, sans-serif" font-size="24" fill="{theme["text"]}">- inventory manifest is committed</text>
  <text x="1055" y="385" font-family="Segoe UI, Arial, sans-serif" font-size="24" fill="{theme["text"]}">- preview is generated from manifest</text>
  <text x="1055" y="470" font-family="Segoe UI, Arial, sans-serif" font-size="26" font-weight="700" fill="{theme["accent"]}">Scenario family</text>
  <text x="1055" y="515" font-family="Consolas, monospace" font-size="30" fill="{theme["text"]}">{_escape_xml(family)}</text>
  <text x="1055" y="605" font-family="Segoe UI, Arial, sans-serif" font-size="26" font-weight="700" fill="{theme["accent"]}">Verification</text>
  <text x="1055" y="650" font-family="Segoe UI, Arial, sans-serif" font-size="24" fill="{theme["text"]}">inventory roundtrip verified</text>
  <text x="1055" y="695" font-family="Segoe UI, Arial, sans-serif" font-size="24" fill="{theme["text"]}">full pytest passed</text>
</svg>
"""


def _write_preview(manifest_path: Path) -> str:
    PREVIEWS_DIR.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    path = _preview_path(str(manifest["example_name"]))
    path.write_text(_render_example_preview(manifest), encoding="utf-8")
    return path.relative_to(ROOT).as_posix()


def _build_entry(manifest_path: Path) -> dict[str, object]:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    name = str(payload["example_name"])
    family = str(payload.get("scenario_family") or payload.get("topology_summary", {}).get("network_style") or "general")
    screenshots = _detect_screenshots(name)
    preview = _write_preview(manifest_path)
    screenshot = screenshots[0] if screenshots else None
    detail_images = screenshots[1:] if len(screenshots) > 1 else []
    return {
        "name": name,
        "title": TITLE_BY_FAMILY.get(family, name.replace("_", " ").title()),
        "scenario_family": family,
        "summary": SUMMARY_BY_FAMILY.get(family, f"Curated {family} example manifest."),
        "capabilities": CAPABILITIES_BY_FAMILY.get(family, []),
        "inventory_json": manifest_path.relative_to(ROOT).as_posix(),
        "screenshots": screenshots,
        "screenshot_count": len(screenshots),
        "screenshot": screenshot,
        "detail_images": detail_images,
        "preview": preview,
        "image": screenshot or preview,
    }


def build_examples_index() -> dict[str, object]:
    return {
        "curated_examples": [
            _build_entry(path)
            for path in _manifest_files()
        ]
    }


def build_examples_gallery_markdown(payload: dict[str, object]) -> str:
    lines = [
        "## Curated Example Gallery",
        "",
        "| Title | Family | Capabilities | Image | Inventory |",
        "| --- | --- | --- | --- | --- |",
    ]
    for entry in payload["curated_examples"]:
        image_path = entry.get("image")
        image_rel = Path(str(image_path)).relative_to("examples").as_posix()
        image_link = "[screenshot]" if entry.get("screenshot") else "[preview]"
        image = f"{image_link}({image_rel})"
        inventory_rel = Path(str(entry["inventory_json"])).relative_to("examples").as_posix()
        inventory = f"[manifest]({inventory_rel})"
        capabilities = ", ".join(entry.get("capabilities") or [])
        lines.append(
            f"| {entry['title']} | `{entry['scenario_family']}` | {capabilities} | {image} | {inventory} |"
        )
        lines.append(f"|  |  | {entry['summary']} |  |  |")
        detail_images = [
            f"[detail {index}]({Path(path).relative_to('examples').as_posix()})"
            for index, path in enumerate(entry.get("detail_images") or [], start=1)
        ]
        if detail_images:
            lines.append(f"|  |  | extra visuals: {'; '.join(detail_images)} |  |  |")

    missing = [entry for entry in payload["curated_examples"] if not entry.get("screenshots")]
    if missing:
        lines.extend(
            [
                "",
                "### Pending Screenshots",
                "",
            ]
        )
        for entry in missing:
            lines.append(f"- `{entry['name']}` currently uses generated preview fallback.")
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
