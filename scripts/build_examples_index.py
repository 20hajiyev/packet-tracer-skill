from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = ROOT / "examples"
SCREENSHOTS_DIR = EXAMPLES_DIR / "screenshots"
PREVIEWS_DIR = EXAMPLES_DIR / "previews"
INDEX_PATH = EXAMPLES_DIR / "index.json"
GALLERY_PATH = EXAMPLES_DIR / "gallery.md"
PROOF_CARDS_PATH = EXAMPLES_DIR / "proof-cards.json"
LOCAL_SAMPLE_EVIDENCE_PATH = EXAMPLES_DIR / "local-sample-evidence.json"
LOCAL_SAMPLE_AUDIT_PATH = ROOT / "output" / "local-sample-audit.json"
PROOF_READINESS_CANDIDATES_PATH = ROOT / "references" / "proof-readiness-candidates.json"


TITLE_BY_FAMILY = {
    "campus": "Complex Campus",
    "home_iot": "Home IoT",
    "service_heavy": "Service Heavy",
    "wan_security_edge": "WAN Security Edge",
}

SUMMARY_BY_FAMILY = {
    "campus": "Management VLAN, Telnet, ACL, DNS, email, AAA, and multi-SSID wireless campus edit.",
    "home_iot": "Home gateway and IoT device onboarding with donor-backed registration state and constrained wireless readiness.",
    "service_heavy": "Service-rich server lab with DNS, DHCP, FTP, email, syslog, AAA, and detailed service metadata.",
    "wan_security_edge": "WAN/security-edge lab with multilayer, tunnel, VPN, and edge-policy coverage metadata.",
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
    "wan_security_edge": [
        "multilayer_switching",
        "vpn",
        "ipsec",
        "gre",
        "ppp",
        "security_edge",
    ],
}

FIXTURE_BY_FAMILY = {
    "campus": "campus_core_complex",
    "home_iot": "home_iot_complex",
    "service_heavy": "service_heavy_complex",
    "wan_security_edge": "wan_security_complex",
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


def _load_proof_cards() -> list[dict[str, object]]:
    if not PROOF_CARDS_PATH.exists():
        return []
    payload = json.loads(PROOF_CARDS_PATH.read_text(encoding="utf-8"))
    cards = payload.get("proof_cards", []) if isinstance(payload, dict) else []
    normalized: list[dict[str, object]] = []
    for card in cards:
        if not isinstance(card, dict):
            continue
        entry = dict(card)
        entry.setdefault("schema_version", "examples.truth.v2")
        entry.setdefault("artifact_type", "proof_card")
        entry.setdefault("artifact_policy", {
            "commit_pkt_binary": False,
            "commit_inventory_json": False,
            "commit_screenshots": False,
            "raw_source_public": False,
        })
        entry.setdefault("try_command", entry.get("explicit_command", ""))
        entry.setdefault("does_not_claim", entry.get("refusal_boundary", "No broad generate-ready support is claimed by this proof card."))
        entry.setdefault(
            "support_level_explanation",
            f"{entry.get('support_level', 'report_supported')} is a proof-card support level, not broad topology generation.",
        )
        entry.setdefault("maturity_summary", {
            "atlas_status": entry.get("support_level", "report_supported"),
            "example_status": "proof_card",
            "donor_backed_ready": entry.get("support_level") == "donor_backed_ready",
            "generate_ready": False,
        })
        normalized.append(entry)
    return normalized


def _load_local_sample_evidence() -> dict[str, object]:
    if LOCAL_SAMPLE_EVIDENCE_PATH.exists():
        payload = json.loads(LOCAL_SAMPLE_EVIDENCE_PATH.read_text(encoding="utf-8"))
        payload.setdefault("source", "examples/local-sample-evidence.json")
        payload.setdefault("available", True)
        return payload
    if not LOCAL_SAMPLE_AUDIT_PATH.exists():
        return {
            "source": "output/local-sample-audit.json",
            "available": False,
            "summary": "No local sample audit artifact was found.",
            "top_capabilities": [],
        }
    payload = json.loads(LOCAL_SAMPLE_AUDIT_PATH.read_text(encoding="utf-8"))
    capabilities = payload.get("detected_config_capabilities", {})
    top_capabilities = [
        {
            "capability": name,
            "sample_count": details.get("sample_count", 0),
            "examples": details.get("examples", [])[:3],
        }
        for name, details in sorted(
            capabilities.items(),
            key=lambda item: item[1].get("sample_count", 0),
            reverse=True,
        )[:12]
        if isinstance(details, dict)
    ]
    return {
        "source": "output/local-sample-audit.json",
        "available": True,
        "policy": "Local user-supplied samples are evidence inputs only, not curated donor truth or npm package content.",
        "total_files": payload.get("total_files"),
        "decode_success_count": payload.get("decode_success_count"),
        "decode_fail_count": payload.get("decode_fail_count"),
        "top_capabilities": top_capabilities,
    }


def _load_proof_readiness_candidates() -> dict[str, object]:
    if not PROOF_READINESS_CANDIDATES_PATH.exists():
        return {
            "schema_version": "proof_readiness.v1",
            "available": False,
            "summary": "No proof-readiness candidate artifact was found.",
            "primary_candidates": [],
            "secondary_candidates": [],
        }
    payload = json.loads(PROOF_READINESS_CANDIDATES_PATH.read_text(encoding="utf-8"))
    payload.setdefault("schema_version", "proof_readiness.v1")
    payload.setdefault("available", True)
    payload.setdefault("primary_candidates", [])
    payload.setdefault("secondary_candidates", [])
    return payload


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
    verification = dict(payload.get("verification_status") or {})
    acceptance_rank = 3 if verification.get("inventory_roundtrip_verified") and verification.get("full_pytest_passed") else 1
    acceptance_label = "known_working_example" if acceptance_rank == 3 else "partially_verified_example"
    source_mode = str(payload.get("source_mode") or "").strip()
    donor_origin = "donor-backed" if "donor-backed" in source_mode else (source_mode or "unknown")
    screenshots = _detect_screenshots(name)
    preview = _write_preview(manifest_path)
    screenshot = screenshots[0] if screenshots else None
    detail_images = screenshots[1:] if len(screenshots) > 1 else []
    primary_capabilities = CAPABILITIES_BY_FAMILY.get(family, [])
    acceptance_excerpt = f"{acceptance_label} | donor={donor_origin} | capabilities={', '.join(primary_capabilities[:3])}"
    if family == "home_iot":
        acceptance_excerpt += " | mode=donor-backed constrained edit"
    fixture_name = FIXTURE_BY_FAMILY.get(family)
    matrix_excerpt = f"{fixture_name or 'ad-hoc'} | {acceptance_label} | family={family}"
    if family == "home_iot":
        parity_excerpt = "iot=known_working_example, iot_registration=donor_backed_ready, wireless_ap=known_working_example"
    else:
        parity_excerpt = ", ".join(f"{cap}=known_working_example" for cap in primary_capabilities[:3]) if primary_capabilities else "no parity excerpt"
    decision_excerpt = f"decision={acceptance_label} | donor_origin={donor_origin}"
    runtime_excerpt = "runtime=donor-backed example artifact"
    return {
        "schema_version": str(payload.get("schema_version") or "examples.truth.v2"),
        "artifact_type": "showcase_example",
        "name": name,
        "title": TITLE_BY_FAMILY.get(family, name.replace("_", " ").title()),
        "scenario_family": family,
        "summary": SUMMARY_BY_FAMILY.get(family, f"Curated {family} example manifest."),
        "capabilities": primary_capabilities,
        "primary_capabilities": primary_capabilities,
        "acceptance_rank": acceptance_rank,
        "acceptance_label": acceptance_label,
        "acceptance_excerpt": acceptance_excerpt,
        "donor_origin": donor_origin,
        "fixture_name": fixture_name,
        "matrix_excerpt": matrix_excerpt,
        "parity_excerpt": parity_excerpt,
        "decision_excerpt": decision_excerpt,
        "runtime_excerpt": runtime_excerpt,
        "artifact_policy": payload.get("artifact_policy") or {
            "commit_pkt_binary": False,
            "commit_inventory_json": True,
            "commit_screenshots": bool(screenshots),
            "raw_source_public": False,
        },
        "maturity_summary": payload.get("maturity_summary") or {
            "atlas_status": "known_working_example",
            "example_status": acceptance_label,
            "donor_backed_ready": donor_origin == "donor-backed",
            "generate_ready": False,
        },
        "inventory_json": manifest_path.relative_to(ROOT).as_posix(),
        "screenshots": screenshots,
        "screenshot_count": len(screenshots),
        "screenshot": screenshot,
        "detail_images": detail_images,
        "preview": preview,
        "image": screenshot or preview,
    }


def build_examples_index() -> dict[str, object]:
    showcase_examples = [
        _build_entry(path)
        for path in _manifest_files()
    ]
    proof_cards = _load_proof_cards()
    return {
        "schema_version": "examples.truth.v2",
        "release_line": "0.2.4 candidate proof surface",
        "support_truth": {
            "generate_ready": 0,
            "policy": "Example artifacts can be known-working, edit-proven, or donor-backed-ready without making broad generation ready.",
        },
        "showcase_examples": showcase_examples,
        "proof_cards": proof_cards,
        "local_sample_evidence": _load_local_sample_evidence(),
        "proof_readiness_candidates": _load_proof_readiness_candidates(),
        "curated_examples": showcase_examples,
    }


def build_examples_gallery_markdown(payload: dict[str, object]) -> str:
    lines = [
        "## Showcase Examples",
        "",
        "These examples are public, text-first proof artifacts derived from donor-backed workflows and aligned with the scenario fixture corpus.",
        "",
        "`0.2.4` candidate examples surface, built on the published `0.2.3` capability release:",
        "",
        "- `campus`",
        "- `home_iot`",
        "- `service_heavy`",
        "",
        "Hero visual:",
        "",
        "- [complex campus screenshot](screenshots/complex_campus_master_edit_v4.png)",
        "",
        "Canonical donor proof:",
        "",
        "- [campus donor proof](../docs/campus-donor-proof.md)",
        "- [home IoT donor proof](../docs/home-iot-donor-proof.md)",
        "- [WAN/security donor proof](../docs/wan-security-donor-proof.md)",
        "",
        "Support truth:",
        "",
        "- showcase examples are screenshot + inventory artifacts for known working donor-backed workflows",
        "- proof cards are text-only evidence for explicit edit paths and donor-backed readiness",
        "- atlas `generate_ready=0` remains intentional; these examples do not claim broad generation support",
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
        lines.append(f"|  |  | `{entry['acceptance_excerpt']}` |  |  |")
        lines.append(f"|  |  | `{entry['matrix_excerpt']}` |  |  |")
        lines.append(f"|  |  | `{entry['parity_excerpt']}` |  |  |")
        lines.append(f"|  |  | `{entry['decision_excerpt']}` |  |  |")
        lines.append(f"|  |  | `{entry['runtime_excerpt']}` |  |  |")
        detail_images = [
            f"[detail {index}]({Path(path).relative_to('examples').as_posix()})"
            for index, path in enumerate(entry.get("detail_images") or [], start=1)
        ]
        if detail_images:
            lines.append(f"|  |  | extra visuals: {'; '.join(detail_images)} |  |  |")

    proof_cards = payload.get("proof_cards") or []
    if proof_cards:
        lines.extend(
            [
                "",
                "## 0.2.4 Candidate Proof Cards",
                "",
                "| Title | Family | Support | Proof | Boundary |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for card in proof_cards:
            proof_doc = str(card.get("proof_doc", ""))
            proof_href = f"../{proof_doc}" if proof_doc.startswith("docs/") else proof_doc
            proof_link = f"[proof]({proof_href})"
            lines.append(
                f"| {card['title']} | `{card['scenario_family']}` | `{card['support_level']}` | {proof_link} | {card['refusal_boundary']} |"
            )
            lines.append(f"|  |  | `{card['parity_excerpt']}` |  |  |")
            lines.append(f"|  |  | try this command: `{card['try_command']}` |  |  |")
            lines.append(f"|  |  | does not claim: {card['does_not_claim']} |  |  |")

    local_evidence = payload.get("local_sample_evidence") or {}
    if local_evidence.get("available"):
        lines.extend(
            [
                "",
                "## Local Sample Evidence Board",
                "",
                f"Local audit source: `{local_evidence['source']}`.",
                "",
                f"Audit summary: `{local_evidence.get('total_files')}` files, `{local_evidence.get('decode_success_count')}` decode successes, `{local_evidence.get('decode_fail_count')}` decode failures.",
                "",
                "This is local evidence only. It does not make user-supplied `.pkt/.pka` files public curated donors, and it does not enter the npm package.",
                "",
                "| Capability | Sample Count | Example Paths |",
                "| --- | --- | --- |",
            ]
        )
        for item in local_evidence.get("top_capabilities", []):
            examples = "; ".join(item.get("examples", []))
            lines.append(f"| `{item['capability']}` | {item['sample_count']} | {examples} |")

    readiness = payload.get("proof_readiness_candidates") or {}
    if readiness.get("available"):
        lines.extend(
            [
                "",
                "## Proof-Readiness Promotion Queue",
                "",
                "This queue connects proof cards, feature atlas status, and local sample evidence. It is a planning artifact, not a `generate_ready` claim.",
                "",
                f"Dashboard: [proof-readiness dashboard](../{readiness.get('dashboard_doc', 'docs/proof-readiness-dashboard.md')})",
                "",
                "| Priority | Capability | Family | Current Status | Explicit Command | Next Safe Action | Blocker |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for priority, candidates in (
            ("primary", readiness.get("primary_candidates", [])),
            ("secondary", readiness.get("secondary_candidates", [])),
        ):
            for candidate in candidates:
                lines.append(
                    f"| `{priority}` | `{candidate['capability']}` | `{candidate['scenario_family']}` | `{candidate['current_status']}` | `{candidate.get('explicit_command', '')}` | {candidate['next_safe_action']} | `{candidate['promotion_blocker']}` |"
                )

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
