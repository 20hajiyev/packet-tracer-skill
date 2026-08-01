from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_examples_index import build_examples_gallery_markdown, build_examples_index  # noqa: E402


def test_build_examples_index_covers_curated_examples() -> None:
    payload = build_examples_index()
    names = {entry["name"] for entry in payload["curated_examples"]}
    assert {"complex_campus_master_edit_v4", "home_iot_cli_edit_v1", "service_heavy_cli_edit_v1"} <= names


def test_build_examples_index_detects_existing_screenshot() -> None:
    payload = build_examples_index()
    campus = next(entry for entry in payload["curated_examples"] if entry["name"] == "complex_campus_master_edit_v4")
    assert campus["screenshot"] == "examples/screenshots/complex_campus_master_edit_v4.png"
    assert campus["image"] == "examples/screenshots/complex_campus_master_edit_v4.png"
    assert campus["screenshots"] == ["examples/screenshots/complex_campus_master_edit_v4.png"]
    assert campus["screenshot_count"] == 1
    assert campus["detail_images"] == []
    assert campus["capabilities"]
    assert campus["acceptance_rank"] == 3
    assert campus["acceptance_label"] == "known_working_example"
    assert campus["acceptance_excerpt"].startswith("known_working_example | donor=donor-backed")
    assert campus["fixture_name"] == "campus_core_complex"
    assert "campus_core_complex" in campus["matrix_excerpt"]
    assert "management_vlan=known_working_example" in campus["parity_excerpt"]
    assert "decision=known_working_example" in campus["decision_excerpt"]
    assert "runtime=donor-backed example artifact" == campus["runtime_excerpt"]
    assert campus["donor_origin"] == "donor-backed"
    assert campus["primary_capabilities"] == campus["capabilities"]
    assert campus["schema_version"] == "examples.truth.v2"
    assert campus["artifact_type"] == "showcase_example"
    assert campus["maturity_summary"]["generate_ready"] is False

    home_iot = next(entry for entry in payload["curated_examples"] if entry["name"] == "home_iot_cli_edit_v1")
    assert home_iot["screenshot"] == "examples/screenshots/home_iot_cli_edit_v1.png"
    assert home_iot["screenshots"] == ["examples/screenshots/home_iot_cli_edit_v1.png"]
    assert home_iot["screenshot_count"] == 1
    assert home_iot["preview"] == "examples/previews/home_iot_cli_edit_v1.svg"
    assert home_iot["image"] == "examples/screenshots/home_iot_cli_edit_v1.png"
    assert home_iot["acceptance_rank"] == 3
    assert home_iot["fixture_name"] == "home_iot_complex"
    assert "capabilities=iot, iot_registration" in home_iot["acceptance_excerpt"]
    assert "mode=donor-backed constrained edit" in home_iot["acceptance_excerpt"]
    assert "iot_registration=donor_backed_ready" in home_iot["parity_excerpt"]

    service_heavy = next(entry for entry in payload["curated_examples"] if entry["name"] == "service_heavy_cli_edit_v1")
    assert service_heavy["screenshot"] == "examples/screenshots/service_heavy_cli_edit_v1.png"
    assert service_heavy["screenshot_count"] == 4
    assert service_heavy["detail_images"] == [
        "examples/screenshots/service_heavy_cli_edit_v1_dhcp.png",
        "examples/screenshots/service_heavy_cli_edit_v1_dns.png",
        "examples/screenshots/service_heavy_cli_edit_v1_ftp.png",
    ]
    assert service_heavy["image"] == "examples/screenshots/service_heavy_cli_edit_v1.png"
    assert service_heavy["acceptance_rank"] == 3
    assert service_heavy["acceptance_label"] == "known_working_example"
    assert service_heavy["fixture_name"] == "service_heavy_complex"
    assert "server_dns" in service_heavy["acceptance_excerpt"]

    assert len(payload["proof_cards"]) == 7
    for card in payload["proof_cards"]:
        assert card["try_command"]
        assert card["does_not_claim"]
        assert card["support_level_explanation"]
    assert payload["support_truth"]["generate_ready"] == 0
    assert payload["local_sample_evidence"]["total_files"] == 367
    assert payload["proof_readiness_candidates"]["release_line"] == "0.2.4 candidate"
    assert len(payload["proof_readiness_candidates"]["primary_candidates"]) == 9
    assert len(payload["proof_readiness_candidates"]["secondary_candidates"]) == 8


def test_checked_in_examples_index_matches_builder() -> None:
    expected = build_examples_index()
    checked_in = json.loads((ROOT / "examples" / "index.json").read_text(encoding="utf-8"))
    assert checked_in == expected


def test_examples_gallery_markdown_contains_curated_entries() -> None:
    payload = build_examples_index()
    gallery = build_examples_gallery_markdown(payload)
    assert "## Showcase Examples" in gallery
    assert "aligned with the scenario fixture corpus" in gallery
    assert "Complex Campus" in gallery
    assert "Home IoT" in gallery
    assert "Service Heavy" in gallery
    assert "screenshots/complex_campus_master_edit_v4.png" in gallery
    assert "complex_campus_master_edit_v4.inventory.json" in gallery
    assert "[screenshot](screenshots/home_iot_cli_edit_v1.png)" in gallery
    assert "[screenshot](screenshots/service_heavy_cli_edit_v1.png)" in gallery
    assert "known_working_example | donor=donor-backed" in gallery
    assert "campus_core_complex | known_working_example | family=campus" in gallery
    assert "management_vlan=known_working_example" in gallery
    assert "iot_registration=donor_backed_ready" in gallery
    assert "## 0.2.4 Candidate Proof Cards" in gallery
    assert "IPv4 Routing / NAT / IOS Management" in gallery
    assert "Security Edge CBAC/ZFW" in gallery
    assert "Local Sample Evidence Board" in gallery
    assert "Proof-Readiness Promotion Queue" in gallery
    assert "proof-readiness dashboard" in gallery
    assert "`ospfv2`" in gallery
    assert "`bgp`" in gallery
    assert "try this command: `set R1 ospfv2 1 network" in gallery
    assert "does not claim:" in gallery
    assert "generate-ready" not in gallery
    assert "decision=known_working_example | donor_origin=donor-backed" in gallery
    assert "runtime=donor-backed example artifact" in gallery
    assert "extra visuals: [detail 1](screenshots/service_heavy_cli_edit_v1_dhcp.png); [detail 2](screenshots/service_heavy_cli_edit_v1_dns.png)" in gallery
    assert "[detail 3](screenshots/service_heavy_cli_edit_v1_ftp.png)" in gallery
    assert "Pending Screenshots" not in gallery
