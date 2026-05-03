from __future__ import annotations

from pathlib import Path
import json
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_release_docs_and_trust_files_exist() -> None:
    required = [
        ROOT / "CONTRIBUTING.md",
        ROOT / "CHANGELOG.md",
        ROOT / "CITATION.cff",
        ROOT / "SECURITY.md",
        ROOT / "CODE_OF_CONDUCT.md",
        ROOT / "docs" / "release-checklist.md",
        ROOT / "docs" / "github-discussions-setup.md",
        ROOT / "docs" / "runtime-truth.md",
        ROOT / "docs" / "curated-donor-registry.md",
        ROOT / "docs" / "campus-donor-proof.md",
        ROOT / "docs" / "home-iot-donor-proof.md",
        ROOT / "docs" / "wan-security-donor-proof.md",
        ROOT / "docs" / "wireless-advanced-proof.md",
        ROOT / "docs" / "industrial-programming-proof.md",
        ROOT / "docs" / "automation-controller-proof.md",
        ROOT / "docs" / "voice-collaboration-proof.md",
        ROOT / "docs" / "l2-resiliency-bgp-proof.md",
        ROOT / "docs" / "ipv4-routing-management-proof.md",
        ROOT / "docs" / "l2-security-qos-proof.md",
        ROOT / "docs" / "security-edge-deepening-proof.md",
        ROOT / "docs" / "generate-ready-pilot-design.md",
        ROOT / "docs" / "packet-tracer-feature-gap-atlas.md",
        ROOT / "docs" / "discovery-keywords.md",
        ROOT / "docs" / "github-launch-ops-0.2.2.md",
        ROOT / "docs" / "publish-preview-roadmap.md",
        ROOT / "docs" / "github-metadata.md",
        ROOT / "docs" / "hero-demo-plan.md",
        ROOT / "docs" / "launch-announcement-0.2.2.md",
        ROOT / "docs" / "post-launch-follow-up.md",
        ROOT / "docs" / "release-notes-0.2.2.md",
        ROOT / "docs" / "release-notes-0.2.3.md",
        ROOT / ".github" / "workflows" / "ci.yml",
        ROOT / ".github" / "ISSUE_TEMPLATE" / "bug_report.yml",
        ROOT / ".github" / "ISSUE_TEMPLATE" / "feature_request.yml",
        ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml",
        ROOT / "templates" / "pt900" / "base_empty.xml",
        ROOT / "templates" / "pt900" / "device_library" / "pc.xml",
        ROOT / "templates" / "pt900" / "device_library" / "printer.xml",
        ROOT / "templates" / "pt900" / "device_library" / "router.xml",
        ROOT / "templates" / "pt900" / "device_library" / "switch.xml",
    ]

    for path in required:
        assert path.exists(), f"missing required release surface file: {path}"


def test_readme_highlights_release_and_runtime_contracts() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "Known Working Scenario Set" in readme
    assert "Runtime Doctor Contract" in readme
    assert "`0.2.3` capability release" in readme
    assert "bridge_resolution" in readme
    assert "references/curated-donor-registry.json" in readme
    assert "references/scenario-fixture-corpus.json" in readme
    assert "docs/release-notes-0.2.2.md" in readme
    assert "docs/release-notes-0.2.3.md" in readme
    assert "docs/hero-demo-plan.md" in readme
    assert "docs/github-launch-ops-0.2.2.md" in readme
    assert "docs/campus-donor-proof.md" in readme
    assert "docs/home-iot-donor-proof.md" in readme
    assert "docs/wan-security-donor-proof.md" in readme
    assert "docs/wireless-advanced-proof.md" in readme
    assert "docs/industrial-programming-proof.md" in readme
    assert "docs/automation-controller-proof.md" in readme
    assert "docs/voice-collaboration-proof.md" in readme
    assert "docs/l2-resiliency-bgp-proof.md" in readme
    assert "docs/ipv4-routing-management-proof.md" in readme
    assert "docs/l2-security-qos-proof.md" in readme
    assert "docs/security-edge-deepening-proof.md" in readme
    assert "docs/generate-ready-pilot-design.md" in readme
    assert "`0.2.3` capability release" in readme
    assert "Voice/collaboration" in readme
    assert "docs/packet-tracer-feature-gap-atlas.md" in readme
    assert "references/packettracer-feature-atlas.json" in readme
    assert "--feature-gap-report" in readme
    assert "docs/post-launch-follow-up.md" in readme
    assert "docs/release-checklist.md" in readme
    assert "docs/runtime-truth.md" in readme
    assert "docs/curated-donor-registry.md" in readme
    assert "best_rejected_donor_class" in readme
    assert "primary_rejection_code" in readme
    assert "what_currently_works" in readme
    assert "best_next_fix" in readme
    assert "shorthand campus prompts should still resolve to the `campus` family" in readme
    assert r'PKT_TWOFISH_LIBRARY="C:\path\to\_twofish.cp314-win_amd64.pyd"' in readme
    assert r'PKT_TWOFISH_SEARCH_ROOTS="C:\path\to\bridge-folder"' in readme
    assert r"$env:USERPROFILE\.codex\skills\pkt\scripts\vendor\_twofish" not in readme
    assert "Advanced wireless" in readme
    assert "Treat these `critical_*` counts as the release truth" in readme
    assert "GitHub Sample Ingestion Is Local/Cache-Only" in readme
    assert "output/remote-import-cache" in readme
    assert "remote-sample-audit.json" in readme
    assert "--remote-dry-run" in readme
    assert "--local-sample-audit-root" in readme
    assert "output/local-sample-audit.json" in readme
    assert "Bu repo Cisco Packet Tracer 9.x `.pkt` faylları" in readme
    assert "generate_ready=0" in readme


def test_package_metadata_is_publish_ready() -> None:
    payload = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    keywords = set(payload["keywords"])
    files = set(payload["files"])
    scripts = payload["scripts"]

    assert payload["version"] == "0.2.3"
    assert {"packet-tracer", "network-lab", "natural-language", "codex", "cursor", "claude"} <= keywords
    assert {
        "CONTRIBUTING.md",
        "CHANGELOG.md",
        "CITATION.cff",
        "SECURITY.md",
        "CODE_OF_CONDUCT.md",
        "bin/packet-tracer-skill.js",
        "scripts/*.py",
        "examples/screenshots/*.png",
        "docs/campus-donor-proof.md",
        "docs/home-iot-donor-proof.md",
        "docs/wan-security-donor-proof.md",
        "docs/wireless-advanced-proof.md",
        "docs/industrial-programming-proof.md",
        "docs/automation-controller-proof.md",
        "docs/voice-collaboration-proof.md",
        "docs/l2-resiliency-bgp-proof.md",
        "docs/ipv4-routing-management-proof.md",
        "docs/l2-security-qos-proof.md",
        "docs/security-edge-deepening-proof.md",
        "docs/generate-ready-pilot-design.md",
        "docs/packet-tracer-feature-gap-atlas.md",
        "docs/github-launch-ops-0.2.2.md",
        "docs/post-launch-follow-up.md",
        "docs/release-notes-0.2.2.md",
        "docs/release-notes-0.2.3.md",
        "docs/runtime-truth.md",
    } <= files
    assert scripts["test"] == "python -m pytest tests -q"
    assert scripts["examples:build"] == "python scripts/build_examples_index.py"
    assert scripts["smoke:parity"] == "python scripts/generate_pkt.py --parity-report \"campus with VLAN DHCP ACL\""


def test_ci_workflow_runs_examples_build_and_tests() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "concurrency:" in workflow
    assert "cancel-in-progress: true" in workflow
    assert "windows-latest" in workflow
    assert "python .\\scripts\\build_examples_index.py" in workflow
    assert "node --check .\\bin\\packet-tracer-skill.js" in workflow
    assert "python .\\scripts\\generate_pkt.py --parity-report \"campus with VLAN DHCP ACL\"" in workflow
    assert "python .\\scripts\\runtime_doctor.py" in workflow
    assert "python -m pytest tests -q" in workflow


def test_launch_prep_docs_are_decision_complete() -> None:
    release_notes = (ROOT / "docs" / "release-notes-0.2.3.md").read_text(encoding="utf-8")
    historical_release_notes = (ROOT / "docs" / "release-notes-0.2.2.md").read_text(encoding="utf-8")
    hero_demo = (ROOT / "docs" / "hero-demo-plan.md").read_text(encoding="utf-8")
    launch_announcement = (ROOT / "docs" / "launch-announcement-0.2.2.md").read_text(encoding="utf-8")
    metadata = (ROOT / "docs" / "github-metadata.md").read_text(encoding="utf-8")
    launch_ops = (ROOT / "docs" / "github-launch-ops-0.2.2.md").read_text(encoding="utf-8")
    donor_proof = (ROOT / "docs" / "campus-donor-proof.md").read_text(encoding="utf-8")
    home_iot_proof = (ROOT / "docs" / "home-iot-donor-proof.md").read_text(encoding="utf-8")
    wan_security_proof = (ROOT / "docs" / "wan-security-donor-proof.md").read_text(encoding="utf-8")
    wireless_advanced_proof = (ROOT / "docs" / "wireless-advanced-proof.md").read_text(encoding="utf-8")
    industrial_programming_proof = (ROOT / "docs" / "industrial-programming-proof.md").read_text(encoding="utf-8")
    automation_controller_proof = (ROOT / "docs" / "automation-controller-proof.md").read_text(encoding="utf-8")
    voice_collaboration_proof = (ROOT / "docs" / "voice-collaboration-proof.md").read_text(encoding="utf-8")
    l2_security_qos_proof = (ROOT / "docs" / "l2-security-qos-proof.md").read_text(encoding="utf-8")
    l2_resiliency_bgp_proof = (ROOT / "docs" / "l2-resiliency-bgp-proof.md").read_text(encoding="utf-8")
    ipv4_routing_management_proof = (ROOT / "docs" / "ipv4-routing-management-proof.md").read_text(encoding="utf-8")
    security_edge_deepening_proof = (ROOT / "docs" / "security-edge-deepening-proof.md").read_text(encoding="utf-8")
    generate_ready_pilot = (ROOT / "docs" / "generate-ready-pilot-design.md").read_text(encoding="utf-8")
    feature_gap_atlas = (ROOT / "docs" / "packet-tracer-feature-gap-atlas.md").read_text(encoding="utf-8")
    follow_up = (ROOT / "docs" / "post-launch-follow-up.md").read_text(encoding="utf-8")
    gallery = (ROOT / "examples" / "gallery.md").read_text(encoding="utf-8")
    examples_readme = (ROOT / "examples" / "README.md").read_text(encoding="utf-8")

    assert "0.2.3" in release_notes
    assert "Windows-first runtime" in release_notes
    assert "external Twofish bridge override" in release_notes
    assert "0.2.2" in historical_release_notes
    assert "complex_campus_master_edit_v4.png" in hero_demo
    assert "--explain-plan" in hero_demo
    assert "alt text:" in hero_demo
    assert "npm Publish Announcement" in launch_announcement
    assert "Short Social Summary" in launch_announcement
    assert "Final About Text" in metadata
    assert "Final Topics" in metadata
    assert "complex_campus_master_edit_v4.png" in metadata
    assert "v0.2.2" in launch_ops
    assert "docs/release-notes-0.2.2.md" in launch_ops
    assert "selection_failure_type=viable_donor_found_but_acceptance_weak" in donor_proof
    assert "best_rejected_donor_class=campus/core" in donor_proof
    assert "primary_rejection_code=layout_reuse_too_weak" in donor_proof
    assert "What This Proves" in donor_proof
    assert "What This Does Not Prove" in donor_proof
    assert "generalized campus generation can still be donor-limited" in donor_proof
    assert "the refusal should be read as donor-limited campus semantics" in donor_proof
    assert "donor-backed constrained-generate" in home_iot_proof
    assert "What This Proves" in home_iot_proof
    assert "What This Does Not Prove" in home_iot_proof
    assert "WAN/security edge" in wan_security_proof
    assert "donor-backed readiness" in wan_security_proof
    assert "What This Proves" in wan_security_proof
    assert "What This Does Not Prove" in wan_security_proof
    assert "broad synthetic WAN/security" in wan_security_proof
    assert "Advanced Wireless Proof" in wireless_advanced_proof
    assert "WEP and WPA Enterprise/RADIUS" in wireless_advanced_proof
    assert "What This Proves" in wireless_advanced_proof
    assert "What This Does Not Prove" in wireless_advanced_proof
    assert "does not make any advanced wireless feature `generate_ready`" in wireless_advanced_proof
    assert "Industrial Programming Proof" in industrial_programming_proof
    assert "Real HTTP and Real WebSocket" in industrial_programming_proof
    assert "set \"Py: real http server 2\" script app" in industrial_programming_proof
    assert "`donor_backed_ready`" in industrial_programming_proof
    assert "does not make any industrial programming feature `generate_ready`" in industrial_programming_proof
    assert "Automation Controller Proof" in automation_controller_proof
    assert "Python and JavaScript script files" in automation_controller_proof
    assert "TCP/UDP test app" in automation_controller_proof
    assert "does not make any automation/controller feature `generate_ready`" in automation_controller_proof
    assert "Voice Collaboration Proof" in voice_collaboration_proof
    assert "telephony-service" in voice_collaboration_proof
    assert "dial-peer voice" in voice_collaboration_proof
    assert "does not make any voice/collaboration feature `generate_ready`" in voice_collaboration_proof
    assert "L2 Resiliency + BGP Proof Wave" in l2_resiliency_bgp_proof
    assert "router bgp" in l2_resiliency_bgp_proof
    assert "spanning-tree" in l2_resiliency_bgp_proof
    assert "channel-group" in l2_resiliency_bgp_proof
    assert "does not make any of these capabilities `generate_ready`" in l2_resiliency_bgp_proof
    assert "IPv4 Routing and IOS Management Proof" in ipv4_routing_management_proof
    assert "OSPFv2" in ipv4_routing_management_proof
    assert "NAT/PAT" in ipv4_routing_management_proof
    assert "does not make any IPv4 routing, NAT, or IOS management capability `generate_ready`" in ipv4_routing_management_proof
    assert "L2 Security and QoS Proof" in l2_security_qos_proof
    assert "dot1x system-auth-control" in l2_security_qos_proof
    assert "`dot1x` is `donor_backed_ready`" in l2_security_qos_proof
    assert "`qos` remains `edit_proven`" in l2_security_qos_proof
    assert "service-policy output" in l2_security_qos_proof
    assert "does not make dot1x or QoS `generate_ready`" in l2_security_qos_proof
    assert "Security Edge Deepening Proof" in security_edge_deepening_proof
    assert "ip inspect name" in security_edge_deepening_proof
    assert "`zfw` is `donor_backed_ready`" in security_edge_deepening_proof
    assert "`cbac` remains `edit_proven`" in security_edge_deepening_proof
    assert "zone-pair security" in security_edge_deepening_proof
    assert "does not make CBAC, ZFW, ASA ACL/NAT, ASA service policy, or clientless VPN `generate_ready`" in security_edge_deepening_proof
    assert "Generate-Ready Pilot Design" in generate_ready_pilot
    assert "does not enable `generate_ready`" in generate_ready_pilot
    assert "single-donor" in generate_ready_pilot
    assert "Feature atlas support is not the same as generation support" in feature_gap_atlas
    assert "First Donor-Backed Edit Readiness Wave" in feature_gap_atlas
    assert "Fifth Donor-Backed Edit Readiness Wave" in feature_gap_atlas
    assert "Sixth Donor-Backed Edit Readiness Wave" in feature_gap_atlas
    assert "Seventh Donor-Backed Edit Readiness Wave" in feature_gap_atlas
    assert "Eighth Donor-Backed Edit Readiness Wave" in feature_gap_atlas
    assert "Third Edit-Proven Wave" in feature_gap_atlas
    assert "--feature-gap-report" in feature_gap_atlas
    assert "Trigger Conditions for `0.2.2` or the Next Minor" in follow_up
    assert "closest rejected donor class" in follow_up
    assert "close shorthand campus family fidelity before broadening scenario scope" in follow_up
    assert "Home IoT" in follow_up
    assert "wan_security_edge" in follow_up
    assert "what_currently_works" in (ROOT / "docs" / "runtime-truth.md").read_text(encoding="utf-8")
    assert "best_next_fix" in (ROOT / "docs" / "runtime-truth.md").read_text(encoding="utf-8")
    assert "registry entry exists" in (ROOT / "docs" / "curated-donor-registry.md").read_text(encoding="utf-8")
    assert "docs/home-iot-donor-proof.md" in (ROOT / "docs" / "curated-donor-registry.md").read_text(encoding="utf-8")
    assert "docs/wan-security-donor-proof.md" in (ROOT / "docs" / "curated-donor-registry.md").read_text(encoding="utf-8")
    assert "Remote Sample Promotion Rules" in (ROOT / "docs" / "curated-donor-registry.md").read_text(encoding="utf-8")
    assert "remote-sample-audit.json" in feature_gap_atlas
    assert "local-sample-audit.json" in feature_gap_atlas
    assert "remote-sample-audit.json" in (ROOT / "docs" / "release-checklist.md").read_text(encoding="utf-8")
    assert "local-sample-audit.json" in (ROOT / "docs" / "release-checklist.md").read_text(encoding="utf-8")
    assert "no raw `.pkt`, `.pka`, or remote cache files" in (ROOT / "docs" / "release-checklist.md").read_text(encoding="utf-8")
    assert "canonical public set" in gallery
    assert "complex campus screenshot" in gallery
    assert "campus donor proof" in gallery
    assert "WAN/security donor proof" in gallery
    assert "canonical public set" in examples_readme
    assert "..\\docs\\campus-donor-proof.md" in examples_readme
    assert "..\\docs\\home-iot-donor-proof.md" in examples_readme
    assert "..\\docs\\wan-security-donor-proof.md" in examples_readme


def test_public_docs_do_not_leak_local_paths_or_mojibake() -> None:
    public_paths = [
        ROOT / "SKILL.md",
        ROOT / "README.md",
        *sorted((ROOT / "docs").glob("*.md")),
        *sorted((ROOT / "examples").glob("*.md")),
        ROOT / "references" / "packettracer-feature-atlas.json",
        ROOT / "references" / "scenario-fixture-corpus.json",
    ]
    forbidden = [".codex", "USERPROFILE", "Ã", "Å", "É", "Ä", "Â", "Æ", "ï¿½", "�"]

    for path in public_paths:
        text = path.read_text(encoding="utf-8")
        for needle in forbidden:
            assert needle not in text, f"{needle!r} leaked into {path}"


def test_npm_pack_dry_run_is_hardened() -> None:
    npm_bin = shutil.which("npm.cmd") or shutil.which("npm")
    assert npm_bin is not None, "npm executable not found"

    result = subprocess.run(
        [npm_bin, "pack", "--dry-run", "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
        shell=False,
    )
    payload = json.loads(result.stdout)
    assert payload and isinstance(payload, list)
    files = {entry["path"] for entry in payload[0]["files"]}

    assert "scripts/__pycache__/build_examples_index.cpython-314.pyc" not in files
    assert "scripts/vendor/__pycache__/twofish.cpython-314.pyc" not in files
    assert not any(path.startswith("examples/previews/") for path in files)
    assert not any(path.startswith("docs/screenshots/") for path in files)
    assert not any(path.startswith("output/remote-import-cache/") for path in files)
    assert not any(path.startswith("output/") for path in files)
    assert not any(path.startswith("pkt_examples/") for path in files)
    assert not any(path.lower().endswith((".pkt", ".pka")) for path in files)
    assert "examples/screenshots/complex_campus_master_edit_v4.png" in files
    assert "examples/screenshots/home_iot_cli_edit_v1.png" in files
    assert "examples/screenshots/service_heavy_cli_edit_v1.png" in files
