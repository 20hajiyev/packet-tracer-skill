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
        ROOT / "docs" / "discovery-keywords.md",
        ROOT / "docs" / "github-launch-ops-0.2.1.md",
        ROOT / "docs" / "publish-preview-roadmap.md",
        ROOT / "docs" / "github-metadata.md",
        ROOT / "docs" / "hero-demo-plan.md",
        ROOT / "docs" / "launch-announcement-0.2.1.md",
        ROOT / "docs" / "post-launch-follow-up.md",
        ROOT / "docs" / "release-notes-0.2.1.md",
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
    assert "`0.2.1` public preview baseline" in readme
    assert "bridge_resolution" in readme
    assert "references/curated-donor-registry.json" in readme
    assert "references/scenario-fixture-corpus.json" in readme
    assert "docs/release-notes-0.2.1.md" in readme
    assert "docs/hero-demo-plan.md" in readme
    assert "docs/github-launch-ops-0.2.1.md" in readme
    assert "docs/campus-donor-proof.md" in readme
    assert "docs/post-launch-follow-up.md" in readme
    assert "docs/release-checklist.md" in readme
    assert "docs/runtime-truth.md" in readme
    assert "docs/curated-donor-registry.md" in readme
    assert "best_rejected_donor_class" in readme
    assert "primary_rejection_code" in readme
    assert "what_currently_works" in readme
    assert "best_next_fix" in readme
    assert "shorthand campus prompts should still resolve to the `campus` family" in readme


def test_package_metadata_is_publish_ready() -> None:
    payload = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    keywords = set(payload["keywords"])
    files = set(payload["files"])
    scripts = payload["scripts"]

    assert payload["version"] == "0.2.1"
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
        "docs/github-launch-ops-0.2.1.md",
        "docs/post-launch-follow-up.md",
        "docs/release-notes-0.2.1.md",
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
    release_notes = (ROOT / "docs" / "release-notes-0.2.1.md").read_text(encoding="utf-8")
    hero_demo = (ROOT / "docs" / "hero-demo-plan.md").read_text(encoding="utf-8")
    launch_announcement = (ROOT / "docs" / "launch-announcement-0.2.1.md").read_text(encoding="utf-8")
    metadata = (ROOT / "docs" / "github-metadata.md").read_text(encoding="utf-8")
    launch_ops = (ROOT / "docs" / "github-launch-ops-0.2.1.md").read_text(encoding="utf-8")
    donor_proof = (ROOT / "docs" / "campus-donor-proof.md").read_text(encoding="utf-8")
    follow_up = (ROOT / "docs" / "post-launch-follow-up.md").read_text(encoding="utf-8")
    gallery = (ROOT / "examples" / "gallery.md").read_text(encoding="utf-8")
    examples_readme = (ROOT / "examples" / "README.md").read_text(encoding="utf-8")

    assert "0.2.1" in release_notes
    assert "Windows-first runtime" in release_notes
    assert "external bridge override" in release_notes
    assert "complex_campus_master_edit_v4.png" in hero_demo
    assert "--explain-plan" in hero_demo
    assert "alt text:" in hero_demo
    assert "npm Publish Announcement" in launch_announcement
    assert "Short Social Summary" in launch_announcement
    assert "Final About Text" in metadata
    assert "Final Topics" in metadata
    assert "complex_campus_master_edit_v4.png" in metadata
    assert "v0.2.1" in launch_ops
    assert "docs/release-notes-0.2.1.md" in launch_ops
    assert "selection_failure_type=viable_donor_found_but_acceptance_weak" in donor_proof
    assert "best_rejected_donor_class=campus/core" in donor_proof
    assert "primary_rejection_code=layout_reuse_too_weak" in donor_proof
    assert "What This Proves" in donor_proof
    assert "What This Does Not Prove" in donor_proof
    assert "generalized campus generation can still be donor-limited" in donor_proof
    assert "the refusal should be read as donor-limited campus semantics" in donor_proof
    assert "Trigger Conditions for `0.2.2` or the Next Minor" in follow_up
    assert "closest rejected donor class" in follow_up
    assert "close shorthand campus family fidelity before broadening scenario scope" in follow_up
    assert "what_currently_works" in (ROOT / "docs" / "runtime-truth.md").read_text(encoding="utf-8")
    assert "best_next_fix" in (ROOT / "docs" / "runtime-truth.md").read_text(encoding="utf-8")
    assert "registry entry exists" in (ROOT / "docs" / "curated-donor-registry.md").read_text(encoding="utf-8")
    assert "canonical public set" in gallery
    assert "complex campus screenshot" in gallery
    assert "campus donor proof" in gallery
    assert "canonical public set" in examples_readme
    assert "..\\docs\\campus-donor-proof.md" in examples_readme


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
    assert "examples/screenshots/complex_campus_master_edit_v4.png" in files
    assert "examples/screenshots/home_iot_cli_edit_v1.png" in files
    assert "examples/screenshots/service_heavy_cli_edit_v1.png" in files
