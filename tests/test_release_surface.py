from __future__ import annotations

from pathlib import Path
import json


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
        ROOT / "docs" / "discovery-keywords.md",
        ROOT / "docs" / "publish-preview-roadmap.md",
        ROOT / "docs" / "github-metadata.md",
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
    assert "bridge_resolution" in readme
    assert "references/curated-donor-registry.json" in readme
    assert "references/scenario-fixture-corpus.json" in readme
    assert "docs/release-checklist.md" in readme
    assert "docs/runtime-truth.md" in readme
    assert "docs/curated-donor-registry.md" in readme


def test_package_metadata_is_publish_ready() -> None:
    payload = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    keywords = set(payload["keywords"])
    files = set(payload["files"])
    scripts = payload["scripts"]

    assert {"packet-tracer", "network-lab", "natural-language", "codex", "cursor", "claude"} <= keywords
    assert {"CONTRIBUTING.md", "CHANGELOG.md", "CITATION.cff", "SECURITY.md", "CODE_OF_CONDUCT.md", "docs"} <= files
    assert scripts["test"] == "python -m pytest tests -q"
    assert scripts["examples:build"] == "python scripts/build_examples_index.py"
    assert scripts["smoke:parity"] == "python scripts/generate_pkt.py --parity-report \"campus with VLAN DHCP ACL\""


def test_ci_workflow_runs_examples_build_and_tests() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "windows-latest" in workflow
    assert "python .\\scripts\\build_examples_index.py" in workflow
    assert "node --check .\\bin\\packet-tracer-skill.js" in workflow
    assert "python .\\scripts\\generate_pkt.py --parity-report \"campus with VLAN DHCP ACL\"" in workflow
    assert "python .\\scripts\\runtime_doctor.py" in workflow
    assert "python -m pytest tests -q" in workflow
