from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_curated_example_artifacts_are_present() -> None:
    screenshot = ROOT / "examples" / "screenshots" / "complex_campus_master_edit_v4.png"
    manifest = ROOT / "examples" / "complex_campus_master_edit_v4.inventory.json"
    examples_readme = ROOT / "examples" / "README.md"

    assert screenshot.exists()
    assert manifest.exists()
    assert examples_readme.exists()


def test_readme_references_curated_example_screenshot() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    examples_readme = (ROOT / "examples" / "README.md").read_text(encoding="utf-8")

    assert "examples/screenshots/complex_campus_master_edit_v4.png" in readme
    assert "screenshots/complex_campus_master_edit_v4.png" in examples_readme
