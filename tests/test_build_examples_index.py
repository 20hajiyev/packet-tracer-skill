from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_examples_index import build_examples_index  # noqa: E402


def test_build_examples_index_covers_curated_examples() -> None:
    payload = build_examples_index()
    names = {entry["name"] for entry in payload["curated_examples"]}
    assert {"complex_campus_master_edit_v4", "home_iot_cli_edit_v1", "service_heavy_cli_edit_v1"} <= names


def test_build_examples_index_detects_existing_screenshot() -> None:
    payload = build_examples_index()
    campus = next(entry for entry in payload["curated_examples"] if entry["name"] == "complex_campus_master_edit_v4")
    assert campus["screenshot"] == "examples/screenshots/complex_campus_master_edit_v4.png"
    assert campus["capabilities"]


def test_checked_in_examples_index_matches_builder() -> None:
    expected = build_examples_index()
    checked_in = json.loads((ROOT / "examples" / "index.json").read_text(encoding="utf-8"))
    assert checked_in == expected
