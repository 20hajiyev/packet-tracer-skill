"""The committed catalogue must carry Cisco's samples and nothing else.

A rebuild on this machine staged 350 extra entries: labs from the user's
Downloads folder, each with an absolute path holding their Windows username,
their filename, and their device labels -- into a file that is committed and
pushed to a public repository. Nothing compared the entries against the
heading the same writer printed above them, "Packet Tracer Installed Sample
Catalog, source root <PACKET_TRACER_SAVES_ROOT>".

Provenance was on every entry the whole time. These tests read it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from sample_catalog import (  # noqa: E402
    DEFAULT_CATALOG_JSON,
    LOCAL_CATALOG_JSON,
    write_catalog_outputs,
)


def _entry(relative_path: str, origin: str, source_path: str | None = None) -> dict:
    entry = {
        "relative_path": relative_path,
        "origin": origin,
        "version": "9.0.0.0810",
        "device_count": 0,
        "link_count": 0,
        "devices": [],
        "links": [],
    }
    if source_path:
        entry["source_path"] = source_path
    return entry


def test_the_committed_catalog_names_no_lab_off_the_installation() -> None:
    items = json.loads(DEFAULT_CATALOG_JSON.read_text(encoding="utf-8"))
    strangers = sorted(
        str(item.get("relative_path"))
        for item in items
        if item.get("origin") != "cisco-local"
    )
    assert not strangers, f"committed catalogue holds labs from off the installation: {strangers[:5]}"


def test_the_committed_catalog_carries_nobody_s_home_directory() -> None:
    text = DEFAULT_CATALOG_JSON.read_text(encoding="utf-8")
    for marker in ("C:\\Users\\\\", "/home/", "/Users/"):
        assert marker not in text, f"committed catalogue carries an absolute home path: {marker}"


def test_a_local_lab_is_written_to_the_local_file_not_the_committed_one(tmp_path: Path) -> None:
    json_path = tmp_path / "catalog.json"
    md_path = tmp_path / "catalog.md"
    local_path = tmp_path / "local.json"
    write_catalog_outputs(
        [
            _entry("01 Networking/DHCP/dhcp_apipa.pkt", "cisco-local"),
            _entry("Senan_K231.pkt", "user-local", r"C:\Users\Sanan\Downloads\Senan_K231.pkt"),
        ],
        json_path=json_path,
        md_path=md_path,
        local_json_path=local_path,
    )

    published = json.loads(json_path.read_text(encoding="utf-8"))
    assert [item["relative_path"] for item in published] == ["01 Networking/DHCP/dhcp_apipa.pkt"]
    assert "Senan_K231" not in md_path.read_text(encoding="utf-8")

    kept = json.loads(local_path.read_text(encoding="utf-8"))
    assert [item["relative_path"] for item in kept] == ["Senan_K231.pkt"]
    assert kept[0]["source_path"].endswith("Senan_K231.pkt")


def test_the_local_file_goes_away_when_the_machine_has_no_local_labs(tmp_path: Path) -> None:
    """Otherwise a stale file keeps offering donors that were removed."""
    local_path = tmp_path / "local.json"
    local_path.write_text("[]", encoding="utf-8")
    write_catalog_outputs(
        [_entry("01 Networking/DHCP/dhcp_apipa.pkt", "cisco-local")],
        json_path=tmp_path / "catalog.json",
        md_path=tmp_path / "catalog.md",
        local_json_path=local_path,
    )
    assert not local_path.exists()


def test_the_local_catalog_is_not_tracked_by_git() -> None:
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert LOCAL_CATALOG_JSON.name in ignore
