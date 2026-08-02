"""Tests for the donor cache that removes the Packet Tracer install requirement.

The cache is shaped like a `saves/` tree so it can answer
`require_packet_tracer_saves_root()` directly. It is an availability
optimisation: a cache that cannot be written must never fail a generation that
would otherwise succeed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import donor_cache  # noqa: E402
from donor_cache import (  # noqa: E402
    MANIFEST_VERSION,
    REQUIRED_PROTOTYPE_SAMPLES,
    _access_score,
    cache_enabled,
    cache_is_usable,
    cache_root,
    missing_requirements_message,
)


@pytest.fixture
def cache_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    target = tmp_path / "cache"
    monkeypatch.setenv("PKT_DONOR_CACHE", str(target))
    return target


def _write_manifest(root: Path, **overrides: object) -> None:
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "created_at": "2026-08-02T00:00:00+00:00",
        "source_root": "/somewhere/saves",
        "target_version": "9.0.0.0810",
        "cached_paths": ["a.pkt"],
    }
    manifest.update(overrides)
    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_cache_root_honours_the_environment(cache_dir: Path) -> None:
    assert cache_root() == cache_dir


def test_cache_can_be_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKT_DONOR_CACHE", "off")

    assert not cache_enabled()
    assert not cache_is_usable("9.0.0.0810")


def test_missing_manifest_is_not_usable(cache_dir: Path) -> None:
    assert not cache_is_usable("9.0.0.0810")


def test_manifest_listing_an_absent_file_is_not_usable(cache_dir: Path) -> None:
    _write_manifest(cache_dir)

    assert not cache_is_usable("9.0.0.0810")


def test_manifest_with_present_files_is_usable(cache_dir: Path) -> None:
    _write_manifest(cache_dir)
    (cache_dir / "a.pkt").write_bytes(b"x")

    assert cache_is_usable("9.0.0.0810")


def test_old_manifest_version_is_rejected(cache_dir: Path) -> None:
    _write_manifest(cache_dir, manifest_version=MANIFEST_VERSION - 1)
    (cache_dir / "a.pkt").write_bytes(b"x")

    assert not cache_is_usable("9.0.0.0810")


def test_a_compatible_recorded_target_is_accepted(cache_dir: Path) -> None:
    """`9.0.0` from an install directory and `9.0.0.0810` from a save agree.

    Comparing these as strings would throw away a good cache on exactly the
    machine it exists to serve — the mistake the donor gate itself used to make.
    """
    _write_manifest(cache_dir, target_version="9.0.0")
    (cache_dir / "a.pkt").write_bytes(b"x")

    assert cache_is_usable("9.0.0.0810")


def test_an_incompatible_recorded_target_is_rejected(cache_dir: Path) -> None:
    _write_manifest(cache_dir, target_version="5.3.0.0011")
    (cache_dir / "a.pkt").write_bytes(b"x")

    assert not cache_is_usable("9.0.0.0810")


def test_corrupt_manifest_is_not_fatal(cache_dir: Path) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "manifest.json").write_text("{not json", encoding="utf-8")

    assert donor_cache.read_manifest() is None
    assert not cache_is_usable("9.0.0.0810")


def test_bootstrap_copies_the_required_prototype_samples(cache_dir: Path, tmp_path: Path) -> None:
    saves = tmp_path / "saves"
    for relative_path in REQUIRED_PROTOTYPE_SAMPLES:
        source = saves / relative_path
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(b"sample-bytes")

    report = donor_cache.bootstrap(saves, catalog=[], target_version="9.0.0.0810")

    assert report.ok
    for relative_path in REQUIRED_PROTOTYPE_SAMPLES:
        assert (cache_dir / relative_path).exists()
    assert report.bytes_written > 0


def test_bootstrap_records_samples_it_could_not_find(cache_dir: Path, tmp_path: Path) -> None:
    saves = tmp_path / "saves"
    saves.mkdir(parents=True, exist_ok=True)

    report = donor_cache.bootstrap(saves, catalog=[], target_version="9.0.0.0810")

    for relative_path in REQUIRED_PROTOTYPE_SAMPLES:
        assert relative_path in report.skipped


def test_bootstrap_is_disabled_with_the_env_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKT_DONOR_CACHE", "off")

    report = donor_cache.bootstrap(tmp_path, catalog=[], target_version="9.0.0.0810")

    assert not report.ok
    assert "disabled" in report.error


def test_bootstrap_never_raises_when_the_cache_is_unwritable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Caching improves availability elsewhere; it must not break the machine that works."""
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("", encoding="utf-8")
    monkeypatch.setenv("PKT_DONOR_CACHE", str(blocker / "cache"))

    report = donor_cache.bootstrap(tmp_path, catalog=[], target_version="9.0.0.0810")

    assert not report.ok
    assert report.error


def test_access_score_prefers_hosts_on_switches_over_device_count() -> None:
    campus_devices = [
        {"name": "SW1", "type": "Switch"},
        *({"name": f"PC{index}", "type": "PC"} for index in range(6)),
    ]
    campus_links = [{"from": f"PC{index}", "to": "SW1"} for index in range(6)]

    router_farm_devices = [
        {"name": "SW1", "type": "Switch"},
        *({"name": f"R{index}", "type": "Router"} for index in range(4)),
        {"name": "PC1", "type": "PC"},
    ]
    router_farm_links = [{"from": f"R{index}", "to": "SW1"} for index in range(4)]

    assert _access_score(campus_devices, campus_links) > _access_score(
        router_farm_devices, router_farm_links
    )


def test_router_uplinks_are_worth_something_but_capped() -> None:
    devices = [{"name": "SW1", "type": "Switch"}, *({"name": f"R{i}", "type": "Router"} for i in range(5))]
    links = [{"from": f"R{i}", "to": "SW1"} for i in range(5)]

    assert _access_score(devices, links) == 2


def test_links_without_endpoints_are_ignored() -> None:
    devices = [{"name": "SW1", "type": "Switch"}, {"name": "PC1", "type": "PC"}]

    assert _access_score(devices, [{"from": "", "to": ""}]) == 0


def test_the_refusal_names_what_is_missing_and_how_to_fix_it(cache_dir: Path) -> None:
    message = missing_requirements_message()

    for relative_path in REQUIRED_PROTOTYPE_SAMPLES:
        assert relative_path in message
    assert str(cache_dir) in message
    assert "PACKET_TRACER_SAVES_ROOT" in message


def test_cache_status_reports_state_for_the_doctor(cache_dir: Path) -> None:
    _write_manifest(cache_dir)
    (cache_dir / "a.pkt").write_bytes(b"x")

    status = donor_cache.cache_status("9.0.0.0810")

    assert status["enabled"] is True
    assert status["usable"] is True
    assert status["cached_file_count"] == 1
    assert status["root"] == str(cache_dir)
