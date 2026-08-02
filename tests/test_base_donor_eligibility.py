"""Coverage reporting and base-donor eligibility are different questions.

A sample proves a capability whether or not it can serve as a generation base.
Applying the donor version policy to both made every bundled sample vanish under
the `exact` default, and campus prompts started refusing with "critical
capability coverage is still missing" — for coverage that was in the catalogue
all along.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_pkt import _base_donor_candidates, _existing_ranked_candidates  # noqa: E402
from packet_tracer_env import build_is_known, save_a_lab_hint  # noqa: E402
from sample_catalog import SampleCandidate, SampleDescriptor  # noqa: E402


def _candidate(tmp_path: Path, name: str, version: str) -> SampleCandidate:
    path = tmp_path / name
    path.write_bytes(b"x")
    sample = SampleDescriptor(
        path=str(path),
        relative_path=name,
        version=version,
        device_count=4,
        link_count=3,
        devices=[],
        links=[],
        capability_tags=[],
        topology_tags=[],
        preferred_roles=[],
        apply_safety_level="acceptance-verified",
    )
    return SampleCandidate(sample=sample, capability_score=1, topology_score=1, total_score=2, reasons=[])


@pytest.fixture
def candidates(tmp_path: Path) -> list[SampleCandidate]:
    return [
        _candidate(tmp_path, "running_build.pkt", "9.0.0.0810"),
        _candidate(tmp_path, "same_release.pkt", "9.0.0.0000"),
        _candidate(tmp_path, "older.pkt", "7.1.0.0000"),
    ]


def test_coverage_keeps_every_sample_that_exists(
    candidates: list[SampleCandidate], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PACKET_TRACER_TARGET_VERSION", "9.0.0.0810")
    monkeypatch.setenv("PACKET_TRACER_DONOR_POLICY", "exact")

    kept = _existing_ranked_candidates(candidates)

    assert len(kept) == 3


def test_coverage_drops_samples_missing_from_disk(tmp_path: Path) -> None:
    present = _candidate(tmp_path, "present.pkt", "9.0.0.0810")
    absent = _candidate(tmp_path, "absent.pkt", "9.0.0.0810")
    Path(absent.sample.path).unlink()

    kept = _existing_ranked_candidates([present, absent])

    assert [item.sample.relative_path for item in kept] == ["present.pkt"]


def test_base_eligibility_applies_the_version_policy(
    candidates: list[SampleCandidate], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PACKET_TRACER_TARGET_VERSION", "9.0.0.0810")
    monkeypatch.setenv("PACKET_TRACER_DONOR_POLICY", "exact")

    bases = _base_donor_candidates(candidates)

    assert [item.sample.relative_path for item in bases] == ["running_build.pkt"]


def test_a_looser_policy_widens_only_the_base_pool(
    candidates: list[SampleCandidate], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PACKET_TRACER_TARGET_VERSION", "9.0.0.0810")
    monkeypatch.setenv("PACKET_TRACER_DONOR_POLICY", "same_minor")

    bases = _base_donor_candidates(candidates)

    assert sorted(item.sample.relative_path for item in bases) == ["running_build.pkt", "same_release.pkt"]
    assert len(_existing_ranked_candidates(candidates)) == 3


def test_build_is_known_distinguishes_a_release_from_a_build() -> None:
    assert build_is_known("9.0.0.0810")
    assert not build_is_known("9.0.0")
    assert not build_is_known("")


def test_the_hint_tells_the_user_the_one_action_that_helps() -> None:
    hint = save_a_lab_hint()

    assert "Save As" in hint
    assert "build" in hint


def test_the_exact_policy_refusal_never_suggests_loosening(monkeypatch: pytest.MonkeyPatch) -> None:
    """Loosening was measured to produce files Packet Tracer refuses to open."""
    from packet_tracer_env import describe_donor_rejection

    message = describe_donor_rejection("9.0.0.0000", "9.0.0.0810", "same_minor", "exact")

    assert "PACKET_TRACER_DONOR_POLICY" not in message
    assert "Save As" in message
