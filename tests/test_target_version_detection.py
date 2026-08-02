"""Where the target Packet Tracer build comes from, and why it matters.

Packet Tracer refuses to open a lab whose `<VERSION>` build differs from its
own, so the build -- not just the release -- has to be known before a donor can
be judged. These tests pin the resolution order and the failure it was written
to remove.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import packet_tracer_env as env  # noqa: E402


def test_release_only_target_cannot_satisfy_the_exact_policy() -> None:
    """The failure the executable probe exists to prevent.

    A three-field target is what the install directory name yields. Under the
    `exact` policy it matches nothing at all -- not even a lab written by that
    very install -- so a user who had never saved anything could not generate.
    """
    assert env.DEFAULT_DONOR_POLICY == "exact"

    tier = env.donor_compatibility("9.0.0", "9.0.0.0810")

    assert tier == "same_minor"
    assert not env.donor_tier_is_accepted(tier)


def test_a_full_build_target_accepts_a_matching_lab() -> None:
    assert env.donor_compatibility("9.0.0.0810", "9.0.0.0810") == "exact"
    assert env.donor_tier_is_accepted("exact")


def test_bundled_samples_stay_rejected_even_with_a_build_target() -> None:
    """Measured: building from a `9.0.0.0000` sample produces a file PT refuses."""
    assert not env.donor_tier_is_accepted(env.donor_compatibility("9.0.0.0810", "9.0.0.0000"))


def test_executable_probe_returns_a_four_field_build_or_nothing() -> None:
    detected = env._build_from_executable()

    if detected is None:  # no install, or a platform with no version resource
        pytest.skip("no Packet Tracer executable available on this machine")
    assert len(env._version_fields(detected)) == 4


def test_executable_probe_rejects_a_binary_from_another_release_line() -> None:
    """A binary that disagrees with the directory holding it is not trusted."""
    if env._build_from_executable() is None:
        pytest.skip("no Packet Tracer executable available on this machine")

    assert env._build_from_executable("7.0.0") is None


def test_executable_is_preferred_over_scanning_local_saves(monkeypatch: pytest.MonkeyPatch) -> None:
    """Asking the binary works on a machine where nothing has ever been saved."""
    monkeypatch.delenv("PACKET_TRACER_TARGET_VERSION", raising=False)
    monkeypatch.setattr(env, "get_packet_tracer_root", lambda: Path("/pt/Cisco Packet Tracer 9.0.0"))
    monkeypatch.setattr(env, "_build_from_executable", lambda release="": "9.0.0.0810")

    def _no_saves_exist(_release: str) -> str | None:
        raise AssertionError("local saves must not be scanned when the binary answered")

    monkeypatch.setattr(env, "_build_from_local_saves", _no_saves_exist)

    assert env.detect_packet_tracer_target_version() == ("9.0.0.0810", "executable")


def test_local_saves_still_answer_where_the_binary_cannot(monkeypatch: pytest.MonkeyPatch) -> None:
    """Linux and macOS carry no version resource, so the older path must remain."""
    monkeypatch.delenv("PACKET_TRACER_TARGET_VERSION", raising=False)
    monkeypatch.setattr(env, "get_packet_tracer_root", lambda: Path("/pt/Cisco Packet Tracer 9.0.0"))
    monkeypatch.setattr(env, "_build_from_executable", lambda release="": None)
    monkeypatch.setattr(env, "_build_from_local_saves", lambda release: "9.0.0.0810")

    assert env.detect_packet_tracer_target_version() == ("9.0.0.0810", "local_save")


def test_release_is_the_last_resort_not_the_first(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PACKET_TRACER_TARGET_VERSION", raising=False)
    monkeypatch.setattr(env, "get_packet_tracer_root", lambda: Path("/pt/Cisco Packet Tracer 9.0.0"))
    monkeypatch.setattr(env, "_build_from_executable", lambda release="": None)
    monkeypatch.setattr(env, "_build_from_local_saves", lambda release: None)

    assert env.detect_packet_tracer_target_version() == ("9.0.0", "install_root")


def test_explicit_override_still_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKET_TRACER_TARGET_VERSION", "8.2.1.0118")

    assert env.detect_packet_tracer_target_version() == ("8.2.1.0118", "env")


def test_exact_policy_refusal_never_offers_a_looser_policy() -> None:
    """Loosening was measured to produce files Packet Tracer refuses to open.

    Two messages used to disagree: `describe_donor_rejection` withheld the
    suggestion on purpose, while the donor resolver's own blocking reason handed
    it out. Recommending it walks the user into a broken state that looks like
    progress.
    """
    message = env.describe_donor_rejection("9.0.0.0000", "9.0.0.0810", "same_minor", "exact")

    assert "PACKET_TRACER_DONOR_POLICY" not in message
    assert "Save As" in message


def test_looser_policies_may_still_suggest_widening() -> None:
    message = env.describe_donor_rejection("8.2.0.0118", "9.0.0.0810", "same_major", "same_minor")

    assert "PACKET_TRACER_DONOR_POLICY=same_major" in message


def test_generation_refusal_reports_the_real_donor_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    """The old fixed string told users to let auto-detection run.

    Auto-detection had already run and rejected everything, so the advice sent
    people looking for a switch to flip that does not exist.
    """
    import generate_pkt

    monkeypatch.setattr(
        generate_pkt,
        "_inspect_packet_tracer_compatibility_donor_cached",
        lambda: env.CompatibilityDonorDetails(
            target_version="9.0.0.0810",
            resolved_path=None,
            donor_version=None,
            donor_source=None,
            status="missing",
            blocking_reason="bundled samples carry a different build",
            candidate_paths=[],
        ),
    )

    gap = generate_pkt._strict_compatibility_gap()

    assert "bundled samples carry a different build" in gap
    assert "let the repo auto-detect" not in gap


def test_diagnosis_failure_falls_back_instead_of_masking_the_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import generate_pkt

    def _explode() -> None:
        raise RuntimeError("donor probe failed")

    monkeypatch.setattr(generate_pkt, "_inspect_packet_tracer_compatibility_donor_cached", _explode)

    assert generate_pkt._strict_compatibility_gap() == generate_pkt.STRICT_COMPATIBILITY_GAP
