"""Tests for the local usage ledger that lets the skill improve with use.

The ledger is an optimisation, so most of these tests are about what it must
*not* do: leak prompt text, grow without bound, or ever become load-bearing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import usage_ledger  # noqa: E402
from usage_ledger import (  # noqa: E402
    OUTCOME_GENERATED_UNVERIFIED,
    OUTCOME_GENERATED_VERIFIED,
    OUTCOME_REFUSED,
    LedgerEntry,
    donor_scores,
    load_entries,
    prompt_fingerprint,
    record,
    summary,
)


@pytest.fixture
def ledger(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.delenv("PKT_USAGE_LEDGER", raising=False)
    return tmp_path / "usage-ledger.jsonl"


def _entry(**overrides: object) -> LedgerEntry:
    defaults = {
        "scenario_family": "campus",
        "donor": "donor-a.pkt",
        "outcome": OUTCOME_GENERATED_UNVERIFIED,
        "prompt_shape": prompt_fingerprint("3 switch 6 pc"),
    }
    defaults.update(overrides)
    return LedgerEntry(**defaults)  # type: ignore[arg-type]


def test_record_and_read_back(ledger: Path) -> None:
    assert record(_entry(), ledger)

    entries = load_entries(ledger)
    assert len(entries) == 1
    assert entries[0]["donor"] == "donor-a.pkt"
    assert entries[0]["outcome"] == OUTCOME_GENERATED_UNVERIFIED
    assert entries[0]["recorded_at"]


def test_prompt_text_is_never_written_to_disk(ledger: Path) -> None:
    """A lab description can contain names or addresses. None of it may persist."""
    secret = "Aysel Qurbanova ofis 192.168.44.7 ucun 3 switch qur"
    record(_entry(prompt_shape=prompt_fingerprint(secret)), ledger)

    written = ledger.read_text(encoding="utf-8")
    for fragment in ("Aysel", "Qurbanova", "192.168.44.7", "ofis"):
        assert fragment not in written


def test_fingerprint_groups_requests_of_the_same_shape() -> None:
    assert prompt_fingerprint("3 switch ve 6 komputer") == prompt_fingerprint("5 switch ve 2 komputer")
    assert prompt_fingerprint("3 SWITCH  ve 6 komputer") == prompt_fingerprint("3 switch ve 6 komputer")
    assert prompt_fingerprint("3 switch ve 6 komputer") != prompt_fingerprint("wireless ap qur")


def test_fingerprint_is_not_reversible() -> None:
    fingerprint = prompt_fingerprint("Muhasibat sobesi ucun 4 pc")
    assert "muhasibat" not in fingerprint.lower()
    assert len(fingerprint) == 16


def test_donor_scores_reward_success_and_penalise_rejection(ledger: Path) -> None:
    shape = prompt_fingerprint("3 switch 6 pc")
    record(_entry(donor="good.pkt", outcome=OUTCOME_GENERATED_VERIFIED, prompt_shape=shape), ledger)
    record(
        _entry(
            donor="ok.pkt",
            outcome=OUTCOME_GENERATED_UNVERIFIED,
            prompt_shape=shape,
            rejected_donors=["bad.pkt"],
        ),
        ledger,
    )

    scores = donor_scores("campus", shape, ledger)

    assert scores["good.pkt"] > scores["ok.pkt"] > 0
    assert scores["bad.pkt"] < 0


def test_matching_prompt_shape_counts_double(ledger: Path) -> None:
    shape = prompt_fingerprint("3 switch 6 pc")
    record(_entry(donor="a.pkt", outcome=OUTCOME_GENERATED_VERIFIED, prompt_shape=shape), ledger)

    matched = donor_scores("campus", shape, ledger)["a.pkt"]
    family_only = donor_scores("campus", prompt_fingerprint("wireless ap"), ledger)["a.pkt"]

    assert matched == family_only * 2


def test_scores_are_scoped_to_the_scenario_family(ledger: Path) -> None:
    record(_entry(scenario_family="campus", donor="a.pkt"), ledger)

    assert donor_scores("campus", path=ledger)
    assert donor_scores("home_iot", path=ledger) == {}


def test_refusals_do_not_make_a_donor_preferred(ledger: Path) -> None:
    record(_entry(donor="a.pkt", outcome=OUTCOME_REFUSED), ledger)

    assert donor_scores("campus", path=ledger).get("a.pkt", 0) <= 0


def test_unknown_outcome_is_rejected(ledger: Path) -> None:
    with pytest.raises(ValueError):
        record(_entry(outcome="made-up"), ledger)


def test_ledger_is_bounded(ledger: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(usage_ledger, "MAX_ENTRIES", 5)
    for index in range(12):
        record(_entry(donor=f"donor-{index}.pkt"), ledger)

    entries = load_entries(ledger)
    assert len(entries) == 5
    assert entries[-1]["donor"] == "donor-11.pkt"


def test_corrupt_lines_are_skipped_not_fatal(ledger: Path) -> None:
    record(_entry(donor="good.pkt"), ledger)
    with ledger.open("a", encoding="utf-8") as handle:
        handle.write("this is not json\n")
        handle.write(json.dumps({"no_donor": True}) + "\n")
    record(_entry(donor="also-good.pkt"), ledger)

    donors = {entry["donor"] for entry in load_entries(ledger)}
    assert donors == {"good.pkt", "also-good.pkt"}


def test_missing_ledger_is_not_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PKT_USAGE_LEDGER", raising=False)
    absent = tmp_path / "nothing-here.jsonl"

    assert load_entries(absent) == []
    assert donor_scores("campus", path=absent) == {}


def test_learning_can_be_switched_off(ledger: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PKT_USAGE_LEDGER", "off")

    assert not usage_ledger.ledger_enabled()
    assert record(_entry(), ledger) is False
    assert not ledger.exists()
    assert load_entries(ledger) == []


def test_summary_reports_what_was_learned(ledger: Path) -> None:
    record(_entry(donor="a.pkt", outcome=OUTCOME_GENERATED_VERIFIED), ledger)
    record(_entry(donor="b.pkt", outcome=OUTCOME_REFUSED), ledger)

    report = summary(ledger)

    assert report["entry_count"] == 2
    assert report["outcomes"][OUTCOME_GENERATED_VERIFIED] == 1
    assert report["scenario_families"]["campus"] == 2
    assert [item["donor"] for item in report["proven_donors"]] == ["a.pkt"]


def test_ledger_default_path_stays_inside_gitignored_output() -> None:
    """The ledger must never land somewhere it could be committed or packaged."""
    assert usage_ledger.DEFAULT_LEDGER_PATH.parent.name == "output"
    assert "output/" in (ROOT / ".gitignore").read_text(encoding="utf-8")
