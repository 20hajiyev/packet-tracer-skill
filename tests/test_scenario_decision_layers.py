"""The refusal must name the layer that actually failed.

When the intent plan has gaps, donor evaluation never runs. Reporting
"donor selection" with zero candidate counts sent users to fix a donor that had
never been consulted.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_pkt import _scenario_generate_decision  # noqa: E402

CAMPUS_COVERAGE = {
    "scenario_generate_readiness": {"family": "campus", "status": "ready"},
    "recommended_next_actions": ["import a donor with the missing capabilities"],
}


def test_intent_gaps_blame_the_prompt_not_the_donor() -> None:
    decision = _scenario_generate_decision(
        CAMPUS_COVERAGE,
        intent_blocking_gaps=["Host-to-VLAN assignment is missing. Specify how many PCs belong to each VLAN."],
    )

    assert decision["status"] == "blocked_by_intent"
    assert decision["blocking_layer"] == "intent"
    assert decision["what_failed"] == "prompt completeness"
    assert "Host-to-VLAN assignment is missing" in decision["why_failed"]
    assert "no donor is implicated" in decision["what_would_make_it_pass"]
    assert decision["allow_generate"] is False


def test_intent_gaps_are_reported_verbatim() -> None:
    gaps = ["first gap", "second gap"]

    decision = _scenario_generate_decision(CAMPUS_COVERAGE, intent_blocking_gaps=gaps)

    assert decision["blocking_reasons"] == gaps


def test_intent_layer_wins_over_runtime_reporting() -> None:
    """A missing donor is not the user's next action while the prompt is incomplete."""
    decision = _scenario_generate_decision(
        CAMPUS_COVERAGE,
        runtime_blocked=True,
        runtime_blocking_reason="no compatible donor",
        intent_blocking_gaps=["Host-to-VLAN assignment is missing."],
    )

    assert decision["blocking_layer"] == "intent"
    assert decision["what_failed"] == "prompt completeness"


def test_no_intent_gaps_leaves_the_other_layers_alone() -> None:
    decision = _scenario_generate_decision(CAMPUS_COVERAGE, intent_blocking_gaps=[])

    assert decision["status"] != "blocked_by_intent"
    assert decision["blocking_layer"] != "intent"


def test_blank_gaps_are_ignored() -> None:
    decision = _scenario_generate_decision(CAMPUS_COVERAGE, intent_blocking_gaps=["", "   "])

    assert decision["status"] != "blocked_by_intent"
