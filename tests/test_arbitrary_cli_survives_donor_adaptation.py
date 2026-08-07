"""`cli R1: ...` has to reach the file, not just the plan.

Measured end to end: the parser produced the `apply_cli` operation correctly and
the plan that reached the file contained none. Donor adaptation rebuilds the
donor-shaping operations from scratch and cleared the whole list to do it,
taking the user's own commands with it. Of seven commands in one prompt, two
appeared in the lab, and both of those only because the donor already had them.

Carrying them across is not enough on its own. Once the operation survived, the
open-first safety profile classified it by falling through to the default,
`workspace_physical_mutation`, which is blocked -- so the first prompt carrying
arbitrary CLI refused to generate at all. Writing IOS text into a device's
configuration is a `config_mutation`, the same class as the switch and router
operations.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import generate_pkt as G  # noqa: E402
from intent_parser import parse_intent  # noqa: E402

PROMPT = (
    "1 router 1 switch 3 komputer qur\n"
    "cli R1: ip domain-name lab.local; banner motd #Test#\n"
    "cli SW1: vtp mode transparent; spanning-tree mode rapid-pvst"
)


def _cli_operations(plan) -> list[dict]:
    return [op for op in plan.edit_operations if op.get("op") == "apply_cli"]


def test_the_parser_captures_every_command() -> None:
    plan = parse_intent(PROMPT)
    operations = _cli_operations(plan)
    assert [op["device"] for op in operations] == ["R1", "SW1"]
    assert operations[0]["lines"] == ["ip domain-name lab.local", "banner motd #Test#"]
    assert operations[1]["lines"] == ["vtp mode transparent", "spanning-tree mode rapid-pvst"]


def test_writing_ios_text_is_a_config_mutation() -> None:
    """Falling through to the default blocked generation outright."""
    assert G._operation_category("edit_operations", {"op": "apply_cli"}) == "config_mutation"
    # The classes it must not be confused with.
    assert G._operation_category("edit_operations", {"op": "set_link"}) == "link_rewrite"
    assert G._operation_category("edit_operations", {"op": "prune_device"}) == "device_prune"


def test_a_config_mutation_is_allowed_in_open_first_mode() -> None:
    profile = G._compatibility_profile()
    assert "config_mutation" in profile.allowed_operations
    assert "config_mutation" not in profile.blocked_operations
    # The class the operation used to fall through to.
    assert "workspace_physical_mutation" in profile.blocked_operations
