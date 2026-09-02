from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from twofish_diagnostics import collect_twofish_diagnostics  # noqa: E402


TWOFISH_DEPENDENT_MODULES = {
    "test_pkt_editor.py",
    "test_pkt_transformer.py",
    "test_xml_minimal_validity.py",
}

TWOFISH_EXEMPT_TESTS = {
    "test_apply_plan_operations_prunes_scenario_references",
    "test_apply_plan_operations_reuses_port_mem_addr_from_existing_links",
}


def _strict_twofish_required() -> bool:
    return os.getenv("PKT_REQUIRE_TWOFISH_TESTS", "").strip().lower() in {"1", "true", "yes", "on"}


def _twofish_ready() -> tuple[bool, str]:
    diagnostics = collect_twofish_diagnostics()
    status = diagnostics.get("twofish_load_status", "")
    message = diagnostics.get("twofish_message", "")
    path = diagnostics.get("resolved_twofish_path", "")
    if status == "ok":
        return True, f"Twofish bridge ready: {path}"
    return False, f"Twofish bridge unavailable: {status or 'missing'} ({message})"


def _donors_ready() -> tuple[bool, str]:
    """Whether this machine can build a lab at all.

    Generation copies device and link prototypes out of real Packet Tracer
    saves; there is nothing to copy from on a machine with no install and no
    donor cache, which is every CI runner. Tests that build a lab used to find
    this out by raising -- `PlanningError: Prompt plan is incomplete` or
    `FileNotFoundError: No Packet Tracer install and no donor cache were found`
    -- so a green suite locally meant a red one on the runner, on every commit
    for four weeks. The twofish bridge already had one probe answering for the
    whole suite; donors had none, and each test decided for itself or not at
    all.
    """
    from packet_tracer_env import (
        get_packet_tracer_compatibility_donor,
        get_packet_tracer_saves_root,
    )

    if get_packet_tracer_saves_root() is None:
        return False, "no Packet Tracer install and no donor cache"
    if get_packet_tracer_compatibility_donor() is None:
        return False, "no Packet Tracer 9.0 compatibility donor"
    return True, "donor saves available"


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "requires_twofish: test requires a local Packet Tracer Twofish bridge and real .pkt decode/edit runtime",
    )
    config.addinivalue_line(
        "markers",
        "requires_donors: test builds a lab, which needs Packet Tracer saves or a donor cache",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        if Path(str(item.fspath)).name in TWOFISH_DEPENDENT_MODULES and item.name not in TWOFISH_EXEMPT_TESTS:
            item.add_marker(pytest.mark.requires_twofish)

    twofish_items = [item for item in items if item.get_closest_marker("requires_twofish") is not None]
    if not twofish_items:
        return

    ready, reason = _twofish_ready()
    if ready:
        return

    if _strict_twofish_required():
        pytest.exit(
            f"{reason}; strict release gate requires PKT_TWOFISH_LIBRARY or PKT_TWOFISH_SEARCH_ROOTS",
            returncode=1,
        )
        return

    skip_marker = pytest.mark.skip(reason=f"{reason}; set PKT_REQUIRE_TWOFISH_TESTS=1 for strict release gating")
    for item in twofish_items:
        item.add_marker(skip_marker)


def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker("requires_donors") is None:
        return
    ready, reason = _donors_ready()
    if not ready:
        pytest.skip(reason)
