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


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "requires_twofish: test requires a local Packet Tracer Twofish bridge and real .pkt decode/edit runtime",
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
