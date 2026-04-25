from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import runtime_doctor  # noqa: E402


def test_runtime_env_examples_are_platform_specific() -> None:
    windows = runtime_doctor.runtime_env_examples("Windows")
    macos = runtime_doctor.runtime_env_examples("macOS")
    linux = runtime_doctor.runtime_env_examples("Linux")

    assert any("PACKET_TRACER_ROOT" in line for line in windows)
    assert any("PKT_TWOFISH_LIBRARY" in line for line in windows)
    assert any("PKT_TWOFISH_SEARCH_ROOTS" in line for line in macos)
    assert any("PKT_TWOFISH_SEARCH_ROOTS" in line for line in linux)
    assert not any(".codex" in line for line in windows + macos + linux)


def test_collect_runtime_doctor_windows_ready(monkeypatch) -> None:
    monkeypatch.setattr(runtime_doctor, "_host_os_label", lambda: "Windows")
    monkeypatch.setattr(
        runtime_doctor,
        "collect_twofish_diagnostics",
        lambda: {
            "python_version": "3.14.0",
            "python_support_status": "ok",
            "python_support_message": "supported",
            "resolved_twofish_path": str(ROOT / "scripts" / "vendor" / "_twofish.cp314-win_amd64.pyd"),
            "twofish_source": "env",
            "twofish_load_status": "ok",
            "twofish_message": "loaded",
            "twofish_sha256": "abc123",
        },
    )
    monkeypatch.setattr(
        runtime_doctor,
        "collect_donor_diagnostics",
        lambda: {
            "target_version": "9.0.0.0810",
            "resolved_donor_path": r"C:\labs\donor.pkt",
            "donor_version": "9.0.0.0810",
            "donor_source": "env",
            "status": "ok",
            "message": "ready",
            "blocking_reason": "",
            "candidate_paths": [{"source": "env", "path": r"C:\labs\donor.pkt"}],
        },
    )
    monkeypatch.setattr(runtime_doctor, "get_packet_tracer_root", lambda: Path(r"C:\Program Files\Cisco Packet Tracer 9.0.0"))
    monkeypatch.setattr(runtime_doctor, "get_packet_tracer_saves_root", lambda: Path(r"C:\Program Files\Cisco Packet Tracer 9.0.0\saves"))
    monkeypatch.setattr(runtime_doctor, "get_packet_tracer_exe", lambda: Path(r"C:\Program Files\Cisco Packet Tracer 9.0.0\bin\PacketTracer.exe"))

    payload = runtime_doctor.collect_runtime_doctor()

    assert payload["host_os"] == "Windows"
    assert payload["installer_support"]["status"] == "supported"
    assert payload["real_pkt_runtime_support"]["status"] == "validated"
    assert payload["detected_layout_type"] == "windows_install_root"
    assert payload["recommended_packet_tracer_root"]
    assert payload["recommended_packet_tracer_saves_root"]
    assert payload["python_support_status"] == "ok"
    assert payload["twofish_load_status"] == "ok"
    assert payload["donor_status"] == "ok"
    assert payload["expected_twofish_patterns"]
    assert payload["twofish_search_roots"]
    assert payload["env_examples"]
    assert payload["capability_impact"]["generate"] == "ready"
    assert payload["capability_impact"]["edit"] == "ready"
    assert payload["runtime_blockers"] == []
    assert "generate" in payload["ready_operations"]
    assert payload["blocked_operations"] == []
    assert payload["what_currently_works"] == "Currently working operations: inventory, decode, edit, generate, validate_open."
    assert payload["what_is_blocked"] == "No runtime operations are currently blocked."
    assert payload["why_it_is_blocked"] == "No runtime blocker is currently active."
    assert payload["best_next_fix"] == "No immediate fix is required."
    assert payload["runtime_grade"] == "ready"
    assert "Runtime is ready." in payload["doctor_summary"]
    assert "Ready operations: inventory, decode, edit, generate, validate_open." in payload["doctor_summary"]
    assert payload["bridge_resolution"] == "repo_local"
    assert payload["bridge_recommendation"] == "Repo-local bridge is resolved."
    assert "run strict decode/edit/generate locally" in payload["runtime_contract_notes"]
    assert payload["recommended_next_steps"] == []
    assert payload["blocking_reason"] == ""


def test_collect_runtime_doctor_linux_reports_windows_first_runtime(monkeypatch) -> None:
    monkeypatch.setattr(runtime_doctor, "_host_os_label", lambda: "Linux")
    monkeypatch.setattr(
        runtime_doctor,
        "collect_twofish_diagnostics",
        lambda: {
            "python_version": "3.14.0",
            "python_support_status": "ok",
            "python_support_message": "supported",
            "resolved_twofish_path": "",
            "twofish_source": "",
            "twofish_load_status": "missing",
            "twofish_message": "no local Twofish bridge was found",
            "twofish_sha256": "",
        },
    )
    monkeypatch.setattr(
        runtime_doctor,
        "collect_donor_diagnostics",
        lambda: {
            "target_version": "9.0.0.0810",
            "resolved_donor_path": "",
            "donor_version": "",
            "donor_source": "",
            "status": "missing",
            "message": "not set",
            "blocking_reason": "not set",
            "candidate_paths": [],
        },
    )
    monkeypatch.setattr(runtime_doctor, "get_packet_tracer_root", lambda: None)
    monkeypatch.setattr(runtime_doctor, "get_packet_tracer_saves_root", lambda: None)
    monkeypatch.setattr(runtime_doctor, "get_packet_tracer_exe", lambda: None)

    payload = runtime_doctor.collect_runtime_doctor()

    assert payload["host_os"] == "Linux"
    assert payload["real_pkt_runtime_support"]["status"] == "windows_first"
    assert "custom Packet Tracer paths" in payload["real_pkt_runtime_support"]["message"]
    assert payload["detected_layout_type"] == "missing"
    assert payload["recommended_packet_tracer_root"]
    assert payload["recommended_packet_tracer_saves_root"]
    assert payload["donor_status"] == "missing"
    assert payload["expected_twofish_patterns"]
    assert payload["env_examples"]
    assert payload["capability_impact"]["generate"] == "blocked"
    assert payload["capability_impact"]["decode"] == "blocked"
    assert "missing_or_incompatible_donor" in payload["runtime_blockers"]
    assert "missing_twofish_bridge" in payload["runtime_blockers"]
    assert "windows_first_runtime" in payload["runtime_blockers"]
    assert "generate" in payload["blocked_operations"]
    assert payload["what_currently_works"] == "No strict runtime operations are currently working."
    assert payload["what_is_blocked"] == "Blocked operations: inventory, decode, edit, generate, validate_open."
    assert "no compatible donor is resolved" in payload["why_it_is_blocked"]
    assert "no local Twofish bridge is resolved" in payload["why_it_is_blocked"]
    assert payload["best_next_fix"] == "Fix the donor path first so inventory/edit/generate can use a compatible 9.0 donor."
    assert payload["runtime_grade"] == "blocked"
    assert "Runtime is blocked." in payload["doctor_summary"]
    assert "Blocked operations:" in payload["doctor_summary"]
    assert payload["bridge_resolution"] == "missing"
    assert "resolve a local bridge" in payload["bridge_recommendation"]
    assert "strict decode/edit/generate remain blocked" in payload["runtime_contract_notes"]
    assert any("Windows-first" in line for line in payload["recommended_next_steps"])
    assert any("Packet Tracer saves" in line for line in payload["recommended_next_steps"])
    assert any("Twofish bridge" in line for line in payload["recommended_next_steps"])
    assert "packet_tracer_root:not_set" in payload["blocking_reason"]
    assert "runtime_os:Linux" in payload["blocking_reason"]


def test_collect_runtime_doctor_reports_external_bridge_resolution(monkeypatch) -> None:
    monkeypatch.setattr(runtime_doctor, "_host_os_label", lambda: "Windows")
    monkeypatch.setattr(
        runtime_doctor,
        "collect_twofish_diagnostics",
        lambda: {
            "python_version": "3.14.0",
            "python_support_status": "ok",
            "python_support_message": "supported",
            "resolved_twofish_path": r"C:\Users\Sanan\.codex\skills\pkt\scripts\vendor\_twofish.cp314-win_amd64.pyd",
            "twofish_source": "env",
            "twofish_load_status": "ok",
            "twofish_message": "loaded",
            "twofish_sha256": "abc123",
        },
    )
    monkeypatch.setattr(
        runtime_doctor,
        "collect_donor_diagnostics",
        lambda: {
            "target_version": "9.0.0.0810",
            "resolved_donor_path": r"C:\labs\donor.pkt",
            "donor_version": "9.0.0.0810",
            "donor_source": "env",
            "status": "ok",
            "message": "ready",
            "blocking_reason": "",
            "candidate_paths": [{"source": "env", "path": r"C:\labs\donor.pkt"}],
        },
    )
    monkeypatch.setattr(runtime_doctor, "get_packet_tracer_root", lambda: Path(r"C:\Program Files\Cisco Packet Tracer 9.0.0"))
    monkeypatch.setattr(runtime_doctor, "get_packet_tracer_saves_root", lambda: Path(r"C:\Program Files\Cisco Packet Tracer 9.0.0\saves"))
    monkeypatch.setattr(runtime_doctor, "get_packet_tracer_exe", lambda: Path(r"C:\Program Files\Cisco Packet Tracer 9.0.0\bin\PacketTracer.exe"))

    payload = runtime_doctor.collect_runtime_doctor()

    assert payload["runtime_grade"] == "partially_ready"
    assert payload["bridge_resolution"] == "external_env"
    assert payload["bridge_path_source"] == "env"
    assert payload["what_currently_works"] == "Currently working operations: inventory, decode, edit, generate, validate_open."
    assert payload["what_is_blocked"] == "No runtime operations are currently blocked."
    assert "external bridge override" in payload["why_it_is_blocked"]
    assert payload["best_next_fix"] == "Move the external bridge into the repo-local vendor path if you need a self-contained runtime claim."
    assert "Runtime operations are ready" in payload["doctor_summary"]
    assert "external environment" in payload["doctor_summary"]
    assert "repo-local vendor bridge" in payload["bridge_recommendation"]
    assert "rely on an external bridge path" in payload["runtime_contract_notes"]
    assert "using_external_bridge_only" in payload["runtime_blockers"]


def test_collect_runtime_doctor_reports_validate_open_only_partial_state(monkeypatch) -> None:
    monkeypatch.setattr(runtime_doctor, "_host_os_label", lambda: "Windows")
    monkeypatch.setattr(
        runtime_doctor,
        "collect_twofish_diagnostics",
        lambda: {
            "python_version": "3.14.0",
            "python_support_status": "ok",
            "python_support_message": "supported",
            "resolved_twofish_path": "",
            "twofish_source": "",
            "twofish_load_status": "missing",
            "twofish_message": "no local Twofish bridge was found",
            "twofish_sha256": "",
        },
    )
    monkeypatch.setattr(
        runtime_doctor,
        "collect_donor_diagnostics",
        lambda: {
            "target_version": "9.0.0.0810",
            "resolved_donor_path": "",
            "donor_version": "",
            "donor_source": "",
            "status": "missing",
            "message": "not set",
            "blocking_reason": "not set",
            "candidate_paths": [],
        },
    )
    monkeypatch.setattr(runtime_doctor, "get_packet_tracer_root", lambda: Path(r"C:\Program Files\Cisco Packet Tracer 9.0.0"))
    monkeypatch.setattr(runtime_doctor, "get_packet_tracer_saves_root", lambda: Path(r"C:\Program Files\Cisco Packet Tracer 9.0.0\saves"))
    monkeypatch.setattr(runtime_doctor, "get_packet_tracer_exe", lambda: Path(r"C:\Program Files\Cisco Packet Tracer 9.0.0\bin\PacketTracer.exe"))

    payload = runtime_doctor.collect_runtime_doctor()

    assert payload["runtime_grade"] == "partially_ready"
    assert payload["ready_operations"] == ["validate_open"]
    assert "inventory" in payload["blocked_operations"]
    assert "decode" in payload["blocked_operations"]
    assert "edit" in payload["blocked_operations"]
    assert "generate" in payload["blocked_operations"]
    assert payload["what_currently_works"] == "Currently working operations: validate_open."
    assert payload["what_is_blocked"] == "Blocked operations: inventory, decode, edit, generate."
    assert "no compatible donor is resolved" in payload["why_it_is_blocked"]
    assert "no local Twofish bridge is resolved" in payload["why_it_is_blocked"]
    assert payload["best_next_fix"] == "Fix the donor path first so inventory/edit/generate can use a compatible 9.0 donor."
    assert "Ready operations: validate_open." in payload["doctor_summary"]
    assert "Blocked operations: inventory, decode, edit, generate." in payload["doctor_summary"]
    assert "Strict decode/edit/generate remain blocked until a local bridge is resolved." in payload["doctor_summary"]
