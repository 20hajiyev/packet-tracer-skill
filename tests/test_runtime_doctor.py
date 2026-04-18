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


def test_collect_runtime_doctor_windows_ready(monkeypatch) -> None:
    monkeypatch.setattr(runtime_doctor, "_host_os_label", lambda: "Windows")
    monkeypatch.setattr(
        runtime_doctor,
        "collect_twofish_diagnostics",
        lambda: {
            "python_version": "3.14.0",
            "python_support_status": "ok",
            "python_support_message": "supported",
            "resolved_twofish_path": r"C:\bridge\_twofish.cp314-win_amd64.pyd",
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
    assert any("Windows-first" in line for line in payload["recommended_next_steps"])
    assert any("Packet Tracer saves" in line for line in payload["recommended_next_steps"])
    assert any("Twofish bridge" in line for line in payload["recommended_next_steps"])
    assert "packet_tracer_root:not_set" in payload["blocking_reason"]
    assert "runtime_os:Linux" in payload["blocking_reason"]
