#!/usr/bin/env python3
"""Unified runtime diagnostics for Packet Tracer skill hosts."""

from __future__ import annotations

import json
import platform
from pathlib import Path

from donor_diagnostics import collect_donor_diagnostics
from packet_tracer_env import (
    detect_packet_tracer_layout,
    get_packet_tracer_exe,
    get_packet_tracer_root,
    get_packet_tracer_saves_root,
    recommended_packet_tracer_root,
    recommended_packet_tracer_saves_root,
)
from twofish_runtime import expected_bridge_patterns, recommended_search_roots
from twofish_diagnostics import collect_twofish_diagnostics


def _host_os_label() -> str:
    labels = {
        "Windows": "Windows",
        "Darwin": "macOS",
        "Linux": "Linux",
    }
    return labels.get(platform.system(), platform.system() or "unknown")


def _packet_tracer_os_name(host_os: str) -> str:
    mapping = {
        "Windows": "Windows",
        "macOS": "Darwin",
        "Linux": "Linux",
    }
    return mapping.get(host_os, host_os)


def runtime_env_examples(host_os: str) -> list[str]:
    if host_os == "Windows":
        return [
            r"$env:PACKET_TRACER_ROOT='C:\Program Files\Cisco Packet Tracer 9.0.0'",
            r"$env:PACKET_TRACER_COMPAT_DONOR='C:\path\to\your-working-9.0-donor.pkt'",
            r'$env:PKT_TWOFISH_LIBRARY="$env:USERPROFILE\.codex\skills\pkt\scripts\vendor\_twofish.cp314-win_amd64.pyd"',
        ]
    if host_os == "macOS":
        return [
            "export PACKET_TRACER_ROOT='/Applications/Cisco Packet Tracer.app/Contents/Resources'",
            "export PACKET_TRACER_COMPAT_DONOR=\"$HOME/path/to/your-working-9.0-donor.pkt\"",
            "export PKT_TWOFISH_SEARCH_ROOTS=\"$HOME/.codex/skills/pkt/scripts/vendor:$HOME/pkt-bridges\"",
        ]
    if host_os == "Linux":
        return [
            "export PACKET_TRACER_ROOT='/opt/pt/bin'",
            "export PACKET_TRACER_COMPAT_DONOR=\"$HOME/path/to/your-working-9.0-donor.pkt\"",
            "export PKT_TWOFISH_SEARCH_ROOTS=\"$HOME/.codex/skills/pkt/scripts/vendor:$HOME/pkt-bridges\"",
        ]
    return []


def _format_operation_list(operations: list[str]) -> str:
    return ", ".join(operations) if operations else "none"


def _best_next_fix(runtime_blockers: list[str], recommended_next_steps: list[str]) -> str:
    blocker_map = {
        "missing_or_incompatible_donor": "Fix the donor path first so inventory/edit/generate can use a compatible 9.0 donor.",
        "missing_twofish_bridge": "Fix the Twofish bridge next so strict decode/edit/generate can run locally.",
        "missing_packet_tracer_root": "Fix PACKET_TRACER_ROOT so the doctor can resolve the install layout deterministically.",
        "missing_packet_tracer_executable": "Fix the Packet Tracer install root or executable path before relying on validate_open.",
        "windows_first_runtime": "Do not assume non-Windows strict runtime support without a custom native bridge and explicit Packet Tracer paths.",
        "using_external_bridge_only": "Move the external bridge into the repo-local vendor path if you need a self-contained runtime claim.",
    }
    for blocker in runtime_blockers:
        if blocker in blocker_map:
            return blocker_map[blocker]
    return recommended_next_steps[0] if recommended_next_steps else "No immediate fix is required."


def _why_it_is_blocked(runtime_blockers: list[str], bridge_resolution: str) -> str:
    if not runtime_blockers:
        return "No runtime blocker is currently active."
    reasons: list[str] = []
    if "missing_or_incompatible_donor" in runtime_blockers:
        reasons.append("no compatible donor is resolved")
    if "missing_twofish_bridge" in runtime_blockers:
        reasons.append("no local Twofish bridge is resolved")
    if "missing_packet_tracer_root" in runtime_blockers:
        reasons.append("Packet Tracer root is not resolved")
    if "missing_packet_tracer_executable" in runtime_blockers:
        reasons.append("Packet Tracer executable is not resolved")
    if "windows_first_runtime" in runtime_blockers:
        reasons.append("strict bundled validation is still Windows-first")
    if bridge_resolution == "external_env":
        reasons.append("strict runtime currently relies on an external bridge override")
    return "; ".join(reasons) + "."


def build_recommended_next_steps(
    *,
    host_os: str,
    python_support_status: str,
    packet_tracer_root: Path | None,
    recommended_root: Path | None,
    recommended_saves_root: Path | None,
    donor_status: str,
    donor_candidates: list[dict[str, object]],
    twofish_load_status: str,
    expected_patterns: list[str],
    search_roots: list[str],
    runtime_supported: bool,
    runtime_message: str,
) -> list[str]:
    guidance: list[str] = []
    if not runtime_supported:
        guidance.append(f"Real runtime is still Windows-first: {runtime_message}")
    if python_support_status != "ok":
        guidance.append("Use Python 3.14.x for Packet Tracer 9.0 encode/decode.")
    if packet_tracer_root is None and recommended_root:
        guidance.append(f"Set PACKET_TRACER_ROOT to {recommended_root}.")
    if donor_status != "ok":
        saves_hint = (
            f" Packet Tracer saves are typically under {recommended_saves_root}."
            if recommended_saves_root
            else ""
        )
        if donor_candidates:
            guidance.append(
                "Pick one discovered donor or export PACKET_TRACER_COMPAT_DONOR explicitly. "
                f"{saves_hint.lstrip() if saves_hint else 'Use your Packet Tracer saves folder.'}"
            )
        else:
            guidance.append(
                "Provide a working 9.0 donor lab with PACKET_TRACER_COMPAT_DONOR or place one under "
                f"{recommended_saves_root or 'your Packet Tracer saves folder'}. "
                "Packet Tracer saves are the default donor search location."
            )
    if twofish_load_status != "ok":
        message = ["Provide a local Twofish bridge"]
        if expected_patterns:
            message.append(f"matching one of: {' | '.join(expected_patterns)}")
        if search_roots:
            message.append(f"in one of these roots: {' | '.join(search_roots)}")
        message.append("or set PKT_TWOFISH_LIBRARY / PKT_TWOFISH_SEARCH_ROOTS.")
        guidance.append(" ".join(message))
    if host_os in {"macOS", "Linux"} and not runtime_supported:
        guidance.append("For non-Windows hosts, install a native Twofish bridge before expecting real .pkt runtime support.")
    return guidance


def collect_runtime_doctor() -> dict[str, object]:
    host_os = _host_os_label()
    installer_supported = host_os in {"Windows", "macOS", "Linux"}
    twofish = collect_twofish_diagnostics()
    donor = collect_donor_diagnostics()
    packet_tracer_os = _packet_tracer_os_name(host_os)
    packet_tracer_root = get_packet_tracer_root()
    packet_tracer_saves = get_packet_tracer_saves_root()
    packet_tracer_exe = get_packet_tracer_exe()
    detected_layout = detect_packet_tracer_layout(packet_tracer_root, packet_tracer_os) if packet_tracer_root else "missing"
    recommended_root = recommended_packet_tracer_root(packet_tracer_os)
    recommended_saves_root = recommended_packet_tracer_saves_root(packet_tracer_os)
    vendor_dir = Path(__file__).resolve().parent / "vendor"
    resolved_patterns = twofish.get("expected_twofish_patterns") or expected_bridge_patterns()
    resolved_search_roots = twofish.get("twofish_search_roots") or recommended_search_roots(vendor_dir)
    resolved_twofish_path = str(twofish.get("resolved_twofish_path") or "")
    if resolved_twofish_path:
        try:
            repo_vendor = vendor_dir.resolve()
            bridge_path = Path(resolved_twofish_path).resolve()
            bridge_resolution = "repo_local" if repo_vendor in bridge_path.parents else "external_env"
        except Exception:
            bridge_resolution = "external_env"
    else:
        bridge_resolution = "missing"

    runtime_supported = host_os == "Windows"
    if runtime_supported:
        runtime_message = "validated Windows Packet Tracer 9.0 runtime path"
    elif twofish.get("resolved_twofish_path"):
        runtime_message = "custom native runtime may work, but bundled validation is still Windows-first"
    else:
        runtime_message = "needs custom Packet Tracer paths and a non-Windows native Twofish bridge"

    blocking_reasons: list[str] = []
    if twofish.get("python_support_status") != "ok":
        blocking_reasons.append(
            f"python_support:{twofish.get('python_support_status')} ({twofish.get('python_support_message')})"
        )
    if twofish.get("twofish_load_status") != "ok":
        blocking_reasons.append(
            f"twofish:{twofish.get('twofish_load_status')} ({twofish.get('twofish_message')})"
        )
    if donor.get("status") != "ok":
        blocking_reasons.append(
            f"donor:{donor.get('status')} ({donor.get('blocking_reason') or donor.get('message')})"
        )
    if packet_tracer_root is None:
        blocking_reasons.append("packet_tracer_root:not_set")
    if not runtime_supported:
        blocking_reasons.append(f"runtime_os:{host_os}")

    recommended_next_steps = build_recommended_next_steps(
        host_os=host_os,
        python_support_status=str(twofish.get("python_support_status", "unknown")),
        packet_tracer_root=packet_tracer_root,
        recommended_root=recommended_root,
        recommended_saves_root=recommended_saves_root,
        donor_status=str(donor.get("status", "unknown")),
        donor_candidates=list(donor.get("candidate_paths", [])),
        twofish_load_status=str(twofish.get("twofish_load_status", "unknown")),
        expected_patterns=list(resolved_patterns),
        search_roots=list(resolved_search_roots),
        runtime_supported=runtime_supported,
        runtime_message=runtime_message,
    )
    capability_impact = {
        "inventory": "ready" if donor.get("status") == "ok" and twofish.get("twofish_load_status") == "ok" else "blocked",
        "decode": "ready" if twofish.get("twofish_load_status") == "ok" else "blocked",
        "edit": "ready" if donor.get("status") == "ok" and twofish.get("twofish_load_status") == "ok" else "blocked",
        "generate": "ready" if runtime_supported and donor.get("status") == "ok" and twofish.get("twofish_load_status") == "ok" else "blocked",
        "validate_open": "ready" if packet_tracer_exe is not None else "blocked",
    }
    ready_operations = [name for name, status in capability_impact.items() if status == "ready"]
    blocked_operations = [name for name, status in capability_impact.items() if status != "ready"]
    runtime_blockers: list[str] = []
    if donor.get("status") != "ok":
        runtime_blockers.append("missing_or_incompatible_donor")
    if twofish.get("twofish_load_status") != "ok":
        runtime_blockers.append("missing_twofish_bridge")
    if packet_tracer_root is None:
        runtime_blockers.append("missing_packet_tracer_root")
    if packet_tracer_exe is None:
        runtime_blockers.append("missing_packet_tracer_executable")
    if not runtime_supported:
        runtime_blockers.append("windows_first_runtime")
    if bridge_resolution == "external_env" and "using_external_bridge_only" not in runtime_blockers:
        runtime_blockers.append("using_external_bridge_only")
    if runtime_blockers:
        runtime_grade = "blocked" if len(ready_operations) == 0 else "partially_ready"
    else:
        runtime_grade = "ready"
    if runtime_grade == "ready":
        doctor_summary = (
            "Runtime is ready. "
            f"Ready operations: {_format_operation_list(ready_operations)}."
        )
    elif bridge_resolution == "external_env" and not blocked_operations:
        doctor_summary = (
            "Runtime operations are ready, but packaged runtime remains partially ready because the bridge "
            "comes from an external environment instead of the repo-local vendor path. "
            f"Ready operations: {_format_operation_list(ready_operations)}."
        )
    elif runtime_grade == "partially_ready":
        doctor_summary = (
            "Runtime is partially ready. "
            f"Ready operations: {_format_operation_list(ready_operations)}. "
            f"Blocked operations: {_format_operation_list(blocked_operations)}."
        )
    else:
        doctor_summary = (
            "Runtime is blocked. "
            f"Blocked operations: {_format_operation_list(blocked_operations)}."
        )
    if bridge_resolution == "external_env" and blocked_operations:
        doctor_summary = f"{doctor_summary} External bridge is being used instead of a repo-local vendor bridge."
    elif bridge_resolution == "missing" and runtime_grade != "ready":
        doctor_summary = f"{doctor_summary} Strict decode/edit/generate remain blocked until a local bridge is resolved."
    what_currently_works = (
        f"Currently working operations: {_format_operation_list(ready_operations)}."
        if ready_operations
        else "No strict runtime operations are currently working."
    )
    what_is_blocked = (
        f"Blocked operations: {_format_operation_list(blocked_operations)}."
        if blocked_operations
        else "No runtime operations are currently blocked."
    )
    why_it_is_blocked = _why_it_is_blocked(runtime_blockers, bridge_resolution)
    best_next_fix = _best_next_fix(runtime_blockers, recommended_next_steps)
    bridge_recommendation = (
        "Use or install a repo-local vendor bridge for fully self-contained runtime readiness."
        if bridge_resolution == "external_env"
        else "Provide PKT_TWOFISH_LIBRARY or PKT_TWOFISH_SEARCH_ROOTS to resolve a local bridge."
        if bridge_resolution == "missing"
        else "Repo-local bridge is resolved."
    )
    runtime_contract_notes = (
        "Repo-local bridge and donor are present, so this checkout can run strict decode/edit/generate locally."
        if bridge_resolution == "repo_local"
        else "Strict decode/edit/generate currently rely on an external bridge path. Repo-local runtime packaging is still incomplete."
        if bridge_resolution == "external_env"
        else "No bridge is resolved. validate_open may still work when Packet Tracer is installed, but strict decode/edit/generate remain blocked."
    )

    return {
        "host_os": host_os,
        "installer_support": {
            "status": "supported" if installer_supported else "unsupported",
            "message": "supported" if installer_supported else "unknown host platform",
        },
        "real_pkt_runtime_support": {
            "status": "validated" if runtime_supported else "windows_first",
            "message": runtime_message,
        },
        "env_examples": runtime_env_examples(host_os),
        "detected_layout_type": detected_layout,
        "recommended_packet_tracer_root": str(recommended_root) if recommended_root else "",
        "recommended_packet_tracer_saves_root": str(recommended_saves_root) if recommended_saves_root else "",
        "packet_tracer_root": str(packet_tracer_root) if packet_tracer_root else "",
        "packet_tracer_saves_root": str(packet_tracer_saves) if packet_tracer_saves else "",
        "packet_tracer_exe": str(packet_tracer_exe) if packet_tracer_exe else "",
        "python_version": twofish.get("python_version", ""),
        "python_support_status": twofish.get("python_support_status", "unknown"),
        "python_support_message": twofish.get("python_support_message", "unknown"),
        "expected_twofish_patterns": resolved_patterns,
        "twofish_search_roots": resolved_search_roots,
        "resolved_twofish_path": resolved_twofish_path,
        "twofish_source": twofish.get("twofish_source", ""),
        "twofish_load_status": twofish.get("twofish_load_status", "unknown"),
        "twofish_message": twofish.get("twofish_message", "unknown"),
        "twofish_sha256": twofish.get("twofish_sha256", ""),
        "bridge_resolution": bridge_resolution,
        "bridge_path_source": "env" if bridge_resolution == "external_env" else "repo" if bridge_resolution == "repo_local" else "",
        "bridge_recommendation": bridge_recommendation,
        "runtime_contract_notes": runtime_contract_notes,
        "target_version": donor.get("target_version", ""),
        "resolved_donor_path": donor.get("resolved_donor_path", ""),
        "donor_version": donor.get("donor_version", ""),
        "donor_source": donor.get("donor_source", ""),
        "donor_status": donor.get("status", "unknown"),
        "donor_message": donor.get("message", "unknown"),
        "donor_blocking_reason": donor.get("blocking_reason", ""),
        "donor_candidates": donor.get("candidate_paths", []),
        "capability_impact": capability_impact,
        "runtime_blockers": runtime_blockers,
        "ready_operations": ready_operations,
        "blocked_operations": blocked_operations,
        "what_currently_works": what_currently_works,
        "what_is_blocked": what_is_blocked,
        "why_it_is_blocked": why_it_is_blocked,
        "best_next_fix": best_next_fix,
        "doctor_summary": doctor_summary,
        "runtime_grade": runtime_grade,
        "recommended_next_steps": recommended_next_steps,
        "blocking_reason": " | ".join(blocking_reasons) if blocking_reasons else "",
    }


def main() -> int:
    print(json.dumps(collect_runtime_doctor()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
