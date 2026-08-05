#!/usr/bin/env python3
"""Verification for generated `.pkt` files, in two tiers.

Structural checks say the bytes are well-formed and internally consistent.
Only Packet Tracer itself can say the file actually opens. The two are kept
apart deliberately, because conflating them is how a repo ends up claiming
runtime proof it never had.

Tier 1 `structural_check` is headless, deterministic and safe for CI.
Tier 2 `open_check` launches Packet Tracer and watches for the file's window.
It replaces the previous `validate_open`, which called `subprocess.Popen` and
immediately printed `{"status": "launched"}` without observing anything at all.
"""

from __future__ import annotations

import json
import platform
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from packet_tracer_env import (
    donor_compatibility,
    donor_tier_is_accepted,
    get_packet_tracer_exe,
    get_packet_tracer_target_version,
)
from pkt_codec import decode_pkt_auto, parse_pkt_xml

DEFAULT_OPEN_TIMEOUT_SECONDS = 150
POLL_INTERVAL_SECONDS = 3


@dataclass
class StructuralReport:
    passed: bool
    pkt_path: str
    version: str = ""
    compatibility_tier: str = ""
    container: str = ""
    device_count: int = 0
    link_count: int = 0
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, object]:
        return {
            "tier": "structural",
            "passed": self.passed,
            "pkt": self.pkt_path,
            "version": self.version,
            "compatibility_tier": self.compatibility_tier,
            "container": self.container,
            "device_count": self.device_count,
            "link_count": self.link_count,
            "failures": self.failures,
            "warnings": self.warnings,
        }


@dataclass
class OpenReport:
    # opened | refused | timeout | process_exited | packet_tracer_missing.
    # `refused` is Packet Tracer's own answer -- the incompatible-file dialog --
    # and is worth distinguishing from `timeout`, which only means nothing was
    # observed in the time allowed.
    status: str
    pkt_path: str
    elapsed_seconds: float = 0.0
    observed_title: str = ""
    detail: str = ""

    @property
    def opened(self) -> bool:
        return self.status == "opened"

    def to_json(self) -> dict[str, object]:
        return {
            "tier": "open",
            "status": self.status,
            "opened": self.opened,
            "pkt": self.pkt_path,
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "observed_title": self.observed_title,
            "detail": self.detail,
        }


def structural_check(pkt_path: str | Path, expected_devices: int | None = None) -> StructuralReport:
    path = Path(pkt_path)
    report = StructuralReport(passed=False, pkt_path=str(path))

    if not path.exists():
        report.failures.append(f"file does not exist: {path}")
        return report
    if path.stat().st_size == 0:
        report.failures.append("file is empty")
        return report

    try:
        xml_bytes, container = decode_pkt_auto(path.read_bytes())
        report.container = container
    except Exception as exc:
        report.failures.append(f"decode failed: {exc}")
        return report

    try:
        root = parse_pkt_xml(xml_bytes)
    except ET.ParseError as exc:
        report.failures.append(f"XML does not parse: {exc}")
        return report

    if root.tag != "PACKETTRACER5":
        report.failures.append(f"unexpected root element: {root.tag}")

    report.version = root.findtext("./VERSION") or ""
    if not report.version:
        report.failures.append("no <VERSION> element")
    else:
        target = get_packet_tracer_target_version()
        report.compatibility_tier = donor_compatibility(report.version, target)
        if not donor_tier_is_accepted(report.compatibility_tier):
            report.failures.append(
                f"version {report.version} is tier '{report.compatibility_tier}' against target {target}"
            )

    devices = root.findall(".//DEVICES/DEVICE")
    links = root.findall(".//LINKS/LINK")
    report.device_count = len(devices)
    report.link_count = len(links)

    if not devices:
        report.failures.append("no devices")

    names: list[str] = []
    ref_to_name: dict[str, str] = {}
    for device in devices:
        name = device.findtext("./ENGINE/NAME") or ""
        if not name:
            report.failures.append("a device has no name")
            continue
        names.append(name)
        save_ref = device.findtext("./ENGINE/SAVE_REF_ID") or ""
        if save_ref:
            ref_to_name[save_ref] = name

    duplicates = {name for name in names if names.count(name) > 1}
    if duplicates:
        report.failures.append(f"duplicate device names: {sorted(duplicates)}")

    # Every link must land on a device that exists. A dangling endpoint is the
    # classic way a pruned donor stops opening.
    #
    # Ports must also be used at most once: one physical interface cannot carry
    # two cables. A generated link that reuses an occupied port produces a lab
    # that looks plausible and is wired wrongly.
    occupied_ports: dict[tuple[str, str], int] = {}
    for index, link in enumerate(links):
        cable = link.find("./CABLE")
        if cable is None:
            report.failures.append(f"link {index} has no CABLE element")
            continue
        endpoints: list[str] = []
        for end in ("FROM", "TO"):
            ref = cable.findtext(end) or ""
            if not ref:
                report.failures.append(f"link {index} has an empty {end} reference")
            elif ref not in ref_to_name:
                report.failures.append(f"link {index} {end} references unknown device {ref!r}")
            else:
                endpoints.append(ref_to_name[ref])

        ports = [(port.text or "").strip() for port in cable.findall("PORT")][:2]
        for device_name, port_name in zip(endpoints, ports):
            if not port_name:
                continue
            key = (device_name, port_name)
            previous = occupied_ports.get(key)
            if previous is not None:
                report.failures.append(
                    f"port {device_name} {port_name} is used by both link {previous} and link {index}"
                )
            else:
                occupied_ports[key] = index

    if expected_devices is not None and report.device_count != expected_devices:
        report.warnings.append(
            f"device count is {report.device_count}, plan expected {expected_devices}; "
            "donor spares are parked rather than deleted"
        )

    report.passed = not report.failures
    return report


# Packet Tracer's own title for the dialog it shows when it will not load a
# file. Detecting it turns a 150-second timeout into an immediate, correctly
# named answer, which is the difference between a corpus run that takes eighty
# minutes to say nothing and one that says which labs are refused.
REFUSAL_WINDOW_TITLE = "Incompatible File"


def _top_level_window_titles() -> list[str]:
    """Every visible top-level window title on the desktop.

    `MainWindowTitle` reports one window per process, and Packet Tracer moves
    which of its windows holds that role: the same open showed only the
    extension's log window in one run and the loaded document in the next. It
    also never shows the modal refusal dialog, so a refused file was
    indistinguishable from a slow one. Enumerating every window is what let
    "opened" and "refused" be told apart at all.
    """
    if platform.system() != "Windows":
        return []
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    titles: list[str] = []

    def collect(hwnd, _lparam):  # pragma: no cover - GUI enumeration
        if not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return True
        buffer = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buffer, length + 1)
        text = buffer.value.strip()
        if text:
            titles.append(text)
        return True

    try:
        user32.EnumWindows(callback_type(collect), 0)
    except OSError:  # pragma: no cover - defensive
        return []
    return titles


def _dismiss_refusal_dialogs() -> int:
    """Close any incompatible-file dialog left on screen, returning how many.

    The dialog is modal: while one is up Packet Tracer will not load anything
    else, so a batch run would report every lab after the first refusal as
    refused too -- and instantly, since the dialog is already there. Clearing it
    before each launch is what makes a sequence of checks mean anything.
    """
    if platform.system() != "Windows":
        return 0
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    handles: list[int] = []

    def collect(hwnd, _lparam):  # pragma: no cover - GUI enumeration
        length = user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return True
        buffer = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buffer, length + 1)
        if REFUSAL_WINDOW_TITLE in buffer.value:
            handles.append(hwnd)
        return True

    try:
        user32.EnumWindows(callback_type(collect), 0)
        for hwnd in handles:
            user32.PostMessageW(hwnd, 0x0010, 0, 0)  # WM_CLOSE
    except OSError:  # pragma: no cover - defensive
        return 0
    if handles:
        time.sleep(1.5)
    return len(handles)


def _windows_titles_matching(stem: str) -> str:
    for title in _top_level_window_titles():
        if stem.lower() in title.lower():
            return title
    return ""


def open_check(
    pkt_path: str | Path,
    timeout_seconds: int = DEFAULT_OPEN_TIMEOUT_SECONDS,
) -> OpenReport:
    """Launch Packet Tracer and wait until the file's window appears.

    Window-title observation is currently implemented for Windows. On other
    hosts the launch still happens and process liveness is reported, which is
    weaker evidence and is labelled as such rather than claimed as an open.
    """
    path = Path(pkt_path).resolve()
    report = OpenReport(status="packet_tracer_missing", pkt_path=str(path))

    executable = get_packet_tracer_exe()
    if executable is None:
        report.detail = "no Packet Tracer executable resolved; set PACKET_TRACER_ROOT"
        return report
    if not path.exists():
        report.status = "process_exited"
        report.detail = f"file does not exist: {path}"
        return report

    _dismiss_refusal_dialogs()
    started = time.monotonic()
    try:
        process = subprocess.Popen([str(executable), str(path)])
    except OSError as exc:
        report.status = "process_exited"
        report.detail = f"could not launch Packet Tracer: {exc}"
        return report

    is_windows = platform.system() == "Windows"
    try:
        while time.monotonic() - started < timeout_seconds:
            if is_windows:
                titles = _top_level_window_titles()
                title = next((entry for entry in titles if path.stem.lower() in entry.lower()), "")
                if title:
                    report.status = "opened"
                    report.observed_title = title
                    report.elapsed_seconds = time.monotonic() - started
                    report.detail = "Packet Tracer window title contains the file name"
                    return report
                refusal = next((entry for entry in titles if REFUSAL_WINDOW_TITLE in entry), "")
                if refusal:
                    report.status = "refused"
                    report.observed_title = refusal
                    report.elapsed_seconds = time.monotonic() - started
                    report.detail = "Packet Tracer put up its incompatible-file dialog"
                    return report

            # Checked after the windows, not before. Packet Tracer runs one
            # instance: launching it again while a copy is open hands the file
            # over and the new process exits at once, which this read as a
            # failure while the file was loading perfectly well behind it.
            if process.poll() is not None and not is_windows:
                report.status = "process_exited"
                report.elapsed_seconds = time.monotonic() - started
                report.detail = f"Packet Tracer exited with code {process.returncode} before the file opened"
                return report

            time.sleep(POLL_INTERVAL_SECONDS)

        report.elapsed_seconds = time.monotonic() - started
        if is_windows:
            report.status = "timeout"
            report.detail = f"no Packet Tracer window titled with {path.stem!r} within {timeout_seconds}s"
        else:
            report.status = "timeout"
            report.detail = (
                "window-title observation is Windows-only; the process stayed alive but the open "
                "was not confirmed. Check manually on this host."
            )
        return report
    finally:
        if process.poll() is None:
            process.terminate()


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Verify a generated Packet Tracer file.")
    parser.add_argument("pkt", help="path to the .pkt file")
    parser.add_argument("--open", action="store_true", help="also launch Packet Tracer and watch for the window")
    parser.add_argument("--timeout", type=int, default=DEFAULT_OPEN_TIMEOUT_SECONDS)
    parser.add_argument("--expect-devices", type=int, default=None)
    args = parser.parse_args()

    structural = structural_check(args.pkt, args.expect_devices)
    payload: dict[str, object] = {"structural": structural.to_json()}

    if args.open:
        payload["open"] = open_check(args.pkt, args.timeout).to_json()

    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if structural.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
