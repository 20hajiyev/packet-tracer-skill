"""The open check has to give the same answer twice for the same file.

Two false verdicts were measured, and both sent an investigation after a
defect that did not exist.

A lab checked five times in a row answered `opened, timeout, timeout, opened,
opened`. The check excludes every window title present before it launches --
which is right, since a window Packet Tracer already had on screen is not
evidence this check opened anything -- but re-checking the same file means the
title it is waiting for is exactly the one that was excluded, so it goes blind
to its own success.

And a bisect over 57 plan operations reported one step `refused`; the same file
re-checked afterwards opened five times out of five. Packet Tracer raises its
incompatible-file dialog for whatever it was asked to load *previously*, and
that dialog is a window which did not exist when the next check started, so it
was counted against the wrong file.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import pkt_verify  # noqa: E402
from pkt_verify import OpenReport, open_check  # noqa: E402


def _answers(monkeypatch, statuses: list[str]) -> list[str]:
    """Drive `open_check` with a scripted sequence of single-launch verdicts."""
    remaining = list(statuses)
    seen: list[str] = []

    def fake_once(pkt_path, timeout_seconds=None):  # noqa: ARG001
        status = remaining.pop(0) if remaining else "timeout"
        seen.append(status)
        return OpenReport(status=status, pkt_path=str(pkt_path))

    monkeypatch.setattr(pkt_verify, "_open_check_once", fake_once)
    return seen


def test_an_open_is_believed_the_first_time(monkeypatch) -> None:
    seen = _answers(monkeypatch, ["opened", "refused"])
    assert open_check("lab.pkt").status == "opened"
    # The second launch never happens: an open costs nothing to trust, and the
    # corpus would otherwise pay for a second launch on every passing lab.
    assert seen == ["opened"]


def test_a_refusal_that_does_not_reproduce_is_not_reported(monkeypatch) -> None:
    seen = _answers(monkeypatch, ["refused", "opened"])
    assert open_check("lab.pkt").status == "opened"
    assert seen == ["refused", "opened"]


def test_a_timeout_that_does_not_reproduce_is_not_reported(monkeypatch) -> None:
    _answers(monkeypatch, ["timeout", "opened"])
    assert open_check("lab.pkt").status == "opened"


def test_a_refusal_that_reproduces_is_reported(monkeypatch) -> None:
    seen = _answers(monkeypatch, ["refused", "refused"])
    assert open_check("lab.pkt").status == "refused"
    assert seen == ["refused", "refused"]


def test_a_single_attempt_reports_what_it_saw(monkeypatch) -> None:
    _answers(monkeypatch, ["refused", "opened"])
    assert open_check("lab.pkt", attempts=1).status == "refused"


def test_the_probe_copy_gets_a_name_no_window_can_be_showing(tmp_path) -> None:
    lab = tmp_path / "leased_line.pkt"
    lab.write_bytes(b"not really a lab")

    first = pkt_verify._unique_probe_copy(lab)
    second = pkt_verify._unique_probe_copy(lab)

    assert first != lab and second != lab and first != second
    # Beside the original, because labs reference their artwork by relative
    # path and a copy elsewhere is a different file in a way that matters.
    assert first.parent == lab.parent
    assert first.read_bytes() == lab.read_bytes()

    for probe in (first, second):
        pkt_verify._discard_probe_copy(probe, lab)
        assert not probe.exists()
    assert lab.exists()


def test_discarding_never_deletes_the_lab_itself(tmp_path) -> None:
    """`_unique_probe_copy` returns the original if the copy could not be made."""
    lab = tmp_path / "leased_line.pkt"
    lab.write_bytes(b"not really a lab")
    pkt_verify._discard_probe_copy(lab, lab)
    assert lab.exists()
