"""A layout pass that nothing calls is a pass that does nothing.

`_compact_stray_devices` was written, unit-tested, and wired in after the wrong
`_separate_overlapping_devices` call -- the one in the editor path, not the one
in the generation pipeline. Its five unit tests passed, the corpus regenerated,
and every lab was still 2550 units wide. The helper was never reached.

Unit tests cannot catch that: they call the function directly, which is exactly
the thing the pipeline was not doing. So this checks the wiring instead. Both
places that finish a lab run the separation pass, and both must follow it with
the compaction pass, or a lab still opens on blank canvas with its topology off
to the left.
"""

from __future__ import annotations

import re
from pathlib import Path

SOURCE = (Path(__file__).resolve().parents[1] / "scripts" / "generate_pkt.py").read_text(
    encoding="utf-8"
)


def test_every_layout_finish_compacts_strays() -> None:
    calls = [
        match.start()
        for match in re.finditer(r"^\s*_separate_overlapping_devices\(root\)\s*$", SOURCE, re.M)
    ]
    assert calls, "the separation pass is not called anywhere"

    for position in calls:
        following = SOURCE[position : position + 400]
        assert "_compact_stray_devices(root)" in following, (
            "a lab is finished without pulling donor leftovers back beside it; "
            "every _separate_overlapping_devices(root) call needs "
            "_compact_stray_devices(root) after it"
        )


def test_the_shortfall_report_runs_before_the_donor_line() -> None:
    """The warning has to reach the same output a user reads for the donor."""
    assert "_report_undelivered_devices(root, blueprint)" in SOURCE
    report_at = SOURCE.index("_report_undelivered_devices(root, blueprint)")
    donor_at = SOURCE.index('print(f"Selected donor:')
    assert report_at < donor_at
