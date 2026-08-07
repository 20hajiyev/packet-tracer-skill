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
    """The warning has to reach the same output a user reads for the donor.

    Written first as `"_report_undelivered_devices(root, blueprint)" in SOURCE`,
    which pinned the argument's spelling rather than the property. Changing the
    check to measure against the pre-adaptation request renamed that argument
    and the test failed while the behaviour was correct. It now matches the
    call however it is spelled.
    """
    call = re.search(r"_report_undelivered_devices\(root, \w+\)", SOURCE)
    assert call, "generation never reports a shortfall"
    donor_at = SOURCE.index('print(f"Selected donor:')
    assert call.start() < donor_at


def test_both_checks_measure_against_the_request_not_the_donor_rewrite() -> None:
    """Donor adaptation rewrites blueprint names, so neither check may read it.

    `SW3` became `MultiLayerSwitch1` in the blueprint during donor adaptation,
    and a check reading that blueprint saw nothing missing while the lab really
    was short of the `SW3` the prompt asked for.
    """
    for function in ("_adopt_planned_names", "_report_undelivered_devices"):
        call = re.search(rf"{function}\(root, (\w+)\)", SOURCE)
        assert call, f"{function} is never called"
        assert call.group(1) != "blueprint", (
            f"{function} reads the donor-adapted blueprint; it must read the "
            "device list captured before donor adaptation"
        )
