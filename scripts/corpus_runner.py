#!/usr/bin/env python3
"""Run a set of prompts end to end and record what actually happened.

Capability claims in this repo were hand-maintained for a long time, which is
how it ended up asserting things no one had measured. This runner produces the
evidence instead: prompt in, `.pkt` out, structural check, and optionally a real
Packet Tracer open. The result file is the input for any readiness claim.

    python scripts/corpus_runner.py                 # structural tier only
    python scripts/corpus_runner.py --open          # also open each file in PT
    python scripts/corpus_runner.py --case campus   # one case

Results land in `output/corpus-results.json`, which is gitignored: this is
evidence about *this* machine's Packet Tracer, not a portable claim.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / "scripts"))

import pkt_verify  # noqa: E402

DEFAULT_RESULTS = SKILL_ROOT / "output" / "corpus-results.json"


@dataclass(frozen=True)
class CorpusCase:
    name: str
    prompt: str
    expects: str = "generate"  # generate | refuse
    note: str = ""


# Deliberately spans the shapes the donor cannot supply directly, because that
# is where `PACKET_TRACER_LINK_STRATEGY=create` is actually exercised.
CORPUS: tuple[CorpusCase, ...] = (
    CorpusCase("minimal", "1 router 1 switch ve 3 komputer qur"),
    CorpusCase("two_switch_chain", "2 switch 1 router ve 4 komputer qur"),
    CorpusCase(
        "campus_star_vlan",
        "3 dene switch ve 6 komputer ve 1 router vlanlarda 10,20,30",
        note="star target on a chain donor; needs a created link",
    ),
    CorpusCase("four_switch", "4 switch 1 router 8 komputer qur"),
    CorpusCase("server_lan", "1 router 1 switch 2 komputer 1 server qur"),
    CorpusCase("hosts_only", "1 switch ve 5 komputer qur"),
    CorpusCase(
        "vlan_uneven",
        "2 switch 1 router 7 komputer vlanlarda 10,20",
        note="7 hosts over 2 VLANs exercises the uneven split",
    ),
    CorpusCase(
        "no_devices",
        "sebeke haqqinda melumat ver",
        expects="refuse",
        note="not a topology request; must not invent one",
    ),
)


@dataclass
class CaseResult:
    name: str
    prompt: str
    expects: str
    note: str = ""
    generated: bool = False
    structural_passed: bool | None = None
    device_count: int = 0
    link_count: int = 0
    version: str = ""
    container: str = ""
    open_status: str = ""
    seconds: float = 0.0
    outcome: str = ""
    detail: str = ""
    failures: list[str] = field(default_factory=list)


def run_case(case: CorpusCase, output_dir: Path, do_open: bool, timeout: int) -> CaseResult:
    result = CaseResult(name=case.name, prompt=case.prompt, expects=case.expects, note=case.note)
    output_path = output_dir / f"corpus_{case.name}.pkt"
    output_path.unlink(missing_ok=True)

    started = time.monotonic()
    completed = subprocess.run(
        [sys.executable, str(SKILL_ROOT / "scripts" / "generate_pkt.py"),
         "--prompt", case.prompt, "--output", str(output_path)],
        capture_output=True,
        text=True,
        cwd=str(SKILL_ROOT),
    )
    result.seconds = round(time.monotonic() - started, 1)
    result.generated = output_path.exists()

    if not result.generated:
        result.detail = (completed.stdout or completed.stderr or "").strip()[-400:]
        result.outcome = "refused_as_expected" if case.expects == "refuse" else "unexpected_refusal"
        return result

    if case.expects == "refuse":
        result.outcome = "unexpected_generation"

    report = pkt_verify.structural_check(output_path)
    result.structural_passed = report.passed
    result.device_count = report.device_count
    result.link_count = report.link_count
    result.version = report.version
    result.container = report.container
    result.failures = report.failures

    if not report.passed:
        result.outcome = result.outcome or "structural_failed"
        return result

    if do_open:
        open_report = pkt_verify.open_check(output_path, timeout_seconds=timeout)
        result.open_status = open_report.status
        result.outcome = result.outcome or ("verified" if open_report.opened else "generated_unverified")
    else:
        result.outcome = result.outcome or "generated_unverified"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--open", action="store_true", help="launch Packet Tracer for each generated file")
    parser.add_argument("--case", action="append", help="run only these cases (repeatable)")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    args = parser.parse_args()

    selected = [case for case in CORPUS if not args.case or case.name in args.case]
    if not selected:
        print(f"no cases matched {args.case}", file=sys.stderr)
        return 2

    output_dir = SKILL_ROOT / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for case in selected:
        result = run_case(case, output_dir, args.open, args.timeout)
        results.append(result)
        flag = {
            "verified": "OK  ",
            "generated_unverified": "GEN ",
            "refused_as_expected": "REF ",
        }.get(result.outcome, "FAIL")
        print(
            f"{flag} {result.name:20} {result.outcome:22} "
            f"devices={result.device_count:<3} links={result.link_count:<3} "
            f"open={result.open_status or '-':16} {result.seconds}s"
        )
        if result.failures:
            for failure in result.failures[:3]:
                print(f"       {failure}")

    payload = {
        "cases": [asdict(item) for item in results],
        "verified": sum(1 for item in results if item.outcome == "verified"),
        "generated": sum(1 for item in results if item.generated),
        "unexpected": sum(
            1 for item in results if item.outcome in {"unexpected_refusal", "unexpected_generation", "structural_failed"}
        ),
        "total": len(results),
    }
    args.results.parent.mkdir(parents=True, exist_ok=True)
    args.results.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(
        f"\n{payload['generated']}/{payload['total']} generated, "
        f"{payload['verified']} opened in Packet Tracer, "
        f"{payload['unexpected']} unexpected. Results: {args.results}"
    )
    return 1 if payload["unexpected"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
