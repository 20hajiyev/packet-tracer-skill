#!/usr/bin/env python3
"""A local, append-only record of what actually worked, so the skill improves with use.

Donor selection is expensive and mostly repetitive: the same scenario families
come back, and the same handful of donors keep winning or keep failing for the
same reasons. Rediscovering that on every run wastes several seconds per
candidate and, worse, throws away the only real evidence the skill ever gets
about which donors survive a Packet Tracer open.

The ledger records the outcome of each generation and feeds it back into donor
ranking on the next run. Nothing is inferred or guessed: an entry is written
only after a real attempt produced a real result.

Privacy and safety rules, deliberately strict:

- the ledger is local only. It is written under `output/`, which is gitignored,
  and it is never committed, packaged, or transmitted anywhere.
- prompts are stored as a normalised fingerprint, not verbatim text, so a lab
  description containing names or addresses does not end up on disk.
- the file is bounded. Old entries are dropped once the cap is reached.
- a corrupt or unreadable ledger is ignored, never fatal. Learning is an
  optimisation; the skill must work identically with the ledger deleted.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LEDGER_PATH = SKILL_ROOT / "output" / "usage-ledger.jsonl"
MAX_ENTRIES = 2000
LEDGER_VERSION = 1

OUTCOME_GENERATED_VERIFIED = "generated_verified"
OUTCOME_GENERATED_UNVERIFIED = "generated_unverified"
OUTCOME_REFUSED = "refused"
OUTCOMES = (OUTCOME_GENERATED_VERIFIED, OUTCOME_GENERATED_UNVERIFIED, OUTCOME_REFUSED)

# Outcomes that count as evidence a donor works, best first.
_SUCCESS_WEIGHT = {
    OUTCOME_GENERATED_VERIFIED: 3,
    OUTCOME_GENERATED_UNVERIFIED: 1,
}


def ledger_path() -> Path:
    override = os.getenv("PKT_USAGE_LEDGER")
    return Path(override).expanduser() if override else DEFAULT_LEDGER_PATH


def ledger_enabled() -> bool:
    """Learning is on by default; `PKT_USAGE_LEDGER=off` disables it entirely."""
    return (os.getenv("PKT_USAGE_LEDGER") or "").strip().lower() not in {"off", "0", "false", "none"}


def prompt_fingerprint(prompt: str) -> str:
    """A stable, non-reversible fingerprint of a prompt's *shape*.

    Digits are collapsed to `#` and case and spacing are normalised, so
    "3 switch 6 pc" and "5 switch 2 pc" share a fingerprint: they are the same
    kind of request, which is exactly the granularity donor reuse needs. The
    result is hashed so no prompt text is ever written to disk.
    """
    normalised = re.sub(r"\d+", "#", (prompt or "").strip().lower())
    normalised = re.sub(r"[^\w#]+", " ", normalised).strip()
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()[:16]


@dataclass
class LedgerEntry:
    scenario_family: str
    donor: str
    outcome: str
    prompt_shape: str = ""
    target_version: str = ""
    donor_version: str = ""
    rejected_donors: list[str] = field(default_factory=list)
    rejection_codes: list[str] = field(default_factory=list)
    recorded_at: str = ""

    def to_json(self) -> dict[str, object]:
        return {
            "v": LEDGER_VERSION,
            "recorded_at": self.recorded_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "scenario_family": self.scenario_family,
            "prompt_shape": self.prompt_shape,
            "donor": self.donor,
            "donor_version": self.donor_version,
            "target_version": self.target_version,
            "outcome": self.outcome,
            "rejected_donors": self.rejected_donors[:20],
            "rejection_codes": self.rejection_codes[:20],
        }


def record(entry: LedgerEntry, path: Path | None = None) -> bool:
    """Append one outcome. Returns False if the ledger is off or unwritable."""
    if not ledger_enabled():
        return False
    if entry.outcome not in OUTCOMES:
        raise ValueError(f"unknown outcome: {entry.outcome}")

    target = path or ledger_path()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry.to_json(), ensure_ascii=False) + "\n")
    except OSError:
        return False

    _trim(target)
    return True


def _trim(path: Path) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    if len(lines) <= MAX_ENTRIES:
        return
    try:
        path.write_text("\n".join(lines[-MAX_ENTRIES:]) + "\n", encoding="utf-8")
    except OSError:
        return


def load_entries(path: Path | None = None) -> list[dict[str, object]]:
    """Read the ledger. A damaged file yields whatever lines still parse."""
    target = path or ledger_path()
    if not ledger_enabled() or not target.exists():
        return []
    entries: list[dict[str, object]] = []
    try:
        raw_lines = target.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and parsed.get("donor"):
            entries.append(parsed)
    return entries


def donor_scores(
    scenario_family: str,
    prompt_shape: str = "",
    path: Path | None = None,
) -> dict[str, int]:
    """Learned preference per donor, as `relative_path -> score`.

    Positive means the donor has produced output for this kind of request
    before; negative means it has been rejected. An exact prompt-shape match
    counts double, because it is stronger evidence than family alone.
    """
    scores: dict[str, int] = defaultdict(int)
    for entry in load_entries(path):
        if str(entry.get("scenario_family") or "") != scenario_family:
            continue
        multiplier = 2 if prompt_shape and entry.get("prompt_shape") == prompt_shape else 1

        donor = str(entry.get("donor") or "")
        weight = _SUCCESS_WEIGHT.get(str(entry.get("outcome") or ""), 0)
        if donor and weight:
            scores[donor] += weight * multiplier

        for rejected in entry.get("rejected_donors") or []:
            name = str(rejected)
            if name:
                scores[name] -= multiplier
    return dict(scores)


def summary(path: Path | None = None) -> dict[str, object]:
    """Human-facing view of what the skill has learned so far."""
    entries = load_entries(path)
    by_outcome: dict[str, int] = defaultdict(int)
    by_family: dict[str, int] = defaultdict(int)
    proven: dict[str, int] = defaultdict(int)
    for entry in entries:
        outcome = str(entry.get("outcome") or "")
        by_outcome[outcome] += 1
        by_family[str(entry.get("scenario_family") or "unknown")] += 1
        if outcome in _SUCCESS_WEIGHT:
            proven[str(entry.get("donor") or "")] += _SUCCESS_WEIGHT[outcome]
    return {
        "ledger_path": str(path or ledger_path()),
        "enabled": ledger_enabled(),
        "entry_count": len(entries),
        "outcomes": dict(by_outcome),
        "scenario_families": dict(by_family),
        "proven_donors": sorted(
            ({"donor": donor, "score": score} for donor, score in proven.items() if score > 0),
            key=lambda item: (-int(item["score"]), str(item["donor"])),
        )[:10],
    }


def main() -> int:
    print(json.dumps(summary(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
