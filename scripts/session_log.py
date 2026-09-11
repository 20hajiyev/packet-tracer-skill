#!/usr/bin/env python3
"""Where a multi-step edit session had got to, so a compacted agent can ask.

Almost nothing in this skill lives in conversation memory: `--doctor`,
`--parity-report` and `--explain-plan` all recompute from the environment, so
losing an earlier turn costs nothing but the time to run them again. One thing
is not recoverable that way. Part-way through a chain of `--explain-plan` ->
`--edit` -> `--parity-report` calls, the question "which file am I working on,
and which step of which plan am I on" has no source but the conversation --
and that is exactly what compaction takes.

So each invocation appends a line here, and `--resume` reads it back.

The rules are the usage ledger's, for the same reasons:

- local only. Written under `output/`, which is gitignored and appears in no
  `package.json` file list, so it reaches neither a repository nor a registry.
- **nothing is load-bearing.** Deleting this file must change no result
  anywhere. It answers a question; it never feeds a decision.
- bounded, and a corrupt or unreadable log is ignored rather than fatal.
- `PKT_SESSION_LOG=off` disables it entirely.

And one rule of its own. Facts are recorded by **allow-list**, never by copying
a payload and stripping what looks sensitive. An edit prompt carries secrets in
ordinary fields -- `passphrase` on `set_wireless_ssid`, `password` on three
more operations, `community` on `set_bgp_neighbor` -- so a deny-list would leak
the first secret field anyone adds after this was written. Operation *names and
counts* are recorded; operation *values* never are, and neither is the prompt,
which is kept as the same non-reversible shape fingerprint the ledger uses.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SKILL_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_PATH = SKILL_ROOT / "output" / "session-log.jsonl"
MAX_ENTRIES = 500
LOG_VERSION = 1

# Every fact that may be written. A key absent from here is dropped whatever it
# holds -- see the module docstring for why this is an allow-list.
ALLOWED_FACTS = frozenset(
    {
        "goal",
        "prompt_shape",
        "device_counts",
        "vlan_ids",
        "capabilities",
        "scenario_family",
        "readiness_status",
        "allow_generate",
        "donor",
        "target_version",
        "operation_counts",
        "next_best_action",
        "parity_counts",
        "contradiction_counts",
        "device_count",
        "link_count",
        "opened",
        "detail",
    }
)

# Values are summarised, never copied wholesale, so a long list cannot become a
# long line and a stray string cannot smuggle a secret through a counter.
_MAX_STRING = 200
_MAX_ITEMS = 40

_OFF_WORDS = {"off", "0", "false", "none"}
_ON_WORDS = {"on", "1", "true"}


def log_path() -> Path:
    override = (os.getenv("PKT_SESSION_LOG") or "").strip()
    if override and override.lower() not in (_OFF_WORDS | _ON_WORDS):
        return Path(override).expanduser()
    return DEFAULT_LOG_PATH


def log_enabled() -> bool:
    return (os.getenv("PKT_SESSION_LOG") or "").strip().lower() not in _OFF_WORDS


# Set when a branch has already written a fuller entry for this process, so the
# wrapper around the dispatch does not add a thinner duplicate beside it. The
# wrapper still fires for every command that writes nothing of its own, which
# is the point of wrapping rather than hooking each branch.
_DETAILED = False


def note_detailed() -> None:
    global _DETAILED
    _DETAILED = True


def had_detailed() -> bool:
    return _DETAILED


def _clean(value: Any) -> Any:
    """Reduce a value to something small, printable and free of running text."""
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        return round(value, 3)
    if isinstance(value, str):
        return value[:_MAX_STRING]
    if isinstance(value, dict):
        return {str(key)[:_MAX_STRING]: _clean(item) for key, item in list(value.items())[:_MAX_ITEMS]}
    if isinstance(value, (list, tuple, set)):
        return [_clean(item) for item in list(value)[:_MAX_ITEMS]]
    return str(value)[:_MAX_STRING]


def normalise(path: Path | str | None) -> str:
    """One spelling per file, so one lab is not mistaken for two.

    The same lab arrived down two routes and was listed twice: the generation
    branch passes a `Path`, which prints with backslashes on Windows, while the
    flag branches pass the string the shell gave, which had forward slashes.
    Resolving both collapses separators and relative prefixes together.
    """
    if not path:
        return ""
    try:
        return str(Path(path).resolve())
    except (OSError, ValueError):
        return str(path)


def artifact_digest(path: Path | str | None) -> str:
    """A `.pkt` identifies itself by its bytes.

    Measured before relying on it: decoding a lab and re-encoding it reproduces
    the file byte for byte, so identical content always hashes identically and
    a changed digest means the lab really changed. That is what lets `--resume`
    check its own answer instead of asserting it.
    """
    if not path:
        return ""
    candidate = Path(path)
    try:
        if not candidate.is_file():
            return ""
        return hashlib.sha256(candidate.read_bytes()).hexdigest()
    except OSError:
        return ""


def record(
    command: str,
    *,
    artifact: Path | str | None = None,
    source: Path | str | None = None,
    status: str = "ok",
    facts: dict[str, Any] | None = None,
) -> None:
    """Append one step. Never raises: a broken log must not break a build."""
    if not log_enabled():
        return
    try:
        entry: dict[str, Any] = {
            "v": LOG_VERSION,
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "command": str(command)[:_MAX_STRING],
            "status": str(status)[:_MAX_STRING],
        }
        if artifact:
            entry["artifact"] = normalise(artifact)[:_MAX_STRING]
            entry["artifact_sha256"] = artifact_digest(artifact)
        if source:
            entry["source"] = normalise(source)[:_MAX_STRING]
            entry["source_sha256"] = artifact_digest(source)
        kept = {key: _clean(value) for key, value in (facts or {}).items() if key in ALLOWED_FACTS}
        if kept:
            entry["facts"] = kept

        path = log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        # One write of one line, so concurrent runs interleave whole lines and
        # never characters: two agents working at once cannot corrupt a log
        # neither of them is allowed to depend on anyway.
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        _trim(path)
    except Exception:
        return


def _trim(path: Path) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) <= MAX_ENTRIES:
            return
        path.write_text("\n".join(lines[-MAX_ENTRIES:]) + "\n", encoding="utf-8")
    except Exception:
        return


def read_entries(path: Path | None = None) -> list[dict[str, Any]]:
    """Every readable entry, oldest first. An unreadable line is skipped."""
    target = path or log_path()
    try:
        if not target.is_file():
            return []
        text = target.read_text(encoding="utf-8")
    except OSError:
        return []
    entries: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            entries.append(parsed)
    return entries


def _names_match(entry: dict[str, Any], wanted: Path) -> bool:
    target = normalise(wanted)
    for key in ("artifact", "source"):
        recorded = entry.get(key)
        if not recorded:
            continue
        recorded = str(recorded)
        if normalise(recorded) == target or Path(recorded).name == wanted.name:
            return True
    return False


def history_for(artifact: Path | str, path: Path | None = None) -> list[dict[str, Any]]:
    """The steps touching one lab, oldest first."""
    wanted = Path(artifact)
    return [entry for entry in read_entries(path) if _names_match(entry, wanted)]


def latest_for(artifact: Path | str, path: Path | None = None) -> dict[str, Any] | None:
    steps = history_for(artifact, path)
    return steps[-1] if steps else None


def artifacts_seen(path: Path | None = None) -> list[str]:
    """Every lab the log mentions, most recently touched first."""
    order: list[str] = []
    for entry in read_entries(path):
        for key in ("artifact", "source"):
            name = entry.get(key)
            if not name:
                continue
            name = str(name)
            if name in order:
                order.remove(name)
            order.append(name)
    return list(reversed(order))


def resume_report(artifact: Path | str, path: Path | None = None) -> dict[str, Any]:
    """Where this lab was left, and whether the log still describes it.

    The check is the point. A log that simply asserted a position would be the
    defect this repository keeps finding: a fact derived in one place and
    believed in another, with nothing comparing them. So the lab is re-hashed
    and a position is claimed only when the two agree. Otherwise the mismatch
    is the answer -- which is the same refusal-first stance the rest of the
    skill takes when it cannot prove something.
    """
    wanted = Path(artifact)
    steps = history_for(wanted, path)
    if not steps:
        return {
            "artifact": str(wanted),
            "known": False,
            "matches_log": False,
            "steps": 0,
            "summary": "no recorded steps for this lab",
        }

    last = steps[-1]
    recorded = str(last.get("artifact_sha256") or last.get("source_sha256") or "")
    on_disk = artifact_digest(wanted)
    exists = wanted.is_file()
    matches = bool(on_disk) and bool(recorded) and on_disk == recorded

    if not exists:
        summary = "the lab the log describes is not on disk any more"
    elif not recorded:
        summary = "the last step recorded no digest, so the position cannot be confirmed"
    elif matches:
        summary = f"last step was `{last.get('command')}` and the lab still matches it"
    else:
        summary = "the lab has changed since the last recorded step; position not claimed"

    report: dict[str, Any] = {
        "artifact": str(wanted),
        "known": True,
        "exists": exists,
        "matches_log": matches,
        "steps": len(steps),
        "last_command": last.get("command"),
        "last_status": last.get("status"),
        "at": last.get("at"),
        "summary": summary,
        "history": [
            {"at": step.get("at"), "command": step.get("command"), "status": step.get("status")}
            for step in steps[-10:]
        ],
    }
    facts = last.get("facts") or {}
    if isinstance(facts, dict):
        if facts.get("next_best_action"):
            report["next_best_action"] = facts["next_best_action"]
        if facts:
            report["last_facts"] = facts
    return report
