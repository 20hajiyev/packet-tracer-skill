"""The one thing recomputing from the environment cannot recover.

`--doctor`, `--parity-report` and `--explain-plan` all re-derive from the
install, the donor registry and the bridge, so a lost conversation costs only
the time to run them again. Part-way through a chain of `--explain-plan` ->
`--edit` -> `--parity-report` there is one question with no such source: which
lab is being worked on, and which step comes next.

These tests hold the log to the three promises that make it safe to write one:
it never carries a secret, it never carries weight, and it never claims a
position it has not checked.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import session_log  # noqa: E402


@pytest.fixture
def log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "session-log.jsonl"
    monkeypatch.setenv("PKT_SESSION_LOG", str(path))
    monkeypatch.setattr(session_log, "_DETAILED", False)
    return path


def _lab(tmp_path: Path, name: str = "lab.pkt", body: bytes = b"a lab") -> Path:
    path = tmp_path / name
    path.write_bytes(body)
    return path


def test_a_secret_in_a_prompt_never_reaches_the_log(log: Path, tmp_path: Path) -> None:
    """`ssid EvSebeke wpa2 sifre Gizli123` is an ordinary edit request.

    Its parsed operations carry the passphrase in a field called `passphrase`,
    and two more operations carry `password` while `set_bgp_neighbor` carries
    `community`. This is why facts are allow-listed rather than filtered: a
    deny-list would leak the first secret field added after it was written.
    """
    session_log.record(
        "edit",
        artifact=_lab(tmp_path),
        facts={
            "device_counts": {"WirelessRouter": 1},
            "passphrase": "Gizli123",
            "password": "s3cret",
            "community": "private",
            "prompt": "Aysel Qurbanova ofis 192.168.44.7 ucun 3 switch qur",
        },
    )
    written = log.read_text(encoding="utf-8")
    for secret in ("Gizli123", "s3cret", "private", "Aysel", "192.168.44.7"):
        assert secret not in written, f"{secret!r} reached the log"
    assert "WirelessRouter" in written, "the allow-listed fact should survive"


def test_an_unknown_fact_is_dropped_rather_than_kept(log: Path) -> None:
    session_log.record("generate", facts={"vlan_ids": [10], "something_new": "whatever"})
    entry = session_log.read_entries(log)[0]
    assert entry["facts"] == {"vlan_ids": [10]}


def test_a_corrupt_log_is_ignored_not_fatal(log: Path) -> None:
    log.write_text("{not json at all\n{\"v\": 1, \"command\": \"generate\"}\n", encoding="utf-8")
    entries = session_log.read_entries(log)
    assert [entry["command"] for entry in entries] == ["generate"]


def test_the_log_is_bounded(log: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(session_log, "MAX_ENTRIES", 5)
    for index in range(12):
        session_log.record("generate", facts={"device_count": index})
    kept = session_log.read_entries(log)
    assert len(kept) == 5
    assert kept[-1]["facts"]["device_count"] == 11, "the newest steps are the ones worth keeping"


def test_logging_off_writes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "session-log.jsonl"
    monkeypatch.setenv("PKT_SESSION_LOG", "off")
    session_log.record("generate", facts={"vlan_ids": [10]})
    assert not path.exists()
    assert session_log.read_entries(path) == []


def test_a_position_is_claimed_only_when_the_lab_still_matches(log: Path, tmp_path: Path) -> None:
    """The check is the whole point.

    A checkpoint believed without checking would be the defect this skill
    spends its passes hunting: one fact derived twice with nothing comparing
    the derivations.
    """
    lab = _lab(tmp_path)
    session_log.record("generate", artifact=lab)

    matching = session_log.resume_report(lab, log)
    assert matching["matches_log"] is True
    assert "still matches" in matching["summary"]

    lab.write_bytes(b"edited by hand")
    changed = session_log.resume_report(lab, log)
    assert changed["matches_log"] is False
    assert "not claimed" in changed["summary"]


def test_a_lab_that_is_gone_is_reported_as_gone(log: Path, tmp_path: Path) -> None:
    lab = _lab(tmp_path)
    session_log.record("generate", artifact=lab)
    lab.unlink()
    report = session_log.resume_report(lab, log)
    assert report["exists"] is False
    assert report["matches_log"] is False


def test_an_unknown_lab_says_so_without_guessing(log: Path, tmp_path: Path) -> None:
    report = session_log.resume_report(tmp_path / "never-seen.pkt", log)
    assert report["known"] is False
    assert report["steps"] == 0


def test_one_lab_reached_by_two_spellings_is_one_lab(log: Path, tmp_path: Path) -> None:
    """A `Path` prints with backslashes on Windows and the shell hands over forward ones."""
    lab = _lab(tmp_path)
    session_log.record("generate", artifact=lab)
    session_log.record("coherence-report", source=str(lab).replace("\\", "/"))
    assert len(session_log.artifacts_seen(log)) == 1
    assert len(session_log.history_for(lab, log)) == 2


def test_concurrent_writers_interleave_lines_not_characters(log: Path) -> None:
    """Two agents at once must not be able to corrupt a log neither may depend on."""
    for index in range(40):
        session_log.record("generate", facts={"device_count": index})
    lines = log.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 40
    for line in lines:
        json.loads(line)


@pytest.mark.requires_donors
def test_deleting_the_log_changes_no_result(tmp_path: Path) -> None:
    """Learning is an optimisation; this is not even that. It must carry no weight."""
    first = tmp_path / "with-log.pkt"
    second = tmp_path / "without-log.pkt"
    prompt = "2 switch 1 router 4 komputer qur vlan 10 20"

    def _run(output: Path, env_value: str) -> subprocess.CompletedProcess:
        import os

        env = dict(os.environ)
        env["PKT_SESSION_LOG"] = env_value
        env["PYTHONIOENCODING"] = "utf-8"
        return subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "generate_pkt.py"),
             "--prompt", prompt, "--output", str(output)],
            capture_output=True, text=True, cwd=str(ROOT), env=env, timeout=1800,
        )

    _run(first, str(tmp_path / "log.jsonl"))
    _run(second, "off")
    if not (first.exists() and second.exists()):
        pytest.skip("generation needs a local donor lab")

    # Compared as content, not as bytes. Two writes of the same lab produce
    # different container bytes -- measured at 0 differing values out of 18351
    # decoded fields, so the difference is in the encoding and not in anything
    # the lab says. Asserting on bytes here would fail for a reason that has
    # nothing to do with the log.
    from generate_pkt import decode_pkt_to_root

    def _content(path: Path) -> list[str]:
        root = decode_pkt_to_root(path)
        return [f"{node.tag}={(node.text or '').strip()}" for node in root.iter()]

    assert _content(first) == _content(second), "the log changed the lab it was only supposed to describe"


def test_the_log_never_ships(tmp_path: Path) -> None:
    """`output/` is gitignored and in no `package.json` file list. Both, checked."""
    import json as _json

    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "output/" in ignore

    files = _json.loads((ROOT / "package.json").read_text(encoding="utf-8"))["files"]
    assert not [pattern for pattern in files if pattern.startswith("output")]
    assert session_log.DEFAULT_LOG_PATH.parent.name == "output"
