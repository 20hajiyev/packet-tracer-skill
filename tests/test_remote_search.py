from __future__ import annotations

from dataclasses import replace
import io
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import remote_search as remote_search_module  # noqa: E402
from intent_parser import parse_intent  # noqa: E402
from remote_search import (  # noqa: E402
    auto_import_remote_candidates,
    build_remote_sample_audit,
    build_remote_search_queries,
    search_remote_candidates,
)


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


def test_build_remote_search_queries_reflect_prompt_intent() -> None:
    plan = parse_intent("6 sobeli kampus sebekesi qur, vlan, dns, ap, server olsun")
    queries = build_remote_search_queries(plan)
    assert queries
    assert any("packet tracer" in query for query in queries)
    assert any("campus" in query or "vlan" in query for query in queries)


def test_search_remote_candidates_parses_github_response(monkeypatch) -> None:
    payload = json.dumps(
        {
            "items": [
                {
                    "html_url": "https://github.com/example/packet-tracer-labs",
                    "default_branch": "main",
                    "archive_url": "https://api.github.com/repos/example/packet-tracer-labs/{archive_format}{/ref}",
                    "license": {"spdx_id": "MIT"},
                }
            ]
        }
    ).encode("utf-8")

    monkeypatch.setattr(remote_search_module.urllib.request, "urlopen", lambda request, timeout=0: _FakeResponse(payload))
    candidates = search_remote_candidates(parse_intent("vlan ve dhcp labi qur"), max_results=5)
    assert candidates
    assert candidates[0].repo_url == "https://github.com/example/packet-tracer-labs"
    assert candidates[0].import_status == "discovered"


def test_auto_import_remote_candidates_extracts_pkt_files(monkeypatch, tmp_path) -> None:
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w") as archive:
        archive.writestr("repo-main/README.md", "# Packet Tracer Lab")
        archive.writestr("repo-main/labs/campus.pkt", b"fake-pkt")
        archive.writestr("repo-main/LICENSE", "MIT License")
    payload = archive_bytes.getvalue()
    monkeypatch.setattr(remote_search_module.urllib.request, "urlopen", lambda request, timeout=0: _FakeResponse(payload))
    candidate = remote_search_module.RemoteSearchCandidate(
        repo_url="https://github.com/example/repo",
        path="",
        source="github",
        search_reason="packet tracer campus",
        license_or_permission="MIT",
        import_status="discovered",
        default_branch="main",
        archive_url="https://api.github.com/repos/example/repo/{archive_format}{/ref}",
    )
    imported = auto_import_remote_candidates([candidate], tmp_path, max_results=1)
    assert imported[0].import_status == "imported"
    assert imported[0].candidate_promotion_status == "validated_curated"
    assert imported[0].pkt_file_count == 1
    assert imported[0].readme_file_count == 1
    assert imported[0].license_file_count == 1
    assert Path(imported[0].path, "labs", "campus.pkt").exists()


def test_auto_import_remote_candidates_dry_run_does_not_download(monkeypatch, tmp_path) -> None:
    def _fail_urlopen(request, timeout=0):
        raise AssertionError("dry-run must not download archives")

    monkeypatch.setattr(remote_search_module.urllib.request, "urlopen", _fail_urlopen)
    candidate = remote_search_module.RemoteSearchCandidate(
        repo_url="https://github.com/example/repo",
        path="",
        source="github",
        search_reason="packet tracer campus",
        license_or_permission="MIT",
        import_status="discovered",
        default_branch="main",
        archive_url="https://api.github.com/repos/example/repo/{archive_format}{/ref}",
    )
    imported = auto_import_remote_candidates([candidate], tmp_path, max_results=1, dry_run=True)
    assert imported[0].import_status == "dry_run"
    assert imported[0].path == ""
    assert imported[0].candidate_promotion_status == "validated_curated"
    assert not any(tmp_path.iterdir())


def test_unknown_license_candidates_remain_reference_only(monkeypatch, tmp_path) -> None:
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w") as archive:
        archive.writestr("repo-main/labs/security.pkt", b"fake-pkt")
    payload = archive_bytes.getvalue()
    monkeypatch.setattr(remote_search_module.urllib.request, "urlopen", lambda request, timeout=0: _FakeResponse(payload))
    candidate = remote_search_module.RemoteSearchCandidate(
        repo_url="https://github.com/example/repo",
        path="",
        source="github",
        search_reason="packet tracer security",
        license_or_permission="unknown",
        import_status="discovered",
        default_branch="main",
        archive_url="https://api.github.com/repos/example/repo/{archive_format}{/ref}",
    )

    imported = auto_import_remote_candidates([candidate], tmp_path, max_results=1)

    assert imported[0].import_status == "imported"
    assert imported[0].candidate_promotion_status == "reference_only"
    assert Path(imported[0].path, "labs", "security.pkt").exists()


def test_remote_sample_audit_separates_import_and_decode_evidence(tmp_path) -> None:
    imported_root = tmp_path / "example_repo"
    imported_root.mkdir()
    (imported_root / "lab.pkt").write_bytes(b"fake-pkt")
    candidate = remote_search_module.RemoteSearchCandidate(
        repo_url="https://github.com/example/repo",
        path=str(imported_root),
        source="github",
        search_reason="packet tracer campus",
        license_or_permission="MIT",
        import_status="imported",
        candidate_promotion_status="validated_curated",
        pkt_file_count=1,
    )

    audit = build_remote_sample_audit([candidate], tmp_path)

    assert audit["candidate_count"] == 1
    assert audit["pkt_file_count"] == 1
    assert audit["decode_failure_count"] == 1
    assert audit["decode_success_count"] == 0
    assert audit["candidates"][0]["decode_status"] == "partial_or_failed"
    assert audit["candidates"][0]["validation_promotion_status"] == "reference_only"


def test_remote_sample_audit_counts_dry_run_candidates(tmp_path) -> None:
    candidate = remote_search_module.RemoteSearchCandidate(
        repo_url="https://github.com/example/repo",
        path="",
        source="github",
        search_reason="packet tracer campus",
        license_or_permission="unknown",
        import_status="dry_run",
        candidate_promotion_status="reference_only",
    )

    audit = build_remote_sample_audit([replace(candidate)], tmp_path)

    assert audit["dry_run_repo_count"] == 1
    assert audit["promotion_status_counts"]["reference_only"] == 1
    assert audit["validation_promotion_status_counts"]["reference_only"] == 1
    assert audit["candidates"][0]["decode_status"] == "not_run"
