from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import remote_search as remote_search_module  # noqa: E402
from intent_parser import parse_intent  # noqa: E402
from remote_search import auto_import_remote_candidates, build_remote_search_queries, search_remote_candidates  # noqa: E402


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
    assert Path(imported[0].path, "labs", "campus.pkt").exists()
