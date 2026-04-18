from __future__ import annotations

from dataclasses import asdict, dataclass
import io
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from intent_parser import IntentPlan

GITHUB_SEARCH_API = "https://api.github.com/search/repositories"


@dataclass
class RemoteSearchCandidate:
    repo_url: str
    path: str
    source: str
    search_reason: str
    license_or_permission: str
    import_status: str
    default_branch: str | None = None
    archive_url: str | None = None


def build_remote_search_queries(plan: IntentPlan) -> list[str]:
    query_tokens = ["packet tracer"]
    query_tokens.extend(capability for capability in plan.capabilities[:4] if capability)
    if plan.network_style:
        query_tokens.append(plan.network_style.replace("_", " "))
    if plan.wireless_mode:
        query_tokens.append(plan.wireless_mode.replace("_", " "))
    if plan.device_requirements.get("Switch", 0) > 1:
        query_tokens.append("campus")
    if plan.device_requirements.get("Router", 0):
        query_tokens.append("router")
    if plan.device_requirements.get("Server", 0):
        query_tokens.append("server")
    if plan.vlan_ids:
        query_tokens.append("vlan")
    primary = " ".join(dict.fromkeys(query_tokens))
    alternate = f"{primary} extension:pkt"
    return [primary, alternate]


def _github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "packet-tracer-skill",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def search_remote_candidates(
    plan: IntentPlan,
    provider: str = "github",
    max_results: int = 10,
) -> list[RemoteSearchCandidate]:
    if provider != "github":
        return []
    candidates: list[RemoteSearchCandidate] = []
    seen_urls: set[str] = set()
    for query in build_remote_search_queries(plan):
        params = urllib.parse.urlencode({"q": query, "per_page": max_results, "sort": "stars", "order": "desc"})
        request = urllib.request.Request(f"{GITHUB_SEARCH_API}?{params}", headers=_github_headers())
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
            continue
        for item in payload.get("items", []):
            repo_url = str(item.get("html_url") or "")
            if not repo_url or repo_url in seen_urls:
                continue
            seen_urls.add(repo_url)
            candidates.append(
                RemoteSearchCandidate(
                    repo_url=repo_url,
                    path="",
                    source="github",
                    search_reason=query,
                    license_or_permission=str((item.get("license") or {}).get("spdx_id") or "unknown"),
                    import_status="discovered",
                    default_branch=item.get("default_branch"),
                    archive_url=item.get("archive_url"),
                )
            )
            if len(candidates) >= max_results:
                return candidates
    return candidates


def auto_import_remote_candidates(
    candidates: list[RemoteSearchCandidate],
    import_cache_root: Path,
    *,
    max_results: int = 3,
) -> list[RemoteSearchCandidate]:
    imported: list[RemoteSearchCandidate] = []
    import_cache_root.mkdir(parents=True, exist_ok=True)
    for candidate in candidates[:max_results]:
        repo_name = candidate.repo_url.rstrip("/").split("/")[-1]
        owner_name = candidate.repo_url.rstrip("/").split("/")[-2] if "/" in candidate.repo_url.rstrip("/") else "repo"
        dest_root = import_cache_root / f"{owner_name}_{repo_name}"
        archive_url = candidate.archive_url
        if not archive_url:
            imported.append(candidate)
            continue
        archive_url = archive_url.replace("{archive_format}", "zipball").replace("{/ref}", f"/{candidate.default_branch or 'HEAD'}")
        request = urllib.request.Request(archive_url, headers=_github_headers())
        try:
            with urllib.request.urlopen(request, timeout=40) as response:
                archive_bytes = response.read()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
            imported.append(candidate)
            continue
        try:
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
                if dest_root.exists():
                    for child in dest_root.iterdir():
                        if child.is_dir():
                            for nested in child.rglob("*"):
                                if nested.is_file():
                                    nested.unlink()
                            for nested_dir in sorted([item for item in child.rglob("*") if item.is_dir()], reverse=True):
                                nested_dir.rmdir()
                            child.rmdir()
                        else:
                            child.unlink()
                dest_root.mkdir(parents=True, exist_ok=True)
                for member in archive.infolist():
                    lower_name = member.filename.lower()
                    if not (
                        lower_name.endswith(".pkt")
                        or lower_name.endswith(".pka")
                        or lower_name.endswith("readme.md")
                        or lower_name.endswith("license")
                        or lower_name.endswith("license.md")
                        or lower_name.endswith("license.txt")
                    ):
                        continue
                    cleaned = re.sub(r"^[^/]+/", "", member.filename).strip("/")
                    if not cleaned:
                        continue
                    target = dest_root / cleaned
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if member.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    with archive.open(member) as source, target.open("wb") as sink:
                        sink.write(source.read())
                candidate.path = str(dest_root)
                candidate.import_status = "imported"
        except zipfile.BadZipFile:
            pass
        imported.append(candidate)
    return imported


def asdict_list(candidates: list[RemoteSearchCandidate]) -> list[dict[str, object]]:
    return [asdict(candidate) for candidate in candidates]
