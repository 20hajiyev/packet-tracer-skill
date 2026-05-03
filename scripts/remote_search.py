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
PERMISSIVE_LICENSES = {
    "APACHE-2.0",
    "BSD-2-CLAUSE",
    "BSD-3-CLAUSE",
    "CC0-1.0",
    "ISC",
    "MIT",
    "UNLICENSE",
}
REMOTE_AUDIT_FILENAME = "remote-sample-audit.json"


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
    candidate_promotion_status: str = "reference_only"
    imported_file_count: int = 0
    pkt_file_count: int = 0
    pka_file_count: int = 0
    readme_file_count: int = 0
    license_file_count: int = 0


def is_permissive_license(license_or_permission: str | None) -> bool:
    value = (license_or_permission or "").strip().upper()
    return value in PERMISSIVE_LICENSES


def candidate_promotion_status(license_or_permission: str | None) -> str:
    return "validated_curated" if is_permissive_license(license_or_permission) else "reference_only"


def candidate_is_curated_eligible(candidate: RemoteSearchCandidate) -> bool:
    return candidate.candidate_promotion_status == "validated_curated"


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
                    candidate_promotion_status=candidate_promotion_status(
                        str((item.get("license") or {}).get("spdx_id") or "unknown")
                    ),
                )
            )
            if len(candidates) >= max_results:
                return candidates
    return candidates


def _allowed_archive_member(filename: str) -> bool:
    lower_name = filename.lower()
    return (
        lower_name.endswith(".pkt")
        or lower_name.endswith(".pka")
        or lower_name.endswith("readme.md")
        or lower_name.endswith("license")
        or lower_name.endswith("license.md")
        or lower_name.endswith("license.txt")
    )


def _increment_file_counters(candidate: RemoteSearchCandidate, target: Path) -> None:
    lower_name = target.name.lower()
    candidate.imported_file_count += 1
    if lower_name.endswith(".pkt"):
        candidate.pkt_file_count += 1
    elif lower_name.endswith(".pka"):
        candidate.pka_file_count += 1
    elif lower_name == "readme.md":
        candidate.readme_file_count += 1
    elif lower_name in {"license", "license.md", "license.txt"}:
        candidate.license_file_count += 1


def _clear_import_destination(dest_root: Path) -> None:
    if not dest_root.exists():
        return
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


def auto_import_remote_candidates(
    candidates: list[RemoteSearchCandidate],
    import_cache_root: Path,
    *,
    max_results: int = 3,
    dry_run: bool = False,
) -> list[RemoteSearchCandidate]:
    imported: list[RemoteSearchCandidate] = []
    if not dry_run:
        import_cache_root.mkdir(parents=True, exist_ok=True)
    for candidate in candidates[:max_results]:
        candidate.candidate_promotion_status = candidate_promotion_status(candidate.license_or_permission)
        repo_name = candidate.repo_url.rstrip("/").split("/")[-1]
        owner_name = candidate.repo_url.rstrip("/").split("/")[-2] if "/" in candidate.repo_url.rstrip("/") else "repo"
        dest_root = import_cache_root / f"{owner_name}_{repo_name}"
        archive_url = candidate.archive_url
        if dry_run:
            candidate.import_status = "dry_run"
            imported.append(candidate)
            continue
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
                _clear_import_destination(dest_root)
                dest_root.mkdir(parents=True, exist_ok=True)
                for member in archive.infolist():
                    if not _allowed_archive_member(member.filename):
                        continue
                    cleaned = re.sub(r"^[^/]+/", "", member.filename).strip("/")
                    if not cleaned:
                        continue
                    target = dest_root / cleaned
                    try:
                        target.resolve().relative_to(dest_root.resolve())
                    except ValueError:
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if member.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    with archive.open(member) as source, target.open("wb") as sink:
                        sink.write(source.read())
                    _increment_file_counters(candidate, target)
                candidate.path = str(dest_root)
                candidate.import_status = "imported"
        except zipfile.BadZipFile:
            pass
        imported.append(candidate)
    return imported


def _decode_audit_for_root(root: Path, license_or_permission: str) -> dict[str, object]:
    pkt_paths = sorted(root.rglob("*.pkt")) if root.exists() else []
    decode_success_count = 0
    decode_failure_count = 0
    detected_features: set[str] = set()
    detected_families: set[str] = set()
    for pkt_path in pkt_paths:
        try:
            from sample_catalog import summarize_pkt_descriptor

            descriptor = summarize_pkt_descriptor(
                pkt_path,
                str(pkt_path.relative_to(root)),
                origin="external-reference",
                prototype_eligible=False,
                trust_level="reference-only",
                role="reference",
                license_or_permission=license_or_permission,
                promotion_status="reference_only",
                donor_eligible=False,
            )
        except Exception:
            decode_failure_count += 1
            continue
        decode_success_count += 1
        detected_features.update(descriptor.capability_tags)
        detected_features.update(descriptor.validated_edit_capabilities)
        detected_families.update(descriptor.archetype_tags)
        detected_families.update(descriptor.device_families)
        detected_families.update(descriptor.topology_tags)
    return {
        "decode_status": "not_run" if not pkt_paths else ("ok" if decode_failure_count == 0 else "partial_or_failed"),
        "decode_success_count": decode_success_count,
        "decode_failure_count": decode_failure_count,
        "detected_feature_tags": sorted(detected_features),
        "detected_feature_families": sorted(detected_families),
    }


def build_remote_sample_audit(
    candidates: list[RemoteSearchCandidate],
    import_cache_root: Path,
) -> dict[str, object]:
    entries: list[dict[str, object]] = []
    license_counts: dict[str, int] = {}
    for candidate in candidates:
        license_value = candidate.license_or_permission or "unknown"
        license_counts[license_value] = license_counts.get(license_value, 0) + 1
        entry = asdict(candidate)
        if candidate.path:
            entry.update(_decode_audit_for_root(Path(candidate.path), candidate.license_or_permission))
        else:
            entry.update(
                {
                    "decode_status": "not_run",
                    "decode_success_count": 0,
                    "decode_failure_count": 0,
                    "detected_feature_tags": [],
                    "detected_feature_families": [],
                }
            )
        if candidate.candidate_promotion_status == "validated_curated" and int(entry.get("decode_success_count", 0)) > 0:
            entry["validation_promotion_status"] = "validated_curated"
        else:
            entry["validation_promotion_status"] = "reference_only"
        entries.append(entry)
    return {
        "audit_version": "1.0",
        "cache_root": str(import_cache_root),
        "raw_pkt_policy": "remote Packet Tracer files stay local/cache-only and are not committed or packed",
        "candidate_count": len(candidates),
        "imported_repo_count": sum(1 for candidate in candidates if candidate.import_status == "imported"),
        "dry_run_repo_count": sum(1 for candidate in candidates if candidate.import_status == "dry_run"),
        "pkt_file_count": sum(candidate.pkt_file_count for candidate in candidates),
        "pka_file_count": sum(candidate.pka_file_count for candidate in candidates),
        "decode_success_count": sum(int(entry.get("decode_success_count", 0)) for entry in entries),
        "decode_failure_count": sum(int(entry.get("decode_failure_count", 0)) for entry in entries),
        "license_counts": license_counts,
        "promotion_status_counts": {
            status: sum(1 for candidate in candidates if candidate.candidate_promotion_status == status)
            for status in sorted({candidate.candidate_promotion_status for candidate in candidates})
        },
        "validation_promotion_status_counts": {
            status: sum(1 for entry in entries if entry.get("validation_promotion_status") == status)
            for status in sorted({str(entry.get("validation_promotion_status")) for entry in entries})
        },
        "top_gaps_filled_by_imported_samples": sorted(
            {
                feature
                for entry in entries
                for feature in entry.get("detected_feature_tags", [])
                if isinstance(feature, str)
            }
        )[:25],
        "candidates": entries,
    }


def write_remote_sample_audit(
    candidates: list[RemoteSearchCandidate],
    import_cache_root: Path,
    audit_path: Path | None = None,
) -> dict[str, object]:
    payload = build_remote_sample_audit(candidates, import_cache_root)
    target = audit_path or (import_cache_root / REMOTE_AUDIT_FILENAME)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return payload


def asdict_list(candidates: list[RemoteSearchCandidate]) -> list[dict[str, object]]:
    return [asdict(candidate) for candidate in candidates]
