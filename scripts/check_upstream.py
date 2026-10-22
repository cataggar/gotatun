#!/usr/bin/env python3
"""Check mullvad/gotatun for the latest stable release tag and verify fork state."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any, Callable

API_BASE = "https://api.github.com"
DEFAULT_UPSTREAM_REPO = "mullvad/gotatun"
DEFAULT_FORK_REPO = "cataggar/gotatun"

SEMVER_RE = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

TARGET_ARCHIVES = (
    ("x86_64-unknown-linux-gnu", "tar.gz"),
    ("aarch64-unknown-linux-gnu", "tar.gz"),
    ("x86_64-apple-darwin", "tar.gz"),
    ("aarch64-apple-darwin", "tar.gz"),
    ("x86_64-pc-windows-msvc", "zip"),
    ("aarch64-pc-windows-msvc", "zip"),
)

ApiFetcher = Callable[[str], tuple[int, Any]]


def parse_semver(tag: str) -> tuple[int, int, int] | None:
    """Parse a strict stable vX.Y.Z tag into (major, minor, patch) or return None."""
    match = SEMVER_RE.match(tag)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def expected_assets(tag: str) -> list[str]:
    """Return the 12 required release asset filenames for a given tag."""
    assets: list[str] = []
    for target, ext in TARGET_ARCHIVES:
        archive = f"gotatun-{tag}-{target}.{ext}"
        assets.append(archive)
        assets.append(f"{archive}.sha256")
    return assets


def default_api_get(url: str) -> tuple[int, Any]:
    """Perform a GET request to the GitHub API and return (status_code, parsed_json)."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "gotatun-check-upstream",
    }
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if body else None
    except urllib.error.HTTPError as err:
        if err.code == 404:
            return 404, None
        body = err.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API request failed ({err.code}) for {url}: {body}") from err


def select_latest_tag(
    tags_payload: list[dict[str, Any]],
    releases_payload: list[dict[str, Any]] | None = None,
) -> str:
    """Select the highest stable semantic version tag, excluding draft/prerelease releases."""
    excluded_tags: set[str] = set()
    for rel in releases_payload or []:
        if not isinstance(rel, dict):
            continue
        tag_name = rel.get("tag_name")
        if tag_name and (bool(rel.get("draft")) or bool(rel.get("prerelease"))):
            excluded_tags.add(str(tag_name))

    candidates: list[tuple[tuple[int, int, int], str]] = []
    for entry in tags_payload:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str) or name in excluded_tags:
            continue
        parsed = parse_semver(name)
        if parsed is not None:
            candidates.append((parsed, name))

    if not candidates:
        raise RuntimeError("No stable semantic version tags found in upstream repository")

    candidates.sort(key=lambda item: item[0])
    return candidates[-1][1]


def dereference_tag(
    repo: str,
    tag: str,
    api_get: ApiFetcher | None = None,
    allow_missing: bool = False,
) -> str | None:
    """Resolve refs/tags/<tag> (including annotated tags) to a 40-hex commit SHA."""
    if api_get is None:
        api_get = default_api_get
    ref_url = f"{API_BASE}/repos/{repo}/git/ref/tags/{tag}"
    status, data = api_get(ref_url)
    if status == 404:
        if allow_missing:
            return None
        raise RuntimeError(f"Tag ref not found: {repo} refs/tags/{tag}")
    if status != 200 or not isinstance(data, dict):
        raise RuntimeError(f"Unexpected response ({status}) fetching {ref_url}")

    obj = data.get("object")
    if not isinstance(obj, dict):
        raise RuntimeError(f"Malformed ref payload for {repo} refs/tags/{tag}")

    for _ in range(5):
        obj_type = obj.get("type")
        obj_sha = obj.get("sha")
        if not isinstance(obj_sha, str) or not SHA_RE.match(obj_sha):
            raise RuntimeError(f"Invalid object SHA {obj_sha!r} for {repo} tag {tag}")

        if obj_type == "commit":
            return obj_sha
        if obj_type == "tag":
            tag_url = f"{API_BASE}/repos/{repo}/git/tags/{obj_sha}"
            tag_status, tag_data = api_get(tag_url)
            if tag_status != 200 or not isinstance(tag_data, dict):
                raise RuntimeError(
                    f"Unexpected response ({tag_status}) dereferencing annotated tag {tag_url}"
                )
            next_obj = tag_data.get("object")
            if not isinstance(next_obj, dict):
                raise RuntimeError(f"Malformed annotated tag payload for {tag_url}")
            obj = next_obj
            continue

        raise RuntimeError(f"Unsupported git object type {obj_type!r} for {repo} tag {tag}")

    raise RuntimeError(f"Exceeded tag dereference depth for {repo} tag {tag}")


def is_release_complete(tag: str, release_payload: Any) -> bool:
    """Return True iff release is non-draft, non-prerelease, and has all 12 non-empty assets."""
    if not isinstance(release_payload, dict):
        return False
    if bool(release_payload.get("draft")) or bool(release_payload.get("prerelease")):
        return False

    assets = release_payload.get("assets")
    if not isinstance(assets, list):
        return False

    valid_assets: set[str] = set()
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = asset.get("name")
        size = asset.get("size", 0)
        state = asset.get("state")
        if state is not None and state != "uploaded":
            continue
        if isinstance(name, str) and isinstance(size, int) and size > 0:
            valid_assets.add(name)

    required = expected_assets(tag)
    return all(req_name in valid_assets for req_name in required)


def check_upstream(
    upstream_repo: str = DEFAULT_UPSTREAM_REPO,
    fork_repo: str = DEFAULT_FORK_REPO,
    api_get: ApiFetcher | None = None,
) -> dict[str, str]:
    """Inspect upstream and fork state, returning tag, upstream_sha, and needs_publish."""
    if api_get is None:
        api_get = default_api_get
    tags_url = f"{API_BASE}/repos/{upstream_repo}/tags?per_page=100"
    tags_status, tags_data = api_get(tags_url)
    if tags_status != 200 or not isinstance(tags_data, list):
        raise RuntimeError(f"Failed to fetch upstream tags from {tags_url} (status {tags_status})")

    releases_url = f"{API_BASE}/repos/{upstream_repo}/releases?per_page=100"
    rel_status, rel_data = api_get(releases_url)
    if rel_status == 404:
        upstream_releases: list[dict[str, Any]] = []
    elif rel_status == 200 and isinstance(rel_data, list):
        upstream_releases = rel_data
    else:
        raise RuntimeError(
            f"Failed to fetch upstream releases from {releases_url} (status {rel_status})"
        )

    tag = select_latest_tag(tags_data, upstream_releases)
    upstream_sha = dereference_tag(upstream_repo, tag, api_get=api_get, allow_missing=False)
    assert upstream_sha is not None

    fork_sha = dereference_tag(fork_repo, tag, api_get=api_get, allow_missing=True)
    if fork_sha is not None and fork_sha != upstream_sha:
        raise RuntimeError(
            f"Fork tag {fork_repo}@{tag} points to {fork_sha}, "
            f"which conflicts with upstream {upstream_repo}@{tag} ({upstream_sha})"
        )

    fork_rel_url = f"{API_BASE}/repos/{fork_repo}/releases/tags/{tag}"
    fork_rel_status, fork_rel_data = api_get(fork_rel_url)
    if fork_rel_status == 404:
        needs_publish = True
    elif fork_rel_status == 200:
        needs_publish = not is_release_complete(tag, fork_rel_data)
    else:
        raise RuntimeError(
            f"Unexpected response ({fork_rel_status}) checking fork release {fork_rel_url}"
        )

    return {
        "tag": tag,
        "upstream_sha": upstream_sha,
        "needs_publish": "true" if needs_publish else "false",
    }


def write_outputs(outputs: dict[str, str], github_output_path: str | None = None) -> None:
    """Write key=value lines to stdout and, if configured, $GITHUB_OUTPUT."""
    lines = [
        f"tag={outputs['tag']}",
        f"upstream_sha={outputs['upstream_sha']}",
        f"needs_publish={outputs['needs_publish']}",
    ]
    for line in lines:
        print(line)

    if github_output_path:
        with open(github_output_path, "a", encoding="utf-8") as fh:
            for line in lines:
                fh.write(f"{line}\n")


def main() -> int:
    upstream_repo = os.environ.get("UPSTREAM_REPOSITORY") or DEFAULT_UPSTREAM_REPO
    fork_repo = os.environ.get("GITHUB_REPOSITORY") or DEFAULT_FORK_REPO
    github_output = os.environ.get("GITHUB_OUTPUT")

    try:
        outputs = check_upstream(upstream_repo=upstream_repo, fork_repo=fork_repo)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    write_outputs(outputs, github_output_path=github_output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
