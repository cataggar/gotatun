#!/usr/bin/env python3
"""Unit tests for scripts/check_upstream.py."""

from __future__ import annotations

import io
import os
import pathlib
import sys
import unittest
from typing import Any
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check_upstream  # noqa: E402


COMMIT_SHA = "a" * 40
ANNOTATED_TAG_SHA = "b" * 40
CONFLICT_SHA = "c" * 40


def make_complete_assets(tag: str) -> list[dict[str, Any]]:
    return [
        {"name": name, "size": 1024, "state": "uploaded"}
        for name in check_upstream.expected_assets(tag)
    ]


class FakeGitHubApi:
    """In-memory mock for GitHub REST API endpoints used by check_upstream."""

    def __init__(self) -> None:
        self.responses: dict[str, tuple[int, Any]] = {}

    def set(self, path: str, status: int, payload: Any) -> None:
        url = f"{check_upstream.API_BASE}{path}"
        self.responses[url] = (status, payload)

    def __call__(self, url: str) -> tuple[int, Any]:
        if url not in self.responses:
            raise AssertionError(f"Unexpected API call: {url}")
        return self.responses[url]


class CheckUpstreamTests(unittest.TestCase):
    def test_parse_semver_and_select_latest_tag(self) -> None:
        self.assertEqual(check_upstream.parse_semver("v0.10.2"), (0, 10, 2))
        self.assertEqual(check_upstream.parse_semver("v1.0.0"), (1, 0, 0))
        self.assertIsNone(check_upstream.parse_semver("0.10.2"))
        self.assertIsNone(check_upstream.parse_semver("v01.2.3"))
        self.assertIsNone(check_upstream.parse_semver("v0.11.0-rc.1"))
        self.assertIsNone(check_upstream.parse_semver("v0.11.0-alpha"))
        self.assertIsNone(check_upstream.parse_semver("v0.11.0-beta.2"))

        tags = [
            {"name": "v0.9.2"},
            {"name": "v0.10.2"},
            {"name": "v0.10.1"},
            {"name": "v0.11.0-rc.1"},
            {"name": "v0.12.0"},
            {"name": "v0.13.0"},
        ]
        releases = [
            {"tag_name": "v0.12.0", "draft": True, "prerelease": False},
            {"tag_name": "v0.13.0", "draft": False, "prerelease": True},
            {"tag_name": "v0.10.2", "draft": False, "prerelease": False},
        ]
        selected = check_upstream.select_latest_tag(tags, releases)
        self.assertEqual(selected, "v0.10.2")

    def test_dereference_annotated_tag(self) -> None:
        api = FakeGitHubApi()
        api.set(
            "/repos/mullvad/gotatun/git/ref/tags/v0.10.2",
            200,
            {"object": {"type": "tag", "sha": ANNOTATED_TAG_SHA}},
        )
        api.set(
            f"/repos/mullvad/gotatun/git/tags/{ANNOTATED_TAG_SHA}",
            200,
            {"object": {"type": "commit", "sha": COMMIT_SHA}},
        )

        sha = check_upstream.dereference_tag("mullvad/gotatun", "v0.10.2", api_get=api)
        self.assertEqual(sha, COMMIT_SHA)

    def test_fork_tag_exists_without_release_needs_publish(self) -> None:
        api = FakeGitHubApi()
        api.set("/repos/mullvad/gotatun/tags?per_page=100", 200, [{"name": "v0.10.2"}])
        api.set("/repos/mullvad/gotatun/releases?per_page=100", 200, [])
        api.set(
            "/repos/mullvad/gotatun/git/ref/tags/v0.10.2",
            200,
            {"object": {"type": "commit", "sha": COMMIT_SHA}},
        )
        # Fork already has the tag pointing to the same commit, but NO release!
        api.set(
            "/repos/cataggar/gotatun/git/ref/tags/v0.10.2",
            200,
            {"object": {"type": "commit", "sha": COMMIT_SHA}},
        )
        api.set("/repos/cataggar/gotatun/releases/tags/v0.10.2", 404, None)

        result = check_upstream.check_upstream(api_get=api)
        self.assertEqual(
            result,
            {
                "tag": "v0.10.2",
                "upstream_sha": COMMIT_SHA,
                "needs_publish": "true",
            },
        )

    def test_draft_or_partial_release_needs_publish(self) -> None:
        api = FakeGitHubApi()
        api.set("/repos/mullvad/gotatun/tags?per_page=100", 200, [{"name": "v0.10.2"}])
        api.set("/repos/mullvad/gotatun/releases?per_page=100", 200, [])
        api.set(
            "/repos/mullvad/gotatun/git/ref/tags/v0.10.2",
            200,
            {"object": {"type": "commit", "sha": COMMIT_SHA}},
        )
        api.set("/repos/cataggar/gotatun/git/ref/tags/v0.10.2", 404, None)

        # Case 1: Draft release even with all 6 assets
        api.set(
            "/repos/cataggar/gotatun/releases/tags/v0.10.2",
            200,
            {
                "draft": True,
                "prerelease": False,
                "assets": make_complete_assets("v0.10.2"),
            },
        )
        result_draft = check_upstream.check_upstream(api_get=api)
        self.assertEqual(result_draft["needs_publish"], "true")

        # Case 2: Published release missing 1 archive asset
        partial_assets = make_complete_assets("v0.10.2")[:-1]
        self.assertEqual(len(partial_assets), 5)
        api.set(
            "/repos/cataggar/gotatun/releases/tags/v0.10.2",
            200,
            {
                "draft": False,
                "prerelease": False,
                "assets": partial_assets,
            },
        )
        result_partial = check_upstream.check_upstream(api_get=api)
        self.assertEqual(result_partial["needs_publish"], "true")

        # Case 3: Asset present but size == 0
        zero_size_assets = make_complete_assets("v0.10.2")
        zero_size_assets[0]["size"] = 0
        api.set(
            "/repos/cataggar/gotatun/releases/tags/v0.10.2",
            200,
            {
                "draft": False,
                "prerelease": False,
                "assets": zero_size_assets,
            },
        )
        result_zero = check_upstream.check_upstream(api_get=api)
        self.assertEqual(result_zero["needs_publish"], "true")

    def test_complete_release_with_matching_fork_tag_returns_false(self) -> None:
        api = FakeGitHubApi()
        api.set("/repos/mullvad/gotatun/tags?per_page=100", 200, [{"name": "v0.10.2"}])
        api.set("/repos/mullvad/gotatun/releases?per_page=100", 200, [])
        api.set(
            "/repos/mullvad/gotatun/git/ref/tags/v0.10.2",
            200,
            {"object": {"type": "tag", "sha": ANNOTATED_TAG_SHA}},
        )
        api.set(
            f"/repos/mullvad/gotatun/git/tags/{ANNOTATED_TAG_SHA}",
            200,
            {"object": {"type": "commit", "sha": COMMIT_SHA}},
        )
        api.set(
            "/repos/cataggar/gotatun/git/ref/tags/v0.10.2",
            200,
            {"object": {"type": "commit", "sha": COMMIT_SHA}},
        )
        api.set(
            "/repos/cataggar/gotatun/releases/tags/v0.10.2",
            200,
            {
                "draft": False,
                "prerelease": False,
                "assets": make_complete_assets("v0.10.2"),
            },
        )

        result = check_upstream.check_upstream(api_get=api)
        self.assertEqual(
            result,
            {
                "tag": "v0.10.2",
                "upstream_sha": COMMIT_SHA,
                "needs_publish": "false",
            },
        )

    def test_conflicting_fork_tag_sha_raises_and_exits_nonzero(self) -> None:
        api = FakeGitHubApi()
        api.set("/repos/mullvad/gotatun/tags?per_page=100", 200, [{"name": "v0.10.2"}])
        api.set("/repos/mullvad/gotatun/releases?per_page=100", 200, [])
        api.set(
            "/repos/mullvad/gotatun/git/ref/tags/v0.10.2",
            200,
            {"object": {"type": "commit", "sha": COMMIT_SHA}},
        )
        api.set(
            "/repos/cataggar/gotatun/git/ref/tags/v0.10.2",
            200,
            {"object": {"type": "commit", "sha": CONFLICT_SHA}},
        )

        with self.assertRaisesRegex(RuntimeError, "conflicts with upstream"):
            check_upstream.check_upstream(api_get=api)

        stderr = io.StringIO()
        with (
            mock.patch.object(check_upstream, "default_api_get", side_effect=api),
            mock.patch("sys.stderr", stderr),
        ):
            rc = check_upstream.main()
        self.assertEqual(rc, 1)
        self.assertIn("conflicts with upstream", stderr.getvalue())

    def test_write_outputs_writes_stdout_and_github_output(self) -> None:
        worktree_dir = pathlib.Path(__file__).resolve().parent
        out_file = worktree_dir / ".test_github_output"
        self.addCleanup(lambda: out_file.unlink(missing_ok=True))

        outputs = {
            "tag": "v0.10.2",
            "upstream_sha": COMMIT_SHA,
            "needs_publish": "true",
        }
        stdout = io.StringIO()
        with (
            mock.patch("sys.stdout", stdout),
            mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(out_file)}, clear=False),
            mock.patch.object(check_upstream, "check_upstream", return_value=outputs),
        ):
            rc = check_upstream.main()

        self.assertEqual(rc, 0)
        expected_text = (
            f"tag=v0.10.2\nupstream_sha={COMMIT_SHA}\nneeds_publish=true\n"
        )
        self.assertEqual(stdout.getvalue(), expected_text)
        self.assertEqual(out_file.read_text(encoding="utf-8"), expected_text)


if __name__ == "__main__":
    unittest.main()
