#!/usr/bin/env python3
"""Unit tests for scripts/release_tool.py."""

from __future__ import annotations

import gzip
import hashlib
import io
from pathlib import Path
import shutil
import struct
import sys
import tarfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_tool  # noqa: E402


def make_synthetic_pe(
    machine: int,
    e_lfanew: int = 0x80,
    with_cert_table: bool = False,
) -> bytes:
    """Construct a minimal valid PE32+ binary with the given COFF Machine type."""
    size_of_opt = 240
    opt_off = e_lfanew + 24
    body_len = opt_off + size_of_opt + 64
    buf = bytearray(body_len)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    struct.pack_into("<H", buf, e_lfanew + 4, machine)
    struct.pack_into("<H", buf, e_lfanew + 20, size_of_opt)
    struct.pack_into("<H", buf, opt_off, 0x020B)  # PE32+
    struct.pack_into("<I", buf, opt_off + 64, 0x12345678)  # CheckSum
    struct.pack_into("<I", buf, opt_off + 108, 16)  # NumberOfRvaAndSizes
    if with_cert_table:
        cert_blob = b"SYNTHETIC-PKCS7-CERT-BLOB-012345"
        sec_dir_off = opt_off + 112 + 4 * 8
        struct.pack_into("<II", buf, sec_dir_off, len(buf), len(cert_blob))
        buf.extend(cert_blob)
    return bytes(buf)


def make_synthetic_wintun_zip() -> tuple[bytes, str]:
    """Create an in-memory Wintun zip containing amd64/arm64 DLLs (with cert tables) and LICENSE.txt."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "wintun/bin/amd64/wintun.dll",
            make_synthetic_pe(release_tool.PE_MACHINE_AMD64, with_cert_table=True),
        )
        zf.writestr(
            "wintun/bin/arm64/wintun.dll",
            make_synthetic_pe(release_tool.PE_MACHINE_ARM64, with_cert_table=True),
        )
        zf.writestr("wintun/LICENSE.txt", b"Wintun License Content\n")
    raw = bio.getvalue()
    return raw, hashlib.sha256(raw).hexdigest().lower()


class ReleaseToolTestCase(unittest.TestCase):
    """Test suite for release_tool.py."""

    scratch_root: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.scratch_root = Path(__file__).resolve().parent / ".test_scratch_release_tool"
        if cls.scratch_root.exists():
            shutil.rmtree(cls.scratch_root)
        cls.scratch_root.mkdir(parents=True, exist_ok=True)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.scratch_root.exists():
            shutil.rmtree(cls.scratch_root)

    def setUp(self) -> None:
        self.work_dir = self.scratch_root / self._testMethodName
        if self.work_dir.exists():
            shutil.rmtree(self.work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        if self.work_dir.exists():
            shutil.rmtree(self.work_dir)

    def test_parse_semver_tag_valid(self) -> None:
        self.assertEqual(release_tool.parse_semver_tag("v0.10.2"), (0, 10, 2))
        self.assertEqual(release_tool.parse_semver_tag("v0.0.0"), (0, 0, 0))
        self.assertEqual(release_tool.parse_semver_tag("v1.2.3"), (1, 2, 3))
        self.assertEqual(release_tool.parse_semver_tag("v12.34.56"), (12, 34, 56))

    def test_parse_semver_tag_rejects_invalid_and_prerelease(self) -> None:
        invalid_tags = [
            "0.10.2",
            "v0.10.2-rc.1",
            "v0.10.2-alpha",
            "v0.10.2+20260101",
            "v01.10.2",
            "v0.01.2",
            "v0.10.02",
            "v1.2",
            "v1.2.3.4",
            "v1.2.x",
            "latest",
            "",
        ]
        for bad in invalid_tags:
            with self.subTest(tag=bad):
                with self.assertRaises(ValueError):
                    release_tool.parse_semver_tag(bad)

    def test_resolve_annotated_tag_and_missing_fork_tag(self) -> None:
        upstream_commit = "1d46b779f5e0743f30a13cc2c325b8114b901fb9"
        tag_obj_1 = "55881ff3d35fad2cfe4a2edf42ee304eca3afe2c"
        tag_obj_2 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

        responses = {
            "repos/mullvad/gotatun/git/ref/tags/v0.10.2": {
                "object": {"type": "tag", "sha": tag_obj_1},
            },
            f"repos/mullvad/gotatun/git/tags/{tag_obj_1}": {
                "object": {"type": "tag", "sha": tag_obj_2},
            },
            f"repos/mullvad/gotatun/git/tags/{tag_obj_2}": {
                "object": {"type": "commit", "sha": upstream_commit},
            },
            "repos/cataggar/gotatun/git/ref/tags/v0.10.2": None,
            "repos/cataggar/gotatun/releases/tags/v0.10.2": None,
            "repos/cataggar/gotatun/releases?per_page=100": [
                {"tag_name": "v0.10.1", "draft": False, "prerelease": False},
            ],
        }

        def fake_api_get(path: str, token: str | None = None, allow_404: bool = False):
            if path in responses:
                val = responses[path]
                if val is None and not allow_404:
                    raise RuntimeError(f"Unexpected 404 for {path}")
                return val
            raise AssertionError(f"Unexpected API path: {path}")

        result = release_tool.resolve_release(
            tag="v0.10.2",
            fork_repo="cataggar/gotatun",
            upstream_repo="mullvad/gotatun",
            api_get=fake_api_get,
        )
        self.assertEqual(
            result,
            {
                "tag": "v0.10.2",
                "version": "0.10.2",
                "upstream_sha": upstream_commit,
                "tag_exists": "false",
                "release_complete": "false",
                "make_latest": "true",
            },
        )

    def test_resolve_fork_tag_conflict_fails(self) -> None:
        upstream_commit = "1d46b779f5e0743f30a13cc2c325b8114b901fb9"
        conflicting_commit = "9524864ca74ec25db6ffccfaa9e2a861a72e6f5d"

        responses = {
            "repos/mullvad/gotatun/git/ref/tags/v0.10.2": {
                "object": {"type": "commit", "sha": upstream_commit},
            },
            "repos/cataggar/gotatun/git/ref/tags/v0.10.2": {
                "object": {"type": "commit", "sha": conflicting_commit},
            },
        }

        def fake_api_get(path: str, token: str | None = None, allow_404: bool = False):
            return responses[path]

        with self.assertRaisesRegex(RuntimeError, "Conflicting tag in fork"):
            release_tool.resolve_release(
                tag="v0.10.2",
                fork_repo="cataggar/gotatun",
                upstream_repo="mullvad/gotatun",
                api_get=fake_api_get,
            )

        with mock.patch.object(release_tool, "github_api_get", side_effect=fake_api_get):
            rc = release_tool.main(["resolve", "--tag", "v0.10.2", "--repo", "cataggar/gotatun"])
            self.assertEqual(rc, 1)

    def test_resolve_complete_release_and_historical_make_latest(self) -> None:
        upstream_commit = "9524864ca74ec25db6ffccfaa9e2a861a72e6f5d"
        tag = "v0.10.1"
        all_assets = [{"name": name, "size": 1024} for name in release_tool.expected_asset_names(tag)]

        responses = {
            f"repos/mullvad/gotatun/git/ref/tags/{tag}": {
                "object": {"type": "commit", "sha": upstream_commit},
            },
            f"repos/cataggar/gotatun/git/ref/tags/{tag}": {
                "object": {"type": "commit", "sha": upstream_commit},
            },
            f"repos/cataggar/gotatun/releases/tags/{tag}": {
                "draft": False,
                "assets": all_assets,
            },
            "repos/cataggar/gotatun/releases?per_page=100": [
                {"tag_name": "v0.10.2", "draft": False, "prerelease": False},
                {"tag_name": "v0.10.1", "draft": False, "prerelease": False},
            ],
        }

        result = release_tool.resolve_release(
            tag=tag,
            fork_repo="cataggar/gotatun",
            upstream_repo="mullvad/gotatun",
            api_get=lambda path, token=None, allow_404=False: responses[path],
        )
        self.assertEqual(result["tag_exists"], "true")
        self.assertEqual(result["release_complete"], "true")
        self.assertEqual(result["make_latest"], "false")

    def test_compute_make_latest_ignores_drafts_and_prereleases(self) -> None:
        releases = [
            {"tag_name": "v0.9.2", "draft": False, "prerelease": False},
            {"tag_name": "v0.10.2", "draft": False, "prerelease": False},
            {"tag_name": "v0.11.0", "draft": True, "prerelease": False},
            {"tag_name": "v0.12.0", "draft": False, "prerelease": True},
        ]
        self.assertTrue(release_tool.compute_make_latest("v0.10.2", releases))
        self.assertTrue(release_tool.compute_make_latest("v0.10.3", releases))
        self.assertFalse(release_tool.compute_make_latest("v0.10.1", releases))
        self.assertFalse(release_tool.compute_make_latest("v0.9.9", releases))

    def test_pe_machine_verification(self) -> None:
        amd64_pe = make_synthetic_pe(release_tool.PE_MACHINE_AMD64)
        arm64_pe = make_synthetic_pe(release_tool.PE_MACHINE_ARM64)

        amd64_file = self.work_dir / "amd64.exe"
        arm64_file = self.work_dir / "arm64.exe"
        amd64_file.write_bytes(amd64_pe)
        arm64_file.write_bytes(arm64_pe)

        self.assertEqual(
            release_tool.check_pe_arch(amd64_file, "x86_64-pc-windows-msvc"),
            release_tool.PE_MACHINE_AMD64,
        )
        self.assertEqual(
            release_tool.check_pe_arch(arm64_file, "aarch64-pc-windows-msvc"),
            release_tool.PE_MACHINE_ARM64,
        )

        with self.assertRaisesRegex(ValueError, "PE machine type mismatch"):
            release_tool.check_pe_arch(amd64_file, "aarch64-pc-windows-msvc")
        with self.assertRaisesRegex(ValueError, "PE machine type mismatch"):
            release_tool.check_pe_arch(arm64_file, "x86_64-pc-windows-msvc")

        bad_pe = self.work_dir / "not_a_pe.exe"
        bad_pe.write_bytes(b"ELF\x00" + b"\x00" * 128)
        with self.assertRaisesRegex(ValueError, "Missing MZ"):
            release_tool.check_pe_arch(bad_pe, "x86_64-pc-windows-msvc")

    def test_fetch_wintun_verifies_sha256_and_extracts(self) -> None:
        raw_zip, zip_sha = make_synthetic_wintun_zip()

        for target in ("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"):
            out_dir = self.work_dir / f"wintun-{target}"
            dll_path, lic_path = release_tool.fetch_wintun(
                target=target,
                output_dir=out_dir,
                expected_sha256=zip_sha,
                downloader=lambda _url: raw_zip,
            )
            self.assertTrue(dll_path.is_file())
            self.assertTrue(lic_path.is_file())
            release_tool.check_pe_arch(dll_path, target)
            self.assertFalse(release_tool.has_pe_authenticode(dll_path))

        signed_pe = make_synthetic_pe(release_tool.PE_MACHINE_AMD64, with_cert_table=True)
        self.assertTrue(release_tool.has_pe_authenticode(signed_pe))
        stripped_pe = release_tool.strip_pe_authenticode(signed_pe)
        self.assertFalse(release_tool.has_pe_authenticode(stripped_pe))
        self.assertEqual(
            release_tool.check_pe_arch(stripped_pe, "x86_64-pc-windows-msvc"),
            release_tool.PE_MACHINE_AMD64,
        )

        with self.assertRaisesRegex(ValueError, "Wintun SHA-256 mismatch"):
            release_tool.fetch_wintun(
                target="x86_64-pc-windows-msvc",
                output_dir=self.work_dir / "bad-wintun",
                expected_sha256="0" * 64,
                downloader=lambda _url: b"not even a zip",
            )

    def _create_source_and_dist(self, tag: str = "v0.10.2") -> tuple[Path, Path]:
        src_dir = self.work_dir / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        (src_dir / "LICENSE").write_text("MPL-2.0 License\n", encoding="utf-8")
        (src_dir / "LICENSE-CLOUDFLARE").write_text("Cloudflare BSD-3 License\n", encoding="utf-8")

        dist_dir = self.work_dir / "dist"
        dist_dir.mkdir(parents=True, exist_ok=True)

        for target, info in release_tool.TARGETS.items():
            if info["is_windows"]:
                bin_file = self.work_dir / f"gotatun-{target}.exe"
                bin_file.write_bytes(make_synthetic_pe(int(info["pe_machine"])))
                wintun_dir = self.work_dir / f"wintun-{target}"
                wintun_dir.mkdir(parents=True, exist_ok=True)
                (wintun_dir / "wintun.dll").write_bytes(make_synthetic_pe(int(info["pe_machine"])))
                (wintun_dir / "LICENSE-WINTUN.txt").write_text("Wintun GPL/Prebuilt License\n", encoding="utf-8")
                release_tool.package_target(
                    tag=tag,
                    target=target,
                    bin_path=bin_file,
                    source_dir=src_dir,
                    dist_dir=dist_dir,
                    wintun_dir=wintun_dir,
                )
            else:
                bin_file = self.work_dir / f"gotatun-{target}"
                bin_file.write_bytes(b"\x7fELF-synthetic-binary-" + target.encode("utf-8"))
                release_tool.package_target(
                    tag=tag,
                    target=target,
                    bin_path=bin_file,
                    source_dir=src_dir,
                    dist_dir=dist_dir,
                )

        return src_dir, dist_dir

    def test_package_and_verify_assets_all_targets(self) -> None:
        tag = "v0.10.2"
        _, dist_dir = self._create_source_and_dist(tag=tag)

        # Confirm all 12 assets pass verification
        release_tool.verify_assets(tag=tag, dist_dir=dist_dir)

        # Inspect Unix tar.gz directly for 0755 mode and contents
        linux_archive = dist_dir / f"gotatun-{tag}-x86_64-unknown-linux-gnu.tar.gz"
        with tarfile.open(linux_archive, "r:gz") as tf:
            bin_info = tf.getmember(f"gotatun-{tag}-x86_64-unknown-linux-gnu/gotatun")
            self.assertEqual(bin_info.mode & 0o777, 0o755)
            names = tf.getnames()
            self.assertIn(f"gotatun-{tag}-x86_64-unknown-linux-gnu/LICENSE", names)
            self.assertIn(f"gotatun-{tag}-x86_64-unknown-linux-gnu/LICENSE-CLOUDFLARE", names)

        # Inspect Windows zip directly for wintun.dll beside gotatun.exe
        win_archive = dist_dir / f"gotatun-{tag}-x86_64-pc-windows-msvc.zip"
        with zipfile.ZipFile(win_archive, "r") as zf:
            names = zf.namelist()
            prefix = f"gotatun-{tag}-x86_64-pc-windows-msvc/"
            self.assertIn(f"{prefix}gotatun.exe", names)
            self.assertIn(f"{prefix}wintun.dll", names)
            self.assertIn(f"{prefix}LICENSE", names)
            self.assertIn(f"{prefix}LICENSE-CLOUDFLARE", names)
            self.assertIn(f"{prefix}LICENSE-WINTUN.txt", names)

    def test_verify_assets_detects_missing_or_corrupted_files(self) -> None:
        tag = "v0.10.2"
        _, dist_dir = self._create_source_and_dist(tag=tag)

        # Corrupt a .sha256 sidecar
        sidecar = dist_dir / f"gotatun-{tag}-x86_64-unknown-linux-gnu.tar.gz.sha256"
        orig_sidecar = sidecar.read_text(encoding="utf-8")
        sidecar.write_text("0" * 64 + f"  gotatun-{tag}-x86_64-unknown-linux-gnu.tar.gz\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "SHA-256 digest mismatch"):
            release_tool.verify_assets(tag=tag, dist_dir=dist_dir)
        sidecar.write_text(orig_sidecar, encoding="utf-8")

        # Remove an asset
        win_zip = dist_dir / f"gotatun-{tag}-aarch64-pc-windows-msvc.zip"
        win_zip.unlink()
        with self.assertRaisesRegex(ValueError, "Missing expected release assets"):
            release_tool.verify_assets(tag=tag, dist_dir=dist_dir)

    def test_package_windows_fails_when_wintun_missing_or_wrong_arch(self) -> None:
        tag = "v0.10.2"
        src_dir = self.work_dir / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        (src_dir / "LICENSE").write_text("MPL-2.0\n", encoding="utf-8")
        dist_dir = self.work_dir / "dist"

        exe_file = self.work_dir / "gotatun.exe"
        exe_file.write_bytes(make_synthetic_pe(release_tool.PE_MACHINE_AMD64))

        # Missing --wintun-dir
        with self.assertRaisesRegex(ValueError, "--wintun-dir is required"):
            release_tool.package_target(
                tag=tag,
                target="x86_64-pc-windows-msvc",
                bin_path=exe_file,
                source_dir=src_dir,
                dist_dir=dist_dir,
                wintun_dir=None,
            )

        # Wrong PE arch on wintun.dll (ARM64 DLL for x86_64 target)
        bad_wintun_dir = self.work_dir / "bad_wintun"
        bad_wintun_dir.mkdir(parents=True, exist_ok=True)
        (bad_wintun_dir / "wintun.dll").write_bytes(make_synthetic_pe(release_tool.PE_MACHINE_ARM64))
        (bad_wintun_dir / "LICENSE-WINTUN.txt").write_text("License\n", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "PE machine type mismatch"):
            release_tool.package_target(
                tag=tag,
                target="x86_64-pc-windows-msvc",
                bin_path=exe_file,
                source_dir=src_dir,
                dist_dir=dist_dir,
                wintun_dir=bad_wintun_dir,
            )

    def test_verify_assets_detects_bad_tar_mode_or_wrong_zip_pe_arch(self) -> None:
        tag = "v0.10.2"
        _, dist_dir = self._create_source_and_dist(tag=tag)

        # Replace Linux archive with one where gotatun has mode 0644 instead of 0755
        target = "x86_64-unknown-linux-gnu"
        archive_name = release_tool.archive_name_for_target(tag, target)
        archive_path = dist_dir / archive_name
        prefix = f"gotatun-{tag}-{target}"
        with open(archive_path, "wb") as raw_fh:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw_fh, mtime=0) as gz_fh:
                with tarfile.open(mode="w", fileobj=gz_fh) as tf:
                    release_tool._add_tar_bytes(tf, f"{prefix}/gotatun", b"binary", mode=0o644)
                    release_tool._add_tar_bytes(tf, f"{prefix}/LICENSE", b"license", mode=0o644)
        digest = release_tool.sha256_file(archive_path)
        (dist_dir / f"{archive_name}.sha256").write_text(f"{digest}  {archive_name}\n", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "must have mode 0755"):
            release_tool.verify_assets(tag=tag, dist_dir=dist_dir)

    def test_render_notes_and_resolve_toolchain(self) -> None:
        notes_path = self.work_dir / "notes.md"
        sha = "1d46b779f5e0743f30a13cc2c325b8114b901fb9"
        text = release_tool.render_notes(
            tag="v0.10.2",
            upstream_sha=sha,
            repo="cataggar/gotatun",
            output_path=notes_path,
        )
        self.assertIn("mullvad/gotatun@v0.10.2", text)
        self.assertIn(sha, text)
        self.assertIn("ghr install cataggar/gotatun", text)
        self.assertIn("ghr install cataggar/gotatun@v0.10.2", text)
        self.assertIn("ghr uninstall cataggar/gotatun", text)
        self.assertIn("glibc >= 2.35", text)
        self.assertIn("wintun.dll", text)

        tc_dir = self.work_dir / "tc"
        tc_dir.mkdir(parents=True, exist_ok=True)
        (tc_dir / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.95.0"\n', encoding="utf-8")
        self.assertEqual(release_tool.resolve_toolchain(tc_dir), "1.95.0")

        (tc_dir / "rust-toolchain.toml").unlink()
        (tc_dir / "Cargo.toml").write_text('[workspace.package]\nrust-version = "1.95"\n', encoding="utf-8")
        self.assertEqual(release_tool.resolve_toolchain(tc_dir), "1.95")


if __name__ == "__main__":
    unittest.main()
