#!/usr/bin/env python3
"""Release tooling for building, verifying, and publishing GotaTun binaries."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import sys
import tarfile
import time
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request
import zipfile

SEMVER_TAG_RE = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_LINE_RE = re.compile(r"^([0-9a-f]{64})  ([^\r\n]+)\r?\n?$")

WINTUN_VERSION = "0.14.1"
WINTUN_URL = f"https://www.wintun.net/builds/wintun-{WINTUN_VERSION}.zip"
WINTUN_SHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
WINTUN_ARCH_MAP: dict[str, str] = {
    "x86_64-pc-windows-msvc": "wintun/bin/amd64/wintun.dll",
    "aarch64-pc-windows-msvc": "wintun/bin/arm64/wintun.dll",
}
WINTUN_LICENSE_ZIP_PATH = "wintun/LICENSE.txt"

PE_MACHINE_AMD64 = 0x8664
PE_MACHINE_ARM64 = 0xAA64

TARGETS: dict[str, dict[str, Any]] = {
    "x86_64-unknown-linux-gnu": {
        "ext": "tar.gz",
        "is_windows": False,
        "pe_machine": None,
        "os_label": "Linux x86_64 (glibc >= 2.35)",
    },
    "aarch64-unknown-linux-gnu": {
        "ext": "tar.gz",
        "is_windows": False,
        "pe_machine": None,
        "os_label": "Linux ARM64 (glibc >= 2.35)",
    },
    "x86_64-apple-darwin": {
        "ext": "tar.gz",
        "is_windows": False,
        "pe_machine": None,
        "os_label": "macOS x86_64 (Intel)",
    },
    "aarch64-apple-darwin": {
        "ext": "tar.gz",
        "is_windows": False,
        "pe_machine": None,
        "os_label": "macOS ARM64 (Apple Silicon)",
    },
    "x86_64-pc-windows-msvc": {
        "ext": "zip",
        "is_windows": True,
        "pe_machine": PE_MACHINE_AMD64,
        "os_label": "Windows x86_64 (MSVC, bundles wintun.dll)",
    },
    "aarch64-pc-windows-msvc": {
        "ext": "zip",
        "is_windows": True,
        "pe_machine": PE_MACHINE_ARM64,
        "os_label": "Windows ARM64 (MSVC, bundles wintun.dll)",
    },
}

DEFAULT_ZIP_DATETIME = (2020, 1, 1, 0, 0, 0)


def parse_semver_tag(tag: str) -> tuple[int, int, int]:
    """Validate and parse a stable vMAJOR.MINOR.PATCH tag into an integer tuple."""
    if not isinstance(tag, str):
        raise ValueError(f"Invalid tag type: {type(tag).__name__}")
    match = SEMVER_TAG_RE.match(tag)
    if not match:
        raise ValueError(
            f"Invalid stable semantic version tag {tag!r}: must match "
            r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$ (no prereleases or build metadata)"
        )
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def archive_name_for_target(tag: str, target: str) -> str:
    """Return the archive filename for a given tag and target."""
    parse_semver_tag(tag)
    if target not in TARGETS:
        raise ValueError(f"Unsupported target: {target!r}")
    ext = TARGETS[target]["ext"]
    return f"gotatun-{tag}-{target}.{ext}"


def expected_asset_names(tag: str) -> list[str]:
    """Return all 12 expected release asset filenames (6 archives + 6 .sha256 sidecars)."""
    parse_semver_tag(tag)
    names: list[str] = []
    for target in TARGETS:
        archive = archive_name_for_target(tag, target)
        names.append(archive)
        names.append(f"{archive}.sha256")
    return names


def get_github_token() -> str | None:
    """Retrieve GitHub token from GH_TOKEN or GITHUB_TOKEN environment variables."""
    for env_key in ("GH_TOKEN", "GITHUB_TOKEN"):
        val = os.environ.get(env_key, "").strip()
        if val:
            return val
    return None


def github_api_get(
    path_or_url: str,
    token: str | None = None,
    allow_404: bool = False,
    retries: int = 3,
    backoff: float = 1.0,
) -> Any:
    """Perform a GET request against the GitHub REST API and return decoded JSON."""
    if path_or_url.startswith("https://") or path_or_url.startswith("http://"):
        url = path_or_url
    else:
        url = f"https://api.github.com/{path_or_url.lstrip('/')}"

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "gotatun-release-tool/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    last_err: Exception | None = None
    for attempt in range(retries):
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as err:
            try:
                if err.code == 404 and allow_404:
                    return None
                if err.code in (429, 500, 502, 503, 504) and attempt + 1 < retries:
                    last_err = err
                    time.sleep(backoff * (2**attempt))
                    continue
                body = ""
                try:
                    body = err.read().decode("utf-8", errors="replace")
                except Exception:
                    pass
                raise RuntimeError(f"GitHub API HTTP {err.code} for {url}: {body or err.reason}") from err
            finally:
                try:
                    err.close()
                except Exception:
                    pass
        except urllib.error.URLError as err:
            last_err = err
            if attempt + 1 < retries:
                time.sleep(backoff * (2**attempt))
                continue
            raise RuntimeError(f"GitHub API request failed for {url}: {err}") from err

    raise RuntimeError(f"GitHub API request failed after {retries} retries for {url}: {last_err}")


def resolve_tag_commit_sha(
    repo: str,
    tag: str,
    token: str | None = None,
    api_get: Callable[..., Any] | None = None,
) -> str | None:
    """Resolve a git tag in repo to its underlying 40-char lowercase commit SHA, dereferencing annotated tags."""
    parse_semver_tag(tag)
    get_fn = api_get if api_get is not None else github_api_get
    ref_data = get_fn(f"repos/{repo}/git/ref/tags/{tag}", token=token, allow_404=True)
    if ref_data is None:
        return None
    if not isinstance(ref_data, dict) or "object" not in ref_data:
        return None

    obj = ref_data["object"]
    hops = 0
    while isinstance(obj, dict) and obj.get("type") == "tag":
        hops += 1
        if hops > 16:
            raise RuntimeError(f"Exceeded maximum tag dereference depth for {repo}@{tag}")
        tag_sha = obj.get("sha")
        if not tag_sha:
            raise RuntimeError(f"Missing sha on tag object for {repo}@{tag}")
        tag_data = get_fn(f"repos/{repo}/git/tags/{tag_sha}", token=token, allow_404=False)
        if not isinstance(tag_data, dict) or "object" not in tag_data:
            raise RuntimeError(f"Malformed tag object response for {repo}@{tag} ({tag_sha})")
        obj = tag_data["object"]

    if not isinstance(obj, dict) or obj.get("type") != "commit":
        obj_type = obj.get("type") if isinstance(obj, dict) else type(obj).__name__
        raise RuntimeError(f"Expected tag {repo}@{tag} to dereference to commit, got {obj_type!r}")

    commit_sha = str(obj.get("sha", "")).strip().lower()
    if not COMMIT_SHA_RE.match(commit_sha):
        raise RuntimeError(f"Invalid commit SHA {commit_sha!r} for {repo}@{tag}")
    return commit_sha


def check_release_complete(
    repo: str,
    tag: str,
    token: str | None = None,
    api_get: Callable[..., Any] | None = None,
) -> bool:
    """Return True if a non-draft release for tag exists in repo with all 12 non-empty expected assets."""
    parse_semver_tag(tag)
    get_fn = api_get if api_get is not None else github_api_get
    release_data = get_fn(f"repos/{repo}/releases/tags/{tag}", token=token, allow_404=True)
    if not isinstance(release_data, dict):
        return False
    if bool(release_data.get("draft", False)):
        return False

    assets = release_data.get("assets")
    if not isinstance(assets, list):
        return False

    asset_sizes: dict[str, int] = {}
    for asset in assets:
        if isinstance(asset, dict) and isinstance(asset.get("name"), str):
            size = asset.get("size", 0)
            asset_sizes[asset["name"]] = int(size) if isinstance(size, int) else 0

    for expected_name in expected_asset_names(tag):
        if asset_sizes.get(expected_name, 0) <= 0:
            return False
    return True


def compute_make_latest(tag: str, releases: list[dict[str, Any]]) -> bool:
    """Return True if tag >= all existing non-draft, non-prerelease stable semver releases."""
    target_tuple = parse_semver_tag(tag)
    for rel in releases:
        if not isinstance(rel, dict):
            continue
        if rel.get("draft", False) or rel.get("prerelease", False):
            continue
        rel_tag = rel.get("tag_name")
        if not isinstance(rel_tag, str):
            continue
        try:
            rel_tuple = parse_semver_tag(rel_tag)
        except ValueError:
            continue
        if rel_tuple > target_tuple:
            return False
    return True


def resolve_release(
    tag: str,
    fork_repo: str,
    upstream_repo: str = "mullvad/gotatun",
    token: str | None = None,
    api_get: Callable[..., Any] | None = None,
) -> dict[str, str]:
    """Resolve upstream tag SHA, fork tag/release state, and make_latest flag."""
    parse_semver_tag(tag)
    get_fn = api_get if api_get is not None else github_api_get
    upstream_sha = resolve_tag_commit_sha(upstream_repo, tag, token=token, api_get=get_fn)
    if upstream_sha is None:
        raise RuntimeError(f"Upstream tag {tag} not found in {upstream_repo}")

    fork_sha = resolve_tag_commit_sha(fork_repo, tag, token=token, api_get=get_fn)
    if fork_sha is not None:
        if fork_sha != upstream_sha:
            raise RuntimeError(
                f"Conflicting tag in fork {fork_repo}: {tag} points to {fork_sha}, "
                f"expected upstream {upstream_sha}"
            )
        tag_exists = True
    else:
        tag_exists = False

    release_complete = check_release_complete(fork_repo, tag, token=token, api_get=get_fn)
    releases_data = get_fn(f"repos/{fork_repo}/releases?per_page=100", token=token, allow_404=False)
    releases_list = releases_data if isinstance(releases_data, list) else []
    make_latest = compute_make_latest(tag, releases_list)

    return {
        "tag": tag,
        "version": tag[1:],
        "upstream_sha": upstream_sha,
        "tag_exists": "true" if tag_exists else "false",
        "release_complete": "true" if release_complete else "false",
        "make_latest": "true" if make_latest else "false",
    }


def write_github_outputs(outputs: dict[str, str], github_output_path: str | None = None) -> None:
    """Write key=value lines to stdout and to $GITHUB_OUTPUT if set."""
    for key, val in outputs.items():
        print(f"{key}={val}")
    output_file = github_output_path if github_output_path is not None else os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as fh:
            for key, val in outputs.items():
                fh.write(f"{key}={val}\n")


def read_pe_machine(source: Path | str | bytes) -> int:
    """Parse a Windows PE image and return its COFF Machine uint16 value."""
    if isinstance(source, (bytes, bytearray)):
        data = bytes(source)
        label = "<bytes>"
    else:
        path = Path(source)
        label = str(path)
        if not path.is_file():
            raise ValueError(f"PE binary does not exist: {label}")
        data = path.read_bytes()

    if len(data) < 0x40:
        raise ValueError(f"File too small to be a valid PE image: {label} ({len(data)} bytes)")
    if data[0:2] != b"MZ":
        raise ValueError(f"Missing MZ DOS header signature in {label}")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 6 > len(data):
        raise ValueError(f"Invalid e_lfanew offset 0x{e_lfanew:x} in {label}")
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError(f"Missing PE\\0\\0 signature at offset 0x{e_lfanew:x} in {label}")

    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    return int(machine)


def check_pe_arch(source: Path | str | bytes, target: str) -> int:
    """Verify that the PE COFF Machine type of source matches the expected Windows target."""
    if target not in TARGETS or not TARGETS[target]["is_windows"]:
        raise ValueError(f"Target {target!r} is not a supported Windows PE target")
    expected_machine = int(TARGETS[target]["pe_machine"])
    actual_machine = read_pe_machine(source)
    if actual_machine != expected_machine:
        label = "<bytes>" if isinstance(source, (bytes, bytearray)) else str(source)
        raise ValueError(
            f"PE machine type mismatch for {label} (target {target}): "
            f"got 0x{actual_machine:04x}, expected 0x{expected_machine:04x}"
        )
    return actual_machine


def _pe_security_dir_offsets(data: bytes, label: str = "<bytes>") -> tuple[int, int, int, int] | None:
    """Return (checksum_off, sec_dir_off, cert_off, cert_size) if the PE has a Security DataDirectory."""
    if len(data) < 0x40 or data[0:2] != b"MZ":
        raise ValueError(f"Missing MZ DOS header signature in {label}")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError(f"Missing PE\\0\\0 signature at offset 0x{e_lfanew:x} in {label}")

    size_of_opt = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt_off = e_lfanew + 24
    if size_of_opt < 68 or opt_off + size_of_opt > len(data):
        return None

    magic = struct.unpack_from("<H", data, opt_off)[0]
    if magic == 0x020B:
        rva_count_rel = 108
        data_dir_rel = 112
    elif magic == 0x010B:
        rva_count_rel = 92
        data_dir_rel = 96
    else:
        return None

    sec_dir_rel = data_dir_rel + 4 * 8
    if size_of_opt < sec_dir_rel + 8:
        return None

    num_rva = struct.unpack_from("<I", data, opt_off + rva_count_rel)[0]
    if num_rva <= 4:
        return None

    checksum_off = opt_off + 64
    sec_dir_off = opt_off + sec_dir_rel
    cert_off, cert_size = struct.unpack_from("<II", data, sec_dir_off)
    return checksum_off, sec_dir_off, cert_off, cert_size


def has_pe_authenticode(source: Path | str | bytes) -> bool:
    """Return True if the PE image has a non-empty DataDirectory[Security] certificate table."""
    data = bytes(source) if isinstance(source, (bytes, bytearray)) else Path(source).read_bytes()
    info = _pe_security_dir_offsets(data)
    if info is None:
        return False
    _, _, cert_off, cert_size = info
    return cert_off != 0 and cert_size != 0


def strip_pe_authenticode(source: Path | str | bytes) -> bytes:
    """Strip the outer PE DataDirectory[Security] WIN_CERTIFICATE table if present at EOF.

    Official wintun-0.14.1.zip is verified by SHA-256 before extraction, and its embedded
    WHQL-signed kernel driver package (wintun.sys + wintun.cat) lives untouched inside the
    PE .rsrc section. However, wintun.dll's outer user-mode PE certificate table uses a
    2021 PKCS#9 counterSignature rather than an RFC 3161 timestamp token, which causes
    `ghr install`'s zip PE scanner to fail with MissingSignedAttrs. Stripping the outer
    certificate table after SHA-256 verification preserves all PE sections and embedded
    driver resources while allowing `ghr install cataggar/gotatun` to work out-of-the-box.
    """
    if isinstance(source, (bytes, bytearray)):
        data = bytes(source)
        label = "<bytes>"
    else:
        path = Path(source)
        label = str(path)
        data = path.read_bytes()

    info = _pe_security_dir_offsets(data, label=label)
    if info is None:
        return data
    checksum_off, sec_dir_off, cert_off, cert_size = info
    if cert_off == 0 and cert_size == 0:
        return data
    if cert_off <= sec_dir_off + 8 or cert_size == 0 or cert_off + cert_size > len(data):
        raise ValueError(
            f"Invalid PE Security directory (offset={cert_off}, size={cert_size}, file_len={len(data)}) in {label}"
        )
    if len(data) - (cert_off + cert_size) > 8:
        raise ValueError(f"PE certificate table is not at end of file in {label}")

    out = bytearray(data[:cert_off])
    out[sec_dir_off : sec_dir_off + 8] = b"\x00" * 8
    out[checksum_off : checksum_off + 4] = b"\x00" * 4
    return bytes(out)


def download_bytes_with_retry(
    url: str,
    retries: int = 3,
    backoff: float = 1.0,
) -> bytes:
    """Download binary content from a URL with retry on transient failures."""
    headers = {"User-Agent": "gotatun-release-tool/1.0"}
    last_err: Exception | None = None
    for attempt in range(retries):
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read()
        except (urllib.error.HTTPError, urllib.error.URLError) as err:
            last_err = err
            if isinstance(err, urllib.error.HTTPError) and err.code not in (429, 500, 502, 503, 504):
                raise RuntimeError(f"HTTP {err.code} downloading {url}: {err.reason}") from err
            if attempt + 1 < retries:
                time.sleep(backoff * (2**attempt))
                continue
    raise RuntimeError(f"Failed to download {url} after {retries} attempts: {last_err}")


def fetch_wintun(
    target: str,
    output_dir: Path | str,
    url: str = WINTUN_URL,
    expected_sha256: str = WINTUN_SHA256,
    downloader: Callable[[str], bytes] | None = None,
) -> tuple[Path, Path]:
    """Download official Wintun zip, verify SHA-256 before opening, and extract matching wintun.dll + LICENSE-WINTUN.txt."""
    if target not in WINTUN_ARCH_MAP:
        raise ValueError(f"Target {target!r} does not use Wintun (expected one of {sorted(WINTUN_ARCH_MAP)})")

    fetch_fn = downloader if downloader is not None else download_bytes_with_retry
    raw_zip = fetch_fn(url)
    actual_sha256 = hashlib.sha256(raw_zip).hexdigest().lower()
    if actual_sha256 != expected_sha256.lower():
        raise ValueError(
            f"Wintun SHA-256 mismatch for {url}: got {actual_sha256}, expected {expected_sha256.lower()}"
        )

    dll_member = WINTUN_ARCH_MAP[target]
    with zipfile.ZipFile(io.BytesIO(raw_zip), "r") as zf:
        names = set(zf.namelist())
        if dll_member not in names:
            raise ValueError(f"Missing {dll_member!r} in Wintun archive")
        if WINTUN_LICENSE_ZIP_PATH not in names:
            raise ValueError(f"Missing {WINTUN_LICENSE_ZIP_PATH!r} in Wintun archive")
        dll_bytes = zf.read(dll_member)
        license_bytes = zf.read(WINTUN_LICENSE_ZIP_PATH)

    if not dll_bytes:
        raise ValueError(f"Extracted {dll_member!r} is empty")
    if not license_bytes:
        raise ValueError(f"Extracted {WINTUN_LICENSE_ZIP_PATH!r} is empty")

    check_pe_arch(dll_bytes, target)
    dll_bytes = strip_pe_authenticode(dll_bytes)

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    dll_path = out_dir / "wintun.dll"
    license_path = out_dir / "LICENSE-WINTUN.txt"
    dll_path.write_bytes(dll_bytes)
    license_path.write_bytes(license_bytes)
    return dll_path, license_path


def sha256_file(path: Path | str) -> str:
    """Compute lowercase hex SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().lower()


def _add_tar_bytes(tf: tarfile.TarFile, arcname: str, data: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name=arcname)
    info.size = len(data)
    info.mode = mode
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.type = tarfile.REGTYPE
    tf.addfile(info, io.BytesIO(data))


def _add_zip_bytes(zf: zipfile.ZipFile, arcname: str, data: bytes, executable: bool = False) -> None:
    info = zipfile.ZipInfo(filename=arcname, date_time=DEFAULT_ZIP_DATETIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    unix_mode = 0o100755 if executable else 0o100644
    info.external_attr = unix_mode << 16
    zf.writestr(info, data)


def package_target(
    tag: str,
    target: str,
    bin_path: Path | str,
    source_dir: Path | str,
    dist_dir: Path | str,
    wintun_dir: Path | str | None = None,
) -> tuple[Path, Path]:
    """Package built binary, licenses, and (on Windows) wintun.dll into dist_dir with a .sha256 sidecar."""
    parse_semver_tag(tag)
    if target not in TARGETS:
        raise ValueError(f"Unsupported target: {target!r}")

    bin_file = Path(bin_path)
    if not bin_file.is_file() or bin_file.stat().st_size == 0:
        raise ValueError(f"Binary file missing or empty: {bin_file}")

    src_dir = Path(source_dir)
    license_file = src_dir / "LICENSE"
    if not license_file.is_file() or license_file.stat().st_size == 0:
        raise ValueError(f"Required LICENSE file missing or empty in {src_dir}")
    cloudflare_license_file = src_dir / "LICENSE-CLOUDFLARE"

    out_dir = Path(dist_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    root_prefix = f"gotatun-{tag}-{target}"
    archive_filename = archive_name_for_target(tag, target)
    archive_path = out_dir / archive_filename
    is_windows = bool(TARGETS[target]["is_windows"])

    bin_bytes = bin_file.read_bytes()
    license_bytes = license_file.read_bytes()
    cloudflare_bytes = (
        cloudflare_license_file.read_bytes()
        if cloudflare_license_file.is_file() and cloudflare_license_file.stat().st_size > 0
        else None
    )

    if is_windows:
        if wintun_dir is None:
            raise ValueError(f"--wintun-dir is required when packaging Windows target {target}")
        wdir = Path(wintun_dir)
        wintun_dll = wdir / "wintun.dll"
        wintun_license = wdir / "LICENSE-WINTUN.txt"
        if not wintun_dll.is_file() or wintun_dll.stat().st_size == 0:
            raise ValueError(f"Required wintun.dll missing or empty at {wintun_dll}")
        if not wintun_license.is_file() or wintun_license.stat().st_size == 0:
            raise ValueError(f"Required LICENSE-WINTUN.txt missing or empty at {wintun_license}")

        check_pe_arch(bin_bytes, target)
        wintun_dll_bytes = strip_pe_authenticode(wintun_dll.read_bytes())
        check_pe_arch(wintun_dll_bytes, target)
        wintun_license_bytes = wintun_license.read_bytes()

        entries: list[tuple[str, bytes, bool]] = [
            (f"{root_prefix}/gotatun.exe", bin_bytes, True),
            (f"{root_prefix}/wintun.dll", wintun_dll_bytes, True),
            (f"{root_prefix}/LICENSE", license_bytes, False),
        ]
        if cloudflare_bytes is not None:
            entries.append((f"{root_prefix}/LICENSE-CLOUDFLARE", cloudflare_bytes, False))
        entries.append((f"{root_prefix}/LICENSE-WINTUN.txt", wintun_license_bytes, False))

        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for arcname, content, is_exec in entries:
                _add_zip_bytes(zf, arcname, content, executable=is_exec)
    else:
        entries_tar: list[tuple[str, bytes, int]] = [
            (f"{root_prefix}/gotatun", bin_bytes, 0o755),
            (f"{root_prefix}/LICENSE", license_bytes, 0o644),
        ]
        if cloudflare_bytes is not None:
            entries_tar.append((f"{root_prefix}/LICENSE-CLOUDFLARE", cloudflare_bytes, 0o644))

        with open(archive_path, "wb") as raw_fh:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw_fh, mtime=0) as gz_fh:
                with tarfile.open(mode="w", fileobj=gz_fh, format=tarfile.PAX_FORMAT) as tf:
                    for arcname, content, mode in entries_tar:
                        _add_tar_bytes(tf, arcname, content, mode=mode)

    digest = sha256_file(archive_path)
    sidecar_path = out_dir / f"{archive_filename}.sha256"
    sidecar_path.write_text(f"{digest}  {archive_filename}\n", encoding="utf-8")
    return archive_path, sidecar_path


def verify_single_archive(tag: str, target: str, dist_dir: Path | str) -> None:
    """Verify a single target's archive and .sha256 sidecar in dist_dir."""
    parse_semver_tag(tag)
    if target not in TARGETS:
        raise ValueError(f"Unsupported target: {target!r}")

    dpath = Path(dist_dir)
    archive_filename = archive_name_for_target(tag, target)
    archive_path = dpath / archive_filename
    sidecar_path = dpath / f"{archive_filename}.sha256"

    if not archive_path.is_file() or archive_path.stat().st_size == 0:
        raise ValueError(f"Missing or empty archive: {archive_path}")
    if not sidecar_path.is_file() or sidecar_path.stat().st_size == 0:
        raise ValueError(f"Missing or empty SHA-256 sidecar: {sidecar_path}")

    sidecar_text = sidecar_path.read_text(encoding="utf-8")
    match = SHA256_LINE_RE.match(sidecar_text)
    if not match:
        raise ValueError(f"Malformed SHA-256 sidecar {sidecar_path}: {sidecar_text!r}")
    expected_digest, recorded_name = match.group(1), match.group(2)
    if recorded_name != archive_filename:
        raise ValueError(
            f"SHA-256 sidecar filename mismatch in {sidecar_path}: "
            f"got {recorded_name!r}, expected {archive_filename!r}"
        )

    actual_digest = sha256_file(archive_path)
    if actual_digest != expected_digest:
        raise ValueError(
            f"SHA-256 digest mismatch for {archive_path}: "
            f"actual {actual_digest} != sidecar {expected_digest}"
        )

    root_prefix = f"gotatun-{tag}-{target}/"
    is_windows = bool(TARGETS[target]["is_windows"])

    if is_windows:
        with zipfile.ZipFile(archive_path, "r") as zf:
            names = zf.namelist()
            if not names:
                raise ValueError(f"Empty zip archive: {archive_path}")
            for name in names:
                if "\\" in name or not name.startswith(root_prefix) or ".." in name.split("/"):
                    raise ValueError(f"Invalid archive member path {name!r} in {archive_path}")

            required_members = [
                f"{root_prefix}gotatun.exe",
                f"{root_prefix}wintun.dll",
                f"{root_prefix}LICENSE",
                f"{root_prefix}LICENSE-WINTUN.txt",
            ]
            name_set = set(names)
            for req in required_members:
                if req not in name_set:
                    raise ValueError(f"Missing required member {req!r} in {archive_path}")
                data = zf.read(req)
                if not data:
                    raise ValueError(f"Archive member {req!r} is empty in {archive_path}")

            exe_bytes = zf.read(f"{root_prefix}gotatun.exe")
            dll_bytes = zf.read(f"{root_prefix}wintun.dll")
            check_pe_arch(exe_bytes, target)
            check_pe_arch(dll_bytes, target)
            if has_pe_authenticode(dll_bytes):
                raise ValueError(
                    f"Bundled wintun.dll in {archive_path} still contains an outer PE certificate table"
                )
    else:
        with tarfile.open(archive_path, "r:gz") as tf:
            members = tf.getmembers()
            if not members:
                raise ValueError(f"Empty tar.gz archive: {archive_path}")
            member_map: dict[str, tarfile.TarInfo] = {}
            for member in members:
                if "\\" in member.name or not member.name.startswith(root_prefix) or ".." in member.name.split("/"):
                    raise ValueError(f"Invalid archive member path {member.name!r} in {archive_path}")
                member_map[member.name] = member

            bin_member_name = f"{root_prefix}gotatun"
            license_member_name = f"{root_prefix}LICENSE"
            for req in (bin_member_name, license_member_name):
                if req not in member_map:
                    raise ValueError(f"Missing required member {req!r} in {archive_path}")
                info = member_map[req]
                if info.size <= 0:
                    raise ValueError(f"Archive member {req!r} is empty in {archive_path}")

            bin_mode = member_map[bin_member_name].mode & 0o777
            if bin_mode != 0o755:
                raise ValueError(
                    f"Binary {bin_member_name!r} in {archive_path} must have mode 0755, got { oct(bin_mode) }"
                )


def verify_assets(tag: str, dist_dir: Path | str) -> None:
    """Verify all 12 release assets exist in dist_dir and pass checksum, content, and PE architecture checks."""
    parse_semver_tag(tag)
    dpath = Path(dist_dir)
    if not dpath.is_dir():
        raise ValueError(f"Dist directory does not exist: {dpath}")

    expected = expected_asset_names(tag)
    missing = [name for name in expected if not (dpath / name).is_file()]
    if missing:
        raise ValueError(f"Missing expected release assets in {dpath}: {', '.join(missing)}")

    for target in TARGETS:
        verify_single_archive(tag, target, dpath)


def render_notes(
    tag: str,
    upstream_sha: str,
    repo: str,
    output_path: Path | str,
    upstream_repo: str = "mullvad/gotatun",
) -> str:
    """Render Markdown release notes for a GotaTun binary release."""
    parse_semver_tag(tag)
    sha = upstream_sha.strip().lower()
    if not COMMIT_SHA_RE.match(sha):
        raise ValueError(f"Invalid upstream commit SHA: {upstream_sha!r}")

    lines = [
        f"# GotaTun `{tag}`",
        "",
        f"Prebuilt multi-platform release binaries for [`{upstream_repo}@{tag}`](https://github.com/{upstream_repo}/tree/{tag}) "
        f"(commit [`{sha[:12]}`](https://github.com/{upstream_repo}/commit/{sha})).",
        "",
        "## Quick Install with `ghr`",
        "",
        "Install the latest release:",
        "",
        "```sh",
        f"ghr install {repo}",
        "```",
        "",
        f"Install this specific version (`{tag}`):",
        "",
        "```sh",
        f"ghr install {repo}@{tag}",
        "```",
        "",
        "Uninstall:",
        "",
        "```sh",
        f"ghr uninstall {repo}",
        "```",
        "",
        "## Release Targets",
        "",
        "| Target | Platform | Archive | Checksum |",
        "| --- | --- | --- | --- |",
    ]
    for target, info in TARGETS.items():
        archive = archive_name_for_target(tag, target)
        lines.append(f"| `{target}` | {info['os_label']} | `{archive}` | `{archive}.sha256` |")

    lines.extend(
        [
            "",
            "## Platform & Runtime Notes",
            "",
            "- **Privileges**: Creating TUN interfaces requires elevated privileges (`sudo` or `CAP_NET_ADMIN` on Linux, `sudo` on macOS, Administrator on Windows).",
            "- **Linux (`gnu`)**: Built on Ubuntu 22.04; requires `glibc >= 2.35` (Ubuntu 22.04+, Debian 12+, Fedora 36+, RHEL 9+).",
            f"- **Windows (`msvc`)**: Archives bundle official [Wintun {WINTUN_VERSION}]({WINTUN_URL}) (`wintun.dll`, zip SHA-256 `{WINTUN_SHA256}`) and `LICENSE-WINTUN.txt` right alongside `gotatun.exe` so Windows loads the architecture-matched `wintun.dll` automatically when installed via `ghr`.",
            "",
            "## Verification",
            "",
            "### SHA-256 Checksums",
            "",
            "```sh",
            f"sha256sum -c gotatun-{tag}-<target>.tar.gz.sha256",
            "# or on macOS:",
            f"shasum -a 256 -c gotatun-{tag}-<target>.tar.gz.sha256",
            "```",
            "",
            "### GitHub Build Provenance Attestation",
            "",
            "```sh",
            f"gh attestation verify gotatun-{tag}-<target>.tar.gz --repo {repo}",
            "```",
            "",
            "## Upstream Provenance",
            "",
            f"- **Upstream Repository**: [`{upstream_repo}`](https://github.com/{upstream_repo})",
            f"- **Upstream Tag**: [`{tag}`](https://github.com/{upstream_repo}/releases/tag/{tag})",
            f"- **Upstream Commit SHA**: `{sha}`",
            "",
        ]
    )

    content = "\n".join(lines)
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(content, encoding="utf-8")
    return content


def resolve_toolchain(source_dir: Path | str) -> str:
    """Determine the Rust toolchain channel from rust-toolchain.toml or Cargo.toml."""
    sdir = Path(source_dir)
    toolchain_toml = sdir / "rust-toolchain.toml"
    if toolchain_toml.is_file():
        text = toolchain_toml.read_text(encoding="utf-8")
        m = re.search(r'^\s*channel\s*=\s*"([^"]+)"', text, flags=re.MULTILINE)
        if m:
            return m.group(1).strip()

    cargo_toml = sdir / "Cargo.toml"
    if cargo_toml.is_file():
        text = cargo_toml.read_text(encoding="utf-8")
        m = re.search(r'^\s*rust-version\s*=\s*"([^"]+)"', text, flags=re.MULTILINE)
        if m:
            return m.group(1).strip()

    return "stable"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GotaTun release helper CLI")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    p_resolve = subparsers.add_parser("resolve", help="Resolve upstream tag and fork release state")
    p_resolve.add_argument("--tag", required=True, help="Stable semver tag (e.g. v0.10.2)")
    p_resolve.add_argument("--repo", required=True, help="Fork repository (owner/repo)")
    p_resolve.add_argument(
        "--upstream-repo",
        default="mullvad/gotatun",
        help="Upstream repository (default: mullvad/gotatun)",
    )

    p_wintun = subparsers.add_parser("fetch-wintun", help="Download and extract verified Wintun DLL")
    p_wintun.add_argument("--target", required=True, help="Windows target triple")
    p_wintun.add_argument("--output-dir", required=True, help="Output directory for wintun.dll and LICENSE-WINTUN.txt")

    p_pe = subparsers.add_parser("check-pe-arch", help="Verify PE COFF Machine header for Windows target")
    p_pe.add_argument("--bin-path", required=True, help="Path to PE binary (.exe or .dll)")
    p_pe.add_argument("--target", required=True, help="Windows target triple")

    p_pkg = subparsers.add_parser("package", help="Package target binary and licenses into dist archive")
    p_pkg.add_argument("--tag", required=True, help="Stable semver tag (e.g. v0.10.2)")
    p_pkg.add_argument("--target", required=True, help="Target triple")
    p_pkg.add_argument("--bin-path", required=True, help="Path to compiled gotatun binary")
    p_pkg.add_argument("--source-dir", required=True, help="Path to upstream source checkout")
    p_pkg.add_argument("--dist-dir", required=True, help="Output directory for archives and .sha256 sidecars")
    p_pkg.add_argument("--wintun-dir", default=None, help="Directory containing wintun.dll and LICENSE-WINTUN.txt")

    p_verify = subparsers.add_parser("verify-assets", help="Verify all 12 release assets in dist directory")
    p_verify.add_argument("--tag", required=True, help="Stable semver tag (e.g. v0.10.2)")
    p_verify.add_argument("--dist-dir", required=True, help="Directory containing release archives and .sha256 files")

    p_notes = subparsers.add_parser("render-notes", help="Render release notes Markdown")
    p_notes.add_argument("--tag", required=True, help="Stable semver tag (e.g. v0.10.2)")
    p_notes.add_argument("--upstream-sha", required=True, help="40-char upstream commit SHA")
    p_notes.add_argument("--repo", required=True, help="Fork repository (owner/repo)")
    p_notes.add_argument("--upstream-repo", default="mullvad/gotatun", help="Upstream repository")
    p_notes.add_argument("--output", required=True, help="Output Markdown file path")

    p_toolchain = subparsers.add_parser("resolve-toolchain", help="Resolve pinned Rust toolchain from source directory")
    p_toolchain.add_argument("--source-dir", required=True, help="Path to upstream source directory")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.subcommand == "resolve":
            token = get_github_token()
            outputs = resolve_release(
                tag=args.tag,
                fork_repo=args.repo,
                upstream_repo=args.upstream_repo,
                token=token,
            )
            write_github_outputs(outputs)
            return 0

        if args.subcommand == "fetch-wintun":
            dll_path, lic_path = fetch_wintun(target=args.target, output_dir=args.output_dir)
            print(f"Extracted {dll_path} and {lic_path}")
            return 0

        if args.subcommand == "check-pe-arch":
            machine = check_pe_arch(args.bin_path, args.target)
            print(f"Verified PE machine 0x{machine:04x} for {args.bin_path} ({args.target})")
            return 0

        if args.subcommand == "package":
            archive_path, sidecar_path = package_target(
                tag=args.tag,
                target=args.target,
                bin_path=args.bin_path,
                source_dir=args.source_dir,
                dist_dir=args.dist_dir,
                wintun_dir=args.wintun_dir,
            )
            print(f"Packaged {archive_path} and {sidecar_path}")
            return 0

        if args.subcommand == "verify-assets":
            verify_assets(tag=args.tag, dist_dir=args.dist_dir)
            print(f"Verified all 12 release assets for {args.tag} in {args.dist_dir}")
            return 0

        if args.subcommand == "render-notes":
            render_notes(
                tag=args.tag,
                upstream_sha=args.upstream_sha,
                repo=args.repo,
                output_path=args.output,
                upstream_repo=args.upstream_repo,
            )
            print(f"Rendered release notes to {args.output}")
            return 0

        if args.subcommand == "resolve-toolchain":
            toolchain = resolve_toolchain(args.source_dir)
            write_github_outputs({"toolchain": toolchain})
            return 0

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
