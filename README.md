# cataggar/gotatun

Release automation for [GotaTun](https://github.com/mullvad/gotatun), a userspace [WireGuard](https://www.wireguard.com/) implementation in Rust by Mullvad VPN.

Upstream does not publish prebuilt binary assets. This repository builds and publishes native `gotatun` (`gotatun-cli`) binaries from official upstream tags so they can be installed with [`ghr`](https://github.com/cataggar/ghr).

## Branches

- **`ghr`** (default) — orphaned release automation and packaging workflows that detect new upstream releases and publish installable binary archives.
- **`main`** — source mirror of the upstream [`mullvad/gotatun`](https://github.com/mullvad/gotatun) repository.

## Install

Install with [`ghr`](https://github.com/cataggar/ghr):

```sh
# Install latest release
ghr install cataggar/gotatun

# Install a specific upstream version
ghr install cataggar/gotatun@v0.10.2

# Verify installation
gotatun --version

# Uninstall
ghr uninstall cataggar/gotatun
```

## Supported Platforms

Every release builds `gotatun-cli` (`--bin gotatun`) from the exact upstream tag commit using the tag's pinned Rust toolchain and `Cargo.lock`:

| Platform | Architecture | Rust Target | Archive Format | Notes |
| --- | --- | --- | --- | --- |
| Linux | x86-64 | `x86_64-unknown-linux-gnu` | `.tar.gz` | Built on Ubuntu 22.04 (`glibc >= 2.35`) |
| Linux | ARM64 | `aarch64-unknown-linux-gnu` | `.tar.gz` | Built on Ubuntu 22.04 (`glibc >= 2.35`) |
| macOS | Intel | `x86_64-apple-darwin` | `.tar.gz` | Built on macOS runner |
| macOS | Apple Silicon | `aarch64-apple-darwin` | `.tar.gz` | Built on macOS ARM64 (`macos-14`) |
| Windows | x86-64 | `x86_64-pc-windows-msvc` | `.zip` | Includes verified `amd64` `wintun.dll` |
| Windows | ARM64 | `aarch64-pc-windows-msvc` | `.zip` | Includes verified `arm64` `wintun.dll` |

Archive naming follows `gotatun-<tag>-<target>.tar.gz` on Unix and `gotatun-<tag>-<target>.zip` on Windows. Each archive includes `LICENSE` (MPL-2.0) and `LICENSE-CLOUDFLARE` (BSD-3-Clause) alongside the `gotatun` binary.

## Platform Notes & Runtime Requirements

Creating and configuring TUN interfaces requires elevated privileges on every platform:

### Linux

- **Minimum glibc**: Linux binaries are built on Ubuntu 22.04 and require **`glibc >= 2.35`** (Ubuntu 22.04+, Debian 12+, Fedora 36+, RHEL 9+, etc.).
- **Privileges**: Grant the binary `CAP_NET_ADMIN` or run as `root`:
  ```sh
  sudo setcap cap_net_admin+epi "$(realpath "$(which gotatun)")"
  gotatun wg0
  ```
- **Privilege dropping & `wg-quick`**: By default, `gotatun` drops privileges after creating the TUN device and UAPI socket, which prevents setting `fwmark`. When `fwmark` is required (such as with `wg-quick`), pass `--disable-drop-privileges` or set `WG_SUDO=1`:
  ```sh
  sudo WG_QUICK_USERSPACE_IMPLEMENTATION=gotatun WG_SUDO=1 wg-quick up wg0
  ```

### macOS

- **Interface naming**: The tunnel interface name must be `utun` (to let the kernel assign the next available interface) or match `utun[0-9]+` (for example `utun8`).
- **Privileges**: Creating `utun` interfaces requires `root` (`sudo`):
  ```sh
  sudo WG_TUN_NAME_FILE=/var/run/wireguard/utun.name gotatun -f utun
  ```

### Windows

- **Privileges**: Run from an elevated (**Administrator**) terminal to create Wintun adapters and UAPI named pipes:
  ```powershell
  gotatun wg0
  ```
- **Bundled `wintun.dll`**: Windows requires the [Wintun](https://www.wintun.net/) layer-3 TUN driver DLL at runtime. Each Windows release archive bundles the official architecture-matched `wintun.dll` (`bin/amd64/wintun.dll` for `x86_64-pc-windows-msvc` and `bin/arm64/wintun.dll` for `aarch64-pc-windows-msvc`) extracted from `https://www.wintun.net/builds/wintun-0.14.1.zip` (verified against SHA-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`), along with `LICENSE-WINTUN.txt` (GPL-2.0).
- **Companion file loading with `ghr`**: Because `ghr` extracts the full release archive into its versioned install directory and launches `gotatun.exe` in place, Windows's default DLL search order automatically resolves `wintun.dll` from the executable directory without extra setup. To override the Wintun DLL location explicitly, pass `--wintun <PATH>` or set the `WINTUN_PATH` environment variable.

## Verification, Provenance & Signing

- **Exact upstream commit parity**: Every release tag in `cataggar/gotatun` mirrors the exact upstream [`mullvad/gotatun`](https://github.com/mullvad/gotatun) commit SHA (annotated tags are dereferenced to their target commit, and conflicting tags are rejected).
- **Checksums & Build Provenance**: Every archive is published with a `<archive>.sha256` sidecar file and a GitHub Actions build provenance attestation generated via [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance). `ghr` verifies these attestations and checksums automatically during installation.
- **Code signing**: The `gotatun` (`gotatun.exe`) binaries are compiled directly from upstream source in GitHub Actions and are **not** signed with an Apple Developer ID certificate, notarized for macOS Gatekeeper, or Authenticode-signed on Windows unless separately configured. (The bundled `wintun.dll` inside Windows archives is the unmodified official WireGuard build and retains its upstream Authenticode/WHQL signatures.)

## Release Automation

- **Daily upstream check** (`.github/workflows/check-upstream.yml`): Runs daily (and via `workflow_dispatch`) to inspect `mullvad/gotatun` tags, select the newest stable semantic version (`vX.Y.Z`), verify whether a complete published release with all 6 target archives and `.sha256` sidecars exists, and dispatch `release.yml` when missing or incomplete.
- **Release workflow** (`.github/workflows/release.yml`): Fetches and verifies the upstream tag commit, mirrors the tag, builds and smoke-tests all 6 targets, stages assets in a draft release, attests build provenance, and publishes the release only after all targets succeed.

To trigger a release build manually for a specific upstream tag:

```sh
gh workflow run release.yml --ref ghr -f tag=v0.10.2
```

## License

Upstream [GotaTun](https://github.com/mullvad/gotatun) is licensed under the [Mozilla Public License 2.0 (MPL-2.0)](https://www.mozilla.org/MPL/2.0/), with prior BoringTun contributions under the BSD 3-Clause License (`LICENSE-CLOUDFLARE`). Windows archives additionally bundle `wintun.dll` under the GPL-2.0 license (`LICENSE-WINTUN.txt`).

