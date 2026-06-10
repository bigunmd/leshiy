# Leshiy Desktop

Cross-platform desktop client for the Leshiy protocol (Tauri v2 + React).

## Develop

```bash
pnpm install
pnpm tauri dev      # launches the app (Linux needs webkit2gtk-4.1; WSLg works)
```

## Build

```bash
pnpm tauri build                    # release bundles for the host OS
pnpm tauri build --bundles deb,rpm  # Linux: .deb + .rpm
pnpm tauri build --no-bundle        # compile only, no installer
```

Bundles land in `src-tauri/target/release/bundle/`.

- **Linux:** `.deb`, `.rpm`, AppImage. `.deb`/`.rpm` need only `dpkg-deb`/`rpmbuild`; AppImage needs `patchelf` and downloads `linuxdeploy`/`appimagetool` on first build.
- **Windows:** `.msi` (WiX) + `.exe` (NSIS) — build on Windows.
- **macOS:** `.dmg` + `.app` — build on macOS.

### Building AppImage on WSL

`linuxdeploy` crashes on WSL because WSL appends the Windows `PATH`, and it can't stat the permission-locked `/mnt/c/.../WindowsApps` directory. Strip the Windows paths (and make sure `patchelf` is installed) for the AppImage step:

```bash
# one-time: a sudo-free patchelf
mkdir -p ~/.local/bin
curl -fsSL https://github.com/NixOS/patchelf/releases/download/0.18.0/patchelf-0.18.0-x86_64.tar.gz \
  | tar xz -C /tmp ./bin/patchelf && cp /tmp/bin/patchelf ~/.local/bin/

# build AppImage with Windows paths removed
env PATH="$HOME/.local/bin:$(printf '%s' "$PATH" | tr ':' '\n' | grep -v '^/mnt/' | paste -sd:)" \
  APPIMAGE_EXTRACT_AND_RUN=1 pnpm tauri build --bundles appimage
```

`pnpm tauri build --bundles deb,rpm` needs none of this. CI builds AppImage on real Ubuntu (no WSL quirk).

## Architecture

The Rust shell (`src-tauri/`) embeds the `leshiy-client` control library (`crates/leshiy-client`) and exposes it to the React UI via Tauri commands + `tunnel:state` / `tunnel:stats` events. Once connected, traffic is routed through a local SOCKS5 proxy plus the OS system proxy. The supervisor is spawned once at startup from the saved settings — changing the transport or SOCKS port takes effect on the next launch.

Icons are generated from `icon-src.svg`:

```bash
node scripts/render-icon.mjs   # SVG -> icon-src.png (1024) via sharp
pnpm tauri icon icon-src.png   # regenerate src-tauri/icons/*
```

## CI

- `.github/workflows/desktop-ci.yml` — builds + lints the app on changes under `apps/desktop`.
- `.github/workflows/desktop-release.yml` — on a `desktop-v*` tag, builds per-OS bundles via `tauri-apps/tauri-action` and drafts a GitHub release.

(The repo's `ci.yml` / `release.yml` cover the CLI/server and are independent of this app.)

## Code signing (deferred)

Releases are currently unsigned. To sign, set the corresponding secrets and wire them in `desktop-release.yml`:

- **Windows (Authenticode):** `TAURI_SIGNING_PRIVATE_KEY` / `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`.
- **macOS (Developer ID + notarization):** requires a paid Apple Developer account — `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID`.
- **Updater:** if the Tauri updater is enabled later, generate an updater keypair with `pnpm tauri signer generate`.

License: **AGPL-3.0-only** (same as the rest of the workspace).
