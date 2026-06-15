# Leshiy Desktop — VPN (Phase 5) Manual Verification

The desktop app has **no automated UI runner** (no vitest/jest), and the VPN path requires
**real privilege elevation**. The GUI + privileged flow is therefore verified by hand. The
automated gates below are green in CI/local; the manual checklist is the Phase-5 acceptance
gate and must be run on a real desktop with `leshiy-helper` available.

## Automated gates (green)

- `cargo test --workspace` — Rust logic incl. `settings` serde (vpn_mtu/vpn_dns) and the
  Tauri `mode_uses_helper` branch (`vpn_mode_branch_selects_helper`).
- `cargo clippy --all-targets -- -D warnings` (workspace) and
  `cargo clippy --manifest-path apps/gui/src-tauri/Cargo.toml --lib -- -D warnings`.
- `cargo fmt --all -- --check` (+ the workspace-excluded tauri crate).
- `npm --prefix apps/gui run build` (tsc + vite).

## Manual checklist — STATUS: ⏳ pending hands-on run

Run `npm --prefix apps/gui run tauri dev` with the helper available on the box.

- [ ] **Boot** — app opens to the ConnectScreen with the Deep Bog theme intact.
- [ ] **Mode pill** — top bar shows `Proxy | VPN` next to the gear; tapping toggles
      `settings.mode` (persists across restart); active = moss fill, inactive = dim.
- [ ] **Idle hint** — Disconnected: Proxy shows "Proxy — routes proxy-aware apps", VPN shows
      "VPN — ready to route all apps"; switching the pill updates it live.
- [ ] **First-run install dialog** — helper not installed + VPN + tap Connect →
      `InstallHelperDialog` with the approved copy (title/body/3 bullets/`Not now` /
      `Install & enable`/OS-auth note). `Not now` stays idle; `Install & enable` → OS
      elevation → on success closes and connects. Second Connect → no dialog, connects direct.
- [ ] **VPN status + expand** — connected: "● all traffic protected" + live speeds; tap
      "tunnel details ▾" → Assigned IP / DNS (= `vpn_dns`) / Active route (= "full tunnel") /
      MTU. (IP/route/MTU are spec §7 defaults until Phase 4's `Status` relays actuals.)
- [ ] **Stats parity** — speeds/totals update ~1 Hz from the helper exactly as proxy mode
      (same `tunnel:state`/`tunnel:stats` → same `useTunnel`); orb animates Connecting→Connected.
- [ ] **VPN-aware kill-switch + MTU/DNS rows** — Settings in VPN: kill-switch reads the VPN
      copy; MTU + DNS rows edit `vpn_mtu`/`vpn_dns`; SOCKS-port row hidden. Proxy mode reverts.
- [ ] **Disconnect teardown** — disconnect in VPN → helper stops, routes/DNS restored
      (verify `ip route` / resolver), orb idle. VPN→Proxy while connected disconnects first.
- [ ] **Remove helper** — Settings → VPN → "Remove VPN helper" → uninstalled; next VPN
      Connect re-shows the install dialog.
- [ ] **Proxy regression** — Proxy Connect/Disconnect unchanged (in-process SOCKS, system
      proxy set/cleared, SOCKS-port row, no helper, no dialog); tray quick-connect = proxy.

## Notes

- The privileged helper itself (`leshiy-helper`) is Phase 4; install/uninstall run under OS
  elevation (`pkexec` / `osascript` / UAC) into `leshiy-helper install`/`uninstall`.
- The helper's root smoke (`cargo test -p leshiy-helper --test root_smoke -- --ignored`,
  needs `CAP_NET_ADMIN` + `LESHIY_TEST_URI`) exercises the real TUN end-to-end.

## Cross-platform VPN — macOS / Windows (on-demand helper) — STATUS: ⏳ pending real hardware

The macOS/Windows GUI VPN uses an **on-demand elevated helper** (no install step). It
compiles + cross-checks here (`x86_64-pc-windows-gnu`) but is **runtime-unverified** — no Mac/
Windows in the dev/CI environment. Verify on real hardware:

- [ ] **Bundle** — `leshiy-helper` ships next to the app (Tauri `externalBin` sidecar); the
      app resolves it next to its own exe.
- [ ] **macOS connect** — VPN mode → Connect → **osascript admin prompt** → `leshiy-helper run
      --ephemeral` starts as root, GUI connects over `/var/run/leshiy/helper.sock`, traffic is
      routed (utun up, routes/DNS set). No install dialog, no remove-helper row.
- [ ] **Windows connect** — VPN mode → Connect → **UAC prompt** → elevated `leshiy-helper run
      --ephemeral` serves `\\.\pipe\leshiy-helper` with a user-SID security descriptor; the
      medium-IL GUI connects across the UAC boundary; Wintun up, traffic routed.
- [ ] **Auth** — a process running as a *different* user cannot open the pipe/socket (DACL /
      peer-uid); the client-SID check (Windows) / `getpeereid` (macOS) rejects mismatches.
- [ ] **Disconnect** — Stop tears down routes/DNS (RAII) and the ephemeral helper **exits**
      (no lingering elevated process). Reconnect re-prompts for elevation.
- [ ] **Decline elevation** — cancelling UAC/osascript surfaces a clear error and returns to idle.
- [ ] **Path with apostrophe** — install under a path containing `'` (e.g. `O'Brien`) still
      elevates correctly (shell/PowerShell single-quote escaping).

**Known follow-ups (out of scope):** persistent services (Windows Service / macOS LaunchDaemon
via SMAppService) for prompt-free connects — needs code-signing/notarization. The on-demand
path is the unsigned-friendly MVP.

---

# Leshiy Android — Manual Verification

Android reuses the React UI and Rust core; the VPN runs **in-process** via a Kotlin `VpnService`
(no helper/root). The engine path is compile-gated in CI; the on-device behavior is verified by
hand (VPN consent + the system VPN lifecycle can't be unit-tested).

## Toolchain (local builds)

- Rust targets: `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android`
- `cargo install cargo-ndk`; Android **NDK r26+** (this repo built with r28).
- **JDK 17** for Gradle (Gradle 8.14 rejects newer JDKs — e.g. Java 25 fails with
  "Unsupported class file major version 69"). Set `JAVA_HOME` to a 17 JDK.
- `export ANDROID_HOME=~/Android NDK_HOME=$ANDROID_HOME/ndk/<ver> ANDROID_NDK_HOME=$NDK_HOME`
- Run: `cd apps/gui && pnpm tauri android dev` (emulator/device) or
  `pnpm tauri android build --debug --target aarch64` (APK).

## Automated gates (green)

- `cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 build -p leshiy-client -p leshiy-tun` (CI: `android-ci.yml`).
- Host + Android `cargo clippy -- -D warnings`, `cargo fmt --check`, `pnpm build`.
- Full `pnpm tauri android build` produces an APK (compiles the Kotlin VpnService/plugin + links the engine `.so`).

## Manual checklist (device/emulator — acceptance gate)

1. Install the APK; launch — the normal UI appears (no install/remove-helper rows, no tray).
2. Import a profile; tap **Connect** → the **system VPN-consent dialog** appears → Allow.
3. The VPN key icon shows in the status bar; orb → Connected; throughput updates.
4. Egress IP = the server (e.g. open an IP-check site); DNS resolves through the tunnel.
5. Background the app → VPN stays up (foreground service); reopen → still Connected.
6. **Disconnect** → orb shows "Disconnecting…" then Disconnected; VPN icon clears; direct connectivity restored.
7. Connect → Disconnect → Connect again is clean (no stuck state).
8. Start another VPN app (or revoke in Settings) → our app handles `onRevoke` (tears down, orb → Disconnected).

## Release / signing

- CI `android-release.yml` triggers on a `android-v*` tag → `tauri android build --apk` (3 ABIs) →
  signed APK(s) attached to a **draft** GitHub Release + `SHA256SUMS`.
- Secrets required for signing: `ANDROID_KEYSTORE_B64` (base64 of the `.jks`),
  `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`. Without them the
  release APK is **unsigned** (installable for testing, not updatable).
- Generate a keystore once: `keytool -genkeypair -v -keystore release.jks -alias leshiy -keyalg RSA -keysize 4096 -validity 10000`.
  **Back it up** — losing it means a new package identity (users must reinstall).

## Known limitations / deferred (out of scope)

- **Per-app split tunnel** (`addAllowedApplication`/`addDisallowedApplication` + an installed-apps
  picker) — the planned follow-up. (We already `addDisallowedApplication(self)` for loop avoidance.)
- **Domain-based split rules** aren't enforced on Android yet (routes come from the VpnService.Builder
  CIDR list; the engine's domain resolver no-ops through Android's `NullController`). CIDR include/exclude
  works (exclude needs API 33+ `excludeRoute`; older devices fall back to full tunnel).
- **QUIC** isn't used on Android (VPN forces REALITY/TCP).
- Google Play (AAB) / F-Droid distribution.
