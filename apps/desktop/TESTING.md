# Leshiy Desktop — VPN (Phase 5) Manual Verification

The desktop app has **no automated UI runner** (no vitest/jest), and the VPN path requires
**real privilege elevation**. The GUI + privileged flow is therefore verified by hand. The
automated gates below are green in CI/local; the manual checklist is the Phase-5 acceptance
gate and must be run on a real desktop with `leshiy-helper` available.

## Automated gates (green)

- `cargo test --workspace` — Rust logic incl. `settings` serde (vpn_mtu/vpn_dns) and the
  Tauri `mode_uses_helper` branch (`vpn_mode_branch_selects_helper`).
- `cargo clippy --all-targets -- -D warnings` (workspace) and
  `cargo clippy --manifest-path apps/desktop/src-tauri/Cargo.toml --lib -- -D warnings`.
- `cargo fmt --all -- --check` (+ the workspace-excluded tauri crate).
- `npm --prefix apps/desktop run build` (tsc + vite).

## Manual checklist — STATUS: ⏳ pending hands-on run

Run `npm --prefix apps/desktop run tauri dev` with the helper available on the box.

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
