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
