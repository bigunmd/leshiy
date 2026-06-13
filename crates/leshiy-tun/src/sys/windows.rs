//! Windows privileged ops: Wintun device (`tun` crate; requires `wintun.dll` beside the
//! binary), routes (`net-route` + `netsh`), DNS (`netsh`), smart-multi-homed-resolution
//! disable, IPv6 leak mitigation, all restored on teardown. Compile-checked on Linux via
//! cross-target `cargo check`; runtime-verified only on real Windows (Task 3.8 smoke).
use super::cmd;
use super::{PrivilegedOps, RouteController, TunSession};
use crate::route_plan::{Cidr, RoutePlan};
use net_route::{Handle, Route};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tun::AbstractDevice; // brings `tun_name()` into scope for the Wintun adapter

const NETSH: &str = "netsh";
const REG: &str = "reg";

pub struct WindowsOps;

#[async_trait::async_trait]
impl PrivilegedOps for WindowsOps {
    async fn start(
        &self,
        tun_name: &str,
        mtu: u16,
        plan: &RoutePlan,
        dns: &[IpAddr],
        force_dns: bool,
        ipv6_killswitch: bool,
    ) -> std::io::Result<TunSession> {
        // MVP carries IPv4 through the tunnel.
        let IpAddr::V4(tun4) = plan.tun_addr else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "tun_addr must be IPv4 in this phase",
            ));
        };
        let IpAddr::V4(_) = plan.server_exception.gateway else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "server exception gateway must be IPv4 in this phase",
            ));
        };

        // 1. Create the Wintun adapter. REQUIRES wintun.dll beside the binary (Task 3.9).
        //    No ensure_root_privileges (Linux-only); the process must already be elevated.
        let mut cfg = tun::Configuration::default();
        cfg.tun_name(tun_name)
            .address(tun4)
            .netmask(std::net::Ipv4Addr::new(255, 255, 255, 0))
            .mtu(mtu)
            .up();
        let device = tun::create_as_async(&cfg).map_err(to_io)?;
        let iface = device.tun_name().map_err(to_io)?;

        // 2. Routes: server host-exception FIRST via the original gateway, then the
        //    default-override halves via the tun interface. Prefer net-route; fall back
        //    to netsh by interface name.
        let handle = Handle::new()?;
        // The active physical interface name, used for the host-exception fallback, the
        // split-tunnel bypass routes, and the IPv6 restore. Resolved once.
        let orig_iface = original_iface_name();
        let exc = &plan.server_exception;
        let exc_route = Route::new(exc.dest.addr, exc.dest.prefix).with_gateway(exc.gateway);
        if handle.add(&exc_route).await.is_err() {
            let args = cmd::win_route_add_via_gateway_args(
                &format!("{}/{}", exc.dest.addr, exc.dest.prefix),
                &exc.gateway.to_string(),
                &orig_iface.clone().unwrap_or_default(),
            );
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            let _ = cmd::run(NETSH, &argv); // best-effort
        }
        // via_tun + bypass go through the net_route `Handle` (IP Helper API) — thousands of
        // fast in-process calls, NOT thousands of `netsh` subprocesses (a subscription can carry
        // thousands of CIDRs; spawning netsh per route stalls connect for minutes). via_tun
        // needs the Wintun adapter's ifindex (from the device); if unavailable, fall back to
        // netsh by name. Best-effort: a bad/duplicate route in a list must not fail the session.
        let tun_idx = device.tun_index().ok().map(|i| i as u32);
        for c in &plan.via_tun {
            let IpAddr::V4(_) = c.addr else {
                continue; // IPv4-only this phase; skip an Include IPv6 CIDR.
            };
            match tun_idx {
                Some(idx) => {
                    let _ = handle
                        .add(&Route::new(c.addr, c.prefix).with_ifindex(idx))
                        .await;
                }
                None => {
                    let args = cmd::win_route_add_via_iface_args(
                        &format!("{}/{}", c.addr, c.prefix),
                        &iface,
                    );
                    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
                    let _ = cmd::run(NETSH, &argv);
                }
            }
        }

        // 2b. Split-tunnel bypass routes (Exclude): each CIDR escapes via the original gateway.
        //     Tracked in `installed_bypass` (shared with the controller + teardown) — they point
        //     at the gateway, so (unlike via_tun) they don't auto-clear when the adapter drops.
        let orig_iface_str = orig_iface.clone().unwrap_or_default();
        let gateway = plan.server_exception.gateway.to_string();
        let installed_bypass: Arc<Mutex<Vec<Cidr>>> = Arc::new(Mutex::new(Vec::new()));
        for b in &plan.bypass {
            let IpAddr::V4(_) = b.dest.addr else {
                continue;
            };
            let _ = handle
                .add(&Route::new(b.dest.addr, b.dest.prefix).with_gateway(b.gateway))
                .await; // best-effort, fast (IP Helper API)
            installed_bypass.lock().unwrap().push(b.dest.clone());
        }

        // 3. DNS on the tun interface (static), so queries ride the tunnel. Plus DNS-leak
        //    hardening (disable smart multi-homed resolution). Both skipped in Include mode.
        let mut smart_backup = None;
        if force_dns {
            if let Some(first) = dns.first() {
                let args = cmd::win_dns_set_static_args(&iface, &first.to_string());
                let argv: Vec<&str> = args.iter().map(String::as_str).collect();
                let _ = cmd::run(NETSH, &argv);
            }
            // Disable smart multi-homed name resolution so Windows can't fan a query out the
            // physical NIC. Back up the prior registry value.
            smart_backup = read_smart_resolution_policy();
            let _ = cmd::run(
                REG,
                &[
                    "add",
                    r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                    "/v",
                    "DisableSmartNameResolution",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "1",
                    "/f",
                ],
            );
        }

        // 4. IPv6 leak mitigation (fail-closed): disable IPv6 binding on the original
        //    interface; restore on drop. Skipped in Include mode. (Full IPv6 is out of scope.)
        let mut v6_disabled_iface = None;
        if ipv6_killswitch && let Some(name) = &orig_iface {
            let _ = cmd::run(
                NETSH,
                &["interface", "ipv6", "set", "interface", name, "disabled"],
            );
            v6_disabled_iface = Some(name.clone());
        }

        let controller = Arc::new(WindowsController {
            tun_iface: iface.clone(),
            orig_iface: orig_iface_str.clone(),
            gateway: gateway.clone(),
            installed_bypass: installed_bypass.clone(),
        });
        let guard = WindowsTeardown {
            tun_iface: iface,
            orig_iface: orig_iface_str,
            gateway,
            v6_disabled_iface,
            smart_backup,
            installed_bypass,
        };
        Ok(TunSession {
            device,
            guard: Box::new(guard),
            controller,
        })
    }
}

/// Live runtime route control for the Windows session via `netsh`. Bypass (Exclude) additions
/// are tracked in `installed_bypass` so teardown can remove them on abort; via_tun (Include)
/// routes auto-clear on Wintun drop and aren't tracked.
struct WindowsController {
    tun_iface: String,
    orig_iface: String,
    gateway: String,
    installed_bypass: Arc<Mutex<Vec<Cidr>>>,
}

#[async_trait::async_trait]
impl RouteController for WindowsController {
    async fn add_bypass(&self, c: &Cidr) -> std::io::Result<()> {
        let IpAddr::V4(_) = c.addr else {
            return Ok(());
        };
        let dest = format!("{}/{}", c.addr, c.prefix);
        let args = cmd::win_route_add_via_gateway_args(&dest, &self.gateway, &self.orig_iface);
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        cmd::run(NETSH, &argv)?;
        self.installed_bypass.lock().unwrap().push(c.clone());
        Ok(())
    }
    async fn remove_bypass(&self, c: &Cidr) -> std::io::Result<()> {
        let dest = format!("{}/{}", c.addr, c.prefix);
        let args = cmd::win_route_del_via_gateway_args(&dest, &self.gateway, &self.orig_iface);
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let _ = cmd::run(NETSH, &argv);
        self.installed_bypass.lock().unwrap().retain(|x| x != c);
        Ok(())
    }
    async fn add_via_tun(&self, c: &Cidr) -> std::io::Result<()> {
        let IpAddr::V4(_) = c.addr else {
            return Ok(());
        };
        let dest = format!("{}/{}", c.addr, c.prefix);
        let args = cmd::win_route_add_via_iface_args(&dest, &self.tun_iface);
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        cmd::run(NETSH, &argv)
    }
    async fn remove_via_tun(&self, c: &Cidr) -> std::io::Result<()> {
        let dest = format!("{}/{}", c.addr, c.prefix);
        let args = cmd::win_route_del_via_iface_args(&dest, &self.tun_iface);
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let _ = cmd::run(NETSH, &argv);
        Ok(())
    }
}

/// The name of the active (lowest-metric) physical IPv4 interface, used for the
/// host-exception fallback route and IPv6 restore. Parsed from `netsh interface ipv4
/// show interfaces`; returns `None` if it can't be determined (callers degrade best-effort).
fn original_iface_name() -> Option<String> {
    let out = cmd::run_capture(NETSH, &["interface", "ipv4", "show", "interfaces"]).ok()?;
    // Columns: Idx  Met  MTU  State  Name. Pick the first "connected" non-loopback row.
    out.lines()
        .filter(|l| l.contains("connected"))
        .filter_map(|l| l.split_whitespace().nth(4).map(str::to_string))
        .find(|n| !n.eq_ignore_ascii_case("Loopback"))
}

/// Read the current `DisableSmartNameResolution` policy value (as a string), or `None`
/// if unset — so teardown can restore exactly (delete vs. set back).
fn read_smart_resolution_policy() -> Option<String> {
    let out = cmd::run_capture(
        REG,
        &[
            "query",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            "/v",
            "DisableSmartNameResolution",
        ],
    )
    .ok()?;
    // The value appears as "...DisableSmartNameResolution    REG_DWORD    0x1".
    out.split_whitespace().last().map(str::to_string)
}

/// Restores DNS, the smart-resolution policy, and IPv6 on drop, and removes any split-tunnel
/// `bypass` routes. Override/exception/via-tun routes auto-clear when the Wintun adapter is
/// dropped; the `bypass` gateway routes do not, so they're deleted explicitly here.
struct WindowsTeardown {
    tun_iface: String,
    /// Physical interface name (empty if it couldn't be resolved) — needed to delete bypass
    /// routes that were added out this interface.
    orig_iface: String,
    /// Original gateway, shared by all bypass routes.
    gateway: String,
    /// `Some(name)` only if we actually disabled IPv6 on that interface (Exclude mode).
    v6_disabled_iface: Option<String>,
    smart_backup: Option<String>,
    /// All bypass routes still installed (static + resolver-added) — removed on teardown.
    installed_bypass: Arc<Mutex<Vec<Cidr>>>,
}

impl Drop for WindowsTeardown {
    fn drop(&mut self) {
        // Best-effort; teardown must never panic.
        for c in self.installed_bypass.lock().unwrap().iter() {
            let dest = format!("{}/{}", c.addr, c.prefix);
            let args = cmd::win_route_del_via_gateway_args(&dest, &self.gateway, &self.orig_iface);
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            let _ = cmd::run(NETSH, &argv);
        }

        let args = cmd::win_dns_reset_dhcp_args(&self.tun_iface);
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let _ = cmd::run(NETSH, &argv);

        match &self.smart_backup {
            // Restore the prior explicit value.
            Some(v) => {
                let _ = cmd::run(
                    REG,
                    &[
                        "add",
                        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                        "/v",
                        "DisableSmartNameResolution",
                        "/t",
                        "REG_DWORD",
                        "/d",
                        if v.ends_with('1') { "1" } else { "0" },
                        "/f",
                    ],
                );
            }
            // No prior value: delete the key we added.
            None => {
                let _ = cmd::run(
                    REG,
                    &[
                        "delete",
                        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                        "/v",
                        "DisableSmartNameResolution",
                        "/f",
                    ],
                );
            }
        }

        if let Some(name) = &self.v6_disabled_iface {
            let _ = cmd::run(
                NETSH,
                &["interface", "ipv6", "set", "interface", name, "enabled"],
            );
        }
    }
}

fn to_io<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // This whole module is `#[cfg(target_os = "windows")]`, so the smoke only compiles for
    // the Windows target (cross-checked with `--tests`). It is `#[ignore]`d because it needs
    // Administrator + `wintun.dll` on real Windows; it cannot run on the Linux build box.
    #[tokio::test]
    #[ignore = "requires Admin + wintun.dll on real Windows; run elevated: cargo test -p leshiy-tun -- --ignored windows_tun_up"]
    async fn windows_tun_up() {
        let plan = RoutePlan::full_tunnel(
            "203.0.113.7".parse().unwrap(),
            "192.168.1.1".parse().unwrap(), // a plausible LAN gateway for the smoke
            "10.71.0.2".parse().unwrap(),
        )
        .unwrap();
        let sess = WindowsOps
            .start(
                "leshiy0",
                1400,
                &plan,
                &["1.1.1.1".parse().unwrap()],
                true,
                true,
            )
            .await
            .expect("Wintun adapter should come up (wintun.dll present, elevated)");
        drop(sess); // should restore DNS + smart-resolution + IPv6 cleanly
    }
}
