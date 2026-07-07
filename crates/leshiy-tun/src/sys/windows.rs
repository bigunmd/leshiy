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
    const CARRIES_V6: bool = true;

    async fn start(
        &self,
        tun_name: &str,
        mtu: u16,
        plan: &RoutePlan,
        dns: &[IpAddr],
        force_dns: bool,
        ipv6_killswitch: bool,
    ) -> std::io::Result<TunSession> {
        // The Wintun adapter always carries an IPv4 address; IPv6 is dual-stacked on top when
        // `plan.tun_addr6` is set (else it stays fail-closed by disabling v6 on the NIC). The
        // server exception may be v6 (v6-reached server); net_route handles both families.
        let IpAddr::V4(tun4) = plan.tun_addr else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "tun_addr must be IPv4",
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
        // Wintun loads `wintun.dll` from the helper's own directory at runtime. If the bundle
        // is missing it (the #1 reason the Windows VPN silently fails to start), surface a
        // clear, actionable error instead of the loader's opaque one.
        let device = tun::create_as_async(&cfg).map_err(|e| {
            std::io::Error::other(format!(
                "failed to create the Wintun adapter: {e}. Ensure wintun.dll is present next to \
                 leshiy-helper.exe (it is bundled with the installer) and that the helper is \
                 running elevated."
            ))
        })?;
        let iface = device.tun_name().map_err(to_io)?;

        // Dual-stack: add the IPv6 address to the adapter so IPv6 can ride the tunnel. Best-effort
        // — if it fails we fall closed to disabling v6 on the NIC (below) instead of leaking v6.
        let carry_v6 = match plan.tun_addr6 {
            Some(IpAddr::V6(v6)) => {
                let args = cmd::win_v6_addr_add_args(&iface, &v6.to_string());
                let argv: Vec<&str> = args.iter().map(String::as_str).collect();
                match cmd::run(NETSH, &argv) {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::error!(%v6, "failed to assign IPv6 adapter address ({e}); failing closed");
                        false
                    }
                }
            }
            _ => false,
        };

        // 2. Routes: server host-exception FIRST via the original gateway, then the
        //    default-override halves via the tun interface. Prefer net-route; fall back
        //    to netsh by interface name.
        let handle = Handle::new()?;
        // The active physical interface name (for the host-exception netsh fallback + IPv6
        // restore) and its ifindex. On Windows, net_route needs the interface index to install
        // a gateway (next-hop) route — a gateway alone fails — so bypass routes that lacked it
        // were silently dropped. Take it from the current default route.
        let orig_iface = original_iface_name();
        let orig_idx = handle
            .default_route()
            .await
            .ok()
            .flatten()
            .and_then(|r| r.ifindex);
        let exc = &plan.server_exception;
        // Attach the v4 egress ifindex only for a v4 exception; let the OS pick for v6.
        let exc_idx = if exc.dest.addr.is_ipv4() { orig_idx } else { None };
        let exc_route = gateway_route(exc.dest.addr, exc.dest.prefix, exc.gateway, exc_idx);
        if handle.add(&exc_route).await.is_err() && exc.dest.addr.is_ipv4() {
            // netsh fallback is v4 (ipv4) syntax only; net_route handles the v6 exception.
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
        // Count via_tun install failures: unlike a failed bypass (the CIDR then rides the tunnel —
        // safe), a failed via_tun means that CIDR is NOT routed through the tunnel. Under an
        // Include base that is a silent direct-traffic leak, so surface it instead of swallowing.
        let mut via_tun_failures = 0usize;
        for c in &plan.via_tun {
            // A v6 via-tun route needs IPv6 carried AND the adapter ifindex (the v4-gateway
            // fallback can't carry v6); otherwise skip it.
            if c.addr.is_ipv6() && (!carry_v6 || tun_idx.is_none()) {
                continue;
            }
            // Route through the Wintun adapter by ifindex (both families), or via its own on-link
            // v4 address if the index is unknown — always net_route (never a netsh subprocess).
            let route = match tun_idx {
                Some(idx) => Route::new(c.addr, c.prefix).with_ifindex(idx),
                None => Route::new(c.addr, c.prefix).with_gateway(IpAddr::V4(tun4)),
            };
            if handle.add(&route).await.is_err() {
                via_tun_failures += 1;
            }
        }
        if via_tun_failures > 0 {
            tracing::warn!(
                failures = via_tun_failures,
                "some via-tun routes failed to install; matching traffic may bypass the tunnel"
            );
        }

        // 2b. Split-tunnel bypass routes (Exclude): each CIDR escapes via the original gateway.
        //     Tracked in `installed_bypass` (shared with the controller + teardown) — they point
        //     at the gateway, so (unlike via_tun) they don't auto-clear when the adapter drops.
        let orig_iface_str = orig_iface.clone().unwrap_or_default();
        let gateway = plan.server_exception.gateway.to_string();
        let installed_bypass: Arc<Mutex<Vec<Cidr>>> = Arc::new(Mutex::new(Vec::new()));
        for b in &plan.bypass {
            // A v6 bypass needs IPv6 carried; otherwise skip (it then rides the tunnel — safe).
            if b.dest.addr.is_ipv6() && !carry_v6 {
                continue;
            }
            let idx = if b.dest.addr.is_ipv4() { orig_idx } else { None };
            let _ = handle
                .add(&gateway_route(b.dest.addr, b.dest.prefix, b.gateway, idx))
                .await; // best-effort, fast (IP Helper API)
            installed_bypass.lock().unwrap_or_else(|e| e.into_inner()).push(b.dest.clone());
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
        // Applied when the caller asked (IPv4-only session) OR when we meant to carry v6 but
        // couldn't assign the address. Skipped when v6 is genuinely carried, and in Include mode.
        let apply_v6off = ipv6_killswitch || (plan.tun_addr6.is_some() && !carry_v6);
        let mut v6_disabled_iface = None;
        if apply_v6off && let Some(name) = &orig_iface {
            let _ = cmd::run(
                NETSH,
                &["interface", "ipv6", "set", "interface", name, "disabled"],
            );
            v6_disabled_iface = Some(name.clone());
        }

        let controller = Arc::new(WindowsController {
            handle: Handle::new()?,
            tun_idx,
            tun_addr: tun4,
            gateway: plan.server_exception.gateway,
            gateway6: plan.orig_gateway6,
            orig_idx,
            carry_v6,
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

/// Live runtime route control for the Windows session via the net_route `Handle` (IP Helper
/// API) — NOT a `netsh` subprocess per route, which (for a domain preset resolving to thousands
/// of IPs) would spawn thousands of processes and wedge the runtime. via_tun routes through the
/// Wintun adapter by ifindex (or, if unknown, via the tun's own on-link address). Bypass
/// additions are tracked in `installed_bypass` so teardown can remove them on abort.
struct WindowsController {
    handle: Handle,
    tun_idx: Option<u32>,
    tun_addr: std::net::Ipv4Addr,
    gateway: IpAddr,
    /// Original IPv6 default gateway (from the plan), used to route resolved v6 bypass rules.
    /// `None` when v6 isn't carried or no v6 default route exists — a v6 bypass is then a no-op.
    gateway6: Option<IpAddr>,
    /// Physical NIC ifindex — required for net_route to install a gateway route on Windows.
    orig_idx: Option<u32>,
    /// Whether IPv6 is carried this session (gates resolved v6 domain via-tun / bypass routes).
    carry_v6: bool,
    installed_bypass: Arc<Mutex<Vec<Cidr>>>,
}

impl WindowsController {
    fn via_tun_route(&self, c: &Cidr) -> Route {
        match self.tun_idx {
            Some(idx) => Route::new(c.addr, c.prefix).with_ifindex(idx),
            None => Route::new(c.addr, c.prefix).with_gateway(IpAddr::V4(self.tun_addr)),
        }
    }

    /// The original gateway to bypass a resolved CIDR through, by address family. `None` for a v6
    /// CIDR when v6 isn't carried or no v6 gateway is known — the CIDR then rides the tunnel (safe).
    fn bypass_gateway(&self, c: &Cidr) -> Option<IpAddr> {
        if c.addr.is_ipv4() {
            self.gateway.is_ipv4().then_some(self.gateway)
        } else if self.carry_v6 {
            self.gateway6
        } else {
            None
        }
    }
}

#[async_trait::async_trait]
impl RouteController for WindowsController {
    async fn add_bypass(&self, c: &Cidr) -> std::io::Result<()> {
        let Some(gw) = self.bypass_gateway(c) else {
            tracing::debug!(cidr = %c, "split-tunnel: no gateway for this family; bypass rides the tunnel");
            return Ok(());
        };
        self.handle
            .add(&gateway_route(c.addr, c.prefix, gw, self.orig_idx))
            .await?;
        self.installed_bypass.lock().unwrap_or_else(|e| e.into_inner()).push(c.clone());
        Ok(())
    }
    async fn remove_bypass(&self, c: &Cidr) -> std::io::Result<()> {
        let Some(gw) = self.bypass_gateway(c) else {
            return Ok(());
        };
        let _ = self
            .handle
            .delete(&gateway_route(c.addr, c.prefix, gw, self.orig_idx))
            .await;
        self.installed_bypass.lock().unwrap_or_else(|e| e.into_inner()).retain(|x| x != c);
        Ok(())
    }
    async fn add_via_tun(&self, c: &Cidr) -> std::io::Result<()> {
        // A v6 via-tun route needs IPv6 carried AND the adapter ifindex (the v4-gateway fallback
        // route can't carry v6); otherwise skip it.
        if c.addr.is_ipv6() && (!self.carry_v6 || self.tun_idx.is_none()) {
            return Ok(());
        }
        self.handle.add(&self.via_tun_route(c)).await
    }
    async fn remove_via_tun(&self, c: &Cidr) -> std::io::Result<()> {
        if c.addr.is_ipv6() && (!self.carry_v6 || self.tun_idx.is_none()) {
            return Ok(());
        }
        let _ = self.handle.delete(&self.via_tun_route(c)).await;
        Ok(())
    }
    async fn teardown_bypass(&self) {
        // Drain the shared list so the guard's `Drop` (which shares the same Arc) finds it empty
        // and skips its slow per-route `netsh` fallback. Delete each route in-process via the
        // net_route Handle (IP Helper API) — orders of magnitude faster than a subprocess per CIDR.
        let routes: Vec<Cidr> = std::mem::take(&mut *self.installed_bypass.lock().unwrap_or_else(|e| e.into_inner()));
        for c in &routes {
            let Some(gw) = self.bypass_gateway(c) else {
                continue;
            };
            let _ = self
                .handle
                .delete(&gateway_route(c.addr, c.prefix, gw, self.orig_idx))
                .await;
        }
    }
}

/// Build a next-hop (gateway) route. On Windows net_route needs the egress interface index to
/// install a gateway route — a gateway alone is rejected — so attach the physical NIC's ifindex
/// when known. Used for the server exception and all bypass routes.
fn gateway_route(addr: IpAddr, prefix: u8, gateway: IpAddr, ifindex: Option<u32>) -> Route {
    let route = Route::new(addr, prefix).with_gateway(gateway);
    match ifindex {
        Some(i) => route.with_ifindex(i),
        None => route,
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
        for c in self.installed_bypass.lock().unwrap_or_else(|e| e.into_inner()).iter() {
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
