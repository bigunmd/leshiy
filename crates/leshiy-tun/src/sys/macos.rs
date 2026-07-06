//! macOS privileged ops: utun device (`tun` crate), routes (`net-route` + BSD `route`),
//! DNS (`networksetup`), IPv6 leak mitigation (`networksetup -setv6off`), all restored on
//! teardown.
//!
//! Verification note (2026-06-11): this box has no Apple SDK, so the macOS target cannot be
//! cross-`check`ed (`ring`'s C build needs an Apple clang+SDK). Instead the module is also
//! compiled under host `test` (see `sys/mod.rs`), which **type-checks** the backend on
//! Linux — the `tun`/`net-route` calls use the cross-platform `AbstractDevice`/`Handle`
//! surface that compiles on every OS. Runtime behaviour is verified only on real macOS via
//! the `#[ignore]`d `macos_tun_up` smoke (Task 3.4).
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
use super::cmd;
use super::{PrivilegedOps, RouteController, TunSession};
use crate::route_plan::{Cidr, RoutePlan};
use net_route::{Handle, Route};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tun::AbstractDevice; // brings `tun_name()` into scope for the utun device

const NETWORKSETUP: &str = "/usr/sbin/networksetup";
const ROUTE: &str = "/sbin/route";
const IFCONFIG: &str = "/sbin/ifconfig";

pub struct MacOsOps;

#[async_trait::async_trait]
impl PrivilegedOps for MacOsOps {
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
        // The utun always carries an IPv4 address; IPv6 is dual-stacked on top when
        // `plan.tun_addr6` is set (else it stays fail-closed via `-setv6off`).
        let IpAddr::V4(tun4) = plan.tun_addr else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "tun_addr must be IPv4",
            ));
        };

        // 1. Create + bring up the utun device. `tun` auto-assigns `utunN`; on macOS the
        //    crate also installs the on-link route from address/netmask. No
        //    `ensure_root_privileges` here — that platform_config is Linux-only.
        let mut cfg = tun::Configuration::default();
        cfg.tun_name(tun_name)
            .address(tun4)
            .netmask(std::net::Ipv4Addr::new(255, 255, 255, 0))
            .mtu(mtu)
            .up();
        let device = tun::create_as_async(&cfg).map_err(to_io)?;
        // Read back the real interface name (e.g. "utun7") for `route -interface`.
        let iface = device.tun_name().map_err(to_io)?;

        // Dual-stack: add the IPv6 address to the utun so IPv6 can ride the tunnel. Best-effort —
        // if it fails we fall closed to `-setv6off` (below) instead of leaking v6.
        let carry_v6 = match plan.tun_addr6 {
            Some(IpAddr::V6(v6)) => {
                let args = cmd::mac_ifconfig_v6_add_args(&iface, &v6.to_string());
                let argv: Vec<&str> = args.iter().map(String::as_str).collect();
                match cmd::run(IFCONFIG, &argv) {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::error!(%v6, "failed to assign IPv6 utun address ({e}); failing closed to -setv6off");
                        false
                    }
                }
            }
            _ => false,
        };

        // 2. Routes: server host-exception FIRST (escape the tunnel via the original
        //    gateway), then the default-override halves via the utun interface.
        let handle = Handle::new()?;
        // Physical NIC ifindex (from the current default route). net_route may need the egress
        // interface to install a gateway route, so attach it to the exception + bypass routes.
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
            // Fallback to BSD `route` if net-route's gateway add is rejected (v4 syntax only).
            let args = cmd::mac_route_add_via_gateway_args(
                &exc.dest.addr.to_string(),
                exc.dest.prefix,
                &exc.gateway.to_string(),
            );
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            let _ = cmd::run(ROUTE, &argv); // best-effort: an identical host route already existing is fine
        }
        // via_tun + bypass go through the net_route `Handle` (PF_ROUTE socket) — thousands of
        // fast in-process messages, NOT a `route` subprocess per CIDR (a subscription can carry
        // thousands; spawning `route` each stalls connect for minutes). via_tun routes through
        // the utun by its index (from the device); if unavailable, fall back to `route` by name.
        // Best-effort: a bad/duplicate route in a list must not fail the session.
        let tun_idx = device.tun_index().ok().map(|i| i as u32);
        for c in &plan.via_tun {
            // Skip an IPv6 via-tun route unless IPv6 is carried this session.
            if c.addr.is_ipv6() && !carry_v6 {
                continue;
            }
            match tun_idx {
                // net_route handles both families through the utun by ifindex.
                Some(idx) => {
                    let _ = handle
                        .add(&Route::new(c.addr, c.prefix).with_ifindex(idx))
                        .await;
                }
                // Fallback `route` builder is v4 syntax only; a v6 route without an ifindex is
                // skipped (tun_idx is essentially always present).
                None if c.addr.is_ipv4() => {
                    let args =
                        cmd::mac_route_add_via_iface_args(&c.addr.to_string(), c.prefix, &iface);
                    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
                    let _ = cmd::run(ROUTE, &argv);
                }
                None => {}
            }
        }

        // 2b. Split-tunnel bypass routes (Exclude): each CIDR escapes via the original gateway.
        //     Tracked in `installed_bypass` (shared with the controller + teardown) — gateway
        //     routes persist after the utun drops, so they're deleted explicitly.
        let installed_bypass: Arc<Mutex<Vec<Cidr>>> = Arc::new(Mutex::new(Vec::new()));
        for b in &plan.bypass {
            // A v6 bypass needs IPv6 carried; otherwise skip (it then rides the tunnel — safe).
            if b.dest.addr.is_ipv6() && !carry_v6 {
                continue;
            }
            let idx = if b.dest.addr.is_ipv4() { orig_idx } else { None };
            let _ = handle
                .add(&gateway_route(b.dest.addr, b.dest.prefix, b.gateway, idx))
                .await; // best-effort, fast (PF_ROUTE socket)
            installed_bypass.lock().unwrap().push(b.dest.clone());
        }

        // 3. DNS: set the configured resolver(s) on every active network service, backing up
        //    the prior servers so teardown can restore them. Skipped in Include mode.
        let services = list_network_services()?;
        let mut dns_backup: Vec<(String, Vec<String>)> = Vec::new();
        if force_dns {
            for svc in &services {
                let prior = current_dns(svc).unwrap_or_default();
                dns_backup.push((svc.clone(), prior));
                let args = cmd::mac_dns_set_args(svc, dns);
                let argv: Vec<&str> = args.iter().map(String::as_str).collect();
                let _ = cmd::run(NETWORKSETUP, &argv);
            }
        }

        // 4. IPv6 leak mitigation (fail-closed): turn IPv6 off on each service; restore to
        //    automatic on drop. Applied when the caller asked (IPv4-only session) OR when we
        //    meant to carry v6 but couldn't assign the address. Skipped when v6 is genuinely
        //    carried, and in Include mode.
        let apply_v6off = ipv6_killswitch || (plan.tun_addr6.is_some() && !carry_v6);
        let mut v6_services: Vec<String> = Vec::new();
        if apply_v6off {
            for svc in &services {
                if cmd::run(NETWORKSETUP, &["-setv6off", svc]).is_ok() {
                    v6_services.push(svc.clone());
                }
            }
        }

        let controller = Arc::new(MacOsController {
            handle: Handle::new()?,
            tun_idx,
            tun_addr: tun4,
            gateway: plan.server_exception.gateway,
            orig_idx,
            carry_v6,
            installed_bypass: installed_bypass.clone(),
        });
        let guard = MacOsTeardown {
            dns_backup,
            v6_services,
            installed_bypass,
        };
        Ok(TunSession {
            device,
            guard: Box::new(guard),
            controller,
        })
    }
}

/// Live runtime route control for the macOS session via the net_route `Handle` (PF_ROUTE
/// socket) — NOT a `route` subprocess per route, which (for a domain preset resolving to
/// thousands of IPs) would spawn thousands of processes and wedge the runtime. via_tun routes
/// through the utun by ifindex (or, if unknown, via the tun's on-link address). Bypass
/// additions are tracked in `installed_bypass` so teardown can remove them on abort.
struct MacOsController {
    handle: Handle,
    tun_idx: Option<u32>,
    tun_addr: std::net::Ipv4Addr,
    gateway: IpAddr,
    orig_idx: Option<u32>,
    /// Whether IPv6 is carried this session (gates resolved v6 domain via-tun routes).
    carry_v6: bool,
    installed_bypass: Arc<Mutex<Vec<Cidr>>>,
}

impl MacOsController {
    fn via_tun_route(&self, c: &Cidr) -> Route {
        match self.tun_idx {
            Some(idx) => Route::new(c.addr, c.prefix).with_ifindex(idx),
            None => Route::new(c.addr, c.prefix).with_gateway(IpAddr::V4(self.tun_addr)),
        }
    }
}

#[async_trait::async_trait]
impl RouteController for MacOsController {
    async fn add_bypass(&self, c: &Cidr) -> std::io::Result<()> {
        let IpAddr::V4(_) = c.addr else {
            return Ok(());
        };
        self.handle
            .add(&gateway_route(
                c.addr,
                c.prefix,
                self.gateway,
                self.orig_idx,
            ))
            .await?;
        self.installed_bypass.lock().unwrap().push(c.clone());
        Ok(())
    }
    async fn remove_bypass(&self, c: &Cidr) -> std::io::Result<()> {
        let _ = self
            .handle
            .delete(&gateway_route(
                c.addr,
                c.prefix,
                self.gateway,
                self.orig_idx,
            ))
            .await;
        self.installed_bypass.lock().unwrap().retain(|x| x != c);
        Ok(())
    }
    async fn add_via_tun(&self, c: &Cidr) -> std::io::Result<()> {
        // A v6 via-tun route needs IPv6 carried AND the utun ifindex (the v4-gateway fallback
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
        // Drain the shared list so the guard's `Drop` (same Arc) finds it empty and skips its slow
        // per-route `route delete` subprocess fallback. Delete each in-process via net_route —
        // far faster than a subprocess per CIDR for a large rule set.
        let routes: Vec<Cidr> = std::mem::take(&mut *self.installed_bypass.lock().unwrap());
        for c in &routes {
            let _ = self
                .handle
                .delete(&gateway_route(
                    c.addr,
                    c.prefix,
                    self.gateway,
                    self.orig_idx,
                ))
                .await;
        }
    }
}

/// Build a next-hop (gateway) route, attaching the egress interface index when known —
/// net_route may need it to install a gateway route. Used for the server exception + bypass.
fn gateway_route(addr: IpAddr, prefix: u8, gateway: IpAddr, ifindex: Option<u32>) -> Route {
    let route = Route::new(addr, prefix).with_gateway(gateway);
    match ifindex {
        Some(i) => route.with_ifindex(i),
        None => route,
    }
}

/// List active network service names (e.g. "Wi-Fi", "Ethernet"). The first output line
/// of `networksetup -listallnetworkservices` is a header and is skipped; a leading `*`
/// marks a disabled service and is stripped.
fn list_network_services() -> std::io::Result<Vec<String>> {
    let out = cmd::run_capture(NETWORKSETUP, &["-listallnetworkservices"])?;
    Ok(out
        .lines()
        .skip(1)
        .map(|l| l.trim_start_matches('*').trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// The current DNS servers for `service`, or empty if "There aren't any DNS Servers set".
fn current_dns(service: &str) -> std::io::Result<Vec<String>> {
    let out = cmd::run_capture(NETWORKSETUP, &["-getdnsservers", service])?;
    if out.contains("aren't any") || out.contains("There aren") {
        Ok(Vec::new())
    } else {
        Ok(out
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect())
    }
}

/// Restores DNS + IPv6 on drop and removes any split-tunnel `bypass` routes. The
/// override/exception/via-tun routes auto-clear when the utun device is dropped; the `bypass`
/// gateway routes do not, so they're deleted explicitly here.
struct MacOsTeardown {
    dns_backup: Vec<(String, Vec<String>)>,
    v6_services: Vec<String>,
    /// All bypass routes still installed (static + resolver-added) — removed on teardown.
    installed_bypass: Arc<Mutex<Vec<Cidr>>>,
}

impl Drop for MacOsTeardown {
    fn drop(&mut self) {
        // Best-effort; teardown must never panic.
        for c in self.installed_bypass.lock().unwrap().iter() {
            let args = cmd::mac_route_del_args(&c.addr.to_string(), c.prefix);
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            let _ = cmd::run(ROUTE, &argv);
        }
        for (svc, prior) in &self.dns_backup {
            let prior_ips: Vec<IpAddr> = prior.iter().filter_map(|s| s.parse().ok()).collect();
            let args = cmd::mac_dns_set_args(svc, &prior_ips); // empty prior -> "empty" (clears)
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            let _ = cmd::run(NETWORKSETUP, &argv);
        }
        for svc in &self.v6_services {
            let _ = cmd::run(NETWORKSETUP, &["-setv6automatic", svc]);
        }
    }
}

fn to_io<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    // Imported only where the macOS-gated smoke below uses it; on the host the smoke is
    // `cfg`-compiled out, so this would otherwise be an unused import.
    #[cfg(target_os = "macos")]
    use super::*;

    // Gated to macOS: the smoke needs root + a real utun on macOS, so it never runs (or even
    // compiles) on the Linux host. `#[ignore]`d so a macOS operator opts in explicitly.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[ignore = "requires root on real macOS; run with: sudo -E cargo test -p leshiy-tun -- --ignored macos_tun_up"]
    async fn macos_tun_up() {
        let plan = RoutePlan::full_tunnel(
            "203.0.113.7".parse().unwrap(),
            "127.0.0.1".parse().unwrap(), // harmless gateway for the smoke
            "10.71.0.2".parse().unwrap(),
        )
        .unwrap();
        let sess = MacOsOps
            .start(
                "utun9",
                1400,
                &plan,
                &["1.1.1.1".parse().unwrap()],
                true,
                true,
            )
            .await
            .expect("utun should come up");
        drop(sess); // should restore DNS + IPv6 cleanly
    }
}
