//! Linux privileged ops: TUN device (rust-tun), routes (net-route), DNS (resolv.conf),
//! and an IPv6 disable kill-switch — all restored on teardown.
use super::{PrivilegedOps, RouteController, TunSession};
use crate::route_plan::{Cidr, RoutePlan};
use net_route::{Handle, Route};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

pub struct LinuxOps;

const RESOLV: &str = "/etc/resolv.conf";
const IPV6_ALL: &str = "/proc/sys/net/ipv6/conf/all/disable_ipv6";
const IPV6_DEFAULT: &str = "/proc/sys/net/ipv6/conf/default/disable_ipv6";
/// iproute2 binary, used only in teardown to remove `bypass` routes synchronously (Drop is
/// not async, and unlike the via-tun routes these don't auto-clear when the device drops).
const IP: &str = "ip";

#[async_trait::async_trait]
impl PrivilegedOps for LinuxOps {
    async fn start(
        &self,
        tun_name: &str,
        mtu: u16,
        plan: &RoutePlan,
        dns: &[IpAddr],
        force_dns: bool,
        ipv6_killswitch: bool,
    ) -> std::io::Result<TunSession> {
        // MVP carries IPv4 through the tunnel; IPv6 is disabled below (fail-closed).
        let IpAddr::V4(tun4) = plan.tun_addr else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "tun_addr must be IPv4 in this phase",
            ));
        };

        // 1. Create + bring up the TUN device.
        let mut cfg = tun::Configuration::default();
        cfg.tun_name(tun_name)
            .address(tun4)
            .netmask(Ipv4Addr::new(255, 255, 255, 0))
            .mtu(mtu)
            .up();
        cfg.platform_config(|p| {
            p.ensure_root_privileges(true);
        });
        let device = tun::create_as_async(&cfg).map_err(to_io)?;

        // 2. Routes: install the server-host exception FIRST (so the encrypted packets to
        //    the server escape the tunnel), then the default-override halves via the TUN.
        let handle = Handle::new()?;
        let ifindex = ifindex_of(tun_name)?;
        let exception = Route::new(
            plan.server_exception.dest.addr,
            plan.server_exception.dest.prefix,
        )
        .with_gateway(plan.server_exception.gateway);
        let _ = handle.add(&exception).await; // best-effort: an existing identical host route is fine
        for c in &plan.via_tun {
            // IPv4-only this phase (the tun is IPv4). An Include IPv6 CIDR is skipped, not errored.
            let IpAddr::V4(_) = c.addr else {
                tracing::warn!(cidr = %c, "skipping IPv6 via_tun route (IPv6 disabled this phase)");
                continue;
            };
            // Best-effort: one bad/duplicate route in a large subscription list must not tear
            // down the whole session (the default-override /1 routes are fresh and won't fail).
            if let Err(e) = handle
                .add(&Route::new(c.addr, c.prefix).with_ifindex(ifindex))
                .await
            {
                tracing::warn!(cidr = %c, "via_tun route add failed (continuing): {e}");
            }
        }

        // 2b. Split-tunnel bypass routes (Exclude mode): each listed CIDR escapes the tunnel
        //     via the original gateway. Tracked in `installed_bypass` (shared with the
        //     controller + teardown) because — unlike via_tun routes — they point at the
        //     gateway and don't auto-clear when the device drops.
        let installed_bypass: Arc<Mutex<Vec<Cidr>>> = Arc::new(Mutex::new(Vec::new()));
        for b in &plan.bypass {
            let IpAddr::V4(_) = b.dest.addr else {
                tracing::warn!(cidr = %b.dest, "skipping IPv6 split-tunnel bypass (IPv6 disabled this phase)");
                continue;
            };
            let _ = handle
                .add(&Route::new(b.dest.addr, b.dest.prefix).with_gateway(b.gateway))
                .await; // best-effort
            installed_bypass.lock().unwrap().push(b.dest.clone());
        }

        // 3. DNS: force the configured resolver(s) so queries ride the tunnel. Skipped in
        //    Include mode (most traffic is direct; the system resolver is left untouched).
        let resolv_backup = if force_dns && !dns.is_empty() {
            let prior = std::fs::read(RESOLV).ok();
            let body: String = dns.iter().map(|ip| format!("nameserver {ip}\n")).collect();
            std::fs::write(RESOLV, body)?;
            prior
        } else {
            None
        };

        // 4. IPv6 kill-switch (fail-closed): disable v6 so it can't leak around the v4 tunnel.
        //    Skipped in Include mode (the un-tunneled majority, including IPv6, stays direct).
        let (ipv6_all_backup, ipv6_default_backup) = if ipv6_killswitch {
            let all = std::fs::read_to_string(IPV6_ALL).ok();
            let def = std::fs::read_to_string(IPV6_DEFAULT).ok();
            let _ = std::fs::write(IPV6_ALL, "1");
            let _ = std::fs::write(IPV6_DEFAULT, "1");
            (all, def)
        } else {
            (None, None)
        };

        let controller = Arc::new(LinuxController {
            handle: Handle::new()?,
            gateway: plan.server_exception.gateway,
            ifindex,
            installed_bypass: installed_bypass.clone(),
        });
        let guard = LinuxTeardown {
            resolv_backup,
            ipv6_all_backup,
            ipv6_default_backup,
            installed_bypass,
        };
        Ok(TunSession {
            device,
            guard: Box::new(guard),
            controller,
        })
    }
}

/// Live runtime route control for the Linux session: `net_route` add/delete for the resolved
/// domain routes. Bypass (Exclude) additions are tracked in `installed_bypass` so the teardown
/// guard can remove them even on a hard abort; via_tun (Include) routes auto-clear on device
/// drop and aren't tracked.
struct LinuxController {
    handle: Handle,
    gateway: IpAddr,
    ifindex: u32,
    installed_bypass: Arc<Mutex<Vec<Cidr>>>,
}

#[async_trait::async_trait]
impl RouteController for LinuxController {
    async fn add_bypass(&self, c: &Cidr) -> std::io::Result<()> {
        let IpAddr::V4(_) = c.addr else {
            return Ok(()); // IPv4-only this phase
        };
        self.handle
            .add(&Route::new(c.addr, c.prefix).with_gateway(self.gateway))
            .await?;
        self.installed_bypass.lock().unwrap().push(c.clone());
        Ok(())
    }
    async fn remove_bypass(&self, c: &Cidr) -> std::io::Result<()> {
        let IpAddr::V4(_) = c.addr else {
            return Ok(());
        };
        let _ = self
            .handle
            .delete(&Route::new(c.addr, c.prefix).with_gateway(self.gateway))
            .await;
        self.installed_bypass.lock().unwrap().retain(|x| x != c);
        Ok(())
    }
    async fn add_via_tun(&self, c: &Cidr) -> std::io::Result<()> {
        let IpAddr::V4(_) = c.addr else {
            return Ok(());
        };
        self.handle
            .add(&Route::new(c.addr, c.prefix).with_ifindex(self.ifindex))
            .await
    }
    async fn remove_via_tun(&self, c: &Cidr) -> std::io::Result<()> {
        let IpAddr::V4(_) = c.addr else {
            return Ok(());
        };
        let _ = self
            .handle
            .delete(&Route::new(c.addr, c.prefix).with_ifindex(self.ifindex))
            .await;
        Ok(())
    }
}

/// Restores DNS + IPv6 state on drop, and removes any split-tunnel `bypass` routes. The
/// default-override / via-tun routes auto-clear when the TUN device is dropped (the interface
/// disappears); the `bypass` routes point at the original gateway, so they're deleted here.
struct LinuxTeardown {
    resolv_backup: Option<Vec<u8>>,
    ipv6_all_backup: Option<String>,
    ipv6_default_backup: Option<String>,
    /// All bypass routes still installed (static + resolver-added) — removed on teardown.
    installed_bypass: Arc<Mutex<Vec<Cidr>>>,
}

impl Drop for LinuxTeardown {
    fn drop(&mut self) {
        // Best-effort; teardown must never panic. `Drop` is synchronous and `net_route`'s
        // delete is async, so remove bypass routes via iproute2 (sync).
        for c in self.installed_bypass.lock().unwrap().iter() {
            let _ = std::process::Command::new(IP)
                .args(["route", "del", &c.to_string()])
                .output();
        }
        if let Some(b) = &self.resolv_backup {
            let _ = std::fs::write(RESOLV, b);
        }
        if let Some(v) = &self.ipv6_all_backup {
            let _ = std::fs::write(IPV6_ALL, v.trim());
        }
        if let Some(v) = &self.ipv6_default_backup {
            let _ = std::fs::write(IPV6_DEFAULT, v.trim());
        }
    }
}

fn to_io<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Read an interface's index from sysfs (Linux), avoiding any `unsafe` FFI.
fn ifindex_of(name: &str) -> std::io::Result<u32> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))?;
    s.trim()
        .parse::<u32>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_plan::RoutePlan;
    use leshiy_client::SplitMode;

    // Needs root + CAP_NET_ADMIN to create a real TUN and install routes, so it can't run on
    // a sandboxed host. `#[ignore]`d; an operator opts in explicitly. The non-ignored value is
    // that it compiles (type-checks the split-tunnel `start` path) under `cargo test`.
    #[tokio::test]
    #[ignore = "requires root + CAP_NET_ADMIN; run: sudo -E cargo test -p leshiy-tun -- --ignored linux_split_exclude_up"]
    async fn linux_split_exclude_up() {
        let excl = Cidr {
            addr: "198.51.100.0".parse().unwrap(),
            prefix: 24,
        };
        let plan = RoutePlan::with_split(
            SplitMode::Exclude,
            &[excl],
            "203.0.113.7".parse().unwrap(),
            "127.0.0.1".parse().unwrap(), // harmless gateway for the smoke
            "10.71.0.2".parse().unwrap(),
        )
        .unwrap();
        let sess = LinuxOps
            .start(
                "leshiy9",
                1400,
                &plan,
                &["1.1.1.1".parse().unwrap()],
                true,
                true,
            )
            .await
            .expect("tun + split routes should come up");
        // `ip route` should now show 198.51.100.0/24 via 127.0.0.1 and 0/1+128/1 via leshiy9.
        drop(sess); // restores DNS/IPv6 and deletes the bypass route
    }

    // Exercises the live RouteController used for resolved domain rules: add a dynamic bypass
    // route, then remove it. Needs a real default gateway so `net_route add ... via gw`
    // succeeds. `#[ignore]`d; runtime-only.
    #[tokio::test]
    #[ignore = "requires root + CAP_NET_ADMIN + a real default gateway; run: sudo -E cargo test -p leshiy-tun -- --ignored linux_controller_bypass_add_remove"]
    async fn linux_controller_bypass_add_remove() {
        let gw = crate::discover::default_gateway_v4()
            .await
            .expect("a default gateway");
        let plan = RoutePlan::full_tunnel(
            "203.0.113.7".parse().unwrap(),
            gw,
            "10.71.0.2".parse().unwrap(),
        )
        .unwrap();
        let sess = LinuxOps
            .start(
                "leshiy8",
                1400,
                &plan,
                &["1.1.1.1".parse().unwrap()],
                true,
                true,
            )
            .await
            .expect("tun up");
        let c = Cidr {
            addr: "198.51.100.0".parse().unwrap(),
            prefix: 24,
        };
        sess.controller.add_bypass(&c).await.expect("add bypass");
        sess.controller
            .remove_bypass(&c)
            .await
            .expect("remove bypass");
        drop(sess); // teardown restores DNS/IPv6 and removes any remaining bypass routes
    }
}
