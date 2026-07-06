//! Linux privileged ops: TUN device (rust-tun), routes (net-route), DNS (resolv.conf),
//! and an IPv6 disable kill-switch — all restored on teardown.
use super::{PrivilegedOps, RouteController, TunSession};
use crate::route_plan::{Cidr, RoutePlan};
use net_route::{Handle, Route};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
        // The TUN interface always carries an IPv4 address; IPv6 is dual-stacked on top when
        // `plan.tun_addr6` is set (else it stays fail-closed via the kill-switch below).
        let IpAddr::V4(tun4) = plan.tun_addr else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "tun_addr must be IPv4",
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

        // 1b. Dual-stack: assign the IPv6 TUN address so IPv6 can ride the tunnel. Best-effort —
        //     if the host has IPv6 disabled the `ip -6 addr add` fails; we then fall closed to
        //     the kill-switch (below) rather than leave IPv6 leaking around a half-set-up tunnel.
        let carry_v6 = match plan.tun_addr6 {
            Some(IpAddr::V6(v6)) => match add_v6_addr(tun_name, v6).await {
                Ok(()) => true,
                Err(e) => {
                    tracing::error!(%v6, "failed to assign IPv6 TUN address ({e}); failing closed to the IPv6 kill-switch");
                    false
                }
            },
            _ => false,
        };

        // 2. Routes — applied in ONE `ip -batch` process: the server-host exception (so
        //    encrypted packets to the server escape the tunnel), the via-TUN routes (default
        //    override and/or include CIDRs, routed through the device), and the bypass routes
        //    (excluded CIDRs via the original gateway). A subscription can carry thousands of
        //    CIDRs; installing them one per netlink round-trip stalls connect, so we batch.
        //    `-force` keeps going past a bad/duplicate line instead of failing the session.
        //    IPv4-only this phase; IPv6 entries are skipped (logged).
        let ifindex = ifindex_of(tun_name)?;
        let installed_bypass: Arc<Mutex<Vec<Cidr>>> = Arc::new(Mutex::new(Vec::new()));
        let mut batch = String::new();
        // `ip -batch` infers the address family from each route's address, so v4 and v6 lines
        // coexist in one batch. IPv6 routes are only emitted when v6 is actually carried.
        let exc = &plan.server_exception;
        if exc.dest.addr.is_ipv4() || carry_v6 {
            batch.push_str(&format!("route add {} via {}\n", exc.dest, exc.gateway));
        }
        for c in &plan.via_tun {
            if c.addr.is_ipv4() || carry_v6 {
                batch.push_str(&format!("route add {} dev {}\n", c, tun_name));
            } else {
                tracing::warn!(cidr = %c, "skipping IPv6 via_tun route (IPv6 not carried)");
            }
        }
        // Bypass routes escape via the family-appropriate gateway the planner chose for each.
        // A v6 bypass needs IPv6 carried; otherwise skip it (it then rides the tunnel — safe).
        for b in &plan.bypass {
            if b.dest.addr.is_ipv6() && !carry_v6 {
                tracing::warn!(cidr = %b.dest, "skipping IPv6 split-tunnel bypass (IPv6 not carried)");
                continue;
            }
            batch.push_str(&format!("route add {} via {}\n", b.dest, b.gateway));
            installed_bypass.lock().unwrap().push(b.dest.clone());
        }
        ip_batch(&batch).await?;

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

        // 4. IPv6 kill-switch (fail-closed): disable v6 so it can't leak around the tunnel.
        //    Applied when the caller asked for it (IPv4-only session) OR when we intended to
        //    carry v6 but couldn't assign the address (so v6 would otherwise leak). Skipped when
        //    v6 is genuinely carried, and in Include mode (the un-tunneled majority stays direct).
        let apply_killswitch = ipv6_killswitch || (plan.tun_addr6.is_some() && !carry_v6);
        let (ipv6_all_backup, ipv6_default_backup) = if apply_killswitch {
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
            carry_v6,
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
    /// Whether IPv6 is carried through the tunnel this session. When false, resolved v6 domain
    /// routes are ignored (v6 is either fail-closed or out of scope).
    carry_v6: bool,
    installed_bypass: Arc<Mutex<Vec<Cidr>>>,
}

#[async_trait::async_trait]
impl RouteController for LinuxController {
    async fn add_bypass(&self, c: &Cidr) -> std::io::Result<()> {
        // Bypass rides the original gateway, which we only have for IPv4 (see the planner's
        // v6-exclude drop). A resolved v6 domain rule therefore stays in the tunnel.
        let IpAddr::V4(_) = c.addr else {
            return Ok(());
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
        // A v6 via-tun route only makes sense when v6 is carried (the TUN has a v6 address).
        if c.addr.is_ipv6() && !self.carry_v6 {
            return Ok(());
        }
        self.handle
            .add(&Route::new(c.addr, c.prefix).with_ifindex(self.ifindex))
            .await
    }
    async fn remove_via_tun(&self, c: &Cidr) -> std::io::Result<()> {
        if c.addr.is_ipv6() && !self.carry_v6 {
            return Ok(());
        }
        let _ = self
            .handle
            .delete(&Route::new(c.addr, c.prefix).with_ifindex(self.ifindex))
            .await;
        Ok(())
    }
}

/// Assign an IPv6 address to the TUN interface (`ip -6 addr add <v6>/64 dev <name>`). The
/// interface's IPv4 address is set by rust-tun at creation; rust-tun's config carries only one
/// address, so the v6 one is added out-of-band here. Fails if the host has IPv6 disabled.
async fn add_v6_addr(tun_name: &str, v6: Ipv6Addr) -> std::io::Result<()> {
    let status = tokio::process::Command::new(IP)
        .args(["-6", "addr", "add", &format!("{v6}/64"), "dev", tun_name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "ip -6 addr add {v6}/64 dev {tun_name} exited {status}"
        )))
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
        // Best-effort; teardown must never panic. `Drop` is synchronous, so batch the deletes
        // through one `ip -batch` process (sync) rather than thousands of `ip route del` spawns.
        let batch: String = self
            .installed_bypass
            .lock()
            .unwrap()
            .iter()
            .map(|c| format!("route del {c}\n"))
            .collect();
        if !batch.is_empty() {
            use std::io::Write;
            if let Ok(mut child) = std::process::Command::new(IP)
                .args(["-force", "-batch", "-"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(batch.as_bytes());
                }
                let _ = child.wait();
            }
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

/// Apply many route changes in a SINGLE `ip -batch` process (commands one per line on stdin,
/// e.g. `route add 1.2.3.0/24 dev leshiy0`). `-force` keeps going past per-line errors so a
/// bad/duplicate entry in a large list can't fail the batch. One process for thousands of
/// routes — vs. a netlink round-trip each — is what keeps connect fast with big subscriptions.
async fn ip_batch(script: &str) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    if script.is_empty() {
        return Ok(());
    }
    let mut child = tokio::process::Command::new(IP)
        .args(["-force", "-batch", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes()).await?;
        // `stdin` is dropped at the end of this block → `ip` sees EOF and runs the batch.
    }
    child.wait().await?;
    Ok(())
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
            None,
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
