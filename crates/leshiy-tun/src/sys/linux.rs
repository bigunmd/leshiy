//! Linux privileged ops: TUN device (rust-tun), routes (net-route), DNS (resolv.conf),
//! and an IPv6 disable kill-switch — all restored on teardown.
use super::{PrivilegedOps, TunSession};
use crate::route_plan::RoutePlan;
use net_route::{Handle, Route};
use std::net::{IpAddr, Ipv4Addr};

pub struct LinuxOps;

const RESOLV: &str = "/etc/resolv.conf";
const IPV6_ALL: &str = "/proc/sys/net/ipv6/conf/all/disable_ipv6";
const IPV6_DEFAULT: &str = "/proc/sys/net/ipv6/conf/default/disable_ipv6";

#[async_trait::async_trait]
impl PrivilegedOps for LinuxOps {
    async fn start(
        &self,
        tun_name: &str,
        mtu: u16,
        plan: &RoutePlan,
        dns: &[IpAddr],
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
            handle
                .add(&Route::new(c.addr, c.prefix).with_ifindex(ifindex))
                .await?;
        }

        // 3. DNS: force the configured resolver(s); queries then ride the tunnel.
        let resolv_backup = std::fs::read(RESOLV).ok();
        if !dns.is_empty() {
            let body: String = dns.iter().map(|ip| format!("nameserver {ip}\n")).collect();
            std::fs::write(RESOLV, body)?;
        }

        // 4. IPv6 kill-switch (fail-closed): disable v6 so it can't leak around the v4 tunnel.
        //    Full IPv6 tunnelling is Phase 3; until then, no leak.
        let ipv6_all_backup = std::fs::read_to_string(IPV6_ALL).ok();
        let ipv6_default_backup = std::fs::read_to_string(IPV6_DEFAULT).ok();
        let _ = std::fs::write(IPV6_ALL, "1");
        let _ = std::fs::write(IPV6_DEFAULT, "1");

        let guard = LinuxTeardown {
            resolv_backup,
            ipv6_all_backup,
            ipv6_default_backup,
        };
        Ok(TunSession {
            device,
            guard: Box::new(guard),
        })
    }
}

/// Restores DNS + IPv6 state on drop. The default-override routes auto-clear when the TUN
/// device is dropped (the interface disappears), so they need no explicit teardown.
struct LinuxTeardown {
    resolv_backup: Option<Vec<u8>>,
    ipv6_all_backup: Option<String>,
    ipv6_default_backup: Option<String>,
}

impl Drop for LinuxTeardown {
    fn drop(&mut self) {
        // Best-effort; teardown must never panic.
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
