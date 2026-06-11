//! Windows privileged ops: Wintun device (`tun` crate; requires `wintun.dll` beside the
//! binary), routes (`net-route` + `netsh`), DNS (`netsh`), smart-multi-homed-resolution
//! disable, IPv6 leak mitigation, all restored on teardown. Compile-checked on Linux via
//! cross-target `cargo check`; runtime-verified only on real Windows (Task 3.8 smoke).
use super::cmd;
use super::{PrivilegedOps, TunSession};
use crate::route_plan::RoutePlan;
use net_route::{Handle, Route};
use std::net::IpAddr;
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
        let exc = &plan.server_exception;
        let exc_route = Route::new(exc.dest.addr, exc.dest.prefix).with_gateway(exc.gateway);
        if handle.add(&exc_route).await.is_err() {
            let orig_iface = original_iface_name().unwrap_or_default();
            let args = cmd::win_route_add_via_gateway_args(
                &format!("{}/{}", exc.dest.addr, exc.dest.prefix),
                &exc.gateway.to_string(),
                &orig_iface,
            );
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            let _ = cmd::run(NETSH, &argv); // best-effort
        }
        for c in &plan.via_tun {
            let args =
                cmd::win_route_add_via_iface_args(&format!("{}/{}", c.addr, c.prefix), &iface);
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            cmd::run(NETSH, &argv)?;
        }

        // 3. DNS on the tun interface (static), so queries ride the tunnel.
        if let Some(first) = dns.first() {
            let args = cmd::win_dns_set_static_args(&iface, &first.to_string());
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            let _ = cmd::run(NETSH, &argv);
        }

        // 4. DNS-leak hardening: disable smart multi-homed name resolution so Windows
        //    can't fan a query out the physical NIC. Back up the prior registry value.
        let smart_backup = read_smart_resolution_policy();
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

        // 5. IPv6 leak mitigation (fail-closed): disable IPv6 binding on the original
        //    interface; restore on drop. (Full IPv6 tunnelling is out of scope.)
        let orig_iface = original_iface_name();
        if let Some(name) = &orig_iface {
            let _ = cmd::run(
                NETSH,
                &["interface", "ipv6", "set", "interface", name, "disabled"],
            );
        }

        let guard = WindowsTeardown {
            tun_iface: iface,
            orig_iface,
            smart_backup,
        };
        Ok(TunSession {
            device,
            guard: Box::new(guard),
        })
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

/// Restores DNS, the smart-resolution policy, and IPv6 on drop. Override/exception routes
/// auto-clear when the Wintun adapter is dropped.
struct WindowsTeardown {
    tun_iface: String,
    orig_iface: Option<String>,
    smart_backup: Option<String>,
}

impl Drop for WindowsTeardown {
    fn drop(&mut self) {
        // Best-effort; teardown must never panic.
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

        if let Some(name) = &self.orig_iface {
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
