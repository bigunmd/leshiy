//! Pure route planning. The split-tunnel inclusion/exclusion layer (a later phase) will
//! extend this without touching the engine. No OS calls here — `sys` applies the plan.
//!
//! **IPv6 (Phase 2 scope):** `via_tun` is intentionally IPv4-only. Carrying IPv6 *through*
//! the tunnel is Phase 3. To avoid a silent IPv6 leak on dual-stack hosts in the meantime,
//! the Linux `sys` backend disables IPv6 (sysctl kill-switch) while the session is up and
//! restores it on teardown — fail-closed, never leaking around the tunnel.
use std::net::IpAddr;

/// Errors from building a route plan.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RoutePlanError {
    #[error("server IP {server} and gateway {gateway} are different address families")]
    FamilyMismatch { server: IpAddr, gateway: IpAddr },
}

/// A CIDR route to send through the TUN.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// A host route that escapes the tunnel (the VPN server itself) via the original gateway,
/// installed *before* the default-route override so the encrypted packets to the server
/// don't loop back into the tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerException {
    pub dest: Cidr,
    pub gateway: IpAddr,
}

/// The full set of routing changes for a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutePlan {
    pub tun_addr: IpAddr,
    pub via_tun: Vec<Cidr>,
    pub server_exception: ServerException,
    /// Split-tunnel **Exclude**-mode routes: each listed CIDR escapes the tunnel via the
    /// original gateway (structurally a `ServerException`). Empty for plain full-tunnel and
    /// for Include mode (where only `via_tun` carries the listed CIDRs instead).
    pub bypass: Vec<ServerException>,
}

/// Convert a `leshiy-client` split CIDR into the route planner's `Cidr` at the crate boundary
/// (the two are field-identical; this avoids a `leshiy-client -> leshiy-tun` dependency cycle).
impl From<leshiy_client::SplitCidr> for Cidr {
    fn from(c: leshiy_client::SplitCidr) -> Self {
        Cidr {
            addr: c.addr,
            prefix: c.prefix,
        }
    }
}

impl RoutePlan {
    /// Full-tunnel plan: `0.0.0.0/1` + `128.0.0.0/1` via the TUN (these override the
    /// default route without deleting it, the WireGuard trick), with the server host
    /// excepted via the original gateway.
    ///
    /// The server-exception prefix follows the address family (`/32` for IPv4, `/128`
    /// for IPv6). `server_ip` and `orig_gateway` must share a family.
    ///
    /// Equivalent to `with_split(SplitMode::Exclude, &[], ...)` (the empty-Exclude case).
    pub fn full_tunnel(
        server_ip: IpAddr,
        orig_gateway: IpAddr,
        tun_addr: IpAddr,
    ) -> Result<RoutePlan, RoutePlanError> {
        Self::with_split(
            leshiy_client::SplitMode::Exclude,
            &[],
            server_ip,
            orig_gateway,
            tun_addr,
        )
    }

    /// Build a plan for a split-tunnel ruleset.
    ///
    /// - **Exclude**: the `0.0.0.0/1` + `128.0.0.0/1` override + the server exception (today's
    ///   full tunnel), PLUS a `bypass` route per static CIDR via the original gateway. An
    ///   empty `static_cidrs` reproduces `full_tunnel` exactly.
    /// - **Include**: ONLY the listed CIDRs ride the TUN (`via_tun`); NO default override and
    ///   no `bypass` (the unmodified default route already escapes the tunnel). The server
    ///   exception is still emitted (a redundant /32-via-gateway route is harmless) so the
    ///   struct shape is uniform for the backends.
    ///
    /// `server_ip` and `orig_gateway` must share an address family. IPv6 entries in
    /// `static_cidrs` are retained in the plan; the per-OS backends filter them while IPv6
    /// tunnelling is out of scope.
    pub fn with_split(
        mode: leshiy_client::SplitMode,
        static_cidrs: &[Cidr],
        server_ip: IpAddr,
        orig_gateway: IpAddr,
        tun_addr: IpAddr,
    ) -> Result<RoutePlan, RoutePlanError> {
        if server_ip.is_ipv4() != orig_gateway.is_ipv4() {
            return Err(RoutePlanError::FamilyMismatch {
                server: server_ip,
                gateway: orig_gateway,
            });
        }
        let host_prefix = if server_ip.is_ipv4() { 32 } else { 128 };
        let server_exception = ServerException {
            dest: Cidr {
                addr: server_ip,
                prefix: host_prefix,
            },
            gateway: orig_gateway,
        };
        match mode {
            leshiy_client::SplitMode::Exclude => Ok(RoutePlan {
                tun_addr,
                via_tun: vec![
                    Cidr {
                        addr: "0.0.0.0".parse().unwrap(),
                        prefix: 1,
                    },
                    Cidr {
                        addr: "128.0.0.0".parse().unwrap(),
                        prefix: 1,
                    },
                ],
                server_exception,
                bypass: static_cidrs
                    .iter()
                    .map(|c| ServerException {
                        dest: c.clone(),
                        gateway: orig_gateway,
                    })
                    .collect(),
            }),
            leshiy_client::SplitMode::Include => Ok(RoutePlan {
                tun_addr,
                via_tun: static_cidrs.to_vec(),
                server_exception,
                bypass: Vec::new(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leshiy_client::SplitMode;
    use std::net::Ipv4Addr;

    #[test]
    fn empty_exclude_split_equals_full_tunnel() {
        let server = "203.0.113.7".parse().unwrap();
        let gw: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();
        let tun = "10.71.0.2".parse().unwrap();
        let a = RoutePlan::full_tunnel(server, gw, tun).unwrap();
        let b = RoutePlan::with_split(SplitMode::Exclude, &[], server, gw, tun).unwrap();
        assert_eq!(a.via_tun, b.via_tun);
        assert_eq!(a.server_exception, b.server_exception);
        assert!(a.bypass.is_empty());
        assert!(b.bypass.is_empty());
    }

    #[test]
    fn exclude_split_adds_bypass_routes_via_orig_gateway() {
        let server = "203.0.113.7".parse().unwrap();
        let gw: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();
        let excl = [Cidr {
            addr: "10.0.0.0".parse().unwrap(),
            prefix: 8,
        }];
        let plan = RoutePlan::with_split(
            SplitMode::Exclude,
            &excl,
            server,
            gw,
            "10.71.0.2".parse().unwrap(),
        )
        .unwrap();
        // The default override is still installed.
        assert!(plan.via_tun.iter().any(|r| r.to_string() == "0.0.0.0/1"));
        assert!(plan.via_tun.iter().any(|r| r.to_string() == "128.0.0.0/1"));
        // The excluded net bypasses via the original gateway.
        assert_eq!(plan.bypass.len(), 1);
        assert_eq!(plan.bypass[0].dest.to_string(), "10.0.0.0/8");
        assert_eq!(plan.bypass[0].gateway, gw);
    }

    #[test]
    fn include_split_only_routes_listed_cidrs_via_tun_no_override() {
        let server = "203.0.113.7".parse().unwrap();
        let gw = Ipv4Addr::new(192, 168, 1, 1).into();
        let incl = [Cidr {
            addr: "10.0.0.0".parse().unwrap(),
            prefix: 8,
        }];
        let plan = RoutePlan::with_split(
            SplitMode::Include,
            &incl,
            server,
            gw,
            "10.71.0.2".parse().unwrap(),
        )
        .unwrap();
        // No 0/1 + 128/1 override; only the listed CIDR rides the TUN.
        assert!(!plan.via_tun.iter().any(|r| r.to_string() == "0.0.0.0/1"));
        assert_eq!(plan.via_tun.len(), 1);
        assert_eq!(plan.via_tun[0].to_string(), "10.0.0.0/8");
        assert!(plan.bypass.is_empty());
    }

    #[test]
    fn with_split_keeps_ipv6_cidrs_in_plan_for_caller_to_filter() {
        let plan = RoutePlan::with_split(
            SplitMode::Exclude,
            &[Cidr {
                addr: "2001:db8::".parse().unwrap(),
                prefix: 32,
            }],
            "203.0.113.7".parse().unwrap(),
            Ipv4Addr::new(192, 168, 1, 1).into(),
            "10.71.0.2".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(plan.bypass.len(), 1);
        assert_eq!(plan.bypass[0].dest.to_string(), "2001:db8::/32");
    }

    #[test]
    fn split_cidr_converts_to_route_cidr() {
        let sc = leshiy_client::SplitCidr {
            addr: "10.0.0.0".parse().unwrap(),
            prefix: 8,
        };
        let c: Cidr = sc.into();
        assert_eq!(c.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn full_tunnel_overrides_default_and_excludes_server() {
        let plan = RoutePlan::full_tunnel(
            "203.0.113.7".parse().unwrap(),       // server public IP
            Ipv4Addr::new(192, 168, 1, 1).into(), // original gateway
            "10.71.0.2".parse().unwrap(),         // tun address
        )
        .unwrap();
        // Two /1 routes override the default without deleting it.
        assert!(plan.via_tun.iter().any(|r| r.to_string() == "0.0.0.0/1"));
        assert!(plan.via_tun.iter().any(|r| r.to_string() == "128.0.0.0/1"));
        // Server IP escapes the tunnel via the original gateway, /32 for IPv4.
        assert_eq!(plan.server_exception.dest.to_string(), "203.0.113.7/32");
        assert_eq!(
            plan.server_exception.gateway,
            IpAddr::from(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn ipv6_server_exception_is_slash_128() {
        let plan = RoutePlan::full_tunnel(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::ffff".parse().unwrap(),
            "10.71.0.2".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(plan.server_exception.dest.prefix, 128);
        assert_eq!(plan.server_exception.dest.to_string(), "2001:db8::1/128");
    }

    #[test]
    fn mismatched_families_are_rejected() {
        let err = RoutePlan::full_tunnel(
            "2001:db8::1".parse().unwrap(),       // IPv6 server
            Ipv4Addr::new(192, 168, 1, 1).into(), // IPv4 gateway
            "10.71.0.2".parse().unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, RoutePlanError::FamilyMismatch { .. }));
    }
}
