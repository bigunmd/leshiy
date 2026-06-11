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
#[derive(Clone, Debug, PartialEq, Eq)]
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
}

impl RoutePlan {
    /// Full-tunnel plan: `0.0.0.0/1` + `128.0.0.0/1` via the TUN (these override the
    /// default route without deleting it, the WireGuard trick), with the server host
    /// excepted via the original gateway.
    ///
    /// The server-exception prefix follows the address family (`/32` for IPv4, `/128`
    /// for IPv6). `server_ip` and `orig_gateway` must share a family.
    pub fn full_tunnel(
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
        Ok(RoutePlan {
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
            server_exception: ServerException {
                dest: Cidr {
                    addr: server_ip,
                    prefix: host_prefix,
                },
                gateway: orig_gateway,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

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
