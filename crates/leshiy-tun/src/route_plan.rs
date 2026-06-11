//! Pure route planning. The split-tunnel inclusion/exclusion layer (a later phase) will
//! extend this without touching the engine. No OS calls here — `sys` applies the plan.
use std::net::IpAddr;

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
    /// default route without deleting it, the WireGuard trick), with the server IP
    /// excepted via the original gateway.
    pub fn full_tunnel(server_ip: IpAddr, orig_gateway: IpAddr, tun_addr: IpAddr) -> RoutePlan {
        RoutePlan {
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
                    prefix: 32,
                },
                gateway: orig_gateway,
            },
        }
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
        );
        // Two /1 routes override the default without deleting it.
        assert!(plan.via_tun.iter().any(|r| r.to_string() == "0.0.0.0/1"));
        assert!(plan.via_tun.iter().any(|r| r.to_string() == "128.0.0.0/1"));
        // Server IP escapes the tunnel via the original gateway.
        assert_eq!(plan.server_exception.dest.to_string(), "203.0.113.7/32");
        assert_eq!(
            plan.server_exception.gateway,
            IpAddr::from(Ipv4Addr::new(192, 168, 1, 1))
        );
    }
}
