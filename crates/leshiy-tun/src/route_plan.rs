//! Pure route planning. The split-tunnel inclusion/exclusion layer extends this without
//! touching the engine. No OS calls here — `sys` applies the plan.
//!
//! **IPv6:** when a v6 TUN address is present (`tun_addr6`), IPv6 is carried *through* the
//! tunnel — the `::/1`+`8000::/1` override rides the device the same way the v4 `0.0.0.0/1`
//! halves do, and v6 excludes bypass via the original v6 gateway ([`RoutePlan::orig_gateway6`]).
//! When no v6 TUN address is present, IPv6 is fail-closed: the backend disables it (sysctl /
//! per-service kill-switch) while the session is up and restores it on teardown — never leaking
//! around the tunnel.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

impl Cidr {
    /// True for one of the four default-override halves a full-tunnel (Exclude-base) plan
    /// installs: `0.0.0.0/1`, `128.0.0.0/1`, and (dual-stack) `::/1`, `8000::/1`. Together each
    /// pair blankets an entire address family — the WireGuard "override the default without
    /// deleting it" trick. In the *main* routing table those covering routes trip docker/IPAM's
    /// "candidate subnet overlaps an existing host route" check ("all predefined address pools
    /// have been fully subnetted"); a backend that uses policy routing pulls these out of
    /// `via_tun` and installs a single `default`/`::/0` in a private table instead, keeping the
    /// main table free of any covering route.
    pub fn is_default_override(&self) -> bool {
        if self.prefix != 1 {
            return false;
        }
        match self.addr {
            IpAddr::V4(a) => a == Ipv4Addr::UNSPECIFIED || a == Ipv4Addr::new(128, 0, 0, 0),
            IpAddr::V6(a) => {
                a == Ipv6Addr::UNSPECIFIED || a == Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)
            }
        }
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
    /// IPv4 address assigned to the TUN interface.
    pub tun_addr: IpAddr,
    /// IPv6 address for the TUN interface. `Some` enables dual-stack: IPv6 is carried
    /// *through* the tunnel (the `::/1`+`8000::/1` override is added under an Exclude
    /// base) instead of being fail-closed by the kill-switch. `None` = IPv4-only tunnel.
    pub tun_addr6: Option<IpAddr>,
    pub via_tun: Vec<Cidr>,
    pub server_exception: ServerException,
    /// Split-tunnel **Exclude**-mode routes: each listed CIDR escapes the tunnel via the
    /// original gateway of its own address family (structurally a `ServerException`). Empty
    /// for plain full-tunnel and for Include mode (where only `via_tun` carries them instead).
    pub bypass: Vec<ServerException>,
    /// The original IPv6 default gateway, when known. The static `bypass` entries already carry
    /// their own per-family gateway, but the live resolver installs v6 domain-rule bypass routes
    /// at runtime and needs this to route them via the right next-hop. `None` when v6 is not
    /// carried (or no v6 default route exists) — a resolved v6 bypass is then a safe no-op.
    pub orig_gateway6: Option<IpAddr>,
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
            None,
        )
    }

    /// Single-direction convenience over [`from_split`](Self::from_split): Exclude puts
    /// `static_cidrs` in the bypass set, Include puts them in the via-tun set. `tun_addr6`
    /// (an IPv6 TUN address) enables carrying IPv6 through the tunnel; `None` keeps it
    /// IPv4-only.
    pub fn with_split(
        mode: leshiy_client::SplitMode,
        static_cidrs: &[Cidr],
        server_ip: IpAddr,
        orig_gateway: IpAddr,
        tun_addr: IpAddr,
        tun_addr6: Option<IpAddr>,
    ) -> Result<RoutePlan, RoutePlanError> {
        match mode {
            leshiy_client::SplitMode::Exclude => Self::from_split(
                mode,
                &[],
                static_cidrs,
                server_ip,
                orig_gateway,
                None,
                tun_addr,
                tun_addr6,
            ),
            leshiy_client::SplitMode::Include => Self::from_split(
                mode,
                static_cidrs,
                &[],
                server_ip,
                orig_gateway,
                None,
                tun_addr,
                tun_addr6,
            ),
        }
    }

    /// Build a two-directional plan: `include_cidrs` ride the TUN, `exclude_cidrs` bypass via
    /// the original gateway, and `base_mode` picks the default policy:
    /// - **Exclude** (default): install the `0.0.0.0/1`+`128.0.0.0/1` override so the default
    ///   route is tunneled; excludes carve more-specific bypass holes; includes can re-tunnel
    ///   a more-specific net inside a broader exclude.
    /// - **Include**: NO override — the default stays direct; only the includes ride the TUN.
    ///
    /// The server exception is always emitted. Overlaps are resolved by the kernel's
    /// longest-prefix-match. `server_ip`/`orig_gateway` must share a family; IPv6 CIDRs are
    /// retained for the per-OS backends to filter.
    #[allow(clippy::too_many_arguments)] // a routing plan legitimately needs all of these
    pub fn from_split(
        base_mode: leshiy_client::SplitMode,
        include_cidrs: &[Cidr],
        exclude_cidrs: &[Cidr],
        server_ip: IpAddr,
        orig_gateway: IpAddr,
        orig_gateway6: Option<IpAddr>,
        tun_addr: IpAddr,
        tun_addr6: Option<IpAddr>,
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
        let mut via_tun = if matches!(base_mode, leshiy_client::SplitMode::Exclude) {
            let mut v = vec![
                Cidr {
                    addr: "0.0.0.0".parse().unwrap(),
                    prefix: 1,
                },
                Cidr {
                    addr: "128.0.0.0".parse().unwrap(),
                    prefix: 1,
                },
            ];
            // Dual-stack: send all IPv6 through the tunnel too (`::/1`+`8000::/1`, the
            // same override-without-deleting trick as v4). Only when a v6 TUN address is
            // present — otherwise IPv6 is fail-closed by the backend's kill-switch.
            if tun_addr6.is_some() {
                v.push(Cidr {
                    addr: "::".parse().unwrap(),
                    prefix: 1,
                });
                v.push(Cidr {
                    addr: "8000::".parse().unwrap(),
                    prefix: 1,
                });
            }
            v
        } else {
            Vec::new()
        };
        via_tun.extend(include_cidrs.iter().cloned());
        // Each bypass escapes via the original gateway of its OWN family. `orig_gateway` is the
        // server-family gateway; `orig_gateway6` is the v6 gateway (used for v6 excludes when the
        // server is reached over v4). A v6 exclude with no v6 gateway is dropped rather than
        // routed via a v4 gateway — under a dual-stack Exclude base it then rides the `::/1`
        // override through the tunnel (fail-safe, never leaked).
        let v6_gateway = if orig_gateway.is_ipv6() {
            Some(orig_gateway)
        } else {
            orig_gateway6
        };
        let bypass = exclude_cidrs
            .iter()
            .filter_map(|c| {
                let gw = if c.addr.is_ipv4() {
                    orig_gateway.is_ipv4().then_some(orig_gateway)
                } else {
                    v6_gateway
                };
                gw.map(|gateway| ServerException {
                    dest: c.clone(),
                    gateway,
                })
            })
            .collect();
        Ok(RoutePlan {
            tun_addr,
            tun_addr6,
            via_tun,
            server_exception,
            bypass,
            orig_gateway6: v6_gateway,
        })
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
        let b = RoutePlan::with_split(SplitMode::Exclude, &[], server, gw, tun, None).unwrap();
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
            None,
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
            None,
        )
        .unwrap();
        // No 0/1 + 128/1 override; only the listed CIDR rides the TUN.
        assert!(!plan.via_tun.iter().any(|r| r.to_string() == "0.0.0.0/1"));
        assert_eq!(plan.via_tun.len(), 1);
        assert_eq!(plan.via_tun[0].to_string(), "10.0.0.0/8");
        assert!(plan.bypass.is_empty());
    }

    #[test]
    fn ipv6_exclude_is_dropped_from_bypass() {
        // No v6 gateway is plumbed, so a v6 exclude is NOT routed via the v4 gateway; it is
        // dropped and (under a dual-stack Exclude base) rides the `::/1` override through the
        // tunnel — fail-safe, never leaked around it.
        let plan = RoutePlan::with_split(
            SplitMode::Exclude,
            &[Cidr {
                addr: "2001:db8::".parse().unwrap(),
                prefix: 32,
            }],
            "203.0.113.7".parse().unwrap(),
            Ipv4Addr::new(192, 168, 1, 1).into(),
            "10.71.0.2".parse().unwrap(),
            Some("fd00:71::2".parse().unwrap()),
        )
        .unwrap();
        assert!(
            plan.bypass.is_empty(),
            "v6 exclude must not bypass via a v4 gateway"
        );
        // No v6 gateway known → the live resolver has none either, so a resolved v6 bypass is a
        // safe no-op rather than being routed via the v4 gateway.
        assert_eq!(plan.orig_gateway6, None);
    }

    #[test]
    fn ipv6_exclude_bypasses_via_v6_gateway_when_present() {
        // With a v6 gateway supplied, a v6 exclude escapes the tunnel via it (v4 server).
        let plan = RoutePlan::from_split(
            SplitMode::Exclude,
            &[],
            &[Cidr {
                addr: "2001:db8::".parse().unwrap(),
                prefix: 32,
            }],
            "203.0.113.7".parse().unwrap(),       // v4 server
            Ipv4Addr::new(192, 168, 1, 1).into(), // v4 gateway
            Some("fe80::1".parse().unwrap()),     // v6 gateway
            "10.71.0.2".parse().unwrap(),
            Some("fd00:71::2".parse().unwrap()),
        )
        .unwrap();
        assert_eq!(plan.bypass.len(), 1);
        assert_eq!(plan.bypass[0].dest.to_string(), "2001:db8::/32");
        assert_eq!(plan.bypass[0].gateway, "fe80::1".parse::<IpAddr>().unwrap());
        // The same v6 gateway is exposed on the plan so the live resolver can bypass runtime-
        // resolved v6 domain rules through it (not just the static excludes above).
        assert_eq!(
            plan.orig_gateway6,
            Some("fe80::1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn dual_stack_full_tunnel_adds_v6_override() {
        // With a v6 TUN address, the Exclude base also overrides all IPv6 via the tunnel.
        let plan = RoutePlan::from_split(
            SplitMode::Exclude,
            &[],
            &[],
            "203.0.113.7".parse().unwrap(),
            Ipv4Addr::new(192, 168, 1, 1).into(),
            None,
            "10.71.0.2".parse().unwrap(),
            Some("fd00:71::2".parse().unwrap()),
        )
        .unwrap();
        assert_eq!(plan.tun_addr6, Some("fd00:71::2".parse().unwrap()));
        assert!(plan.via_tun.iter().any(|r| r.to_string() == "0.0.0.0/1"));
        assert!(plan.via_tun.iter().any(|r| r.to_string() == "::/1"));
        assert!(plan.via_tun.iter().any(|r| r.to_string() == "8000::/1"));
    }

    #[test]
    fn ipv4_only_tunnel_has_no_v6_override() {
        // Without a v6 TUN address, no `::/1` override is emitted (IPv6 stays fail-closed).
        let plan = RoutePlan::full_tunnel(
            "203.0.113.7".parse().unwrap(),
            Ipv4Addr::new(192, 168, 1, 1).into(),
            "10.71.0.2".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(plan.tun_addr6, None);
        assert!(!plan.via_tun.iter().any(|r| r.addr.is_ipv6()));
    }

    #[test]
    fn from_split_mixes_include_and_exclude_with_exclude_base() {
        let inc = [Cidr {
            addr: "1.2.3.0".parse().unwrap(),
            prefix: 24,
        }];
        let exc = [Cidr {
            addr: "1.0.0.0".parse().unwrap(),
            prefix: 8,
        }];
        let plan = RoutePlan::from_split(
            SplitMode::Exclude,
            &inc,
            &exc,
            "203.0.113.7".parse().unwrap(),
            Ipv4Addr::new(192, 168, 1, 1).into(),
            None,
            "10.71.0.2".parse().unwrap(),
            None,
        )
        .unwrap();
        // Exclude base keeps the default override.
        assert!(plan.via_tun.iter().any(|r| r.to_string() == "0.0.0.0/1"));
        // The included /24 is ALSO via tun (more specific than the excluded /8 → wins).
        assert!(plan.via_tun.iter().any(|r| r.to_string() == "1.2.3.0/24"));
        // The excluded /8 bypasses via the gateway.
        assert_eq!(plan.bypass.len(), 1);
        assert_eq!(plan.bypass[0].dest.to_string(), "1.0.0.0/8");
    }

    #[test]
    fn from_split_include_base_has_no_override() {
        let inc = [Cidr {
            addr: "1.2.3.0".parse().unwrap(),
            prefix: 24,
        }];
        let plan = RoutePlan::from_split(
            SplitMode::Include,
            &inc,
            &[],
            "203.0.113.7".parse().unwrap(),
            Ipv4Addr::new(192, 168, 1, 1).into(),
            None,
            "10.71.0.2".parse().unwrap(),
            None,
        )
        .unwrap();
        assert!(!plan.via_tun.iter().any(|r| r.to_string() == "0.0.0.0/1"));
        assert_eq!(plan.via_tun.len(), 1);
    }

    #[test]
    fn default_override_halves_are_recognized() {
        for s in ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"] {
            let (addr, prefix) = s.split_once('/').unwrap();
            let c = Cidr {
                addr: addr.parse().unwrap(),
                prefix: prefix.parse().unwrap(),
            };
            assert!(c.is_default_override(), "{s} should be a default override");
        }
        // Specific includes / excludes and the true default are NOT override halves.
        for s in [
            "0.0.0.0/0",
            "10.0.0.0/8",
            "192.168.1.0/24",
            "1.2.3.0/1",
            "::/0",
            "2000::/1",
        ] {
            let (addr, prefix) = s.split_once('/').unwrap();
            let c = Cidr {
                addr: addr.parse().unwrap(),
                prefix: prefix.parse().unwrap(),
            };
            assert!(
                !c.is_default_override(),
                "{s} must not be a default override"
            );
        }
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
