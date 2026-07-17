//! SSRF guard: resolve a target and reject forbidden address classes.
//!
//! Link-local (169.254.0.0/16, fe80::/10), unspecified (0.0.0.0/::), broadcast,
//! and multicast addresses are never legitimate relay targets. Loopback,
//! RFC 1918 private (10/8, 172.16/12, 192.168/16) and IPv6 unique-local
//! (fc00::/7) addresses are blocked by **default** because an authenticated
//! client must not be able to pivot the exit into its own host or LAN. An
//! operator who runs an exit specifically to reach an internal network opts in
//! via `allow_private` (see `ServerConfig::allow_private_egress`).
//!
//! IPv4-mapped IPv6 targets (`::ffff:a.b.c.d`) are canonicalized to IPv4 before
//! classification so they cannot smuggle a forbidden v4 address past the v6 rules.
//!
//! Returns the resolved `SocketAddr` so callers connect to the resolved
//! address, preventing DNS-rebinding attacks.

use crate::{RealityError, Result};
use std::net::{IpAddr, SocketAddr};

/// Classify a resolved IP against the egress policy.
///
/// `allow_private` permits loopback / RFC 1918 / IPv6 unique-local targets.
/// Link-local (incl. cloud metadata 169.254.169.254), unspecified, broadcast
/// and multicast are forbidden regardless of `allow_private`.
/// Canonicalize an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its IPv4 form, leaving other
/// addresses unchanged. A dual-stack listener reports v4 peers in the mapped form, so per-IP
/// bookkeeping (connection limits, rate limits, logs) must normalize to avoid treating the same
/// client's v4 and v4-mapped forms as distinct.
pub fn canonical_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn check_ip(addr: IpAddr, allow_private: bool) -> Result<()> {
    // Canonicalize IPv4-mapped IPv6 to IPv4 so the v4 rules apply uniformly.
    let addr = canonical_ip(addr);

    let forbidden = match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // CGNAT / carrier-grade NAT: 100.64.0.0/10 (RFC 6598) — routable-internally, a real
            // SSRF pivot target, and not covered by `is_private()`. Grouped with private space.
            let is_cgnat = o[0] == 100 && (o[1] & 0xc0) == 64;
            // Other special-use v4 blocks that are never a legitimate public relay target,
            // forbidden regardless of `allow_private`: 192.0.0.0/24 (IETF protocol assignments),
            // 198.18.0.0/15 (benchmarking, RFC 2544), 240.0.0.0/4 (reserved / class E).
            let is_special = (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || (o[0] >= 240);
            v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_link_local()
                || v4.is_broadcast()
                || is_special
                || (!allow_private && (v4.is_loopback() || v4.is_private() || is_cgnat))
        }
        IpAddr::V6(v6) => {
            // fc00::/7 (unique-local) — checked by hand; `is_unique_local` is unstable.
            let is_unique_local = (v6.segments()[0] & 0xfe00) == 0xfc00;
            v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
                || (!allow_private && (v6.is_loopback() || is_unique_local))
        }
    };

    if forbidden {
        return Err(RealityError::Malformed(
            "forbidden target address".to_string(),
        ));
    }
    Ok(())
}

/// Apply the egress policy (see [`check_ip`]) to an already-resolved bare IP.
///
/// For callers whose target carries no port and needs no resolution — the ICMP egress, whose
/// destination is lifted straight off the packet being relayed (ADR-0030). Same policy as
/// [`resolve_all_checked`], minus the DNS step it has nothing to look up.
pub fn check_ip_allowed(addr: IpAddr, allow_private: bool) -> Result<()> {
    check_ip(addr, allow_private)
}

/// Resolve `target` (e.g. `"example.com:443"`, `"[2001:db8::1]:443"`, or
/// `"127.0.0.1:80"`) and return **all** resolved `SocketAddr`s that pass the
/// egress policy (see [`check_ip`]), in resolver order.
///
/// Forbidden addresses are filtered out rather than aborting the whole target, so
/// a legitimate dual-stack host whose result mixes families still connects, while
/// a policy-violating address is never dialed. Callers try the returned addresses
/// in turn — a leading unreachable one (e.g. an AAAA on an IPv4-only network) then
/// falls through to the next instead of failing the dial. Returning resolved
/// addresses (never re-resolving) preserves the DNS-rebinding guarantee. Errors if
/// nothing resolves or every result is forbidden.
pub async fn resolve_all_checked(target: &str, allow_private: bool) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(target)
        .await
        .map_err(RealityError::Io)?
        .filter(|a| check_ip(a.ip(), allow_private).is_ok())
        .collect();

    if addrs.is_empty() {
        return Err(RealityError::Malformed(format!(
            "no allowed address resolved for {target}"
        )));
    }

    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // --- Always forbidden, regardless of allow_private ---

    #[test]
    fn metadata_ipv4_blocked_always() {
        // 169.254.169.254 — cloud instance metadata (link-local)
        assert!(check_ip(ip("169.254.169.254"), false).is_err());
        assert!(check_ip(ip("169.254.169.254"), true).is_err());
    }

    #[test]
    fn ipv4_mapped_metadata_blocked() {
        // ::ffff:169.254.169.254 must be canonicalized to v4 and blocked,
        // not slip through the v6 branch.
        assert!(check_ip(ip("::ffff:169.254.169.254"), false).is_err());
        assert!(check_ip(ip("::ffff:169.254.169.254"), true).is_err());
    }

    #[test]
    fn ipv4_mapped_loopback_blocked_when_private_denied() {
        // ::ffff:127.0.0.1 -> 127.0.0.1, blocked under default policy.
        assert!(check_ip(ip("::ffff:127.0.0.1"), false).is_err());
    }

    #[test]
    fn unspecified_and_multicast_blocked_always() {
        assert!(check_ip(ip("0.0.0.0"), true).is_err());
        assert!(check_ip(ip("224.0.0.1"), true).is_err());
        assert!(check_ip(ip("::"), true).is_err());
        assert!(check_ip(ip("ff02::1"), true).is_err());
    }

    #[test]
    fn ipv6_link_local_blocked_always() {
        assert!(check_ip(ip("fe80::1"), false).is_err());
        assert!(check_ip(ip("fe80::1"), true).is_err());
    }

    // --- Private/loopback: blocked by default, allowed only on opt-in ---

    #[test]
    fn loopback_blocked_by_default() {
        assert!(check_ip(ip("127.0.0.1"), false).is_err());
        assert!(check_ip(ip("::1"), false).is_err());
    }

    #[test]
    fn rfc1918_blocked_by_default() {
        assert!(check_ip(ip("10.0.0.1"), false).is_err());
        assert!(check_ip(ip("172.16.0.1"), false).is_err());
        assert!(check_ip(ip("192.168.1.1"), false).is_err());
    }

    /// CGNAT 100.64.0.0/10 (RFC 6598) is an SSRF pivot target `is_private()` misses; blocked by
    /// default, opt-in with `allow_private` like other private space (M13).
    #[test]
    fn cgnat_blocked_by_default_allowed_on_opt_in() {
        assert!(check_ip(ip("100.64.0.1"), false).is_err());
        assert!(check_ip(ip("100.100.50.1"), false).is_err());
        assert!(check_ip(ip("100.127.255.254"), false).is_err());
        assert!(check_ip(ip("100.64.0.1"), true).is_ok());
        // Boundaries: 100.63.x and 100.128.x are outside the /10 and stay public.
        assert!(check_ip(ip("100.63.255.255"), false).is_ok());
        assert!(check_ip(ip("100.128.0.1"), false).is_ok());
    }

    /// Special-use v4 blocks are forbidden regardless of `allow_private` (M13).
    #[test]
    fn special_use_v4_blocked_always() {
        assert!(check_ip(ip("192.0.0.1"), true).is_err()); // 192.0.0.0/24
        assert!(check_ip(ip("198.18.0.1"), true).is_err()); // 198.18.0.0/15
        assert!(check_ip(ip("198.19.255.1"), true).is_err());
        assert!(check_ip(ip("240.0.0.1"), true).is_err()); // 240.0.0.0/4
        assert!(check_ip(ip("255.255.255.254"), true).is_err());
        // Adjacent public addresses unaffected.
        assert!(check_ip(ip("192.0.1.1"), false).is_ok());
        assert!(check_ip(ip("198.20.0.1"), false).is_ok());
    }

    #[test]
    fn ipv6_unique_local_blocked_by_default() {
        // fc00::/7
        assert!(check_ip(ip("fc00::1"), false).is_err());
        assert!(check_ip(ip("fd12:3456::1"), false).is_err());
    }

    #[test]
    fn loopback_and_private_allowed_on_opt_in() {
        assert!(check_ip(ip("127.0.0.1"), true).is_ok());
        assert!(check_ip(ip("::1"), true).is_ok());
        assert!(check_ip(ip("10.0.0.1"), true).is_ok());
        assert!(check_ip(ip("192.168.1.1"), true).is_ok());
        assert!(check_ip(ip("fc00::1"), true).is_ok());
    }

    // --- Public addresses always allowed ---

    #[test]
    fn public_allowed() {
        assert!(check_ip(ip("1.1.1.1"), false).is_ok());
        assert!(check_ip(ip("8.8.8.8"), false).is_ok());
        assert!(check_ip(ip("2606:4700:4700::1111"), false).is_ok());
    }

    #[test]
    fn canonical_ip_unmaps_v4_mapped() {
        assert_eq!(canonical_ip(ip("::ffff:1.2.3.4")), ip("1.2.3.4"));
        assert_eq!(canonical_ip(ip("1.2.3.4")), ip("1.2.3.4"));
        assert_eq!(canonical_ip(ip("2001:db8::1")), ip("2001:db8::1"));
    }

    #[tokio::test]
    async fn resolve_all_checked_blocks_loopback_by_default() {
        // Loopback is filtered out under the default policy → nothing left → error.
        assert!(resolve_all_checked("127.0.0.1:80", false).await.is_err());
    }

    #[tokio::test]
    async fn resolve_all_checked_allows_loopback_on_opt_in() {
        let addrs = resolve_all_checked("127.0.0.1:80", true).await.unwrap();
        assert!(addrs.iter().any(|a| a.ip() == ip("127.0.0.1")));
    }

    #[tokio::test]
    async fn resolve_all_checked_keeps_public_addr() {
        let addrs = resolve_all_checked("1.1.1.1:443", false).await.unwrap();
        assert_eq!(addrs, vec!["1.1.1.1:443".parse::<SocketAddr>().unwrap()]);
    }
}
