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
fn check_ip(addr: IpAddr, allow_private: bool) -> Result<()> {
    // Canonicalize IPv4-mapped IPv6 to IPv4 so the v4 rules apply uniformly.
    let addr = match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    };

    let forbidden = match addr {
        IpAddr::V4(v4) => {
            v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_link_local()
                || v4.is_broadcast()
                || (!allow_private && (v4.is_loopback() || v4.is_private()))
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

/// Resolve `target` (e.g. `"example.com:443"` or `"127.0.0.1:80"`) and
/// return the first resolved `SocketAddr` after verifying it against the
/// egress policy (see [`check_ip`]).
pub async fn resolve_checked(target: &str, allow_private: bool) -> Result<SocketAddr> {
    let mut addrs = tokio::net::lookup_host(target)
        .await
        .map_err(RealityError::Io)?;

    let addr = addrs
        .next()
        .ok_or_else(|| RealityError::Malformed(format!("no address resolved for {target}")))?;

    check_ip(addr.ip(), allow_private)?;

    Ok(addr)
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

    #[tokio::test]
    async fn resolve_checked_blocks_loopback_by_default() {
        assert!(resolve_checked("127.0.0.1:80", false).await.is_err());
    }

    #[tokio::test]
    async fn resolve_checked_allows_loopback_on_opt_in() {
        let addr = resolve_checked("127.0.0.1:80", true).await.unwrap();
        assert_eq!(addr.ip(), ip("127.0.0.1"));
    }
}
